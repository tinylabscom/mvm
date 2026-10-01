//! The resolved manifest, and folding a policy into a launch.
//!
//! A resolved policy is lowered into exactly the values the launch flags
//! carry — `--allow-host`, endpoint routes, `--secret`, `--mount`,
//! `--allow-env`, `--cpu-limit`, `--timeout` — and from there it takes the one
//! road every launch takes: grant resolution, plan synthesis, signing, and
//! admission. Nothing here signs or admits anything, and nothing here trusts
//! a signature: a profile and the same flags produce the same plan because
//! they are, by the time admission sees them, the same flags.
//!
//! [`ResolvedManifest`] is the resolved policy as a document: what
//! `mvmctl policy resolve` writes and `--plan FILE` reads back. Reading it
//! back re-validates it, and a document that carries an execution plan or a
//! signature is refused: admission synthesizes and signs the plan itself.

use std::path::Path;

use mvm_contract::policy::routes::{EgressRoute, parse_endpoint_spec};
use serde::{Deserialize, Serialize};

use super::merge::{canonical_allow, deny_covers, split_host_port};
use super::model::PolicyBody;
use super::source::PolicyError;
use crate::admission::run_secrets::RunSecretSpec;

/// A resolved policy as a document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ResolvedManifest {
    /// The layers it was resolved from, lowest precedence first.
    /// Informational: reading the manifest back ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_from: Vec<String>,
    /// The merged policy, denies already applied.
    #[serde(default)]
    pub policy: PolicyBody,
}

/// Keys an execution plan or a signed envelope carries and a resolved
/// manifest never does.
const PLAN_KEYS: &[&str] = &[
    "signature",
    "signer_id",
    "plan",
    "plan_id",
    "nonce",
    "image",
];

impl ResolvedManifest {
    /// Read a resolved manifest, refusing a plan or a signature, and
    /// re-validating the policy it carries.
    ///
    /// # Errors
    ///
    /// Not JSON, an execution plan or signed envelope, an unknown key, or a
    /// policy the merge refuses.
    pub fn read(path: &Path) -> Result<Self, PolicyError> {
        let label = format!("resolved manifest {}", path.display());
        let bytes = std::fs::read(path).map_err(|error| {
            PolicyError::new(&label, format!("reading: {error}")).in_file(Some(path))
        })?;
        Self::from_json(&bytes, &label, Some(path))
    }

    /// Parse and re-validate a resolved manifest.
    ///
    /// # Errors
    ///
    /// See [`read`](Self::read).
    pub fn from_json(bytes: &[u8], label: &str, file: Option<&Path>) -> Result<Self, PolicyError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| PolicyError::new(label, format!("not JSON: {error}")).in_file(file))?;
        if let Some(key) = value
            .as_object()
            .and_then(|object| PLAN_KEYS.iter().find(|key| object.contains_key(**key)))
        {
            return Err(PolicyError::new(
                label,
                "this is an execution plan or a signed envelope, not a resolved manifest. A \
                 supplied plan or signature is never trusted: give `mvmctl policy resolve` \
                 output and admission synthesizes and signs the plan itself",
            )
            .in_file(file)
            .at_key(*key));
        }
        let manifest: Self = serde_json::from_value(value)
            .map_err(|error| PolicyError::new(label, error.to_string()).in_file(file))?;
        let revalidated = super::resolve::revalidate(label, file, manifest.policy.clone())?;
        Ok(Self {
            resolved_from: manifest.resolved_from,
            policy: revalidated.policy,
        })
    }

    /// The manifest for a resolved policy.
    #[must_use]
    pub fn from_resolved(resolved: &super::merge::ResolvedPolicy) -> Self {
        Self {
            resolved_from: resolved.layers.iter().map(|l| l.label.clone()).collect(),
            policy: resolved.policy.clone(),
        }
    }
}

/// The policy-bearing flags of one launch, before a policy is folded in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchFlags {
    /// `--allow-host`.
    pub allow_host: Vec<String>,
    /// `--net`.
    pub net: bool,
    /// Whether `--network-preset` was given.
    pub network_preset: bool,
    /// `--allow-endpoint`.
    pub allow_endpoint: Vec<String>,
    /// `--cpu-limit`.
    pub cpu_limit: Option<u32>,
    /// `--timeout`.
    pub timeout: Option<u64>,
    /// `--secret`.
    pub secret: Vec<String>,
    /// Secret names the launch binds from somewhere other than a flag — the
    /// project manifest's `[secrets]` table. A policy's secret deny list
    /// reaches these too.
    pub declared_secrets: Vec<String>,
    /// `--mount`.
    pub mounts: Vec<String>,
    /// The names `--env` sets.
    pub env_names: Vec<String>,
    /// `--allow-env`.
    pub allow_env: Vec<String>,
    /// `--cpus`.
    pub cpus: u32,
    /// `--memory`, in MiB.
    pub memory_mib: u64,
}

/// The flags after a policy is folded in: what the launch then runs with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FoldedLaunch {
    pub allow_host: Vec<String>,
    /// Endpoint routes the policy contributes; `--allow-endpoint` routes are
    /// merged with these where routes are resolved.
    pub routes: Vec<EgressRoute>,
    pub cpu_limit: Option<u32>,
    pub timeout: Option<u64>,
    pub secret: Vec<String>,
    pub mounts: Vec<String>,
    pub allow_env: Vec<String>,
    /// The resolved tool rules, carried to the plan the launch synthesizes.
    /// Empty means the tool dimension is unused.
    pub tools: mvm_contract::policy::tool_rules::ToolRules,
}

fn refuse(key: &str, message: impl Into<String>) -> PolicyError {
    PolicyError::new("command line", message).at_key(key)
}

/// Fold `policy` into `flags`. The flags are the last, most specific layer:
/// they may add what the policy allows alongside it, and may never reach what
/// the policy denies, blocks, or bounds.
///
/// # Errors
///
/// A flag that asks for something the policy denies or exceeds, named.
pub fn fold(policy: &PolicyBody, flags: &LaunchFlags) -> Result<FoldedLaunch, PolicyError> {
    let network = fold_network(policy, flags)?;
    let (cpu_limit, timeout) = fold_resources(policy, flags)?;
    Ok(FoldedLaunch {
        allow_host: network,
        routes: if policy.network.block == Some(true) {
            Vec::new()
        } else {
            policy.network.routes.clone()
        },
        cpu_limit,
        timeout,
        secret: fold_secrets(policy, flags)?,
        mounts: fold_mounts(policy, flags)?,
        allow_env: fold_env(policy, flags)?,
        tools: policy.tools.to_tool_rules(),
    })
}

fn fold_network(policy: &PolicyBody, flags: &LaunchFlags) -> Result<Vec<String>, PolicyError> {
    let net = &policy.network;
    if net.block == Some(true) {
        let asks = !flags.allow_host.is_empty()
            || flags.net
            || flags.network_preset
            || !flags.allow_endpoint.is_empty();
        if asks {
            return Err(refuse(
                "network",
                "the policy blocks the network; --allow-host, --allow-endpoint, --net and \
                 --network-preset cannot turn it back on",
            ));
        }
        return Ok(Vec::new());
    }
    if !net.deny.is_empty() && (flags.net || flags.network_preset) {
        return Err(refuse(
            "network",
            "--net and --network-preset expand to presets a deny list cannot be applied to \
             under this policy; name destinations with --allow-host",
        ));
    }
    let mut allow = net.allow.clone();
    for entry in &flags.allow_host {
        let canonical = canonical_allow(entry).map_err(|reason| refuse("--allow-host", reason))?;
        let (host, port) = split_host_port(&canonical);
        if let Some(deny) = net.deny.iter().find(|d| deny_covers(d, host, port)) {
            return Err(refuse(
                "--allow-host",
                format!("{canonical} is denied by the policy ({deny})"),
            ));
        }
        if !allow.contains(&canonical) {
            allow.push(canonical);
        }
    }
    for spec in &flags.allow_endpoint {
        if let Ok((_, host, port, _)) = parse_endpoint_spec(spec)
            && let Some(deny) = net.deny.iter().find(|d| deny_covers(d, &host, port))
        {
            return Err(refuse(
                "--allow-endpoint",
                format!("{host}:{port} is denied by the policy ({deny})"),
            ));
        }
    }
    Ok(allow)
}

fn fold_resources(
    policy: &PolicyBody,
    flags: &LaunchFlags,
) -> Result<(Option<u32>, Option<u64>), PolicyError> {
    let bounds = &policy.resources;
    if let Some(max) = bounds.max_cpus
        && flags.cpus > max
    {
        return Err(refuse(
            "--cpus",
            format!(
                "{} vCPUs exceeds the policy's max_cpus of {max}",
                flags.cpus
            ),
        ));
    }
    if let Some(raw) = &bounds.max_memory {
        let max = mvm_core::util::parse_human_size(raw)
            .map_err(|error| refuse("resources.max_memory", format!("{error:#}")))?;
        if flags.memory_mib > u64::from(max) {
            return Err(refuse(
                "--memory",
                format!(
                    "{} MiB exceeds the policy's max_memory of {raw}",
                    flags.memory_mib
                ),
            ));
        }
    }
    let cpu = match (bounds.cpu_millicores, flags.cpu_limit) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let timeout = match (bounds.wall_clock_secs.map(u64::from), flags.timeout) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    Ok((cpu, timeout))
}

fn fold_secrets(policy: &PolicyBody, flags: &LaunchFlags) -> Result<Vec<String>, PolicyError> {
    let secrets = &policy.secrets;
    let mut specs: Vec<RunSecretSpec> = secrets
        .bind
        .iter()
        .map(|grant| RunSecretSpec {
            name: grant.name.clone(),
            destinations: grant.hosts.clone(),
        })
        .collect();
    if let Some(name) = flags
        .declared_secrets
        .iter()
        .find(|name| secrets.deny.contains(name))
    {
        return Err(refuse(
            "[secrets]",
            format!("secret {name:?} is declared by the project but denied by the policy"),
        ));
    }
    for raw in &flags.secret {
        let spec: RunSecretSpec = raw
            .parse()
            .map_err(|error: anyhow::Error| refuse("--secret", format!("{error:#}")))?;
        if secrets.deny.contains(&spec.name) {
            return Err(refuse(
                "--secret",
                format!("secret {:?} is denied by the policy", spec.name),
            ));
        }
        match specs.iter_mut().find(|s| s.name == spec.name) {
            None => specs.push(spec),
            Some(existing) => {
                if spec.destinations.is_empty() {
                    continue;
                }
                if !existing.destinations.is_empty()
                    && let Some(wider) = spec
                        .destinations
                        .iter()
                        .find(|host| !existing.destinations.contains(host))
                {
                    return Err(refuse(
                        "--secret",
                        format!(
                            "secret {:?}: {wider:?} widens the destinations the policy allows ({})",
                            spec.name,
                            existing.destinations.join(", ")
                        ),
                    ));
                }
                existing.destinations = spec.destinations;
            }
        }
    }
    Ok(specs
        .into_iter()
        .map(|spec| {
            if spec.destinations.is_empty() {
                spec.name
            } else {
                format!("{}:{}", spec.name, spec.destinations.join(","))
            }
        })
        .collect())
}

fn mount_host(spec: &str) -> &str {
    spec.split_once(':').map_or(spec, |(host, _)| host)
}

fn mount_guest(spec: &str) -> Option<&str> {
    spec.split_once(':')
        .map(|(_, rest)| rest.split(':').next().unwrap_or(rest))
}

fn resolved_host_path(path: &str) -> std::path::PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| Path::new(path).to_path_buf());
    canonicalize_with_missing_tail(absolute)
}

fn canonicalize_with_missing_tail(mut path: std::path::PathBuf) -> std::path::PathBuf {
    let mut tail = Vec::new();
    while !path.exists() {
        let Some(name) = path.file_name().map(ToOwned::to_owned) else {
            return path;
        };
        tail.push(name);
        if !path.pop() {
            return path;
        }
    }
    let mut resolved = std::fs::canonicalize(&path).unwrap_or(path);
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    resolved
}

fn fold_mounts(policy: &PolicyBody, flags: &LaunchFlags) -> Result<Vec<String>, PolicyError> {
    let shares = &policy.shares;
    for spec in &flags.mounts {
        let host = mount_host(spec);
        let absolute = resolved_host_path(host);
        if let Some(deny) = shares
            .deny
            .iter()
            .find(|deny| absolute.starts_with(resolved_host_path(deny)))
        {
            return Err(refuse(
                "--mount",
                format!("{host} is under {deny}, which the policy denies as a share source"),
            ));
        }
    }
    let mut mounts = flags.mounts.clone();
    for share in &shares.mount {
        match flags
            .mounts
            .iter()
            .find(|spec| mount_guest(spec) == Some(share.guest.as_str()))
        {
            Some(spec) if mount_host(spec) != share.host => {
                return Err(refuse(
                    "--mount",
                    format!(
                        "{} is mounted from {} by the policy; {spec} would replace it",
                        share.guest, share.host
                    ),
                ));
            }
            Some(_) => {}
            None => mounts.push(format!(
                "{}:{}:{}",
                share.host,
                share.guest,
                if share.writable { "rw" } else { "ro" }
            )),
        }
    }
    Ok(mounts)
}

fn fold_env(policy: &PolicyBody, flags: &LaunchFlags) -> Result<Vec<String>, PolicyError> {
    let env = &policy.env;
    for name in &flags.env_names {
        if env.deny.contains(name) {
            return Err(refuse("--env", format!("{name} is denied by the policy")));
        }
        let listed = env.allow.contains(name) || env.readmit.contains(name);
        if !env.allow.is_empty() && !listed {
            return Err(refuse(
                "--env",
                format!("{name} is not in the policy's env allow-list"),
            ));
        }
    }
    let mut allow_env = flags.allow_env.clone();
    for name in &env.readmit {
        if !allow_env.contains(name) {
            allow_env.push(name.clone());
        }
    }
    Ok(allow_env)
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
