//! Folding an ordered list of layers into one policy.
//!
//! The rules, which are the security contract of composition:
//!
//! - **Allows are unioned, denies are unioned, and a deny beats an allow**, in
//!   every section: a denied host, secret, share source, variable or tool is
//!   removed from the result whichever layer allowed it.
//! - **Blocked network stays blocked.** Once any layer sets
//!   `network.block = true`, every allow and route is dropped, and a later
//!   layer that says `block = false` is an error rather than a quiet no-op.
//! - **A secret's destinations only narrow.** A later layer naming the same
//!   secret may list a subset of the hosts an earlier one listed, never a host
//!   outside it. The launch then checks the result against the allow-list
//!   stored with `mvmctl secret set`, which no layer can widen either.
//! - **A share is writable only if every layer naming it says so.**
//! - **Every resource bound is a ceiling**: the smallest wins.
//! - **Escape hatches** (`env.readmit`) are honoured only in user-authored
//!   layers.
//!
//! Every error names the layer, its file, and the key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mvm_contract::policy::routes::{EgressRoute, RouteSet};
use mvm_core::env_hygiene::classify;
use serde::Serialize;

use super::model::{
    EnvSection, NetworkSection, PolicyBody, ResourcesSection, SecretGrant, SecretsSection,
    ShareGrant, SharesSection, ToolsSection,
};
use super::source::{LayerOrigin, PolicyError};

/// One layer of policy, in resolution order.
#[derive(Debug, Clone)]
pub struct Layer {
    /// Human label, e.g. ``group `registries` (built-in)``.
    pub label: String,
    pub file: Option<PathBuf>,
    pub origin: LayerOrigin,
    pub body: PolicyBody,
}

/// A layer, as reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerSummary {
    pub label: String,
    pub origin: LayerOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
}

/// The outcome of resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedPolicy {
    /// The merged policy, with denies already applied.
    pub policy: PolicyBody,
    /// The layers, lowest precedence first.
    pub layers: Vec<LayerSummary>,
    /// Which layer contributed each item, keyed `section.field.value`.
    pub provenance: BTreeMap<String, String>,
    /// What the merge dropped or narrowed, for the operator.
    pub notes: Vec<String>,
    /// Whether any contributing profile selects policy by backend.
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub backend_conditioned: bool,
}

impl ResolvedPolicy {
    /// A policy that says nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            policy: PolicyBody::default(),
            layers: Vec::new(),
            provenance: BTreeMap::new(),
            notes: Vec::new(),
            backend_conditioned: false,
        }
    }
}

fn layer_error(layer: &Layer, key: &str, message: impl Into<String>) -> PolicyError {
    PolicyError::new(&layer.label, message)
        .in_file(layer.file.as_deref())
        .at_key(key)
}

/// Fold `layers`, lowest precedence first.
///
/// # Errors
///
/// A value that does not parse, a rule the composition breaks, or an escape
/// hatch in a layer that may not use one — naming the layer, file and key.
pub fn merge_layers(layers: &[Layer]) -> Result<ResolvedPolicy, PolicyError> {
    let mut acc = Accumulator::default();
    for layer in layers {
        acc.network(layer)?;
        acc.secrets(layer)?;
        acc.shares(layer)?;
        acc.env(layer)?;
        acc.tools(layer);
        acc.resources(layer)?;
    }
    let mut resolved = acc.finish()?;
    resolved.layers = layers
        .iter()
        .map(|layer| LayerSummary {
            label: layer.label.clone(),
            origin: layer.origin,
            file: layer.file.clone(),
        })
        .collect();
    Ok(resolved)
}

/// One item and the layer that first contributed it.
#[derive(Debug, Clone)]
struct Sourced<T> {
    value: T,
    from: String,
}

#[derive(Debug, Default)]
struct Accumulator {
    blocked_by: Option<String>,
    allow: Vec<Sourced<String>>,
    deny: Vec<Sourced<String>>,
    routes: Vec<Sourced<EgressRoute>>,
    secrets: Vec<Sourced<SecretGrant>>,
    secret_deny: Vec<Sourced<String>>,
    shares: Vec<Sourced<ShareGrant>>,
    share_deny: Vec<Sourced<String>>,
    env_allow: Vec<Sourced<String>>,
    env_deny: Vec<Sourced<String>>,
    env_readmit: Vec<Sourced<String>>,
    tools_allow: Vec<Sourced<String>>,
    tools_deny: Vec<Sourced<String>>,
    cpu_millicores: Option<Sourced<u32>>,
    wall_clock_secs: Option<Sourced<u32>>,
    max_cpus: Option<Sourced<u32>>,
    max_memory: Option<Sourced<(u64, String)>>,
    notes: Vec<String>,
}

fn push_unique(items: &mut Vec<Sourced<String>>, value: String, from: &str) {
    if !items.iter().any(|item| item.value == value) {
        items.push(Sourced {
            value,
            from: from.to_string(),
        });
    }
}

/// Canonical `host:port` for an allow entry, through the one `--allow-host`
/// parser so a policy and the flag agree on what an entry means.
pub(crate) fn canonical_allow(entry: &str) -> Result<String, String> {
    crate::admission::run_network::parse_allow_host(entry)
        .map(|rule| rule.to_string())
        .map_err(|error| format!("{error:#}"))
}

/// A deny pattern: `HOST[:PORT]` or `*.suffix[:PORT]`; no port means every
/// port.
fn parse_deny(entry: &str) -> Result<(String, Option<u16>), String> {
    let entry = entry.trim();
    let (host, port) = match entry.rsplit_once(':') {
        Some((host, port)) => (
            host,
            Some(
                port.parse::<u16>()
                    .map_err(|_| format!("{entry:?}: {port:?} is not a port"))?,
            ),
        ),
        None => (entry, None),
    };
    let bare = host.strip_prefix("*.").unwrap_or(host);
    if bare.is_empty() || bare.contains(['*', '/', ' ']) {
        return Err(format!("{entry:?} must be HOST[:PORT] or *.suffix[:PORT]"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// Whether deny pattern `deny` covers `host:port`.
pub(crate) fn deny_covers(deny: &str, host: &str, port: u16) -> bool {
    let Ok((pattern, deny_port)) = parse_deny(deny) else {
        return false;
    };
    if deny_port.is_some_and(|p| p != port) {
        return false;
    }
    let host = host.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() && host.ends_with(&format!(".{suffix}")),
        None => host == pattern,
    }
}

/// Split a canonical `host:port`.
pub(crate) fn split_host_port(entry: &str) -> (&str, u16) {
    match entry.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().unwrap_or(443)),
        None => (entry, 443),
    }
}

fn validate_secret_name(layer: &Layer, key: &str, name: &str) -> Result<(), PolicyError> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || c == ':' || c == ',')
    {
        return Err(layer_error(
            layer,
            key,
            format!("{name:?} is not a secret name"),
        ));
    }
    Ok(())
}

fn validate_host_only(layer: &Layer, key: &str, host: &str) -> Result<(), PolicyError> {
    if host.is_empty() || host.contains([':', '/']) || host.chars().any(char::is_whitespace) {
        return Err(layer_error(
            layer,
            key,
            format!(
                "{host:?} is not a host name (name the host only; which ports are reachable \
                 is the network section's decision)"
            ),
        ));
    }
    Ok(())
}

fn validate_env_name(layer: &Layer, key: &str, name: &str) -> Result<(), PolicyError> {
    if !mvm_core::vm_backend::is_secret_env_name(name) {
        return Err(layer_error(
            layer,
            key,
            format!("{name:?} is not a variable name ([A-Za-z_][A-Za-z0-9_]*)"),
        ));
    }
    Ok(())
}

/// A share's host path, absolute: relative paths resolve against the
/// declaring file's directory.
fn absolute_share_host(layer: &Layer, host: &str) -> Result<String, PolicyError> {
    let path = Path::new(host);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match layer.file.as_deref().and_then(Path::parent) {
            Some(dir) => dir.join(path),
            None => {
                return Err(layer_error(
                    layer,
                    "shares.mount.host",
                    format!(
                        "{host:?} is relative, and this layer has no file to resolve it against"
                    ),
                ));
            }
        }
    };
    Ok(std::fs::canonicalize(&absolute)
        .unwrap_or(absolute)
        .display()
        .to_string())
}

fn narrower(current: &mut Option<Sourced<u32>>, value: Option<u32>, from: &str) {
    if let Some(value) = value
        && current.as_ref().is_none_or(|c| value < c.value)
    {
        *current = Some(Sourced {
            value,
            from: from.to_string(),
        });
    }
}

impl Accumulator {
    fn network(&mut self, layer: &Layer) -> Result<(), PolicyError> {
        let NetworkSection {
            allow,
            deny,
            block,
            routes,
        } = &layer.body.network;
        match (block, &self.blocked_by) {
            (Some(true), None) => self.blocked_by = Some(layer.label.clone()),
            (Some(false), Some(by)) => {
                return Err(layer_error(
                    layer,
                    "network.block",
                    format!("cannot turn the network back on: {by} blocked it"),
                ));
            }
            _ => {}
        }
        for entry in allow {
            let canonical = canonical_allow(entry)
                .map_err(|reason| layer_error(layer, "network.allow", reason))?;
            push_unique(&mut self.allow, canonical, &layer.label);
        }
        for entry in deny {
            parse_deny(entry).map_err(|reason| layer_error(layer, "network.deny", reason))?;
            push_unique(
                &mut self.deny,
                entry.trim().to_ascii_lowercase(),
                &layer.label,
            );
        }
        if !routes.is_empty() {
            RouteSet::new(routes.clone())
                .map_err(|error| layer_error(layer, "network.routes", error.to_string()))?;
        }
        for route in routes {
            if let Some(existing) = self.routes.iter().find(|r| {
                (r.value.host == route.host && r.value.port == route.port) || r.value.id == route.id
            }) {
                return Err(layer_error(
                    layer,
                    "network.routes",
                    format!(
                        "route {:?} for {}:{} collides with route {:?} from {}; composition cannot \
                         add rules to a route another layer declared",
                        route.id, route.host, route.port, existing.value.id, existing.from
                    ),
                ));
            }
            self.routes.push(Sourced {
                value: route.clone(),
                from: layer.label.clone(),
            });
        }
        Ok(())
    }

    fn secrets(&mut self, layer: &Layer) -> Result<(), PolicyError> {
        let SecretsSection { bind, deny } = &layer.body.secrets;
        for grant in bind {
            validate_secret_name(layer, "secrets.bind.name", &grant.name)?;
            for host in &grant.hosts {
                validate_host_only(layer, "secrets.bind.hosts", host)?;
            }
            match self.secrets.iter_mut().find(|s| s.value.name == grant.name) {
                None => self.secrets.push(Sourced {
                    value: grant.clone(),
                    from: layer.label.clone(),
                }),
                Some(existing) => {
                    if grant.hosts.is_empty() {
                        continue;
                    }
                    if existing.value.hosts.is_empty() {
                        existing.value.hosts = grant.hosts.clone();
                        continue;
                    }
                    if let Some(wider) = grant
                        .hosts
                        .iter()
                        .find(|host| !existing.value.hosts.contains(host))
                    {
                        return Err(layer_error(
                            layer,
                            "secrets.bind.hosts",
                            format!(
                                "secret {:?}: {wider:?} widens the destinations {} allowed ({}); \
                                 a later layer may only narrow them",
                                grant.name,
                                existing.from,
                                existing.value.hosts.join(", ")
                            ),
                        ));
                    }
                    existing.value.hosts = grant.hosts.clone();
                }
            }
        }
        for name in deny {
            validate_secret_name(layer, "secrets.deny", name)?;
            push_unique(&mut self.secret_deny, name.clone(), &layer.label);
        }
        Ok(())
    }

    fn shares(&mut self, layer: &Layer) -> Result<(), PolicyError> {
        let SharesSection { mount, deny } = &layer.body.shares;
        for share in mount {
            if !share.guest.starts_with('/') {
                return Err(layer_error(
                    layer,
                    "shares.mount.guest",
                    format!("{:?} must be an absolute guest path", share.guest),
                ));
            }
            let host = absolute_share_host(layer, &share.host)?;
            match self
                .shares
                .iter_mut()
                .find(|s| s.value.guest == share.guest)
            {
                Some(existing) if existing.value.host != host => {
                    return Err(layer_error(
                        layer,
                        "shares.mount.guest",
                        format!(
                            "{} is already mounted from {} by {}",
                            share.guest, existing.value.host, existing.from
                        ),
                    ));
                }
                Some(existing) => existing.value.writable &= share.writable,
                None => self.shares.push(Sourced {
                    value: ShareGrant {
                        host,
                        guest: share.guest.clone(),
                        writable: share.writable,
                    },
                    from: layer.label.clone(),
                }),
            }
        }
        for prefix in deny {
            let prefix = absolute_share_host(layer, prefix)?;
            push_unique(&mut self.share_deny, prefix, &layer.label);
        }
        Ok(())
    }

    fn env(&mut self, layer: &Layer) -> Result<(), PolicyError> {
        let EnvSection {
            allow,
            deny,
            readmit,
        } = &layer.body.env;
        for name in allow {
            validate_env_name(layer, "env.allow", name)?;
            push_unique(&mut self.env_allow, name.clone(), &layer.label);
        }
        for name in deny {
            validate_env_name(layer, "env.deny", name)?;
            push_unique(&mut self.env_deny, name.clone(), &layer.label);
        }
        if !readmit.is_empty() && layer.origin != LayerOrigin::User {
            return Err(layer_error(
                layer,
                "env.readmit",
                format!(
                    "re-admitting a denied variable is an escape hatch, honoured only in a \
                     user-authored profile; this is a {} layer",
                    layer.origin.as_str()
                ),
            ));
        }
        for name in readmit {
            validate_env_name(layer, "env.readmit", name)?;
            if classify(name).is_none() {
                return Err(layer_error(
                    layer,
                    "env.readmit",
                    format!("{name:?} is not on the denylist; list it under env.allow instead"),
                ));
            }
            push_unique(&mut self.env_readmit, name.clone(), &layer.label);
        }
        Ok(())
    }

    fn tools(&mut self, layer: &Layer) {
        let ToolsSection { allow, deny } = &layer.body.tools;
        for name in allow {
            push_unique(&mut self.tools_allow, name.clone(), &layer.label);
        }
        for name in deny {
            push_unique(&mut self.tools_deny, name.clone(), &layer.label);
        }
    }

    fn resources(&mut self, layer: &Layer) -> Result<(), PolicyError> {
        let ResourcesSection {
            cpu_millicores,
            wall_clock_secs,
            max_cpus,
            max_memory,
        } = &layer.body.resources;
        for (key, value) in [
            ("resources.cpu_millicores", cpu_millicores),
            ("resources.wall_clock_secs", wall_clock_secs),
            ("resources.max_cpus", max_cpus),
        ] {
            if *value == Some(0) {
                return Err(layer_error(layer, key, "must be greater than zero"));
            }
        }
        narrower(&mut self.cpu_millicores, *cpu_millicores, &layer.label);
        narrower(&mut self.wall_clock_secs, *wall_clock_secs, &layer.label);
        narrower(&mut self.max_cpus, *max_cpus, &layer.label);
        if let Some(raw) = max_memory {
            let mib = mvm_core::util::parse_human_size(raw).map_err(|error| {
                layer_error(layer, "resources.max_memory", format!("{error:#}"))
            })?;
            if mib == 0 {
                return Err(layer_error(
                    layer,
                    "resources.max_memory",
                    "must be greater than zero",
                ));
            }
            if self
                .max_memory
                .as_ref()
                .is_none_or(|m| u64::from(mib) < m.value.0)
            {
                self.max_memory = Some(Sourced {
                    value: (u64::from(mib), raw.clone()),
                    from: layer.label.clone(),
                });
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<ResolvedPolicy, PolicyError> {
        let mut provenance = BTreeMap::new();
        let mut notes = std::mem::take(&mut self.notes);

        // Network: a block drops everything; otherwise a deny drops what it covers.
        let (allow, routes) =
            if let Some(by) = &self.blocked_by {
                if !self.allow.is_empty() || !self.routes.is_empty() {
                    notes.push(format!(
                        "network is blocked by {by}; {} allowed host(s) and {} route(s) dropped",
                        self.allow.len(),
                        self.routes.len()
                    ));
                }
                provenance.insert("network.block".to_string(), by.clone());
                (Vec::new(), Vec::new())
            } else {
                let allow: Vec<Sourced<String>> = self
                    .allow
                    .into_iter()
                    .filter(|entry| {
                        let (host, port) = split_host_port(&entry.value);
                        match self.deny.iter().find(|d| deny_covers(&d.value, host, port)) {
                            Some(deny) => {
                                notes.push(format!(
                                    "{} (allowed by {}) is denied by {}",
                                    entry.value, entry.from, deny.from
                                ));
                                false
                            }
                            None => true,
                        }
                    })
                    .collect();
                let routes: Vec<Sourced<EgressRoute>> =
                    self.routes
                        .into_iter()
                        .filter(|route| {
                            match self.deny.iter().find(|d| {
                                deny_covers(&d.value, &route.value.host, route.value.port)
                            }) {
                                Some(deny) => {
                                    notes.push(format!(
                                        "route {:?} (from {}) is denied by {}",
                                        route.value.id, route.from, deny.from
                                    ));
                                    false
                                }
                                None => true,
                            }
                        })
                        .collect();
                (allow, routes)
            };
        for entry in &allow {
            provenance.insert(format!("network.allow.{}", entry.value), entry.from.clone());
        }
        for route in &routes {
            provenance.insert(
                format!("network.routes.{}", route.value.id),
                route.from.clone(),
            );
        }
        let route_values: Vec<EgressRoute> = routes.into_iter().map(|r| r.value).collect();
        if !route_values.is_empty() {
            RouteSet::new(route_values.clone()).map_err(|error| {
                PolicyError::new("resolved policy", error.to_string()).at_key("network.routes")
            })?;
        }

        let secrets: Vec<SecretGrant> = self
            .secrets
            .into_iter()
            .filter(|secret| {
                match self
                    .secret_deny
                    .iter()
                    .find(|d| d.value == secret.value.name)
                {
                    Some(deny) => {
                        notes.push(format!(
                            "secret {:?} (bound by {}) is denied by {}",
                            secret.value.name, secret.from, deny.from
                        ));
                        false
                    }
                    None => {
                        provenance.insert(
                            format!("secrets.bind.{}", secret.value.name),
                            secret.from.clone(),
                        );
                        true
                    }
                }
            })
            .map(|secret| secret.value)
            .collect();
        if self.blocked_by.is_some() && !secrets.is_empty() {
            notes.push(
                "secrets are bound but the network is blocked, so no request can carry them"
                    .to_string(),
            );
        }

        let shares: Vec<ShareGrant> = self
            .shares
            .into_iter()
            .filter(|share| {
                match self
                    .share_deny
                    .iter()
                    .find(|d| Path::new(&share.value.host).starts_with(&d.value))
                {
                    Some(deny) => {
                        notes.push(format!(
                            "share {} (from {}) comes from a path denied by {}",
                            share.value.host, share.from, deny.from
                        ));
                        false
                    }
                    None => {
                        provenance.insert(
                            format!("shares.mount.{}", share.value.guest),
                            share.from.clone(),
                        );
                        true
                    }
                }
            })
            .map(|share| share.value)
            .collect();

        let env_deny: Vec<String> = self.env_deny.iter().map(|d| d.value.clone()).collect();
        let readmit: Vec<String> = self
            .env_readmit
            .iter()
            .map(|r| r.value.clone())
            .filter(|name| !env_deny.contains(name))
            .collect();
        let mut env_allow = Vec::new();
        for entry in self.env_allow {
            if env_deny.contains(&entry.value) {
                notes.push(format!(
                    "variable {} (allowed by {}) is denied",
                    entry.value, entry.from
                ));
                continue;
            }
            if let Some(family) = classify(&entry.value)
                && !readmit.contains(&entry.value)
            {
                return Err(PolicyError::new(
                    &entry.from,
                    format!(
                        "{} is a {} variable the hygiene denylist refuses; re-admit it with \
                         env.readmit in a user-authored profile",
                        entry.value,
                        family.label()
                    ),
                )
                .at_key("env.allow"));
            }
            env_allow.push(entry.value);
        }

        let tools_deny: Vec<String> = self.tools_deny.iter().map(|d| d.value.clone()).collect();
        let tools_allow: Vec<String> = self
            .tools_allow
            .into_iter()
            .map(|t| t.value)
            .filter(|t| !tools_deny.contains(t))
            .collect();

        for (key, bound) in [
            ("resources.cpu_millicores", &self.cpu_millicores),
            ("resources.wall_clock_secs", &self.wall_clock_secs),
            ("resources.max_cpus", &self.max_cpus),
        ] {
            if let Some(bound) = bound {
                provenance.insert(key.to_string(), bound.from.clone());
            }
        }
        if let Some(memory) = &self.max_memory {
            provenance.insert("resources.max_memory".to_string(), memory.from.clone());
        }

        let policy = PolicyBody {
            network: NetworkSection {
                allow: allow.into_iter().map(|a| a.value).collect(),
                deny: self.deny.into_iter().map(|d| d.value).collect(),
                block: self.blocked_by.is_some().then_some(true),
                routes: route_values,
            },
            secrets: SecretsSection {
                bind: secrets,
                deny: self.secret_deny.into_iter().map(|d| d.value).collect(),
            },
            shares: SharesSection {
                mount: shares,
                deny: self.share_deny.into_iter().map(|d| d.value).collect(),
            },
            env: EnvSection {
                allow: env_allow,
                deny: env_deny,
                readmit,
            },
            tools: ToolsSection {
                allow: tools_allow,
                deny: tools_deny,
            },
            resources: ResourcesSection {
                cpu_millicores: self.cpu_millicores.map(|c| c.value),
                wall_clock_secs: self.wall_clock_secs.map(|w| w.value),
                max_cpus: self.max_cpus.map(|m| m.value),
                max_memory: self.max_memory.map(|m| m.value.1),
            },
        };
        Ok(ResolvedPolicy {
            policy,
            layers: Vec::new(),
            provenance,
            notes,
            backend_conditioned: false,
        })
    }
}

#[cfg(test)]
#[path = "merge_tests.rs"]
mod tests;
