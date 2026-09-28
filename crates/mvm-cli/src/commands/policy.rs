//! `mvmctl policy` — authored workload policy: resolve, show, validate and
//! compare profiles, and list the groups they compose.
//!
//! This is the workload's own policy — profiles and groups a user or project
//! writes, resolved on this host. Tenant policy bundles and their rollout are
//! a control-plane concern and are not here. Everything below is a thin shell
//! over `mvm_client::policy_profiles`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use mvm_client::policy_profiles::builtin;
use mvm_client::policy_profiles::model::{GroupFile, ProfileFile};
use mvm_client::policy_profiles::resolve::resolve_file;
use mvm_client::policy_profiles::{
    Platform, PolicyBody, PolicySelection, PolicyStore, ProjectPolicy, ResolvedManifest,
    ResolvedPolicy, resolve,
};
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::user_config::MvmConfig;
use serde::Serialize;

use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PolicyAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PolicyAction {
    /// Resolve a profile into the manifest `run --plan` accepts
    Resolve(ResolveArgs),
    /// Show the effective policy (toml, json, or the plan it yields)
    Show(ShowArgs),
    /// Check a profile or group file; --strict refuses warnings
    Validate(ValidateArgs),
    /// Compare what two profiles allow and deny
    Diff(DiffArgs),
    /// List the built-in groups and profiles, and your own
    Groups(GroupsArgs),
}

/// Which policy a subcommand looks at.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct Target {
    /// Profile NAME or PATH (default: the project's `[policy]` table)
    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Project directory whose mvm.toml `[policy]` applies (default: .)
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,
    /// Match `[[when]]` blocks against this backend (default: the host's)
    #[arg(long, value_name = "BACKEND", value_parser = parse_backend)]
    pub backend: Option<BackendKind>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ResolveArgs {
    #[command(flatten)]
    pub target: Target,
    /// Write the manifest here instead of stdout
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// `show` output formats.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::commands) enum ShowFormat {
    /// The merged policy, in the authoring format.
    #[default]
    Toml,
    /// The merged policy with its layers, provenance and notes.
    Json,
    /// What the signed plan would carry: grants, egress, routes, bindings.
    Plan,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ShowArgs {
    #[command(flatten)]
    pub target: Target,
    /// Output format
    #[arg(long, value_enum, default_value = "toml")]
    pub format: ShowFormat,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ValidateArgs {
    #[command(flatten)]
    pub target: Target,
    /// Treat every warning as an error, and check bound secrets exist
    #[arg(long)]
    pub strict: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct DiffArgs {
    /// The first profile, NAME or PATH
    #[arg(value_name = "A")]
    pub a: String,
    /// The second profile, NAME or PATH
    #[arg(value_name = "B")]
    pub b: String,
    /// Match `[[when]]` blocks against this backend (default: the host's)
    #[arg(long, value_name = "BACKEND", value_parser = parse_backend)]
    pub backend: Option<BackendKind>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct GroupsArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

fn parse_backend(raw: &str) -> Result<BackendKind, String> {
    serde_json::from_value(serde_json::Value::String(raw.replace('-', "_")))
        .map_err(|_| format!("unknown backend {raw:?}"))
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        PolicyAction::Resolve(a) => resolve_cmd(a),
        PolicyAction::Show(a) => show(a),
        PolicyAction::Validate(a) => validate(a),
        PolicyAction::Diff(a) => diff(a),
        PolicyAction::Groups(a) => groups(a),
    }
}

fn platform(backend: Option<BackendKind>) -> Platform {
    Platform::current(Some(backend.unwrap_or_else(|| {
        mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name())
    })))
}

/// Resolve the target the way a launch would: the named profile, if any,
/// with the project's contribution (its `[policy]` table and
/// `[network] allow_hosts`) from `--project`, or from `.` when no profile is
/// named.
fn resolve_target(target: &Target) -> Result<ResolvedPolicy> {
    let project_dir = match (&target.project, &target.profile) {
        (Some(dir), _) => Some(dir.clone()),
        (None, None) => Some(PathBuf::from(".")),
        (None, Some(_)) => None,
    };
    let project = match &project_dir {
        Some(dir) => match mvm_core::manifest::manifest_in_dir(dir)? {
            Some(path) => {
                let manifest = mvm_core::manifest::Manifest::read_file(&path)?;
                Some(ProjectPolicy::from_manifest(&path, &manifest))
            }
            None if target.profile.is_none() => bail!(
                "no profile named and no mvm.toml in {}; name a profile or pass --project",
                dir.display()
            ),
            None => None,
        },
        None => None,
    };
    let selection = PolicySelection::for_launch(target.profile.as_deref(), project)?
        .context("the project's mvm.toml has no [policy] table and no [network] allow_hosts")?;
    Ok(resolve(
        &PolicyStore::from_config(),
        &selection,
        platform(target.backend),
    )?)
}

fn resolve_cmd(args: ResolveArgs) -> Result<()> {
    let resolved = resolve_target(&args.target)?;
    for note in &resolved.notes {
        ui::warn(note);
    }
    let mut json = serde_json::to_string_pretty(&ResolvedManifest::from_resolved(&resolved))?;
    json.push('\n');
    match &args.output {
        Some(path) => {
            std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
            ui::success(&format!(
                "Wrote {}; run it with `mvmctl run --plan {}`",
                path.display(),
                path.display()
            ));
        }
        None => print!("{json}"),
    }
    Ok(())
}

fn show(args: ShowArgs) -> Result<()> {
    let resolved = resolve_target(&args.target)?;
    match args.format {
        ShowFormat::Toml => {
            for layer in &resolved.layers {
                println!("# layer: {} ({})", layer.label, layer.origin.as_str());
            }
            for note in &resolved.notes {
                println!("# note: {note}");
            }
            print!("{}", toml::to_string_pretty(&resolved.policy)?);
        }
        ShowFormat::Json => crate::json_out::emit_json(&resolved)?,
        ShowFormat::Plan => {
            let config = mvm_core::user_config::load(None);
            let preview = mvm_client::policy_profiles::preview::preview(&resolved.policy, &config)?;
            crate::json_out::emit_json(&preview)?;
        }
    }
    Ok(())
}

/// A path to a file that exists is validated as that file (a profile, or
/// failing that a group); anything else as a profile reference.
fn validate(args: ValidateArgs) -> Result<()> {
    let resolved = match args.target.profile.as_deref().map(Path::new) {
        Some(path) if path.is_file() => resolve_file(
            &PolicyStore::from_config(),
            path,
            platform(args.target.backend),
        )?,
        _ => resolve_target(&args.target)?,
    };
    let mut problems: Vec<String> = resolved.notes.clone();
    if !resolved.policy.tools.is_empty() {
        problems.push(
            "the [tools] section is recorded but not enforced yet; nothing stops a tool it \
             denies"
                .to_string(),
        );
    }
    if args.strict {
        problems.extend(unknown_secrets(&resolved.policy)?);
    }
    for problem in &problems {
        ui::warn(problem);
    }
    if args.strict && !problems.is_empty() {
        bail!(
            "policy has {} warning(s) and --strict refuses them",
            problems.len()
        );
    }
    ui::success(&format!(
        "policy is valid ({} layer(s), enforcement-relevant sections: {})",
        resolved.layers.len(),
        sections(&resolved.policy).join(", ")
    ));
    Ok(())
}

/// Bound secrets that are not stored, or whose stored allow-list does not
/// admit the policy's destinations.
fn unknown_secrets(policy: &PolicyBody) -> Result<Vec<String>> {
    if policy.secrets.bind.is_empty() {
        return Ok(Vec::new());
    }
    let service =
        mvm_client::secret::SecretService::local().context("opening the local secret service")?;
    let mut problems = Vec::new();
    for grant in &policy.secrets.bind {
        let spec = mvm_client::admission::run_secrets::RunSecretSpec {
            name: grant.name.clone(),
            destinations: grant.hosts.clone(),
        };
        if let Err(error) =
            mvm_client::admission::run_secrets::run_secret_refs(&service, "local", &[spec])
        {
            problems.push(format!("secret {:?}: {error:#}", grant.name));
        }
    }
    Ok(problems)
}

fn sections(policy: &PolicyBody) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (name, empty) in [
        ("network", policy.network.is_empty()),
        ("secrets", policy.secrets.is_empty()),
        ("shares", policy.shares.is_empty()),
        ("env", policy.env.is_empty()),
        ("tools", policy.tools.is_empty()),
        ("resources", policy.resources.is_empty()),
    ] {
        if !empty {
            out.push(name);
        }
    }
    if out.is_empty() {
        out.push("none");
    }
    out
}

/// One section's difference between two policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::commands) struct DiffLine {
    pub key: String,
    /// `+` only in B, `-` only in A.
    pub change: char,
    pub value: String,
}

/// Every item that is in one policy and not the other, section by section.
pub(in crate::commands) fn policy_diff(a: &PolicyBody, b: &PolicyBody) -> Vec<DiffLine> {
    fn items(policy: &PolicyBody) -> BTreeSet<(String, String)> {
        let mut set = BTreeSet::new();
        let mut add = |key: &str, value: String| {
            set.insert((key.to_string(), value));
        };
        policy
            .network
            .allow
            .iter()
            .for_each(|v| add("network.allow", v.clone()));
        policy
            .network
            .deny
            .iter()
            .for_each(|v| add("network.deny", v.clone()));
        if policy.network.block == Some(true) {
            add("network.block", "true".into());
        }
        policy
            .network
            .routes
            .iter()
            .for_each(|r| add("network.routes", format!("{} {}:{}", r.id, r.host, r.port)));
        policy.secrets.bind.iter().for_each(|s| {
            add("secrets.bind", format!("{}:{}", s.name, s.hosts.join(",")));
        });
        policy
            .secrets
            .deny
            .iter()
            .for_each(|v| add("secrets.deny", v.clone()));
        policy.shares.mount.iter().for_each(|m| {
            add(
                "shares.mount",
                format!(
                    "{}:{}:{}",
                    m.host,
                    m.guest,
                    if m.writable { "rw" } else { "ro" }
                ),
            );
        });
        policy
            .shares
            .deny
            .iter()
            .for_each(|v| add("shares.deny", v.clone()));
        policy
            .env
            .allow
            .iter()
            .for_each(|v| add("env.allow", v.clone()));
        policy
            .env
            .deny
            .iter()
            .for_each(|v| add("env.deny", v.clone()));
        policy
            .env
            .readmit
            .iter()
            .for_each(|v| add("env.readmit", v.clone()));
        policy
            .tools
            .allow
            .iter()
            .for_each(|v| add("tools.allow", v.clone()));
        policy
            .tools
            .deny
            .iter()
            .for_each(|v| add("tools.deny", v.clone()));
        let r = &policy.resources;
        if let Some(v) = r.cpu_millicores {
            add("resources.cpu_millicores", v.to_string());
        }
        if let Some(v) = r.wall_clock_secs {
            add("resources.wall_clock_secs", v.to_string());
        }
        if let Some(v) = r.max_cpus {
            add("resources.max_cpus", v.to_string());
        }
        if let Some(v) = &r.max_memory {
            add("resources.max_memory", v.clone());
        }
        set
    }
    let (left, right) = (items(a), items(b));
    let mut lines: Vec<DiffLine> = left
        .difference(&right)
        .map(|(key, value)| DiffLine {
            key: key.clone(),
            change: '-',
            value: value.clone(),
        })
        .chain(right.difference(&left).map(|(key, value)| DiffLine {
            key: key.clone(),
            change: '+',
            value: value.clone(),
        }))
        .collect();
    lines.sort_by(|x, y| (&x.key, &x.value, x.change).cmp(&(&y.key, &y.value, y.change)));
    lines
}

fn diff(args: DiffArgs) -> Result<()> {
    let target = |profile: &str| Target {
        profile: Some(profile.to_string()),
        project: None,
        backend: args.backend,
    };
    let a = resolve_target(&target(&args.a))?;
    let b = resolve_target(&target(&args.b))?;
    let lines = policy_diff(&a.policy, &b.policy);
    if args.json {
        return crate::json_out::emit_json(&lines);
    }
    if lines.is_empty() {
        println!("{} and {} resolve to the same policy", args.a, args.b);
    }
    for line in &lines {
        println!("{} {} {}", line.change, line.key, line.value);
    }
    Ok(())
}

/// One entry of `policy groups`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::commands) struct Listed {
    pub kind: &'static str,
    pub name: String,
    pub origin: &'static str,
    pub required: bool,
    pub description: Option<String>,
}

pub(in crate::commands) fn listing(store: &PolicyStore) -> Result<Vec<Listed>> {
    let mut out = Vec::new();
    for (name, text) in builtin::GROUPS {
        let group: GroupFile = toml::from_str(text)?;
        out.push(Listed {
            kind: "group",
            name: (*name).to_string(),
            origin: "built-in",
            required: group.required,
            description: group.description,
        });
    }
    for (name, text) in builtin::PROFILES {
        let profile: ProfileFile = toml::from_str(text)?;
        out.push(Listed {
            kind: "profile",
            name: (*name).to_string(),
            origin: "built-in",
            required: false,
            description: profile.description,
        });
    }
    for (kind, dir) in [
        ("group", store.groups_dir()),
        ("profile", store.profiles_dir()),
    ] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut names: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .collect();
        names.sort();
        for path in names {
            let text = std::fs::read_to_string(&path)?;
            let (required, description) = if kind == "group" {
                let group: GroupFile =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                (group.required, group.description)
            } else {
                let profile: ProfileFile =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                (false, profile.description)
            };
            out.push(Listed {
                kind,
                name: path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                origin: "user",
                required,
                description,
            });
        }
    }
    Ok(out)
}

fn groups(args: GroupsArgs) -> Result<()> {
    let listed = listing(&PolicyStore::from_config())?;
    if args.json {
        return crate::json_out::emit_json(&listed);
    }
    for item in &listed {
        println!(
            "{:<8} {:<16} {:<9}{} {}",
            item.kind,
            item.name,
            item.origin,
            if item.required { " required" } else { "" },
            item.description.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::policy_profiles::model::{NetworkSection, ResourcesSection};

    #[test]
    fn backends_parse_by_their_snake_or_kebab_name() {
        assert_eq!(parse_backend("firecracker"), Ok(BackendKind::Firecracker));
        assert_eq!(
            parse_backend("apple-container"),
            Ok(BackendKind::AppleContainer)
        );
        assert!(parse_backend("vmware").is_err());
    }

    #[test]
    fn a_diff_lists_what_each_side_has_alone() {
        let a = PolicyBody {
            network: NetworkSection {
                allow: vec!["a.test:443".into(), "both.test:443".into()],
                ..NetworkSection::default()
            },
            ..PolicyBody::default()
        };
        let b = PolicyBody {
            network: NetworkSection {
                allow: vec!["both.test:443".into(), "b.test:443".into()],
                block: Some(true),
                ..NetworkSection::default()
            },
            resources: ResourcesSection {
                max_cpus: Some(2),
                ..ResourcesSection::default()
            },
            ..PolicyBody::default()
        };
        let lines: Vec<String> = policy_diff(&a, &b)
            .iter()
            .map(|l| format!("{} {} {}", l.change, l.key, l.value))
            .collect();
        assert_eq!(
            lines,
            [
                "- network.allow a.test:443",
                "+ network.allow b.test:443",
                "+ network.block true",
                "+ resources.max_cpus 2",
            ]
        );
        assert!(policy_diff(&a, &a).is_empty());
    }

    #[test]
    fn the_listing_names_every_built_in_and_user_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::at(dir.path());
        std::fs::create_dir_all(store.groups_dir()).unwrap();
        std::fs::write(
            store.groups_dir().join("mine.toml"),
            "description = \"m\"\nrequired = true\n",
        )
        .unwrap();
        let listed = listing(&store).unwrap();
        assert_eq!(
            listed.iter().filter(|l| l.origin == "built-in").count(),
            builtin::GROUPS.len() + builtin::PROFILES.len()
        );
        let mine = listed.iter().find(|l| l.name == "mine").unwrap();
        assert!(mine.required && mine.origin == "user" && mine.kind == "group");
    }
}
