//! `mvmctl why` — answer one policy question without booting a workload.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{ArgGroup, Args as ClapArgs};
use mvm_client::policy_profiles::query::{PolicyAnswer, PolicyQuery, answer};
use mvm_client::policy_profiles::{
    Platform, PolicySelection, PolicyStore, ProjectPolicy, ResolvedManifest, ResolvedPolicy,
    resolve,
};
use mvm_contract::protocol::vm_backend::BackendKind;

#[derive(ClapArgs, Debug, Clone)]
#[command(group(
    ArgGroup::new("subject")
        .required(true)
        .multiple(false)
        .args(["host", "path", "tool", "secret"])
))]
pub(in crate::commands) struct Args {
    /// Ask whether HOST[:PORT] is reachable (port defaults to 443)
    #[arg(long, value_name = "HOST[:PORT]")]
    pub host: Option<String>,
    /// Ask whether this host path is shared with the workload
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Ask whether the authored policy allows this tool
    #[arg(long, value_name = "TOOL")]
    pub tool: Option<String>,
    /// Ask whether the authored policy binds this stored secret
    #[arg(long, value_name = "SECRET")]
    pub secret: Option<String>,
    /// Resolve this profile instead of the project's `[policy]`
    #[arg(long, value_name = "NAME|PATH", conflicts_with = "plan")]
    pub profile: Option<String>,
    /// Query a resolved manifest written by `mvmctl policy resolve`
    #[arg(long, value_name = "FILE", conflicts_with_all = ["profile", "project", "backend"])]
    pub plan: Option<PathBuf>,
    /// Project directory whose mvm.toml policy applies (default: discover from .)
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,
    /// Resolve platform conditions for this backend (default: the host's)
    #[arg(long, value_name = "BACKEND", value_parser = parse_backend)]
    pub backend: Option<BackendKind>,
    /// Emit a machine-readable answer
    #[arg(long)]
    pub json: bool,
}

fn parse_backend(raw: &str) -> Result<BackendKind, String> {
    serde_json::from_value(serde_json::Value::String(raw.replace('-', "_")))
        .map_err(|_| format!("unknown backend {raw:?}"))
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let resolved = resolve_policy(&args)?;
    let query = selected_query(&args)?;
    let result = answer(&resolved, query).map_err(anyhow::Error::msg)?;
    if args.json {
        crate::json_out::emit_json(&result)
    } else {
        print_answer(&result);
        Ok(())
    }
}

fn selected_query(args: &Args) -> Result<PolicyQuery> {
    if let Some(host) = &args.host {
        return Ok(PolicyQuery::Host(host.clone()));
    }
    if let Some(path) = &args.path {
        let absolute = std::path::absolute(path)
            .with_context(|| format!("resolving path {}", path.display()))?;
        return Ok(PolicyQuery::Path(absolute));
    }
    if let Some(tool) = &args.tool {
        return Ok(PolicyQuery::Tool(tool.clone()));
    }
    if let Some(secret) = &args.secret {
        return Ok(PolicyQuery::Secret(secret.clone()));
    }
    unreachable!("clap requires exactly one why subject")
}

fn resolve_policy(args: &Args) -> Result<ResolvedPolicy> {
    if let Some(path) = &args.plan {
        let manifest = ResolvedManifest::read(path)?;
        return Ok(ResolvedPolicy {
            policy: manifest.policy,
            layers: Vec::new(),
            provenance: Default::default(),
            notes: Vec::new(),
            backend_conditioned: false,
        });
    }

    let project = project_policy(args)?;
    let Some(selection) = PolicySelection::for_launch(args.profile.as_deref(), project)? else {
        return Ok(ResolvedPolicy::empty());
    };
    let backend = args
        .backend
        .unwrap_or_else(|| mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name()));
    Ok(resolve(
        &PolicyStore::from_config(),
        &selection,
        Platform::current(Some(backend)),
    )?)
}

fn project_policy(args: &Args) -> Result<Option<ProjectPolicy>> {
    if args.profile.is_some() && args.project.is_none() {
        return Ok(None);
    }
    let start = args.project.clone().unwrap_or_else(|| PathBuf::from("."));
    let path = mvm_core::manifest::discover_manifest_from_dir(&start)?;
    path.map(|path| {
        let manifest = mvm_core::manifest::Manifest::read_file(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        Ok(ProjectPolicy::from_manifest(&path, &manifest))
    })
    .transpose()
}

fn print_answer(answer: &PolicyAnswer) {
    println!(
        "{}: {} {}",
        if answer.allowed { "ALLOW" } else { "DENY" },
        answer.subject,
        answer.value
    );
    println!("reason: {}", answer.reason);
    if let Some(rule) = &answer.matched {
        println!("matched: {rule}");
    }
    if !answer.enforced {
        println!("note: this policy dimension is recorded but not enforced by the runtime yet");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_project_is_default_deny() {
        let dir = tempfile::tempdir().unwrap();
        let args = Args {
            host: Some("api.example.com".into()),
            path: None,
            tool: None,
            secret: None,
            profile: None,
            plan: None,
            project: Some(dir.path().to_path_buf()),
            backend: Some(BackendKind::Firecracker),
            json: false,
        };
        let resolved = resolve_policy(&args).unwrap();
        let result = answer(&resolved, selected_query(&args).unwrap()).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn a_resolved_manifest_is_queried_directly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{"policy":{"network":{"allow":["api.example.com:443"]}}}"#,
        )
        .unwrap();
        let args = Args {
            host: Some("api.example.com".into()),
            path: None,
            tool: None,
            secret: None,
            profile: None,
            plan: Some(path),
            project: None,
            backend: None,
            json: true,
        };
        let resolved = resolve_policy(&args).unwrap();
        assert!(
            answer(&resolved, selected_query(&args).unwrap())
                .unwrap()
                .allowed
        );
    }
}
