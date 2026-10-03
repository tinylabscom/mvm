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
    /// HTTP method for a routed host query; requires --request-path
    #[arg(long, value_name = "METHOD", requires_all = ["host", "request_path"])]
    pub method: Option<String>,
    /// HTTP path for a routed host query; requires --method
    #[arg(long, value_name = "PATH", requires_all = ["host", "method"])]
    pub request_path: Option<String>,
    /// Ask whether this host path is shared with the workload
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Ask whether the authored policy allows this tool
    #[arg(long, value_name = "TOOL")]
    pub tool: Option<String>,
    /// Ask whether the authored policy binds this stored secret
    #[arg(long, value_name = "SECRET")]
    pub secret: Option<String>,
    /// Resolve these profiles instead of the project's `[policy]` (repeatable;
    /// later profiles compose over the earlier ones and take precedence)
    #[arg(long, value_name = "NAME|PATH", conflicts_with = "plan")]
    pub profile: Vec<String>,
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
        if let (Some(method), Some(path)) = (&args.method, &args.request_path) {
            return Ok(PolicyQuery::Http {
                host: host.clone(),
                method: method.clone(),
                path: path.clone(),
            });
        }
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
    let selection = PolicySelection::for_launch(
        &args.profile,
        project.as_ref().map(|(policy, _)| policy.clone()),
    )?;
    let backend = args
        .backend
        .unwrap_or_else(|| mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name()));
    let mut resolved = match selection {
        Some(selection) => resolve(
            &PolicyStore::from_config(),
            &selection,
            Platform::current(Some(backend)),
        )?,
        None => ResolvedPolicy::empty(),
    };
    if let Some((_, manifest)) = project {
        add_project_launch_bindings(&mut resolved, &manifest)?;
    }
    Ok(resolved)
}

fn project_policy(args: &Args) -> Result<Option<(ProjectPolicy, mvm_core::manifest::Manifest)>> {
    if !args.profile.is_empty() && args.project.is_none() {
        return Ok(None);
    }
    let start = args.project.clone().unwrap_or_else(|| PathBuf::from("."));
    let path = mvm_core::manifest::discover_manifest_from_dir(&start)?;
    path.map(|path| {
        let manifest = mvm_core::manifest::Manifest::read_file(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        Ok((ProjectPolicy::from_manifest(&path, &manifest), manifest))
    })
    .transpose()
}

fn add_project_launch_bindings(
    resolved: &mut ResolvedPolicy,
    manifest: &mvm_core::manifest::Manifest,
) -> Result<()> {
    use mvm_client::policy_profiles::model::SecretGrant;

    let mut routes = manifest.network.routes.clone();
    routes.extend(resolved.policy.network.routes.iter().cloned());
    resolved.policy.network.routes =
        mvm_client::admission::run_routes::resolve_run_routes(&[], &routes)?.routes;
    for (name, spec) in &manifest.secrets {
        if !resolved
            .policy
            .secrets
            .bind
            .iter()
            .any(|grant| grant.name == *name)
        {
            resolved.policy.secrets.bind.push(SecretGrant {
                name: name.clone(),
                hosts: spec.hosts.clone(),
            });
        }
    }
    Ok(())
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
            method: None,
            request_path: None,
            path: None,
            tool: None,
            secret: None,
            profile: Vec::new(),
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
            method: None,
            request_path: None,
            path: None,
            tool: None,
            secret: None,
            profile: Vec::new(),
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

    #[test]
    fn a_project_manifest_contributes_secret_bindings_and_endpoint_routes() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "flake = \".\"\n[secrets]\napi = { hosts = [\"api.example.com\"] }\n[[network.routes]]\nid = \"api\"\nhost = \"api.example.com\"\nintercept = true\nrules = [{ method = \"GET\", path = \"/public/**\", outcome = \"allow\" }]\n",
        )
        .unwrap();
        let mut args = Args {
            host: None,
            method: None,
            request_path: None,
            path: None,
            tool: None,
            secret: Some("api".into()),
            profile: Vec::new(),
            plan: None,
            project: Some(project.path().to_path_buf()),
            backend: Some(BackendKind::Firecracker),
            json: true,
        };
        let resolved = resolve_policy(&args).unwrap();
        assert!(
            answer(&resolved, selected_query(&args).unwrap())
                .unwrap()
                .allowed
        );
        args.secret = None;
        args.host = Some("api.example.com".into());
        args.method = Some("GET".into());
        args.request_path = Some("/public/x".into());
        assert!(
            answer(&resolved, selected_query(&args).unwrap())
                .unwrap()
                .allowed
        );
        args.method = Some("POST".into());
        assert!(
            !answer(&resolved, selected_query(&args).unwrap())
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn project_secret_cannot_override_an_authored_deny() {
        let manifest = mvm_core::manifest::Manifest::from_toml_str(
            "flake = \".\"\n[secrets]\napi = { hosts = [\"api.example.com\"] }\n",
        )
        .unwrap();
        let mut resolved = ResolvedPolicy::empty();
        resolved.policy.secrets.deny.push("api".into());
        add_project_launch_bindings(&mut resolved, &manifest).unwrap();
        let result = answer(&resolved, PolicyQuery::Secret("api".into())).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.matched.as_deref(), Some("secrets.deny = \"api\""));
    }
}
