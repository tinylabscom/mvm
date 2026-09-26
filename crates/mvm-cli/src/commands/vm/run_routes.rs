//! The endpoint routes a launch carries: the project manifest's
//! `[[network.routes]]` and the `--allow-endpoint` flags.
//!
//! Resolution lives in `mvm_client::admission::run_routes`; this reads the
//! project manifest the run names, if it names one on this host.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_client::admission::run_routes::{RunRoutes, resolve_run_routes};

use super::exec::RunArgs;

/// Resolve the launch's routes before anything boots.
pub(in crate::commands) fn launch_routes(args: &RunArgs) -> Result<RunRoutes> {
    let manifest_routes = project_manifest(args)?
        .map(|manifest| manifest.network.routes)
        .unwrap_or_default();
    resolve_run_routes(&args.allow_endpoint, &manifest_routes)
}

/// The manifest `--manifest` points at, or the one in a local `--flake`
/// directory. A registered manifest name or a remote flake has no local file.
fn project_manifest(args: &RunArgs) -> Result<Option<mvm_core::manifest::Manifest>> {
    let path = match (args.manifest.as_deref(), args.flake.as_deref()) {
        (Some(manifest), _) => {
            mvm_core::manifest::resolve_manifest_config_path(Path::new(manifest)).ok()
        }
        (None, Some(flake)) if Path::new(flake).is_dir() => {
            mvm_core::manifest::manifest_in_dir(Path::new(flake))?
        }
        _ => None,
    };
    path.map(|path| {
        mvm_core::manifest::Manifest::read_file(&path)
            .with_context(|| format!("reading {} for its network routes", path.display()))
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_flake_manifest_contributes_its_routes_and_a_flag_adds_another() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "flake = \".\"\n[[network.routes]]\nid = \"github\"\nhost = \"api.github.com\"\nintercept = true\nrules = [{ method = \"GET\", path = \"/repos/org/**\", outcome = \"allow\" }]\n",
        )
        .unwrap();
        let args = RunArgs {
            flake: Some(project.path().display().to_string()),
            allow_endpoint: vec!["GET https://example.com/docs/**".into()],
            ..RunArgs::default()
        };
        let routes = launch_routes(&args).unwrap();
        assert_eq!(routes.routes.len(), 2);
        assert_eq!(routes.routes[0].id, "github");
        assert_eq!(
            routes.with_allow_host(&["api.github.com:443".into()]),
            ["api.github.com:443", "example.com:443"]
        );
    }

    #[test]
    fn a_run_with_neither_carries_no_routes() {
        assert!(launch_routes(&RunArgs::default()).unwrap().is_empty());
    }
}
