//! Connect the local client to the stdio MCP adapter.

use std::io;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use mvm_client::policy_profiles::{Platform, PolicySelection, PolicyStore, ProjectPolicy, resolve};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub transport: Transport,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Transport {
    /// Read and write newline-delimited JSON-RPC on stdin/stdout
    Stdio {
        /// Bind drive tools to this machine when its signed plan grants them
        #[arg(long)]
        machine: Option<String>,
    },
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    match args.transport {
        Transport::Stdio { machine } => {
            let client: Arc<dyn mvm_client::MvmClient> = Arc::new(mvm_client::LocalBackend::new());
            let drive = machine
                .as_deref()
                .map(mvm_client::drive::LocalDrive::bind)
                .transpose()?
                .flatten();
            reject_legacy_tool_policy(None)?;
            let server = crate::mcp::McpServer::new(client);
            let server = match drive {
                Some(drive) => server.with_drive(Arc::new(drive)),
                None => server,
            };
            let stdin = io::stdin();
            let stdout = io::stdout();
            server.serve(stdin.lock(), stdout.lock())?;
            Ok(())
        }
    }
}

fn reject_legacy_tool_policy(project: Option<&Path>) -> Result<()> {
    let dir = project.unwrap_or_else(|| Path::new("."));
    let project = match mvm_core::manifest::manifest_in_dir(dir)? {
        Some(path) => {
            let manifest = mvm_core::manifest::Manifest::read_file(&path)?;
            Some(ProjectPolicy::from_manifest(&path, &manifest))
        }
        None => None,
    };
    if let Some(selection) = PolicySelection::for_launch(&[], project)? {
        let backend = mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name());
        resolve(
            &PolicyStore::from_config(),
            &selection,
            Platform::current(Some(backend)),
        )
        .context("resolving the project policy for MCP")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn old_project_tool_rules_refuse_mcp_startup() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("mvm.toml"),
            "[policy]\nprofile = \"./legacy.toml\"\n",
        )
        .unwrap();
        std::fs::write(
            project.path().join("legacy.toml"),
            "[overrides.tools]\nallow = [\"read\"]\n",
        )
        .unwrap();
        let error = reject_legacy_tool_policy(Some(project.path()))
            .expect_err("tool policy must not be ignored");
        assert!(format!("{error:#}").contains("tools"), "{error:#}");
    }
}
