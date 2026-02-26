use anyhow::{Context, Result};
use std::collections::BTreeMap;

use mvm_core::build_env::ShellEnvironment;

use crate::scripts::render_script;

/// Build the mvm-guest-agent binary via Nix (cached in the Nix store).
///
/// Returns the absolute path to the built binary.
pub fn build_guest_agent(env: &dyn ShellEnvironment) -> Result<String> {
    let workspace = workspace_root()?;
    let flake_path = format!("{}/nix/guest-agent", workspace);

    env.log_info("Building mvm-guest-agent...");

    let output = env
        .shell_exec_stdout(&format!(
            "nix build 'path:{}' --no-link --print-out-paths 2>/dev/null",
            flake_path
        ))
        .with_context(|| "Failed to build mvm-guest-agent via nix")?;

    let store_path = output
        .lines()
        .rev()
        .find(|l| l.starts_with("/nix/store/"))
        .ok_or_else(|| anyhow::anyhow!("nix build did not produce guest agent output path"))?
        .trim()
        .to_string();

    let agent_bin = format!("{}/bin/mvm-guest-agent", store_path);
    env.log_success(&format!("Guest agent: {}", agent_bin));
    Ok(agent_bin)
}

/// Inject the guest agent into an ext4 rootfs image.
///
/// Mounts the rootfs, copies the agent binary, writes a systemd unit, and
/// creates the multi-user.target.wants symlink so it starts at boot.
pub fn inject_into_rootfs(
    env: &dyn ShellEnvironment,
    agent_bin: &str,
    rootfs_path: &str,
) -> Result<()> {
    env.log_info("Injecting guest agent into rootfs...");

    let mut ctx = BTreeMap::new();
    ctx.insert("agent_bin", agent_bin.to_string());
    ctx.insert("rootfs", rootfs_path.to_string());

    env.shell_exec(&render_script("inject_guest_agent", &ctx)?)
        .with_context(|| "Failed to inject guest agent into rootfs")?;

    env.log_success("Guest agent injected into rootfs");
    Ok(())
}

/// Build the guest agent and inject it into the rootfs at `rootfs_path`.
pub fn ensure_guest_agent(env: &dyn ShellEnvironment, rootfs_path: &str) -> Result<()> {
    let agent_bin = build_guest_agent(env)?;
    inject_into_rootfs(env, &agent_bin, rootfs_path)
}

/// Determine the mvm workspace root path.
///
/// Checks `MVM_WORKSPACE_DIR` first, then tries to locate it relative to the
/// running binary, and falls back to the compile-time `CARGO_MANIFEST_DIR`.
fn workspace_root() -> Result<String> {
    // Environment variable override.
    if let Ok(dir) = std::env::var("MVM_WORKSPACE_DIR")
        && !dir.is_empty()
    {
        return Ok(dir);
    }

    // Try to detect from binary location: <workspace>/target/{debug,release}/mvm
    if let Ok(exe) = std::env::current_exe()
        && let Some(workspace) = exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
        && workspace.join("nix").join("guest-agent").exists()
    {
        return Ok(workspace.display().to_string());
    }

    // Fallback: compile-time path. CARGO_MANIFEST_DIR for mvm-build is
    // <workspace>/crates/mvm-build — navigate up two levels.
    let compile_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = compile_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| {
            anyhow::anyhow!("cannot determine workspace root from CARGO_MANIFEST_DIR")
        })?;

    Ok(workspace.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_finds_directory() {
        let root = workspace_root().expect("should find workspace root");
        let nix_dir = std::path::Path::new(&root).join("nix").join("guest-agent");
        assert!(
            nix_dir.exists(),
            "expected nix/guest-agent at {}, got {}",
            root,
            nix_dir.display()
        );
    }

    #[test]
    fn workspace_root_env_override() {
        let original = std::env::var("MVM_WORKSPACE_DIR").ok();
        // SAFETY: test-only; tests run single-threaded for env var manipulation.
        unsafe { std::env::set_var("MVM_WORKSPACE_DIR", "/tmp/fake-workspace") };
        let root = workspace_root().unwrap();
        assert_eq!(root, "/tmp/fake-workspace");

        // Restore.
        match original {
            Some(v) => unsafe { std::env::set_var("MVM_WORKSPACE_DIR", v) },
            None => unsafe { std::env::remove_var("MVM_WORKSPACE_DIR") },
        }
    }
}
