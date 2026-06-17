//! Host-side source of the guest agent + netinit binaries baked into an
//! OCI rootfs ([`crate::oci_runtime_inject`]).
//!
//! An mkGuest rootfs gets the agent from a nix build inside the builder
//! VM. An arbitrary OCI image has no nix build of its own, so for the
//! `run --image` path the host produces the binaries directly and bakes
//! them in. This module mirrors the existing host cross-compile pattern
//! (`crates/mvm-cli/build.rs` cross-compiles the host-vm bins with
//! `cargo-zigbuild` to a static musl target) and caches the result under
//! `~/.cache/mvm/guest-agent/<version>/<arch>/`.
//!
//! `cargo-zigbuild` is the single portable cross path: the agent pulls
//! `ring` (C), so a static musl build needs a musl C cross-compiler, and
//! zig supplies it without a system `<arch>-linux-musl-gcc`. The build is
//! only reachable from a source checkout (it needs the workspace + zig);
//! an end-user mvmctl gets the binaries from the published runtime
//! overlay instead (a separate path).

use mvm_core::arch::GuestArch;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::oci_runtime_inject::MvmRuntimeBinaries;

#[derive(Debug, Error)]
pub enum GuestAgentBuildError {
    #[error("cargo-zigbuild failed: {reason}")]
    BuildFailed { reason: String },

    #[error("built guest binary missing after zigbuild: {0}")]
    OutputMissing(PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// On-disk cache layout for one `(version, arch)` of the guest binaries.
/// Pure path construction — no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAgentLayout {
    pub dir: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
}

impl GuestAgentLayout {
    pub fn under(cache_root: &Path, version: &str, arch: GuestArch) -> Self {
        let dir = cache_root
            .join("guest-agent")
            .join(version)
            .join(arch.to_string());
        Self {
            agent: dir.join("mvm-guest-agent"),
            netinit: dir.join("mvm-guest-netinit"),
            dir,
        }
    }

    fn is_complete(&self) -> bool {
        self.agent.is_file() && self.netinit.is_file()
    }

    fn binaries(&self) -> MvmRuntimeBinaries {
        MvmRuntimeBinaries {
            agent: self.agent.clone(),
            netinit: self.netinit.clone(),
        }
    }
}

/// The musl target triple cargo-zigbuild cross-compiles to for `arch`.
/// Static musl so the binary runs in any guest userspace (no loader).
pub fn musl_target_triple(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Aarch64 => "aarch64-unknown-linux-musl",
        GuestArch::X86_64 => "x86_64-unknown-linux-musl",
    }
}

/// Spec for the `cargo zigbuild` invocation that produces the guest
/// binaries. Pure data; [`build_guest_binaries`] runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAgentBuildSpec {
    /// Workspace root (dir containing `Cargo.toml`, `crates/`).
    pub workspace_root: PathBuf,
    pub arch: GuestArch,
    /// Override the cargo binary (tests). `None` ⇒ `cargo` on `$PATH`.
    pub cargo: Option<PathBuf>,
}

impl GuestAgentBuildSpec {
    pub fn new(workspace_root: PathBuf, arch: GuestArch) -> Self {
        Self {
            workspace_root,
            arch,
            cargo: None,
        }
    }

    pub fn target_triple(&self) -> &'static str {
        musl_target_triple(self.arch)
    }

    /// `cargo zigbuild` argv. Builds both guest bins with `dev-shell`
    /// (the `run --image` exec path uses the dev-shell-gated handler,
    /// matching `nix/packages/mvm-guest-agent.nix`).
    pub fn argv(&self) -> Vec<String> {
        let cargo = self
            .cargo
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "cargo".to_string());
        vec![
            cargo,
            "zigbuild".to_string(),
            "--release".to_string(),
            "--target".to_string(),
            self.target_triple().to_string(),
            "-p".to_string(),
            "mvm-guest".to_string(),
            "--bin".to_string(),
            "mvm-guest-agent".to_string(),
            "--bin".to_string(),
            "mvm-guest-netinit".to_string(),
            "--features".to_string(),
            "mvm-guest/dev-shell".to_string(),
        ]
    }

    /// Paths the build drops the binaries at under the workspace target
    /// dir.
    pub fn output_dir(&self) -> PathBuf {
        self.workspace_root
            .join("target")
            .join(self.target_triple())
            .join("release")
    }
}

/// Resolve the guest binaries for `(version, arch)`, building + caching
/// them from `workspace_root` on a cache miss.
pub fn resolve_or_build_guest_binaries(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, version, arch);
    if layout.is_complete() {
        return Ok(layout.binaries());
    }
    let spec = GuestAgentBuildSpec::new(workspace_root.to_path_buf(), arch);
    let (agent, netinit) = build_guest_binaries(&spec)?;
    install_into_cache(&agent, &netinit, cache_root, version, arch)
}

/// Copy already-built guest binaries into the cache and return the
/// cached paths. Lets a caller that already has the binaries (e.g. a
/// prior `cargo zigbuild`) pre-warm the cache without rebuilding.
pub fn install_into_cache(
    agent_src: &Path,
    netinit_src: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, version, arch);
    std::fs::create_dir_all(&layout.dir)?;
    install_one(agent_src, &layout.agent)?;
    install_one(netinit_src, &layout.netinit)?;
    Ok(layout.binaries())
}

fn install_one(src: &Path, dst: &Path) -> Result<(), GuestAgentBuildError> {
    if !src.is_file() {
        return Err(GuestAgentBuildError::OutputMissing(src.to_path_buf()));
    }
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)?;
    set_exec(dst)?;
    Ok(())
}

/// Run `cargo zigbuild` for the spec, returning the built binary paths.
pub fn build_guest_binaries(
    spec: &GuestAgentBuildSpec,
) -> Result<(PathBuf, PathBuf), GuestAgentBuildError> {
    let argv = spec.argv();
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(&spec.workspace_root);
    // Pin RUSTC to the rustup toolchain when available — a Homebrew
    // `rustc` earlier on `$PATH` carries no cross-target std and fails
    // the musl build with E0463.
    if let Some(rustc) = rustup_rustc() {
        cmd.env("RUSTC", rustc);
    }
    let out = cmd
        .output()
        .map_err(|e| GuestAgentBuildError::BuildFailed {
            reason: format!("spawn `{}`: {e}", argv[0]),
        })?;
    if !out.status.success() {
        return Err(GuestAgentBuildError::BuildFailed {
            reason: format!(
                "exit {:?}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ),
        });
    }
    let dir = spec.output_dir();
    let agent = dir.join("mvm-guest-agent");
    let netinit = dir.join("mvm-guest-netinit");
    for p in [&agent, &netinit] {
        if !p.is_file() {
            return Err(GuestAgentBuildError::OutputMissing(p.clone()));
        }
    }
    Ok((agent, netinit))
}

/// `rustup which rustc` path, or `None` if rustup isn't installed.
fn rustup_rustc() -> Option<PathBuf> {
    let out = std::process::Command::new("rustup")
        .args(["which", "rustc"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

#[cfg(unix)]
fn set_exec(path: &Path) -> Result<(), GuestAgentBuildError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_exec(_path: &Path) -> Result<(), GuestAgentBuildError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn musl_triple_per_arch() {
        assert_eq!(
            musl_target_triple(GuestArch::Aarch64),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            musl_target_triple(GuestArch::X86_64),
            "x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn layout_is_versioned_and_arched() {
        let l = GuestAgentLayout::under(Path::new("/c"), "0.16.1", GuestArch::Aarch64);
        assert_eq!(l.dir, PathBuf::from("/c/guest-agent/0.16.1/aarch64"));
        assert_eq!(
            l.agent,
            PathBuf::from("/c/guest-agent/0.16.1/aarch64/mvm-guest-agent")
        );
        assert_eq!(
            l.netinit,
            PathBuf::from("/c/guest-agent/0.16.1/aarch64/mvm-guest-netinit")
        );
    }

    #[test]
    fn build_argv_targets_musl_with_dev_shell_and_both_bins() {
        let spec = GuestAgentBuildSpec::new(PathBuf::from("/ws"), GuestArch::Aarch64);
        let argv = spec.argv();
        assert_eq!(argv[0], "cargo");
        assert_eq!(argv[1], "zigbuild");
        assert!(argv.contains(&"aarch64-unknown-linux-musl".to_string()));
        assert!(argv.contains(&"mvm-guest-agent".to_string()));
        assert!(argv.contains(&"mvm-guest-netinit".to_string()));
        assert!(argv.contains(&"mvm-guest/dev-shell".to_string()));
        // output_dir is under the target triple's release dir.
        assert_eq!(
            spec.output_dir(),
            PathBuf::from("/ws/target/aarch64-unknown-linux-musl/release")
        );
    }

    #[test]
    fn install_and_resolve_round_trips_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let agent_src = tmp.path().join("a");
        let netinit_src = tmp.path().join("n");
        std::fs::write(&agent_src, b"AGENT").unwrap();
        std::fs::write(&netinit_src, b"NETINIT").unwrap();
        let cache = tmp.path().join("cache");

        let installed = install_into_cache(
            &agent_src,
            &netinit_src,
            &cache,
            "0.16.1",
            GuestArch::Aarch64,
        )
        .expect("install");
        assert_eq!(std::fs::read(&installed.agent).unwrap(), b"AGENT");

        // A subsequent resolve hits the cache and never builds (the
        // workspace path is bogus; if it built it would fail).
        let resolved = resolve_or_build_guest_binaries(
            &cache,
            "0.16.1",
            GuestArch::Aarch64,
            Path::new("/nonexistent-workspace"),
        )
        .expect("resolve from cache");
        assert_eq!(resolved, installed);
    }

    #[test]
    fn install_rejects_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let err = install_into_cache(
            &tmp.path().join("missing-agent"),
            &tmp.path().join("missing-netinit"),
            &tmp.path().join("cache"),
            "0.16.1",
            GuestArch::Aarch64,
        )
        .unwrap_err();
        assert!(matches!(err, GuestAgentBuildError::OutputMissing(_)));
    }
}
