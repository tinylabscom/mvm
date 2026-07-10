//! Host-side source of the guest runtime binaries baked into an OCI rootfs
//! ([`crate::oci_runtime_inject`]).
//!
//! An mkGuest rootfs gets the agent from a nix build inside the builder
//! VM. An arbitrary OCI image has no nix build of its own, so for the
//! `run --image` path the host produces the binaries directly and bakes
//! them in. This module mirrors the existing host cross-compile pattern
//! (`crates/mvm-cli/build.rs` cross-compiles the host-vm bins with
//! `cargo-zigbuild` to a static musl target) and caches the result under
//! `~/.cache/mvm/guest-agent/<version>/<arch>/dev-shell/`.
//!
//! `cargo-zigbuild` is the single portable cross path: the agent pulls
//! `ring` (C), so a static musl build needs a musl C cross-compiler, and
//! zig supplies it without a system `<arch>-linux-musl-gcc`. The
//! source-checkout build ([`resolve_or_build_guest_binaries`]) is only
//! reachable with the workspace + zig; a **shipped mvmctl** embeds these
//! binaries at build time (`crates/mvm-cli/build.rs`) and installs the embedded
//! bytes via [`install_prebuilt_guest_binaries`]. The resolution order —
//! cache → source checkout → embedded — lives in `run_image::inject_and_materialize`.

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
    pub oci_init: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub egress_client: PathBuf,
    pub entrypoint_runner: PathBuf,
    pub verity_init: PathBuf,
}

/// Built guest runtime binary paths ready to install into the cache.
#[derive(Debug, Clone, Copy)]
pub struct GuestRuntimeBinaryPaths<'a> {
    pub oci_init: &'a Path,
    pub agent: &'a Path,
    pub netinit: &'a Path,
    pub egress_client: &'a Path,
    pub entrypoint_runner: &'a Path,
    pub verity_init: &'a Path,
}

/// Embedded guest runtime binary bytes ready to install into the cache.
#[derive(Debug, Clone, Copy)]
pub struct GuestRuntimeBinaryBytes<'a> {
    pub oci_init: &'a [u8],
    pub agent: &'a [u8],
    pub netinit: &'a [u8],
    pub egress_client: &'a [u8],
    pub entrypoint_runner: &'a [u8],
    pub verity_init: &'a [u8],
}

/// Cache segment keying the agent build variant. The `run --image` path needs
/// the dev-shell (exec-capable) agent, and this module always builds with it
/// (see [`GuestAgentBuildSpec`]); keying the cache by the variant means a stale,
/// same-version agent built *without* dev-shell (the old, segment-less layout)
/// is never reused for an exec-capable request — the cause of the
/// "guest agent built without dev-shell feature" exec failure on a cache hit.
const AGENT_VARIANT: &str = "dev-shell";

impl GuestAgentLayout {
    pub fn under(cache_root: &Path, version: &str, arch: GuestArch) -> Self {
        let dir = cache_root
            .join("guest-agent")
            .join(version)
            .join(arch.to_string())
            .join(AGENT_VARIANT);
        Self {
            oci_init: dir.join("mvm-oci-init"),
            agent: dir.join("mvm-guest-agent"),
            netinit: dir.join("mvm-guest-netinit"),
            egress_client: dir.join("mvm-egress-client"),
            entrypoint_runner: dir.join("mvm-oci-entrypoint"),
            verity_init: dir.join("mvm-verity-init"),
            dir,
        }
    }

    fn is_complete(&self) -> bool {
        self.oci_init.is_file()
            && self.agent.is_file()
            && self.netinit.is_file()
            && self.egress_client.is_file()
            && self.entrypoint_runner.is_file()
            && self.verity_init.is_file()
    }

    fn binaries(&self) -> MvmRuntimeBinaries {
        MvmRuntimeBinaries {
            oci_init: self.oci_init.clone(),
            agent: self.agent.clone(),
            netinit: self.netinit.clone(),
            egress_client: self.egress_client.clone(),
            entrypoint_runner: self.entrypoint_runner.clone(),
            verity_init: self.verity_init.clone(),
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

    /// `cargo zigbuild` argv. Builds the guest runtime bins with `dev-shell`
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
            "--bin".to_string(),
            "mvm-oci-init".to_string(),
            "--bin".to_string(),
            "mvm-oci-entrypoint".to_string(),
            "--bin".to_string(),
            "mvm-verity-init".to_string(),
            "-p".to_string(),
            "mvm-guest-helpers".to_string(),
            "--bin".to_string(),
            "mvm-egress-client".to_string(),
            "--features".to_string(),
            "mvm-guest/dev-shell".to_string(),
        ]
    }

    /// Paths the build drops the binaries at under the workspace target
    /// dir.
    pub fn output_dir(&self) -> PathBuf {
        std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.workspace_root.join("target"))
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
    let built = build_guest_binaries(&spec)?;
    install_into_cache(
        GuestRuntimeBinaryPaths {
            oci_init: &built.0,
            agent: &built.1,
            netinit: &built.2,
            egress_client: &built.3,
            entrypoint_runner: &built.4,
            verity_init: &built.5,
        },
        cache_root,
        version,
        arch,
    )
}

/// Copy already-built guest binaries into the cache and return the
/// cached paths. Lets a caller that already has the binaries (e.g. a
/// prior `cargo zigbuild`) pre-warm the cache without rebuilding.
pub fn install_into_cache(
    src: GuestRuntimeBinaryPaths<'_>,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, version, arch);
    std::fs::create_dir_all(&layout.dir)?;
    install_one(src.oci_init, &layout.oci_init)?;
    install_one(src.agent, &layout.agent)?;
    install_one(src.netinit, &layout.netinit)?;
    install_one(src.egress_client, &layout.egress_client)?;
    install_one(src.entrypoint_runner, &layout.entrypoint_runner)?;
    install_one(src.verity_init, &layout.verity_init)?;
    Ok(layout.binaries())
}

/// The cached guest binaries if a complete set is already present, else `None`.
/// Lets a caller check the cache without triggering a source-checkout build.
pub fn cached_guest_binaries(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Option<MvmRuntimeBinaries> {
    let layout = GuestAgentLayout::under(cache_root, version, arch);
    layout.is_complete().then(|| layout.binaries())
}

/// Install guest binaries from in-memory bytes (embedded in the host binary at
/// build time) into the cache. The end-user path: a shipped mvmctl has no
/// source checkout to cross-compile from, so it writes the embedded bytes here.
pub fn install_prebuilt_guest_binaries(
    bytes: GuestRuntimeBinaryBytes<'_>,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<MvmRuntimeBinaries, GuestAgentBuildError> {
    let layout = GuestAgentLayout::under(cache_root, version, arch);
    std::fs::create_dir_all(&layout.dir)?;
    write_exec(&layout.oci_init, bytes.oci_init)?;
    write_exec(&layout.agent, bytes.agent)?;
    write_exec(&layout.netinit, bytes.netinit)?;
    write_exec(&layout.egress_client, bytes.egress_client)?;
    write_exec(&layout.entrypoint_runner, bytes.entrypoint_runner)?;
    write_exec(&layout.verity_init, bytes.verity_init)?;
    Ok(layout.binaries())
}

fn write_exec(dst: &Path, bytes: &[u8]) -> Result<(), GuestAgentBuildError> {
    let _ = std::fs::remove_file(dst);
    std::fs::write(dst, bytes)?;
    set_exec(dst)
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
) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf), GuestAgentBuildError> {
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
    let oci_init = dir.join("mvm-oci-init");
    let agent = dir.join("mvm-guest-agent");
    let netinit = dir.join("mvm-guest-netinit");
    let egress_client = dir.join("mvm-egress-client");
    let entrypoint_runner = dir.join("mvm-oci-entrypoint");
    let verity_init = dir.join("mvm-verity-init");
    for p in [
        &oci_init,
        &agent,
        &netinit,
        &egress_client,
        &entrypoint_runner,
        &verity_init,
    ] {
        if !p.is_file() {
            return Err(GuestAgentBuildError::OutputMissing(p.clone()));
        }
    }
    Ok((
        oci_init,
        agent,
        netinit,
        egress_client,
        entrypoint_runner,
        verity_init,
    ))
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
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn install_prebuilt_then_cached_round_trips() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::Aarch64;
        let version = env!("CARGO_PKG_VERSION");

        // Nothing cached yet.
        assert!(cached_guest_binaries(cache.path(), version, arch).is_none());

        // Install embedded-style bytes, then the cache lookup finds them.
        let bins = install_prebuilt_guest_binaries(
            GuestRuntimeBinaryBytes {
                oci_init: b"fake-oci-init-elf",
                agent: b"fake-agent-elf",
                netinit: b"fake-netinit-elf",
                egress_client: b"fake-egress-client-elf",
                entrypoint_runner: b"fake-entrypoint-runner-elf",
                verity_init: b"fake-verity-init-elf",
            },
            cache.path(),
            version,
            arch,
        )
        .expect("install prebuilt");
        assert!(bins.oci_init.is_file());
        assert!(bins.agent.is_file());
        assert!(bins.netinit.is_file());
        assert!(bins.egress_client.is_file());
        assert!(bins.entrypoint_runner.is_file());
        assert!(bins.verity_init.is_file());
        assert_eq!(
            std::fs::read(&bins.verity_init).unwrap(),
            b"fake-verity-init-elf"
        );
        assert_eq!(std::fs::read(&bins.oci_init).unwrap(), b"fake-oci-init-elf");
        assert_eq!(std::fs::read(&bins.agent).unwrap(), b"fake-agent-elf");
        assert_eq!(
            std::fs::read(&bins.egress_client).unwrap(),
            b"fake-egress-client-elf"
        );
        assert_eq!(
            std::fs::read(&bins.entrypoint_runner).unwrap(),
            b"fake-entrypoint-runner-elf"
        );

        let cached = cached_guest_binaries(cache.path(), version, arch).expect("now cached");
        assert_eq!(cached.oci_init, bins.oci_init);
        assert_eq!(cached.agent, bins.agent);
        // Executable bit is set on the installed binary.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cached.agent)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "installed agent must be executable");
        }
    }

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
    fn layout_is_versioned_arched_and_variant_keyed() {
        let version = env!("CARGO_PKG_VERSION");
        let l = GuestAgentLayout::under(Path::new("/c"), version, GuestArch::Aarch64);
        let expected_dir = PathBuf::from("/c")
            .join("guest-agent")
            .join(version)
            .join("aarch64")
            .join("dev-shell");
        // The `dev-shell` segment keys the variant so a stale same-version agent
        // built without dev-shell is never reused for the exec-capable request.
        assert_eq!(l.dir, expected_dir);
        assert_eq!(l.oci_init, l.dir.join("mvm-oci-init"));
        assert_eq!(l.agent, l.dir.join("mvm-guest-agent"));
        assert_eq!(l.netinit, l.dir.join("mvm-guest-netinit"));
        assert_eq!(l.egress_client, l.dir.join("mvm-egress-client"));
        assert_eq!(l.entrypoint_runner, l.dir.join("mvm-oci-entrypoint"));
        assert_eq!(l.verity_init, l.dir.join("mvm-verity-init"));
    }

    #[test]
    fn build_argv_targets_musl_with_dev_shell_and_both_bins() {
        let mut env = TestEnv::new();
        env.remove("CARGO_TARGET_DIR");
        let spec = GuestAgentBuildSpec::new(PathBuf::from("/ws"), GuestArch::Aarch64);
        let argv = spec.argv();
        assert_eq!(argv[0], "cargo");
        assert_eq!(argv[1], "zigbuild");
        assert!(argv.contains(&"aarch64-unknown-linux-musl".to_string()));
        assert!(argv.contains(&"mvm-guest-agent".to_string()));
        assert!(argv.contains(&"mvm-guest-netinit".to_string()));
        assert!(argv.contains(&"mvm-oci-init".to_string()));
        assert!(argv.contains(&"mvm-oci-entrypoint".to_string()));
        assert!(argv.contains(&"mvm-verity-init".to_string()));
        assert!(argv.contains(&"mvm-egress-client".to_string()));
        assert!(argv.contains(&"mvm-guest-helpers".to_string()));
        assert!(argv.contains(&"mvm-guest/dev-shell".to_string()));
        // output_dir is under the target triple's release dir.
        assert_eq!(
            spec.output_dir(),
            PathBuf::from("/ws/target/aarch64-unknown-linux-musl/release")
        );
    }

    #[test]
    fn output_dir_honors_cargo_target_dir_override() {
        let mut env = TestEnv::new();
        env.set("CARGO_TARGET_DIR", "/tmp/custom-target");
        let spec = GuestAgentBuildSpec::new(PathBuf::from("/ws"), GuestArch::Aarch64);
        assert_eq!(
            spec.output_dir(),
            PathBuf::from("/tmp/custom-target/aarch64-unknown-linux-musl/release")
        );
    }

    #[test]
    fn install_and_resolve_round_trips_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let oci_init_src = tmp.path().join("i");
        let agent_src = tmp.path().join("a");
        let netinit_src = tmp.path().join("n");
        let egress_client_src = tmp.path().join("e");
        let entrypoint_runner_src = tmp.path().join("r");
        let verity_init_src = tmp.path().join("v");
        std::fs::write(&oci_init_src, b"INIT").unwrap();
        std::fs::write(&agent_src, b"AGENT").unwrap();
        std::fs::write(&netinit_src, b"NETINIT").unwrap();
        std::fs::write(&egress_client_src, b"EGRESS").unwrap();
        std::fs::write(&entrypoint_runner_src, b"RUNNER").unwrap();
        std::fs::write(&verity_init_src, b"VERITY").unwrap();
        let cache = tmp.path().join("cache");

        let installed = install_into_cache(
            GuestRuntimeBinaryPaths {
                oci_init: &oci_init_src,
                agent: &agent_src,
                netinit: &netinit_src,
                egress_client: &egress_client_src,
                entrypoint_runner: &entrypoint_runner_src,
                verity_init: &verity_init_src,
            },
            &cache,
            version,
            GuestArch::Aarch64,
        )
        .expect("install");
        assert_eq!(std::fs::read(&installed.oci_init).unwrap(), b"INIT");
        assert_eq!(std::fs::read(&installed.agent).unwrap(), b"AGENT");
        assert_eq!(std::fs::read(&installed.egress_client).unwrap(), b"EGRESS");
        assert_eq!(
            std::fs::read(&installed.entrypoint_runner).unwrap(),
            b"RUNNER"
        );
        assert_eq!(std::fs::read(&installed.verity_init).unwrap(), b"VERITY");

        // A subsequent resolve hits the cache and never builds (the
        // workspace path is bogus; if it built it would fail).
        let resolved = resolve_or_build_guest_binaries(
            &cache,
            version,
            GuestArch::Aarch64,
            Path::new("/nonexistent-workspace"),
        )
        .expect("resolve from cache");
        assert_eq!(resolved, installed);
    }

    #[test]
    fn install_rejects_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let err = install_into_cache(
            GuestRuntimeBinaryPaths {
                oci_init: &tmp.path().join("missing-oci-init"),
                agent: &tmp.path().join("missing-agent"),
                netinit: &tmp.path().join("missing-netinit"),
                egress_client: &tmp.path().join("missing-egress-client"),
                entrypoint_runner: &tmp.path().join("missing-entrypoint-runner"),
                verity_init: &tmp.path().join("missing-verity-init"),
            },
            &tmp.path().join("cache"),
            version,
            GuestArch::Aarch64,
        )
        .unwrap_err();
        assert!(matches!(err, GuestAgentBuildError::OutputMissing(_)));
    }
}
