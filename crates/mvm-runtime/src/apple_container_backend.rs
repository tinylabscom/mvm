//! Apple Container backend: Apple's prebuilt container kernel on the in-house HVF VMM.
//!
//! `AppleContainerBackend` is the HVF workload runner with one substitution:
//! the kernel image. It resolves Apple's prebuilt container kernel from the
//! local artifact cache ([`crate::apple_container::artifacts`]), sets it as
//! the launch config's `kernel_path` (which the runner maps to
//! `KernelImage::Path`), and delegates the entire lifecycle — boot,
//! activation, egress, broker, stop, wait, snapshots — to the same
//! [`crate::backend::hvf_runner`] that serves `--hypervisor hvf`. The guest
//! boots mvm's universal initramfs, the agent is PID 1, and activation is
//! the standard `ActivateEnvironment` flow every runner backend uses.
//!
//! The `initrd_path` contract is the runner's own: a sealed boot expects
//! the universal-initramfs artifact attached by the caller (the CLI attach
//! path), exactly as for HVF, and a boot without it behaves precisely as an
//! HVF boot without it — this backend adds no gate of its own.
//!
//! Honest reporting, not silent degradation: `capabilities()` and the
//! claims array of `security_profile()` are the HVF runner's verbatim
//! (the isolation story is identical — only the kernel image differs);
//! the profile's notes record that the kernel is a fetched artifact whose
//! provenance is not an mvm build. The backend is opt-in only —
//! `AnyBackend::auto_select` never returns this kind.

use std::path::Path;

use anyhow::Result;
use mvm_core::vm_backend::WarmStartError;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, SnapshotCapability, StartMode, VmBackend, VmCapabilities,
    VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus, WarmStartOutcome,
};
use thiserror::Error;

use crate::apple_container::artifacts;
use crate::backend::HvfRunner;

/// Typed, fail-closed errors for requests this backend cannot satisfy.
/// Every error names what was refused and why, rather than silently falling
/// back to another backend or panicking.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AppleContainerError {
    /// The Apple container kernel is not in the cache; `hint` names where
    /// to fetch it.
    #[error("apple-container artifact missing: {what} at {path} — {hint}")]
    ArtifactMissing {
        what: &'static str,
        path: String,
        hint: &'static str,
    },
}

/// Apple Container backend — a thin kernel-substituting delegate over the
/// HVF workload runner. See the module docs for the design and the
/// honesty rules.
pub struct AppleContainerBackend {
    runner: HvfRunner,
}

impl AppleContainerBackend {
    /// Construct the backend. Side-effect free — the runner is a pure
    /// struct init and no artifact is probed until `start`.
    pub fn new() -> Self {
        Self {
            runner: crate::backend::hvf_runner(),
        }
    }
    /// Resolve the kernel and return the launch config with `kernel_path`
    /// pointing at it. Everything else about the config passes through
    /// untouched — the runner maps it exactly as an HVF launch would.
    fn config_with_kernel(&self, config: &VmStartConfig) -> Result<VmStartConfig> {
        let kernel = artifacts::resolve()?;
        Ok(kernel_override_config(config, &kernel))
    }
}

impl Default for AppleContainerBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The pure config mapping behind [`AppleContainerBackend::start`]: clone
/// the config and substitute the kernel image. Split out so the mapping is
/// unit-testable without a runner.
fn kernel_override_config(config: &VmStartConfig, kernel: &Path) -> VmStartConfig {
    let mut cfg = config.clone();
    cfg.kernel_path = Some(kernel.display().to_string());
    cfg
}

impl VmBackend for AppleContainerBackend {
    fn name(&self) -> &str {
        "apple-container"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::AppleContainer
    }

    fn capabilities(&self) -> VmCapabilities {
        self.runner.capabilities()
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        self.runner.start(&self.config_with_kernel(config)?)
    }

    fn start_with_mode(&self, config: &VmStartConfig, mode: StartMode) -> Result<VmId> {
        self.runner
            .start_with_mode(&self.config_with_kernel(config)?, mode)
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        self.runner.wait(id)
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        self.runner.pause(id)
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        self.runner.resume(id)
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        self.runner.stop(id)
    }

    fn stop_all(&self) -> Result<()> {
        self.runner.stop_all()
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        self.runner.status(id)
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        self.runner.list()
    }

    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        self.runner.logs(id, lines, hypervisor)
    }

    fn warm_start(
        &self,
        config: &VmStartConfig,
        requested: SnapshotCapability,
    ) -> std::result::Result<WarmStartOutcome, WarmStartError> {
        self.runner.warm_start(config, requested)
    }

    fn is_available(&self) -> Result<bool> {
        // Available when the HVF runner is and the kernel artifact is in
        // the cache; a missing kernel reports at `start` with the typed
        // fetch hint, but a probe should not conclude a workload could
        // start here without it.
        Ok(self.runner.is_available()? && artifacts::resolve().is_ok())
    }

    fn install(&self) -> Result<()> {
        self.runner.install()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // The claims array is the HVF runner's verbatim: the boot, the
        // isolation boundary, and the activation stack are identical — only
        // the kernel image differs, and the notes say so honestly.
        let inner = self.runner.security_profile();
        BackendSecurityProfile {
            claims: inner.claims,
            layer_coverage: inner.layer_coverage,
            tier: inner.tier,
            notes: &[
                "This backend is the HVF workload runner booting Apple's prebuilt container \
                 kernel: the same universal initramfs, guest agent, activation flow, egress \
                 gate, and isolation boundary as the HVF backend — only the kernel image differs.",
                "The kernel is a fetched binary artifact (Apple's container kernel), not an \
                 mvm-built image: its provenance is the artifact cache, exactly like any \
                 externally-sourced kernel a launch config names.",
                "Opt-in only; never selected by auto-detect.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AnyBackend;

    fn cfg(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Extract the typed error from the `anyhow` wrapper the trait returns,
    /// so tests assert the exact variant, not a substring.
    fn typed(err: &anyhow::Error) -> &AppleContainerError {
        err.downcast_ref::<AppleContainerError>()
            .expect("apple-container failures must be the typed error")
    }

    #[test]
    fn kind_and_name_are_apple_container() {
        let b = AppleContainerBackend::new();
        assert_eq!(b.name(), "apple-container");
        assert_eq!(b.kind(), BackendKind::AppleContainer);
    }

    #[test]
    fn selector_and_alias_resolve_through_any_backend() {
        for sel in ["apple-container", "container"] {
            let backend = AnyBackend::from_hypervisor(sel);
            assert!(
                matches!(backend, AnyBackend::AppleContainer(_)),
                "selector {sel} must resolve to the apple-container backend"
            );
            assert_eq!(backend.name(), "apple-container");
            assert_eq!(backend.kind(), BackendKind::AppleContainer);
        }
    }

    #[test]
    fn auto_select_never_returns_apple_container() {
        // Opt-in only: `auto_select`'s ladder constructs Firecracker/Hvf/
        // Libkrun and nothing else, so this holds on every platform the
        // ladder can resolve to.
        assert_ne!(
            AnyBackend::auto_select().kind(),
            BackendKind::AppleContainer,
            "auto_select must never fall through to the apple-container backend"
        );
    }

    #[test]
    fn kernel_override_substitutes_only_the_kernel_path() {
        let config = VmStartConfig {
            name: "ac-test".to_string(),
            rootfs_path: "/img/rootfs.ext4".to_string(),
            initrd_path: Some("/cache/initramfs/initrd.cpio".to_string()),
            memory_mib: 1024,
            ..Default::default()
        };
        let overridden =
            kernel_override_config(&config, Path::new("/cache/apple-container/vmlinux"));
        assert_eq!(
            overridden.kernel_path.as_deref(),
            Some("/cache/apple-container/vmlinux")
        );
        // Everything else passes through untouched — the runner maps the
        // rest exactly as an HVF launch would.
        assert_eq!(overridden.rootfs_path, config.rootfs_path);
        assert_eq!(overridden.initrd_path, config.initrd_path);
        assert_eq!(overridden.memory_mib, config.memory_mib);
        assert_eq!(overridden.name, config.name);
    }

    #[test]
    fn kernel_override_replaces_a_caller_supplied_kernel() {
        let config = VmStartConfig {
            kernel_path: Some("/other/Image".to_string()),
            ..cfg("x")
        };
        let overridden =
            kernel_override_config(&config, Path::new("/cache/apple-container/vmlinux"));
        assert_eq!(
            overridden.kernel_path.as_deref(),
            Some("/cache/apple-container/vmlinux"),
            "this backend's whole point is which kernel boots — a caller's kernel never wins"
        );
    }

    #[test]
    fn start_reports_missing_kernel_with_the_fetch_hint() {
        // Point MVM_HOME (and HOME) at an empty tempdir so resolution
        // deterministically finds no kernel — the typed error must surface
        // before any delegation (and no VM is attempted).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        let err = b.start(&cfg("x")).unwrap_err();
        let AppleContainerError::ArtifactMissing { what, path, hint } = typed(&err);
        assert!(what.contains("kernel"));
        assert!(path.contains("apple-container"));
        assert!(hint.contains("container kernel"));
    }

    #[test]
    fn capabilities_and_claims_mirror_the_hvf_runner() {
        let b = AppleContainerBackend::new();
        let runner = crate::backend::hvf_runner();
        let (mine, theirs) = (b.capabilities(), runner.capabilities());
        assert_eq!(mine.vsock, theirs.vsock);
        assert_eq!(mine.no_routable_guest_nic, theirs.no_routable_guest_nic);
        assert_eq!(mine.standby_pool, theirs.standby_pool);
        assert_eq!(mine.snapshot_capability, theirs.snapshot_capability);
        assert_eq!(mine.pause_resume, theirs.pause_resume);

        let profile = b.security_profile();
        let runner_profile = runner.security_profile();
        assert_eq!(
            profile.claims, runner_profile.claims,
            "the claims array is the HVF runner's verbatim — only the kernel image differs"
        );
        assert_eq!(profile.tier, runner_profile.tier);
        assert!(
            profile
                .notes
                .iter()
                .any(|n| n.contains("prebuilt container kernel")),
            "the notes must record the kernel provenance honestly"
        );
    }

    #[test]
    fn availability_tracks_the_runner_and_the_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        // No kernel in the isolated cache: unavailable regardless of platform.
        assert!(!b.is_available().unwrap());
    }
}
