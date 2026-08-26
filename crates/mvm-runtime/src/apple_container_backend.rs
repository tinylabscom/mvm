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
//! the profile's notes record that the kernel is a fetched artifact
//! trusted only with a matching digest sidecar in the artifact cache,
//! and that the sealed boot path is live-proven on this kernel. The
//! backend is opt-in only — `AnyBackend::auto_select` never returns this
//! kind.

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
use crate::workload_backend::{EgressSubstitutionTransport, WorkloadBackend};
use crate::workload_runner::StopTiming;

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
    /// The cached kernel failed its digest attestation: the
    /// `vmlinux.blake3` sidecar is missing, malformed, or names a digest
    /// the kernel bytes do not hash to. `reason` says which (a mismatch
    /// names both the pinned and the actual digest); `hint` says how to
    /// stage a trusted kernel and record its digest. An unpinned or
    /// tampered kernel must never boot.
    #[error("apple-container kernel untrusted: {reason} at {path} — {hint}")]
    ArtifactUntrusted {
        path: String,
        reason: String,
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

    pub(crate) fn stop_with_timing(&self, id: &VmId) -> Result<StopTiming> {
        self.runner.stop_with_timing(id)
    }
}

impl Default for AppleContainerBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The pure config mapping behind [`AppleContainerBackend::start`]: clone
/// the config and substitute the kernel image. Split out so the mapping is
/// unit-testable without a runner. `pub` as the backend's kernel-
/// substitution contract surface: callers (and the conformance suite) can
/// verify exactly what the backend changes about a launch config — the
/// kernel path and nothing else.
pub fn kernel_override_config(config: &VmStartConfig, kernel: &Path) -> VmStartConfig {
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
        let mut capabilities = self.runner.capabilities();
        // Apple Container is a separate opt-in wrapper; it does not route the
        // context-aware standby claim seam, so it must not inherit HVF's live
        // handoff capability accidentally.
        capabilities.standby_pool = false;
        capabilities
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
        // the cache AND verified against its digest sidecar; a missing,
        // unpinned, or tampered kernel reports at `start` with the typed
        // error, but a probe must never conclude a workload could start
        // here on a kernel that failed attestation.
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
                 mvm-built image: it is trusted only with a matching vmlinux.blake3 digest \
                 sidecar in the artifact cache — resolution fails closed when the sidecar is \
                 absent, malformed, or disagrees with the kernel bytes, and an unverified \
                 kernel never makes this backend available.",
                "The sealed block+ext4 boot path is live-proven on macOS HVF with this \
                 kernel: dm-verity-verified rootfs and runtime-overlay mounts, activation \
                 acknowledged by the guest agent, and the uid-901 privilege drop all observed \
                 in the gated end-to-end boot test.",
                "Opt-in only; never selected by auto-detect.",
            ],
        }
    }
}

impl WorkloadBackend for AppleContainerBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        // The same posture as the HVF runner this backend delegates to:
        // proxy-aware substitution over the vsock UDS channel, no
        // transparent :80/:443 terminator. Delegating keeps the two in
        // lock-step if the runner's transport ever changes.
        self.runner.egress_substitution_transport()
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
        let AppleContainerError::ArtifactMissing { what, path, hint } = typed(&err) else {
            panic!("expected ArtifactMissing, got {:?}", typed(&err));
        };
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
        assert!(!mine.standby_pool);
        assert!(theirs.standby_pool);
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
        assert!(
            profile.notes.iter().any(|n| n.contains("vmlinux.blake3")),
            "the notes must record the digest-sidecar attestation requirement"
        );
        assert!(
            profile.notes.iter().any(|n| n.contains("live-proven")),
            "the notes must record that the sealed boot path is live-proven on this kernel"
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

    /// Stage `bytes` (+ optional sidecar contents) into the isolated
    /// cache's apple-container artifact dir. The caller must already hold
    /// an isolated `MVM_HOME` (the tests' `TestEnv`).
    fn stage_kernel(bytes: &[u8], sidecar: Option<&str>) {
        let dir = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir())
            .join(artifacts::ARTIFACT_DIR_NAME);
        std::fs::create_dir_all(&dir).expect("artifact dir");
        std::fs::write(dir.join(artifacts::KERNEL_FILE_NAME), bytes).expect("kernel");
        if let Some(sidecar) = sidecar {
            std::fs::write(dir.join(artifacts::KERNEL_DIGEST_FILE_NAME), sidecar).expect("sidecar");
        }
    }

    #[test]
    fn unpinned_or_tampered_kernel_does_not_make_the_backend_available() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        // Unpinned: a kernel with no digest sidecar is untrusted.
        stage_kernel(b"untrusted-kernel", None);
        assert!(
            !b.is_available().unwrap(),
            "an unpinned kernel must never make the backend available"
        );
        // Tampered: a well-formed pin for different bytes must still fail.
        let wrong = "0".repeat(64);
        stage_kernel(b"tampered-kernel", Some(&wrong));
        assert!(
            !b.is_available().unwrap(),
            "a kernel whose bytes fail attestation must never make the backend available"
        );
    }

    #[test]
    fn start_with_unpinned_or_tampered_kernel_surfaces_the_typed_untrusted_error() {
        // The kernel-substitution path (`config_with_kernel`, called by
        // `start`) must surface the attestation failure unchanged — never
        // a fallback to a caller kernel, never an opaque I/O error.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();

        stage_kernel(b"untrusted-kernel", None);
        let err = b.start(&cfg("x")).unwrap_err();
        let AppleContainerError::ArtifactUntrusted { path, reason, hint } = typed(&err) else {
            panic!("expected ArtifactUntrusted, got {:?}", typed(&err));
        };
        assert!(path.contains("apple-container"));
        assert!(reason.contains("no digest sidecar"));
        assert!(hint.contains("b3sum"));

        let pinned = "0".repeat(64);
        stage_kernel(b"tampered-kernel", Some(&pinned));
        let err = b.start(&cfg("x")).unwrap_err();
        let AppleContainerError::ArtifactUntrusted { reason, .. } = typed(&err) else {
            panic!("expected ArtifactUntrusted, got {:?}", typed(&err));
        };
        assert!(
            reason.contains(&pinned),
            "the error must name the pinned digest: {reason}"
        );
        assert!(
            reason.contains("hashed"),
            "the error must name the actual digest: {reason}"
        );
    }

    #[test]
    fn workload_transport_mirrors_the_hvf_runner() {
        let b = AppleContainerBackend::new();
        let transport = b.egress_substitution_transport();
        assert_eq!(
            transport,
            b.runner.egress_substitution_transport(),
            "the transport delegates to the runner's own declaration"
        );
        assert_eq!(transport, EgressSubstitutionTransport::VsockUdsChannel);
        assert!(transport.supports_proxy_aware_substitution());
        assert!(!transport.supports_transparent_terminator());
    }

    #[test]
    fn workload_identity_and_capabilities_delegate() {
        let b = AppleContainerBackend::new();
        // `&dyn WorkloadBackend` still carries the full VmBackend surface:
        // identity and capabilities are the backend's own delegations.
        let workload: &dyn WorkloadBackend = &b;
        assert_eq!(workload.name(), "apple-container");
        assert_eq!(workload.kind(), BackendKind::AppleContainer);
        let (mine, theirs) = (
            workload.capabilities(),
            crate::backend::hvf_runner().capabilities(),
        );
        assert_eq!(mine.vsock, theirs.vsock);
        assert_eq!(mine.no_routable_guest_nic, theirs.no_routable_guest_nic);
        assert!(!mine.standby_pool);
        assert!(theirs.standby_pool);
        assert_eq!(mine.snapshot_capability, theirs.snapshot_capability);
        assert_eq!(mine.pause_resume, theirs.pause_resume);
    }

    #[test]
    fn require_workload_backend_accepts_apple_container() {
        // The admitted-funnel boundary is pure permission — it matches the
        // backend kind and never probes the artifact cache, so no isolated
        // MVM_HOME is needed here (the kernel is resolved at `start`).
        let backend = AnyBackend::from_hypervisor("apple-container");
        let workload = crate::workload_backend::require_workload_backend(&backend)
            .expect("apple-container boots the full admitted stack — it is a workload backend");
        assert_eq!(workload.name(), "apple-container");
        assert_eq!(workload.kind(), BackendKind::AppleContainer);
    }

    #[test]
    #[ignore = "live: needs the apple-container kernel, the universal initramfs, the runtime overlay, and a codesigned mvm-hvf-supervisor on macOS HVF (MVM_AC_E2E=1)"]
    fn start_boots_a_sealed_workload_on_the_apple_container_kernel() {
        // End-to-end: resolves the Apple container kernel from the cache, boots
        // a sealed OCI rootfs with the universal initramfs on the in-house HVF
        // VMM, drives the full ActivateEnvironment flow, and tears down.
        // Artifacts resolve from the real cache — this test never isolates
        // MVM_HOME. MVM_AC_E2E_ROOTFS names a sealed OCI ext4 with its
        // rootfs.verity / rootfs.roothash sidecars beside it.
        if std::env::var("MVM_AC_E2E").ok().as_deref() != Some("1") {
            return;
        }
        let root = std::path::PathBuf::from(
            std::env::var("MVM_AC_E2E_ROOTFS").expect("MVM_AC_E2E_ROOTFS"),
        );
        let dir = root.parent().expect("rootfs parent").to_path_buf();
        let sidecar = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .expect(name)
                .trim()
                .to_string()
        };
        let version = env!("CARGO_PKG_VERSION");
        let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
        let overlay = cache.join("runtime-overlay").join(version).join("aarch64");
        let initrd = cache
            .join("initramfs")
            .join(version)
            .join("aarch64")
            .join("initramfs.cpio.gz");
        let config = VmStartConfig {
            name: format!("ac-e2e-{}", std::process::id()),
            rootfs_path: root.display().to_string(),
            initrd_path: Some(initrd.display().to_string()),
            verity_path: Some(dir.join("rootfs.verity").display().to_string()),
            roothash: Some(sidecar("rootfs.roothash")),
            runtime_overlay_path: Some(overlay.join("overlay.ext4").display().to_string()),
            runtime_overlay_verity_path: Some(overlay.join("overlay.verity").display().to_string()),
            runtime_overlay_roothash: Some(sidecar(
                &overlay.join("overlay.roothash").display().to_string(),
            )),
            cpus: 2,
            memory_mib: 1024,
            ..Default::default()
        };
        let b = AppleContainerBackend::new();
        let id = b
            .start(&config)
            .expect("bring-up must succeed on the apple container kernel");
        assert_eq!(b.status(&id).unwrap(), VmStatus::Running);
        assert!(
            b.list().unwrap().iter().any(|v| v.name == id.0),
            "the running VM must appear in the inventory"
        );
        assert!(b.logs(&id, 5, false).is_ok());
        b.stop(&id).expect("stop");
        assert_eq!(b.status(&id).unwrap(), VmStatus::Stopped);
    }
}
