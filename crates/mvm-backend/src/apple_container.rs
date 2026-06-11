//! Apple Container backend for macOS 26+.
//!
//! Uses Apple's Containerization framework to run Linux containers in
//! lightweight VMs with sub-second startup. Each container gets its own
//! VM with dedicated networking (vmnet) and vsock for guest communication.
//!
//! The actual Containerization framework calls are behind a Swift FFI bridge
//! (`mvm-apple-container` crate). This module provides the `VmBackend`
//! implementation that translates `VmStartConfig` into container operations.
//!
//! # Platform Requirements
//!
//! - macOS 26+ on Apple Silicon
//! - Containerization framework available via Xcode 26+
//!
//! # Architecture
//!
//! ```text
//! AppleContainerBackend (this module)
//!   └── swift-bridge FFI (future: mvm-apple-container crate)
//!         └── Containerization.framework
//!               ├── ContainerManager (lifecycle)
//!               ├── LinuxContainer (per-VM)
//!               └── vminitd (PID 1, gRPC over vsock:1024)
//! ```

use anyhow::{Context, Result};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage, StartMode, VmBackend,
    VmCapabilities, VmId, VmInfo, VmNetworkInfo, VmStartConfig, VmStatus,
};

use crate::base::ui;

/// Apple Container backend using macOS Containerization framework.
///
/// Currently a stub implementation — the Swift FFI bridge will be
/// connected when macOS 26 is available. All lifecycle methods return
/// appropriate errors until the bridge is wired up.
pub struct AppleContainerBackend;

impl AppleContainerBackend {
    /// Check whether the Apple Containerization framework is available
    /// at runtime (macOS 26+ on Apple Silicon).
    ///
    /// Uses the Swift FFI bridge when available, falls back to platform
    /// detection otherwise.
    pub fn is_platform_available() -> bool {
        // Try the Swift bridge first (most accurate — checks actual framework)
        if crate::providers::apple_container::is_available() {
            return true;
        }
        // Fall back to platform detection (works without Swift bridge)
        mvm_core::platform::current().has_apple_containers()
    }
}

impl VmBackend for AppleContainerBackend {
    fn name(&self) -> &str {
        "apple-container"
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            vsock: true,
            tap_networking: false,
            // Apple's Virtualization framework does not expose
            // virtio-balloon to guests; memory ballooning is handled
            // by the host kernel via macOS memory pressure, not by
            // an in-guest device. Declared `false` so the host-side
            // reclaim controller skips this backend cleanly.
            balloon: false,
            // Apple Container runs on macOS with APFS, so clonefile is available.
            fs_quick_checkpoint: cfg!(target_os = "macos"),
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        if !Self::is_platform_available() {
            anyhow::bail!(
                "Apple Containers require macOS 26+ on Apple Silicon.\n\
                 Use '--hypervisor firecracker' or run on a supported platform."
            );
        }

        let kernel_path = config.kernel_path.as_deref().unwrap_or_default();
        if kernel_path.is_empty() {
            anyhow::bail!(
                "Apple Container backend requires a kernel path.\n\
                 Build with 'mvmctl build --flake .' first."
            );
        }

        // Plan 74 W2 / ADR-051 admission gate — refuse pre-W1.4b
        // rootfs that lack the `/mvm/runtime` mount point. Runs
        // before the CoW clone so a refusal exits clean (no
        // per-instance disk written, no half-formed VM state).
        // Sidecar lives next to the *source* rootfs.
        let original_rootfs = std::path::Path::new(&config.rootfs_path);
        let original_dir = original_rootfs
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(original_dir)?;

        // Plan 53 Plan D: clone the rootfs to a per-instance path so
        // each running VM owns its disk image. Apple VZ refuses to
        // attach the same writable disk to two VMs concurrently; the
        // clone also keeps templates pristine across multiple instances.
        // APFS Copy-on-Write makes this O(1) regardless of rootfs size
        // when source and destination live on the same volume.
        let effective_rootfs = prepare_instance_rootfs(&config.name, &config.rootfs_path)?;

        // W6.2.1: read the sidecar next to the *original* rootfs (the
        // per-instance clone is a CoW copy under a different name; the
        // sidecar lives next to the source). Populates the
        // accessible/sealed flag for `mvmctl console`'s gate.
        crate::base::runtime_meta::record_from_rootfs(
            &config.name,
            StartMode::Detached,
            original_rootfs,
        )?;

        ui::info(&format!(
            "Starting Apple Container '{}' (cpus={}, mem={}MiB)...",
            config.name, config.cpus, config.memory_mib
        ));

        crate::providers::apple_container::start(
            &config.name,
            kernel_path,
            effective_rootfs
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("instance rootfs path is not valid UTF-8"))?,
            config.cpus,
            config.memory_mib as u64,
        )
        .map_err(|e| anyhow::anyhow!("Apple Container start failed: {e}"))?;

        ui::success(&format!("Apple Container '{}' started.", config.name));
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let stop_result = crate::providers::apple_container::stop(&id.0)
            .map_err(|e| anyhow::anyhow!("Apple Container stop failed: {e}"));
        // Best-effort: remove the per-instance rootfs clone (Plan D).
        // A missing file means stop already cleaned up or the VM never
        // reached the clone step.
        if let Ok(path) = instance_rootfs_path(&id.0)
            && path.exists()
            && let Err(e) = std::fs::remove_file(&path)
        {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to remove per-instance rootfs clone"
            );
        }
        stop_result
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        // Apple Virtualization.framework supports VZ pause/resume but the
        // `container` CLI's surface doesn't expose it; matches
        // `capabilities().pause_resume == false`. Revisit if we drop the
        // CLI shell-out for a direct VZ binding.
        anyhow::bail!(
            "pause is not supported by the apple-container backend (the `container` CLI does not expose VZ pause)"
        )
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        anyhow::bail!(
            "resume is not supported by the apple-container backend (the `container` CLI does not expose VZ pause)"
        )
    }

    fn stop_all(&self) -> Result<()> {
        let ids = crate::providers::apple_container::list_ids();
        for id in &ids {
            if let Err(e) = crate::providers::apple_container::stop(id) {
                tracing::warn!("Failed to stop container '{id}': {e}");
            }
        }
        Ok(())
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let ids = crate::providers::apple_container::list_ids();
        if ids.contains(&id.0) {
            Ok(VmStatus::Running)
        } else {
            Ok(VmStatus::Stopped)
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let ids = crate::providers::apple_container::list_ids();
        Ok(ids
            .into_iter()
            .map(|id| {
                // Read persisted port mappings if available
                let ports = read_vm_ports(&id);
                VmInfo {
                    id: VmId(id.clone()),
                    name: id,
                    status: VmStatus::Running,
                    guest_ip: None,
                    cpus: 0,
                    memory_mib: 0,
                    profile: None,
                    revision: None,
                    flake_ref: None,
                    ports,
                }
            })
            .collect())
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        anyhow::bail!("Apple Container logs not yet implemented for VM '{}'", id.0)
    }

    fn is_available(&self) -> Result<bool> {
        Ok(Self::is_platform_available())
    }

    fn install(&self) -> Result<()> {
        ui::info(
            "Apple Containers are built into macOS 26+. No separate installation needed.\n\
             Ensure you are running macOS 26 or later on Apple Silicon.",
        );
        Ok(())
    }

    fn network_info(&self, id: &VmId) -> Result<VmNetworkInfo> {
        // Apple Containers use vmnet with 192.168.64.0/24 subnet.
        // The actual IP is assigned dynamically by vmnet.
        anyhow::bail!(
            "Apple Container network info not yet available for VM '{}'",
            id.0
        )
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // Apple VZ backend uses vsock directly (VZVirtioSocketDevice).
        // The guest agent listens on `GUEST_AGENT_PORT` (5252), same as
        // Firecracker.
        Ok(GuestChannelInfo::Vsock {
            cid: 3, // standard guest CID
            port: crate::providers::apple_container::GUEST_AGENT_PORT,
        })
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 2: hardware isolation via Apple VZ (Hypervisor.framework).
        // Claim 3 (verified boot via dm-verity) is partial — the W3
        // pipeline currently targets Firecracker; the VZ-backed rootfs
        // still boots without the dm-verity initramfs.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1 — host-fs isolation via VZ
                ClaimStatus::Holds,       // 2 — uid-0 protections same as FC
                ClaimStatus::DoesNotHold, // 3 — verified boot for VZ rootfs not yet wired
                ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds,       // 5 — vsock framing is fuzzed
                ClaimStatus::Holds,       // 6 — image hash verification
                ClaimStatus::Holds,       // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "Hardware isolation via Apple VZ (Containerization.framework).",
                "Claim 3 (verified boot) is partial — dm-verity for VZ-backed rootfs not yet wired.",
            ],
        }
    }
}

/// Per-instance rootfs path inside `~/.mvm/vms/<vm_name>/`.
///
/// Plan 53 Plan D: the rootfs clone (CoW on APFS, byte copy elsewhere)
/// lives here. Each running Apple Container VM owns its own copy so VZ
/// can attach it writable without conflicting with sibling instances.
fn instance_rootfs_path(vm_name: &str) -> Result<std::path::PathBuf> {
    Ok(mvm_core::config::vm_state_dir(vm_name).join("rootfs.ext4"))
}

/// Materialize the per-instance rootfs for an Apple Container VM and
/// return its absolute path.
///
/// If the source path is already the per-instance path (rare, but
/// possible for a re-start), this is a no-op. Otherwise, it removes
/// any stale per-instance file from a prior failed run, then clones
/// the source into the per-instance location via [`reflink_or_copy`].
/// The strategy used (Reflink vs Copied) is logged so users can see
/// when the fast path applied.
fn prepare_instance_rootfs(vm_name: &str, source_rootfs: &str) -> Result<std::path::PathBuf> {
    let instance_path = instance_rootfs_path(vm_name)?;
    prepare_instance_rootfs_inner(&instance_path, source_rootfs)
}

/// Inner implementation that doesn't read `HOME`. Tests pass a tempdir
/// here directly so they don't have to mutate process-global env vars.
fn prepare_instance_rootfs_inner(
    instance_path: &std::path::Path,
    source_rootfs: &str,
) -> Result<std::path::PathBuf> {
    let source_path = std::path::Path::new(source_rootfs);
    if source_path == instance_path {
        // Already the per-instance copy — nothing to clone.
        return Ok(instance_path.to_path_buf());
    }
    if instance_path.exists() {
        std::fs::remove_file(instance_path).with_context(|| {
            format!(
                "removing stale per-instance rootfs at {}",
                instance_path.display()
            )
        })?;
    }
    let strategy = crate::base::cow::clone_rootfs_for_instance(source_path, instance_path)?;
    tracing::info!(
        ?strategy,
        source = %source_path.display(),
        instance = %instance_path.display(),
        "prepared per-instance rootfs",
    );
    Ok(instance_path.to_path_buf())
}

/// Read persisted port mappings from the VM state directory.
fn read_vm_ports(vm_name: &str) -> Vec<mvm_core::vm_backend::VmPortMapping> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("ports");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .split(',')
        .filter_map(|spec| {
            let (host, guest) = spec.split_once(':')?;
            Some(mvm_core::vm_backend::VmPortMapping {
                host: host.parse().ok()?,
                guest: guest.parse().ok()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_container_backend_name() {
        let backend = AppleContainerBackend;
        assert_eq!(backend.name(), "apple-container");
    }

    #[test]
    fn test_apple_container_capabilities() {
        let backend = AppleContainerBackend;
        let caps = backend.capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(caps.vsock);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn test_apple_container_security_profile_tier_2_partial_claim_3() {
        let backend = AppleContainerBackend;
        let profile = backend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        // L1-L5 all enforced (VZ provides hardware isolation).
        assert!(profile.layer_coverage.is_microvm());
        // Only claim 3 (verified boot) does not hold yet.
        assert_eq!(profile.dropped_claims(), vec![3]);
        assert!(profile.na_claims().is_empty());
    }

    #[test]
    fn instance_rootfs_path_layout_honors_data_dir() {
        // MVM_DATA_DIR is process-global; HOME_TEST_LOCK serializes us with
        // every other test that mutates env-derived path roots.
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os("MVM_DATA_DIR");
        // SAFETY: guarded by HOME_TEST_LOCK.
        unsafe { std::env::set_var("MVM_DATA_DIR", "/var/home/user/.mvm") };
        let p = instance_rootfs_path("vm-1").expect("resolve rootfs path");
        assert_eq!(
            p,
            std::path::PathBuf::from("/var/home/user/.mvm/vms/vm-1/rootfs.ext4")
        );
        unsafe {
            match saved {
                Some(v) => std::env::set_var("MVM_DATA_DIR", v),
                None => std::env::remove_var("MVM_DATA_DIR"),
            }
        }
    }

    #[test]
    fn prepare_instance_rootfs_inner_clones_into_per_instance_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let src = temp.path().join("template.ext4");
        std::fs::write(&src, b"template payload").expect("write src");

        let instance = temp.path().join(".mvm/vms/test-vm/rootfs.ext4");
        let path = prepare_instance_rootfs_inner(&instance, src.to_str().unwrap()).expect("clone");

        assert_eq!(path, instance);
        assert_eq!(std::fs::read(&path).unwrap(), b"template payload");

        // Idempotent stale-cleanup: a second call after writes to the
        // clone should produce a fresh per-instance copy from the source.
        std::fs::write(&path, b"prior failed run").expect("write stale");
        let second_path =
            prepare_instance_rootfs_inner(&instance, src.to_str().unwrap()).expect("re-clone");
        assert_eq!(std::fs::read(&second_path).unwrap(), b"template payload");
    }

    #[test]
    fn prepare_instance_rootfs_inner_is_noop_when_source_matches_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let instance = temp.path().join(".mvm/vms/restart/rootfs.ext4");
        std::fs::create_dir_all(instance.parent().unwrap()).expect("mkdir");
        std::fs::write(&instance, b"already-instance").expect("seed");

        let p = prepare_instance_rootfs_inner(&instance, instance.to_str().unwrap()).expect("noop");
        assert_eq!(p, instance);
        // Source content preserved — no clone, no stale-cleanup.
        assert_eq!(std::fs::read(&instance).unwrap(), b"already-instance");
    }

    #[test]
    fn test_apple_container_list_returns_empty() {
        // Isolate HOME so the persisted ~/.mvm/vms registry doesn't bleed
        // into this assertion when the developer's real dev VM is running.
        let temp = std::path::PathBuf::from(format!(
            "/tmp/mvmac-list-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&temp).expect("create temp HOME");
        let saved = std::env::var("HOME").ok();
        // SAFETY: list() is the only HOME consumer in this test; no other
        // threads in this test process race with it.
        unsafe { std::env::set_var("HOME", &temp) };

        let backend = AppleContainerBackend;
        let vms = backend.list().unwrap();
        assert!(vms.is_empty());

        unsafe {
            match saved {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_apple_container_stop_all_succeeds() {
        let backend = AppleContainerBackend;
        assert!(backend.stop_all().is_ok());
    }

    #[test]
    fn test_apple_container_status_returns_stopped() {
        let backend = AppleContainerBackend;
        let status = backend.status(&VmId("test".into())).unwrap();
        assert_eq!(status, VmStatus::Stopped);
    }
}
