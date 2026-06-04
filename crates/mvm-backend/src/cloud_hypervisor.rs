//! Cloud Hypervisor backend for mvm.
//!
//! Cloud Hypervisor (CH) is a rust-vmm-based Tier 1 microVM monitor —
//! the same family as Firecracker, with a richer device model. mvm
//! offers it as a peer to Firecracker at the same security tier;
//! the choice between them is workload-shape, not security-shape.
//!
//! ## When to pick Cloud Hypervisor over Firecracker
//!
//! - **VFIO passthrough** (PCI device passthrough, including GPU).
//!   Firecracker explicitly excludes this from its device model;
//!   ADR-013 §"GPU and graphics support" names CH as the path for
//!   compute-GPU workloads (CUDA, ROCm, etc.).
//! - **virtio-gpu** for accelerated graphics in-VM (FC doesn't support).
//! - **Larger guests**: CH's memory + device model handles more vCPUs
//!   and devices than FC's intentionally minimal one.
//! - **virtio-fs** for high-throughput shared filesystems (FC's path
//!   is more limited).
//!
//! Firecracker remains the default for typical mvm workloads — its
//! attack surface is smaller, boot is faster, and the security work
//! (jailer, dm-verity, seccomp tier) targets it. CH is for workloads
//! that need what FC deliberately doesn't have.
//!
//! ## Status
//!
//! `start`/`stop`/`stop_all`/`status`/`list`/`logs` are wired
//! against the Cloud Hypervisor JSON API via `crate::ch_runtime`.
//! The implementation has not yet been validated end-to-end against
//! a live `cloud-hypervisor` binary (mvm CI lacks a Linux+CH host
//! today); the pure pieces (JSON config builder, path helpers) are
//! unit-tested in `ch_runtime`, and the shell-out paths are
//! reviewed against CH's published API but will surface real-world
//! fitness issues on first live run.
//!
//! Once validated, CH is selectable via:
//!
//!   `mvmctl run --hypervisor cloud-hypervisor`
//!
//! and the `mkGuest { hypervisor = "cloud-hypervisor"; }` argument.
//!
//! ## What's deliberately out of scope here
//!
//! - **TAP networking.** CH supports `net` configs the same shape
//!   as Firecracker, but mvm's TAP+bridge plumbing
//!   (`crate::network`) is FC-specific today. The CH start path
//!   does not configure networking — VMs boot with vsock only.
//!   Wiring TAP in is a follow-up that mirrors what
//!   `microvm::run_from_build` does for FC.
//! - **Snapshot/restore.** CH supports them; the host-side
//!   snapshot mvm orchestrates (`mvm-security::snapshot_hmac` +
//!   `template_snapshot_dir`) is FC-API-shaped today.
//! - **dm-verity.** ADR-002 §W3 targets Firecracker; CH parity
//!   is the Tier-1-equality follow-up named in the security
//!   profile note.

use anyhow::{Context, Result};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage, StartMode, VmBackend,
    VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::ch_runtime;

/// Cloud Hypervisor backend (rust-vmm; Linux/KVM + macOS/HVF).
///
/// Same security tier as Firecracker (Tier 1, rust-vmm-based,
/// passes the plan 53 "fork test"); richer device model. The choice
/// between CH and FC is workload-shape, not security-shape.
pub struct CloudHypervisorBackend;

/// Default kernel cmdline for CH-booted guests. Matches FC's mvm
/// minimal-guest shape (`init=/init` runs the busybox /init from
/// `mkGuest`'s rootfs; `console=ttyS0` so CH's `serial: Tty` mode
/// gets the bootlog). No `net.ifnames=0`/`mvm.ip=...` because CH
/// boots vsock-only here (see module docs on TAP being out of
/// scope).
const DEFAULT_CMDLINE: &str = "root=/dev/vda rw rootwait init=/init \
console=ttyS0 reboot=k panic=1";

impl VmBackend for CloudHypervisorBackend {
    fn name(&self) -> &str {
        "cloud-hypervisor"
    }

    fn capabilities(&self) -> VmCapabilities {
        // CH supports more than Firecracker: pause/resume, snapshots,
        // VFIO, virtio-gpu, virtio-fs. We surface the subset that's
        // generic at this level; backend-specific extras (GPU,
        // virtio-fs) are addressed via dedicated fields when the
        // VmStartConfig + VmCapabilities shapes grow them.
        //
        // `tap_networking: false` reflects the current
        // implementation: the start path does not configure a TAP
        // device. CH itself supports TAP — flip to `true` once the
        // network-wiring follow-up lands.
        VmCapabilities {
            pause_resume: true,
            snapshots: true,
            vsock: true,
            tap_networking: false,
            // Cloud-hypervisor exposes virtio-balloon via the
            // `balloon` field on `VmConfig` and the
            // `/api/v1/vm.resize` endpoint for runtime adjustment.
            // Same opt-in shape as Firecracker — present only when
            // `VmStartConfig::mem_initial_mib` is `Some`.
            balloon: true,
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        let kernel = config
            .kernel_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("cloud-hypervisor start requires kernel_path"))?;
        if config.rootfs_path.is_empty() {
            anyhow::bail!("cloud-hypervisor start requires rootfs_path");
        }

        // Per-VM directory + sockets. Same convention as FC.
        let abs_dir = ch_runtime::ch_vm_dir(&config.name)
            .with_context(|| format!("resolving per-VM dir for {}", config.name))?;
        let api_socket = ch_runtime::ch_api_socket(&abs_dir);
        let vsock_socket = ch_runtime::ch_vsock_socket(&abs_dir);

        // W6.2 console gate — same call site as the other 4 real
        // backends. Records `accessible` from the sidecar so
        // `mvmctl console` enforces the gate consistently.
        let rootfs = std::path::Path::new(&config.rootfs_path);
        // Plan 74 W2 / ADR-051 admission gate — refuse pre-W1.4b
        // rootfs that lack the `/mvm/runtime` mount point. Runs
        // before any backend-side work so a refusal exits clean
        // (no daemon started, no PID file left behind).
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| std::path::Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;

        // Spawn the daemon. Waits for the API socket.
        ch_runtime::start_ch_daemon(&abs_dir, &api_socket)?;

        let memory_mib = if config.memory_mib == 0 {
            256
        } else {
            config.memory_mib
        };
        // Balloon opt-in. CH validates `mem_initial < memory` for us
        // at vm.create, but we mirror Firecracker's defensive check
        // so the misuse surfaces with a clearer host-side message.
        let balloon_mib = match config.mem_initial_mib {
            Some(0) => {
                anyhow::bail!("cloud-hypervisor: mem_initial_mib must be > 0 when set");
            }
            Some(initial) if initial >= memory_mib => {
                anyhow::bail!(
                    "cloud-hypervisor: mem_initial_mib ({initial}) must be < memory_mib ({memory_mib})"
                );
            }
            Some(initial) => Some(memory_mib - initial),
            None => None,
        };

        // Configure the VM. CH ignores fields we omit; only the
        // required shape is sent.
        let args = ch_runtime::VmConfigArgs {
            kernel_path: kernel,
            rootfs_path: &config.rootfs_path,
            initrd_path: config.initrd_path.as_deref(),
            cmdline: Some(DEFAULT_CMDLINE),
            cpus: config.cpus.max(1),
            memory_mib,
            balloon_mib,
            vsock_cid: 3,
            vsock_socket_path: vsock_socket,
        };
        let body = ch_runtime::build_vm_config(&args);
        ch_runtime::api_put(&abs_dir, &api_socket, "/api/v1/vm.create", &body)?;

        // Boot.
        ch_runtime::api_put_empty(&api_socket, "/api/v1/vm.boot")?;

        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let abs_dir = ch_runtime::ch_vm_dir(&id.0)
            .with_context(|| format!("resolving per-VM dir for {}", id.0))?;
        let api_socket = ch_runtime::ch_api_socket(&abs_dir);

        // Graceful guest shutdown (ACPI poweroff). Best-effort:
        // teardown of the VMM below reaps the daemon regardless.
        let _ = ch_runtime::api_put_empty(&api_socket, "/api/v1/vm.shutdown");
        // Then exit the VMM — frees the API socket + reaps the
        // daemon's child processes.
        let _ = ch_runtime::api_put_empty(&api_socket, "/api/v1/vmm.shutdown");

        // Best-effort process + socket cleanup.
        ch_runtime::reap(&abs_dir)
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        let abs_dir = ch_runtime::ch_vm_dir(&id.0)
            .with_context(|| format!("resolving per-VM dir for {}", id.0))?;
        let api_socket = ch_runtime::ch_api_socket(&abs_dir);
        ch_runtime::api_put_empty(&api_socket, "/api/v1/vm.pause")
            .with_context(|| format!("PUT /api/v1/vm.pause for VM '{}'", id.0))
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        let abs_dir = ch_runtime::ch_vm_dir(&id.0)
            .with_context(|| format!("resolving per-VM dir for {}", id.0))?;
        let api_socket = ch_runtime::ch_api_socket(&abs_dir);
        ch_runtime::api_put_empty(&api_socket, "/api/v1/vm.resume")
            .with_context(|| format!("PUT /api/v1/vm.resume for VM '{}'", id.0))
    }

    fn balloon_set_target(&self, id: &VmId, target_inflate_mib: u32) -> Result<()> {
        let abs_dir = ch_runtime::ch_vm_dir(&id.0)
            .with_context(|| format!("resolving per-VM dir for {}", id.0))?;
        let api_socket = ch_runtime::ch_api_socket(&abs_dir);
        let bytes = u64::from(target_inflate_mib) * 1024 * 1024;
        // CH's resize endpoint accepts `desired_vcpus`, `desired_ram`,
        // and `desired_balloon` (all optional). Sending only the
        // balloon field leaves vcpus + ram alone.
        let body = format!(r#"{{"desired_balloon": {bytes}}}"#);
        ch_runtime::api_put(&abs_dir, &api_socket, "/api/v1/vm.resize", &body).with_context(|| {
            format!(
                "PUT /api/v1/vm.resize (desired_balloon={bytes}) for VM '{}'; \
                     VM may have been launched without `mem_initial_mib` (no balloon device)",
                id.0
            )
        })
    }

    fn balloon_state(&self, id: &VmId) -> Result<mvm_core::vm_backend::BalloonState> {
        let abs_dir = ch_runtime::ch_vm_dir(&id.0)
            .with_context(|| format!("resolving per-VM dir for {}", id.0))?;
        let api_socket = ch_runtime::ch_api_socket(&abs_dir);
        let body = ch_runtime::api_get(&api_socket, "/api/v1/vm.info")
            .with_context(|| format!("GET /api/v1/vm.info for VM '{}'", id.0))?;
        let parsed: serde_json::Value = serde_json::from_str(body.trim())
            .with_context(|| format!("parse vm.info response: {body:?}"))?;

        // Memory cap comes from `config.memory.size` (bytes); CH
        // doesn't echo a separate "max balloon" so we derive it.
        // Current balloon inflation is at `config.balloon.size` —
        // CH keeps the live size up-to-date there after resize.
        let memory_bytes = parsed
            .pointer("/config/memory/size")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("vm.info missing /config/memory/size: {body}"))?;
        let balloon_bytes = parsed
            .pointer("/config/balloon/size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let mib = |b: u64| (b / (1024 * 1024)) as u32;
        let max_mib = mib(memory_bytes);
        let inflated_mib = mib(balloon_bytes);
        Ok(mvm_core::vm_backend::BalloonState {
            max_mib,
            inflated_mib,
            host_committed_mib: max_mib.saturating_sub(inflated_mib),
        })
    }

    fn stop_all(&self) -> Result<()> {
        let names = ch_runtime::list_ch_vms().unwrap_or_default();
        let mut first_err: Option<anyhow::Error> = None;
        for name in names {
            if let Err(e) = self.stop(&VmId(name.clone())) {
                tracing::warn!(vm = %name, error = %e, "stop_all: failed to stop CH VM");
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let abs_dir = match ch_runtime::ch_vm_dir(&id.0) {
            Ok(d) => d,
            Err(_) => return Ok(VmStatus::Stopped),
        };
        let pid_file = ch_runtime::ch_pid_file(&abs_dir);
        if ch_runtime::is_pid_alive(&pid_file).unwrap_or(false) {
            Ok(VmStatus::Running)
        } else {
            Ok(VmStatus::Stopped)
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let names = ch_runtime::list_ch_vms().unwrap_or_default();
        Ok(names
            .into_iter()
            .map(|name| VmInfo {
                id: VmId(name.clone()),
                name,
                status: VmStatus::Running,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            })
            .collect())
    }

    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        let abs_dir = ch_runtime::ch_vm_dir(&id.0)
            .with_context(|| format!("resolving per-VM dir for {}", id.0))?;
        let filename = if hypervisor { "ch.log" } else { "console.log" };
        let log_file = format!("{abs_dir}/{filename}");
        crate::base::shell::run_in_vm_stdout(&format!(
            "tail -n {lines} {log_file} 2>/dev/null || true"
        ))
    }

    fn is_available(&self) -> Result<bool> {
        Ok(mvm_core::platform::current().has_cloud_hypervisor())
    }

    fn install(&self) -> Result<()> {
        anyhow::bail!(
            "Cloud Hypervisor must be installed via the host's package \
             manager (apt: cloud-hypervisor; nixpkgs: cloud-hypervisor; \
             cargo: cloud-hypervisor) or downloaded from \
             https://github.com/cloud-hypervisor/cloud-hypervisor/releases. \
             Once installed, mvm detects it on PATH automatically."
        )
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // CH exposes vsock natively; the guest agent listens on the
        // shared GUEST_AGENT_PORT (same contract as Firecracker /
        // libkrun / libkrun).
        Ok(GuestChannelInfo::Vsock {
            cid: 3,
            port: mvm_guest::vsock::GUEST_AGENT_PORT,
        })
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 1 — rust-vmm-based, comparable VMM TCB to Firecracker.
        // Passes the plan 53 §"fork test" (rust-vmm origin, no
        // Firecracker-excluded features in the boot path; the richer
        // device set is opt-in per VM, not always-on).
        //
        // Claim 3 (verified boot) is partial because the W3 dm-verity
        // pipeline currently targets Firecracker; CH support is a
        // follow-up that lands alongside the bring-up wave.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1 — host-fs isolation via KVM/HVF
                ClaimStatus::Holds,       // 2 — uid-0 protections same as FC
                ClaimStatus::DoesNotHold, // 3 — verified boot pending
                ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds,       // 5 — vsock framing is fuzzed
                ClaimStatus::Holds,       // 6 — image hash verification
                ClaimStatus::Holds,       // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 1",
            notes: &[
                "rust-vmm-based; comparable VMM TCB to Firecracker.",
                "Picks up where Firecracker stops: VFIO, virtio-gpu, \
                 virtio-fs, larger guests.",
                "Claim 3 (verified boot) pending — dm-verity pipeline \
                 targets Firecracker today; CH parity is a follow-up.",
                "Default for workloads that need CH-specific devices; \
                 Firecracker remains the default for typical mvm work.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_hypervisor_backend_name() {
        assert_eq!(CloudHypervisorBackend.name(), "cloud-hypervisor");
    }

    #[test]
    fn cloud_hypervisor_capabilities_richer_than_firecracker() {
        let caps = CloudHypervisorBackend.capabilities();
        assert!(caps.pause_resume, "CH supports pause/resume");
        assert!(caps.snapshots, "CH supports snapshots");
        assert!(caps.vsock, "CH supports vsock");
        // tap_networking is false in this implementation — CH
        // supports it, but the start path doesn't wire TAP yet.
        // See module docs ("What's deliberately out of scope here").
        assert!(!caps.tap_networking, "CH TAP wiring is a follow-up");
    }

    #[test]
    fn cloud_hypervisor_security_profile_is_tier_1_with_partial_claim_3() {
        let p = CloudHypervisorBackend.security_profile();
        assert_eq!(p.tier, "Tier 1");
        assert!(p.layer_coverage.is_microvm());
        assert_eq!(
            p.dropped_claims(),
            vec![3],
            "claim 3 (verified boot) is the only outstanding gap"
        );
    }

    #[test]
    fn cloud_hypervisor_start_requires_kernel_path() {
        // Empty kernel_path / missing rootfs surface as a clear
        // input-validation error *before* any shell-out fires —
        // catches misuse without needing a live CH binary.
        let config = VmStartConfig {
            name: "ch-test".to_string(),
            rootfs_path: "/tmp/rootfs.ext4".to_string(),
            ..Default::default()
        };
        let err = CloudHypervisorBackend
            .start(&config)
            .expect_err("start without kernel_path must error");
        assert!(
            err.to_string().contains("kernel_path"),
            "error must name kernel_path, got: {err}"
        );
    }

    #[test]
    fn cloud_hypervisor_start_requires_rootfs_path() {
        let config = VmStartConfig {
            name: "ch-test".to_string(),
            kernel_path: Some("/k/vmlinux".to_string()),
            rootfs_path: String::new(),
            ..Default::default()
        };
        let err = CloudHypervisorBackend
            .start(&config)
            .expect_err("start without rootfs_path must error");
        assert!(
            err.to_string().contains("rootfs_path"),
            "error must name rootfs_path, got: {err}"
        );
    }

    #[test]
    fn cloud_hypervisor_stop_all_is_idempotent_when_no_vms() {
        // No CH VMs in this test environment — stop_all walks an
        // empty list and returns Ok. The host-mutating shell-out
        // path is fenced by `list_ch_vms` returning empty.
        CloudHypervisorBackend
            .stop_all()
            .expect("stop_all over no-VMs must be Ok");
    }

    #[test]
    fn cloud_hypervisor_status_returns_stopped_when_pid_absent() {
        // No pid file under ~/microvm/vms/<name>/ — status reports
        // Stopped without erroring. Exercises the "no VM here" path
        // through the real `is_pid_alive` shell-out.
        let s = CloudHypervisorBackend
            .status(&VmId("ch-status-test-no-vm".to_string()))
            .expect("status must not error on absent VM");
        assert_eq!(s, VmStatus::Stopped);
    }

    #[test]
    fn cloud_hypervisor_guest_channel_uses_shared_vsock_port() {
        let info = CloudHypervisorBackend
            .guest_channel_info(&VmId("any".to_string()))
            .expect("guest_channel_info is static in scaffolding");
        let GuestChannelInfo::Vsock { cid, port } = info else {
            panic!("CH must use vsock, not UnixSocket");
        };
        assert_eq!(cid, 3);
        assert_eq!(port, mvm_guest::vsock::GUEST_AGENT_PORT);
    }
}
