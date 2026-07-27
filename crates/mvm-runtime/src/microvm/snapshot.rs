//! Firecracker snapshot controls, gated on the device-model guard below.
//!
//! `verify_and_resume` / `verify_and_resume_from_dir` in
//! `crate::vm::instance_snapshot` run the no-NIC guard strictly between
//! loading a snapshot paused and resuming it — see there for the full
//! ordering. That path backs the live `mvmctl pause`/`resume` cycle today.
//!
//! `warm_restore_instance_from_path` reuses the same load → guard → resume
//! ordering via `guarded_load_resume`, but skips the instance-snapshot HMAC
//! verify: its caller (the fork restore path) already established the
//! content's integrity upstream via the checkpoint lineage's content-address
//! and audit-chain checks, so a second verifier here would either be
//! redundant or fail closed on content it was never meant to see.
//!
//! `restore_from_template_snapshot` runs `verify_snapshot_artifacts` (the
//! template snapshot's own Ed25519 + HMAC sidecar — a separate, stronger
//! check than the instance-snapshot HMAC path) before calling
//! `guarded_load_resume`. See its doc comment for a known device re-bind
//! limitation this path does not yet close. The bare `warm_restore_instance`
//! stays refused — it has no caller.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::instrument;

use crate::base::shell::shell_quote;
#[cfg(test)]
use crate::vm::instance_snapshot::SpyIO;
use crate::vm::instance_snapshot::{
    FirecrackerIO, PrimedOutcome, VsockPostRestoreSignal, guarded_load_resume, signal_post_restore,
    wait_for_primed_polling,
};

use super::daemon::api_put_socket;
use super::{abs_vms_dir, require_linux_env};

/// Restore `template_id`'s sealed Firecracker snapshot into a fresh, paused
/// VMM for `config.name`: verify the template's own Ed25519 + HMAC sidecar
/// (`crate::base::snapshot_integrity::verify_snapshot_artifacts`) before any
/// Firecracker work, then run the same load → no-NIC-guard → resume ordering
/// as the fork restore path via `guarded_load_resume`. Fails closed at either
/// step: a tampered/unsigned snapshot never reaches Firecracker, and a
/// NIC-carrying restored device model is torn down and never resumed.
///
/// This deliberately does NOT route through the instance-snapshot HMAC
/// verifier (`verify_and_resume`/`verify_and_resume_from_dir`): that path is
/// the AES-GCM/HMAC envelope `mvmctl pause`/`resume` seals under a
/// per-tenant DEK, a different mechanism than a template's Ed25519-signed
/// sidecar. Running it here would either drop the Ed25519 check silently or
/// fail closed on content it was never meant to see.
///
/// # Known limitation: device re-bind
///
/// A restored VMM reopens whatever host paths were baked into `vmstate.bin`
/// at snapshot-creation time — the rootfs drive, the vsock UDS, and so on.
/// The fork restore path (`FcForkRestorer::restore_fork`) captures those
/// paths in a `device-anchors.json` sidecar and bind-mounts the new
/// instance's own device files over them in a private mount namespace
/// before calling `guarded_load_resume`, so the snapshot's baked-in absolute
/// paths resolve to the right content for that instance.
///
/// Nothing analogous exists for a template snapshot. `allocate_slot` only
/// reserves a fresh `~/.mvm/vms/<name>/` directory for `config.name` — it
/// lays down no rootfs/vsock backing files at whatever paths the template's
/// `vmstate.bin` recorded, and the seal side
/// (`crate::base::snapshot_integrity::seal_snapshot_artifacts`) captures no
/// device-anchor sidecar to remap from. Until a template-snapshot
/// device-anchor-and-remap mechanism lands, a real restore attempt fails
/// inside `load_snapshot_paused`'s `PUT /snapshot/load` call the moment
/// Firecracker tries to reopen a drive or vsock path that doesn't exist
/// under the fresh instance directory — that failure surfaces as an `Err`
/// before the device-model guard or `resume` ever runs, so this is a clean
/// refusal rather than a silent wrong-device restore, but it is also not yet
/// a working end-to-end path. Nothing in the shipped CLI populates a
/// template revision's `SnapshotInfo` today (`seal_snapshot_artifacts` has no
/// caller), so wiring the verify+guard ordering here carries no live
/// regression risk; treat this as scaffolding the create-side wiring still
/// needs to land on top of.
#[instrument(skip_all, fields(template_id, name = %config.name))]
pub fn restore_from_template_snapshot(
    template_id: &str,
    config: &super::flake_run::FlakeRunConfig,
    snapshot_dir: &str,
    _snapshot_info: &mvm_core::template::SnapshotInfo,
) -> Result<()> {
    config.validate()?;
    // Defense in depth: `config.name` is interpolated into shell commands
    // inside `load_snapshot_paused` (`FirecrackerIO` shells out to stop a
    // stale paused process and start a fresh one). Re-check at the boundary
    // so no caller can smuggle shell/JSON metacharacters in.
    mvm_core::naming::validate_vm_name(&config.name)
        .with_context(|| format!("template restore refused invalid VM name {:?}", config.name))?;
    require_linux_env()?;

    crate::base::snapshot_integrity::verify_snapshot_artifacts(snapshot_dir).with_context(
        || format!("verifying template '{template_id}' snapshot integrity at {snapshot_dir}"),
    )?;

    let abs_vms = abs_vms_dir();
    let vm_dir = format!("{}/{}", abs_vms.trim(), config.name);
    let socket = std::path::PathBuf::from(format!("{vm_dir}/fc.socket"));
    let io = FirecrackerIO::new(socket);

    guarded_load_resume(&io, std::path::Path::new(snapshot_dir)).with_context(|| {
        format!(
            "restoring template '{template_id}' snapshot for '{}' from {snapshot_dir}",
            config.name
        )
    })
}

/// Refuse the bare live-memory restore entry point.
///
/// Unlike [`warm_restore_instance_from_path`], this resolves its own snapshot
/// directory (the canonical per-instance `~/.mvm/instances/<name>/snapshot/`)
/// rather than taking a caller-verified one, so it would need its own
/// instance-snapshot HMAC verify wired in before it could reuse
/// `guarded_load_resume`. It has no caller today — stays refused until that
/// design lands.
pub fn warm_restore_instance(
    name: &str,
    _token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    anyhow::bail!(
        "Firecracker memory restore is disabled; use the vsock workload runner for a cold boot of '{name}'"
    )
}

/// Warm-restore `name` from the sealed content at `snapshot_dir` into its
/// running (paused) Firecracker, then best-effort deliver `token` so the
/// guest reseeds.
///
/// Callers other than the fork restore path do not exist yet. The fork
/// path's checkpoint content is content-addressed and audit-chain verified
/// upstream of this call — by `verify_content` and
/// `verify_checkpoint_against_chain` inside the checkpoint lineage module,
/// before the checkpoint triple is even cloned into `snapshot_dir` — so this
/// function deliberately does NOT run the instance-snapshot HMAC verifier
/// (`verify_and_resume_from_dir`) on that content: it was never sealed by
/// that envelope, and re-running an unrelated verifier against it would fail
/// closed on legitimate fork content. It goes straight to
/// [`guarded_load_resume`], which still runs the no-NIC device-model guard
/// between load and resume.
pub fn warm_restore_instance_from_path(
    name: &str,
    snapshot_dir: &str,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    // Defense in depth: `name` is interpolated into shell commands inside
    // `load_snapshot_paused` (`FirecrackerIO` shells out to stop a stale
    // paused process and start a fresh one). The CLI validates the name
    // earlier, but this is a `pub fn` reachable from other crates — re-check
    // at the boundary so no caller can smuggle shell/JSON metacharacters in.
    mvm_core::naming::validate_vm_name(name)
        .with_context(|| format!("warm-restore refused invalid VM name {name:?}"))?;
    require_linux_env()?;

    let abs_vms = abs_vms_dir();
    let vm_dir = format!("{}/{name}", abs_vms.trim());
    let socket = std::path::PathBuf::from(format!("{vm_dir}/fc.socket"));
    let io = FirecrackerIO::new(socket);

    guarded_load_resume(&io, std::path::Path::new(snapshot_dir))
        .with_context(|| format!("warm-restore of '{name}' from {snapshot_dir}"))?;

    // Give a freshly-resumed guest a bounded window to reattach its vsock
    // connection before delivering the reseed signal — without this, a
    // merely slow-to-reattach guest (not a genuinely broken one) spuriously
    // reports `Undelivered`. Skipped for the fork path's no-rotation
    // (all-zero) token: there is nothing to reseed, so no reason to add
    // latency waiting on a probe whose answer wouldn't change anything.
    let zero_token = [0u8; mvm_core::crypto::vmgenid::GENID_BYTES];
    if token != zero_token
        && !should_attempt_reseed_delivery(RESEED_POLL_TIMEOUT, RESEED_POLL_INTERVAL, || {
            probe_guest_reachable(name)
        })
    {
        tracing::warn!(
            name,
            timeout = ?RESEED_POLL_TIMEOUT,
            "warm-restore: guest agent unreachable after readiness poll (VM is resumed) — reporting reseed undelivered"
        );
        return Ok(mvm_core::vm_backend::ReseedStatus::Undelivered);
    }

    // Delivering the reseed token is still best-effort past the readiness
    // poll: a transport failure here must not undo an otherwise-successful
    // restore — the VM is already up and resumed past the guard.
    let reseed = match signal_post_restore(name, &VsockPostRestoreSignal { token }) {
        Ok(outcome) if outcome.reseeded => mvm_core::vm_backend::ReseedStatus::Rotated,
        Ok(_) => mvm_core::vm_backend::ReseedStatus::NotRotated,
        Err(e) => {
            tracing::warn!(
                name,
                error = %e,
                "warm-restore: post-restore signal undelivered (VM is resumed)"
            );
            mvm_core::vm_backend::ReseedStatus::Undelivered
        }
    };
    Ok(reseed)
}

/// Bounded deadline for the guest-agent reachability poll that runs before
/// delivering the reseed signal — generous enough to cover a slow vsock
/// reattach after a fresh Firecracker VMM starts.
const RESEED_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Delay between reseed-delivery reachability polls.
const RESEED_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// One reachability probe against the guest agent for `vm_name` — mirrors
/// [`crate::vm::instance_snapshot::VsockPrimedSignalSource::probe_once`], but
/// checks basic vsock reachability (`Ping`/`Pong`) rather than the workload's
/// warmup barrier: reseed delivery only needs to know the agent is back on
/// vsock, not that the workload has finished warming. Any transport/agent
/// error is treated as "not yet reachable" (best-effort) so a transient blip
/// during vsock reattach doesn't end the poll early — the bounded deadline
/// still applies.
fn probe_guest_reachable(vm_name: &str) -> bool {
    use mvm_agentd::vsock::{GUEST_AGENT_PORT, GuestRequest, GuestResponse, call_unary};
    let Ok(transport) = crate::vsock_transport::for_vm(vm_name) else {
        return false;
    };
    let Ok(mut stream) = transport.connect(GUEST_AGENT_PORT) else {
        return false;
    };
    matches!(
        call_unary(&mut stream, &GuestRequest::Ping),
        Ok(GuestResponse::Pong)
    )
}

/// Decide whether reseed delivery should proceed: polls `probe` up to
/// `timeout` (reusing [`wait_for_primed_polling`]'s bounded-poll policy) and
/// reports whether the guest became reachable in time.
///
/// Pure aside from the clock/sleep inside `wait_for_primed_polling`, so the
/// "poll until reachable, else give up at the deadline" policy is
/// unit-tested with a fake probe — no live guest. The caller is responsible
/// for skipping this entirely on a no-rotation (zero) token; this function
/// always polls when called.
fn should_attempt_reseed_delivery<F: FnMut() -> bool>(
    timeout: std::time::Duration,
    interval: std::time::Duration,
    probe: F,
) -> bool {
    wait_for_primed_polling(timeout, interval, probe) == PrimedOutcome::Primed
}

pub fn create_snapshot_files(
    name: &str,
    vmstate_path: &std::path::Path,
    mem_path: &std::path::Path,
) -> Result<()> {
    require_linux_env()?;
    anyhow::ensure!(
        vmstate_path.is_absolute(),
        "vmstate_path must be absolute, got {}",
        vmstate_path.display()
    );
    anyhow::ensure!(
        mem_path.is_absolute(),
        "mem_path must be absolute, got {}",
        mem_path.display()
    );

    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let socket = format!("{}/fc.socket", abs_dir);
    let q_socket = shell_quote(&socket);

    let vmstate_str = vmstate_path.to_string_lossy();
    let mem_str = mem_path.to_string_lossy();

    // PUT /snapshot/create with snapshot_type=Full writes vmstate + guest memory.
    // The VM must be paused before this call; Firecracker refuses the request
    // with an error if vCPUs are still running.
    let payload = format!(
        r#"{{"snapshot_type":"Full","snapshot_path":"{vmstate}","mem_file_path":"{mem}"}}"#,
        vmstate = vmstate_str,
        mem = mem_str,
    );
    api_put_socket(&socket, "/snapshot/create", &payload).with_context(|| {
        format!(
            "PUT /snapshot/create for VM '{}' (socket {})",
            name, q_socket
        )
    })?;
    Ok(())
}

/// Partial view of Firecracker's own restored-VM configuration (the shape
/// `GET /vm/config` reports once a snapshot is loaded), carrying only the
/// `network-interfaces` array.
///
/// This is intentionally not `#[serde(deny_unknown_fields)]`: it is a slice
/// of Firecracker's own config schema (which also carries `boot-source`,
/// `drives`, `machine-config`, `vsock`, and more), not a host↔snapshot
/// type mvm controls end to end. Rejecting the fields we don't read would
/// make this view brittle against upstream additions.
#[derive(Debug, Deserialize)]
pub struct RestoredDeviceModel {
    #[serde(rename = "network-interfaces", default)]
    pub network_interfaces: Vec<serde_json::Value>,
}

/// Parse a `GET /vm/config` response body into a [`RestoredDeviceModel`].
///
/// A standalone function (rather than inlining `serde_json::from_str` at the
/// one production call site in [`FirecrackerIO::restored_device_model`])
/// so it's directly reachable — no live Firecracker needed — for adversarial
/// testing of this parser: it runs on a Firecracker-controlled response body,
/// which this crate does not treat as fully trusted input.
///
/// [`FirecrackerIO::restored_device_model`]: crate::vm::instance_snapshot::FirecrackerIO::restored_device_model
pub fn parse_restored_device_model(body: &str) -> Result<RestoredDeviceModel> {
    serde_json::from_str(body).context("parsing GET /vm/config response")
}

/// Refuse to restore a snapshot whose device model carries a network
/// interface.
///
/// A restored VMM reconstructs whatever devices the snapshot captured. Any
/// network interface would let guest traffic reach a device outside the
/// vsock transport, bypassing the sole auditable egress boundary — so a
/// non-empty `network-interfaces` list is a hard refusal, not a warning.
///
/// Pure: inspects only the passed-in config. No I/O, no VM, no clock.
pub fn assert_vsock_only_device_model(config: &RestoredDeviceModel) -> Result<()> {
    let count = config.network_interfaces.len();
    anyhow::ensure!(
        count == 0,
        "restore refused: the snapshot's device model carries {count} network \
         interface(s) — a network interface would bypass the vsock-only egress boundary"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_restore_is_fail_closed() {
        let err = warm_restore_instance("vm", [0u8; mvm_core::crypto::vmgenid::GENID_BYTES])
            .expect_err("legacy restore must refuse");
        assert!(err.to_string().contains("disabled"));
    }

    // ──────────────────────────────────────────────────────────────
    // Template restore — Ed25519 verify + no-NIC guard
    // ──────────────────────────────────────────────────────────────

    fn test_run_config(name: &str) -> super::super::flake_run::FlakeRunConfig {
        super::super::flake_run::FlakeRunConfig {
            name: name.to_string(),
            slot: crate::base::config::VmSlot::new(name, 0),
            vmlinux_path: "/k/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/k/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            revision_hash: "abc".to_string(),
            flake_ref: "/p".to_string(),
            profile: None,
            cpus: 2,
            memory: 1024,
            mem_initial: None,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
        }
    }

    fn test_snapshot_info() -> mvm_core::template::SnapshotInfo {
        mvm_core::template::SnapshotInfo {
            created_at: "2026-01-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 1,
            mem_size_bytes: 1,
            boot_args: "console=ttyS0".to_string(),
            vcpus: 1,
            mem_mib: 128,
            compatibility: None,
        }
    }

    /// Mirrors `fork_restore_refuses_nic` in `crate::vm::instance_snapshot`:
    /// the template restore path composes on the same `guarded_load_resume`
    /// ordering, so a NIC-carrying restored device model must refuse, tear
    /// down the paused VMM, and never resume — regardless of which caller
    /// (fork or template) established content integrity upstream.
    #[test]
    fn template_restore_refuses_nic() {
        let spy = SpyIO::new(true);
        let dir = tempfile::tempdir().unwrap();
        let err =
            guarded_load_resume(&spy, dir.path()).expect_err("a NIC-carrying restore must refuse");
        assert!(err.to_string().contains("device-model guard"), "got: {err}");
        let calls = spy.calls();
        assert!(
            calls.contains(&"teardown_paused"),
            "a refused restore must tear down the paused VMM: {calls:?}"
        );
        assert!(
            !calls.contains(&"resume"),
            "resume must never run when the guard refuses: {calls:?}"
        );
    }

    #[test]
    fn template_restore_refuses_tampered_snapshot() {
        // Hermetic: MVM_HOME points at a tempdir so the HMAC key and Ed25519
        // signing identity `seal_snapshot_artifacts`/`verify_snapshot_artifacts`
        // load are test-local, never the real host's.
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let snap_dir = tmp.path().join("snap");
        std::fs::create_dir_all(&snap_dir).unwrap();
        std::fs::write(snap_dir.join("vmstate.bin"), b"template-vmstate").unwrap();
        std::fs::write(snap_dir.join("mem.bin"), b"template-mem").unwrap();
        let snap_dir_str = snap_dir.to_string_lossy().into_owned();

        crate::base::snapshot_integrity::seal_snapshot_artifacts(&snap_dir_str)
            .expect("sealing a freshly-written snapshot must succeed");

        // Tamper with the sealed vmstate — the HMAC (and Ed25519 signature)
        // sidecar no longer matches the bytes on disk.
        let mut bytes = std::fs::read(snap_dir.join("vmstate.bin")).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(snap_dir.join("vmstate.bin"), &bytes).unwrap();

        let config = test_run_config("tmpl-restore-vm");
        let info = test_snapshot_info();
        let err = restore_from_template_snapshot("tmpl-1", &config, &snap_dir_str, &info)
            .expect_err("a tampered template snapshot must refuse restore");
        let chained: String = err
            .chain()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            chained.contains("HMAC verification"),
            "expected the verify step's own failure, got: {chained}"
        );
        assert!(
            !chained.contains("restoring template"),
            "verify must fail closed before guarded_load_resume ever runs: {chained}"
        );
    }

    fn device_model_with(network_interfaces: Vec<serde_json::Value>) -> RestoredDeviceModel {
        RestoredDeviceModel { network_interfaces }
    }

    #[test]
    fn restore_refuses_nic_device_model() {
        let config = device_model_with(vec![serde_json::json!({
            "iface_id": "eth0",
            "host_dev_name": "tap0",
        })]);
        let err =
            assert_vsock_only_device_model(&config).expect_err("a NIC in the model must refuse");
        assert!(
            err.to_string().contains("vsock-only egress boundary"),
            "expected the vsock-boundary refusal, got: {err}"
        );
    }

    #[test]
    fn restore_accepts_vsock_only_device_model() {
        let config = device_model_with(Vec::new());
        assert_vsock_only_device_model(&config).expect("no NIC must be admitted");
    }

    #[test]
    fn restore_refuses_multiple_nic_device_model() {
        let config = device_model_with(vec![
            serde_json::json!({"iface_id": "eth0"}),
            serde_json::json!({"iface_id": "eth1"}),
        ]);
        let err = assert_vsock_only_device_model(&config)
            .expect_err("multiple NICs in the model must refuse");
        assert!(err.to_string().contains('2'), "count in message: {err}");
    }

    #[test]
    fn restored_device_model_parses_network_interfaces_from_full_vm_config_json() {
        // Shaped after Firecracker's own `GET /vm/config` response: several
        // sibling sections this view does not model at all. Deserializing
        // must succeed and ignore everything but `network-interfaces`.
        let raw = serde_json::json!({
            "boot-source": {"kernel_image_path": "/vmlinux", "boot_args": "console=ttyS0"},
            "drives": [{"drive_id": "rootfs", "path_on_host": "/rootfs.ext4"}],
            "machine-config": {"vcpu_count": 2, "mem_size_mib": 1024},
            "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0"}],
            "vsock": {"vsock_id": "vsock0", "guest_cid": 3, "uds_path": "/v.sock"},
        })
        .to_string();

        let config: RestoredDeviceModel = serde_json::from_str(&raw).unwrap();
        assert_eq!(config.network_interfaces.len(), 1);
        assert!(assert_vsock_only_device_model(&config).is_err());
    }

    #[test]
    fn restored_device_model_defaults_to_empty_when_field_absent() {
        // Older/minimal config bodies may omit `network-interfaces` entirely
        // (Firecracker only includes devices that were actually attached);
        // absence must mean "no NIC", not a deserialization failure.
        let raw = serde_json::json!({
            "boot-source": {"kernel_image_path": "/vmlinux", "boot_args": "console=ttyS0"},
        })
        .to_string();

        let config: RestoredDeviceModel = serde_json::from_str(&raw).unwrap();
        assert!(config.network_interfaces.is_empty());
        assert!(assert_vsock_only_device_model(&config).is_ok());
    }

    #[test]
    fn parse_restored_device_model_rejects_malformed_body() {
        let err = parse_restored_device_model("not json").unwrap_err();
        assert!(
            err.to_string().contains("parsing GET /vm/config response"),
            "got: {err}"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Reseed-delivery readiness poll — the poll POLICY, no live guest
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn reseed_delivery_proceeds_once_the_probe_becomes_reachable() {
        use std::cell::Cell;
        use std::time::Duration;
        let calls = Cell::new(0u32);
        let should_attempt = should_attempt_reseed_delivery(
            Duration::from_secs(5),
            Duration::from_millis(1),
            || {
                calls.set(calls.get() + 1);
                calls.get() >= 3
            },
        );
        assert!(should_attempt, "delivery must proceed once reachable");
        assert_eq!(calls.get(), 3, "stops polling at the first success");
    }

    #[test]
    fn reseed_delivery_gives_up_when_the_probe_never_becomes_reachable() {
        use std::time::Duration;
        let should_attempt = should_attempt_reseed_delivery(
            Duration::from_millis(15),
            Duration::from_millis(1),
            || false,
        );
        assert!(
            !should_attempt,
            "an unreachable guest past the deadline must give up, not hang"
        );
    }
}
