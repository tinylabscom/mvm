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
//! The template restore entry point and the bare `warm_restore_instance`
//! stay refused. A template snapshot carries its own Ed25519 + HMAC sidecar
//! (a separate, stronger check) that isn't wired up yet; `warm_restore_instance`
//! has no caller. Re-enabling either needs a design that keeps its own
//! integrity check and adds the same guard ordering on top of it.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::instrument;

use crate::base::shell::shell_quote;
use crate::vm::instance_snapshot::{
    FirecrackerIO, POST_RESTORE_READY_TIMEOUT, VsockPostRestoreSignal, guarded_load_resume,
    signal_post_restore,
};

use super::daemon::api_put_socket;
use super::{abs_vms_dir, require_linux_env};

/// Refuse template snapshot restore.
///
/// Snapshots capture complete VMM device state and may contain a network
/// interface, bypassing the vsock-only egress boundary. Template snapshots
/// are sealed with their own Ed25519 + HMAC sidecar, a separate mechanism
/// from the instance-snapshot HMAC path the no-NIC guard is wired behind;
/// restoring them needs a design that keeps that signature check AND adds
/// the guard, so this stays refused until that design lands.
#[instrument(skip_all, fields(template_id, name = %config.name))]
pub fn restore_from_template_snapshot(
    template_id: &str,
    config: &super::flake_run::FlakeRunConfig,
    snapshot_dir: &str,
    _snapshot_info: &mvm_core::template::SnapshotInfo,
) -> Result<()> {
    let _ = (template_id, snapshot_dir);
    config.validate()?;
    anyhow::bail!(
        "Firecracker template snapshot restore is disabled; use the vsock workload runner"
    );
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

    // Delivering the reseed token is best-effort: the guest agent takes a
    // beat to re-accept on the recreated vsock after the fresh VMM starts, so
    // a transport failure here must not undo an otherwise-successful
    // restore — the VM is already up and resumed past the guard. The fork
    // caller passes an all-zero token (no rotation) and delivers the real
    // token + verb grant over vsock separately once it observes the agent is
    // reachable; a zero token's honest outcome is `NotRotated`, not `Rotated`.
    let reseed = match signal_post_restore(
        name,
        &VsockPostRestoreSignal {
            token,
            grant_envelope: None,
        },
        POST_RESTORE_READY_TIMEOUT,
    ) {
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

// The device-model guard lives in mvm-vmm so every backend shares one
// implementation of the refusal. Re-exported here for callers that still
// reach for it by its original path.
pub use mvm_vmm::snapshot::assert_vsock_only_device_model;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_restore_is_fail_closed() {
        let err = warm_restore_instance("vm", [0u8; mvm_core::crypto::vmgenid::GENID_BYTES])
            .expect_err("legacy restore must refuse");
        assert!(err.to_string().contains("disabled"));
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
        let err = assert_vsock_only_device_model(config.network_interfaces.len())
            .expect_err("a NIC in the model must refuse");
        assert!(
            err.to_string().contains("vsock-only egress boundary"),
            "expected the vsock-boundary refusal, got: {err}"
        );
    }

    #[test]
    fn restore_accepts_vsock_only_device_model() {
        let config = device_model_with(Vec::new());
        assert_vsock_only_device_model(config.network_interfaces.len())
            .expect("no NIC must be admitted");
    }

    #[test]
    fn restore_refuses_multiple_nic_device_model() {
        let config = device_model_with(vec![
            serde_json::json!({"iface_id": "eth0"}),
            serde_json::json!({"iface_id": "eth1"}),
        ]);
        let err = assert_vsock_only_device_model(config.network_interfaces.len())
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
        assert!(assert_vsock_only_device_model(config.network_interfaces.len()).is_err());
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
        assert!(assert_vsock_only_device_model(config.network_interfaces.len()).is_ok());
    }
}
