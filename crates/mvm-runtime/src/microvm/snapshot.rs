//! Firecracker snapshot capture controls and fail-closed legacy restore entries.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::instrument;

use crate::base::shell::shell_quote;

use super::daemon::api_put_socket;
use super::{abs_vms_dir, require_linux_env};

/// Refuse template snapshot restore.
///
/// Snapshots capture complete VMM device state and may contain the retired
/// Firecracker NIC. The runner's cold-boot path is the only admitted workload
/// launch path.
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

/// Refuse the legacy live-memory restore entry point.
///
/// Verified instance resume is owned by `vm::instance_snapshot`, and verified
/// checkpoint forks use `FirecrackerIO::load_snapshot_for_fork` directly.
pub fn warm_restore_instance(
    name: &str,
    _token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    anyhow::bail!(
        "Firecracker memory restore is disabled; use the verified snapshot resume path for '{name}'"
    )
}

pub fn warm_restore_instance_from_path(
    name: &str,
    _snapshot_dir: &str,
    _token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    anyhow::bail!(
        "Firecracker memory restore is disabled; use the verified snapshot fork path for '{name}'"
    )
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
        assert!(err.to_string().contains("verified snapshot resume path"));
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
}
