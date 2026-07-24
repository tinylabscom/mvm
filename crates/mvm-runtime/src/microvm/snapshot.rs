//! Firecracker snapshot controls that do not alter the runner's device model.

use anyhow::{Context, Result};
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

/// Refuse live-memory restore entry points.
///
/// A restored VMM can reintroduce devices captured in an older snapshot, so
/// Firecracker memory restore is unavailable on the vsock-only workload path.
pub fn warm_restore_instance(
    name: &str,
    _token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    anyhow::bail!(
        "Firecracker memory restore is disabled; use the vsock workload runner for a cold boot of '{name}'"
    )
}

pub fn warm_restore_instance_from_path(
    name: &str,
    _snapshot_dir: &str,
    _token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    anyhow::bail!(
        "Firecracker memory restore is disabled; use the vsock workload runner for '{name}'"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_restore_is_fail_closed() {
        let err = warm_restore_instance("vm", [0u8; mvm_core::crypto::vmgenid::GENID_BYTES])
            .expect_err("legacy restore must refuse");
        assert!(err.to_string().contains("disabled"));
    }
}
