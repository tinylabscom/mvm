//! Firecracker-specific host mechanics: the API client, the VMM process
//! lifecycle, and the fork mount namespace.
//!
//! Implementation detail of the Firecracker backend. Items are `pub` only
//! where something outside this crate genuinely names them.

pub mod daemon;
pub mod fc_api;
pub mod fork_namespace;
pub mod lifecycle;

pub use daemon::*;
pub use fc_api::*;
pub use fork_namespace::*;
pub use lifecycle::*;

use anyhow::Result;

/// Absolute root of the per-VM directories (`<mvm_home>/vms`) as a `String`
/// for shell interpolation. A host path, resolved on the host — never `echo`d
/// inside a VM (on macOS every `run_in_vm` shells into the dev VM,
/// auto-starting a heavyweight builder; on Linux the in-VM env is the host,
/// so host-side resolution is identical anyway).
pub fn abs_vms_dir() -> String {
    mvm_core::config::vms_dir().display().to_string()
}

/// Resolve the absolute directory path for a running VM by name:
/// `<mvm_home>/vms/<name>`. A host path the VMM reads, resolved on the host.
pub fn resolve_running_vm_dir(name: &str) -> Result<String> {
    Ok(mvm_core::config::running_vm_dir(name))
}

/// Return the host-side path to Firecracker's PID file for VM `name`:
/// `<mvm_home>/vms/<name>/fc.pid`. The Firecracker workspace shares the
/// per-VM directory with the host metadata every backend writes; the file
/// sets are disjoint (`fc.*`, `run-info.json` vs pid/console/socket files).
///
/// Returns `None` when the mvm root cannot be resolved (neither `MVM_HOME`
/// nor `$HOME` set — e.g. hermetic test environments that intentionally
/// omit them).
pub fn fc_pid_path(name: &str) -> Option<std::path::PathBuf> {
    mvm_core::config::mvm_home_strict().ok()?;
    Some(mvm_core::config::vm_state_dir(name).join("fc.pid"))
}

/// Path to the host-side UDS that proxies the guest agent's vsock port for a
/// Firecracker VM whose per-VM directory is `dir` (as returned by
/// [`resolve_running_vm_dir`]). `pub` so CLI-layer callers — e.g. the FC fork
/// path delivering a post-restore grant to a forked child — can locate the
/// same socket used by the verified snapshot restore paths, without
/// reimplementing the layout.
pub fn firecracker_vsock_uds_path(dir: &str) -> String {
    format!("{dir}/runtime/v.sock")
}
