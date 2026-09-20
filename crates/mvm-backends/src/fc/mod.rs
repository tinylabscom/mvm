//! Firecracker-specific host mechanics: the API client, the VMM process
//! lifecycle, and the fork mount namespace.
//!
//! Implementation detail of the Firecracker backend. Items are `pub` only
//! where something outside this crate genuinely names them.

pub mod capabilities;
pub mod control;
pub mod daemon;
pub mod fc_api;
pub mod fork_namespace;
pub mod guards;
pub mod host;
pub mod io;
pub mod lifecycle;
pub mod observe;
pub mod snapshot;
pub mod snapshot_decode;

pub use capabilities::*;
pub use control::*;
pub use daemon::*;
pub use fc_api::*;
pub use fork_namespace::*;
pub use guards::*;
pub use host::*;
pub use io::*;
pub use lifecycle::*;
pub use observe::*;
pub use snapshot::*;
pub use snapshot_decode::UndecodableSnapshot;

use std::path::{Path, PathBuf};

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

/// The directory Firecracker's host-side sockets live under for the VM whose
/// state dir is `dir`: the API socket, the vsock mux, and every
/// `v.sock_<port>` the guest dials.
///
/// That is the state dir itself unless it is too deep for a Unix socket path,
/// in which case it is the same short hashed namespace every other per-VM
/// socket falls back to. The kernel refuses an over-long `sun_path` outright,
/// so without the fallback a long `MVM_HOME` does not produce a slow
/// Firecracker, it produces one that exits before creating its API socket.
pub fn fc_socket_dir(dir: &str) -> PathBuf {
    mvm_core::config::vm_socket_dir_at(Path::new(dir))
}

/// Firecracker's API socket for the VM whose state dir is `dir`.
pub fn fc_api_socket_path(dir: &str) -> String {
    fc_socket_dir(dir).join(FC_API_SOCKET).display().to_string()
}

/// The directory holding the vsock mux and the `v.sock_<port>` sockets the
/// guest dials, for the VM whose state dir is `dir`.
pub fn fc_vsock_runtime_dir(dir: &str) -> PathBuf {
    fc_socket_dir(dir).join(FC_VSOCK_RUNTIME_DIR)
}

/// Path to the host-side UDS that proxies the guest agent's vsock port for a
/// Firecracker VM whose per-VM directory is `dir` (as returned by
/// [`resolve_running_vm_dir`]). `pub` so CLI-layer callers — e.g. the FC fork
/// path delivering a post-restore grant to a forked child — can locate the
/// same socket used by the verified snapshot restore paths, without
/// reimplementing the layout.
pub fn firecracker_vsock_uds_path(dir: &str) -> String {
    fc_vsock_runtime_dir(dir)
        .join(FC_VSOCK_MUX)
        .display()
        .to_string()
}

/// Refuse a VM whose Firecracker sockets were moved out of its state dir,
/// for a path that records them relative to that dir.
///
/// A fork remaps the parent's state dir onto the child's inside a private
/// mount namespace, and finds that dir as the vsock socket's grandparent. With
/// the sockets relocated those are two different directories, so the remap
/// would carry the vsock and leave the config and secrets drives pointing at
/// the parent's copies. Refusing is the only safe answer there.
pub fn ensure_fc_sockets_in_state_dir(dir: &str, what: &str) -> Result<()> {
    let socket_dir = fc_socket_dir(dir);
    if socket_dir != Path::new(dir) {
        anyhow::bail!(
            "{what} needs Firecracker's sockets inside the VM state dir {dir}, but that path \
             is too long for a Unix socket (limit {} bytes), so they live in {} instead; \
             use a shorter MVM_HOME",
            mvm_core::config::UNIX_SOCKET_PATH_MAX_BYTES,
            socket_dir.display()
        );
    }
    Ok(())
}

/// Firecracker's API socket file name.
const FC_API_SOCKET: &str = "fc.socket";
/// The subdirectory holding the vsock mux and the guest-dialed sockets.
const FC_VSOCK_RUNTIME_DIR: &str = "runtime";
/// The vsock mux socket file name. Firecracker derives each guest-dialed
/// socket from it as `v.sock_<port>`.
const FC_VSOCK_MUX: &str = "v.sock";

#[cfg(test)]
mod tests {
    use super::*;

    /// The longest socket Firecracker creates under its socket dir.
    fn longest_fc_socket(dir: &str) -> PathBuf {
        fc_vsock_runtime_dir(dir).join(format!("{FC_VSOCK_MUX}_{}", u32::from(u16::MAX)))
    }

    #[test]
    fn a_short_state_dir_keeps_every_firecracker_socket_in_place() {
        let dir = "/srv/state/vms/mvm-stage0-firecracker-26289-1789708959173633880";
        assert_eq!(fc_socket_dir(dir), Path::new(dir));
        assert_eq!(fc_api_socket_path(dir), format!("{dir}/fc.socket"));
        assert_eq!(
            firecracker_vsock_uds_path(dir),
            format!("{dir}/runtime/v.sock")
        );
        ensure_fc_sockets_in_state_dir(dir, "a fork").expect("a short dir keeps its sockets");
    }

    /// The hosted-runner cold bootstrap's state dir: 98 bytes, which put the
    /// API socket at 108 and made Firecracker exit with "path must be shorter
    /// than SUN_LEN" before it created anything.
    #[test]
    fn a_state_dir_too_deep_for_a_socket_moves_every_firecracker_socket() {
        let dir = "/home/runner/work/_temp/source-bootstrap-home/vms/\
                   mvm-stage0-firecracker-26289-1789708959173633880";
        assert!(
            !mvm_core::config::fits_unix_socket_path(Path::new(&format!("{dir}/fc.socket"))),
            "the fixture must reproduce an over-long API socket"
        );
        for socket in [
            PathBuf::from(fc_api_socket_path(dir)),
            PathBuf::from(firecracker_vsock_uds_path(dir)),
            longest_fc_socket(dir),
        ] {
            assert!(
                !socket.starts_with(dir),
                "{} must leave the state dir",
                socket.display()
            );
            assert!(
                mvm_core::config::fits_unix_socket_path(&socket),
                "{} must fit a Unix socket",
                socket.display()
            );
        }
        let err = ensure_fc_sockets_in_state_dir(dir, "a fork")
            .expect_err("relocated sockets must refuse a fork");
        assert!(err.to_string().contains("MVM_HOME"), "{err}");
    }

    /// Whenever the shared fallback keeps the state dir, every Firecracker
    /// socket must fit too — otherwise the fallback is measuring the wrong
    /// names and a dir at the threshold boots nothing.
    #[test]
    fn the_shared_fallback_threshold_covers_firecracker_socket_names() {
        let base = "/h/vms/";
        for len in 1..120 {
            let dir = format!("{base}{}", "a".repeat(len));
            if fc_socket_dir(&dir) != Path::new(&dir) {
                continue;
            }
            for socket in [
                PathBuf::from(fc_api_socket_path(&dir)),
                longest_fc_socket(&dir),
            ] {
                assert!(
                    mvm_core::config::fits_unix_socket_path(&socket),
                    "{} kept in place but does not fit",
                    socket.display()
                );
            }
        }
    }
}
