//! The two directions of a Firecracker host vsock channel.

use std::path::{Path, PathBuf};

use mvm_core::vm_backend::HostDialRoute;

/// The host UDS Firecracker connects *out* to when the guest dials
/// `CID_HOST:<port>`: the sibling `<runtime_dir>/v.sock_<port>` of the vsock mux
/// socket. The host must own a listener there before the guest dials.
pub(super) fn fc_guest_dial_socket(runtime_dir: &Path, port: u32) -> PathBuf {
    runtime_dir.join(format!("v.sock_{port}"))
}

/// How the host dials a port the guest listens on: through the VM's vsock mux
/// with the `CONNECT <port>` handshake. Firecracker bridges no per-port socket.
pub(super) fn mux_route(state_dir: &Path) -> HostDialRoute {
    HostDialRoute::Mux(PathBuf::from(mvm_agentd::vsock::vsock_uds_path(
        &state_dir.to_string_lossy(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guest_dial_socket_is_the_mux_sibling_for_the_port() {
        assert_eq!(
            fc_guest_dial_socket(Path::new("/run/vm"), 7),
            Path::new("/run/vm/v.sock_7")
        );
    }

    #[test]
    fn the_host_reaches_the_guest_through_the_mux() {
        let state = Path::new("/var/mvm/vm-a");
        let HostDialRoute::Mux(mux) = mux_route(state) else {
            panic!("firecracker has no per-port socket");
        };
        assert_eq!(
            mux,
            Path::new(&mvm_agentd::vsock::vsock_uds_path("/var/mvm/vm-a"))
        );
    }
}
