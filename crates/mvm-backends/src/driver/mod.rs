//! Concrete [`mvm_vmm::driver::VmmDriver`] implementations.

pub mod fc;
pub mod hvf;
pub mod hvf_bootargs;
pub mod hvf_restore;
pub mod libkrun;
pub mod qemu;

pub mod hvf_process;
pub mod libkrun_process;
pub mod qemu_process;

pub use fc::FcDriver;
pub use hvf::HvfDriver;
pub use libkrun::LibkrunDriver;
pub use qemu::QemuDriver;

/// Keep socket fixtures independent of a potentially deep platform `TMPDIR`.
/// The private directory is removed with its owner; the process environment
/// and production socket namespace are never changed.
#[cfg(test)]
fn socket_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;

    tempfile::Builder::new()
        .prefix("mvm-sock-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .expect("create short private socket fixture directory")
}

/// Host-dialable workload services. Guest-dialed and builder-only services
/// must never be exposed through a workload's host connection API.
fn host_dialable_port(port: u32) -> bool {
    use mvm_net::channel::GuestService;
    port == GuestService::MachineControl.port()
        || port == GuestService::Telemetry.port()
        || mvm_agentd::vsock::dev_console_data_ports().any(|allowed| allowed == port)
}

#[cfg(test)]
mod tests {
    use super::host_dialable_port;
    use mvm_net::channel::GuestService;

    #[test]
    fn socket_fixture_binds_nested_endpoints_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = super::socket_tempdir();
        let root = dir.path().to_path_buf();
        assert_eq!(root.parent(), Some(std::path::Path::new("/tmp")));
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for relative in [
            "child/runtime/v.sock_5254",
            "vsock/vsock-20001.sock",
            "hvf-agent.sock",
        ] {
            let socket = root.join(relative);
            std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
            let listener = UnixListener::bind(&socket).unwrap();
            let client = UnixStream::connect(&socket).unwrap();
            let (server, _) = listener.accept().unwrap();
            drop((client, server, listener));
        }
        drop(dir);
        assert!(
            !root.exists(),
            "the socket fixture must remove its owned state"
        );
    }

    #[test]
    fn host_dial_ports_exclude_guest_dialed_and_builder_services() {
        for port in 0..=u32::from(u16::MAX) {
            assert_eq!(
                host_dialable_port(port),
                port == GuestService::MachineControl.port()
                    || port == GuestService::Telemetry.port()
                    || (20001..=20128).contains(&port),
                "unexpected host-dial policy for port {port}"
            );
        }
        assert!(!host_dialable_port(u32::MAX));
    }
}
