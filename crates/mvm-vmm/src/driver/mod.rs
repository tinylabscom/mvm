//! Backend-agnostic VMM driver seam.
//!
//! The `VmmDriver` trait, `RunningVm` handle, and the backend-agnostic boot
//! recipe (`VmmSpec`) live here, with the concrete [`VmmDriver`]
//! implementations beside them, below the workload lifecycle orchestration in
//! `mvm-runtime`.

#[cfg(unix)]
pub mod prepared_disks;
#[cfg(unix)]
pub mod readonly_data;
pub mod spec;
pub mod traits;

pub use traits::{
    ChildForkRequest, DuplexStream, LateVolumeAttach, PreloadedResumeError, RunningVm,
    RunningVmStopTiming, StandbyParentSpawn, VmmDriver,
};

// Concrete drivers, one feature per backend family. `fc` turns on `libkrun`
// and `qemu` too: the Firecracker driver reuses libkrun's stop deadline and
// QEMU's KVM probe.
#[cfg(feature = "fc")]
pub mod fc;
#[cfg(feature = "hvf")]
pub mod hvf;
#[cfg(feature = "hvf")]
pub mod hvf_bootargs;
#[cfg(feature = "hvf")]
pub mod hvf_restore;
#[cfg(feature = "libkrun")]
pub mod libkrun;
#[cfg(feature = "qemu")]
pub mod qemu;

#[cfg(feature = "hvf")]
pub mod hvf_process;
#[cfg(feature = "libkrun")]
pub mod libkrun_process;
#[cfg(feature = "qemu")]
pub mod qemu_process;

#[cfg(feature = "fc")]
pub use fc::FcDriver;
#[cfg(feature = "hvf")]
pub use hvf::HvfDriver;
#[cfg(feature = "libkrun")]
pub use libkrun::LibkrunDriver;
#[cfg(feature = "qemu")]
pub use qemu::QemuDriver;

/// Keep socket fixtures independent of a potentially deep platform `TMPDIR`.
/// The private directory is removed with its owner; the process environment
/// and production socket namespace are never changed.
#[cfg(all(test, any(feature = "fc", feature = "hvf")))]
pub(crate) fn socket_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;

    tempfile::Builder::new()
        .prefix("mvm-sock-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .expect("create short private socket fixture directory")
}

/// Kill a child that timed out or failed during boot, and reap it, so a
/// long-lived parent never accumulates zombies. Failures are logged rather
/// than returned: the caller is already on the error path this exists for.
#[cfg(feature = "libkrun")]
pub(crate) fn kill_and_reap(child: &mut std::process::Child) {
    if let Err(error) = child.kill() {
        tracing::warn!(%error, pid = child.id(), "failed to kill child on error path");
    }
    if let Err(error) = child.wait() {
        tracing::warn!(%error, pid = child.id(), "failed to reap killed child");
    }
}

/// Host-dialable workload services. Guest-dialed and builder-only services
/// must never be exposed through a workload's host connection API.
#[cfg(any(feature = "fc", feature = "libkrun", feature = "qemu"))]
fn host_dialable_port(port: u32) -> bool {
    use mvm_core::net::channel::GuestService;
    port == GuestService::MachineControl.port()
        || port == GuestService::Telemetry.port()
        || mvm_agentd::vsock::dev_console_data_ports().any(|allowed| allowed == port)
}

#[cfg(all(test, feature = "fc", feature = "libkrun"))]
mod tests {
    use super::host_dialable_port;
    use mvm_core::net::channel::GuestService;

    #[test]
    fn kill_and_reap_leaves_no_zombie() {
        // Another test may have emptied the process-wide PATH; taking the env lock keeps
        // this spawn out of that window.
        let _env = mvm_core::util::test_env::TestEnv::new();
        let mut child = std::process::Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep fixture");
        let pid = i32::try_from(child.id()).expect("child pid fits pid_t");
        super::kill_and_reap(&mut child);
        // The helper must have reaped the child: a raw WNOHANG waitpid then
        // finds no child at all (ECHILD). A zombie would be reported
        // reapable (waitpid returns its pid).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: `pid` names our own just-spawned child; `status` is a
            // writable int buffer read only after a successful call.
            let found = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if found == -1 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD),
                    "waitpid failed for a reason other than the child being reaped"
                );
                return;
            }
            assert_ne!(found, pid, "child was left a zombie: killed but not reaped");
            assert!(
                std::time::Instant::now() < deadline,
                "killed child did not exit within the deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

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
