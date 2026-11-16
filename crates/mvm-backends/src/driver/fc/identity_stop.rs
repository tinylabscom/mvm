//! A Firecracker shutdown target pinned to a kernel process lifetime.

use std::path::Path;

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
#[cfg(any(target_os = "linux", test))]
use anyhow::ensure;
use mvm_vmm::host::process_identity::ProcessIdentity;

/// Prepared identity-bound stop authority. Unsupported kernels fail closed.
#[derive(Debug)]
pub struct FirecrackerStop {
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
}

impl FirecrackerStop {
    /// Pin the exact observed process and verify its executable and API socket.
    pub fn connect(process: &ProcessIdentity, api_socket: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::FromRawFd;
            let pid = libc::pid_t::try_from(process.pid)?;
            ensure!(pid > 1, "invalid Firecracker PID");
            // Arm before inspecting /proc: any later signal uses only this
            // descriptor, never a PID that may have been recycled meanwhile.
            // SAFETY: pidfd_open takes scalar arguments and returns an owned fd.
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            let raw = libc::c_int::try_from(raw).context("pidfd outside descriptor range")?;
            ensure!(
                raw >= 0,
                "pin Firecracker process: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: successful pidfd_open returned a new owned descriptor.
            let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            validate_identity(
                process,
                &ProcessIdentity::capture(&process.vm_id, process.pid)?,
            )?;
            ensure!(
                crate::fc::host::is_firecracker_for_socket(process.pid, api_socket)?,
                "Firecracker API socket does not belong to registered process"
            );
            let exe = std::fs::read_link(format!("/proc/{}/exe", process.pid))?;
            ensure!(
                exe.file_name().is_some_and(|name| name == "firecracker"),
                "registered process executable is not Firecracker"
            );
            // The observations must bracket the executable/socket check.
            validate_identity(
                process,
                &ProcessIdentity::capture(&process.vm_id, process.pid)?,
            )?;
            let target = Self { pidfd };
            target
                .signal(0)
                .context("registered Firecracker is not signalable")?;
            ensure!(
                !target.wait(std::time::Instant::now())?,
                "registered Firecracker has already exited"
            );
            Ok(target)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (process, api_socket);
            anyhow::bail!("identity-bound Firecracker stop requires Linux pidfd support")
        }
    }

    /// Stop only the pinned lifetime, with the driver's existing grace/escalation.
    pub fn stop(self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            super::terminate_observed(
                |signal| {
                    self.signal(match signal {
                        super::FcStopSignal::Terminate => libc::SIGTERM,
                        super::FcStopSignal::ForceKill => libc::SIGKILL,
                    })
                },
                |deadline| self.wait(deadline),
            )
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("identity-bound Firecracker stop requires Linux pidfd support")
    }

    #[cfg(target_os = "linux")]
    fn signal(&self, signal: libc::c_int) -> Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: the pidfd is owned and the optional siginfo pointer is null.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) || signal == 0 {
                return Err(error).context("signal pinned Firecracker");
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn wait(&self, deadline: std::time::Instant) -> Result<bool> {
        use std::os::fd::AsRawFd;
        loop {
            let timeout = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll receives one initialized descriptor and a finite timeout.
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("wait for pinned Firecracker");
            }
            ensure!(
                descriptor.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
                "invalid Firecracker lifetime observer"
            );
            return Ok(descriptor.revents & libc::POLLIN != 0);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn validate_identity(expected: &ProcessIdentity, observed: &ProcessIdentity) -> Result<()> {
    ensure!(expected == observed, "Firecracker process identity changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recycled_pid_or_reboot_never_matches_the_registered_process() {
        let identity = ProcessIdentity {
            vm_id: "workload".into(),
            pid: 42,
            start_ticks: 70,
            boot_id: "boot".into(),
        };
        validate_identity(&identity, &identity).unwrap();
        for replacement in [
            ProcessIdentity {
                start_ticks: 71,
                ..identity.clone()
            },
            ProcessIdentity {
                boot_id: "next-boot".into(),
                ..identity.clone()
            },
            ProcessIdentity {
                vm_id: "replacement".into(),
                ..identity.clone()
            },
        ] {
            assert!(validate_identity(&identity, &replacement).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_ordinary_child_is_not_a_firecracker_shutdown_target() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let process = ProcessIdentity::capture("workload", child.id()).unwrap();
        assert!(FirecrackerStop::connect(&process, Path::new("/not/a/vm/socket")).is_err());
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_stop_refuses_a_stale_identity_then_stops_only_the_registered_child() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("firecracker");
        let current = std::env::current_exe().unwrap();
        std::fs::hard_link(&current, &executable)
            .or_else(|_| std::fs::copy(&current, &executable).map(|_| ()))
            .unwrap();
        let socket = directory.path().join("api.sock");
        let mut child = ChildGuard(
            std::process::Command::new(&executable)
                .args([
                    "--ignored",
                    "--exact",
                    "driver::fc::identity_stop::tests::firecracker_process_fixture",
                    "--skip",
                    "--api-sock",
                ])
                .arg(&socket)
                .env("MVM_FC_STOP_TEST", "1")
                .spawn()
                .unwrap(),
        );
        let identity = ProcessIdentity::capture("workload", child.0.id()).unwrap();
        let mut stale = identity.clone();
        stale.start_ticks += 1;
        assert!(FirecrackerStop::connect(&stale, &socket).is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        let target = FirecrackerStop::connect(&identity, &socket).unwrap();
        assert!(FirecrackerStop::connect(&identity, &directory.path().join("other.sock")).is_err());
        target.stop().unwrap();
        assert!(!child.0.wait().unwrap().success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "subprocess fixture for the pidfd stop test"]
    fn firecracker_process_fixture() {
        if std::env::var_os("MVM_FC_STOP_TEST").is_none() {
            return;
        }
        loop {
            std::thread::park();
        }
    }
}
