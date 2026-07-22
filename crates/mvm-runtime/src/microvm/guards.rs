//! RAII resource guards — prevent leaks when VM launch fails partway through.

use tracing::warn;

use crate::base::config::VmSlot;
use crate::base::shell::run_in_vm;
use crate::network;

/// RAII guard for a Firecracker process started on the Linux host.
///
/// On drop, kills the Firecracker process using the PID file and cleans up
/// the API socket. Call `defuse()` after a successful launch to prevent
/// cleanup (ownership transfers to the normal stop path).
pub struct FirecrackerGuard {
    /// Absolute path to the VM directory on the Linux host (contains fc.pid, fc.socket).
    abs_dir: Option<String>,
}

impl FirecrackerGuard {
    /// Create a new guard for a Firecracker process in the given directory.
    pub fn new(abs_dir: &str) -> Self {
        Self {
            abs_dir: Some(abs_dir.to_string()),
        }
    }

    /// Defuse the guard — prevents cleanup on drop.
    /// Call this after the VM has been fully started and run-info written.
    pub fn defuse(&mut self) {
        self.abs_dir = None;
    }
}

impl Drop for FirecrackerGuard {
    fn drop(&mut self) {
        if let Some(ref dir) = self.abs_dir {
            warn!(dir = %dir, "FirecrackerGuard: killing orphaned Firecracker process");
            if let Err(e) = run_in_vm(&format!(
                r#"
                if [ -f {dir}/fc.pid ]; then
                    sudo kill "$(cat {dir}/fc.pid)" 2>/dev/null || true
                    rm -f {dir}/fc.pid
                elif [ -f {dir}/.fc-pid ]; then
                    sudo kill "$(cat {dir}/.fc-pid)" 2>/dev/null || true
                    rm -f {dir}/.fc-pid
                fi
                sudo rm -f {dir}/fc.socket
                "#,
                dir = dir,
            )) {
                warn!("FirecrackerGuard: cleanup failed: {e}");
            }
        }
    }
}

/// RAII guard for a TAP network interface created on the Linux host.
///
/// On drop, destroys the TAP device. Call `defuse()` after a successful
/// launch to prevent cleanup (ownership transfers to the normal stop path).
pub struct TapGuard {
    slot: Option<VmSlot>,
}

impl TapGuard {
    /// Create a new guard for a TAP device associated with the given slot.
    pub fn new(slot: &VmSlot) -> Self {
        Self {
            slot: Some(slot.clone()),
        }
    }

    /// Defuse the guard — prevents cleanup on drop.
    pub fn defuse(&mut self) {
        self.slot = None;
    }
}

impl Drop for TapGuard {
    fn drop(&mut self) {
        if let Some(ref slot) = self.slot {
            warn!(tap = %slot.tap_dev, "TapGuard: destroying orphaned TAP device");
            if let Err(e) = network::tap_destroy(slot) {
                warn!("TapGuard: cleanup failed: {e}");
            }
        }
    }
}

/// Removes a slot reservation if launch fails before real run-info is written.
pub struct SlotReservationGuard {
    slot: Option<VmSlot>,
}

impl SlotReservationGuard {
    pub fn new(slot: &VmSlot) -> Self {
        Self {
            slot: Some(slot.clone()),
        }
    }

    pub fn defuse(&mut self) {
        self.slot = None;
    }
}

impl Drop for SlotReservationGuard {
    fn drop(&mut self) {
        if let Some(ref slot) = self.slot
            && let Err(e) = super::observe::release_slot_reservation(slot)
        {
            warn!(
                vm = %slot.name,
                slot = slot.index,
                "SlotReservationGuard: cleanup failed: {e}"
            );
        }
    }
}

/// RAII reaper for the per-VM substitution endpoint when it is spawned
/// **before** boot (the placeholders it mints must ride the boot
/// cmdline). If a later boot step fails and returns before the endpoint
/// is fully wired, `Drop` reaps it so its decrypted-secret process can't outlive
/// a failed launch. Defused once the VM is fully up (the normal `stop_vm` path
/// then owns teardown, same as `FirecrackerGuard`/`TapGuard`).
#[cfg(target_os = "linux")]
pub struct EndpointGuard {
    pub(super) vm_name: Option<String>,
}

#[cfg(target_os = "linux")]
impl EndpointGuard {
    pub(super) fn new(vm_name: &str) -> Self {
        Self {
            vm_name: Some(vm_name.to_string()),
        }
    }
    pub(super) fn defuse(&mut self) {
        self.vm_name = None;
    }
}

#[cfg(target_os = "linux")]
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(ref name) = self.vm_name {
            warn!(vm = %name, "EndpointGuard: reaping orphaned substitution endpoint");
            crate::substitution_spawn::reap_substitution_endpoint(
                &mvm_core::config::vm_state_dir(name),
                name,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_guard_defuse_prevents_cleanup() {
        use crate::base::shell_mock;

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();
        let _handler = shell_mock::install_handler(move |_script: &str| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let mut guard = FirecrackerGuard::new("/tmp/test-vm");
            guard.defuse();
            // guard drops here — should NOT call shell
        }

        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "defused FirecrackerGuard must not run cleanup"
        );
    }

    #[test]
    fn firecracker_guard_runs_cleanup_on_drop() {
        use crate::base::shell_mock;

        let scripts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let scripts_clone = scripts.clone();
        let _handler = shell_mock::install_handler(move |script: &str| {
            scripts_clone
                .lock()
                .expect("mutex must not be poisoned")
                .push(script.to_string());
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let _guard = FirecrackerGuard::new("/tmp/test-vm");
            // guard drops here without defuse — should run cleanup
        }

        let captured = scripts.lock().expect("mutex must not be poisoned");
        assert_eq!(captured.len(), 1, "FirecrackerGuard must call cleanup once");
        assert!(
            captured[0].contains("fc.pid") || captured[0].contains(".fc-pid"),
            "cleanup must reference PID file"
        );
        assert!(
            captured[0].contains("/tmp/test-vm"),
            "cleanup must reference the VM directory"
        );
    }

    #[test]
    fn tap_guard_defuse_prevents_cleanup() {
        use crate::base::shell_mock;

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();
        let _handler = shell_mock::install_handler(move |_script: &str| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let mut guard = TapGuard::new(&VmSlot::new("test-vm", 0));
            guard.defuse();
        }

        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "defused TapGuard must not run cleanup"
        );
    }

    #[test]
    fn tap_guard_runs_cleanup_on_drop() {
        use crate::base::shell_mock;

        let scripts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let scripts_clone = scripts.clone();
        let _handler = shell_mock::install_handler(move |script: &str| {
            scripts_clone
                .lock()
                .expect("mutex must not be poisoned")
                .push(script.to_string());
            shell_mock::MockResponse {
                exit_code: 0,
                stdout: String::new(),
            }
        });

        {
            let _guard = TapGuard::new(&VmSlot::new("test-vm", 0));
        }

        let captured = scripts.lock().expect("mutex must not be poisoned");
        assert_eq!(captured.len(), 1, "TapGuard must call cleanup once");
        assert!(
            captured[0].contains("ip link del"),
            "cleanup must destroy TAP device"
        );
    }

    #[test]
    fn firecracker_guard_tolerates_cleanup_failure() {
        use crate::base::shell_mock;

        let _handler = shell_mock::install_handler(|_script: &str| shell_mock::MockResponse {
            exit_code: 1,
            stdout: String::new(),
        });

        // Should not panic even though cleanup shell command fails
        {
            let _guard = FirecrackerGuard::new("/tmp/nonexistent-vm");
        }
    }
}
