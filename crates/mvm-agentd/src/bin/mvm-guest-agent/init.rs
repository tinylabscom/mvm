//! PID-1 initramfs harness for the universal initramfs boot path.
//!
//! When `mvm-guest-agent` is executed as `/init` (PID 1) it runs through
//! this harness before entering the normal vsock control plane:
//!
//!   1. Mount `/proc`, `/sys`, and `/dev`.
//!   2. Install a SIGCHLD handler so orphaned descendants become zombies
//!      that PID 1 reaps immediately.
//!   3. Hand control back to `main`; the normal vsock accept loop serves
//!      `ActivateEnvironment` as the only allowed verb.
//!   4. `apply_activation` mounts the rootfs, runtime overlay, and volumes,
//!      drops privilege, and flips the boot state to `Activated`.
//!
//! Linux-only.  On non-Linux targets the functions are no-ops so the
//! workspace still compiles on macOS.

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

use mvm_agentd::guest_mount;
use mvm_agentd::vsock::ActivateEnvironment;

use crate::state::{ActivationState, AgentBootState};

/// Fixed workload UID/GID the agent drops to after activation.
/// Matches the existing `agentUid` used by `nix/lib/mk-guest.nix`.
pub(crate) const WORKLOAD_UID: u32 = 901;
pub(crate) const WORKLOAD_GID: u32 = 901;

/// True when this process is PID 1 in the initramfs.
pub(crate) fn is_pid1() -> bool {
    std::process::id() == 1
}

/// Run early PID-1 setup.  Must be called before the vsock bind/listen
/// loop starts.  On non-Linux platforms this is a no-op.
pub(crate) fn early_setup() {
    if !is_pid1() {
        return;
    }
    eprintln!("mvm-guest-agent: running as PID 1, performing early initramfs setup");

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = guest_mount::mount_early_filesystems() {
            fatal(&format!("early filesystem mount failed: {e}"));
        }
        install_sigchld_handler();
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Should never be PID 1 on non-Linux, but keep the compile path
        // quiet.
    }
}

/// Apply an `ActivateEnvironment` message in PID-1 mode.  Mounts the
/// rootfs, runtime overlay, and custom volumes, then drops privilege.
/// On non-PID-1 boots this is a no-op and returns success.
pub(crate) fn apply_activation(
    env: &ActivateEnvironment,
    boot_state: &AgentBootState,
) -> Result<(), guest_mount::MountError> {
    if !is_pid1() {
        return Ok(());
    }

    boot_state.set_activation(ActivationState::Activating);

    let new_root = guest_mount::mount_rootfs(&env.rootfs)?;
    guest_mount::mount_runtime_overlay(&env.runtime, &new_root)?;
    guest_mount::mount_volumes(&env.volumes, &new_root)?;
    guest_mount::pivot_to_root(&new_root)?;
    guest_mount::drop_privilege(WORKLOAD_UID, WORKLOAD_GID)?;

    boot_state.set_activation(ActivationState::Activated);
    eprintln!("mvm-guest-agent: activation complete, serving operational RPCs");
    Ok(())
}

/// Log a fatal PID-1 error and exit.  There is no init to fall back to,
/// so panicking or plain `exit` both surface the failure on the console.
#[cfg(target_os = "linux")]
fn fatal(message: &str) -> ! {
    eprintln!("mvm-guest-agent: FATAL (PID 1): {message}");
    let _ = std::fs::write(
        "/dev/console",
        format!("mvm-guest-agent FATAL: {message}\n"),
    );
    std::thread::sleep(std::time::Duration::from_millis(200));
    std::process::exit(1);
}

// ============================================================================
// SIGCHLD handling (Linux only)
// ============================================================================

#[cfg(target_os = "linux")]
static SIGCHLD_INSTALLED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
fn install_sigchld_handler() {
    if SIGCHLD_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    // SAFETY: `on_sigchld` is async-signal-safe: it only calls `waitpid`
    // in a loop with `WNOHANG` and writes to `STDERR_FILENO` on failure.
    // The handler is installed once from the main thread before any child
    // processes exist.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_sigchld as *const () as usize;
        action.sa_flags = libc::SA_NOCLDSTOP | libc::SA_RESTART;
        let rc = libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut());
        if rc != 0 {
            fatal(&format!(
                "sigaction(SIGCHLD) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

/// SIGCHLD handler.  Reap any zombie children without blocking.  The
/// loop is required because multiple children may exit while the signal
/// is masked and Linux collapses concurrent SIGCHLD deliveries.
#[cfg(target_os = "linux")]
unsafe extern "C" fn on_sigchld(_sig: libc::c_int) {
    loop {
        let mut status = 0;
        // SAFETY: `waitpid(-1, WNOHANG)` is async-signal-safe and does not
        // block.  The status pointer is owned on this signal-handler stack.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
    }
}
