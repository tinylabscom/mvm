//! PID-1 initramfs harness for the universal initramfs boot path.
//!
//! When `mvm-guest-agent` is executed as `/init` (PID 1) it runs through
//! this harness before entering the normal vsock control plane:
//!
//!   1. Mount `/proc`, `/sys`, and `/dev`.
//!   2. Start the orphan reaper so descendants re-parented to PID 1 are
//!      collected instead of accumulating as zombies. It is a thread, not
//!      a SIGCHLD handler, so it can publish the statuses of children the
//!      agent owns rather than destroying them — see
//!      [`mvm_agentd::child_wait`].
//!   3. Hand control back to `main`; the normal vsock accept loop serves
//!      `ActivateEnvironment` as the only allowed verb.
//!   4. `apply_activation` mounts the rootfs, runtime overlay, and volumes,
//!      drops privilege, and flips the boot state to `Activated`.
//!
//! Linux-only.  On non-Linux targets the functions are no-ops so the
//! workspace still compiles on macOS.

use mvm_agentd::guest_mount;
use mvm_agentd::vsock::ActivateEnvironment;

use crate::globals::VALIDATED_EXTENSIONS;
use crate::state::{ActivationState, AgentBootState};

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
    #[cfg(target_os = "linux")]
    {
        if crate::transport::unix_transport_selected() {
            // A shared-kernel container runtime has already mounted /proc,
            // /sys, and /dev for the namespace and drops CAP_SYS_ADMIN, so
            // the initramfs early mounts would fail with EPERM. The agent
            // is still PID 1 of the container's PID namespace, so the
            // orphan reaper is still required.
            eprintln!(
                "mvm-guest-agent: unix transport — container runtime provides early filesystems"
            );
        } else {
            if let Err(e) = guest_mount::mount_early_filesystems() {
                fatal(&format!("early filesystem mount failed: {e}"));
            }
            seed_wall_clock_from_host_epoch();
        }
        provision_host_signer_anchor();
        // In the universal initramfs path there is no second init to copy the
        // signed verb-grant into /run/mvm before the agent starts listening.
        // Pin it now from the kernel cmdline so the pre-activation trust
        // decision sees the pinned grant before the agent accepts requests.
        mvm_agentd::guest_bootstrap::provision_verb_grant();
        mvm_agentd::child_wait::install_orphan_reaper();
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Should never be PID 1 on non-Linux, but keep the compile path
        // quiet.
    }
}

/// Apply the host's launch epoch before trust-policy timestamps or workload
/// TLS validation can observe the RTC-less guest's kernel clock.
#[cfg(target_os = "linux")]
fn seed_wall_clock_from_host_epoch() {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .unwrap_or_else(|error| fatal(&format!("read /proc/cmdline for wall clock: {error}")));
    match mvm_agentd::restore_clock::resync_from_cmdline(&cmdline) {
        Ok(epoch) => eprintln!("mvm-guest-agent: wall clock set from host epoch {epoch}"),
        Err(error) => fatal(&format!("wall clock synchronization failed: {error}")),
    }
}

/// Copy the host-signer anchor off the kernel cmdline into the filesystem the
/// control listener reads it from.
///
/// A block-backed guest gets this from the init, which copies the key off
/// the config drive. The universal initramfs has no config drive and no second
/// init — the agent itself is `/init` — so without this the anchor never lands,
/// every control connection is refused for want of a pinned key, and the run
/// dies at `ActivateEnvironment`, its very first RPC.
///
/// Absent or malformed tokens are logged, not fatal: the guest simply stays
/// anchorless and keeps refusing control connections, which is the same
/// fail-closed posture as before.
#[cfg(target_os = "linux")]
fn provision_host_signer_anchor() {
    let result = std::fs::read_to_string("/proc/cmdline")
        .map_err(|e| anyhow::anyhow!("read /proc/cmdline: {e}"))
        .and_then(|cmdline| {
            mvm_agentd::vsock::provision_host_signer_anchor_from_cmdline(
                &cmdline,
                std::path::Path::new("/"),
            )
        });
    match result {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("mvm-guest-agent: no host-signer anchor on cmdline; control stays closed")
        }
        Err(e) => eprintln!("mvm-guest-agent: host-signer anchor not provisioned: {e}"),
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
    guest_mount::mount_runtime_overlay(env.runtime.as_ref(), &new_root)?;
    guest_mount::mount_volumes(&env.volumes, &new_root)?;
    #[cfg(target_os = "linux")]
    if let Some(device) = mvm_agentd::guest_bootstrap::cmdline_value("mvm.sdk_dev") {
        guest_mount::mount_sdk_sidecar(&device, &new_root)?;
    }
    if env.rootfs.in_place {
        // Shared-kernel container: the runtime already owns `/`, so there is
        // no staged root to pivot into — activation is the privilege drop
        // and the gate flip only.
        eprintln!("mvm-guest-agent: in-place root, skipping pivot");
    } else {
        guest_mount::pivot_to_root(&new_root)?;
    }
    // The same post-mount setup the legacy per-rootfs init performs: mediated
    // tools, egress CA, verb grant, netinit, loopback + resolver, egress client.
    // It has to land after the pivot (it writes into the workload's root) and
    // before the privilege drop (mounts and interface changes need root).
    bootstrap_guest_environment()?;
    let validated_extensions = mvm_agentd::extension::validate_extensions(
        &env.extensions,
        std::path::Path::new("/run/mvm/extension-markers"),
    );
    if let Err(error) = &validated_extensions {
        return Err(guest_mount::MountError::InvalidConfig(error.clone()));
    }
    VALIDATED_EXTENSIONS
        .set(validated_extensions)
        .map_err(|_| {
            guest_mount::MountError::InvalidConfig("extensions already activated".into())
        })?;
    guest_mount::drop_guest_agent_privilege(guest_mount::WORKLOAD_UID, guest_mount::WORKLOAD_GID)?;

    boot_state.set_activation(ActivationState::Activated);
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

/// Run the post-mount setup shared with the legacy per-rootfs init.
#[cfg(target_os = "linux")]
fn bootstrap_guest_environment() -> Result<(), guest_mount::MountError> {
    mvm_agentd::guest_bootstrap::provision_guest_environment().map_err(|_| {
        guest_mount::MountError::GuestBootstrap(
            "egress was required but no egress client resolved".to_string(),
        )
    })
}

/// The agent is PID 1 only inside a Linux guest, so there is nothing to set up
/// on a host build. Spelled out rather than left as a `cfg`-erased call site so
/// the Linux path cannot quietly disappear.
#[cfg(not(target_os = "linux"))]
fn bootstrap_guest_environment() -> Result<(), guest_mount::MountError> {
    Ok(())
}
