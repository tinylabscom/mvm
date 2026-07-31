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

use std::path::{Path, PathBuf};
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
        if crate::transport::unix_transport_selected() {
            // A shared-kernel container runtime has already mounted /proc,
            // /sys, and /dev for the namespace and drops CAP_SYS_ADMIN, so
            // the initramfs early mounts would fail with EPERM. The agent
            // is still PID 1 of the container's PID namespace, so the
            // SIGCHLD reaper is still required.
            eprintln!(
                "mvm-guest-agent: unix transport — container runtime provides early filesystems"
            );
        } else if let Err(e) = guest_mount::mount_early_filesystems() {
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
    guest_mount::mount_runtime_overlay(env.runtime.as_ref(), &new_root)?;
    guest_mount::mount_volumes(&env.volumes, &new_root)?;
    if env.rootfs.in_place {
        // Shared-kernel container: the runtime already owns `/`, so there is
        // no staged root to pivot into — activation is the privilege drop
        // and the gate flip only.
        eprintln!("mvm-guest-agent: in-place root, skipping pivot");
    } else {
        guest_mount::pivot_to_root(&new_root)?;
    }
    guest_mount::drop_privilege(WORKLOAD_UID, WORKLOAD_GID)?;

    boot_state.set_activation(ActivationState::Activated);
    eprintln!("mvm-guest-agent: activation complete, serving operational RPCs");
    Ok(())
}

// ============================================================================
// Container-mode activation (not PID 1; launched with an activation file)
// ============================================================================

/// Environment variable naming a serialized `ActivateEnvironment` the
/// agent reads and applies itself when it is not PID 1 — the boot where
/// the guest's own init system (e.g. vminitd) stays PID 1 and starts the
/// agent as an ordinary root process.
pub(crate) const ACTIVATION_FILE_ENV: &str = "MVM_ACTIVATION_FILE";

/// How this process learns its activation environment, selected once at
/// startup from the pid and the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActivationEntry {
    /// PID 1: activation arrives over the control plane as the
    /// `ActivateEnvironment` RPC. A file, if also present, is ignored —
    /// the PID-1 contract keeps a single host-driven activation channel,
    /// so a stray file can never self-activate an initramfs boot.
    Pid1Rpc,
    /// Not PID 1 with an activation file: self-activate in container mode
    /// (private mount namespace + chroot) before serving.
    ContainerFile(PathBuf),
    /// Not PID 1 and no activation file: no boot-time activation (the
    /// non-initramfs modes, where applying an environment is a no-op).
    None,
}

/// The pure entry-mode decision, split from [`activation_entry`] so the
/// full matrix is unit-testable without env or pid manipulation.
pub(crate) fn select_activation_entry(
    is_pid1: bool,
    activation_file: Option<&str>,
) -> ActivationEntry {
    if is_pid1 {
        return ActivationEntry::Pid1Rpc;
    }
    match activation_file.filter(|v| !v.trim().is_empty()) {
        Some(path) => ActivationEntry::ContainerFile(PathBuf::from(path)),
        None => ActivationEntry::None,
    }
}

/// Resolve this process's activation entry mode from the real pid and
/// environment.
pub(crate) fn activation_entry() -> ActivationEntry {
    select_activation_entry(
        is_pid1(),
        std::env::var(ACTIVATION_FILE_ENV).ok().as_deref(),
    )
}

/// One ordered step of the container-mode activation sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerStep {
    /// `unshare(CLONE_NEWNS)` + private propagation — always first, so no
    /// mount below can perturb the init system's namespace.
    UnshareMountNamespace,
    /// Mount the rootfs (verity / plain / virtio-fs) at the staging path.
    MountRootfs,
    /// Mount the dm-verity runtime overlay inside the staged root.
    MountRuntimeOverlay,
    /// Mount custom virtio-fs volumes inside the staged root.
    MountVolumes,
    /// Move pseudo-filesystems and chroot into the staged root.
    PivotIntoRoot,
    /// Drop to the workload uid/gid — always last.
    DropPrivilege,
}

/// The ordered activation sequence for `env`, pure so tests can pin the
/// ordering for every rootfs shape. [`run_container_activation`] performs
/// exactly these steps; keep the two in lockstep.
pub(crate) fn container_activation_plan(env: &ActivateEnvironment) -> Vec<ContainerStep> {
    let mut steps = vec![
        ContainerStep::UnshareMountNamespace,
        ContainerStep::MountRootfs,
    ];
    if env.runtime.is_some() {
        steps.push(ContainerStep::MountRuntimeOverlay);
    }
    if !env.volumes.is_empty() {
        steps.push(ContainerStep::MountVolumes);
    }
    if !env.rootfs.in_place {
        // An in-place root is already `/` (the shared-kernel tier); there
        // is no staged root to pivot into.
        steps.push(ContainerStep::PivotIntoRoot);
    }
    steps.push(ContainerStep::DropPrivilege);
    steps
}

/// Failure to read, parse, or apply a container-mode activation file.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ContainerActivationError {
    /// The file could not be read.
    #[error("read activation file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    /// The file is not a valid serialized `ActivateEnvironment`.
    #[error("parse activation file {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    /// A mount/namespace/privilege step failed.
    #[error("container activation failed: {0}")]
    Mount(#[from] guest_mount::MountError),
}

/// Read the serialized `ActivateEnvironment` at `path` and apply it in
/// container mode, flipping the boot state exactly like the PID-1 RPC
/// path: `Activating` while the mount sequence runs, then `Activated` (or
/// `Failed` with the reason). Fails closed: a missing or malformed file is
/// a typed error, never a panic and never a partially-applied environment.
pub(crate) fn apply_container_activation(
    path: &Path,
    boot_state: &AgentBootState,
) -> Result<(), ContainerActivationError> {
    let bytes = std::fs::read(path).map_err(|source| ContainerActivationError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let env: ActivateEnvironment =
        serde_json::from_slice(&bytes).map_err(|source| ContainerActivationError::Parse {
            path: path.display().to_string(),
            source,
        })?;

    boot_state.set_activation(ActivationState::Activating);
    match run_container_activation(&env) {
        Ok(()) => {
            boot_state.set_activation(ActivationState::Activated);
            eprintln!("mvm-guest-agent: container activation complete, serving operational RPCs");
            Ok(())
        }
        Err(e) => {
            boot_state.set_activation(ActivationState::Failed {
                message: e.to_string(),
            });
            Err(ContainerActivationError::Mount(e))
        }
    }
}

/// Perform the steps of [`container_activation_plan`] in order. The
/// PID-1 path mounts and pivots in the initramfs's own namespace; here
/// every mount happens inside the private namespace entered first.
fn run_container_activation(env: &ActivateEnvironment) -> Result<(), guest_mount::MountError> {
    if env.rootfs.in_place {
        eprintln!("mvm-guest-agent: in-place root, skipping pivot");
    }
    let mut new_root = PathBuf::new();
    for step in container_activation_plan(env) {
        match step {
            ContainerStep::UnshareMountNamespace => guest_mount::unshare_mount_namespace()?,
            ContainerStep::MountRootfs => new_root = guest_mount::mount_rootfs(&env.rootfs)?,
            ContainerStep::MountRuntimeOverlay => {
                guest_mount::mount_runtime_overlay(env.runtime.as_ref(), &new_root)?;
            }
            ContainerStep::MountVolumes => guest_mount::mount_volumes(&env.volumes, &new_root)?,
            ContainerStep::PivotIntoRoot => guest_mount::pivot_to_root_container(&new_root)?,
            ContainerStep::DropPrivilege => {
                guest_mount::drop_privilege(WORKLOAD_UID, WORKLOAD_GID)?;
            }
        }
    }
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::{RootfsConfig, RuntimeOverlayConfig, VolumeConfig};
    use mvm_core::security::AgentProfile;

    fn boot_state() -> AgentBootState {
        AgentBootState::new(AgentProfile::default(), std::time::Instant::now())
    }

    fn block_rootfs() -> RootfsConfig {
        RootfsConfig {
            data_dev: "/dev/vda".to_string(),
            hash_dev: None,
            roothash: None,
            virtiofs_tag: None,
            in_place: false,
        }
    }

    fn env_with(
        rootfs: RootfsConfig,
        runtime: Option<RuntimeOverlayConfig>,
        volumes: Vec<VolumeConfig>,
    ) -> ActivateEnvironment {
        ActivateEnvironment {
            rootfs,
            runtime,
            volumes,
            verb_grant_envelope: None,
        }
    }

    // --- entry-mode selection: the full pid x file matrix ---

    #[test]
    fn pid1_always_selects_the_rpc_entry_even_with_a_file() {
        assert_eq!(
            select_activation_entry(true, Some("/run/mvm/activation.json")),
            ActivationEntry::Pid1Rpc,
            "a stray file must never self-activate a PID-1 boot"
        );
        assert_eq!(
            select_activation_entry(true, None),
            ActivationEntry::Pid1Rpc
        );
    }

    #[test]
    fn non_pid1_selects_container_mode_only_with_a_real_file() {
        assert_eq!(
            select_activation_entry(false, Some("/run/mvm/activation.json")),
            ActivationEntry::ContainerFile(PathBuf::from("/run/mvm/activation.json"))
        );
        assert_eq!(select_activation_entry(false, None), ActivationEntry::None);
        // An empty or whitespace-only value is not a file.
        assert_eq!(
            select_activation_entry(false, Some("")),
            ActivationEntry::None
        );
        assert_eq!(
            select_activation_entry(false, Some("   ")),
            ActivationEntry::None
        );
    }

    // --- the ordered activation plan, per rootfs shape ---

    #[test]
    fn plan_for_plain_block_root_is_unshare_mount_pivot_drop() {
        let plan = container_activation_plan(&env_with(block_rootfs(), None, Vec::new()));
        assert_eq!(
            plan,
            vec![
                ContainerStep::UnshareMountNamespace,
                ContainerStep::MountRootfs,
                ContainerStep::PivotIntoRoot,
                ContainerStep::DropPrivilege,
            ]
        );
    }

    #[test]
    fn plan_for_sealed_root_inserts_overlay_and_volumes_before_pivot() {
        let env = env_with(
            block_rootfs(),
            Some(RuntimeOverlayConfig {
                data_dev: "/dev/vdc".to_string(),
                hash_dev: "/dev/vdd".to_string(),
                roothash: "ab".repeat(32),
            }),
            vec![VolumeConfig {
                tag: "share0".to_string(),
                mountpoint: "/srv/share".to_string(),
                read_only: true,
            }],
        );
        let plan = container_activation_plan(&env);
        assert_eq!(
            plan,
            vec![
                ContainerStep::UnshareMountNamespace,
                ContainerStep::MountRootfs,
                ContainerStep::MountRuntimeOverlay,
                ContainerStep::MountVolumes,
                ContainerStep::PivotIntoRoot,
                ContainerStep::DropPrivilege,
            ]
        );
        // Unshare is always first and the privilege drop always last.
        assert_eq!(plan.first(), Some(&ContainerStep::UnshareMountNamespace));
        assert_eq!(plan.last(), Some(&ContainerStep::DropPrivilege));
    }

    #[test]
    fn plan_for_in_place_root_skips_the_pivot() {
        let env = env_with(
            RootfsConfig {
                data_dev: String::new(),
                hash_dev: None,
                roothash: None,
                virtiofs_tag: None,
                in_place: true,
            },
            None,
            Vec::new(),
        );
        let plan = container_activation_plan(&env);
        assert!(!plan.contains(&ContainerStep::PivotIntoRoot));
        assert_eq!(
            plan,
            vec![
                ContainerStep::UnshareMountNamespace,
                ContainerStep::MountRootfs,
                ContainerStep::DropPrivilege,
            ]
        );
    }

    // --- fail-closed file handling (error paths return before any
    // syscall, so these are safe on every platform) ---

    #[test]
    fn missing_activation_file_is_a_typed_read_error() {
        let bs = boot_state();
        let err =
            apply_container_activation(Path::new("/nonexistent/activation.json"), &bs).unwrap_err();
        assert!(
            matches!(err, ContainerActivationError::Read { .. }),
            "expected Read, got: {err}"
        );
        // The state machine never entered Activating.
        assert_eq!(bs.activation_state(), ActivationState::Awaiting);
    }

    #[test]
    fn malformed_activation_file_is_a_typed_parse_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("activation.json");
        std::fs::write(&path, b"{not json").expect("write");
        let bs = boot_state();
        let err = apply_container_activation(&path, &bs).unwrap_err();
        assert!(
            matches!(err, ContainerActivationError::Parse { .. }),
            "expected Parse, got: {err}"
        );
        assert_eq!(bs.activation_state(), ActivationState::Awaiting);
    }

    #[test]
    fn schema_valid_but_wrong_shape_is_a_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("activation.json");
        std::fs::write(&path, br#"{"rootfs": null}"#).expect("write");
        let bs = boot_state();
        let err = apply_container_activation(&path, &bs).unwrap_err();
        assert!(
            matches!(err, ContainerActivationError::Parse { .. }),
            "expected Parse, got: {err}"
        );
    }
}
