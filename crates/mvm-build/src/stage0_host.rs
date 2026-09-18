//! Host-side Stage 0 pieces that belong to no particular VMM.
//!
//! Materializing the verified seed as an ext4 root, and deciding from the guest
//! console whether the bootstrap succeeded, are the same work regardless of
//! which hypervisor booted the guest. They lived inside `libkrun_builder`
//! because libkrun was the only backend that ran Stage 0; a second backend
//! would otherwise have had to fork them, and forked copies of "did the build
//! succeed" drift in exactly the way that hides a failure.
//!
//! Nothing here touches a VMM API. The pieces that genuinely do — supervisor
//! spawn, FFI context construction — stay in their backend's module.

use std::path::{Path, PathBuf};

use crate::builder_vm::BuilderVmError;

// Stage 0's persistent Nix store. Still defined in `libkrun_builder` because
// its implementation pulls in a chain of host-mkfs helpers that have not been
// untangled yet; re-exported here so callers already name the VMM-independent
// path and the eventual move costs them nothing.
pub use crate::libkrun_builder::{prepopulate_stage0_nix_store_image, stage0_nix_store_image_name};

/// Materialize the verified Stage 0 seed as the root ext4 disk the VMM boots.
///
/// `RootDir` remains the cache/source representation because Stage 0 creates it
/// before any guest-built kernel or rootfs exists; it is never handed to the VMM
/// as a host directory.
pub fn materialize_stage0_root_disk(
    root_dir: &Path,
    vm_state_dir: &Path,
) -> Result<PathBuf, BuilderVmError> {
    let image_path = vm_state_dir.join("root.ext4");
    let input =
        crate::rootfs::MaterializeExt4Input::new(root_dir.to_path_buf(), image_path.clone(), 0)
            .with_deferred_nodes(stage0_root_mount_nodes());
    crate::rootfs::materialize_ext4_pure(&input).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "materializing Stage 0 root disk from {}: {e}",
            root_dir.display()
        ))
    })?;
    Ok(image_path)
}

/// Mount points the seed tarball does not carry, plus the size reserve PID 1
/// deletes to free room for its own bootstrap state.
pub(crate) fn stage0_root_mount_nodes() -> Vec<mvm_fs::ext4::Node> {
    let mut nodes = [
        "/bin",
        "/dev",
        "/etc",
        "/nix-seed-ro",
        "/nix-stage0-store",
        "/proc",
        "/run",
        "/sys",
        "/tmp",
    ]
    .into_iter()
    .map(|path| mvm_fs::ext4::Node::Dir {
        path: path.to_string(),
        mode: 0o755,
        xattrs: Vec::new(),
        owner: mvm_fs::ext4::Owner::ROOT,
    })
    .collect::<Vec<_>>();
    nodes.push(mvm_fs::ext4::Node::File {
        path: crate::stage0::ROOT_RUNTIME_RESERVE_PATH.to_string(),
        mode: 0o600,
        data: vec![0; crate::stage0::ROOT_RUNTIME_RESERVE_BYTES],
        xattrs: Vec::new(),
        owner: mvm_fs::ext4::Owner::ROOT,
    });
    nodes
}

/// Last `max_lines` non-empty lines of a console log, for surfacing the guest's
/// actual error in a halt failure (the build error sits just above the halt
/// banner). Best-effort: an unreadable/missing log yields an empty string.
pub(crate) fn read_console_tail(console_log_path: &str, max_lines: usize) -> String {
    let Ok(contents) = std::fs::read_to_string(console_log_path) else {
        return String::new();
    };
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

/// Did a guest that halted without a clean VMM exit nonetheless finish?
///
/// Stage 0 powers off on every path, so a halt on its own says nothing. This is
/// the narrow case where the artifacts are present *and* the guest printed its
/// done marker, which together mean the build completed and only the teardown
/// was untidy.
pub fn stage0_guest_halt_completed_successfully(console_log: &Path, artifact_out: &Path) -> bool {
    let outputs_present =
        artifact_out.join("vmlinux").is_file() || artifact_out.join("rootfs.ext4").is_file();
    if !outputs_present {
        return false;
    }
    std::fs::read_to_string(console_log)
        .map(|log| log.contains("stage0-init: done; halting"))
        .unwrap_or(false)
}

/// What the Stage 0 guest's console says about how it terminated.
#[derive(Debug, PartialEq, Eq)]
pub enum Stage0HaltOutcome {
    /// `stage0-init` finished the build and copied artifacts to `/out`.
    CleanHalt,
    /// `nix build` (or a copy step) failed; the guest powered off anyway.
    BuildFailed,
    /// The guest refused before starting the build — no egress proxy, no
    /// clock, a share that would not mount. Carries the refusal, because it
    /// names a cause the nix output never will.
    SetupFailed(String),
    /// No terminal marker at all — a panic, kill, or truncated console.
    NoCleanHalt,
}

/// Decide Stage 0 success from the guest console, not the VMM exit code.
///
/// A supervisor that exits 0 only means the guest powered off — and
/// `stage0-init` powers off cleanly on build failure too (its own error is
/// printed, then `reboot`). Absent this check the caller would trip on a
/// downstream "rootfs.ext4 missing" error that hides the real nix failure.
/// `stage0-init` prints one stable terminal line, so match on it; every backend
/// keys on the same markers.
pub fn stage0_console_halt_outcome(log: &str) -> Stage0HaltOutcome {
    // Setup refusals are checked first and win over everything else: the
    // guest stops before `nix build` runs, so any later marker would be
    // describing a build that never started.
    if let Some(why) = log
        .lines()
        .find_map(|line| line.trim().strip_prefix("stage0-init: FATAL: "))
    {
        return Stage0HaltOutcome::SetupFailed(why.trim().to_string());
    }
    if log.contains("stage0-init: build failed") {
        Stage0HaltOutcome::BuildFailed
    } else if log.contains("stage0-init: done; halting") {
        Stage0HaltOutcome::CleanHalt
    } else {
        Stage0HaltOutcome::NoCleanHalt
    }
}

/// Turn a Stage 0 console's terminal state into the caller's result, naming the
/// console log path in both failure messages so an operator always knows where
/// to look instead of hitting a downstream error that hides the real cause.
/// Split out of the wait call site so this message construction is
/// unit-testable without spawning a VM.
pub fn stage0_run_result(console: &str, console_log_path: &str) -> Result<(), BuilderVmError> {
    match stage0_console_halt_outcome(console) {
        Stage0HaltOutcome::CleanHalt => Ok(()),
        Stage0HaltOutcome::BuildFailed => Err(BuilderVmError::NixBuildFailed(format!(
            "nix build failed inside the Stage 0 guest; console log at {console_log_path}\n{}",
            read_console_tail(console_log_path, 20)
        ))),
        Stage0HaltOutcome::SetupFailed(why) => Err(BuilderVmError::NixBuildFailed(format!(
            "Stage 0 guest refused to start the build: {why}; console log at {console_log_path}"
        ))),
        Stage0HaltOutcome::NoCleanHalt => Err(BuilderVmError::ExtractionFailed(format!(
            "Stage 0 guest did not reach a clean halt; console log at {console_log_path}\n{}",
            read_console_tail(console_log_path, 20)
        ))),
    }
}

/// Read a Stage 0 guest's console and turn it into the caller's result.
///
/// The console is the result channel — the guest powers off on success and
/// failure alike — so every backend has to do exactly this after its VM stops.
/// An unreadable console is not treated as success: it yields the same
/// no-clean-halt refusal an empty one would.
pub fn stage0_result_from_console(console_log: &Path) -> Result<(), BuilderVmError> {
    let console = std::fs::read_to_string(console_log).unwrap_or_default();
    stage0_run_result(&console, &console_log.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console is the result channel, so a backend that cannot read it must
    /// refuse rather than assume the build worked.
    #[test]
    fn an_unreadable_console_is_not_success() {
        let err = stage0_result_from_console(Path::new("/nonexistent/console.log"))
            .expect_err("a missing console cannot prove a clean halt");
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_done_marker_on_disk_resolves_to_success() {
        let tmp = tempfile::tempdir().unwrap();
        let console = tmp.path().join("console.log");
        std::fs::write(&console, b"nix output\nstage0-init: done; halting\n").unwrap();

        stage0_result_from_console(&console).expect("the done marker is a clean halt");
    }

    /// A setup refusal names a cause the nix output never will, so it has to
    /// survive into the error the operator sees.
    #[test]
    fn a_setup_refusal_keeps_its_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let console = tmp.path().join("console.log");
        std::fs::write(&console, b"stage0-init: FATAL: egress proxy unreachable\n").unwrap();

        let err = stage0_result_from_console(&console).expect_err("a refusal is not success");
        assert!(
            err.to_string().contains("egress proxy unreachable"),
            "the refusal reason must survive: {err}"
        );
    }
}
