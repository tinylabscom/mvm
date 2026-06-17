//! Tie a spawned networking helper (gvproxy / passt) to the lifetime of the
//! supervisor that spawns it, so a dead supervisor never orphans the helper.
//!
//! The supervisor's `SIGTERM` handler already reaps gvproxy on a graceful
//! `mvmctl stop` / `kill`, but a `SIGKILL` or a panic it can't catch leaves the
//! helper re-parented to init — accumulating as a leaked daemon (commonly stuck
//! at gvproxy's "waiting for clients" when the VM never connected).
//!
//! On Linux, `PR_SET_PDEATHSIG` closes that gap at the source: the kernel
//! delivers `SIGTERM` to the child the instant its parent dies, for *any*
//! reason. macOS has no equivalent primitive for an unmodifiable child, so the
//! orphan-reaper (`mvmctl cache prune` / reconcile-on-entry) is the backstop
//! there — this call is a no-op on non-Linux hosts.

use std::process::Command;

/// Arrange for `cmd`'s child to receive `SIGTERM` if this process (its parent)
/// dies. Call it on the `Command` immediately before `spawn()`.
pub(crate) fn tie_to_parent_death(cmd: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the closure runs in the forked child after `fork(2)` and
        // before `execve(2)`, where only async-signal-safe functions are
        // permitted — `prctl`, `getppid`, and `_exit` all qualify
        // (signal-safety(7)). `PR_SET_PDEATHSIG` is preserved across the
        // following `execve` for a non-set-id binary (gvproxy / passt are
        // not set-id). The `getppid() == 1` check closes the race where the
        // parent exits between `fork` and `prctl`: if we were already
        // re-parented to init, honour the death signal we just missed.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() == 1 {
                    libc::_exit(0);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No parent-death primitive for an unmodifiable child on macOS; the
        // orphan-reaper is the backstop. Touch `cmd` so the arg isn't unused.
        let _ = cmd;
    }
}

#[cfg(test)]
mod tests {
    use super::tie_to_parent_death;
    use std::process::Command;

    #[test]
    fn tied_command_still_spawns_and_exits_clean() {
        // On Linux this exercises the real `pre_exec` `prctl` + `getppid` path
        // in an actual fork/exec — the parent (this test) is alive, so the
        // child proceeds to exec `true`. On macOS it is the documented no-op.
        // Either way the command must still run to completion.
        let mut cmd = Command::new("true");
        tie_to_parent_death(&mut cmd);
        let status = cmd.status().expect("spawn `true`");
        assert!(status.success());
    }
}
