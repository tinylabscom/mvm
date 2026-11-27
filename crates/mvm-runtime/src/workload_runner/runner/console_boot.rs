use anyhow::Result;

/// Only the HVF supervisor owns console capture for the VM's whole life;
/// other backends need the launcher's follower, not a competing writer.
pub(super) fn supervisor_owns_console(kind: mvm_core::vm_backend::BackendKind) -> bool {
    kind == mvm_core::vm_backend::BackendKind::Hvf
}

/// Boot the VMM while `beside` runs on its own thread: installing the
/// best-effort console follower, and on a cold start syncing the launch's
/// lease and generation first.
pub(super) fn boot_beside<T>(
    boot: impl FnOnce() -> Result<T>,
    beside: impl FnOnce() + Send,
    boot_finished: impl FnOnce(),
) -> Result<T> {
    std::thread::scope(|scope| {
        let beside = scope.spawn(beside);
        let result = boot();
        boot_finished();
        // A panic in `beside` must not turn a successful boot into a failure
        // here: a caller that needs its outcome records it from inside.
        // Joining ensures the follower is installed, and any sync finished,
        // before activation.
        let _ = beside.join();
        result
    })
}
