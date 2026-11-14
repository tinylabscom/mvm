use anyhow::Result;

/// Only the HVF supervisor owns console capture for the VM's whole life;
/// other backends need the launcher's follower, not a competing writer.
pub(super) fn supervisor_owns_console(kind: mvm_core::vm_backend::BackendKind) -> bool {
    kind == mvm_core::vm_backend::BackendKind::Hvf
}

/// Boot the VMM while the best-effort console follower is being installed.
pub(super) fn boot_while_starting_console<T>(
    boot: impl FnOnce() -> Result<T>,
    start_console: impl FnOnce() + Send,
    boot_finished: impl FnOnce(),
) -> Result<T> {
    std::thread::scope(|scope| {
        let console = scope.spawn(start_console);
        let result = boot();
        boot_finished();
        // Console capture is best-effort and must never turn a successful VM
        // boot into a failure. Joining still ensures the follower is installed
        // before activation can produce output.
        let _ = console.join();
        result
    })
}
