#[cfg(all(test, feature = "test-support"))]
use std::error::Error;
// Gated exactly like its only user below. Under plain `#[cfg(test)]` this is an
// unused import whenever `test-support` is off, which is what a package-scoped
// `cargo clippy -p mvm-runtime --all-targets` builds — green in CI, where the
// workspace build turns the feature on, and a hard error locally.
#[cfg(all(test, feature = "test-support"))]
use std::path::Path;

#[cfg(all(test, feature = "test-support"))]
use crate::mock_guest_agent::MockGuestAgent;

#[cfg(all(test, feature = "test-support"))]
fn is_permission_denied_io(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn error_chain_has_permission_denied(err: &(dyn Error + 'static)) -> bool {
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        return is_permission_denied_io(io_err);
    }
    let mut source = err.source();
    while let Some(next) = source {
        if let Some(io_err) = next.downcast_ref::<std::io::Error>()
            && is_permission_denied_io(io_err)
        {
            return true;
        }
        source = next.source();
    }
    false
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn start_mock_guest_agent(vm_dir: &Path) -> Option<MockGuestAgent> {
    match MockGuestAgent::start(vm_dir) {
        Ok(agent) => Some(agent),
        Err(err) if error_chain_has_permission_denied(err.as_ref()) => {
            eprintln!(
                "skipping test: sandbox denied starting MockGuestAgent under {}: {err}",
                vm_dir.display()
            );
            None
        }
        Err(err) => panic!(
            "starting MockGuestAgent under {} failed: {err}",
            vm_dir.display()
        ),
    }
}
