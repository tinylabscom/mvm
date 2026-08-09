#[cfg(all(test, feature = "test-support"))]
use std::error::Error;
#[cfg(test)]
#[cfg(test)]
use std::path::Path;

#[cfg(all(test, feature = "test-support"))]
use crate::mock_guest_agent::MockGuestAgent;

#[cfg(test)]
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

#[cfg(test)]
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
