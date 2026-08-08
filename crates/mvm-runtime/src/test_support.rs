#[cfg(all(test, feature = "test-support"))]
use std::error::Error;
#[cfg(test)]
use std::os::unix::net::UnixListener;
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
pub(crate) fn bind_unix_listener(path: &Path) -> Option<UnixListener> {
    if let Some(parent) = path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        if is_permission_denied_io(&err) {
            eprintln!(
                "skipping test: sandbox denied creating Unix socket parent {}: {err}",
                parent.display()
            );
            return None;
        }
        panic!(
            "creating Unix socket parent {} failed: {err}",
            parent.display()
        );
    }
    let _ = std::fs::remove_file(path);
    match UnixListener::bind(path) {
        Ok(listener) => Some(listener),
        Err(err) if is_permission_denied_io(&err) => {
            eprintln!(
                "skipping test: sandbox denied binding Unix socket {}: {err}",
                path.display()
            );
            None
        }
        Err(err) => panic!("binding Unix socket {} failed: {err}", path.display()),
    }
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
