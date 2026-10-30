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
fn io_failure_details(err: &anyhow::Error) -> Option<(std::io::ErrorKind, Option<i32>)> {
    err.chain().find_map(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .map(|error| (error.kind(), error.raw_os_error()))
    })
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn start_mock_guest_agent(vm_dir: &Path) -> Option<MockGuestAgent> {
    match MockGuestAgent::start(vm_dir, None) {
        Ok(agent) => Some(agent),
        Err(err) if error_chain_has_permission_denied(err.as_ref()) => {
            eprintln!(
                "skipping test: sandbox denied starting MockGuestAgent under {}: {err}",
                vm_dir.display()
            );
            None
        }
        Err(err) => panic!(
            "starting MockGuestAgent under {} failed: {err}; I/O (kind, OS code): {:?}",
            vm_dir.display(),
            io_failure_details(&err)
        ),
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::io_failure_details;
    use std::io::{Error, ErrorKind};

    #[test]
    fn startup_io_details_survive_context_without_formatting_inner_payloads() {
        let error = anyhow::Error::new(Error::new(
            ErrorKind::AlreadyExists,
            "synthetic-sensitive-inner-payload",
        ))
        .context("creating fixture signer")
        .context("starting fixture");
        let details = io_failure_details(&error);
        assert_eq!(details, Some((ErrorKind::AlreadyExists, None)));
        assert!(!format!("{details:?}").contains("synthetic-sensitive-inner-payload"));
    }

    #[test]
    fn startup_io_details_preserve_os_code_and_distinguish_non_io_errors() {
        let io = Error::from_raw_os_error(2);
        let expected = (io.kind(), io.raw_os_error());
        let error = anyhow::Error::new(io).context("creating fixture signer");
        assert_eq!(io_failure_details(&error), Some(expected));
        assert_eq!(
            io_failure_details(&anyhow::anyhow!("fixture failure")),
            None
        );
    }
}
