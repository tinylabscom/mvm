use std::path::Path;
use std::process::{Command, ExitStatus};

/// Whether an owned builder endpoint received the teardown signal.
///
/// The endpoint is deliberately terminated after its builder VM exits. That
/// lifecycle event is not a build failure and belongs at debug level rather
/// than on the contributor's stderr stream.
pub(super) fn builder_egress_endpoint_was_terminated(status: &ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        status.signal() == Some(libc::SIGTERM)
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        false
    }
}

pub(super) fn builder_egress_supervisor_command(
    mvmctl_path: &Path,
    endpoint_path: &Path,
) -> Command {
    let mut command = Command::new(mvmctl_path);
    command
        .arg("__builder-egress-supervisor")
        .arg("--endpoint")
        .arg(endpoint_path)
        // This child's stdout is a typed JSON handshake channel. The parent
        // CLI's verbose RUST_LOG value must not turn tracing records into
        // protocol bytes before the wrapper execs the endpoint.
        .env("RUST_LOG", "off")
        .env_remove(mvm_core::observability::span_timing::ENV_ENABLE)
        .env_remove(mvm_core::observability::span_timing::ENV_OUT)
        .env_remove(mvm_core::observability::span_timing::ENV_FILTER);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn sigterm_is_expected_teardown_only() {
        use std::os::unix::process::ExitStatusExt;

        let terminated = ExitStatus::from_raw(libc::SIGTERM);
        let failed = ExitStatus::from_raw(1 << 8);

        assert!(builder_egress_endpoint_was_terminated(&terminated));
        assert!(!builder_egress_endpoint_was_terminated(&failed));
    }
}
