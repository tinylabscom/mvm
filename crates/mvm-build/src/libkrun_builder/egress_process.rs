use std::path::Path;
use std::process::{Command, ExitStatus};

use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};

use crate::builder_vm::BuilderVmError;

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

/// The egress supervisor command for `host`: the current executable re-run as
/// `mvmctl`. A library embedder's executable is not `mvmctl`, so it is refused
/// before any command exists.
pub(super) fn builder_egress_supervisor_command_for(
    host: &HostProcess,
    endpoint_path: &Path,
) -> Result<Command, BuilderVmError> {
    host.refuse_cli_spawn(CliSpawn::BuilderEgressSupervisor)?;
    let mvmctl_path = std::env::current_exe().map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "resolve mvmctl for persistent builder egress supervisor: {e}"
        ))
    })?;
    Ok(builder_egress_supervisor_command(
        &mvmctl_path,
        endpoint_path,
    ))
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

    #[test]
    fn mvmctl_runs_its_own_executable_as_the_egress_supervisor() {
        let command = builder_egress_supervisor_command_for(
            &HostProcess::undeclared(),
            Path::new("/opt/mvm-network-endpoint"),
        )
        .expect("mvmctl may re-run itself");

        assert_eq!(
            command.get_program(),
            std::env::current_exe().unwrap().as_os_str()
        );
    }

    #[test]
    fn a_library_embedder_constructs_no_egress_supervisor_command() {
        let err = builder_egress_supervisor_command_for(
            &HostProcess::undeclared().as_library_embedder(),
            Path::new("/opt/mvm-network-endpoint"),
        )
        .expect_err("an embedder never re-runs its executable as mvmctl");

        match err {
            BuilderVmError::CliSpawnRefused(refused) => {
                assert_eq!(refused.spawn(), &CliSpawn::BuilderEgressSupervisor);
            }
            other => panic!("expected a typed refusal, got {other}"),
        }
    }
}
