use std::path::Path;
use std::process::Stdio;

/// A failure to supervise the persistent builder's egress endpoint.
#[derive(Debug, thiserror::Error)]
pub enum EgressSupervisorError {
    #[error("running builder egress endpoint: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("builder egress endpoint exited with {0}")]
    Exit(std::process::ExitStatus),
}

/// Arm parent-death supervision before spawning the endpoint, then wait for it.
///
/// This operation owns the process lifetime; frontends supply only the executable
/// selected by their payload registration, not a spawn callback.
pub fn supervise_egress_endpoint(endpoint: &Path) -> Result<(), EgressSupervisorError> {
    supervise(endpoint, mvm_hostd::parent_death::exit_when_orphaned)
}

fn supervise(
    endpoint: &Path,
    arm_parent_death: impl FnOnce(),
) -> Result<(), EgressSupervisorError> {
    arm_parent_death();
    let status = mvm_core::env_hygiene::helper_command(endpoint)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(EgressSupervisorError::Spawn)?;
    if !status.success() {
        return Err(EgressSupervisorError::Exit(status));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn watchdog_is_armed_even_when_spawn_fails() {
        let armed = Cell::new(false);
        let error = supervise(
            Path::new("/definitely/missing/mvm-network-endpoint"),
            || {
                armed.set(true);
            },
        )
        .expect_err("missing endpoint");
        assert!(armed.get());
        assert!(matches!(error, EgressSupervisorError::Spawn(_)));
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_success_and_failure_are_distinct() {
        assert!(supervise(Path::new("/usr/bin/true"), || {}).is_ok());
        assert!(matches!(
            supervise(Path::new("/usr/bin/false"), || {}),
            Err(EgressSupervisorError::Exit(_))
        ));
    }
}
