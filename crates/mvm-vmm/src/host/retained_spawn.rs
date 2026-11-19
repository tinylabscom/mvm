//! Failed spawn rollback keeps the original child until its collected exit is known.

use std::process::Child;
use std::sync::Mutex;

use super::network_endpoint_spawn::OwnedEndpoint;
use anyhow::{Context, Result, ensure};

struct Custody {
    child: Option<Child>,
    owner: Option<OwnedEndpoint>,
    uncertain: bool,
}

/// A failed helper startup whose original child has not yet been proven reaped.
pub struct RetainedSpawnFailure {
    cause: anyhow::Error,
    custody: Mutex<Custody>,
}

impl std::fmt::Debug for RetainedSpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedSpawnFailure")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RetainedSpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "helper startup failed with retained original custody: {}",
            self.cause
        )
    }
}

impl std::error::Error for RetainedSpawnFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

impl RetainedSpawnFailure {
    /// Whether rollback collected the original child's exit, not just signaled it.
    /// This says nothing about descendants or successful workload teardown.
    pub(crate) fn exit_collected(&self) -> bool {
        let custody = self
            .custody
            .lock()
            .expect("retained spawn custody poisoned");
        !custody.uncertain
            && custody.child.is_none()
            && custody
                .owner
                .as_ref()
                .is_none_or(|owner| owner.exit_status().is_some())
    }

    /// Retry only this original child; success requires a collected exit status.
    pub fn retry_stop(&self) -> Result<()> {
        let mut custody = self
            .custody
            .lock()
            .expect("retained spawn custody poisoned");
        ensure!(
            !custody.uncertain,
            "original helper child custody is uncertain"
        );
        if custody.child.is_some() {
            super::process_exit::require_owned_child_custody()?;
            // Rollback owns the child already and must accept an exit before
            // observer capture; adoption requires a still-running helper.
            custody.owner = custody.child.take().map(OwnedEndpoint::new);
        }
        if let Some(owner) = custody.owner.as_mut() {
            let result = owner.shutdown();
            if owner.exit_status().is_none() {
                result.context("original helper rollback remains unconfirmed")?;
                anyhow::bail!("helper rollback has no collected exit");
            }
        }
        Ok(())
    }
}

impl Drop for RetainedSpawnFailure {
    fn drop(&mut self) {
        let custody = self
            .custody
            .get_mut()
            .expect("retained spawn custody poisoned");
        // Formatting/dropping an error must not discard the original uncertain handle.
        if custody.child.as_ref().is_some()
            || custody
                .owner
                .as_ref()
                .is_some_and(|owner| owner.exit_status().is_none())
        {
            std::mem::forget(custody.child.take());
            std::mem::forget(custody.owner.take());
        }
    }
}

/// Reap a failed spawn synchronously or return an error retaining its exact child.
pub fn rollback(error: anyhow::Error, child: Child) -> anyhow::Error {
    let failure = RetainedSpawnFailure {
        cause: error,
        custody: Mutex::new(Custody {
            child: Some(child),
            owner: None,
            uncertain: false,
        }),
    };
    match failure.retry_stop() {
        Ok(()) => {
            // Keep the original failure detail; the retained error itself also
            // records that subsequent retries have no live process to signal.
            anyhow::Error::new(failure)
        }
        Err(rollback) => {
            let detail = format!("{}; original child rollback: {rollback:#}", failure.cause);
            anyhow::Error::new(failure).context(detail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_error_keeps_exact_child_and_collects_exit_before_return() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let error = rollback(anyhow::anyhow!("injected startup failure"), child);
        let retained = error.downcast_ref::<RetainedSpawnFailure>().unwrap();
        assert!(retained.exit_collected());
        retained.retry_stop().unwrap();
        retained.retry_stop().unwrap();
        let custody = retained.custody.lock().unwrap();
        let original = custody.owner.as_ref().expect("original owner retained");
        assert_eq!(original.id(), pid);
        assert!(
            original.exit_status().is_some(),
            "signal success alone is not rollback"
        );
    }

    #[test]
    fn child_exit_before_observer_capture_is_rollback_evidence() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let pid = child.id();
        let status = child.wait().unwrap();
        let error = rollback(anyhow::anyhow!("startup failed after child exit"), child);
        assert!(
            error
                .to_string()
                .contains("startup failed after child exit")
        );
        assert!(!error.to_string().contains("original child rollback:"));
        let retained = error.downcast_ref::<RetainedSpawnFailure>().unwrap();
        assert!(retained.exit_collected());
        retained.retry_stop().unwrap();
        let custody = retained.custody.lock().unwrap();
        let owner = custody.owner.as_ref().unwrap();
        assert_eq!(owner.id(), pid);
        assert_eq!(owner.exit_status(), Some(status));
        assert_eq!(owner.retained_process_descriptor_count(), 0);
    }

    #[test]
    fn uncertain_custody_forbids_signal_and_keeps_the_actual_child() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let retained = RetainedSpawnFailure {
            cause: anyhow::anyhow!("injected wait failure"),
            custody: Mutex::new(Custody {
                child: Some(child),
                owner: None,
                uncertain: true,
            }),
        };
        assert!(retained.retry_stop().is_err());
        assert!(!retained.exit_collected());
        let mut custody = retained.custody.lock().unwrap();
        let mut original = custody.child.take().unwrap();
        assert_eq!(original.id(), pid);
        assert!(
            original.try_wait().unwrap().is_none(),
            "uncertain rollback must not signal"
        );
        original.kill().unwrap();
        original.wait().unwrap();
    }
}
