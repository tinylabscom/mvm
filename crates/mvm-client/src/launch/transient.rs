//! Transient launch orchestration and observation before session rollback.

use super::{LaunchOutcome, LaunchRequest, generated_transient_name};
use crate::local::LocalBackend;
use mvm_core::client::Result;
use mvm_core::launch_trace::failure::{Phase, Record};

impl LocalBackend {
    /// The transient launch path: collision check, secret-ref validation +
    /// recording, attachment registration, lease acquisition, admitted boot,
    /// registration. Failures attempt existing rollback; a known command-stop
    /// failure retains state and resources without another stop or liveness check.
    #[tracing::instrument(skip_all)]
    pub(super) async fn launch_transient(&self, request: LaunchRequest) -> Result<LaunchOutcome> {
        let name = request
            .name
            .clone()
            .unwrap_or_else(generated_transient_name);
        self.ensure_transient_name_free(&name)?;
        self.validate_and_record_secret_refs(&name, &request.secret_refs)?;

        let mut phase = Phase::TransientBoot;
        let result = match self.attach_lease_and_boot(&name, &request, true).await {
            Ok(outcome) => {
                phase = Phase::TransientCommand;
                match self.start_requested_command(outcome, &request) {
                    Ok(outcome) => Ok(outcome),
                    Err(failure) if failure.stop.is_err() => {
                        Record::new(phase).emit();
                        return Err(failure.into_error());
                    }
                    Err(failure) => Err(failure.into_error()),
                }
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                observe_then_cleanup(Record::new(phase), Record::emit, || {
                    // Idempotent rollback of everything this session recorded.
                    if let Err(cleanup) = self.cleanup_transient(&name) {
                        tracing::warn!(error = %cleanup, machine = %name, "transient cleanup after failed launch");
                    }
                });
                Err(e)
            }
        }
    }
}

fn observe_then_cleanup<T>(
    record: Record,
    observe: impl FnOnce(Record) -> T,
    cleanup: impl FnOnce(),
) {
    let _ = observe(record);
    cleanup();
}

#[cfg(test)]
mod tests {
    #[test]
    fn typed_observation_precedes_cleanup_even_when_the_writer_refuses() {
        use mvm_core::launch_trace::failure::{Phase, Record};
        let events = std::cell::RefCell::new(Vec::new());
        let retained_state = std::cell::Cell::new(true);
        super::observe_then_cleanup(
            Record::new(Phase::TransientCommand),
            |record| {
                assert!(retained_state.get());
                assert_eq!(record.phase, Phase::TransientCommand);
                events.borrow_mut().push("observe");
                Err::<(), _>(std::io::ErrorKind::BrokenPipe)
            },
            || {
                events.borrow_mut().push("cleanup");
                retained_state.set(false);
            },
        );
        assert_eq!(*events.borrow(), ["observe", "cleanup"]);
        assert!(!retained_state.get());
    }
}
