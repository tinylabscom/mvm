//! Deliver one entrypoint call's events to a consumer that is allowed to be
//! slow.
//!
//! [`crate::entrypoint::execute_streaming`] invokes its sink from the pump's
//! drain loop — the same loop that checks the child's deadline and advances
//! its kill ladder. A sink that writes to the host cannot run there. A host
//! that stops reading parks the loop inside a socket write; from that moment
//! the deadline is never checked, the kill ladder never advances, and a
//! workload outlives its timeout for as long as the host stays wedged. The
//! pump's queue is unbounded, so the parked loop also grows it without limit.
//!
//! So the two run on different threads. The pump gets a worker thread whose
//! sink only does a channel send — non-blocking whatever the host is doing —
//! and the caller's thread drains that channel into the real consumer. The
//! child's deadline is therefore enforced on schedule even when nothing is
//! reading the other end.
//!
//! Order survives the split: one FIFO channel, one producer, one consumer.
//! Interleaving between stdout and stderr reflects arrival order, which is
//! the point — the two are independent pipes and the kernel defines no order
//! between them either.

use std::sync::mpsc;
use std::time::Duration;

use crate::entrypoint::{EntrypointCall, RunOutcome, execute_streaming};
use crate::vsock::{EntrypointEvent, RunEntrypointError};

/// Run one entrypoint call, handing each event to `consume` on the calling
/// thread as it arrives.
///
/// Returns the single terminal event that ends the call. It is never handed
/// to `consume`, so a caller framing events onto a wire writes exactly one
/// terminal after everything else — which is what lets the host read until
/// terminal without desyncing.
pub fn stream_call(
    call: EntrypointCall<'_>,
    consume: &mut dyn FnMut(EntrypointEvent),
) -> EntrypointEvent {
    let timeout = call.timeout;
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let pumping = scope.spawn(move || {
            execute_streaming(&call, &mut |event| {
                // The receiver is drained below, inside this scope, so a send
                // only fails once the consumer has unwound. Nothing is left
                // to deliver to at that point.
                let _ = tx.send(event);
            })
        });

        // Ends when the pump thread returns and drops its sender.
        for event in rx {
            consume(event);
        }

        // Joining here rather than letting the scope do it is what keeps a
        // panicked pump from unwinding the whole connection: the call is
        // answered with a terminal the host can act on, and the agent goes on
        // serving.
        match pumping.join() {
            Ok(outcome) => terminal_event(outcome, timeout),
            Err(_) => EntrypointEvent::Error {
                kind: RunEntrypointError::InternalError,
                message: "entrypoint pump panicked".to_string(),
            },
        }
    })
}

/// Map a finished run onto the one event that ends its response.
fn terminal_event(outcome: RunOutcome, timeout: Duration) -> EntrypointEvent {
    match outcome {
        RunOutcome::Exited { code } => EntrypointEvent::Exit { code },
        RunOutcome::Timeout => EntrypointEvent::Error {
            kind: RunEntrypointError::Timeout,
            message: format!("wrapper exceeded {}s timeout", timeout.as_secs()),
        },
        RunOutcome::StdinCap => EntrypointEvent::Error {
            kind: RunEntrypointError::PayloadCap,
            message: "stdin exceeded its cap".to_string(),
        },
        RunOutcome::SpawnFailed { message } => EntrypointEvent::Error {
            kind: RunEntrypointError::InternalError,
            message,
        },
        RunOutcome::WrapperCrashed { signal } => EntrypointEvent::Error {
            kind: RunEntrypointError::WrapperCrashed,
            message: format!("wrapper exited via signal {signal}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_run_outcome_maps_to_exactly_one_terminal_event() {
        // The wire contract is one terminal per call. A non-terminal here
        // would leave the host reading a stream that has already ended.
        let outcomes = [
            RunOutcome::Exited { code: 3 },
            RunOutcome::Timeout,
            RunOutcome::StdinCap,
            RunOutcome::SpawnFailed {
                message: "no such wrapper".to_string(),
            },
            RunOutcome::WrapperCrashed { signal: 11 },
        ];
        for outcome in outcomes {
            let named = format!("{outcome:?}");
            let event = terminal_event(outcome, Duration::from_secs(9));
            assert!(
                event.is_terminal(),
                "{named} produced the non-terminal {event:?}"
            );
        }
    }

    #[test]
    fn a_timeout_terminal_names_the_budget_it_blew() {
        let event = terminal_event(RunOutcome::Timeout, Duration::from_secs(9));
        match event {
            EntrypointEvent::Error { kind, message } => {
                assert_eq!(kind, RunEntrypointError::Timeout);
                assert!(message.contains('9'), "message was {message:?}");
            }
            other => panic!("expected an Error terminal, got {other:?}"),
        }
    }

    #[test]
    fn an_exit_code_survives_the_terminal_mapping() {
        assert_eq!(
            terminal_event(RunOutcome::Exited { code: 7 }, Duration::from_secs(1)),
            EntrypointEvent::Exit { code: 7 }
        );
    }
}
