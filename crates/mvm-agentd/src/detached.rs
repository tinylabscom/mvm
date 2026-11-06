//! Detached agent threads that report their own death.
//!
//! The agent's background loops (monitoring, health checks, listeners) are
//! never joined. A panic in one ends that thread alone, and the default hook
//! prints an anonymous "thread '<unnamed>' panicked" line that says nothing
//! about which duty stopped. [`spawn_named`] gives the thread a name and adds
//! one line saying which loop ended and why.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Run `body`, calling `report(name, message)` if it panics. Returns whether
/// it panicked.
fn run_reporting(name: &str, body: impl FnOnce(), report: impl FnOnce(&str, &str)) -> bool {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(()) => false,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string());
            report(name, &message);
            true
        }
    }
}

/// Spawn a detached thread called `name`. If it panics, a line naming it goes
/// to stderr (the guest console) in addition to the panic hook's own output.
/// A failure to create the thread is reported the same way and returned.
///
/// # Errors
///
/// The OS error from creating the thread.
pub fn spawn_named(name: &'static str, body: impl FnOnce() + Send + 'static) -> io::Result<()> {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            run_reporting(name, body, |name, message| {
                eprintln!("mvm-guest-agent: thread {name} stopped by a panic: {message}");
            });
        })
        .map(drop)
        .inspect_err(|error| {
            eprintln!("mvm-guest-agent: could not start thread {name}: {error}");
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_is_reported_with_the_thread_name_and_message() {
        let mut seen = None;
        let panicked = run_reporting(
            "monitoring",
            || panic!("sampler exploded"),
            |name, message| seen = Some((name.to_string(), message.to_string())),
        );
        assert!(panicked);
        assert_eq!(
            seen,
            Some(("monitoring".to_string(), "sampler exploded".to_string()))
        );
    }

    #[test]
    fn a_formatted_panic_payload_is_reported_too() {
        let mut message = String::new();
        run_reporting("x", || panic!("code {}", 7), |_, m| message = m.to_string());
        assert_eq!(message, "code 7");
    }

    #[test]
    fn a_clean_exit_reports_nothing() {
        let mut reported = false;
        let panicked = run_reporting("x", || {}, |_, _| reported = true);
        assert!(!panicked && !reported);
    }

    #[test]
    fn the_spawned_thread_carries_its_name_and_runs_the_body() {
        let (tx, rx) = std::sync::mpsc::channel();
        spawn_named("agent-test-thread", move || {
            tx.send(std::thread::current().name().map(str::to_string))
                .unwrap();
        })
        .unwrap();
        assert_eq!(rx.recv().unwrap().as_deref(), Some("agent-test-thread"));
    }
}
