//! Where a host that owns real per-VM output brokers registers itself, so
//! every workload this crate boots gets its console followed without this
//! crate ever naming the type that does the following.
//!
//! [`ConsoleStreamer`](super::runner::ConsoleStreamer) exists because the
//! broker lives in the host-daemon crate, which sits *above* this one. That
//! leaves the wiring two possible shapes, and only one of them works here: a
//! constructor argument would have to be threaded through
//! [`crate::backend`]'s argument-free runner helpers and everything that
//! reaches them — `auto_select`, the descriptor catalog, the capability
//! selector — putting an observability dependency in signatures that have no
//! business carrying one. A one-time registration at process startup is the
//! shape the builder-backend constructor already uses for exactly this
//! dependency-direction problem.
//!
//! Registration is once per process and cannot be replaced. A hook that could
//! be swapped mid-run would let one VM's output be captured and the next VM's
//! not, for no reason a reader of a log could ever reconstruct.
//!
//! With nothing registered the hook stays
//! [`NoopConsoleStreamer`](super::runner::NoopConsoleStreamer), so an embedder
//! that never registers one boots workloads exactly as before.

use std::sync::{Arc, OnceLock};

use super::runner::{ConsoleStreamer, NoopConsoleStreamer};

static INSTALLED: OnceLock<Arc<dyn ConsoleStreamer>> = OnceLock::new();

/// Register the process's console streamer.
///
/// Returns whether this call is the one that installed it — `false` means a
/// streamer was already registered and this one was discarded. Callers at
/// startup can ignore that; a caller that needs its own hook to be the live
/// one must check.
pub fn install_console_streamer(streamer: Arc<dyn ConsoleStreamer>) -> bool {
    INSTALLED.set(streamer).is_ok()
}

/// Whether a streamer has been registered for this process.
pub fn console_streamer_installed() -> bool {
    INSTALLED.get().is_some()
}

/// The hook every [`WorkloadRunner`](super::WorkloadRunner) starts life with.
pub fn active_console_streamer() -> Arc<dyn ConsoleStreamer> {
    INSTALLED.get().map_or_else(
        || Arc::new(NoopConsoleStreamer) as Arc<dyn ConsoleStreamer>,
        Arc::clone,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording {
        started: Mutex<Vec<String>>,
    }

    impl ConsoleStreamer for Recording {
        fn start(&self, vm_name: &str, _console_log: &Path) {
            self.started.lock().unwrap().push(vm_name.to_string());
        }
        fn stop(&self, _vm_name: &str) {}
    }

    /// One test, because the registration is process-global and once-only:
    /// splitting the before/after halves into separate `#[test]`s would make
    /// them order-dependent under a shared test binary.
    #[test]
    fn the_hook_is_a_noop_until_registered_and_the_first_registration_wins() {
        assert!(
            !console_streamer_installed(),
            "nothing in this crate may register a streamer at load time"
        );
        // The default is inert, not absent: a runner built before any
        // registration still has something to call.
        active_console_streamer().start("vm-before", Path::new("/dev/null"));

        let first = Arc::new(Recording::default());
        assert!(install_console_streamer(
            first.clone() as Arc<dyn ConsoleStreamer>
        ));
        assert!(console_streamer_installed());

        let second = Arc::new(Recording::default());
        assert!(
            !install_console_streamer(second.clone() as Arc<dyn ConsoleStreamer>),
            "a second registration must be refused, not silently swapped in"
        );

        active_console_streamer().start("vm-after", Path::new("/dev/null"));
        assert_eq!(first.started.lock().unwrap().as_slice(), ["vm-after"]);
        assert!(second.started.lock().unwrap().is_empty());
    }
}
