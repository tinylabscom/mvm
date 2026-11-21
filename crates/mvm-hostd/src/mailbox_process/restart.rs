//! When the mailbox helper reopens itself instead of exiting.
//!
//! A commit to the policy coordinator that ends with an unknown outcome, or a
//! coordinator that is briefly unreachable, stops a serving run. The journal is
//! not damaged by that: opening it again re-enrolls with the coordinator, which
//! reconciles the outcome. The helper outlives its launcher, so it does this in
//! its own process, through the same open path as a first start.

use std::io::{Error, Result, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::READY_MARKER;
use crate::mailbox_commit::OrderingFlags;

/// Wait before the first reopen, and the cap the wait doubles up to.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The waits between reopens.
#[derive(Clone, Copy)]
pub(super) struct Backoff {
    pub(super) floor: Duration,
    pub(super) cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            floor: BACKOFF_FLOOR,
            cap: BACKOFF_CAP,
        }
    }
}

/// Carried inside an [`Error`] to say the run ended in a way a reopen can
/// recover from.
#[derive(Debug, thiserror::Error)]
#[error("a mailbox commit's outcome is unknown; the helper reopens to reconcile it: {0}")]
pub(super) struct Restartable(String);

pub(super) fn is_restartable(error: &Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<Restartable>())
}

/// Whether this process has told its launcher it is ready. The launcher reads
/// the marker once and closes the pipe, so it is written once per process.
#[derive(Default)]
pub(super) struct Readiness(AtomicBool);

impl Readiness {
    pub(super) fn announce(&self) -> Result<()> {
        if self.0.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        std::io::stdout().write_all(READY_MARKER)
    }

    fn announced(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Mark `error` restartable when the flags say only an unknown outcome stopped
/// the run: ready was announced by this process, no refusal and no retention
/// pass happened, and the VM still needs the helper. Anything else, including a
/// failure before the first readiness, is returned unchanged.
pub(super) fn classify(
    error: Error,
    ready: &Readiness,
    flags: &OrderingFlags,
    keep: bool,
) -> Error {
    let set = |flag: &AtomicBool| flag.load(Ordering::SeqCst);
    let restartable = ready.announced()
        && keep
        && set(&flags.unknown)
        && !set(&flags.refused)
        && !set(&flags.retention);
    if restartable {
        Error::other(Restartable(error.to_string()))
    } else {
        error
    }
}

/// Run until a run ends in anything but a restartable error. `now` is a
/// monotonic clock; a run that outlived the cap resets the wait to the floor.
pub(super) fn run_restarting(
    mut run: impl FnMut() -> Result<()>,
    keep_going: impl Fn() -> bool,
    mut sleep: impl FnMut(Duration),
    mut now: impl FnMut() -> Duration,
    backoff: Backoff,
) -> Result<()> {
    let mut delay = backoff.floor;
    loop {
        let started = now();
        let error = match run() {
            Err(error) if is_restartable(&error) => error,
            other => return other,
        };
        if now().saturating_sub(started) > backoff.cap {
            delay = backoff.floor;
        }
        tracing::warn!(%error, ?delay, "mailbox helper reopening");
        sleep(delay);
        delay = (delay * 2).min(backoff.cap);
        if !keep_going() {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn restartable() -> Error {
        Error::other(Restartable("unknown".into()))
    }

    fn flags(refused: bool, unknown: bool, retention: bool) -> OrderingFlags {
        let flags = OrderingFlags::default();
        flags.refused.store(refused, Ordering::SeqCst);
        flags.unknown.store(unknown, Ordering::SeqCst);
        flags.retention.store(retention, Ordering::SeqCst);
        flags
    }

    fn ready(announced: bool) -> Readiness {
        Readiness(AtomicBool::new(announced))
    }

    fn classified(ready_: bool, flags_: OrderingFlags, keep: bool) -> bool {
        is_restartable(&classify(Error::other("x"), &ready(ready_), &flags_, keep))
    }

    #[test]
    fn only_an_unknown_outcome_after_readiness_is_restartable() {
        assert!(classified(true, flags(false, true, false), true));
        assert!(
            !classified(true, flags(true, false, false), true),
            "refused"
        );
        assert!(!classified(true, flags(true, true, false), true), "both");
        assert!(
            !classified(true, flags(false, false, false), true),
            "neither"
        );
        assert!(
            !classified(false, flags(false, true, false), true),
            "not ready"
        );
        assert!(
            !classified(true, flags(false, true, true), true),
            "retention"
        );
        assert!(
            !classified(true, flags(false, true, false), false),
            "vm gone"
        );
    }

    #[test]
    fn a_classified_error_keeps_its_kind_when_it_is_not_restartable() {
        let error = Error::new(std::io::ErrorKind::PermissionDenied, "refused");
        let out = classify(error, &ready(true), &flags(true, false, false), true);
        assert_eq!(out.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn readiness_is_announced_once() {
        let ready = ready(false);
        assert!(!ready.announced());
        ready.announce().unwrap();
        assert!(ready.announced());
        ready.announce().unwrap();
    }

    struct Rig {
        runs: Cell<u32>,
        sleeps: RefCell<Vec<Duration>>,
        clock: Cell<Duration>,
    }

    impl Rig {
        fn new() -> Self {
            Self {
                runs: Cell::new(0),
                sleeps: RefCell::new(Vec::new()),
                clock: Cell::new(Duration::ZERO),
            }
        }

        fn drive(
            &self,
            results: impl Fn(u32) -> Result<()>,
            run_takes: Duration,
            keep: impl Fn(u32) -> bool,
        ) -> Result<()> {
            run_restarting(
                || {
                    self.runs.set(self.runs.get() + 1);
                    self.clock.set(self.clock.get() + run_takes);
                    results(self.runs.get())
                },
                || keep(self.runs.get()),
                |d| self.sleeps.borrow_mut().push(d),
                || self.clock.get(),
                Backoff::default(),
            )
        }
    }

    fn secs(values: &[u64]) -> Vec<Duration> {
        values.iter().map(|s| Duration::from_secs(*s)).collect()
    }

    #[test]
    fn a_restartable_error_sleeps_then_runs_again() {
        let rig = Rig::new();
        let out = rig.drive(
            |run| if run < 3 { Err(restartable()) } else { Ok(()) },
            Duration::ZERO,
            |_| true,
        );
        assert!(out.is_ok());
        assert_eq!(rig.runs.get(), 3);
        assert_eq!(*rig.sleeps.borrow(), secs(&[1, 2]));
    }

    #[test]
    fn another_error_is_returned_at_once() {
        let rig = Rig::new();
        let out = rig.drive(
            |_| Err(Error::new(std::io::ErrorKind::PermissionDenied, "no")),
            Duration::ZERO,
            |_| true,
        );
        assert_eq!(
            out.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(rig.runs.get(), 1);
        assert!(rig.sleeps.borrow().is_empty());
    }

    #[test]
    fn the_loop_stops_when_the_vm_is_gone() {
        let rig = Rig::new();
        let out = rig.drive(|_| Err(restartable()), Duration::ZERO, |runs| runs < 2);
        assert!(out.is_err());
        assert_eq!(rig.runs.get(), 2);
    }

    #[test]
    fn the_wait_doubles_up_to_the_cap() {
        let rig = Rig::new();
        let _ = rig.drive(|_| Err(restartable()), Duration::ZERO, |runs| runs < 7);
        assert_eq!(*rig.sleeps.borrow(), secs(&[1, 2, 4, 8, 16, 30, 30]));
    }

    #[test]
    fn a_long_run_resets_the_wait() {
        let rig = Rig::new();
        let _ = rig.drive(
            |_| Err(restartable()),
            Duration::from_secs(31),
            |runs| runs < 3,
        );
        assert_eq!(*rig.sleeps.borrow(), secs(&[1, 1, 1]));
    }
}
