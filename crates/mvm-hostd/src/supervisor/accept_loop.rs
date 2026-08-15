//! Accept-error policy shared by every guest-facing listener.
//!
//! `accept(2)` reports two very different things through one error channel.
//! Some errors mean the listener is dead and the loop must stop (`EBADF`,
//! `EINVAL`, `ENOTSOCK`). Others are about the *pending connection* or about
//! transient host pressure — a peer that reset between SYN and accept, a signal,
//! or exhausted file descriptors — and the listener is still perfectly good.
//!
//! Treating the second class as fatal ends egress for a VM that did nothing
//! wrong, for the rest of its life: fd exhaustion is usually host-wide, so the
//! process that caused it is typically not the one that dies, and the VM does
//! not recover when the host does.

use std::io;
use std::time::Duration;

use crate::supervisor::audit_recorder::{EventCategory, Recorder};

/// Ceiling on the retry delay. Fd exhaustion clears on a human timescale, so a
/// second between probes is cheap; the cap exists to stop the shift growing
/// without bound, not because a longer wait would hurt.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Consecutive transient errors tolerated before backing off at all. A lone
/// `ECONNABORTED` is one dead connection attempt and the next accept should be
/// immediate; only a *sustained* streak indicates pressure worth pausing for.
const FREE_RETRIES: u32 = 4;

/// What the caller should do about an accept error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptAction {
    /// The listener is still usable. Sleep this long, then accept again.
    Retry(Duration),
    /// The listener cannot recover. Stop the loop.
    Fatal,
}

/// Classify an accept error, given how many transient errors have arrived
/// back-to-back (0 for the first).
///
/// Unrecognised errno values are treated as fatal. A listener failing in a way
/// we have not characterised should surface loudly rather than spin forever on
/// an error nothing will clear.
#[must_use]
pub fn classify_accept_error(err: &io::Error, consecutive: u32) -> AcceptAction {
    let transient = match err.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::OutOfMemory => true,
        // EMFILE/ENFILE/ENOBUFS have no stable `ErrorKind`, so they only ever
        // arrive as a raw errno.
        //
        // The second group is what `accept(2)` reports about the *pending
        // connection* rather than about the listener. Linux passes errors
        // already pending on the new socket back through the accept call, and
        // the man page is explicit that an application should treat them like
        // EAGAIN and retry. Omitting them is not neutral: the terminator loop
        // is bound to a real TcpListener, so a single EPROTO there would end
        // transparent egress for that VM permanently — the exact failure this
        // module exists to prevent, arriving through a different errno.
        _ => matches!(
            err.raw_os_error(),
            Some(libc::EMFILE)
                | Some(libc::ENFILE)
                | Some(libc::ENOBUFS)
                | Some(libc::ENOMEM)
                | Some(libc::EPROTO)
                | Some(libc::EPERM)
                | Some(libc::ENOSR)
                | Some(libc::ETIMEDOUT)
                | Some(libc::ENETDOWN)
                | Some(libc::ENETUNREACH)
                | Some(libc::EHOSTUNREACH)
                | Some(libc::EOPNOTSUPP)
        ),
    };
    if transient {
        AcceptAction::Retry(retry_delay(consecutive))
    } else {
        AcceptAction::Fatal
    }
}

/// Delay before retry `consecutive` (0-based): free for the first few, then
/// 1 ms doubling to the ceiling.
fn retry_delay(consecutive: u32) -> Duration {
    let Some(over) = consecutive.checked_sub(FREE_RETRIES) else {
        return Duration::ZERO;
    };
    // Saturating shift: a listener wedged for a very long time must not
    // overflow its way back to a zero delay.
    let ms = 1u64.saturating_mul(1u64 << over.min(16));
    Duration::from_millis(ms).min(MAX_RETRY_DELAY)
}

/// Record a guest-facing listener giving up.
///
/// A VM that loses egress goes quiet rather than failing loudly — the workload
/// keeps running and its connections simply stop working. Without an entry in
/// the chain the only trace is a line on this process's stderr, and for the
/// terminator (a spawned task the primary loop does not join) not even the
/// process exit signals it.
pub async fn record_listener_stopped(recorder: Option<&Recorder>, listener: &str, reason: &str) {
    let Some(recorder) = recorder else {
        tracing::warn!(
            listener,
            reason,
            "listener stopped with no recorder to audit it"
        );
        return;
    };
    let labels = [
        ("listener".to_string(), listener.to_string()),
        ("reason".to_string(), reason.to_string()),
    ];
    if let Err(error) = recorder
        .record_unbound(EventCategory::Host, "host.listener_stopped", labels)
        .await
    {
        tracing::warn!(%error, listener, "listener-stop audit emit failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errno(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn peer_and_signal_errors_retry_immediately() {
        for code in [libc::EINTR, libc::ECONNABORTED, libc::ECONNRESET] {
            assert_eq!(
                classify_accept_error(&errno(code), 0),
                AcceptAction::Retry(Duration::ZERO),
                "errno {code} is about one pending connection, not the listener"
            );
        }
    }

    #[test]
    fn fd_exhaustion_retries_rather_than_killing_the_listener() {
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(
                classify_accept_error(&errno(code), 0),
                AcceptAction::Retry(Duration::ZERO),
                "errno {code} is host pressure; the listener is still good"
            );
        }
    }

    #[test]
    fn dead_listener_errors_are_fatal() {
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            assert_eq!(
                classify_accept_error(&errno(code), 0),
                AcceptAction::Fatal,
                "errno {code} means the listener cannot serve again"
            );
        }
    }

    #[test]
    fn a_pending_connections_network_error_retries_rather_than_ending_the_terminator() {
        // Linux `accept()` reports errors already pending on the *new* socket
        // through the accept call. The man page is explicit that these should be
        // treated like EAGAIN and retried — they describe one dead connection
        // attempt, never the listener. This matters for `serve_terminator`,
        // which is the one loop bound to a real TcpListener: without this, a
        // single EPROTO permanently ends transparent egress for that VM.
        for code in [
            libc::EPROTO,
            libc::EPERM,
            libc::ENETDOWN,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ETIMEDOUT,
            libc::EOPNOTSUPP,
        ] {
            assert!(
                matches!(
                    classify_accept_error(&errno(code), 0),
                    AcceptAction::Retry(_)
                ),
                "errno {code} is a pending connection's error, not the listener's"
            );
        }
    }

    #[test]
    fn unrecognised_errors_are_fatal_rather_than_spinning() {
        // Pinned to an errno `accept(2)` can genuinely produce but that says
        // nothing characterised about the listener. The earlier pin was `EDOM`,
        // which `accept` cannot return at all — so the assertion held for every
        // errno that mattered and the missing pending-connection family went
        // unnoticed. A fatal-by-default policy is only honest if its test uses
        // an error the syscall can actually raise.
        assert_eq!(
            classify_accept_error(&errno(libc::EFAULT), 0),
            AcceptAction::Fatal
        );
    }

    #[tokio::test]
    async fn a_stopped_listener_lands_in_the_chain() {
        use crate::supervisor::audit::CapturingAuditSigner;
        use mvm_core::plan::TenantId;
        use std::sync::Arc;

        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), TenantId("local".into()));
        record_listener_stopped(Some(&recorder), "terminator", "bad file descriptor").await;

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "host.listener_stopped");
        assert_eq!(
            entries[0].labels.get("listener").map(String::as_str),
            Some("terminator")
        );
        assert_eq!(
            entries[0].labels.get("reason").map(String::as_str),
            Some("bad file descriptor")
        );
    }

    #[test]
    fn a_sustained_streak_backs_off_and_caps() {
        let delay = |n: u32| match classify_accept_error(&errno(libc::EMFILE), n) {
            AcceptAction::Retry(d) => d,
            AcceptAction::Fatal => panic!("EMFILE must retry"),
        };
        assert_eq!(
            delay(FREE_RETRIES - 1),
            Duration::ZERO,
            "first few are free"
        );
        assert_eq!(delay(FREE_RETRIES), Duration::from_millis(1));
        assert_eq!(delay(FREE_RETRIES + 1), Duration::from_millis(2));
        assert_eq!(delay(FREE_RETRIES + 4), Duration::from_millis(16));
        assert_eq!(
            delay(1_000),
            MAX_RETRY_DELAY,
            "and never grows past the cap"
        );
    }
}
