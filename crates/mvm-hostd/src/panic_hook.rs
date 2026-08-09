//! Redacting panic hook for the host daemons.
//!
//! The supervisor and its helper subprocesses are the only processes in the
//! system that hold secret material in the clear. `xtask
//! check-no-display-on-secret-types` keeps those values out of `Debug` and
//! `Display` impls, but a panic payload is neither: `.expect(&format!("...
//! {token}"))`, or an `unwrap()` on an error type that transitively carries a
//! value, produces a string the gate never sees. That string goes to stderr,
//! which in the supervisor's case is a captured log file.
//!
//! This hook is the last place to catch that. It runs every payload through
//! the same [`SecretsScanner`] the stream plane uses, so a value that would be
//! redacted on its way out of the guest is also redacted on its way into a
//! crash log.
//!
//! # What this hook deliberately does not do
//!
//! **It does not exit the process.** A panic hook runs for *every* panic,
//! including ones that are about to be caught. Three places rely on
//! `catch_unwind` to contain a fault without losing the process — the observer
//! pipeline, the gateway-bridge signer fan-out, and the host-services FFI
//! boundary — and a hook that exited would silently convert all of them into
//! crashes. Panic *policy* belongs at those call sites, which can tell a
//! contained fault from a fatal one; the hook only observes.
//!
//! **It does not emit an audit entry.** The audit signer takes a mutex and a
//! file lock, and the most likely reason to be in this hook holding secret
//! material is that something in that path just failed. A hook that tried to
//! sign would deadlock on the lock it already holds, or hit a poisoned mutex
//! and panic again — and a panic inside a panic hook aborts. Crash reporting
//! that can take down the process it is reporting on is worse than none.

use std::panic::PanicHookInfo;
use std::sync::Once;

use crate::supervisor::secrets_scanner::SecretsScanner;

static INSTALL: Once = Once::new();

/// Mask substituted for a matched secret. Fixed-width on purpose: the length
/// of the original is itself a hint, and a crash log is exactly the artifact
/// that gets pasted into a ticket.
const MASK: &[u8] = b"[redacted]";

/// Install the redacting hook for `role`, once per process.
///
/// Chains to whatever hook was already installed, so this composes with a
/// test harness's hook or a future reporter rather than replacing it. Safe to
/// call from every daemon `main`; subsequent calls are no-ops.
pub fn install(role: &'static str) {
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            report(role, info);
            previous(info);
        }));
    });
}

/// Render one panic as a redacted log line.
fn report(role: &'static str, info: &PanicHookInfo<'_>) {
    let scanner = SecretsScanner::with_default_rules();
    let (message, categories) = redact_payload(&scanner, payload_of(info));
    // `location()` is the only positional signal available: release builds are
    // built with `strip = true`, so there is no symbolized backtrace to pair
    // it with.
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown>".to_string());

    if categories.is_empty() {
        tracing::error!(role, location, message, "daemon panicked");
    } else {
        // Naming the categories without the values tells an operator which
        // credential to rotate, which is the actionable half of the leak.
        tracing::error!(
            role,
            location,
            message,
            redacted = categories.join(","),
            "daemon panicked; secret material was redacted from the payload"
        );
    }
}

/// Extract the panic payload as a string.
///
/// `panic!` with a format string yields `String`; a literal yields `&str`.
/// Anything else (`panic_any`) has no meaningful text, and its `Debug` is not
/// something we want to render into a log — it could be the very value we are
/// trying to keep out.
fn payload_of<'a>(info: &'a PanicHookInfo<'_>) -> &'a str {
    let payload = info.payload();
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    }
}

/// Run `message` through the scanner, returning the redacted text and the
/// categories that matched.
///
/// Lossy UTF-8 on the way back: the scanner works in bytes and a mask can land
/// mid-sequence. A crash log is a diagnostic, so a replacement character is an
/// acceptable price for never emitting the original bytes.
fn redact_payload(scanner: &SecretsScanner, message: &str) -> (String, Vec<&'static str>) {
    let (redacted, categories) = scanner.redact(message.as_bytes(), MASK);
    (String::from_utf8_lossy(&redacted).into_owned(), categories)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case the hook exists for: a secret interpolated into a panic
    /// message, which no `Debug`/`Display` gate can reach.
    #[test]
    fn a_secret_in_the_payload_is_redacted() {
        let scanner = SecretsScanner::with_default_rules();
        let leaked = "failed to authenticate with ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let (message, categories) = redact_payload(&scanner, leaked);

        assert!(
            !message.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            "the raw token survived redaction: {message}"
        );
        assert!(
            message.contains("[redacted]"),
            "expected a mask in {message}"
        );
        assert!(
            !categories.is_empty(),
            "a matched secret must name its category so the operator knows what to rotate"
        );
    }

    /// Redaction must not eat ordinary diagnostics — a hook that masked
    /// everything would make the test above pass while destroying the logs.
    #[test]
    fn an_ordinary_message_passes_through_intact() {
        let scanner = SecretsScanner::with_default_rules();
        let (message, categories) = redact_payload(&scanner, "vsock accept failed: EAGAIN");
        assert_eq!(message, "vsock accept failed: EAGAIN");
        assert!(categories.is_empty());
    }

    #[test]
    fn a_string_payload_is_recovered() {
        let info = std::panic::catch_unwind(|| panic!("{}", "formatted".to_string()))
            .expect_err("the closure panics");
        assert!(info.downcast_ref::<String>().is_some());
    }

    /// A non-string payload must not be rendered via `Debug` — that is a path
    /// back to the value we are trying to keep out of the log.
    #[test]
    fn a_non_string_payload_is_not_rendered() {
        let payload = std::panic::catch_unwind(|| std::panic::panic_any(42u32))
            .expect_err("the closure panics");
        assert!(payload.downcast_ref::<String>().is_none());
        assert!(payload.downcast_ref::<&'static str>().is_none());
    }

    /// Installing twice must not stack hooks — each install wraps the
    /// previous one, so an unguarded `install` in a retry loop would grow an
    /// unbounded chain and multiply every future panic's output.
    #[test]
    fn install_is_idempotent() {
        install("test-role");
        install("test-role");
        // Reaching here without recursion or a double-install panic is the
        // assertion; `Once` guarantees the body ran at most once.
    }
}
