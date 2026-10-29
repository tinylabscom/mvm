//! The supervisor's side of a paused-snapshot request, as the host sees it.
//!
//! The host asks for a capture by writing `snapshot.request` and waits for the
//! frame to appear. A capture can be refused for a reason that is a property of
//! the moment (a device with host I/O still draining), and killing the guest
//! for that — as an error out of the run loop does — turns a retryable refusal
//! into a lost machine and leaves the host waiting out its whole deadline with
//! nothing to report. Instead the supervisor leaves the request in place, so
//! the next turn of the pause hold tries again, and records why in
//! [`ERROR_FILE`] for the host to quote if it never publishes.

use std::path::{Path, PathBuf};

/// Why the last capture attempt was refused, beside the request file.
pub const ERROR_FILE: &str = "snapshot.error";

/// Longest reason kept, so a runaway message cannot grow a state directory file.
const MAX_REASON_BYTES: usize = 512;

fn error_path(request: &Path) -> PathBuf {
    request.with_file_name(ERROR_FILE)
}

/// Record the outcome of one capture attempt.
///
/// `last` is the reason already on disk. The pause hold calls this every
/// millisecond, so an unchanged reason is not rewritten; a success removes the
/// file so a later reader never sees a refusal that has since cleared.
pub fn settle_attempt(request: &Path, last: &mut String, outcome: Result<(), String>) {
    let path = error_path(request);
    match outcome {
        Ok(()) => {
            if !last.is_empty() {
                let _ = std::fs::remove_file(&path);
                last.clear();
            }
        }
        Err(mut reason) => {
            reason.truncate(reason.floor_char_boundary(MAX_REASON_BYTES));
            if *last != reason {
                let _ = mvm_core::util::atomic_io::atomic_write(&path, reason.as_bytes());
                *last = reason;
            }
        }
    }
}

/// Forget any refusal left by an earlier request in `state_dir`.
pub fn clear_error(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(ERROR_FILE));
}

/// The reason the supervisor last gave for not publishing, if it gave one.
pub fn last_error(state_dir: &Path) -> Option<String> {
    std::fs::read_to_string(state_dir.join(ERROR_FILE))
        .ok()
        .filter(|reason| !reason.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_recorded_once_and_cleared_by_the_attempt_that_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let request = dir.path().join("snapshot.request");
        std::fs::write(&request, b"capture\n").unwrap();
        let mut last = String::new();

        settle_attempt(&request, &mut last, Err("device busy".into()));
        assert_eq!(last_error(dir.path()).as_deref(), Some("device busy"));
        assert!(
            request.exists(),
            "the request stays so the next turn retries"
        );

        settle_attempt(&request, &mut last, Err("device busy".into()));
        assert_eq!(last_error(dir.path()).as_deref(), Some("device busy"));

        settle_attempt(&request, &mut last, Err("gic".into()));
        assert_eq!(last_error(dir.path()).as_deref(), Some("gic"));

        settle_attempt(&request, &mut last, Ok(()));
        assert_eq!(last_error(dir.path()), None);
    }

    #[test]
    fn an_oversized_reason_is_cut_on_a_character_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let request = dir.path().join("snapshot.request");
        let mut last = String::new();
        settle_attempt(&request, &mut last, Err("é".repeat(1000)));
        let kept = last_error(dir.path()).unwrap();
        assert!(kept.len() <= MAX_REASON_BYTES);
        assert!(kept.chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_stale_refusal_is_cleared_before_a_new_request() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ERROR_FILE), b"old").unwrap();
        clear_error(dir.path());
        assert_eq!(last_error(dir.path()), None);
    }
}
