//! The supervisor's side of a paused-snapshot request, as the host sees it.
//!
//! The host asks for a capture by writing `snapshot.request` (naming a nonce)
//! and waits for that nonce's frame to appear. A capture can be refused for a reason that is a property of
//! the moment (a device with host I/O still draining), and killing the guest
//! for that — as an error out of the run loop does — turns a retryable refusal
//! into a lost machine and leaves the host waiting out its whole deadline with
//! nothing to report. Instead the supervisor leaves the request in place, so
//! the next turn of the pause hold tries again, and records why in
//! [`ERROR_FILE`] for the host to quote if it never publishes.

use std::io::Read;
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

/// File name of the exclusive lock that orders pause, capture and resume.
const LOCK_FILE: &str = "capture.lock";

/// Exclusive ownership of a VM's pause and capture sequence, held for the
/// guard's lifetime. A second requester queues behind it, so a resume can never
/// land inside a capture and two captures never share the request file.
#[derive(Debug)]
pub struct CaptureLock {
    _file: std::fs::File,
}

impl CaptureLock {
    /// Block until this process owns the sequence for `state_dir`.
    pub fn acquire(state_dir: &Path) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(state_dir.join(LOCK_FILE))?;
        // SAFETY: `file` is open and owned here; the lock lives as long as it.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

/// A fresh identity for one capture request. Outputs are published under it, so
/// a supervisor that finishes an abandoned request late writes files nobody
/// is waiting on instead of overwriting the next capture's.
pub fn new_nonce() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// The request file's body for `nonce`.
pub fn request_body(nonce: &str) -> String {
    format!("capture {nonce}\n")
}

/// The nonce a request file names, if it is well formed.
pub fn request_nonce(body: &str) -> Option<&str> {
    let nonce = body.strip_prefix("capture ")?.strip_suffix('\n')?;
    (!nonce.is_empty() && nonce.len() <= 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some(nonce)
}

/// Where the output published for `nonce` lands, derived from the configured path.
pub fn output_for(base: &Path, nonce: &str) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(".");
    name.push(nonce);
    PathBuf::from(name)
}

/// Remove every published output beside `base`, whatever request made it.
pub fn sweep_outputs(base: &Path) {
    let (Some(dir), Some(stem)) = (base.parent(), base.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && name
                .strip_prefix(stem)
                .is_some_and(|rest| rest.starts_with('.'))
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Read the request at `path` and the nonce it names.
pub fn read_request(path: &Path) -> Result<(String, String), String> {
    let body = std::fs::read_to_string(path).map_err(|error| format!("request read: {error}"))?;
    let nonce = request_nonce(&body)
        .ok_or_else(|| "request names no capture identity".to_string())?
        .to_owned();
    Ok((body, nonce))
}

/// Consume the request that was served: removed only if it still reads `body`,
/// so a request a later caller wrote meanwhile is left for its own attempt.
pub fn consume_request(path: &Path, body: &str) {
    if std::fs::read_to_string(path).is_ok_and(|now| now == body) {
        let _ = std::fs::remove_file(path);
    }
}

/// Forget any refusal left by an earlier request in `state_dir`.
pub fn clear_error(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(ERROR_FILE));
}

/// The reason the supervisor last gave for not publishing, if it gave one.
///
/// Oversized, malformed or unreadable records are ignored. The byte limit does
/// not bound filesystem wait time or prevent following links.
pub fn last_error(state_dir: &Path) -> Option<String> {
    let file = std::fs::File::open(state_dir.join(ERROR_FILE)).ok()?;
    let mut reason = String::new();
    file.take((MAX_REASON_BYTES + 1) as u64)
        .read_to_string(&mut reason)
        .ok()?;
    (!reason.is_empty() && reason.len() <= MAX_REASON_BYTES).then_some(reason)
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
    fn a_reason_at_the_byte_limit_is_preserved_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let reason = "é".repeat(MAX_REASON_BYTES / 2);
        std::fs::write(dir.path().join(ERROR_FILE), &reason).unwrap();
        assert_eq!(last_error(dir.path()), Some(reason));
    }

    #[test]
    fn an_oversized_replacement_is_not_a_refusal_record() {
        let dir = tempfile::tempdir().unwrap();
        let request = dir.path().join("snapshot.request");
        settle_attempt(&request, &mut String::new(), Err("device busy".into()));
        assert_eq!(last_error(dir.path()).as_deref(), Some("device busy"));

        for size in [MAX_REASON_BYTES + 1, MAX_REASON_BYTES * 1024] {
            let replacement = dir.path().join("replacement");
            std::fs::write(&replacement, "x".repeat(size)).unwrap();
            std::fs::rename(&replacement, dir.path().join(ERROR_FILE)).unwrap();
            assert_eq!(last_error(dir.path()), None, "replacement size {size}");
        }
    }

    #[test]
    fn malformed_utf8_is_not_a_refusal_record() {
        let dir = tempfile::tempdir().unwrap();
        for bytes in [b"busy\xff".as_slice(), b"busy\xc3".as_slice()] {
            std::fs::write(dir.path().join(ERROR_FILE), bytes).unwrap();
            assert_eq!(last_error(dir.path()), None);
        }
    }

    #[test]
    fn missing_empty_or_unreadable_records_add_no_reason() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(last_error(dir.path()), None);
        let path = dir.path().join(ERROR_FILE);
        std::fs::write(&path, b"").unwrap();
        assert_eq!(last_error(dir.path()), None);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(last_error(dir.path()), None);
    }

    #[test]
    fn a_stale_refusal_is_cleared_before_a_new_request() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ERROR_FILE), b"old").unwrap();
        clear_error(dir.path());
        assert_eq!(last_error(dir.path()), None);
    }

    #[test]
    fn a_second_capture_waits_for_the_first_to_release_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let first = CaptureLock::acquire(dir.path()).unwrap();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let path = dir.path().to_path_buf();
        let second = std::thread::spawn(move || {
            let _lock = CaptureLock::acquire(&path).unwrap();
            acquired_tx.send(()).unwrap();
        });
        assert!(
            acquired_rx.try_recv().is_err(),
            "the second requester must queue"
        );
        drop(first);
        acquired_rx.recv().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn a_late_writers_output_never_aliases_the_next_requests() {
        let base = Path::new("/s/snapshot.ram");
        let (a, b) = (new_nonce(), new_nonce());
        assert_ne!(a, b);
        assert_ne!(output_for(base, &a), output_for(base, &b));
        assert_eq!(request_nonce(&request_body(&a)), Some(a.as_str()));
        for bad in [
            "capture\n",
            "capture \n",
            "capture ../x\n",
            "capture abc",
            "x abc\n",
        ] {
            assert_eq!(request_nonce(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sweeping_removes_abandoned_outputs_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("snapshot.ram");
        let stale = output_for(&base, "abc");
        std::fs::write(&stale, b"x").unwrap();
        std::fs::write(&base, b"fixed").unwrap();
        let other = dir.path().join("snapshot.frame.abc");
        std::fs::write(&other, b"y").unwrap();
        sweep_outputs(&base);
        assert!(!stale.exists() && base.exists() && other.exists());
    }

    #[test]
    fn serving_a_request_never_consumes_a_newer_one() {
        let dir = tempfile::tempdir().unwrap();
        let request = dir.path().join("snapshot.request");
        let (old, new) = (new_nonce(), new_nonce());
        std::fs::write(&request, request_body(&old)).unwrap();
        let (body, nonce) = read_request(&request).unwrap();
        assert_eq!(nonce, old);
        // The caller gave up and a second caller wrote its own request.
        std::fs::write(&request, request_body(&new)).unwrap();
        consume_request(&request, &body);
        assert_eq!(read_request(&request).unwrap().1, new);
        let (body, _) = read_request(&request).unwrap();
        consume_request(&request, &body);
        assert!(!request.exists());
    }

    #[test]
    fn a_request_without_an_identity_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let request = dir.path().join("snapshot.request");
        std::fs::write(&request, b"capture\n").unwrap();
        assert!(read_request(&request).is_err());
    }
}
