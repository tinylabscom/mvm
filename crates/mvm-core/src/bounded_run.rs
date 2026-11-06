//! Run a prepared command with a wall-clock bound and capped output capture.
//!
//! A host tool that hangs would otherwise hang its caller, and one that prints
//! without end would otherwise fill memory and, through its error text, the
//! log. [`run_bounded`] kills the child at the deadline, keeps at most the
//! requested bytes of each stream while still draining the rest so the child
//! never blocks on a full pipe, and [`excerpt`] turns captured bytes into text
//! that is safe to put in an error.

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How long a command may run and how much of each stream is kept.
#[derive(Debug, Clone, Copy)]
pub struct RunBounds {
    /// Wall-clock limit; the child is killed when it is exceeded.
    pub timeout: Duration,
    /// Bytes of stdout kept.
    pub max_stdout: usize,
    /// Bytes of stderr kept.
    pub max_stderr: usize,
}

impl RunBounds {
    /// `timeout`, keeping `cap` bytes of each stream.
    #[must_use]
    pub const fn new(timeout: Duration, cap: usize) -> Self {
        Self {
            timeout,
            max_stdout: cap,
            max_stderr: cap,
        }
    }
}

/// What a bounded command produced. Streams are cut at the bounds.
#[derive(Debug)]
pub struct BoundedOutput {
    /// Exit status.
    pub status: ExitStatus,
    /// At most `max_stdout` bytes of stdout.
    pub stdout: Vec<u8>,
    /// At most `max_stderr` bytes of stderr.
    pub stderr: Vec<u8>,
}

/// Why a bounded run produced no output.
#[derive(Debug)]
pub enum BoundedRunError {
    /// The program could not be started.
    Spawn(std::io::Error),
    /// The child outlived the wall-clock bound and was killed.
    TimedOut(Duration),
    /// Waiting for the child failed.
    Wait(std::io::Error),
}

impl std::fmt::Display for BoundedRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start: {e}"),
            Self::TimedOut(after) => write!(f, "did not finish within {}s", after.as_secs()),
            Self::Wait(e) => write!(f, "waiting failed: {e}"),
        }
    }
}

impl std::error::Error for BoundedRunError {}

fn capped_reader<R: Read + Send + 'static>(
    mut pipe: R,
    limit: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let _ = (&mut pipe).take(limit as u64).read_to_end(&mut kept);
        // Keep draining so a chatty child is never blocked on a full pipe.
        let _ = std::io::copy(&mut pipe, &mut std::io::sink());
        kept
    })
}

/// Run `cmd` with null stdin and piped, capped output.
///
/// # Errors
///
/// [`BoundedRunError`] when the child cannot start, outlives the bound (it is
/// killed and reaped), or cannot be waited on.
pub fn run_bounded(mut cmd: Command, bounds: RunBounds) -> Result<BoundedOutput, BoundedRunError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(BoundedRunError::Spawn)?;
    let stdout = child
        .stdout
        .take()
        .map(|p| capped_reader(p, bounds.max_stdout));
    let stderr = child
        .stderr
        .take()
        .map(|p| capped_reader(p, bounds.max_stderr));
    let deadline = Instant::now() + bounds.timeout;
    let mut attempt = 0u32;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            // Readers are left to finish on their own: a grandchild holding
            // the pipe open must not hold this call open too.
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BoundedRunError::TimedOut(bounds.timeout));
            }
            Ok(None) => {
                std::thread::sleep(crate::poll_backoff::poll_delay(attempt));
                attempt = attempt.saturating_add(1);
            }
            Err(e) => return Err(BoundedRunError::Wait(e)),
        }
    };
    let join = |h: Option<std::thread::JoinHandle<Vec<u8>>>| {
        h.map(|h| h.join().unwrap_or_default()).unwrap_or_default()
    };
    Ok(BoundedOutput {
        status,
        stdout: join(stdout),
        stderr: join(stderr),
    })
}

/// Marker appended when [`excerpt`] cuts text.
pub const TRUNCATED_MARK: &str = "...[truncated]";

/// Captured bytes as error text: lossy UTF-8, trimmed, control characters
/// other than newline and tab replaced, cut to `max_chars` characters.
#[must_use]
pub fn excerpt(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    let mut out: String = trimmed
        .chars()
        .take(max_chars)
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect();
    if trimmed.chars().count() > max_chars {
        out.push_str(TRUNCATED_MARK);
    }
    out
}

/// Test helper: a script file that can be executed at once.
///
/// Writing a script from a threaded test process and then running it races
/// with any other thread that forks while the write handle is open, and the
/// run fails with "text file busy". A short-lived `sh` writes it instead, so
/// this process never holds a write handle to it. The file is renamed into
/// place, so replacing a script that was just run never writes to a busy
/// file.
#[cfg(all(unix, any(test, feature = "test-support")))]
pub mod test_support {
    use std::path::Path;

    /// Write `#!/bin/sh` plus `body` to `path`, mode 0755.
    ///
    /// # Panics
    ///
    /// When the file cannot be written.
    pub fn write_executable_script(path: &Path, body: &str) {
        // Absolute `sh`, and a pinned PATH inside the script: other tests in
        // the same process rewrite PATH, and these scripts must not care.
        let status = crate::env_hygiene::helper_command("/bin/sh")
            .arg("-c")
            .arg(
                r#"printf '#!/bin/sh\nPATH=/usr/bin:/bin; export PATH\n%s\n' "$1" > "$2.new" && /bin/chmod 755 "$2.new" && /bin/mv -f "$2.new" "$2""#,
            )
            .arg("sh")
            .arg(body)
            .arg(path)
            .status()
            .expect("run sh to write a test script");
        assert!(status.success(), "could not write {}", path.display());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::test_support::write_executable_script;
    use super::*;

    fn script(dir: &tempfile::TempDir, body: &str) -> Command {
        let path = dir.path().join("tool.sh");
        write_executable_script(&path, body);
        crate::env_hygiene::helper_command(path)
    }

    #[test]
    fn a_normal_run_returns_exact_output_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_bounded(
            script(&dir, "printf out; printf err >&2; exit 3"),
            RunBounds::new(Duration::from_secs(10), 1024),
        )
        .unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"out");
        assert_eq!(out.stderr, b"err");
    }

    #[test]
    fn a_tool_that_outlives_the_bound_is_killed_with_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let err = run_bounded(
            script(&dir, "exec sleep 30"),
            RunBounds::new(Duration::from_millis(200), 1024),
        )
        .unwrap_err();
        assert!(matches!(err, BoundedRunError::TimedOut(_)), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn ten_megabytes_of_output_is_kept_only_up_to_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let out = run_bounded(
            script(
                &dir,
                "head -c 10485760 /dev/zero | tr '\\0' x; head -c 10485760 /dev/zero | tr '\\0' y >&2",
            ),
            RunBounds::new(Duration::from_secs(30), 4096),
        )
        .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 4096);
        assert_eq!(out.stderr.len(), 4096);
    }

    #[test]
    fn an_excerpt_is_capped_and_has_no_control_characters() {
        let long = "z".repeat(10_000);
        let text = excerpt(long.as_bytes(), 200);
        assert_eq!(text.chars().count(), 200 + TRUNCATED_MARK.len());
        assert!(text.ends_with(TRUNCATED_MARK));
        assert_eq!(excerpt(b"  ok\x1b[31m red\n", 200), "ok?[31m red");
        assert_eq!(excerpt(b"short", 200), "short");
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let err = run_bounded(
            crate::env_hygiene::helper_command("/nonexistent/mvm-tool"),
            RunBounds::new(Duration::from_secs(1), 16),
        )
        .unwrap_err();
        assert!(matches!(err, BoundedRunError::Spawn(_)));
    }
}
