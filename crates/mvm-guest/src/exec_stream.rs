//! Streaming exec core (dev-shell only). Runs `sh -c <command>` and emits
//! `ExecEvent` chunks via an `emit` closure as the child produces output,
//! returning the terminal `Exit`. The wire-writing lives in the agent bin
//! (`do_exec_streaming`); this core is closure-driven so it is unit-
//! testable without a vsock `File`. Mirrors `process_rpc::spawn_drain` +
//! the `handle_proc_wait` sleep-poll loop (the in-repo streaming idiom —
//! mvm-guest has no `libc::poll` usage). Plan 159 WS-5 E.
#![cfg(feature = "dev-shell")]

use crate::vsock::ExecEvent;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Per-stream total-byte cap (1 MiB) — bounds host capture-mode memory
/// (was `MAX_EXEC_OUTPUT` in the agent bin).
pub const MAX_EXEC_OUTPUT: usize = 1024 * 1024;
const DRAIN_BUF: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn spawn_drain<R: Read + Send + 'static>(
    mut reader: R,
    buf: Arc<Mutex<Vec<u8>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; DRAIN_BUF];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf
                    .lock()
                    .expect("exec drain buf")
                    .extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
    })
}

/// Emit newly-buffered bytes (past `*sent`) as one chunk, capped at
/// `MAX_EXEC_OUTPUT` total per stream. Returns true if the cap was hit
/// (caller should stop and truncate).
fn drain_into<F: FnMut(ExecEvent)>(
    buf: &Arc<Mutex<Vec<u8>>>,
    sent: &mut usize,
    stdout: bool,
    emit: &mut F,
) -> bool {
    let b = buf.lock().expect("exec drain buf");
    if b.len() <= *sent {
        return false;
    }
    let room = MAX_EXEC_OUTPUT.saturating_sub(*sent);
    if room == 0 {
        return true;
    }
    let new = &b[*sent..];
    let take = new.len().min(room);
    let chunk = new[..take].to_vec();
    emit(if stdout {
        ExecEvent::Stdout { chunk }
    } else {
        ExecEvent::Stderr { chunk }
    });
    *sent += take;
    take < new.len()
}

/// Run `command` under `/bin/sh -c`, streaming stdout/stderr via `emit`
/// (arrival order, ~poll-interval granularity), and return the terminal
/// `ExecEvent::Exit`. `emit` is never called with `Exit` — that is the
/// return value.
pub fn stream_exec<F: FnMut(ExecEvent)>(
    command: &str,
    stdin_data: Option<&str>,
    mut emit: F,
) -> ExecEvent {
    let mut child = match Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            emit(ExecEvent::Stderr {
                chunk: format!("failed to spawn: {e}").into_bytes(),
            });
            return ExecEvent::Exit { code: -1 };
        }
    };

    if let Some(data) = stdin_data
        && let Some(ref mut pipe) = child.stdin
        && let Err(e) = pipe.write_all(data.as_bytes())
    {
        eprintln!("failed to write exec stdin pipe: {e}");
    }
    drop(child.stdin.take());

    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    let mut out_handle = child.stdout.take().map(|o| spawn_drain(o, out_buf.clone()));
    let mut err_handle = child.stderr.take().map(|e| spawn_drain(e, err_buf.clone()));

    let mut sent_out = 0usize;
    let mut sent_err = 0usize;

    loop {
        let capped = drain_into(&out_buf, &mut sent_out, true, &mut emit)
            | drain_into(&err_buf, &mut sent_err, false, &mut emit);
        if capped {
            let _ = child.kill();
            let _ = child.wait();
            emit(ExecEvent::Stderr {
                chunk: b"\n... (truncated)".to_vec(),
            });
            return ExecEvent::Exit { code: -1 };
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Child exited: join the drain threads so every buffered
                // byte has been appended (a happens-before edge — the
                // thread only returns after its final append), then flush
                // the tail. Avoids the timing race a bare sleep would have.
                if let Some(h) = out_handle.take() {
                    let _ = h.join();
                }
                if let Some(h) = err_handle.take() {
                    let _ = h.join();
                }
                let _ = drain_into(&out_buf, &mut sent_out, true, &mut emit);
                let _ = drain_into(&err_buf, &mut sent_err, false, &mut emit);
                return ExecEvent::Exit {
                    code: status.code().unwrap_or(-1),
                };
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(e) => {
                emit(ExecEvent::Stderr {
                    chunk: format!("wait failed: {e}").into_bytes(),
                });
                return ExecEvent::Exit { code: -1 };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_stdout_then_exit_zero() {
        let mut events = Vec::new();
        let term = stream_exec("printf hello", None, |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 0 }));
        let out: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stdout { chunk } => Some(chunk.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn captures_stderr_and_nonzero_exit() {
        let mut events = Vec::new();
        let term = stream_exec("printf oops 1>&2; exit 3", None, |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 3 }));
        let err: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stderr { chunk } => Some(chunk.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(err, b"oops");
    }

    #[test]
    fn pipes_stdin() {
        let mut events = Vec::new();
        let term = stream_exec("cat", Some("piped"), |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 0 }));
        let out: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stdout { chunk } => Some(chunk.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(out, b"piped");
    }

    #[test]
    fn large_final_write_is_not_truncated() {
        // Emit ~256 KiB right before exit; the joined drain must capture all of it.
        // head -c 262144 /dev/zero is standard on macOS + Linux (POSIX).
        // 262144 < MAX_EXEC_OUTPUT (1 MiB) so the cap is not hit.
        let mut events = Vec::new();
        let term = stream_exec("head -c 262144 /dev/zero", None, |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 0 }));
        let total: usize = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stdout { chunk } => Some(chunk.len()),
                _ => None,
            })
            .sum();
        assert_eq!(
            total, 262144,
            "all 256 KiB of stdout must be streamed, none lost"
        );
    }
}
