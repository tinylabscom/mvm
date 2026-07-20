//! Test fixture for `entrypoint::execute`.
//!
//! Stands in for the production wrapper binaries (e.g. `python-runner`)
//! when exercising the per-call lifecycle — spawn, drain, poll, kill.
//! Compiled as an ELF binary so the `/proc/self/fd/<n>` `argv[0]` that
//! `spawn_path` synthesizes on Linux loads directly without re-opening
//! the path by name; a `#!/bin/sh` script would fail in that flow once
//! the validation-held fd's `FD_CLOEXEC` had closed the fd before the
//! interpreter reopened the path.
//!
//! Behavior is encoded in a stdin header so that `execute`'s
//! `env_clear()` and no-argv invocation shape match the production
//! contract one-for-one. The first bytes of stdin contain directive
//! lines terminated by a blank line; the remaining bytes (after the
//! header terminator) are available to the `CAT_STDIN` directive.
//!
//! Directive grammar (one per line, processed in order):
//!
//! - `STDOUT TEXT`        — write `TEXT\n` to stdout
//! - `STDERR TEXT`        — write `TEXT\n` to stderr
//! - `ENV NAME`           — write `NAME=<value>\n` (or `NAME=<unset>\n`) to stdout
//! - `CAT_STDIN`          — copy remaining stdin to stdout, no newline
//! - `FD3_HEX HEX`        — hex-decode HEX, write raw bytes to fd 3
//! - `SLEEP_MS N`         — sleep N milliseconds
//! - `UNBOUNDED_STDOUT`   — write `b'A'` blocks to stdout until killed
//! - `EXIT N`             — exit with code N; terminates the block
//!
//! Lives under `tests/bin/` with `test = false`, mirroring `fake-runner`.
//! It is never selected by the production guest closure.

use std::io::{self, Read, Write};
use std::time::Duration;

fn main() {
    let mut stdin_bytes = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut stdin_bytes) {
        eprintln!("entrypoint-test-wrapper: read stdin: {e}");
        std::process::exit(101);
    }

    let (header, rest) = split_header(&stdin_bytes);
    let header = std::str::from_utf8(header).unwrap_or_else(|e| {
        eprintln!("entrypoint-test-wrapper: header not utf-8: {e}");
        std::process::exit(102);
    });

    let mut stdin_remainder: &[u8] = rest;
    for line in header.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (cmd, arg) = match line.split_once(' ') {
            Some((c, a)) => (c, a),
            None => (line, ""),
        };
        match cmd {
            "STDOUT" => {
                let mut out = io::stdout().lock();
                writeln!(out, "{arg}").unwrap();
                out.flush().unwrap();
            }
            "STDERR" => {
                let mut err = io::stderr().lock();
                writeln!(err, "{arg}").unwrap();
                err.flush().unwrap();
            }
            "ENV" => {
                let mut out = io::stdout().lock();
                match std::env::var(arg) {
                    Ok(v) => writeln!(out, "{arg}={v}").unwrap(),
                    Err(_) => writeln!(out, "{arg}=<unset>").unwrap(),
                }
                out.flush().unwrap();
            }
            "CAT_STDIN" => {
                let mut out = io::stdout().lock();
                out.write_all(stdin_remainder).unwrap();
                out.flush().unwrap();
                stdin_remainder = &[];
            }
            "FD3_HEX" => {
                let bytes = hex_decode(arg);
                write_fd3(&bytes);
            }
            "SLEEP_MS" => {
                let ms: u64 = arg.parse().unwrap_or_else(|_| {
                    eprintln!("entrypoint-test-wrapper: bad SLEEP_MS arg {arg:?}");
                    std::process::exit(103);
                });
                std::thread::sleep(Duration::from_millis(ms));
            }
            "UNBOUNDED_STDOUT" => unbounded_stdout(),
            "EXIT" => {
                let code: i32 = arg.parse().unwrap_or_else(|_| {
                    eprintln!("entrypoint-test-wrapper: bad EXIT arg {arg:?}");
                    std::process::exit(104);
                });
                std::process::exit(code);
            }
            other => {
                eprintln!("entrypoint-test-wrapper: unknown directive {other:?}");
                std::process::exit(105);
            }
        }
    }
}

/// Split the stdin bytes into the directive header and the remainder.
/// The header ends at the first `\n\n` (or `\r\n\r\n`); if no
/// terminator is present, the entire buffer is treated as header.
fn split_header(buf: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = find_subslice(buf, b"\n\n") {
        (&buf[..i], &buf[i + 2..])
    } else if let Some(i) = find_subslice(buf, b"\r\n\r\n") {
        (&buf[..i], &buf[i + 4..])
    } else {
        (buf, &[])
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        match (from_hex(bytes[i]), from_hex(bytes[i + 1])) {
            (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
            _ => {
                eprintln!("entrypoint-test-wrapper: bad hex byte at {i}");
                std::process::exit(106);
            }
        }
        i += 2;
    }
    out
}

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Write to fd 3 with raw `libc::write`. We deliberately avoid
/// constructing an `OwnedFd` / `File` from the raw fd to keep the
/// caller's fd open across multiple directives.
fn write_fd3(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                3,
                bytes.as_ptr().add(written) as *const _,
                bytes.len() - written,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("entrypoint-test-wrapper: write fd3: {err}");
            std::process::exit(107);
        }
        written += n as usize;
    }
}

fn unbounded_stdout() {
    let buf = [b'A'; 4096];
    let mut out = io::stdout().lock();
    loop {
        if out.write_all(&buf).is_err() {
            return;
        }
    }
}
