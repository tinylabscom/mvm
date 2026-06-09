//! Plan 97 Phase E — Rust client for the `mvm-vz-supervisor`
//! control socket.
//!
//! The supervisor binds a `SOCK_STREAM` unix socket at
//! `<vm_state_dir>/control.sock` mode 0700 and accepts newline-framed
//! text commands (the verb list + response shape live in the
//! Rust-native supervisor's control socket in `mvm-vm-host`). This
//! module wraps the dial +
//! send + readline + parse cycle into a small synchronous client
//! `VzBackend` uses for `pause` / `resume` / `balloon_set_target` and
//! the snapshot verbs.
//!
//! Single short-lived connection per command; no connection pool.
//! Commands all run on the supervisor's main dispatch queue (the same
//! one Vz requires), so multi-connection concurrency adds nothing
//! while complicating cleanup. Set
//! `MVM_VZ_CONTROL_TIMEOUT_MS` to override the default 2 s I/O
//! timeout.

use anyhow::{Result, anyhow, bail};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-VM control socket location. Plan 97 Phase E — the supervisor
/// binds this path when `control_socket_path` is set in its
/// `SupervisorConfig`.
pub fn control_socket_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join("control.sock")
}

/// Open a connection to the supervisor and exchange one verb. Returns
/// the supervisor's response **without** the trailing newline.
///
/// Errors when the socket file is missing, the connect fails, or the
/// supervisor's response starts with `ERR`. The caller is responsible
/// for mapping `ERR <message>` to a richer typed error if needed.
pub fn send_command(socket_path: &Path, command: &str) -> Result<String> {
    if command.contains('\n') {
        bail!("control command must not contain a newline: {command:?}");
    }
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| anyhow!("connect {}: {e}", socket_path.display()))?;
    stream
        .set_read_timeout(Some(timeout()))
        .map_err(|e| anyhow!("set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(timeout()))
        .map_err(|e| anyhow!("set_write_timeout: {e}"))?;

    let mut payload = command.as_bytes().to_vec();
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .map_err(|e| anyhow!("write command {command:?}: {e}"))?;

    // Read up to the first newline (one response per command). We
    // can't use `BufReader::read_line` directly without holding the
    // stream; do it by hand so a future client-pool wrapper can use
    // the same primitive.
    let mut response = Vec::with_capacity(64);
    let mut buf = [0u8; 1];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|e| anyhow!("read response: {e}"))?;
        if n == 0 {
            // EOF before newline — supervisor closed the connection.
            break;
        }
        if buf[0] == b'\n' {
            break;
        }
        response.push(buf[0]);
    }
    let line = String::from_utf8(response).map_err(|e| anyhow!("response was not UTF-8: {e}"))?;

    if let Some(rest) = line.strip_prefix("ERR") {
        let message = rest.trim_start();
        bail!("supervisor refused {command:?}: {message}");
    }
    Ok(line.strip_prefix("OK").unwrap_or(&line).trim().to_string())
}

fn timeout() -> Duration {
    if let Ok(ms) = std::env::var("MVM_VZ_CONTROL_TIMEOUT_MS")
        && let Ok(parsed) = ms.parse::<u64>()
    {
        return Duration::from_millis(parsed);
    }
    DEFAULT_TIMEOUT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Spawn a one-shot fake supervisor on `path` that accepts a single
    /// connection, reads one line, and replies `response\n`.
    fn fake_supervisor(path: PathBuf, response: String) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(&path).expect("bind fake supervisor");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf); // drain the command
                let mut payload = response.into_bytes();
                payload.push(b'\n');
                let _ = stream.write_all(&payload);
            }
        })
    }

    fn tmp_socket_path() -> PathBuf {
        // tempfile gives us a unique path; the file won't exist (we'll
        // bind to it). Drop guard removes the dir at end.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("control.sock");
        // Leak the tempdir so the path stays valid through the test;
        // bind() will create the socket file under it.
        std::mem::forget(dir);
        path
    }

    #[test]
    fn ok_response_strips_prefix_and_whitespace() {
        let path = tmp_socket_path();
        let h = fake_supervisor(path.clone(), "OK running".to_string());
        let r = send_command(&path, "STATUS").expect("status ok");
        assert_eq!(r, "running");
        h.join().unwrap();
    }

    #[test]
    fn bare_ok_returns_empty_string() {
        let path = tmp_socket_path();
        let h = fake_supervisor(path.clone(), "OK".to_string());
        let r = send_command(&path, "PAUSE").expect("pause ok");
        assert_eq!(r, "");
        h.join().unwrap();
    }

    #[test]
    fn err_response_propagates_message() {
        let path = tmp_socket_path();
        let h = fake_supervisor(
            path.clone(),
            "ERR no traditional memory balloon device attached".to_string(),
        );
        let err = send_command(&path, "BALLOON 128").expect_err("err propagates");
        assert!(
            err.to_string().contains("no traditional memory balloon"),
            "error explains why: {err}"
        );
        h.join().unwrap();
    }

    #[test]
    fn newline_in_command_is_rejected_before_connect() {
        // Even with no supervisor running, embedded \n should error
        // before the socket dial.
        let err = send_command(Path::new("/nonexistent.sock"), "PAUSE\nRESUME")
            .expect_err("newline injection refused");
        assert!(err.to_string().contains("must not contain a newline"));
    }

    #[test]
    fn connect_missing_socket_surfaces_path() {
        let err = send_command(Path::new("/nonexistent/control.sock"), "STATUS")
            .expect_err("missing socket errors");
        assert!(
            err.to_string().contains("/nonexistent/control.sock"),
            "error includes the path: {err}"
        );
    }
}
