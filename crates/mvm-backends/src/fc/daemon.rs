//! Firecracker daemon lifecycle + the raw HTTP-over-UDS API client:
//! socket/uds path helpers, process spawn, and the PUT/PATCH call plumbing.

use anyhow::{Context, Result};
use tracing::instrument;

use mvm_vmm::host::shell::{run_in_vm_stdout, run_in_vm_visible, shell_quote};
use mvm_vmm::host::ui;

use super::{firecracker_vsock_uds_path, resolve_running_vm_dir};

/// Resolve the path to the per-VM serial console log file.
///
/// The host-side netinit-audit emitter
/// (`netinit_audit::emit_for_vm`) reads this file after the
/// agent is ready and parses the netinit Report from the
/// captured `__MVM_NETINIT_REPORT__` line. The path follows the
/// existing convention (`<vm_dir>/console.log`); a backend
/// that doesn't split console + hypervisor logs returns a
/// path that may not exist, which the caller treats as
/// "no netinit report available" rather than an error.
pub fn vm_console_log_path(vm_name: &str) -> Result<std::path::PathBuf> {
    let abs_dir = resolve_running_vm_dir(vm_name)?;
    Ok(std::path::PathBuf::from(format!("{abs_dir}/console.log")))
}

/// Start a Firecracker daemon in a per-VM directory with its own socket.
#[instrument(skip_all)]
pub fn start_vm_firecracker(abs_dir: &str, abs_socket: &str) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, true)
}

/// Start Firecracker without unlinking a mounted child vsock UDS.
pub fn start_vm_firecracker_for_snapshot(abs_dir: &str, abs_socket: &str) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, false)
}

fn start_vm_firecracker_inner(abs_dir: &str, abs_socket: &str, clean_vsock: bool) -> Result<()> {
    ui::info("Starting Firecracker...");
    let vsock = firecracker_vsock_uds_path(abs_dir);
    let vsock_cleanup = if clean_vsock {
        format!("rm -f {vsock} {abs_dir}/v.sock")
    } else {
        String::new()
    };
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
        {vsock_cleanup}
        touch {dir}/console.log {dir}/firecracker.log
        sudo bash -c 'nohup setsid firecracker --api-sock {socket} --enable-pci \
            </dev/null >{dir}/console.log 2>{dir}/firecracker.log &
            echo $! > {dir}/fc.pid'
        "#,
        socket = abs_socket,
        dir = abs_dir,
        vsock_cleanup = vsock_cleanup,
    ))?;

    // The socket wait used to live in the heredoc above as
    // `for i in $(seq 1 30); do [ -S sock ] && break; sleep 0.1; done`, which
    // put a 100 ms floor under every launch — the socket normally appears in
    // single-digit milliseconds and was rounded up to the tick. Waiting here
    // lets it use the shared backoff, and keeps the shell to the one thing it
    // is needed for: becoming root to exec Firecracker.
    wait_for_api_socket(std::path::Path::new(abs_socket), API_SOCKET_TIMEOUT)?;
    ui::info("Firecracker started.");
    Ok(())
}

/// How long to wait for Firecracker to create its API socket. The shell loop
/// this replaced allowed 30 x 100 ms, so keeping 3 s means a host slow enough
/// to need the old ceiling still boots.
const API_SOCKET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Wait for Firecracker to create its API socket, backing off rather than
/// ticking.
///
/// Takes the path and the timeout so the expiry branch is testable without
/// spawning a VMM. A wait that never fires is the failure mode worth pinning,
/// and it is unreachable through the launch path.
fn wait_for_api_socket(socket: &std::path::Path, timeout: std::time::Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut attempt = 0u32;
    loop {
        if is_unix_socket(socket) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Firecracker API socket {} did not appear within {timeout:?}",
                socket.display()
            );
        }
        std::thread::sleep(mvm_core::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
}

/// Whether `path` is a unix socket — what `[ -S ]` tested. A regular file left
/// at the path is not the API socket appearing.
fn is_unix_socket(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.file_type().is_socket())
}

/// Send an API PUT to a specific Firecracker socket.
///
/// The body no longer traverses a shell at all: it is framed by
/// `Content-Length` on a socket this process owns, so the quoting fragility
/// the old `curl --data` shape had to defend against does not arise.
#[instrument(skip_all, fields(path))]
pub fn api_put_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    fc_api_call("PUT", socket, path, Some(data))
}

/// Hand the Firecracker-created vsock multiplexer socket to the mvmctl user.
///
/// Firecracker runs as root and consequently creates this socket as root. Only
/// the invoking user needs to dial it, so transfer ownership and keep the mode
/// private instead of making the control plane world-writable.
pub fn secure_vsock_socket_for_caller(vsock: &str) -> Result<()> {
    let quoted = shell_quote(vsock);
    run_in_vm_visible(&format!(
        "set -eu\nsudo chown -- \"$(id -u):$(id -g)\" {quoted}\nchmod 0600 {quoted}"
    ))
}

/// Shared body for FC's PUT/PATCH calls.
///
/// Delegates to [`crate::fc::fc_api::call`], the native HTTP-over-UDS client
/// this crate already carries for the warm-restore path. That client exists
/// precisely because each call used to be a `curl` subprocess, and it already
/// encodes the one thing that is easy to get wrong here: Firecracker answers
/// `Connection: keep-alive` and holds the socket open regardless of what the
/// request asked for, so the body must be framed by `Content-Length` and never
/// by EOF. The boot path was the last caller still shelling out.
///
/// Reaching the socket without `sudo` is what [`adopt_api_socket`] arranges.
fn fc_api_call(method: &str, socket: &str, path: &str, data: Option<&str>) -> Result<()> {
    // The request target is built by this crate, never by a caller, but it is
    // interpolated into a request line: reject anything that could terminate
    // it. A drive id that ever became externally influenced must not be able
    // to smuggle a second request.
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        anyhow::bail!("refusing malformed Firecracker API path {path:?}");
    }
    crate::fc::fc_api::call(std::path::Path::new(socket), method, path, data).map(|_body| ())
}

/// Hand the Firecracker-created API socket to the invoking user.
///
/// Firecracker is launched through `sudo`, so it creates its API socket as
/// root and nothing but root can dial it — which is why every API call used to
/// be a `sudo curl`. Transferring ownership once, at mode 0600, lets the rest
/// of the boot speak to the socket in-process.
///
/// This is the same trade [`secure_vsock_socket_for_caller`] already makes for
/// the vsock multiplexer, and the principal is unchanged: the user running
/// mvmctl already drives this VM, via `sudo`, on every call. What changes is
/// that they no longer need `sudo` to do it, so a process running as that user
/// can reach the API socket directly. Mode 0600 keeps it off-limits to every
/// other user on the host.
pub fn adopt_api_socket(socket: &str) -> Result<()> {
    let quoted = shell_quote(socket);
    run_in_vm_visible(&format!(
        "set -eu\nsudo chown -- \"$(id -u):$(id -g)\" {quoted}\nchmod 0600 {quoted}"
    ))
}

/// Read the pid recorded by [`start_vm_firecracker`].
pub fn read_firecracker_pid(abs_dir: &str) -> Result<u32> {
    let q_dir = shell_quote(abs_dir);
    let output = run_in_vm_stdout(&format!("cat {q_dir}/fc.pid"))?;
    output
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parse Firecracker pid from {abs_dir}/fc.pid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot that reaches the deadline with no socket must fail with a
    /// message naming the path, not hang. The shell loop this replaced had the
    /// same ceiling; the wait is unreachable from a unit test through the
    /// launch path, which is why the timeout is a parameter.
    #[test]
    fn waiting_for_an_api_socket_that_never_appears_fails_with_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("fc.socket");
        let err = wait_for_api_socket(&missing, std::time::Duration::from_millis(30))
            .expect_err("a socket that never appears must not succeed");
        let rendered = err.to_string();
        assert!(
            rendered.contains("fc.socket"),
            "unexpected error: {rendered}"
        );
    }

    /// `[ -S ]`, which is what the shell tested: a regular file sitting at the
    /// socket path is not Firecracker having come up.
    #[test]
    fn a_regular_file_at_the_socket_path_is_not_the_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let decoy = dir.path().join("fc.socket");
        std::fs::write(&decoy, b"not a socket").expect("write decoy");
        assert!(!is_unix_socket(&decoy));

        let listener_path = dir.path().join("real.socket");
        let _listener =
            std::os::unix::net::UnixListener::bind(&listener_path).expect("bind unix socket");
        assert!(is_unix_socket(&listener_path));
        // And the wait returns immediately for one that is already there.
        wait_for_api_socket(&listener_path, std::time::Duration::from_millis(5))
            .expect("an existing socket is observed on the first probe");
    }

    /// The request target is interpolated into a request line. Nothing builds
    /// one from user input today, but a path carrying CRLF would append a
    /// second request to the same connection, so it is refused before connect
    /// rather than trusted because of where it came from.
    #[test]
    fn an_api_path_that_could_split_the_request_is_refused() {
        for bad in [
            "/drives/a\r\nPUT /actions HTTP/1.1",
            "/drives/a\nPUT /actions HTTP/1.1",
            "drives/no-leading-slash",
        ] {
            let err = fc_api_call("PUT", "/nonexistent.socket", bad, Some("{}"))
                .expect_err("malformed path must be refused");
            assert!(
                err.to_string().contains("malformed"),
                "expected a refusal for {bad:?}, got: {err}"
            );
        }
    }

    #[test]
    fn vsock_socket_access_is_private_to_the_invoking_user() {
        use mvm_vmm::host::shell::mock as shell_mock;
        use std::sync::{Arc, Mutex};

        let scripts = Arc::new(Mutex::new(Vec::new()));
        let captured = scripts.clone();
        let _guard = shell_mock::install_handler(move |script| {
            captured.lock().unwrap().push(script.to_string());
            shell_mock::MockResponse::empty()
        });

        secure_vsock_socket_for_caller("/tmp/vm with quote'/runtime/v.sock")
            .expect("secure socket");

        let scripts = scripts.lock().unwrap();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("sudo chown -- \"$(id -u):$(id -g)\""));
        assert!(scripts[0].contains("chmod 0600"));
        assert!(scripts[0].contains("'/tmp/vm with quote'\\''/runtime/v.sock'"));
        assert!(!scripts[0].contains("chmod 0666"));
    }
}
