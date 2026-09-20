//! Firecracker daemon lifecycle + the raw HTTP-over-UDS API client:
//! socket/uds path helpers, process spawn, and the PUT/PATCH call plumbing.

use anyhow::{Context, Result};
use tracing::instrument;

use mvm_vmm::host::shell::{run_in_vm_visible, shell_quote};
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
    start_vm_firecracker_inner(abs_dir, abs_socket, true, "")
}

/// Start a Firecracker daemon inside a scope carrying its guest's memory and
/// task ceilings and the CPU share this launch was admitted under.
///
/// Separate from [`start_vm_firecracker`] rather than a wider signature on it:
/// the unbounded entry point exists for harnesses that boot no admitted guest
/// at all, and keeping the bounds off its signature is what stops one of them
/// from inventing a bound no run was admitted under. A snapshot load reaches the
/// same scope through [`start_vm_firecracker_scoped`].
#[instrument(skip_all)]
pub fn start_vm_firecracker_bounded(
    abs_dir: &str,
    abs_socket: &str,
    machine_id: &str,
    bounds: &mvm_core::spawn_scope::SpawnBounds,
) -> Result<()> {
    let prefix = spawn_scope_prefix(machine_id, std::path::Path::new(abs_dir), bounds);
    start_vm_firecracker_inner(abs_dir, abs_socket, true, &prefix)
}

/// Start Firecracker for a snapshot load, inside a scope prefix the caller has
/// already built.
///
/// The restore paths take the prefix rather than the bounds because the value
/// that ends up on the launch line has to be the one a test can read back: an
/// unwrapped Firecracker loads the snapshot and runs the restored guest exactly
/// as well, and is simply unbounded. `clean_vsock` is false for a fork, whose
/// private mount namespace has already put the child's vsock UDS in place.
pub(crate) fn start_vm_firecracker_scoped(
    abs_dir: &str,
    abs_socket: &str,
    clean_vsock: bool,
    scope: &str,
) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, clean_vsock, scope)
}

/// The `systemd-run` scope prefix for the launch line, shell-quoted, or empty
/// when nothing is to be bound.
///
/// Firecracker is the one per-VM process this repo starts through a shell
/// rather than a `Command` — it is `sudo`-elevated and detaches itself with
/// `nohup setsid` — so it needs the prefix as text. The tokens come from the
/// same builder the `Command` path uses, so the two cannot drift into bounding
/// different things.
pub(crate) fn spawn_scope_prefix(
    machine_id: &str,
    state_dir: &std::path::Path,
    bounds: &mvm_core::spawn_scope::SpawnBounds,
) -> String {
    match mvm_core::spawn_scope::scope_prefix_for_spawn(machine_id, state_dir, bounds) {
        Some(tokens) => {
            let quoted: Vec<String> = tokens.iter().map(|t| shell_quote(t)).collect();
            format!("{} ", quoted.join(" "))
        }
        None => String::new(),
    }
}

/// The file the launch script records a scoped launcher's pid in, so the
/// launch can fail if the service manager never creates the scope.
const SCOPE_LAUNCHER_PID_FILE: &str = "scope-launcher.pid";

fn start_vm_firecracker_inner(
    abs_dir: &str,
    abs_socket: &str,
    clean_vsock: bool,
    scope: &str,
) -> Result<()> {
    ensure_api_socket_fits(abs_socket)?;
    ui::info("Starting Firecracker...");
    run_in_vm_visible(&firecracker_launch_script(
        abs_dir,
        abs_socket,
        clean_vsock,
        scope,
    ))?;
    if !scope.is_empty() {
        let dir = std::path::Path::new(abs_dir);
        let machine = dir
            .file_name()
            .map_or_else(|| abs_dir.to_string(), |n| n.to_string_lossy().into_owned());
        mvm_core::spawn_scope::await_detached_launcher(
            &dir.join(SCOPE_LAUNCHER_PID_FILE),
            &machine,
        )?;
    }

    // The socket wait used to live in the launch script as
    // `for i in $(seq 1 30); do [ -S sock ] && break; sleep 0.1; done`, which
    // put a 100 ms floor under every launch — the socket normally appears in
    // single-digit milliseconds and was rounded up to the tick. Waiting here
    // lets it use the shared backoff, and keeps the shell to the one thing it
    // is needed for: becoming root to exec Firecracker.
    wait_for_api_socket(std::path::Path::new(abs_socket), API_SOCKET_TIMEOUT).map_err(|e| {
        with_firecracker_stderr(
            e,
            &std::path::Path::new(abs_dir).join(FIRECRACKER_STDERR_LOG),
        )
    })?;
    ui::info("Firecracker started.");
    Ok(())
}

/// Where the launch script sends Firecracker's stderr, relative to the VM dir.
const FIRECRACKER_STDERR_LOG: &str = "firecracker.log";

/// How much of that log a startup failure quotes. Firecracker reports a
/// refused start in its last few lines; the whole file is left on disk.
const STDERR_TAIL_LINES: usize = 20;

/// Refuse an API socket path the kernel would refuse, before starting a
/// process that can only exit.
///
/// Firecracker reports this itself — "path must be shorter than SUN_LEN" — but
/// only in its own log, after which the host sees nothing but a socket that
/// never appears.
fn ensure_api_socket_fits(abs_socket: &str) -> Result<()> {
    if !mvm_core::config::fits_unix_socket_path(std::path::Path::new(abs_socket)) {
        anyhow::bail!(
            "Firecracker API socket path {abs_socket} is {} bytes, longer than a Unix socket \
             can be ({} bytes); Firecracker would exit without creating it",
            abs_socket.len(),
            mvm_core::config::UNIX_SOCKET_PATH_MAX_BYTES
        );
    }
    Ok(())
}

/// Attach what Firecracker wrote to stderr to a startup failure.
///
/// A Firecracker that refuses to start exits within milliseconds and says why
/// only in this log. Quoting it here is what turns "the socket did not appear"
/// into the actual reason, on hosts where nobody can read the file afterwards.
fn with_firecracker_stderr(err: anyhow::Error, log: &std::path::Path) -> anyhow::Error {
    match std::fs::read_to_string(log) {
        Ok(text) if !text.trim().is_empty() => {
            let lines: Vec<&str> = text.lines().collect();
            let tail = lines[lines.len().saturating_sub(STDERR_TAIL_LINES)..].join("\n");
            err.context(format!("Firecracker stderr ({}):\n{tail}", log.display()))
        }
        _ => err.context(format!(
            "Firecracker wrote nothing to {} before the deadline",
            log.display()
        )),
    }
}

/// The launch script, built rather than run.
///
/// Pure so a test can read back whether the CPU scope actually reached the
/// launch line. An unwrapped Firecracker boots identically and is simply not
/// bounded, which is precisely the failure that needs a test rather than an
/// inspection.
///
/// Privilege justification: Firecracker is launched through `sudo` because, on
/// the reference builder-VM host, the invoking user does not have direct access
/// to `/dev/kvm` and the TAP/vsock network plumbing it configures.
///
/// The pid marker is written by the launched process itself (`echo $$`) and not
/// by the caller (`echo $!`), because `$!` does not reliably name Firecracker.
/// `sudo` with `use_pty` — the default since sudo 1.9.14, which is what Ubuntu
/// 24.04 ships — forks a monitor and runs the command as its child rather than
/// exec'ing it, so `$!` names a process whose `comm` is `sudo`. Liveness is
/// probed by comparing `/proc/<pid>/comm` against `firecracker`, so on such a
/// host every boot read as "the VMM exited" on the first poll while the guest
/// was in fact booting normally. Writing `$$` from inside is correct whichever
/// of `sudo`/`setsid` forks, since the `exec` makes that same pid Firecracker.
/// The `sh -c` costs no surviving process for the same reason.
/// The `sudo ` prefix a launch needs, or empty when the caller is already root.
///
/// `sudo` is on this path because the invoking user usually cannot open
/// `/dev/kvm`. When mvmctl already runs as root it buys nothing and costs a
/// process exec — measured at ~7 ms on the reference builder host, twice per
/// launch, against a dispatch budget in the low hundreds.
///
/// Pure over the effective uid so the decision is testable without running the
/// suite as root, which is the only way this branch could otherwise be covered.
pub(crate) fn sudo_prefix_for_euid(euid: u32) -> &'static str {
    if euid == 0 { "" } else { "sudo " }
}

fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` takes no arguments, dereferences no pointers, and
    // always returns the effective uid of the calling process.
    unsafe { libc::geteuid() }
}

fn firecracker_launch_script(
    abs_dir: &str,
    abs_socket: &str,
    clean_vsock: bool,
    scope: &str,
) -> String {
    firecracker_launch_script_as(abs_dir, abs_socket, clean_vsock, scope, effective_user_id())
}

fn firecracker_launch_script_as(
    abs_dir: &str,
    abs_socket: &str,
    clean_vsock: bool,
    scope: &str,
    euid: u32,
) -> String {
    let sudo = sudo_prefix_for_euid(euid);
    let vsock = firecracker_vsock_uds_path(abs_dir);
    let vsock_cleanup = if clean_vsock {
        format!(
            "rm -f {} {}",
            shell_quote(&vsock),
            shell_quote(&format!("{abs_dir}/v.sock"))
        )
    } else {
        String::new()
    };
    let q_dir = shell_quote(abs_dir);
    let q_socket = shell_quote(abs_socket);
    // The API socket's directory is the VM dir unless the socket was moved to
    // the short fallback namespace, which nothing else creates.
    let q_socket_dir = shell_quote(
        &std::path::Path::new(abs_socket)
            .parent()
            .map_or_else(|| abs_dir.to_string(), |p| p.display().to_string()),
    );
    let q_pid = shell_quote(&format!("{abs_dir}/fc.pid"));
    // `$!` is the scope launcher itself, recorded so the caller can tell a
    // scope that was created from a service manager that never answered. It is
    // never used as Firecracker's pid; that marker is written from inside.
    let record_launcher = if scope.is_empty() {
        String::new()
    } else {
        format!(
            "echo $! > {}",
            shell_quote(&format!("{abs_dir}/{SCOPE_LAUNCHER_PID_FILE}"))
        )
    };
    format!(
        r#"
        mkdir -p {q_dir} {q_socket_dir}
        {sudo}rm -f {q_socket}
        {vsock_cleanup}
        touch {q_dir}/console.log {q_dir}/firecracker.log
        {scope}{sudo}setsid nohup sh -c 'echo $$ > "$0"; exec firecracker --api-sock "$1" --enable-pci' {q_pid} {q_socket} \
            </dev/null >{q_dir}/console.log 2>{q_dir}/firecracker.log &
        {record_launcher}
        "#,
        q_dir = q_dir,
        q_pid = q_pid,
        q_socket = q_socket,
        q_socket_dir = q_socket_dir,
        vsock_cleanup = vsock_cleanup,
        scope = scope,
        sudo = sudo,
        record_launcher = record_launcher,
    )
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
    secure_socket_for_caller_as(vsock, effective_user_id())
}

/// Restrict a Firecracker-created control socket to the invoking user.
///
/// A root caller already owns sockets created by the root Firecracker process,
/// so changing their ownership through another shell is redundant. Non-root
/// callers retain the privileged ownership transfer that makes the socket
/// reachable without widening it to other users.
fn secure_socket_for_caller_as(socket: &str, euid: u32) -> Result<()> {
    if euid == 0 {
        use std::os::unix::fs::PermissionsExt as _;

        return std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restrict Firecracker socket {socket}"));
    }

    let quoted = shell_quote(socket);
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
/// Privilege justification: `chown` is privileged and must be done once, by the
/// same `sudo` session that launched Firecracker. After this hand-off the rest
/// of the boot path (including the vsock mux socket, see
/// [`secure_vsock_socket_for_caller`]) talks to Firecracker without any further
/// elevation.
///
/// This is the same trade [`secure_vsock_socket_for_caller`] already makes for
/// the vsock multiplexer, and the principal is unchanged: the user running
/// mvmctl already drives this VM, via `sudo`, on every call. What changes is
/// that they no longer need `sudo` to do it, so a process running as that user
/// can reach the API socket directly. Mode 0600 keeps it off-limits to every
/// other user on the host.
pub fn adopt_api_socket(socket: &str) -> Result<()> {
    secure_socket_for_caller_as(socket, effective_user_id())
}

/// Read the pid recorded by [`start_vm_firecracker`].
pub fn read_firecracker_pid(abs_dir: &str) -> Result<u32> {
    let path = std::path::Path::new(abs_dir).join("fc.pid");
    let output =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    output
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parse Firecracker pid from {}", path.display()))
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

    /// The failure the hosted runners hit: Firecracker refused the socket
    /// path and exited, and the host reported only that the socket never
    /// appeared. The reason has to be in the error itself.
    #[test]
    fn a_socket_that_never_appears_quotes_what_firecracker_said() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join(FIRECRACKER_STDERR_LOG);
        std::fs::write(
            &log,
            "Error: RunWithApi(FailedToBindAndRunHttpServer(IOError(Error { kind: \
             InvalidInput, message: \"path must be shorter than SUN_LEN\" })))\n",
        )
        .expect("write log");
        let err = wait_for_api_socket(
            &dir.path().join("fc.socket"),
            std::time::Duration::from_millis(5),
        )
        .map_err(|e| with_firecracker_stderr(e, &log))
        .expect_err("no socket");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("SUN_LEN"), "{rendered}");
        assert!(rendered.contains("did not appear"), "{rendered}");
        assert!(rendered.contains(&log.display().to_string()), "{rendered}");
    }

    #[test]
    fn a_silent_firecracker_is_reported_as_silent_with_the_log_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join(FIRECRACKER_STDERR_LOG);
        let rendered = format!(
            "{:#}",
            with_firecracker_stderr(anyhow::anyhow!("socket did not appear"), &log)
        );
        assert!(rendered.contains("wrote nothing"), "{rendered}");
        assert!(rendered.contains(&log.display().to_string()), "{rendered}");
    }

    #[test]
    fn only_the_tail_of_a_long_stderr_log_is_quoted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join(FIRECRACKER_STDERR_LOG);
        let body: String = (0..100).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&log, body).expect("write log");
        let rendered = format!("{:#}", with_firecracker_stderr(anyhow::anyhow!("x"), &log));
        assert!(rendered.contains("line 99"), "{rendered}");
        assert!(!rendered.contains("line 79\n"), "{rendered}");
    }

    #[test]
    fn an_api_socket_path_the_kernel_would_refuse_is_refused_before_launch() {
        let long = format!("/{}/fc.socket", "d".repeat(120));
        let err = ensure_api_socket_fits(&long).expect_err("too long to bind");
        assert!(
            err.to_string().contains("longer than a Unix socket"),
            "{err}"
        );
        ensure_api_socket_fits("/srv/vms/w/fc.socket").expect("a short path fits");
    }

    #[test]
    fn the_launch_script_creates_a_relocated_socket_directory() {
        let script = firecracker_launch_script_as(
            "/deep/home/vms/w",
            "/tmp/mvm-sock/0123456789abcdef/fc.socket",
            true,
            "",
            0,
        );
        assert!(
            script.contains("mkdir -p '/deep/home/vms/w' '/tmp/mvm-sock/0123456789abcdef'"),
            "{script}"
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

        secure_socket_for_caller_as("/tmp/vm with quote'/runtime/v.sock", 1000)
            .expect("secure socket");

        let scripts = scripts.lock().unwrap();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("sudo chown -- \"$(id -u):$(id -g)\""));
        assert!(scripts[0].contains("chmod 0600"));
        assert!(scripts[0].contains("'/tmp/vm with quote'\\''/runtime/v.sock'"));
        assert!(!scripts[0].contains("chmod 0666"));
    }

    #[test]
    fn root_secures_a_socket_without_spawning_a_shell() {
        use mvm_vmm::host::shell::mock as shell_mock;
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("fc.socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))
            .expect("make initial mode broad");

        let scripts = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&scripts);
        let _guard = shell_mock::install_handler(move |script| {
            captured
                .lock()
                .expect("scripts lock")
                .push(script.to_string());
            shell_mock::MockResponse::empty()
        });

        secure_socket_for_caller_as(&socket.to_string_lossy(), 0).expect("secure root socket");

        assert!(scripts.lock().expect("scripts lock").is_empty());
        let mode = std::fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// Firecracker is the one per-VM process started through a shell, so its
    /// bound has to reach the launch *line* rather than a `Command`.
    #[test]
    fn a_granted_share_prefixes_the_firecracker_launch_line() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");

        let prefix = spawn_scope_prefix(
            "vm-bounded",
            scratch.path(),
            &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(512).with_cpu_grant(Some(
                mvm_contract::grants::CpuGrant::Share { millicores: 1500 },
            )),
        );
        let script =
            firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", true, &prefix, 1000);

        assert!(script.contains("CPUQuota=150%"), "{script}");
        assert!(script.contains("'MemoryMax=768M'"), "{script}");
        assert!(script.contains("'MemorySwapMax=0'"), "{script}");
        assert!(script.contains("'TasksMax=1024'"), "{script}");
        // The unit carries a per-boot suffix, so match the stem rather than a
        // name that can no longer be reconstructed from the machine id.
        assert!(script.contains("vm-bounded-"), "{script}");
        assert!(script.contains(".scope"), "{script}");
        // Ahead of the launch, not merely somewhere in the script: Firecracker
        // has to be born inside the scope.
        let scope_at = script.find("systemd-run").expect("prefix present");
        let launch_at = script
            .find("sudo setsid nohup sh -c")
            .expect("launch present");
        assert!(scope_at < launch_at, "{script}");
        // And the launcher is recorded after it is backgrounded, so a manager
        // that never creates the scope fails the launch.
        let recorded_at = script
            .find("echo $! > '/tmp/vm/scope-launcher.pid'")
            .expect("launcher pid recorded");
        assert!(launch_at < recorded_at, "{script}");
    }

    /// Memory and task ceilings are not grants, so a launch admitted with no
    /// CPU share still carries them.
    #[test]
    fn an_ungranted_launch_line_still_carries_the_ceilings() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let prefix = spawn_scope_prefix(
            "vm-ceilinged",
            scratch.path(),
            &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(2048),
        );
        assert!(prefix.contains("'MemoryMax=2304M'"), "{prefix}");
        assert!(prefix.contains("'TasksMax=1024'"), "{prefix}");
        assert!(!prefix.contains("CPUQuota"), "{prefix}");
    }

    #[test]
    fn an_unscoped_launch_line_carries_no_scope() {
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", true, "", 1000);
        assert!(!script.contains("systemd-run"), "{script}");
        assert!(!script.contains("scope-launcher.pid"), "{script}");
        assert!(script.contains("sudo setsid nohup sh -c"), "{script}");
        assert!(
            script.contains("exec firecracker"),
            "the shell must exec Firecracker, never leave one behind: {script}"
        );
    }

    /// The regression this exists for: `$!` names Firecracker only when every
    /// wrapper in the launch chain execs. `sudo` with `use_pty` (the default
    /// since 1.9.14, and what Ubuntu 24.04 ships) forks a monitor instead, so
    /// `$!` was the `sudo` pid and the `/proc/<pid>/comm == firecracker`
    /// liveness probe read every boot as an immediate VMM exit.
    #[test]
    fn the_pid_marker_is_written_by_the_launched_process_not_the_caller() {
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", true, "", 1000);

        assert!(
            !script.contains("echo $!"),
            "$! does not survive a forking sudo/setsid: {script}"
        );
        assert!(
            script.contains(r#"echo $$ > "$0""#),
            "the pid must come from the process that becomes Firecracker: {script}"
        );

        // Written before the exec, so the marker is in place by the time the
        // API socket exists and the caller starts probing liveness.
        let write_at = script.find("echo $$").expect("pid write present");
        let exec_at = script.find("exec firecracker").expect("exec present");
        assert!(write_at < exec_at, "{script}");

        // And it names the path the rest of the tree reads.
        assert!(script.contains("/tmp/vm/fc.pid"), "{script}");
    }

    #[test]
    fn a_host_without_the_mechanism_leaves_the_launch_line_untouched() {
        // No mechanism on this host: the boot proceeds unbounded rather than
        // failing, and the read-back reports it as declared.
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty = scratch.path().join("empty-path");
        std::fs::create_dir_all(&empty).expect("empty PATH");
        env.set("PATH", &empty);
        env.remove("XDG_RUNTIME_DIR");
        env.remove("DBUS_SESSION_BUS_ADDRESS");
        assert_eq!(
            spawn_scope_prefix(
                "vm-x",
                scratch.path(),
                &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(512)
            ),
            ""
        );
    }
}

#[cfg(test)]
mod sudo_elision_tests {
    use super::*;

    /// A non-root caller cannot open /dev/kvm, so the elevation must stay.
    #[test]
    fn a_non_root_launch_still_elevates() {
        assert_eq!(sudo_prefix_for_euid(1000), "sudo ");
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", true, "", 1000);
        assert!(script.contains("sudo setsid nohup sh -c"), "{script}");
        assert!(script.contains("sudo rm -f"), "{script}");
    }

    /// Already root: sudo buys no privilege and costs a process exec on a path
    /// measured in milliseconds.
    #[test]
    fn a_root_launch_skips_sudo_entirely() {
        assert_eq!(sudo_prefix_for_euid(0), "");
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", true, "", 0);
        assert!(
            !script.contains("sudo"),
            "root launch must not shell out to sudo: {script}"
        );
    }

    /// The pid marker is the part that broke before: `$!` names sudo's monitor
    /// under use_pty, so the pid is written from inside and made correct by the
    /// `exec`. That has to hold whether or not sudo is in the line.
    #[test]
    fn both_shapes_write_the_pid_from_inside_and_exec_firecracker() {
        for euid in [0, 1000] {
            let script =
                firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", true, "", euid);
            assert!(
                script.contains(r#"echo $$ > "$0""#),
                "euid {euid} must write the pid from inside: {script}"
            );
            assert!(
                script.contains("exec firecracker"),
                "euid {euid} must exec so the pid names Firecracker: {script}"
            );
            assert!(
                script.contains("setsid nohup sh -c"),
                "euid {euid}: {script}"
            );
        }
    }

    /// The spawn scope must precede the launch in both shapes.
    #[test]
    fn the_spawn_scope_precedes_the_launch_with_and_without_sudo() {
        for euid in [0, 1000] {
            let script = firecracker_launch_script_as(
                "/tmp/vm",
                "/tmp/vm/fc.socket",
                true,
                "systemd-run --scope ",
                euid,
            );
            let scope_at = script.find("systemd-run").expect("scope present");
            let launch_at = script.find("setsid nohup sh -c").expect("launch present");
            assert!(scope_at < launch_at, "euid {euid}: {script}");
        }
    }
}
