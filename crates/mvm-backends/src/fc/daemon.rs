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
    ensure_api_socket_fits(abs_socket)?;
    secure_socket_dir(abs_dir)?;
    start_vm_firecracker_inner(abs_dir, abs_socket, "", None)
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
    guard: &mut super::FirecrackerGuard,
) -> Result<()> {
    validate_required_scope(machine_id, bounds)?;
    ensure_api_socket_fits(abs_socket)?;
    secure_socket_dir(abs_dir)?;
    let prefix = spawn_scope_prefix(machine_id, std::path::Path::new(abs_dir), bounds)?;
    start_vm_firecracker_inner(abs_dir, abs_socket, &prefix, Some(guard))
}

/// Start Firecracker for a snapshot load, inside a scope prefix the caller has
/// already built.
///
/// The restore paths take the prefix rather than the bounds because the value
/// that ends up on the launch line has to be the one a test can read back: an
/// unwrapped Firecracker loads the snapshot and runs the restored guest exactly
/// as well, and is simply unbounded.
pub(crate) fn start_vm_firecracker_scoped(
    abs_dir: &str,
    abs_socket: &str,
    scope: &str,
) -> Result<()> {
    anyhow::ensure!(
        !scope.trim().is_empty(),
        "required Firecracker scope is missing"
    );
    ensure_api_socket_fits(abs_socket)?;
    secure_socket_dir(abs_dir)?;
    start_vm_firecracker_inner(abs_dir, abs_socket, scope, None)
}

/// The required legacy `systemd-run` scope prefix, or a pre-launch refusal.
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
) -> Result<String> {
    validate_required_scope(machine_id, bounds)?;
    let tokens = mvm_core::spawn_scope::scope_prefix_for_spawn(machine_id, state_dir, bounds)
        .context("required Firecracker scope could not be prepared")?;
    let quoted: Vec<String> = tokens.iter().map(|t| shell_quote(t)).collect();
    Ok(format!("{} ", quoted.join(" ")))
}

pub(crate) fn validate_required_scope(
    machine_id: &str,
    bounds: &mvm_core::spawn_scope::SpawnBounds,
) -> Result<()> {
    bounds.validate_required_inputs()?;
    mvm_core::spawn_scope::validate_scope_id(machine_id)?;
    if let Some(gap) = mvm_core::spawn_scope::mechanism_gap() {
        anyhow::bail!("required Firecracker scope unavailable: {}", gap.describe());
    }
    Ok(())
}

/// The file the launch script records a scoped launcher's pid in, so the
/// launch can fail if the service manager never creates the scope.
const SCOPE_LAUNCHER_PID_FILE: &str = "scope-launcher.pid";

/// Make the VM's socket directory ours before a root Firecracker binds in it.
///
/// A deep state directory moves the sockets to a short `/tmp` name another
/// local user can compute. The launch script `rm`s a socket there and later
/// `chown`s the one Firecracker binds, so a directory someone else created
/// would let them redirect that `chown`; refuse a directory the invoking user
/// does not own.
fn secure_socket_dir(abs_dir: &str) -> Result<()> {
    mvm_core::config::secure_fallback_socket_dir_at(std::path::Path::new(abs_dir))
        .context("securing the Firecracker socket directory")
}

fn start_vm_firecracker_inner(
    abs_dir: &str,
    abs_socket: &str,
    scope: &str,
    guard: Option<&mut super::FirecrackerGuard>,
) -> Result<()> {
    ui::info("Starting Firecracker...");
    if let Some(guard) = guard {
        guard
            .arm(abs_dir)
            .context("retiring prior Firecracker markers before launch")?;
    }
    // A process started here serves the socket its own command line names, so
    // any record that this dir's VMM came from the idle pool is now stale.
    super::idle_pool::forget_claim_origin(std::path::Path::new(abs_dir));
    run_in_vm_visible(&firecracker_launch_script(abs_dir, abs_socket, scope))?;
    await_started_firecracker(abs_dir, abs_socket, scope)?;
    // Every launch, not only a cold boot: the snapshot-restore path starts its
    // own fresh VMM through this same function and then speaks to the socket
    // in-process, and a root-created socket it had not been handed refused the
    // non-root claimer with EACCES.
    adopt_api_socket(abs_socket)
        .context("adopting the Firecracker API socket for the invoking user")?;
    ui::info("Firecracker started.");
    Ok(())
}

/// Start an idle Firecracker for the pool: the same launch line as a VM's,
/// inside the scope `scope` names, without the progress lines a launch prints.
pub(crate) fn start_idle_firecracker(abs_dir: &str, abs_socket: &str, scope: &str) -> Result<()> {
    anyhow::ensure!(
        !scope.trim().is_empty(),
        "required Firecracker scope is missing"
    );
    ensure_api_socket_fits(abs_socket)?;
    secure_socket_dir(abs_dir)?;
    let identity = std::path::Path::new(abs_dir).join(super::idle_pool::FC_IDENTITY_FILE);
    let output = mvm_vmm::host::shell::run_in_vm(&idle_firecracker_launch_script(
        abs_dir,
        abs_socket,
        scope,
        &identity.to_string_lossy(),
    ))?;
    if !output.status.success() {
        anyhow::bail!(
            "idle Firecracker launch script failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    await_started_firecracker(abs_dir, abs_socket, scope)
}

/// Wait for a just-launched Firecracker: its scope, when it has one, then its
/// API socket.
fn await_started_firecracker(abs_dir: &str, abs_socket: &str, scope: &str) -> Result<()> {
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
    })
}

/// Where the launch script sends Firecracker's stderr, relative to the VM dir.
///
/// It and `console.log` carry guest and VMM diagnostics, so the script
/// replaces both with fresh 0600 files before Firecracker's redirections open
/// them: a link left at either path is removed rather than written through, and
/// neither file is ever created under the caller's umask. The umask is set in a
/// subshell so Firecracker's own sockets keep the modes it chooses.
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

fn firecracker_launch_script(abs_dir: &str, abs_socket: &str, scope: &str) -> String {
    firecracker_launch_script_as(abs_dir, abs_socket, scope, effective_user_id())
}

fn firecracker_launch_script_as(abs_dir: &str, abs_socket: &str, scope: &str, euid: u32) -> String {
    launch_script(abs_dir, abs_socket, scope, euid, None)
}

/// The launch script for an idle pool process: the same line, with the
/// launched process also recording its own pid and start time in
/// `identity_file` before it becomes Firecracker. The record comes from the
/// process itself, so it exists as soon as Firecracker does, whether or not
/// the `mvmctl` that started it is still running.
pub(crate) fn idle_firecracker_launch_script(
    abs_dir: &str,
    abs_socket: &str,
    scope: &str,
    identity_file: &str,
) -> String {
    launch_script(
        abs_dir,
        abs_socket,
        scope,
        effective_user_id(),
        Some(identity_file),
    )
}

fn launch_script(
    abs_dir: &str,
    abs_socket: &str,
    scope: &str,
    euid: u32,
    identity_file: Option<&str>,
) -> String {
    let sudo = sudo_prefix_for_euid(euid);
    let vsock = firecracker_vsock_uds_path(abs_dir);
    let vsock_cleanup = format!(
        "rm -f {} {}",
        shell_quote(&vsock),
        shell_quote(&format!("{abs_dir}/v.sock"))
    );
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
    let marker_mode = if euid == 0 { "600" } else { "644" };
    // Publish identity markers with a same-directory rename so readers cannot
    // observe a truncated or empty pid while the detached process starts.
    let write_marker = r#"write_marker() {
            marker_path=$1
            marker_value=$2
            marker_mode=$3
            marker_tmp=$(mktemp "${marker_path}.tmp.XXXXXXXXXX") || return 1
            if ! printf "%s\n" "$marker_value" > "$marker_tmp"; then
                rm -f "$marker_tmp"
                return 1
            fi
            if ! chmod "$marker_mode" "$marker_tmp"; then
                rm -f "$marker_tmp"
                return 1
            fi
            if ! mv -f "$marker_tmp" "$marker_path"; then
                rm -f "$marker_tmp"
                return 1
            fi
        }"#;
    let payload = match identity_file {
        None => format!(
            "'{write_marker}; write_marker \"$0\" \"$$\" \"{marker_mode}\" && exec firecracker --api-sock \"$1\"' {q_pid} {q_socket}"
        ),
        Some(identity) => {
            // A root caller can read owner-only files; a sudo-elevated
            // process must leave its records readable to the invoking user,
            // inside the pool's owner-only directory.
            let umask = if euid == 0 { "umask 077; " } else { "" };
            format!(
                "'{umask}{write_marker}; s=$(sed \"s/^.*) //\" /proc/$$/stat | cut -d\" \" -f20); \
                 write_marker \"$2\" \"$$ $s\" \"{marker_mode}\" && \
                 write_marker \"$0\" \"$$\" \"{marker_mode}\" && \
                 exec firecracker --api-sock \"$1\"' {q_pid} {q_socket} {q_identity}",
                q_identity = shell_quote(identity),
            )
        }
    };
    format!(
        r#"
        mkdir -p {q_dir} {q_socket_dir}
        {sudo}rm -f {q_socket}
        {vsock_cleanup}
        (umask 077 && rm -f {q_dir}/console.log {q_dir}/firecracker.log && touch {q_dir}/console.log {q_dir}/firecracker.log)
        {scope}{sudo}setsid nohup sh -c {payload} \
            </dev/null >{q_dir}/console.log 2>{q_dir}/firecracker.log &
        {record_launcher}
        "#,
        q_dir = q_dir,
        payload = payload,
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
        std::thread::sleep(mvm_core::poll_backoff::fine_poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
}

/// Whether `path` is a unix socket — what `[ -S ]` tested. A regular file left
/// at the path is not the API socket appearing.
fn is_unix_socket(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
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

/// Open a keep-alive session to the Firecracker API socket, reusing one
/// connection across multiple calls. The boot config sequence sends ~11 PUTs;
/// pipelining them through one connection saves 10 connect round trips.
pub fn api_session(socket: &str) -> Result<crate::fc::fc_api::FcSession> {
    crate::fc::fc_api::FcSession::connect(std::path::Path::new(socket))
}

/// Send an API PUT through an open session, with the same path validation as
/// [`api_put_socket`].
#[instrument(skip_all, fields(path))]
pub fn api_put_session(
    session: &mut crate::fc::fc_api::FcSession,
    path: &str,
    data: &str,
) -> Result<()> {
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        anyhow::bail!("refusing malformed Firecracker API path {path:?}");
    }
    session.call("PUT", path, Some(data)).map(|_body| ())
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
        "set -eu\nsudo chown -h -- \"$(id -u):$(id -g)\" {quoted}\nchmod 0600 {quoted}"
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

/// Hand a restored Firecracker's vsock socket to the invoking user.
///
/// A snapshot load creates the restored device model, and the VMM binds the
/// vsock socket the snapshot (or a fork's override) names right then — as root
/// when it was launched through `sudo`. The claim that follows dials that
/// socket as the invoking user, so a restore gives it the same hand-off a cold
/// boot gives its vsock socket after `PUT /vsock`. A load that restored no
/// vsock device bound nothing, and there is nothing to hand over.
pub fn secure_restored_vsock_socket(vsock: &std::path::Path) -> Result<()> {
    if !is_unix_socket(vsock) {
        return Ok(());
    }
    secure_vsock_socket_for_caller(&vsock.to_string_lossy())
}

/// Hand the Firecracker-created API socket to the invoking user.
///
/// Firecracker is launched through `sudo`, so it creates its API socket as
/// root and nothing but root can dial it — which is why every API call used to
/// be a `sudo curl`. Transferring ownership once, at mode 0600, lets the rest
/// of the boot speak to the socket in-process. [`start_vm_firecracker_inner`]
/// does this for every VMM it starts, so the cold boot and the snapshot
/// restore cannot drift apart on it.
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
    output.trim().parse::<u32>().with_context(|| {
        format!(
            "parse Firecracker pid from {} (marker contents: {:?})",
            path.display(),
            output.trim()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An idle process records its own pid and start time before it execs
    /// Firecracker; a VM launch line records neither.
    #[test]
    fn only_the_idle_launch_line_records_the_process_identity() {
        let idle = launch_script(
            "/p/idle-1",
            "/p/idle-1/fc.socket",
            "",
            0,
            Some("/p/idle-1/fc.identity"),
        );
        assert!(idle.contains(r#"write_marker "$2" "$$ $s""#), "{idle}");
        assert!(idle.contains("/proc/$$/stat"), "{idle}");
        assert!(idle.contains("'/p/idle-1/fc.identity'"), "{idle}");
        assert!(
            idle.contains("umask 077"),
            "root keeps its records owner-only"
        );
        // Every launch line creates its log files owner-only; only root's
        // payload also narrows the identity record it writes under sudo.
        let as_user = launch_script("/p/i", "/p/i/fc.socket", "", 1000, Some("/p/i/id"));
        assert!(idle.contains("umask 077; write_marker() {"), "{idle}");
        assert!(
            !as_user.contains("umask 077; write_marker() {"),
            "{as_user}"
        );
        assert!(as_user.contains("(umask 077 && rm -f"), "{as_user}");
        let vm = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", 0);
        assert!(!vm.contains("/proc/$$/stat"), "{vm}");
        assert!(
            vm.contains(r#"write_marker "$0" "$$" "600" && exec firecracker --api-sock "$1""#),
            "{vm}"
        );
    }

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

    /// Runs the real script with a stand-in for Firecracker. The launch's
    /// redirections run in the background, so the assertions read what the
    /// foreground creation guaranteed before any of them could open a file.
    #[test]
    fn the_launch_script_creates_private_logs_and_never_writes_through_a_link() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let vm = root.path().join("vm");
        std::fs::create_dir(&vm).unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let victim_mode = std::fs::metadata(&victim).unwrap().permissions().mode();
        std::os::unix::fs::symlink(&victim, vm.join("console.log")).unwrap();
        std::fs::write(
            vm.join(FIRECRACKER_STDERR_LOG),
            b"SYNTHETIC_MARKER from a prior run",
        )
        .unwrap();
        std::fs::set_permissions(
            vm.join(FIRECRACKER_STDERR_LOG),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let script = firecracker_launch_script_as(
            vm.to_str().unwrap(),
            vm.join("fc.socket").to_str().unwrap(),
            "",
            0,
        );
        let stubs = root.path().join("bin");
        std::fs::create_dir(&stubs).unwrap();
        std::fs::write(stubs.join("firecracker"), b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(
            stubs.join("firecracker"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env("PATH", format!("{}:/usr/bin:/bin", stubs.display()))
            .status()
            .expect("run launch script");
        assert!(status.success());

        for name in ["console.log", FIRECRACKER_STDERR_LOG] {
            let meta = std::fs::symlink_metadata(vm.join(name)).unwrap();
            assert!(meta.file_type().is_file(), "{name} is a fresh regular file");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
            let body = std::fs::read(vm.join(name)).unwrap();
            assert!(
                !body.windows(16).any(|w| w == b"SYNTHETIC_MARKER"),
                "{name} kept a prior run's payload"
            );
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode(),
            victim_mode
        );
    }

    #[test]
    fn the_launch_script_creates_a_relocated_socket_directory() {
        let script = firecracker_launch_script_as(
            "/deep/home/vms/w",
            "/tmp/mvm-sock/0123456789abcdef/fc.socket",
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
        assert!(scripts[0].contains("sudo chown -h -- \"$(id -u):$(id -g)\""));
        assert!(scripts[0].contains("chmod 0600"));
        assert!(scripts[0].contains("'/tmp/vm with quote'\\''/runtime/v.sock'"));
        assert!(!scripts[0].contains("chmod 0666"));
    }

    /// A restore whose snapshot carried no vsock device bound no socket, so
    /// there is nothing to hand to the invoking user and no shell to run.
    #[test]
    fn a_restore_that_bound_no_vsock_socket_hands_nothing_over() {
        use mvm_vmm::host::shell::mock as shell_mock;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&scripts);
        let _guard = shell_mock::install_handler(move |script| {
            captured
                .lock()
                .expect("scripts lock")
                .push(script.to_string());
            shell_mock::MockResponse::empty()
        });

        secure_restored_vsock_socket(&dir.path().join("runtime/v.sock"))
            .expect("a missing vsock socket is not an error");
        assert!(scripts.lock().expect("scripts lock").is_empty());
    }

    /// A restore that did bind the vsock socket hands it over exactly as a cold
    /// boot does: `chown` through sudo for a non-root caller, a bare 0600 for
    /// root.
    #[test]
    fn a_restored_vsock_socket_is_handed_to_the_invoking_user() {
        use mvm_vmm::host::shell::mock as shell_mock;
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("v.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&scripts);
        let _guard = shell_mock::install_handler(move |script| {
            captured
                .lock()
                .expect("scripts lock")
                .push(script.to_string());
            shell_mock::MockResponse::empty()
        });

        secure_restored_vsock_socket(&socket).expect("hand over the bound socket");

        let scripts = scripts.lock().expect("scripts lock");
        if effective_user_id() == 0 {
            assert!(scripts.is_empty());
            let mode = std::fs::metadata(&socket)
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        } else {
            assert_eq!(scripts.len(), 1, "{scripts:?}");
            assert!(scripts[0].contains("sudo chown"), "{}", scripts[0]);
            assert!(scripts[0].contains("v.sock"), "{}", scripts[0]);
        }
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
        )
        .expect("required scope");
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", &prefix, 1000);

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
        )
        .expect("required scope");
        assert!(prefix.contains("'MemoryMax=2304M'"), "{prefix}");
        assert!(prefix.contains("'TasksMax=1024'"), "{prefix}");
        assert!(!prefix.contains("CPUQuota"), "{prefix}");
    }

    #[test]
    fn an_unscoped_launch_line_carries_no_scope() {
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", 1000);
        assert!(!script.contains("systemd-run"), "{script}");
        assert!(!script.contains("scope-launcher.pid"), "{script}");
        assert!(script.contains("sudo setsid nohup sh -c"), "{script}");
        assert!(
            script.contains("exec firecracker"),
            "the shell must exec Firecracker, never leave one behind: {script}"
        );
    }

    #[test]
    fn the_launch_line_uses_virtio_mmio_instead_of_forcing_pci() {
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", 1000);

        assert!(script.contains("exec firecracker --api-sock"), "{script}");
        assert!(
            !script.contains("--enable-pci"),
            "virtio-mmio is portable across GICv2 and GICv3 hosts: {script}"
        );
    }

    /// The regression this exists for: `$!` names Firecracker only when every
    /// wrapper in the launch chain execs. `sudo` with `use_pty` (the default
    /// since 1.9.14, and what Ubuntu 24.04 ships) forks a monitor instead, so
    /// `$!` was the `sudo` pid and the `/proc/<pid>/comm == firecracker`
    /// liveness probe read every boot as an immediate VMM exit.
    #[test]
    fn the_pid_marker_is_written_by_the_launched_process_not_the_caller() {
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", 1000);

        assert!(
            !script.contains("echo $!"),
            "$! does not survive a forking sudo/setsid: {script}"
        );
        assert!(
            script.contains(r#"write_marker "$0" "$$" "644""#),
            "the pid must come from the process that becomes Firecracker: {script}"
        );

        // Written before the exec, so the marker is in place by the time the
        // API socket exists and the caller starts probing liveness.
        let write_at = script
            .find(r#"write_marker "$0" "$$" "644""#)
            .expect("pid write present");
        let exec_at = script.find("exec firecracker").expect("exec present");
        assert!(write_at < exec_at, "{script}");

        // And it names the path the rest of the tree reads.
        assert!(script.contains("/tmp/vm/fc.pid"), "{script}");
    }

    #[cfg(unix)]
    #[test]
    fn detached_launch_atomically_publishes_a_parseable_pid_before_exec() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary launch root");
        let bin = root.path().join("bin");
        let vm_dir = root.path().join("vm");
        std::fs::create_dir_all(&bin).expect("fake command directory");
        std::fs::create_dir_all(&vm_dir).expect("VM directory");

        let make_executable = |path: &std::path::Path, contents: &str| {
            std::fs::write(path, contents).expect("write fake command");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("make fake command executable");
        };
        make_executable(
            &bin.join("sudo"),
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$MVM_TEST_SUDO_PID_FILE\"\n\"$@\" &\nchild=$!\nwait \"$child\"\n",
        );
        make_executable(&bin.join("setsid"), "#!/bin/sh\nexec \"$@\"\n");
        make_executable(&bin.join("nohup"), "#!/bin/sh\nexec \"$@\"\n");

        let invoked = root.path().join("firecracker-invoked");
        let sudo_pid_file = root.path().join("sudo.pid");
        make_executable(
            &bin.join("firecracker"),
            "#!/bin/sh\n: > \"$MVM_TEST_FIRECRACKER_INVOKED\"\n",
        );

        let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
            &std::env::var_os("PATH").expect("PATH is set"),
        )))
        .expect("construct test PATH");
        let dir = vm_dir.to_string_lossy();
        let socket = vm_dir.join("fc.socket");
        let script = firecracker_launch_script_as(&dir, &socket.to_string_lossy(), "", 1000);
        let output = std::process::Command::new("bash")
            .args(["-c", &script])
            .env("PATH", path)
            .env("MVM_TEST_FIRECRACKER_INVOKED", &invoked)
            .env("MVM_TEST_SUDO_PID_FILE", &sudo_pid_file)
            .output()
            .expect("run detached launch script");
        assert!(
            output.status.success(),
            "launch script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !invoked.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "fake Firecracker was not invoked"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let pid = read_firecracker_pid(&dir).expect("launch must publish a parseable pid");
        let marker = std::fs::read_to_string(vm_dir.join("fc.pid")).expect("read pid marker");
        assert_eq!(marker, format!("{pid}\n"));
        let marker_mode = std::fs::metadata(vm_dir.join("fc.pid"))
            .expect("stat pid marker")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(marker_mode, 0o644, "sudo-launched marker stays readable");
        let sudo_pid = std::fs::read_to_string(sudo_pid_file).expect("read fake sudo pid");
        assert_ne!(pid.to_string(), sudo_pid.trim());
    }

    #[test]
    fn malformed_pid_error_includes_marker_contents() {
        let dir = tempfile::tempdir().expect("temporary VM directory");
        std::fs::write(dir.path().join("fc.pid"), "$\n").expect("write malformed marker");

        let error = read_firecracker_pid(&dir.path().to_string_lossy())
            .expect_err("a nonnumeric pid marker must be rejected")
            .to_string();
        assert!(
            error.contains("marker contents: \"$\""),
            "malformed marker should be visible in the error: {error}"
        );
    }

    #[test]
    fn invalid_required_bounds_never_reach_the_launcher() {
        use mvm_contract::grants::CpuGrant;
        use mvm_core::spawn_scope::SpawnBounds;

        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let _guard = mvm_vmm::host::shell::mock::install_handler(|_| {
            panic!("invalid bounds must not launch")
        });
        for bounds in [
            SpawnBounds::for_guest_memory(0),
            SpawnBounds::for_guest_memory(512)
                .with_cpu_grant(Some(CpuGrant::Share { millicores: 0 })),
            SpawnBounds::for_guest_memory(512)
                .with_cpu_grant(Some(CpuGrant::Share { millicores: 9 })),
        ] {
            assert!(
                start_vm_firecracker_bounded(
                    scratch.path().to_str().unwrap(),
                    scratch.path().join("fc.socket").to_str().unwrap(),
                    "invalid-bounds",
                    &bounds,
                    &mut super::super::FirecrackerGuard::pending(),
                )
                .is_err()
            );
        }
        for scope in ["", " \t"] {
            assert!(start_vm_firecracker_scoped("/unused", "/unused/socket", scope).is_err());
            assert!(start_idle_firecracker("/unused", "/unused/socket", scope).is_err());
        }
        assert!(
            spawn_scope_prefix(
                "../invalid",
                scratch.path(),
                &SpawnBounds::for_guest_memory(512),
            )
            .is_err()
        );
    }

    #[test]
    fn required_bounds_refuse_before_the_shell_launcher_is_called() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty = scratch.path().join("empty-path");
        std::fs::create_dir(&empty).expect("empty PATH");
        env.set("PATH", &empty);
        env.remove("XDG_RUNTIME_DIR");
        env.remove("DBUS_SESSION_BUS_ADDRESS");
        let _guard = mvm_vmm::host::shell::mock::install_handler(|_| {
            panic!("missing required bounds must refuse before invoking the launcher")
        });
        let socket = scratch.path().join("fc.socket");
        let error = start_vm_firecracker_bounded(
            scratch.path().to_str().expect("directory"),
            socket.to_str().expect("socket"),
            "required-bounds",
            &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(512),
            &mut super::super::FirecrackerGuard::pending(),
        )
        .expect_err("missing scope must refuse");
        assert!(format!("{error:#}").contains("scope"), "{error:#}");
    }

    #[test]
    fn a_host_without_the_mechanism_refuses_the_required_scope() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty = scratch.path().join("empty-path");
        std::fs::create_dir_all(&empty).expect("empty PATH");
        env.set("PATH", &empty);
        env.remove("XDG_RUNTIME_DIR");
        env.remove("DBUS_SESSION_BUS_ADDRESS");
        assert!(
            spawn_scope_prefix(
                "vm-x",
                scratch.path(),
                &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(512)
            )
            .is_err()
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
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", 1000);
        assert!(script.contains("sudo setsid nohup sh -c"), "{script}");
        assert!(script.contains("sudo rm -f"), "{script}");
    }

    /// Already root: sudo buys no privilege and costs a process exec on a path
    /// measured in milliseconds.
    #[test]
    fn a_root_launch_skips_sudo_entirely() {
        assert_eq!(sudo_prefix_for_euid(0), "");
        let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", 0);
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
            let script = firecracker_launch_script_as("/tmp/vm", "/tmp/vm/fc.socket", "", euid);
            assert!(
                script.contains(r#"write_marker "$0" "$$""#),
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
                "systemd-run --scope ",
                euid,
            );
            let scope_at = script.find("systemd-run").expect("scope present");
            let launch_at = script.find("setsid nohup sh -c").expect("launch present");
            assert!(scope_at < launch_at, "euid {euid}: {script}");
        }
    }
}
