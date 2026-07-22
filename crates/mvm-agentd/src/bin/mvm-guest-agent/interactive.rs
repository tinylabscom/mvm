//! Dev-only interactive surface: exec, run-code, run-detached, and the
//! PTY-over-vsock console relay. Every item here is gated behind the
//! `interactive` feature so none of it links into a production agent build
//! (claim 4 / claim 15) — the module itself is declared
//! `#[cfg(feature = "interactive")]` in the bin root, and each item repeats
//! the same gate so the boundary is legible from inside the file too.

use mvm_agentd::vsock::GuestResponse;

use crate::HandlerCtx;
use crate::socket::write_response;

/// Process registry singleton — shared across all `ProcStart` /
/// `ProcWait` / etc. dispatches inside one agent process. Dev-only
/// (gated alongside `process_rpc`); the symbol is absent from prod
/// builds.
#[cfg(feature = "interactive")]
pub(crate) fn proc_registry() -> &'static mvm_agentd::process_rpc::Registry {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<mvm_agentd::process_rpc::Registry> = OnceLock::new();
    REGISTRY.get_or_init(mvm_agentd::process_rpc::Registry::new)
}

/// `ProcWait` streaming arm — writes intermediate Stdout/Stderr
/// frames to the connection and returns the terminal event for the
/// dispatch loop to write last. Mirrors `handle_run_entrypoint`.
#[cfg(feature = "interactive")]
pub(crate) fn handle_proc_wait_streaming(
    file: &mut std::fs::File,
    pid_token: &str,
    timeout_secs: Option<u64>,
) -> mvm_agentd::vsock::ProcWaitEvent {
    let caps = mvm_agentd::process_rpc::Caps::production();
    let registry = proc_registry();
    mvm_agentd::process_rpc::handle_proc_wait(registry, &caps, pid_token, timeout_secs, |ev| {
        write_response(file, &GuestResponse::ProcWaitEvent(ev));
    })
}

/// `Exec` streaming arm — writes intermediate `ExecEvent` Stdout/Stderr
/// frames to the connection and returns the terminal `Exit` or `TimedOut`
/// for the dispatch loop to write last. Mirrors `handle_run_entrypoint` /
/// `handle_proc_wait_streaming`. (interactive only)
#[cfg(feature = "interactive")]
fn do_exec_streaming(
    file: &mut std::fs::File,
    command: &str,
    stdin_data: Option<&str>,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    let terminal = mvm_agentd::exec_stream::stream_exec(command, stdin_data, timeout_secs, |ev| {
        write_response(file, &GuestResponse::ExecEvent(ev));
    });
    GuestResponse::ExecEvent(terminal)
}

/// Spawn `argv` as a detached workload and return its ack (interactive only).
///
/// Models the image `/init` entrypoint launch, but agent-driven and
/// non-blocking: the child gets its own session (`setsid`), stdin from
/// `/dev/null`, and stdout/stderr on `/dev/console` (which the host
/// backend captures to `console.log`). The call returns immediately with
/// `DetachedStarted { pid }`; a detached reaper thread waits on the child
/// and reports its exit code to the host's workload-exit port via
/// `mvm-exit-report`, so the VM powers off when the workload finishes
/// (docker `-d` semantics). The reaper never blocks the agent request loop.
#[cfg(feature = "interactive")]
fn do_run_detached(argv: Vec<String>, env: Vec<(String, String)>) -> GuestResponse {
    do_run_detached_with(
        argv,
        env,
        std::path::Path::new("/dev/console"),
        std::path::Path::new("/usr/local/bin/mvm-exit-report"),
    )
}

/// Testable core of [`do_run_detached`]. `console` receives the workload's
/// stdout/stderr (production: `/dev/console`, captured by the backend to
/// `console.log`); `exit_report_bin` is the reporter the reaper execs with the
/// workload's exit code (production: `/usr/local/bin/mvm-exit-report`). A test
/// points both at a tempdir to observe the spawn, the console redirect, and the
/// reported exit code without a live guest.
#[cfg(feature = "interactive")]
fn do_run_detached_with(
    argv: Vec<String>,
    env: Vec<(String, String)>,
    console: &std::path::Path,
    exit_report_bin: &std::path::Path,
) -> GuestResponse {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let Some((program, args)) = argv.split_first() else {
        return GuestResponse::Error {
            message: "run-detached refused: empty argv".to_string(),
        };
    };

    let devnull = match std::fs::File::open("/dev/null") {
        Ok(f) => f,
        Err(e) => {
            return GuestResponse::Error {
                message: format!("run-detached: open /dev/null: {e}"),
            };
        }
    };
    // Two independent write handles to the console so stdout and stderr
    // each own their fd (no shared-offset surprises).
    let console_out = match std::fs::OpenOptions::new().write(true).open(console) {
        Ok(f) => f,
        Err(e) => {
            return GuestResponse::Error {
                message: format!("run-detached: open console {}: {e}", console.display()),
            };
        }
    };
    let console_err = match std::fs::OpenOptions::new().write(true).open(console) {
        Ok(f) => f,
        Err(e) => {
            return GuestResponse::Error {
                message: format!("run-detached: open console {}: {e}", console.display()),
            };
        }
    };

    // env_clear(), then a minimal safe base plus the caller's vars.
    // Drop malformed entries rather than let `Command::env` panic
    // (empty key, key containing '=' or NUL, value containing NUL).
    let safe_env = env.into_iter().filter(|(k, v)| {
        !k.is_empty() && !k.contains('=') && !k.contains('\0') && !v.contains('\0')
    });

    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .envs(safe_env)
        .stdin(Stdio::from(devnull))
        .stdout(Stdio::from(console_out))
        .stderr(Stdio::from(console_err));

    // SAFETY: runs in the post-fork pre-exec child. `setsid(2)` is
    // async-signal-safe and is the only work done here — it detaches the
    // workload into its own session so it outlives this request's
    // connection and isn't tied to the agent's controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return GuestResponse::Error {
                message: format!("run-detached: spawn {program}: {e}"),
            };
        }
    };
    let pid = child.id() as i32;

    // Reaper: wait for the detached workload, then report its exit code
    // to the host so the VM powers off (best-effort). Never touches the
    // agent request loop.
    let exit_report_bin = exit_report_bin.to_path_buf();
    std::thread::spawn(move || {
        let mut child = child;
        let code = match child.wait() {
            Ok(status) => status.code().unwrap_or(-1),
            Err(_) => -1,
        };
        let _ = std::process::Command::new(&exit_report_bin)
            .arg(code.to_string())
            .status();
    });

    GuestResponse::DetachedStarted { pid }
}

/// Write one staged file to disk (creating parents, applying mode) before an
/// `ExecBatch` runs its commands. (interactive only)
#[cfg(feature = "interactive")]
fn stage_file_to_disk(s: &mvm_agentd::vsock::StageFile) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = std::path::Path::new(&s.path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&s.path, &s.content)?;
    std::fs::set_permissions(&s.path, std::fs::Permissions::from_mode(s.mode))
}

/// `getrusage(RUSAGE_CHILDREN).ru_maxrss` (KiB on Linux): the high-water RSS
/// across reaped children — a cumulative peak proxy for the batch. `None` when
/// the call fails or reports nothing. (interactive only)
#[cfg(feature = "interactive")]
fn read_peak_rss_kib() -> Option<u64> {
    // SAFETY: getrusage only writes the provided rusage struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) };
    (rc == 0 && usage.ru_maxrss > 0).then_some(usage.ru_maxrss as u64)
}

/// `ExecBatch` arm (interactive only): stage every file, then run each argv
/// command buffered (stop at the first non-zero exit), returning one
/// `ExecOutcomeWire` per command run. One round-trip, no streaming.
#[cfg(feature = "interactive")]
fn do_exec_batch(
    stages: &[mvm_agentd::vsock::StageFile],
    commands: &[Vec<String>],
    timeout_secs: Option<u64>,
) -> GuestResponse {
    use mvm_agentd::vsock::{ExecEvent, ExecOutcomeWire};
    for s in stages {
        if let Err(e) = stage_file_to_disk(s) {
            return GuestResponse::Error {
                message: format!("exec-batch staging {} failed: {e}", s.path),
            };
        }
    }
    let mut outcomes = Vec::new();
    for argv in commands {
        let command = argv
            .iter()
            .map(|a| shell_quote_for_sh(a))
            .collect::<Vec<_>>()
            .join(" ");
        let start = std::time::Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let terminal =
            mvm_agentd::exec_stream::stream_exec(&command, None, timeout_secs, |ev| match ev {
                ExecEvent::Stdout { chunk } => stdout.extend_from_slice(&chunk),
                ExecEvent::Stderr { chunk } => stderr.extend_from_slice(&chunk),
                _ => {}
            });
        let status = match terminal {
            ExecEvent::Exit { code } => code,
            ExecEvent::TimedOut => 124,
            _ => -1,
        };
        outcomes.push(ExecOutcomeWire {
            status,
            stdout,
            stderr,
            duration_ms: start.elapsed().as_millis() as u64,
            peak_rss_kib: read_peak_rss_kib(),
        });
        if status != 0 {
            break;
        }
    }
    GuestResponse::ExecBatchResult { outcomes }
}

/// Read the wrapper's language from `/etc/mvm/wrapper.json`. Returns
/// `None` if the file is missing, unparseable, or the field is
/// absent — caller treats that as "language unknown, refuse the
/// `RunCode` call rather than guess".
#[cfg(feature = "interactive")]
fn read_wrapper_language() -> Option<String> {
    let raw = std::fs::read_to_string("/etc/mvm/wrapper.json").ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("language")?.as_str().map(str::to_owned)
}

/// Stateless run-code v1: dispatch a fresh interpreter subprocess
/// with the user-supplied source on its `-c` / `-e` arg. Refuses
/// unknown languages with a wire-stable error string. Streams output
/// via `do_exec_streaming`.
///
/// A future v2 will route through the warm-process pool instead,
/// providing stateful eval across calls. Wire shape stays identical —
/// the dispatch flips inside this function.
#[cfg(feature = "interactive")]
fn do_run_code(file: &mut std::fs::File, code: &str, timeout_secs: Option<u64>) -> GuestResponse {
    let lang = match read_wrapper_language() {
        Some(l) => l,
        None => {
            write_response(
                file,
                &GuestResponse::ExecEvent(mvm_agentd::vsock::ExecEvent::Stderr {
                    chunk: b"run-code refused: /etc/mvm/wrapper.json missing or has no \
                         language field"
                        .to_vec(),
                }),
            );
            return GuestResponse::ExecEvent(mvm_agentd::vsock::ExecEvent::Exit { code: -1 });
        }
    };
    let interpreter = match lang.as_str() {
        "python" => "python3",
        "node" => "node",
        other => {
            write_response(
                file,
                &GuestResponse::ExecEvent(mvm_agentd::vsock::ExecEvent::Stderr {
                    chunk: format!(
                        "run-code refused: unsupported language {:?} \
                     (supported: python, node)",
                        other
                    )
                    .into_bytes(),
                }),
            );
            return GuestResponse::ExecEvent(mvm_agentd::vsock::ExecEvent::Exit { code: -1 });
        }
    };
    // Build the shell command. Single-quote the code so the shell
    // doesn't expand `$VAR` / backticks inside it; embedded single
    // quotes get the close-quote-escape-reopen treatment.
    let interp_flag = if interpreter == "node" { "-e" } else { "-c" };
    let shell_command = format!(
        "{} {} {}",
        interpreter,
        interp_flag,
        shell_quote_for_sh(code)
    );
    do_exec_streaming(file, &shell_command, None, timeout_secs)
}

/// Single-quote `s` for `/bin/sh` consumption: doubles up embedded
/// `'` as `'\''` (close-quote, escaped-quote, re-open). Mirrors
/// `mvm_cli::commands::vm::session::shell_quote` — duplicated here
/// rather than depending on mvm-cli to keep the agent's dependency
/// surface lean.
#[cfg(feature = "interactive")]
fn shell_quote_for_sh(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_exec(
    ctx: &mut HandlerCtx,
    command: String,
    stdin: Option<String>,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    eprintln!("[audit] exec request: {:?}", command);
    do_exec_streaming(ctx.file, &command, stdin.as_deref(), timeout_secs)
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_exec_batch(
    stages: Vec<mvm_agentd::vsock::StageFile>,
    commands: Vec<Vec<String>>,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    eprintln!(
        "[audit] exec-batch request: {} stages, {} commands",
        stages.len(),
        commands.len()
    );
    do_exec_batch(&stages, &commands, timeout_secs)
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_run_code(
    ctx: &mut HandlerCtx,
    code: String,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    // Stateless v1: read /etc/mvm/wrapper.json to learn the
    // wrapper's language, then dispatch a fresh interpreter
    // subprocess. A future v2 will route through the
    // warm-process pool's persistent wrapper for stateful
    // eval; wire shape stays identical.
    //
    // Code body is NOT logged (matches `mvmctl session
    // run-code`'s host-side audit posture — argv / code can
    // carry user-typed secrets).
    eprintln!("[audit] run-code request");
    do_run_code(ctx.file, &code, timeout_secs)
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_run_detached(argv: Vec<String>, env: Vec<(String, String)>) -> GuestResponse {
    // Argv is NOT logged: it can carry user-typed secrets, mirroring
    // the run-code audit posture.
    eprintln!("[audit] run-detached request: {} args", argv.len());
    do_run_detached(argv, env)
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_console_open(
    cols: u16,
    rows: u16,
    env: Vec<(String, String)>,
    argv: Vec<String>,
) -> GuestResponse {
    // Check security policy — console requires access.console = true.
    // When no policy file is provisioned (dev mode), use permissive defaults.
    let policy = mvm_agentd::builder_agent::load_security_policy()
        .ok()
        .flatten()
        .unwrap_or_else(mvm_core::security::SecurityPolicy::dev_defaults);
    let console_allowed = policy.access.console;
    if !console_allowed {
        return GuestResponse::Error {
            message: "console rejected: access.console not enabled in security policy".to_string(),
        };
    }
    match mvm_agentd::console::open_session(cols, rows, &env, &argv) {
        Ok(session) => {
            let session_id = session.session_id;
            let data_port = session.data_port;
            eprintln!("console: opened session {session_id}, data port {data_port}");

            // Run the relay in a background thread
            std::thread::spawn(move || {
                let exit_code = mvm_agentd::console::run_console_relay(&session);
                eprintln!("console: session {session_id} ended, exit code {exit_code}");
            });

            GuestResponse::ConsoleOpened {
                session_id,
                data_port,
            }
        }
        Err(e) => GuestResponse::Error {
            message: format!("console open failed: {e}"),
        },
    }
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_console_close(session_id: u32) -> GuestResponse {
    // Console sessions end when the shell exits or the host disconnects.
    // Explicit close is a no-op if already closed.
    if mvm_agentd::console::is_active() {
        GuestResponse::Error {
            message: "explicit close not yet supported — disconnect to end session".to_string(),
        }
    } else if let Some(exit_code) = mvm_agentd::console::completed_exit_code(session_id) {
        GuestResponse::ConsoleExited {
            session_id,
            exit_code,
        }
    } else {
        GuestResponse::ConsoleExited {
            session_id,
            exit_code: 0,
        }
    }
}

#[cfg(feature = "interactive")]
pub(crate) fn handle_console_resize(session_id: u32, cols: u16, rows: u16) -> GuestResponse {
    if mvm_agentd::console::resize_active_session(cols, rows) {
        eprintln!("console: resized to {cols}x{rows}");
        GuestResponse::ConsoleResized { session_id }
    } else {
        GuestResponse::Error {
            message: "no active console session to resize".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The detached-workload handler actually spawns the argv, redirects its
    /// stdout to the console target, and the reaper reports the exit code — the
    /// end-to-end behaviour behind `machine run -d -- <cmd>`, exercised on the
    /// host without a live guest. This is the regression guard for a guest agent
    /// that links the `RunDetached` handler but doesn't actually run the workload.
    #[cfg(feature = "interactive")]
    #[test]
    fn run_detached_spawns_redirects_console_and_reports_exit() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let console = dir.path().join("console");
        let reported = dir.path().join("reported-code");
        // The handler opens the console for writing (it exists in production as
        // `/dev/console`); pre-create the stand-in so the open succeeds.
        std::fs::File::create(&console).unwrap();

        // Stand-in for `mvm-exit-report`: records its exit-code argument so the
        // reaper's report is observable.
        let reporter = dir.path().join("exit-report.sh");
        std::fs::write(
            &reporter,
            format!("#!/bin/sh\nprintf '%s' \"$1\" > {}\n", reported.display()),
        )
        .unwrap();
        std::fs::set_permissions(&reporter, std::fs::Permissions::from_mode(0o755)).unwrap();

        let resp = do_run_detached_with(
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf RAN-DETACHED; exit 7".into(),
            ],
            vec![],
            &console,
            &reporter,
        );
        let pid = match resp {
            GuestResponse::DetachedStarted { pid } => pid,
            other => panic!("expected DetachedStarted, got {other:?}"),
        };
        assert!(pid > 0, "expected a positive pid, got {pid}");

        // The spawn is asynchronous: poll until the workload's stdout reaches the
        // console target AND the reaper reports the exit code.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let console_body = std::fs::read_to_string(&console).unwrap_or_default();
            let reported_code = std::fs::read_to_string(&reported).unwrap_or_default();
            if console_body.contains("RAN-DETACHED") && reported_code == "7" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "detached workload did not complete: console={console_body:?} reported_code={reported_code:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[cfg(feature = "interactive")]
    #[test]
    fn run_detached_refuses_empty_argv() {
        match do_run_detached_with(
            vec![],
            vec![],
            std::path::Path::new("/dev/null"),
            std::path::Path::new("/bin/true"),
        ) {
            GuestResponse::Error { message } => {
                assert!(message.contains("empty argv"), "got: {message}")
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
