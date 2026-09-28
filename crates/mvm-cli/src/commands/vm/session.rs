//! `mvmctl machine session …` — the session lifecycle verbs.
//!
//! Session metadata is persisted at `<mvm_home>/run/sessions/<id>.json` (see
//! `mvm_core::session`). Starting, calling, killing, reaping and retiming a
//! session are `mvm_client::entrypoint::session`'s, the same functions the
//! host library calls, so a session started from a language SDK and one
//! started here are admitted, audited and torn down identically. What stays
//! here is the terminal surface: argument checks phrased as flags, rendering,
//! and the dev-only verbs (`exec`, `run-code`, `console`) no library caller
//! is offered.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use mvm_client::entrypoint::verb_audit::audit_verb_refusal;
use mvm_client::entrypoint::{EntrypointAdmission, EntrypointVm, SessionVmName, WorkloadSource};
use mvm_core::audit::{LocalAuditKind, emit as audit_emit};
use mvm_core::session::{self, MAX_IDLE_TIMEOUT_SECS, SessionId, SessionState};
use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::ui;

use mvm_client::entrypoint::require_running_session;
#[cfg(test)]
use mvm_client::entrypoint::session::enforce_creator_pid_gate;
/// Tell a machine's guest agent its new idle timeout; see
/// [`mvm_client::entrypoint::update_idle_timeout`].
pub(in crate::commands) use mvm_client::entrypoint::update_idle_timeout as dispatch_update_idle_timeout;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Cmd {
    /// List all active sessions.
    Ls(LsArgs),
    /// Print session metadata as JSON.
    Info(InfoArgs),
    /// Terminate a session immediately.
    Kill(KillArgs),
    /// Update the substrate-side idle timeout for a session.
    SetTimeout(SetTimeoutArgs),
    /// Boot a microVM and register a session without dispatching
    /// anything into it. The session id is printed on stdout for
    /// capture by SDK callers; subsequent `session attach`/`exec`/
    /// `run-code`/`console` calls use that id.
    Start(StartArgs),
    /// Re-attach to an existing session and dispatch a `RunEntrypoint`
    /// call into its VM (the SDK's `Session.attach()`).
    Attach(AttachArgs),
    /// Run an arbitrary shell command against a dev-mode session.
    /// Refused on prod-mode sessions.
    Exec(ExecArgs),
    /// Run user code (interpreted by the wrapper's runtime) against a
    /// dev-mode session. Refused on prod-mode sessions.
    RunCode(RunCodeArgs),
    /// Open an interactive PTY shell into a dev-mode session. State
    /// (cwd, env, history) persists across the lifetime of the
    /// console — the underlying microVM is held warm by the session.
    /// Refused on prod-mode sessions.
    Console(ConsoleArgs),
    /// Reap idle sessions: tear down the VM and mark each record
    /// `state = Reaped`. Most session verbs already do an opportunistic
    /// reap before their own work; this verb is for cron / explicit
    /// cleanup. Idempotent.
    Reap(ReapArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct LsArgs {
    /// Emit JSON array on stdout. Default: tab-separated table.
    #[arg(long)]
    pub json: bool,
    /// After listing, emit advisory warnings on stderr for sessions
    /// that look stale or long-lived. Two flagged conditions:
    ///
    /// - **Stale** (defensive): a session in `Running` state whose
    ///   `last_invoke_at` is past `idle_timeout_secs`. The lazy
    ///   reaper that runs at the start of every `session` verb
    ///   should have caught this — if it didn't, the substrate
    ///   teardown failed silently and the record diverged from the
    ///   actual VM state. Worth investigating.
    /// - **Long-lived dev** (advisory): a `Running` `mode=dev`
    ///   session older than 1 hour. Within its idle timeout, but
    ///   old enough that the user may have forgotten about
    ///   `--keep-alive-dev`. Dev sessions expose `session
    ///   exec`/`run-code`/`console`, so leaving them open is more
    ///   surface than a forgotten prod session.
    #[arg(long)]
    pub warn_stale: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct InfoArgs {
    /// Session id to inspect.
    pub session_id: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct KillArgs {
    /// Session id to terminate.
    pub session_id: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct SetTimeoutArgs {
    /// Session id to update.
    pub session_id: String,
    /// New idle-reaper timeout in seconds. Must be > 0.
    pub seconds: u64,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct AttachArgs {
    /// Session id to dispatch into (positional). Omit with --continue.
    pub session_id: Option<String>,
    /// Re-attach the most-recently-active running session.
    #[arg(short = 'c', long = "continue", conflicts_with_all = ["session_id", "resume"])]
    pub continue_latest: bool,
    /// Re-attach a specific session id (alias for the positional).
    #[arg(
        short = 'r',
        long = "resume",
        value_name = "ID",
        conflicts_with = "session_id"
    )]
    pub resume: Option<String>,
    /// Path to stdin payload, or `-` for mvmctl's own stdin. Default:
    /// no stdin (the wrapper sees an empty pipe).
    #[arg(long, value_name = "PATH")]
    pub stdin: Option<String>,
    /// Wall-clock timeout for the call, in seconds. Unset ⇒ no kill.
    #[arg(long)]
    pub timeout: Option<u64>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ExecArgs {
    /// Session id to dispatch into.
    pub session_id: String,
    /// Command and args to run inside the dev session.
    /// Use `--` before the command if it has flags that look like
    /// `mvmctl` flags (e.g. `mvmctl session exec <id> -- ls -la`).
    #[arg(required = true, last = true)]
    pub argv: Vec<String>,
    /// Wall-clock timeout for the call, in seconds. Unset ⇒ no kill.
    #[arg(long)]
    pub timeout: Option<u64>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RunCodeArgs {
    /// Session id to dispatch into.
    pub session_id: String,
    /// Code body to run. The wrapper interprets this in its native
    /// runtime (Python, Node, etc. — language is determined by the
    /// session's wrapper, not by the CLI).
    pub code: String,
    /// Wall-clock timeout for the call, in seconds. Unset ⇒ no kill.
    #[arg(long)]
    pub timeout: Option<u64>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct StartArgs {
    /// Template (or pre-built manifest) to boot. Same resolution
    /// rules as `mvmctl invoke`'s `<MANIFEST>` argument.
    pub manifest: String,
    /// Load admitted secret bindings from Workload IR.
    #[arg(long, value_name = "PATH")]
    pub from_workload_ir: Option<std::path::PathBuf>,
    /// Start the session in dev mode. Required for subsequent
    /// `session exec` / `run-code` / `console` calls — those verbs
    /// refuse prod-mode sessions. Default: prod (matches the
    /// substrate's safe-default discipline).
    #[arg(long)]
    pub dev: bool,
    /// Restrict the sealed prod session's granted ProdSafe verbs to
    /// this explicit allow-list instead of the computed default.
    /// Repeatable. Refused with `--dev`, which stays permissive by
    /// contract.
    #[arg(long = "agent-verb", value_name = "VERB")]
    pub agent_verb: Vec<String>,
    /// vCPU count for the booted VM. Default 2.
    #[arg(long, default_value_t = crate::commands::shared::default_vcpus())]
    pub cpus: u32,
    /// Memory for the booted VM (MiB). Default 512.
    #[arg(long, default_value = "512")]
    pub memory_mib: u32,
    /// Idle timeout (seconds) baked into the session record. Reapers
    /// (when implemented) consult this value; a follow-up
    /// `session set-timeout` call can update it. Default 300 (5
    /// minutes).
    #[arg(long, default_value_t = mvm_core::session::DEFAULT_IDLE_TIMEOUT_SECS)]
    pub idle_timeout: u64,
    /// Tear the session down automatically after the next attach
    /// completes (no manual `session kill` needed).
    #[arg(long)]
    pub ephemeral: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ConsoleArgs {
    /// Session id to drop into.
    pub session_id: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ReapArgs {}

pub(in crate::commands) fn run(cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Opportunistic lazy reap: every session verb sweeps idle records
    // before its own work. Failures are logged, not propagated —
    // reaping is best-effort cleanup, not load-bearing for the verb.
    // Skipped on `Reap` itself (which does the same work explicitly)
    // to avoid double-counting.
    if !matches!(args.command, Cmd::Reap(_)) {
        reap_expired_sessions(false);
    }
    match args.command {
        Cmd::Ls(a) => cmd_ls(a),
        Cmd::Info(a) => cmd_info(a),
        Cmd::Kill(a) => cmd_kill(a),
        Cmd::SetTimeout(a) => cmd_set_timeout(a),
        Cmd::Start(a) => cmd_start(a),
        Cmd::Attach(a) => cmd_attach(a),
        Cmd::Exec(a) => cmd_exec(a),
        Cmd::RunCode(a) => cmd_run_code(a),
        Cmd::Console(a) => cmd_console(a),
        Cmd::Reap(a) => cmd_reap(cli, a),
    }
}

fn validate_start_args(args: &StartArgs) -> Result<()> {
    if args.dev && !args.agent_verb.is_empty() {
        bail!("--agent-verb is refused with --dev; dev sessions stay permissive by contract");
    }
    Ok(())
}

/// Tear down every session whose idle timeout has lapsed and mark it
/// `Reaped`, printing each id when `verbose`. Best-effort; see
/// [`mvm_client::entrypoint::reap_expired_sessions`].
pub(in crate::commands) fn reap_expired_sessions(verbose: bool) -> Vec<SessionId> {
    let reaped = mvm_client::entrypoint::reap_expired_sessions();
    if verbose {
        for id in &reaped {
            println!("{id}");
        }
    }
    reaped
}

fn cmd_ls(args: LsArgs) -> Result<()> {
    let sessions = session::list_sessions().context("listing sessions")?;
    if args.json {
        // JSON mode is for machine consumers; warning text on stderr
        // is fine to keep but no per-record `stale` field is wired
        // yet — keeps the schema stable. If a consumer wants
        // structured stale info, they can derive it from the
        // existing fields the same way we do below.
        if args.warn_stale {
            emit_stale_warnings(&sessions);
        }
        println!("{}", serde_json::to_string(&sessions)?);
        return Ok(());
    }
    if sessions.is_empty() {
        ui::info("No active sessions.");
        return Ok(());
    }
    println!("ID\tWORKLOAD\tVM\tMODE\tSTATE\tINVOKES\tIDLE_TIMEOUT\tSTARTED_AT");
    for s in &sessions {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s.id,
            s.workload_id,
            s.vm_name,
            s.mode,
            s.state,
            s.invoke_count,
            s.idle_timeout_secs,
            s.started_at,
        );
    }
    if args.warn_stale {
        emit_stale_warnings(&sessions);
    }
    Ok(())
}

/// Threshold beyond which a Running dev session is considered
/// "long-lived" and worth flagging — within its idle timeout, but
/// old enough to have been forgotten. One hour is a compromise
/// between "noise on every modest debugging session" and "actually
/// catches the forgot-about-it case".
const LONG_LIVED_DEV_THRESHOLD_SECS: i64 = 3600;

/// Inspect `sessions` for staleness signals and emit advisory
/// warnings on stderr. Two conditions:
///
/// - **Stale Running**: state == Running but `last_invoke_at`
///   (falling back to `started_at`) is past `idle_timeout_secs`.
///   The lazy reaper at the start of every session verb should
///   have caught this; if it didn't, the substrate teardown failed
///   silently. Defensive — usually no hits.
/// - **Long-lived dev**: state == Running, mode == Dev,
///   `now - started_at > LONG_LIVED_DEV_THRESHOLD_SECS`. Within
///   timeout but worth a reminder. Dev sessions expose shell /
///   exec / run-code surface.
///
/// Best-effort throughout: records with unparseable timestamps are
/// skipped silently. The classification is read-only — no record
/// mutation, no VM teardown.
fn emit_stale_warnings(sessions: &[mvm_core::session::SessionRecord]) {
    let now = chrono::Utc::now();
    let mut stale_running: Vec<&mvm_core::session::SessionRecord> = Vec::new();
    let mut long_lived_dev: Vec<&mvm_core::session::SessionRecord> = Vec::new();

    for record in sessions {
        if record.state != SessionState::Running {
            continue;
        }
        let last_str = record
            .last_invoke_at
            .as_deref()
            .unwrap_or(&record.started_at);
        let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(last_str) else {
            continue;
        };
        let elapsed_since_used = now
            .signed_duration_since(last_dt.with_timezone(&chrono::Utc))
            .num_seconds();
        if elapsed_since_used > 0 && (elapsed_since_used as u64) > record.idle_timeout_secs {
            stale_running.push(record);
            // A session can be both stale-Running AND long-lived-dev,
            // but reporting it once (under the more urgent stale
            // category) is enough.
            continue;
        }

        if record.mode == mvm_core::session::SessionMode::Dev {
            let Ok(started_dt) = chrono::DateTime::parse_from_rfc3339(&record.started_at) else {
                continue;
            };
            let age = now
                .signed_duration_since(started_dt.with_timezone(&chrono::Utc))
                .num_seconds();
            if age > LONG_LIVED_DEV_THRESHOLD_SECS {
                long_lived_dev.push(record);
            }
        }
    }

    // Warnings go to stderr (not stdout) so they don't corrupt
    // `--json` machine output. `ui::warn` itself writes to stdout
    // (matches the rest of mvm's CLI feedback discipline) — for the
    // ls advisory we want stderr specifically. Format mirrors the
    // `[mvm]` prefix style for visual continuity.
    if !stale_running.is_empty() {
        eprintln!(
            "[mvm] WARN: {} stale Running session(s) past idle_timeout — \
             reaper teardown may have failed:",
            stale_running.len()
        );
        for r in stale_running {
            eprintln!(
                "[mvm] WARN:   {} (vm {}, idle_timeout={}s, started_at={})",
                r.id, r.vm_name, r.idle_timeout_secs, r.started_at
            );
        }
    }
    if !long_lived_dev.is_empty() {
        eprintln!(
            "[mvm] WARN: {} long-lived dev session(s) older than 1 hour — \
             check `mvmctl machine session info <id>` and consider `mvmctl machine session kill`:",
            long_lived_dev.len()
        );
        for r in long_lived_dev {
            eprintln!(
                "[mvm] WARN:   {} (vm {}, started_at={})",
                r.id, r.vm_name, r.started_at
            );
        }
    }
}

fn cmd_info(args: InfoArgs) -> Result<()> {
    let record = mvm_client::entrypoint::session_info(&args.session_id)?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

fn cmd_kill(args: KillArgs) -> Result<()> {
    let record = mvm_client::entrypoint::kill_session(&args.session_id)?;
    ui::info(&format!(
        "Killed session {} (vm {})",
        record.id, record.vm_name
    ));
    Ok(())
}

fn cmd_set_timeout(args: SetTimeoutArgs) -> Result<()> {
    if args.seconds == 0 {
        bail!("--seconds must be > 0");
    }
    if args.seconds > MAX_IDLE_TIMEOUT_SECS {
        bail!(
            "--seconds {} exceeds the {}s hard ceiling (24h). \
             Long-running sessions are a foot-gun: extend periodically with \
             repeated `mvmctl machine session set-timeout` calls, or split work \
             across shorter-lived sessions.",
            args.seconds,
            MAX_IDLE_TIMEOUT_SECS
        );
    }
    let update = mvm_client::entrypoint::set_session_idle_timeout(&args.session_id, args.seconds)?;
    let id = &update.record.id;
    // Best-effort: the host record is what the reaper enforces; telling the
    // agent only lets its warm-process pool recycle on the same clock.
    match update.substrate {
        Ok((prev, 0)) => {
            tracing::debug!(
                session = %id,
                prev_secs = prev,
                "set-timeout: agent acknowledged but no warm-process pool active"
            );
        }
        Ok((prev, applied)) => {
            ui::info(&format!("substrate idle timeout: {prev}s → {applied}s"));
        }
        Err(e) => {
            tracing::warn!(
                session = %id,
                err = %e,
                "set-timeout: agent dispatch failed; host reaper still enforces"
            );
        }
    }
    ui::info(&format!(
        "Updated session {id} idle_timeout_secs={}",
        update.record.idle_timeout_secs
    ));
    Ok(())
}

fn cmd_attach(args: AttachArgs) -> Result<()> {
    let resolved_id: String = if args.continue_latest {
        let rec = mvm_core::session::most_recent_running_on_disk()?
            .ok_or_else(|| anyhow::anyhow!("no running session to --continue"))?;
        rec.id.into_string()
    } else if let Some(id) = args.resume.or(args.session_id) {
        id
    } else {
        bail!("provide a session id, --resume <id>, or --continue");
    };

    let (id, record) = require_running_session(&resolved_id)?;
    let stdin_bytes = super::invoke::read_stdin_payload(args.stdin.as_deref())?;
    ui::info(&format!(
        "attach: dispatching into session {id} (vm {})",
        record.vm_name
    ));
    // The session was admitted by whichever invocation started it, so there
    // is no plan in this process to open a stdin stream under; `--stdin` is a
    // path or `-` read to the end, which is a complete payload either way.
    // Unset `--timeout` keeps the default 30-second kill window.
    let exit_code = super::invoke::dispatch_into_session(
        &id,
        &record,
        stdin_bytes,
        args.timeout.unwrap_or(30),
    )?;
    if record.ephemeral {
        ui::info(&format!("ephemeral session {id}: torn down after attach"));
    }
    if exit_code != 0 {
        mvm_observability::exit(exit_code);
    }
    Ok(())
}

fn cmd_exec(args: ExecArgs) -> Result<()> {
    let (id, record) = require_running_session(&args.session_id)?;
    require_dev_mode(&id, &record, "exec")?;

    if args.argv.is_empty() {
        bail!("exec requires at least one argv element after `--`");
    }
    // Audit-log the dispatch BEFORE we run user-supplied argv so the
    // log line lands even if the call hangs / panics. We deliberately
    // don't include the argv content in `detail` — it can carry user-
    // typed secrets (auth tokens, env-shaped flags). The `vm_name`
    // + `session=<id>` correlation is enough to attribute access.
    audit_emit(
        LocalAuditKind::SessionExec,
        Some(&record.vm_name),
        Some(&format!("session={id}")),
    );
    // Rebuild the shell command from argv. Shell-quote each element so
    // an embedded space or quote in user-provided args doesn't get
    // re-tokenized by bash.
    let cmd_line = args
        .argv
        .iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    run_in_session(&id, &record, cmd_line, args.timeout).inspect_err(|e| {
        audit_verb_refusal(&record.vm_name, e);
    })
}

fn cmd_run_code(args: RunCodeArgs) -> Result<()> {
    let (id, record) = require_running_session(&args.session_id)?;
    require_dev_mode(&id, &record, "run-code")?;

    // Audit BEFORE dispatch — same rationale as cmd_exec. Code body
    // is omitted from `detail` for the same secrecy reason.
    audit_emit(
        LocalAuditKind::SessionRunCode,
        Some(&record.vm_name),
        Some(&format!("session={id}")),
    );
    // Dispatch via the dev-only `RunCode` vsock verb. The agent
    // reads `/etc/mvm/wrapper.json` to learn the wrapper's language
    // and spawns the matching interpreter (`python3 -c` /
    // `node -e`).
    //
    // v1 is stateless — each call gets a fresh interpreter, so
    // `from foo import bar` in call 1 isn't visible in call 2. v2
    // routes through the warm-process pool's wrapper for stateful
    // eval; the wire shape stays identical.
    dispatch_run_code(&id, &record, args.code, args.timeout).inspect_err(|e| {
        audit_verb_refusal(&record.vm_name, e);
    })
}

/// Send a `RunCode` request to the session's guest agent and stream
/// the result. Mirrors `run_in_session`'s I/O shape but goes through
/// the structured `RunCode` verb rather than a shell-quote of the
/// code body. The agent's `/etc/mvm/wrapper.json`-based dispatch
/// picks the right interpreter; if the wrapper's language is unknown or the
/// runtime gate refuses the request, the response surfaces the refusal
/// directly.
fn dispatch_run_code(
    id: &SessionId,
    record: &mvm_core::session::SessionRecord,
    code: String,
    timeout_secs: Option<u64>,
) -> Result<()> {
    use std::io::Write;

    if !crate::exec::wait_for_agent(&record.vm_name, 30) {
        bail!("guest agent did not become reachable within 30s");
    }

    let transport = mvm_runtime::vsock_transport::for_vm(&record.vm_name)
        .with_context(|| format!("Picking transport for guest agent on {:?}", record.vm_name))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("Connecting to guest agent on {:?}", record.vm_name))?;
    let request_code = code.clone();
    let req = mvm_agentd::vsock::GuestRequest::RunCode { code, timeout_secs };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(&record.vm_name, &req);
    let terminal = mvm_agentd::vsock::send_run_code_streaming(
        &mut stream,
        &request_code,
        timeout_secs,
        |event| match event {
            mvm_agentd::vsock::ExecEvent::Stdout { chunk } => {
                let mut so = std::io::stdout();
                let _ = so.write_all(chunk);
                let _ = so.flush();
            }
            mvm_agentd::vsock::ExecEvent::Stderr { chunk } => {
                let mut se = std::io::stderr();
                let _ = se.write_all(chunk);
                let _ = se.flush();
            }
            _ => {}
        },
    )?;
    let exit_code = match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => code,
        mvm_agentd::vsock::ExecEvent::TimedOut => {
            eprintln!("{}", crate::exec::timeout_exit_message(timeout_secs));
            crate::exec::EXEC_TIMEOUT_EXIT_CODE
        }
        other => bail!("unexpected terminal exec event: {other:?}"),
    };

    if let Err(e) = session::update_session(id, |r| {
        r.invoke_count = r.invoke_count.saturating_add(1);
        r.last_invoke_at = Some(rfc3339_now());
        Ok(())
    }) {
        tracing::warn!(err = %e, "failed to bump session invoke counter");
    }

    if exit_code != 0 {
        mvm_observability::exit(exit_code);
    }
    Ok(())
}

fn require_dev_mode(
    id: &SessionId,
    record: &mvm_core::session::SessionRecord,
    verb: &str,
) -> Result<()> {
    use mvm_core::session::SessionMode;
    if record.mode == SessionMode::Prod {
        bail!(
            "session {id} is mode=prod; '{verb}' is dev-only. \
             Start the session with mode=dev to allow ad-hoc execution."
        );
    }
    Ok(())
}

/// Dispatch a shell command into an already-running session VM via
/// the existing `Exec` vsock verb. Streams stdout/stderr to mvmctl's
/// own streams; exits non-zero with the wrapper's exit code on failure.
///
/// Note: `Exec` is DevOnly on the guest side (gated by the runtime profile
/// and signed grant). This verb is itself gated by `require_dev_mode` above;
/// the underlying call still enforces the same policy and surfaces any typed
/// refusal to the user.
fn run_in_session(
    id: &SessionId,
    record: &mvm_core::session::SessionRecord,
    command: String,
    timeout_secs: Option<u64>,
) -> Result<()> {
    use std::io::Write;

    let vm = crate::exec::SessionVm {
        vm_name: record.vm_name.clone(),
    };
    let output = crate::exec::dispatch_in_session(&vm, command, timeout_secs)
        .with_context(|| format!("dispatching command into session {id}"))?;

    let _ = std::io::stdout().write_all(output.stdout.as_bytes());
    let _ = std::io::stderr().write_all(output.stderr.as_bytes());

    if let Err(e) = session::update_session(id, |r| {
        r.invoke_count = r.invoke_count.saturating_add(1);
        r.last_invoke_at = Some(rfc3339_now());
        Ok(())
    }) {
        tracing::warn!(err = %e, "failed to bump session invoke counter");
    }

    if output.exit_code != 0 {
        mvm_observability::exit(output.exit_code);
    }
    Ok(())
}

/// Single-quote `s` so bash sees it as one literal token. Doubles up
/// embedded `'` as `'\''` (close-quote, escaped-quote, re-open).
fn shell_quote(s: &str) -> String {
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

fn rfc3339_now() -> String {
    use chrono::SecondsFormat;
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Boot a session VM and register a session record, but **don't** dispatch
/// anything into it. The session id is printed on stdout for SDK / shell
/// capture; subsequent `session attach` / `exec` / `run-code` / `console`
/// calls operate on it.
fn cmd_start(args: StartArgs) -> Result<()> {
    use mvm_core::session::SessionMode;

    validate_start_args(&args)?;
    if args.idle_timeout == 0 {
        bail!("--idle-timeout must be > 0");
    }
    if args.idle_timeout > MAX_IDLE_TIMEOUT_SECS {
        bail!(
            "--idle-timeout {} exceeds the {}s hard ceiling (24h). \
             Use `mvmctl machine session set-timeout` to extend periodically \
             instead of opting in to an unbounded keepalive.",
            args.idle_timeout,
            MAX_IDLE_TIMEOUT_SECS
        );
    }

    let slot = mvm_client::entrypoint::resolve_slot(WorkloadSource::Manifest(&args.manifest))?;
    let mode = if args.dev {
        SessionMode::Dev
    } else {
        SessionMode::Prod
    };
    let admission = EntrypointAdmission::builder(mvm_client::entrypoint::backend_name_for(None)?)
        .cpus(args.cpus)
        .mem_mib(u64::from(args.memory_mib))
        .secrets(mvm_client::admission::secrets::resolve_workload_secrets(
            args.from_workload_ir.as_deref(),
        )?)
        .agent_verb_override(args.agent_verb.clone())
        .dev(args.dev)
        .build()?;

    ui::info(&format!(
        "session start: booting {mode} session for template '{slot}'"
    ));
    let record = crate::commands::env::builder_vm::with_pair_artifact_source(|pair| {
        mvm_client::entrypoint::start_session(
            mvm_client::entrypoint::SessionStart {
                vm: EntrypointVm {
                    slot: &slot,
                    vm_name: SessionVmName::Prefixed("session"),
                    cpus: args.cpus,
                    memory_mib: args.memory_mib,
                    admission,
                },
                mode,
                idle_timeout_secs: args.idle_timeout,
                ephemeral: args.ephemeral,
            },
            pair,
        )
    })?;
    ui::info(&format!(
        "session ready: id={} vm={} mode={mode} idle_timeout={}s",
        record.id, record.vm_name, args.idle_timeout
    ));
    // Session id on stdout (separate stream from the human-readable
    // ui::info) so SDK callers can capture it cleanly.
    println!("{}", record.id);
    Ok(())
}

fn cmd_reap(cli: &Cli, _args: ReapArgs) -> Result<()> {
    let reaped = reap_expired_sessions(cli.verbose > 0);
    ui::info(&format!("Reaped {} idle session(s).", reaped.len()));
    Ok(())
}

/// Open an interactive PTY shell into a dev-mode session. Refused on
/// prod sessions.
fn cmd_console(args: ConsoleArgs) -> Result<()> {
    let (id, record) = require_running_session(&args.session_id)?;
    require_dev_mode(&id, &record, "console")?;

    // Bump last_invoke_at so observers see the activity. Done before
    // we hand off to the PTY relay because the relay blocks until the
    // user exits — we don't want the session to look idle while the
    // user is actively shelling around in it.
    if let Err(e) = session::update_session(&id, |r| {
        r.last_invoke_at = Some(rfc3339_now());
        Ok(())
    }) {
        tracing::warn!(err = %e, "failed to update session last_invoke_at");
    }

    ui::info(&format!(
        "session console: attaching to session {id} (vm {})",
        record.vm_name
    ));
    audit_emit(
        LocalAuditKind::SessionConsoleOpen,
        Some(&record.vm_name),
        Some(&format!("session={id}")),
    );
    // The underlying `console_interactive` already emits
    // `ConsoleSessionStart` / `ConsoleSessionEnd` audit events for the
    // PTY lifecycle — this `SessionConsoleOpen` event is the
    // session-id correlation: the PTY events alone don't tell a
    // forensics consumer which `mvmctl session` invocation opened
    // them, but `vm_name` is shared so a join recovers the chain.
    super::console::console_interactive(
        &record.vm_name,
        super::console::ConsoleSessionOptions::default(),
    )
    .map(|_| ())
    .with_context(|| format!("opening console for session {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_core::util::test_env::TestEnv;

    struct RuntimeDirGuard {
        _temp: tempfile::TempDir,
        env: TestEnv,
    }

    impl RuntimeDirGuard {
        /// Set an additional env var on this guard's `TestEnv`. Tests that
        /// already hold the guard must mutate through it rather than create a
        /// second `TestEnv`, which would deadlock on the shared env lock.
        fn set(&mut self, key: &str, value: &str) {
            self.env.set(key, value);
        }
    }

    fn isolated_runtime_dir() -> RuntimeDirGuard {
        let temp = tempfile::tempdir().expect("tempdir");
        // `TestEnv` serializes env-mutating tests behind a process-wide lock
        // and restores `MVM_HOME` (and anything else set via the guard)
        // on drop.
        let mut env = TestEnv::new();
        env.set("MVM_HOME", temp.path());
        RuntimeDirGuard { _temp: temp, env }
    }

    #[test]
    fn info_errors_for_unknown_id() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new().to_string();
        let err = cmd_info(InfoArgs { session_id: id }).unwrap_err();
        assert!(
            err.to_string().contains("no session with id"),
            "expected missing-id error, got: {err}"
        );
    }

    #[test]
    fn set_timeout_zero_is_rejected() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new().to_string();
        let err = cmd_set_timeout(SetTimeoutArgs {
            session_id: id,
            seconds: 0,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("must be > 0"),
            "expected zero-seconds error, got: {err}"
        );
    }

    #[test]
    fn set_timeout_above_ceiling_is_rejected() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new().to_string();
        let err = cmd_set_timeout(SetTimeoutArgs {
            session_id: id,
            seconds: MAX_IDLE_TIMEOUT_SECS + 1,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("ceiling"),
            "expected ceiling error, got: {err}"
        );
    }

    #[test]
    fn validate_start_args_refuses_agent_verbs_on_dev() {
        let err = validate_start_args(&StartArgs {
            manifest: "tmpl".into(),
            from_workload_ir: None,
            dev: true,
            agent_verb: vec!["ping".into()],
            cpus: 2,
            memory_mib: 512,
            idle_timeout: mvm_core::session::DEFAULT_IDLE_TIMEOUT_SECS,
            ephemeral: false,
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--agent-verb is refused with --dev"),
            "expected explicit dev conflict error, got: {err}"
        );
    }

    #[test]
    fn set_timeout_at_exactly_ceiling_is_accepted() {
        let _guard = isolated_runtime_dir();
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        let id = rec.id.to_string();
        session::write_session(&rec).unwrap();
        // The dispatch-to-vsock part will warn (no real VM) but the
        // record update happens first and shouldn't fail at the
        // ceiling boundary.
        cmd_set_timeout(SetTimeoutArgs {
            session_id: id.clone(),
            seconds: MAX_IDLE_TIMEOUT_SECS,
        })
        .unwrap();
        let parsed = SessionId::parse(&id).unwrap();
        let reread = session::read_session(&parsed).unwrap().unwrap();
        assert_eq!(reread.idle_timeout_secs, MAX_IDLE_TIMEOUT_SECS);
    }

    #[test]
    fn set_timeout_invalid_id_is_rejected() {
        let _guard = isolated_runtime_dir();
        let err = cmd_set_timeout(SetTimeoutArgs {
            session_id: "ABCDE".into(),
            seconds: 60,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("Invalid session id"),
            "expected invalid-id error, got: {err}"
        );
    }

    #[test]
    fn set_timeout_updates_existing_record() {
        let _guard = isolated_runtime_dir();
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        let id_str = rec.id.to_string();
        session::write_session(&rec).unwrap();
        cmd_set_timeout(SetTimeoutArgs {
            session_id: id_str.clone(),
            seconds: 999,
        })
        .unwrap();
        let id = SessionId::parse(&id_str).unwrap();
        let reread = session::read_session(&id).unwrap().unwrap();
        assert_eq!(reread.idle_timeout_secs, 999);
    }

    #[test]
    fn creator_pid_gate_off_by_default() {
        // Without the env var, attach should not check creator_pid
        // even when it differs from the caller's. We construct a
        // record whose creator_pid is intentionally bogus.
        let _guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        rec.creator_pid = 99999; // not us
        let id = rec.id.clone();
        session::write_session(&rec).unwrap();
        // Default env: gate is off, so the check passes.
        enforce_creator_pid_gate(&id, &rec).expect("gate should be off by default");
    }

    #[test]
    fn creator_pid_gate_pid_zero_records_pass_through() {
        // Records written before the field existed have
        // creator_pid=0; the gate is implicitly disabled for them
        // even when the env var is set, so old records keep working.
        let mut guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        rec.creator_pid = 0;
        let id = rec.id.clone();

        guard.set(session::STRICT_CREATOR_PID_ENV, "1");
        let result = enforce_creator_pid_gate(&id, &rec);
        result.expect("creator_pid=0 records bypass the gate");
    }

    #[test]
    fn creator_pid_gate_rejects_different_pid_when_enabled() {
        // With the env var on AND a non-zero creator_pid that
        // differs from the caller's, the gate must refuse.
        let mut guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        rec.creator_pid = std::process::id().wrapping_add(1); // definitely not us
        let id = rec.id.clone();

        guard.set(session::STRICT_CREATOR_PID_ENV, "1");
        let result = enforce_creator_pid_gate(&id, &rec);
        let err = result.expect_err("different PID should be refused");
        assert!(
            err.to_string().contains("created by pid"),
            "expected creator-pid error, got: {err}"
        );
    }

    #[test]
    fn creator_pid_gate_accepts_same_pid_when_enabled() {
        // The common case: caller IS the creator. Gate accepts.
        let mut guard = isolated_runtime_dir();
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        // `new_running` captures std::process::id() into creator_pid,
        // so the caller (this test) is by construction the creator.
        let id = rec.id.clone();

        guard.set(session::STRICT_CREATOR_PID_ENV, "1");
        let result = enforce_creator_pid_gate(&id, &rec);
        result.expect("same-pid call should pass the gate");
    }

    #[test]
    fn require_running_session_rejects_unknown() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new().to_string();
        let err = require_running_session(&id).unwrap_err();
        assert!(
            err.to_string().contains("no session with id"),
            "expected missing-id error, got: {err}"
        );
    }

    #[test]
    fn require_running_session_rejects_killed() {
        let _guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        rec.state = session::SessionState::Killed;
        let id = rec.id.to_string();
        session::write_session(&rec).unwrap();
        let err = require_running_session(&id).unwrap_err();
        assert!(
            err.to_string().contains("not running"),
            "expected not-running error, got: {err}"
        );
    }

    #[test]
    fn require_dev_mode_rejects_prod_session() {
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        let err = require_dev_mode(&rec.id, &rec, "exec").unwrap_err();
        assert!(
            err.to_string().contains("dev-only"),
            "expected dev-only error, got: {err}"
        );
    }

    #[test]
    fn require_dev_mode_accepts_dev_session() {
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Dev);
        require_dev_mode(&rec.id, &rec, "exec").expect("dev session should pass");
    }

    #[test]
    fn exec_with_empty_argv_is_rejected() {
        let _guard = isolated_runtime_dir();
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Dev);
        let id = rec.id.to_string();
        session::write_session(&rec).unwrap();
        let err = cmd_exec(ExecArgs {
            session_id: id,
            argv: vec![],
            timeout: None,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("at least one argv element"),
            "expected empty-argv error, got: {err}"
        );
    }

    #[test]
    fn shell_quote_basic_token_wrapped_in_single_quotes() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_handles_embedded_single_quote() {
        // Bash escape sequence: close-quote, escaped-quote, re-open.
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn shell_quote_preserves_spaces_and_special_chars() {
        assert_eq!(shell_quote("a b $c|d"), "'a b $c|d'");
    }

    #[test]
    fn attach_with_unknown_id_errors_before_dispatch() {
        // No session record on disk → require_running_session bails
        // before any attempt to talk to a vsock.
        let _guard = isolated_runtime_dir();
        let id = SessionId::new().to_string();
        let err = cmd_attach(AttachArgs {
            session_id: Some(id),
            continue_latest: false,
            resume: None,
            stdin: None,
            timeout: None,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("no session with id"),
            "expected missing-id error, got: {err}"
        );
    }

    #[test]
    fn attach_continue_with_no_sessions_errors() {
        // Empty session store → most_recent_running_on_disk returns None
        // → cmd_attach bails before touching any vsock.
        let _guard = isolated_runtime_dir();
        let err = cmd_attach(AttachArgs {
            session_id: None,
            continue_latest: true,
            resume: None,
            stdin: None,
            timeout: None,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("no running session"),
            "expected no-running-session error, got: {err}"
        );
    }

    #[test]
    fn run_code_on_prod_session_is_rejected() {
        let _guard = isolated_runtime_dir();
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        let id = rec.id.to_string();
        session::write_session(&rec).unwrap();
        let err = cmd_run_code(RunCodeArgs {
            session_id: id,
            code: "print(1)".into(),
            timeout: None,
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("dev-only"),
            "expected dev-only error, got: {err}"
        );
    }

    #[test]
    fn console_unknown_id_errors_before_pty_attach() {
        let _guard = isolated_runtime_dir();
        let id = SessionId::new().to_string();
        let err = cmd_console(ConsoleArgs { session_id: id }).unwrap_err();
        assert!(
            err.to_string().contains("no session with id"),
            "expected missing-id error, got: {err}"
        );
    }

    #[test]
    fn console_on_prod_session_is_rejected() {
        let _guard = isolated_runtime_dir();
        let rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        let id = rec.id.to_string();
        session::write_session(&rec).unwrap();
        let err = cmd_console(ConsoleArgs { session_id: id }).unwrap_err();
        assert!(
            err.to_string().contains("dev-only"),
            "expected dev-only error, got: {err}"
        );
    }

    #[test]
    fn console_on_killed_session_is_rejected() {
        let _guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Dev);
        rec.state = session::SessionState::Killed;
        let id = rec.id.to_string();
        session::write_session(&rec).unwrap();
        let err = cmd_console(ConsoleArgs { session_id: id }).unwrap_err();
        assert!(
            err.to_string().contains("not running"),
            "expected not-running error, got: {err}"
        );
    }

    #[test]
    fn reap_marks_idle_sessions_as_reaped() {
        let _guard = isolated_runtime_dir();
        // Stale: started_at well past idle_timeout — should be reaped.
        let mut stale =
            session::SessionRecord::new_running("vm-stale", "wl", session::SessionMode::Prod);
        let stale_ts = chrono::Utc::now() - chrono::Duration::seconds(900);
        stale.idle_timeout_secs = 60;
        stale.started_at = stale_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let stale_id = stale.id.clone();
        session::write_session(&stale).unwrap();

        // Fresh: still within idle window — should remain Running.
        let fresh =
            session::SessionRecord::new_running("vm-fresh", "wl", session::SessionMode::Prod);
        let fresh_id = fresh.id.clone();
        session::write_session(&fresh).unwrap();

        let reaped = reap_expired_sessions(false);
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0], stale_id);

        let reread = session::read_session(&stale_id).unwrap().unwrap();
        assert_eq!(reread.state, session::SessionState::Reaped);
        let fresh_after = session::read_session(&fresh_id).unwrap().unwrap();
        assert_eq!(fresh_after.state, session::SessionState::Running);
    }

    #[test]
    fn reap_skips_already_killed_sessions() {
        let _guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        rec.state = session::SessionState::Killed;
        rec.idle_timeout_secs = 60;
        rec.started_at = (chrono::Utc::now() - chrono::Duration::seconds(900))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        session::write_session(&rec).unwrap();

        let reaped = reap_expired_sessions(false);
        assert!(
            reaped.is_empty(),
            "killed sessions are skipped, got {reaped:?}"
        );
    }

    #[test]
    fn reap_is_idempotent_on_already_reaped() {
        let _guard = isolated_runtime_dir();
        let mut rec = session::SessionRecord::new_running("vm-1", "wl", session::SessionMode::Prod);
        rec.state = session::SessionState::Reaped;
        session::write_session(&rec).unwrap();
        let reaped = reap_expired_sessions(false);
        assert!(reaped.is_empty());
    }
}
