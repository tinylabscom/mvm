//! Warm sessions: one booted VM, many entrypoint calls.
//!
//! A session's metadata is a record under the MVM home (see
//! `mvm_core::session`), so any process on the host can find it; the VM
//! itself is whatever the backend started. The operations here are the ones
//! every surface shares — start, call, kill, reap, and the idle-timeout
//! update — so a session started by the host library and one started by the
//! CLI are admitted, audited and torn down identically.
//!
//! Calls into one session are serialized within a process: the guest agent
//! runs one entrypoint call per VM and answers a second with `Busy`, so a
//! caller that issues two at once would otherwise see a spurious failure.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use anyhow::{Context, Result, bail};
use mvm_core::audit::{LocalAuditKind, emit as audit_emit};
use mvm_core::session::{
    self, MAX_IDLE_TIMEOUT_SECS, SessionId, SessionMode, SessionRecord, SessionState,
};

use super::boot::{SessionVm, stop_session_vm};
use super::call::{AGENT_WAIT_SECS, EntrypointVm, boot_entrypoint_vm, bump_invoke_count};
use super::dispatch::{CallObserver, CallOutcome, DispatchStdin, EntrypointDispatch, dispatch};
use crate::launch::runtime_source::PairArtifactSource;

/// Output from an ad-hoc development-session call, independent of its wire protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevSessionOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

/// A reported guest outcome. Transport and policy failures remain errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevSessionCompletion {
    Exited(i32),
    TimedOut,
}

/// Require the development surface without weakening the running/creator gates.
pub fn require_dev_mode(id: &SessionId, record: &SessionRecord, verb: &str) -> Result<()> {
    if record.mode == SessionMode::Prod {
        bail!(
            "session {id} is mode=prod; '{verb}' is dev-only. \
             Start the session with mode=dev to allow ad-hoc execution."
        );
    }
    Ok(())
}

/// Dispatch literal argv into a development session. Arguments never become shell syntax.
pub fn exec_session(
    raw_id: &str,
    argv: Vec<String>,
    timeout_secs: Option<u64>,
    mut on_output: impl FnMut(&DevSessionOutput),
) -> Result<DevSessionCompletion> {
    dev_session_call(raw_id, "exec", LocalAuditKind::SessionExec, |record| {
        anyhow::ensure!(
            !argv.is_empty(),
            "exec requires at least one argv element after `--`"
        );
        let command = session_exec_wrapper(&argv);
        dispatch_dev_call(record, &mut on_output, |stream, output| {
            crate::guest::emit_vsock_rpc_audit(
                &record.vm_name,
                &mvm_agentd::vsock::GuestRequest::Exec {
                    command: String::new(),
                    stdin: None,
                    timeout_secs,
                },
            );
            mvm_agentd::vsock::send_exec_streaming(stream, &command, None, timeout_secs, output)
        })
        .with_context(|| format!("dispatching command into session {}", record.id))
    })
}

/// Evaluate code through the guest's language-aware development verb.
pub fn run_session_code(
    raw_id: &str,
    code: String,
    timeout_secs: Option<u64>,
    mut on_output: impl FnMut(&DevSessionOutput),
) -> Result<DevSessionCompletion> {
    dev_session_call(
        raw_id,
        "run-code",
        LocalAuditKind::SessionRunCode,
        |record| {
            dispatch_dev_call(record, &mut on_output, |stream, output| {
                crate::guest::emit_vsock_rpc_audit(
                    &record.vm_name,
                    &mvm_agentd::vsock::GuestRequest::RunCode {
                        code: String::new(),
                        timeout_secs,
                    },
                );
                mvm_agentd::vsock::send_run_code_streaming(stream, &code, timeout_secs, output)
            })
        },
    )
}

fn dev_session_call(
    raw_id: &str,
    verb: &str,
    audit: LocalAuditKind,
    dispatch: impl FnOnce(&SessionRecord) -> Result<DevSessionCompletion>,
) -> Result<DevSessionCompletion> {
    let id = parse_id(raw_id)?;
    let lock = call_lock(&id);
    let _turn = lock.lock().unwrap_or_else(PoisonError::into_inner);
    // Read under the call lock; a caller cannot supply stale or fabricated metadata.
    let (_, record) = require_running_session(raw_id)?;
    require_dev_mode(&id, &record, verb)?;
    audit_emit(audit, Some(&record.vm_name), Some(&format!("session={id}")));
    let completion = dispatch(&record).inspect_err(|error| {
        super::verb_audit::audit_verb_refusal(&record.vm_name, error);
    })?;
    // Nonzero exits and timeouts are invocations; refusals and transport errors are not.
    bump_invoke_count(&id);
    Ok(completion)
}

fn dispatch_dev_call(
    record: &SessionRecord,
    on_output: &mut dyn FnMut(&DevSessionOutput),
    send: impl FnOnce(
        &mut std::os::unix::net::UnixStream,
        &mut dyn FnMut(&mvm_agentd::vsock::ExecEvent),
    ) -> Result<mvm_agentd::vsock::ExecEvent>,
) -> Result<DevSessionCompletion> {
    if !crate::readiness::wait_for_guest_agent(&record.vm_name, 30) {
        bail!("guest agent did not become reachable within 30s");
    }
    let transport = mvm_runtime::vsock_transport::for_vm(&record.vm_name)
        .with_context(|| format!("Picking transport for guest agent on {:?}", record.vm_name))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("Connecting to guest agent on {:?}", record.vm_name))?;
    let terminal = send(&mut stream, &mut |event| {
        if let Some(output) = dev_output(event) {
            on_output(&output);
        }
    })?;
    dev_completion(terminal)
}

fn dev_output(event: &mvm_agentd::vsock::ExecEvent) -> Option<DevSessionOutput> {
    match event {
        mvm_agentd::vsock::ExecEvent::Stdout { chunk } => {
            Some(DevSessionOutput::Stdout(chunk.clone()))
        }
        mvm_agentd::vsock::ExecEvent::Stderr { chunk } => {
            Some(DevSessionOutput::Stderr(chunk.clone()))
        }
        mvm_agentd::vsock::ExecEvent::Exit { .. } | mvm_agentd::vsock::ExecEvent::TimedOut => None,
    }
}

fn dev_completion(terminal: mvm_agentd::vsock::ExecEvent) -> Result<DevSessionCompletion> {
    match terminal {
        mvm_agentd::vsock::ExecEvent::Exit { code } => Ok(DevSessionCompletion::Exited(code)),
        mvm_agentd::vsock::ExecEvent::TimedOut => Ok(DevSessionCompletion::TimedOut),
        other => bail!("unexpected terminal exec event: {other:?}"),
    }
}

fn session_exec_wrapper(argv: &[String]) -> String {
    use mvm_vmm::host::shell::shell_quote;
    let command = argv
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "set -e\nexport PATH={}:\"$PATH\"\nexec 'bash' '-c' {}\n",
        shell_quote(mvm_core::guest_netd::MEDIATED_TOOLS_BIN),
        shell_quote(&command),
    )
}

/// Resolve and record ordinary-session console activity before entering a blocking relay.
/// Both session policy and VM accessibility are checked before recording activity.
pub fn prepare_console_session(raw_id: &str) -> Result<SessionRecord> {
    let (id, record) = require_running_session(raw_id)?;
    require_dev_mode(&id, &record, "console")?;
    crate::console::enforce_accessible_gate(&record.vm_name, false)?;
    if let Err(error) = session::update_session(&id, |record| {
        record.last_invoke_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        Ok(())
    }) {
        tracing::warn!(err = %error, "failed to update session last_invoke_at");
    }
    audit_emit(
        LocalAuditKind::SessionConsoleOpen,
        Some(&record.vm_name),
        Some(&format!("session={id}")),
    );
    Ok(record)
}

/// List ordinary sessions without exposing the on-disk registry to consumers.
pub fn list_sessions() -> Result<Vec<SessionRecord>> {
    session::list_sessions().context("listing sessions")
}

/// Select the most recently active running session for a continuation.
pub fn latest_running_session() -> Result<SessionRecord> {
    session::most_recent_running_on_disk()?
        .ok_or_else(|| anyhow::anyhow!("no running session to --continue"))
}

/// A session to start: the VM it boots, and the record it is kept under.
pub struct SessionStart<'a> {
    /// What the session's VM boots from and under.
    pub vm: EntrypointVm<'a>,
    /// The mode the session is recorded under; `Dev` admits the dev-only
    /// session verbs.
    pub mode: SessionMode,
    /// How long the session may sit idle before the reaper takes it.
    pub idle_timeout_secs: u64,
    /// Tear the session down after its next call.
    pub ephemeral: bool,
}

/// Refuse an idle timeout of zero or past the hard ceiling.
///
/// # Errors
/// `secs` is zero, or longer than a day.
pub fn validate_idle_timeout(secs: u64) -> Result<()> {
    if secs == 0 {
        bail!("the idle timeout must be > 0 seconds");
    }
    if secs > MAX_IDLE_TIMEOUT_SECS {
        bail!(
            "an idle timeout of {secs}s exceeds the {MAX_IDLE_TIMEOUT_SECS}s hard ceiling \
             (24h); extend a session periodically instead of keeping one alive unbounded"
        );
    }
    Ok(())
}

/// Boot a session VM and register its record, dispatching nothing.
///
/// The VM boots under the same admission a transient call does, and the
/// record is written only once the agent answers, so a session that exists is
/// one that can take a call. A record that cannot be written tears the VM
/// down: a VM nobody holds a handle to is a leak.
///
/// # Errors
/// An invalid idle timeout, a refused admission or boot, an agent that never
/// answered, or a record that could not be written.
pub fn start_session(
    start: SessionStart<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<SessionRecord> {
    let SessionStart {
        vm,
        mode,
        idle_timeout_secs,
        ephemeral,
    } = start;
    validate_idle_timeout(idle_timeout_secs)?;
    let slot = vm.slot;
    let booted = boot_entrypoint_vm(vm, pair)?;
    booted.await_agent(AGENT_WAIT_SECS)?;

    let mut record = SessionRecord::new_running(&booted.vm.vm_name, slot, mode);
    record.idle_timeout_secs = idle_timeout_secs;
    record.ephemeral = ephemeral;
    if let Err(e) = session::write_session(&record) {
        let err = anyhow::anyhow!("registering session: {e}");
        // The boot was admitted, so its session ends here, as a failed start.
        match stop_session_vm(&booted.vm) {
            Ok(()) => crate::admission::emit_failed(&booted.admission, "session-register", &err),
            Err(stop) => crate::launch::record_unsealed_end(
                Some((&booted.admission.emitter, booted.admission.admitted.plan())),
                crate::launch::UnsealedEnd::new(
                    &booted.vm.vm_name,
                    crate::launch::UnsealedReason::StopFailed,
                )
                .error(format!("{stop:#}")),
            ),
        }
        return Err(err);
    }
    audit_emit(
        LocalAuditKind::SessionStart,
        Some(&record.vm_name),
        Some(&format!(
            "session={},template={slot},mode={mode},idle_timeout_secs={idle_timeout_secs}",
            record.id
        )),
    );
    ensure_idle_timeout_owner(&record, &booted.admission.admitted.plan().tenant.0);
    Ok(record)
}

/// Make sure a process outlives this one to enforce `record`'s idle timeout.
///
/// On libkrun and HVF that is the VM's own supervisor, already running. The
/// backends with no supervisor rely on the tenant's host agent, which this
/// starts if it is not up. Best-effort: a session whose agent could not be
/// started still runs, and the client sweep still reaps it.
fn ensure_idle_timeout_owner(record: &SessionRecord, tenant: &str) {
    let Some(kind) = mvm_runtime::AnyBackend::started_vm_kind(&record.vm_name) else {
        return;
    };
    if !mvm_hostd::host_agent_sessions::host_agent_enforces_session_expiry(kind) {
        return;
    }
    if let Err(e) = mvm_runtime::ensure_host_agent_daemon(tenant) {
        tracing::warn!(
            session = %record.id,
            vm = %record.vm_name,
            error = %format!("{e:#}"),
            "no host agent to enforce the idle timeout; only a session command will reap it"
        );
    }
}

/// Read a session record by id.
///
/// # Errors
/// A malformed id, an unreadable store, or no such session.
pub fn session_info(raw_id: &str) -> Result<SessionRecord> {
    let id = parse_id(raw_id)?;
    session::read_session(&id)
        .context("reading session")?
        .ok_or_else(|| anyhow::anyhow!("no session with id {id}"))
}

/// Look up a running session by id, applying the strict-creator gate. The
/// errors are stable phrasings callers match on.
///
/// # Errors
/// A malformed id, no such session, a session that is not running, or a
/// caller the strict-creator gate refuses.
pub fn require_running_session(raw_id: &str) -> Result<(SessionId, SessionRecord)> {
    let record = session_info(raw_id)?;
    let id = record.id.clone();
    if record.state != SessionState::Running {
        bail!(
            "session {id} is not running (state: {}); cannot dispatch",
            record.state
        );
    }
    enforce_creator_pid_gate(&id, &record)?;
    Ok((id, record))
}

/// The strict-creator-PID gate. Silent unless the strict-creator env var is
/// set *and* the record carries a non-zero creator; then a call from any other
/// process is refused.
///
/// PIDs are reused, so this is a foot-gun guard rather than a boundary: the
/// session table's file permissions are the access boundary.
///
/// # Errors
/// The gate is on and the caller is not the creator.
pub fn enforce_creator_pid_gate(id: &SessionId, record: &SessionRecord) -> Result<()> {
    if !session::strict_creator_pid_enabled() || record.creator_pid == 0 {
        return Ok(());
    }
    let caller = std::process::id();
    if caller != record.creator_pid {
        bail!(
            "session {id} was created by pid {} but caller pid is {caller} \
             ({}=1). Either unset the env var or call from the same process that \
             created the session.",
            record.creator_pid,
            session::STRICT_CREATOR_PID_ENV,
        );
    }
    Ok(())
}

/// Dispatch one call into a running session.
///
/// The session's plan was admitted by whichever process started it, so this
/// process holds nothing to open a stdin stream under: the payload is always
/// the complete, one-frame kind. Calls into the same session from this
/// process wait their turn.
///
/// A call that returned counts against the session; an ephemeral session is
/// torn down and marked `Reaped` after it, whatever the workload's exit.
///
/// # Errors
/// The dispatch failed. The session is left as it was.
pub fn call_session(
    id: &SessionId,
    record: &SessionRecord,
    payload: Vec<u8>,
    timeout_secs: u64,
    observer: &mut dyn CallObserver,
) -> Result<CallOutcome> {
    let lock = call_lock(id);
    let _turn = lock.lock().unwrap_or_else(PoisonError::into_inner);
    audit_emit(
        LocalAuditKind::SessionAttach,
        Some(&record.vm_name),
        Some(&format!("session={id}")),
    );
    let outcome = dispatch(
        EntrypointDispatch {
            vm_name: &record.vm_name,
            stdin: DispatchStdin::OneShot(super::dispatch::one_shot_payload(payload)),
            timeout_secs,
            session_id: Some(id),
        },
        observer,
    )
    .with_context(|| format!("dispatching into session {id}"))?;
    bump_invoke_count(id);
    if record.ephemeral {
        end_session_vm(&record.vm_name);
        let _ = session::update_session(id, |r| {
            r.state = SessionState::Reaped;
            Ok(())
        });
    }
    Ok(outcome)
}

/// Kill a running session: mark it `Killed`, then tear its VM down and seal
/// its audit session as `stopped`.
///
/// The order is load-bearing. A call in flight sees its connection drop and
/// re-reads the record; if it already says `Killed` the call reports the kill
/// rather than a generic transport error. Tearing down first would race.
///
/// # Errors
/// A malformed id, no such session, or one that is not running.
pub fn kill_session(raw_id: &str) -> Result<SessionRecord> {
    let record = session_info(raw_id)?;
    let id = record.id.clone();
    if record.state != SessionState::Running {
        bail!(
            "session {id} is not running (state: {}); cannot kill",
            record.state
        );
    }
    session::update_session(&id, |r| {
        r.state = SessionState::Killed;
        Ok(())
    })
    .context("updating session record before kill")?;
    end_session_vm(&record.vm_name);
    audit_emit(
        LocalAuditKind::SessionKill,
        Some(&record.vm_name),
        Some(&format!("session={id}")),
    );
    forget_call_lock(&id);
    Ok(record)
}

/// Tear down every session whose idle timeout has lapsed, mark it `Reaped`,
/// and seal its audit chain once its VM is down, returning the ids reaped.
///
/// The per-VM supervisor enforces the same timeout on its own on the backends
/// that have one; this sweep is what catches the rest when a session verb
/// runs. Both claim a session through
/// [`mvm_hostd::supervisor::session_expiry::claim_expired_session`], so a
/// session is reaped and audited once whichever notices first.
///
/// The record is marked before the VM is torn down, as [`kill_session`]
/// does: a call in flight that loses its connection then reads why.
///
/// Best-effort throughout: one session's failure never stops the sweep.
#[must_use]
pub fn reap_expired_sessions() -> Vec<SessionId> {
    let now = chrono::Utc::now();
    let candidates = match session::list_expired_session_ids(now) {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!(err = %e, "reap: failed to list candidates");
            return Vec::new();
        }
    };
    let mut reaped = Vec::new();
    for id in candidates {
        let record = match mvm_hostd::supervisor::session_expiry::claim_expired_session(&id, now) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(session = %id, err = %e, "reap: could not claim session");
                continue;
            }
        };
        end_session_vm(&record.vm_name);
        forget_call_lock(&id);
        reaped.push(id);
    }
    reaped
}

/// Stop a session's VM and seal its audit session as `stopped`: the end of a
/// session that was killed, reaped, or used up, where no workload exit was
/// observed. Best-effort, because the reaper calls this where nobody is
/// waiting for an error.
///
/// The plan is read before the stop, which removes the state dir it lives in.
/// A VM whose stop failed may still be running, so its session is left
/// unsealed rather than closed over a guest that can still extend it; `trust
/// audit verify` then reports it `UNSEALED`. Either way the end is on the
/// record: an unsealed end writes why, chain-signed when there is a plan.
fn end_session_vm(vm_name: &str) {
    end_session_vm_with(vm_name, stop_session_vm);
}

/// [`end_session_vm`] with the stop supplied, so the refusal to seal after a
/// failed stop can be tested without a VM that refuses to die.
fn end_session_vm_with(vm_name: &str, stop: impl FnOnce(&SessionVm) -> Result<()>) {
    let plan = mvm_hostd::audit::plan_persist::read_plan(vm_name).ok();
    let vm = SessionVm {
        vm_name: vm_name.to_string(),
    };
    if let Err(e) = stop(&vm) {
        crate::launch::record_session_stop_failure(plan.as_ref(), vm_name, &format!("{e:#}"));
        return;
    }
    match plan {
        Some(plan) => crate::launch::seal_stopped_session(&plan, vm_name),
        None => crate::launch::record_unsealed_end(
            None,
            crate::launch::UnsealedEnd::new(vm_name, crate::launch::UnsealedReason::NoVerifiedPlan)
                .error("no admitted plan persisted beside the VM"),
        ),
    }
}

/// A session's new idle timeout, and what its guest agent made of it.
pub struct IdleTimeoutUpdate {
    /// The record as rewritten.
    pub record: SessionRecord,
    /// The agent's `(previous_secs, applied_secs)`, or why it could not be
    /// told. The host record is what the reaper enforces either way; telling
    /// the agent only lets its warm-process pool recycle on the same clock.
    pub substrate: Result<(u64, u64)>,
}

/// Set a session's idle timeout, then tell its guest agent.
///
/// # Errors
/// An invalid timeout or id, or a record that could not be rewritten.
pub fn set_session_idle_timeout(raw_id: &str, secs: u64) -> Result<IdleTimeoutUpdate> {
    validate_idle_timeout(secs)?;
    let id = parse_id(raw_id)?;
    let record = session::update_session(&id, |r| {
        r.idle_timeout_secs = secs;
        Ok(())
    })
    .context("updating session timeout")?;
    let substrate = update_idle_timeout(&record.vm_name, secs);
    Ok(IdleTimeoutUpdate { record, substrate })
}

/// Send `UpdateIdleTimeout` to a VM's guest agent, returning its
/// `(previous_secs, applied_secs)`. `applied_secs == 0` means the agent took
/// the verb but runs no warm-process pool. A refusal the plan's grant caused
/// is recorded as a chain-signed `verb_denied` entry before it is returned.
///
/// # Errors
/// The agent unreachable, lacking the capability, or refusing the verb.
pub fn update_idle_timeout(vm_name: &str, secs: u64) -> Result<(u64, u64)> {
    let transport = mvm_runtime::vsock_transport::for_vm(vm_name)
        .with_context(|| format!("Picking transport for guest agent on {vm_name:?}"))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("Connecting to guest agent on {vm_name:?}"))?;
    if let Err(err) = mvm_agentd::vsock::require_capabilities(
        &mut stream,
        &[mvm_agentd::vsock::GuestCapability::UpdateIdleTimeout],
    ) {
        super::verb_audit::audit_verb_refusal(vm_name, &err);
        return Err(err);
    }
    let req = mvm_agentd::vsock::GuestRequest::UpdateIdleTimeout { secs };
    crate::guest::emit_vsock_rpc_audit(vm_name, &req);
    let response = match mvm_agentd::vsock::call_unary(&mut stream, &req) {
        Ok(response) => response,
        Err(err) => {
            let err = anyhow::Error::from(err);
            super::verb_audit::audit_verb_refusal(vm_name, &err);
            return Err(err);
        }
    };
    match classify_update_idle_response(response) {
        UpdateIdleOutcome::Applied {
            previous_secs,
            applied_secs,
        } => Ok((previous_secs, applied_secs)),
        UpdateIdleOutcome::Denied { verb } => {
            super::verb_audit::emit_verb_denied(vm_name, &verb);
            bail!("guest agent denied verb {verb:?}: not in the plan's agent_verbs grant")
        }
        UpdateIdleOutcome::Unexpected { detail } => {
            bail!("unexpected response to UpdateIdleTimeout: {detail}")
        }
    }
}

/// The classified outcome of an `UpdateIdleTimeout` RPC, split out so every
/// arm is testable without a live agent.
#[derive(Debug, PartialEq, Eq)]
enum UpdateIdleOutcome {
    Applied {
        previous_secs: u64,
        applied_secs: u64,
    },
    Denied {
        verb: String,
    },
    Unexpected {
        detail: String,
    },
}

fn classify_update_idle_response(resp: mvm_agentd::vsock::GuestResponse) -> UpdateIdleOutcome {
    use mvm_agentd::vsock::GuestResponse;
    match resp {
        GuestResponse::UpdateIdleTimeoutAck {
            previous_secs,
            applied_secs,
        } => UpdateIdleOutcome::Applied {
            previous_secs,
            applied_secs,
        },
        GuestResponse::VerbNotAuthorized { verb } => UpdateIdleOutcome::Denied { verb },
        other => UpdateIdleOutcome::Unexpected {
            detail: format!("{other:?}"),
        },
    }
}

fn parse_id(raw_id: &str) -> Result<SessionId> {
    SessionId::parse(raw_id).with_context(|| format!("Invalid session id: {raw_id:?}"))
}

type CallLocks = Mutex<HashMap<SessionId, Arc<Mutex<()>>>>;

fn call_locks() -> &'static CallLocks {
    static LOCKS: OnceLock<CallLocks> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The lock calls into `id` take their turn on.
fn call_lock(id: &SessionId) -> Arc<Mutex<()>> {
    let mut locks = call_locks().lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(locks.entry(id.clone()).or_default())
}

/// Drop a finished session's lock, so a long-lived process does not keep one
/// per session it ever touched.
fn forget_call_lock(id: &SessionId) {
    call_locks()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn isolated() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    fn running(vm: &str, mode: SessionMode) -> SessionRecord {
        let record = SessionRecord::new_running(vm, "wl", mode);
        session::write_session(&record).expect("write");
        record
    }

    #[test]
    fn dev_wire_adapter_preserves_binary_channels_and_requires_a_terminal() {
        use mvm_agentd::vsock::ExecEvent;
        let bytes = vec![0, 255, b'\n'];
        for event in [
            ExecEvent::Stdout {
                chunk: bytes.clone(),
            },
            ExecEvent::Stderr {
                chunk: bytes.clone(),
            },
        ] {
            let expected = match &event {
                ExecEvent::Stdout { chunk } => DevSessionOutput::Stdout(chunk.clone()),
                ExecEvent::Stderr { chunk } => DevSessionOutput::Stderr(chunk.clone()),
                _ => unreachable!(),
            };
            assert_eq!(dev_output(&event), Some(expected));
            assert!(dev_completion(event).is_err());
        }
        assert_eq!(dev_output(&ExecEvent::Exit { code: 9 }), None);
        assert_eq!(dev_output(&ExecEvent::TimedOut), None);
        assert_eq!(
            dev_completion(ExecEvent::Exit { code: 9 }).expect("exit"),
            DevSessionCompletion::Exited(9)
        );
        assert_eq!(
            dev_completion(ExecEvent::TimedOut).expect("timeout"),
            DevSessionCompletion::TimedOut
        );
    }

    #[test]
    fn dev_completions_count_nonzero_exits_and_timeouts_but_not_transport_errors() {
        let _home = isolated();
        let record = running("dev-counter", SessionMode::Dev);
        for (index, completion) in [
            DevSessionCompletion::Exited(0),
            DevSessionCompletion::Exited(7),
            DevSessionCompletion::TimedOut,
        ]
        .into_iter()
        .enumerate()
        {
            let got = dev_session_call(
                record.id.as_str(),
                "exec",
                LocalAuditKind::SessionExec,
                |current| {
                    assert_eq!(current.vm_name, record.vm_name);
                    Ok(completion)
                },
            )
            .expect("reported outcome");
            assert_eq!(got, completion);
            let updated = session_info(record.id.as_str()).expect("record");
            assert_eq!(updated.invoke_count, index as u64 + 1);
            assert!(updated.last_invoke_at.is_some());
        }
        dev_session_call(
            record.id.as_str(),
            "run-code",
            LocalAuditKind::SessionRunCode,
            |_| bail!("transport failed"),
        )
        .expect_err("transport error");
        assert_eq!(
            session_info(record.id.as_str())
                .expect("record")
                .invoke_count,
            3
        );
    }

    #[test]
    fn dev_session_gates_refuse_before_dispatch() {
        let _home = isolated();
        let record = running("prod-no-exec", SessionMode::Prod);
        let err = dev_session_call(
            record.id.as_str(),
            "exec",
            LocalAuditKind::SessionExec,
            |_| panic!("prod must not dispatch"),
        )
        .expect_err("prod refused");
        assert!(err.to_string().contains("mode=prod"));
        session::update_session(&record.id, |record| {
            record.mode = SessionMode::Dev;
            record.state = SessionState::Killed;
            Ok(())
        })
        .expect("update");
        let err = dev_session_call(
            record.id.as_str(),
            "run-code",
            LocalAuditKind::SessionRunCode,
            |_| panic!("killed must not dispatch"),
        )
        .expect_err("killed refused");
        assert!(err.to_string().contains("not running"));
        assert_eq!(
            session_info(record.id.as_str())
                .expect("record")
                .invoke_count,
            0
        );
    }

    #[test]
    fn development_calls_enforce_the_creator_gate() {
        let (mut env, _home) = isolated();
        let mut record = running("dev-other-creator", SessionMode::Dev);
        record.creator_pid = std::process::id().wrapping_add(1);
        session::write_session(&record).expect("write");
        env.set(session::STRICT_CREATOR_PID_ENV, "1");
        dev_session_call(
            record.id.as_str(),
            "exec",
            LocalAuditKind::SessionExec,
            |_| panic!("creator mismatch must not dispatch"),
        )
        .expect_err("creator gate");
        assert_eq!(
            session_info(record.id.as_str())
                .expect("record")
                .invoke_count,
            0
        );
    }

    #[test]
    fn empty_exec_is_refused_without_connecting() {
        let _home = isolated();
        let record = running("dev-empty", SessionMode::Dev);
        let err = exec_session(record.id.as_str(), Vec::new(), None, |_| {
            panic!("no output")
        })
        .expect_err("empty argv");
        assert!(err.to_string().contains("at least one argv"));
        assert_eq!(
            session_info(record.id.as_str())
                .expect("record")
                .invoke_count,
            0
        );
    }

    #[test]
    fn console_preparation_touches_without_counting_an_invocation() {
        let _home = isolated();
        let record = running("dev-console", SessionMode::Dev);
        prepare_console_session(record.id.as_str()).expect("dev console");
        let updated = session_info(record.id.as_str()).expect("record");
        assert!(updated.last_invoke_at.is_some());
        assert_eq!(updated.invoke_count, 0);
        let prod = running("prod-console", SessionMode::Prod);
        prepare_console_session(prod.id.as_str()).expect_err("prod console refused");
        assert!(
            session_info(prod.id.as_str())
                .expect("record")
                .last_invoke_at
                .is_none()
        );
    }

    #[test]
    fn sealed_console_refusal_does_not_touch_session_activity() {
        let _home = isolated();
        let record = running("sealed-dev-console", SessionMode::Dev);
        mvm_runtime::vm::runtime_meta::write(
            &record.vm_name,
            &mvm_runtime::vm::runtime_meta::VmRuntimeMeta {
                mode: mvm_runtime::vm::runtime_meta::StartModeKind::Detached,
                accessible: false,
                rootfs_path: None,
                runtime_overlay_version: None,
                observability_target: None,
            },
        )
        .expect("sealed metadata");
        let error = prepare_console_session(record.id.as_str()).expect_err("sealed console");
        assert!(error.to_string().contains("sealed image"));
        let unchanged = session_info(record.id.as_str()).expect("record");
        assert_eq!(unchanged.last_invoke_at, record.last_invoke_at);
        assert_eq!(unchanged.invoke_count, 0);
    }

    #[test]
    fn session_exec_retains_mediated_path_and_literal_argv() {
        use mvm_vmm::host::shell::shell_quote;
        let args = vec!["printf".into(), "it's $HOME; $(exit 1)".into()];
        let wrapper = session_exec_wrapper(&args);
        assert_eq!(
            wrapper,
            format!(
                "set -e\nexport PATH={}:\"$PATH\"\nexec 'bash' '-c' {}\n",
                shell_quote(mvm_core::guest_netd::MEDIATED_TOOLS_BIN),
                shell_quote("'printf' 'it'\\''s $HOME; $(exit 1)'"),
            )
        );
    }

    #[test]
    fn latest_and_list_select_only_running_for_continuation() {
        let _home = isolated();
        assert!(latest_running_session().is_err());
        let record = running("continue-dev", SessionMode::Dev);
        assert_eq!(latest_running_session().expect("running").id, record.id);
        assert_eq!(list_sessions().expect("list").len(), 1);
        session::update_session(&record.id, |record| {
            record.state = SessionState::Killed;
            Ok(())
        })
        .expect("update");
        assert!(latest_running_session().is_err());
        assert_eq!(list_sessions().expect("list").len(), 1);
    }

    #[test]
    fn idle_timeouts_of_zero_or_past_a_day_are_refused() {
        assert!(validate_idle_timeout(0).is_err());
        assert!(validate_idle_timeout(MAX_IDLE_TIMEOUT_SECS + 1).is_err());
        validate_idle_timeout(MAX_IDLE_TIMEOUT_SECS).expect("the ceiling itself is allowed");
        validate_idle_timeout(1).expect("one second is allowed");
    }

    #[test]
    fn info_on_an_unknown_id_says_so() {
        let _home = isolated();
        let error = session_info(SessionId::new().as_str()).expect_err("missing");
        assert!(error.to_string().contains("no session with id"));
    }

    #[test]
    fn a_malformed_id_is_refused() {
        let _home = isolated();
        let error = session_info("ABC").expect_err("malformed");
        assert!(error.to_string().contains("Invalid session id"));
    }

    #[test]
    fn a_killed_session_is_not_dispatchable() {
        let _home = isolated();
        let mut record = running("vm-k", SessionMode::Prod);
        session::update_session(&record.id, |r| {
            r.state = SessionState::Killed;
            Ok(())
        })
        .expect("mark killed");
        record.state = SessionState::Killed;
        let error = require_running_session(record.id.as_str()).expect_err("not running");
        assert!(error.to_string().contains("not running"));
    }

    #[test]
    fn killing_a_session_marks_it_killed() {
        let _home = isolated();
        let record = running("vm-kill-me", SessionMode::Prod);
        kill_session(record.id.as_str()).expect("killed");
        let reread = session_info(record.id.as_str()).expect("still recorded");
        assert_eq!(reread.state, SessionState::Killed);
        let again = kill_session(record.id.as_str()).expect_err("already killed");
        assert!(again.to_string().contains("cannot kill"));
    }

    #[test]
    fn setting_a_timeout_rewrites_the_record_even_when_the_agent_is_gone() {
        let _home = isolated();
        let record = running("vm-timeout", SessionMode::Prod);
        let update = set_session_idle_timeout(record.id.as_str(), 999).expect("updated");
        assert_eq!(update.record.idle_timeout_secs, 999);
        assert!(update.substrate.is_err(), "no agent is listening");
    }

    #[test]
    fn reaping_takes_only_expired_running_sessions() {
        let _home = isolated();
        let mut stale = SessionRecord::new_running("vm-stale", "wl", SessionMode::Prod);
        stale.idle_timeout_secs = 60;
        stale.started_at = (chrono::Utc::now() - chrono::Duration::seconds(900))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        session::write_session(&stale).expect("write");
        let fresh = running("vm-fresh", SessionMode::Prod);

        assert_eq!(reap_expired_sessions(), vec![stale.id.clone()]);
        assert_eq!(
            session_info(stale.id.as_str()).expect("read").state,
            SessionState::Reaped
        );
        assert_eq!(
            session_info(fresh.id.as_str()).expect("read").state,
            SessionState::Running
        );
    }

    #[test]
    fn reaping_seals_the_expired_sessions_audit_chain_like_a_stop() {
        let _home = isolated();
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let signer = mvm_hostd::audit::host_keypair::load_or_init().expect("host signer");
        let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing).expect("chain");
        emitter.emit_admitted(&plan, "host:test").expect("admitted");
        emitter.emit_launched(&plan, "mock").expect("launched");

        let mut stale = SessionRecord::new_running("vm-sealed", "wl", SessionMode::Prod);
        stale.idle_timeout_secs = 60;
        stale.started_at = (chrono::Utc::now() - chrono::Duration::seconds(900))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        session::write_session(&stale).expect("write");
        mvm_hostd::audit::plan_persist::write_plan("vm-sealed", &plan).expect("persist plan");

        assert_eq!(reap_expired_sessions(), vec![stale.id.clone()]);
        let chain = std::fs::read_to_string(mvm_hostd::audit::emitter::audit_path_for_tenant(
            &mvm_core::config::mvm_audit_dir(),
            &plan.tenant.0,
        ))
        .expect("chain");
        assert!(chain.contains("session.sealed"), "got: {chain}");
        assert!(chain.contains("\"stopped\""), "got: {chain}");
    }

    /// Admit `plan` on the host chain and persist it beside `vm`, as a
    /// session boot does.
    fn admitted_session_plan(vm: &str) -> mvm_core::plan::ExecutionPlan {
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let signer = mvm_hostd::audit::host_keypair::load_or_init().expect("host signer");
        let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing).expect("chain");
        emitter.emit_admitted(&plan, "host:test").expect("admitted");
        emitter.emit_launched(&plan, "mock").expect("launched");
        mvm_hostd::audit::plan_persist::write_plan(vm, &plan).expect("persist plan");
        plan
    }

    /// The seal reasons on `plan`'s session, from a verified chain.
    fn seal_reasons(
        plan: &mvm_core::plan::ExecutionPlan,
    ) -> Vec<mvm_hostd::audit::session::SealReason> {
        let signer = mvm_hostd::audit::host_keypair::load_or_init().expect("host signer");
        let report = mvm_hostd::audit::session::verify_session(
            &mvm_core::config::mvm_audit_dir(),
            &plan.tenant.0,
            &plan.plan_id.0,
            &signer.verifying,
        );
        assert_eq!(
            report.verdict,
            mvm_hostd::audit::session::Verdict::Verified,
            "{report:?}"
        );
        report.seals.iter().map(|check| check.seal.reason).collect()
    }

    #[test]
    fn killing_a_session_seals_its_audit_chain_as_stopped() {
        let _home = isolated();
        let plan = admitted_session_plan("vm-killed-sealed");
        let record = running("vm-killed-sealed", SessionMode::Prod);

        kill_session(record.id.as_str()).expect("killed");

        assert_eq!(
            seal_reasons(&plan),
            vec![mvm_hostd::audit::session::SealReason::Stopped]
        );
    }

    #[test]
    fn a_session_whose_vm_would_not_stop_is_left_unsealed() {
        let _home = isolated();
        let plan = admitted_session_plan("vm-wont-stop");

        end_session_vm_with("vm-wont-stop", |_| Err(anyhow::anyhow!("still running")));

        let signer = mvm_hostd::audit::host_keypair::load_or_init().expect("host signer");
        let report = mvm_hostd::audit::session::verify_session(
            &mvm_core::config::mvm_audit_dir(),
            &plan.tenant.0,
            &plan.plan_id.0,
            &signer.verifying,
        );
        assert_eq!(
            report.verdict,
            mvm_hostd::audit::session::Verdict::Unsealed,
            "{report:?}"
        );
        let chain = std::fs::read_to_string(mvm_hostd::audit::emitter::audit_path_for_tenant(
            &mvm_core::config::mvm_audit_dir(),
            &plan.tenant.0,
        ))
        .expect("chain");
        assert!(chain.contains("plan.teardown_failed"), "{chain}");
        assert!(chain.contains("stop-failed"), "{chain}");
        assert!(chain.contains("still running"), "{chain}");
    }

    #[test]
    fn a_session_with_no_persisted_plan_records_why_it_has_no_seal() {
        let _home = isolated();
        let plan = admitted_session_plan("vm-other");
        let record = running("vm-no-plan", SessionMode::Prod);

        kill_session(record.id.as_str()).expect("killed");

        let chain = std::fs::read_to_string(mvm_hostd::audit::emitter::audit_path_for_tenant(
            &mvm_core::config::mvm_audit_dir(),
            &plan.tenant.0,
        ))
        .expect("chain");
        assert!(
            !chain.contains("session.sealed"),
            "nothing to bind a seal to: {chain}"
        );
        let local =
            std::fs::read_to_string(mvm_core::audit::default_audit_log()).expect("local audit log");
        assert!(local.contains("session_unsealed"), "{local}");
        assert!(local.contains("no-verified-plan"), "{local}");
    }

    #[test]
    fn the_creator_gate_refuses_another_process_only_when_enabled() {
        let (mut env, _home) = isolated();
        let mut record = SessionRecord::new_running("vm", "wl", SessionMode::Prod);
        record.creator_pid = std::process::id().wrapping_add(1);
        enforce_creator_pid_gate(&record.id, &record).expect("off by default");
        env.set(session::STRICT_CREATOR_PID_ENV, "1");
        let error = enforce_creator_pid_gate(&record.id, &record).expect_err("refused");
        assert!(error.to_string().contains("created by pid"));
        record.creator_pid = 0;
        enforce_creator_pid_gate(&record.id, &record).expect("an unknown creator is not gated");
    }

    #[test]
    fn calls_into_one_session_share_one_lock() {
        let id = SessionId::new();
        let first = call_lock(&id);
        let second = call_lock(&id);
        assert!(Arc::ptr_eq(&first, &second));
        forget_call_lock(&id);
        assert!(!Arc::ptr_eq(&first, &call_lock(&id)));
        forget_call_lock(&id);
    }

    #[test]
    fn a_call_into_a_session_whose_vm_is_gone_fails_and_leaves_the_count() {
        let _home = isolated();
        let record = running("vm-gone", SessionMode::Prod);
        let mut observer = super::super::dispatch::CapturedOutput::default();
        let error = call_session(&record.id, &record, Vec::new(), 1, &mut observer)
            .expect_err("no VM to dispatch into");
        assert!(format!("{error:#}").contains("dispatching into session"));
        assert_eq!(
            session_info(record.id.as_str()).expect("read").invoke_count,
            0
        );
    }

    #[test]
    fn the_update_idle_response_classifies_every_arm() {
        use mvm_agentd::vsock::GuestResponse;
        assert_eq!(
            classify_update_idle_response(GuestResponse::UpdateIdleTimeoutAck {
                previous_secs: 10,
                applied_secs: 20,
            }),
            UpdateIdleOutcome::Applied {
                previous_secs: 10,
                applied_secs: 20
            }
        );
        assert_eq!(
            classify_update_idle_response(GuestResponse::VerbNotAuthorized {
                verb: "update-idle-timeout".into(),
            }),
            UpdateIdleOutcome::Denied {
                verb: "update-idle-timeout".into()
            }
        );
        let UpdateIdleOutcome::Unexpected { detail } =
            classify_update_idle_response(GuestResponse::Pong)
        else {
            panic!("a Pong is unexpected");
        };
        assert!(detail.contains("Pong"));
    }
}
