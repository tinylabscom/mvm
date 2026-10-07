//! Booting an admitted entrypoint VM, and running one call in it.
//!
//! [`boot_entrypoint_vm`] is the one boot a transient call and a session start
//! share: the plan is admitted, `plan.launched` or `plan.failed` is written
//! against it, and the booted VM comes back holding the admission so a
//! streamed stdin can be opened under the very plan it booted with.
//! [`run_entrypoint_call`] adds the rest of a transient call: a session record
//! so the call is visible while it runs, the agent wait, the dispatch, and the
//! teardown or the keep-alive.

use std::cell::RefCell;

use anyhow::{Context, Result};
use mvm_core::session::{SessionId, SessionMode};

use super::admission::EntrypointAdmission;
use super::boot::{
    AdmitInputs, SessionAuditSubstrate, SessionBoot, SessionVm, SessionVmName, boot_session_vm,
    stop_session_vm, tear_down_session_vm,
};
use super::dispatch::{
    CallObserver, CallOutcome, CallStdin, CallTerminal, EntrypointDispatch, authorize_stdin,
    dispatch,
};
use crate::admission::{AdmissionContext, emit_failed, emit_launched};
use crate::launch::runtime_source::PairArtifactSource;
use crate::launch::{
    TransientEnd, UnsealedEnd, UnsealedReason, record_unsealed_end, seal_transient_end,
};

/// How long a freshly booted VM's agent has to answer.
pub const AGENT_WAIT_SECS: u64 = 30;

/// What an entrypoint VM boots from and under.
pub struct EntrypointVm<'a> {
    /// The built workload slot.
    pub slot: &'a str,
    /// How the VM is named.
    pub vm_name: SessionVmName<'a>,
    /// vCPUs.
    pub cpus: u32,
    /// Guest memory, MiB.
    pub memory_mib: u32,
    /// The admission policy; its backend is the one booted on.
    pub admission: EntrypointAdmission,
}

/// A booted entrypoint VM and the admission it booted under.
pub struct BootedEntrypoint {
    /// The running VM.
    pub vm: SessionVm,
    /// The admitted plan and its audit emitter.
    pub admission: AdmissionContext,
}

impl BootedEntrypoint {
    /// Wait for the guest agent to answer. On a timeout the VM is torn down
    /// and `plan.failed` is written against its plan: a VM whose agent never
    /// came up is unusable, and leaving it would leave dead state behind.
    ///
    /// # Errors
    /// The agent did not answer within `timeout_secs`.
    pub fn await_agent(&self, timeout_secs: u64) -> Result<()> {
        if crate::readiness::wait_for_guest_agent(&self.vm.vm_name, timeout_secs) {
            return Ok(());
        }
        let err = anyhow::anyhow!("guest agent did not become reachable within {timeout_secs}s");
        let vm = self.vm.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tear_down_session_vm(vm);
        }));
        emit_failed(&self.admission, "agent-wait", &err);
        Err(err)
    }
}

/// Boot `vm` under its admission, writing `plan.launched` when the backend
/// started and `plan.failed` when it did not.
///
/// # Errors
/// Anything the admission or the boot refuses.
pub fn boot_entrypoint_vm(
    vm: EntrypointVm<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<BootedEntrypoint> {
    let EntrypointVm {
        slot,
        vm_name,
        cpus,
        memory_mib,
        admission,
    } = vm;
    let backend_name = admission.backend_name().to_string();
    let admitted: RefCell<Option<AdmissionContext>> = RefCell::new(None);
    let admit = |inputs: AdmitInputs<'_>| -> Result<Option<SessionAuditSubstrate>> {
        let entry = admission.admit(inputs)?;
        *admitted.borrow_mut() = Some(entry.context);
        Ok(Some(entry.substrate))
    };
    let boot = SessionBoot::builder(slot, vm_name)
        .cpus(cpus)
        .memory_mib(memory_mib)
        .network_policy(admission.network_policy().clone())
        .backend_name(&backend_name)
        .build();
    match boot_session_vm(boot, &admit, pair) {
        Ok(vm) => {
            let Some(context) = admitted.borrow_mut().take() else {
                // The boot refuses an unadmitted plan, so this cannot happen;
                // a VM with no plan to bind its narrative to is torn down
                // rather than handed back.
                tear_down_session_vm(vm);
                anyhow::bail!("the entrypoint VM booted without an admitted plan");
            };
            emit_launched(&context, &backend_name, true);
            Ok(BootedEntrypoint {
                vm,
                admission: context,
            })
        }
        Err(e) => {
            if let Some(context) = admitted.borrow_mut().take() {
                emit_failed(&context, "backend-start", &e);
            }
            Err(e)
        }
    }
}

/// Whether a call's VM outlives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallLifecycle {
    /// Torn down when the call ends.
    Transient,
    /// Left running under a session the caller reuses and reaps.
    KeepAlive {
        /// The mode the session is recorded under; `Dev` admits the dev-only
        /// session verbs.
        mode: SessionMode,
    },
}

/// One transient entrypoint call.
pub struct EntrypointCall<'a> {
    /// What the VM boots from and under. Its admission's stdin grant is set
    /// from `stdin`, so the two cannot disagree.
    pub vm: EntrypointVm<'a>,
    /// What reaches the workload's stdin.
    pub stdin: CallStdin,
    /// Wall-clock kill window for the call.
    pub timeout_secs: u64,
    /// Whether the VM outlives the call.
    pub lifecycle: CallLifecycle,
}

/// Boot a VM, dispatch one call into it, and tear it down (or keep it alive).
///
/// A session record is registered for the call's lifetime so `session ls`
/// sees it, and a transport drop coincident with a `session kill` is reported
/// as the kill. A transient call's audit session ends with its VM: once the VM
/// is stopped, `plan.exited` and a seal are written under the admitted plan
/// (see [`CallEnd`]). A kept-alive call keeps the record, writes a `SessionStart`
/// audit entry, and tells the observer which VM and session it left running —
/// even when the call itself failed, because the VM is still there.
///
/// # Errors
/// A refused admission or boot, an agent that never answered, or a failed
/// dispatch — the last only after the VM has been torn down or kept alive.
pub fn run_entrypoint_call(
    call: EntrypointCall<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
    observer: &mut dyn CallObserver,
) -> Result<CallOutcome> {
    let EntrypointCall {
        mut vm,
        stdin,
        timeout_secs,
        lifecycle,
    } = call;
    let streams_stdin = stdin.is_streaming();
    vm.admission = vm.admission.with_stream_stdin(streams_stdin);
    let slot = vm.slot;
    let backend_name = vm.admission.backend_name().to_string();
    let named = vm.vm_name.resolve();
    observer.vm_named(&named);
    let booted = boot_entrypoint_vm(
        EntrypointVm {
            slot: vm.slot,
            vm_name: SessionVmName::Exact(&named),
            cpus: vm.cpus,
            memory_mib: vm.memory_mib,
            admission: vm.admission,
        },
        pair,
    )?;
    let vm_name = booted.vm.vm_name.clone();

    let mode = match lifecycle {
        CallLifecycle::Transient => SessionMode::Prod,
        CallLifecycle::KeepAlive { mode } => mode,
    };
    let session_id = register_call_session(&vm_name, slot, mode);
    if let Err(e) = booted.await_agent(AGENT_WAIT_SECS) {
        deregister_call_session(session_id.as_ref());
        return Err(e);
    }

    // The admitted plan is borrowed across the dispatch because a streamed
    // stdin is opened under it: the gate takes the proof-carrying type, so the
    // authority for every byte written is the plan this boot was admitted
    // under.
    let dispatch_stdin = match authorize_stdin(stdin, Some(&booted.admission.admitted)) {
        Ok(stdin) => stdin,
        Err(refusal) => {
            end_transient_call(&booted, &backend_name, CallEnd::NOT_RUN);
            deregister_call_session(session_id.as_ref());
            return Err(refusal);
        }
    };
    observer.dispatching(&vm_name, streams_stdin);
    let result = dispatch(
        EntrypointDispatch {
            vm_name: &vm_name,
            stdin: dispatch_stdin,
            timeout_secs,
            session_id: session_id.as_ref(),
        },
        observer,
    );
    observer.dispatched();

    match lifecycle {
        CallLifecycle::KeepAlive { mode } => {
            if let Some(id) = session_id.as_ref() {
                bump_invoke_count(id);
                mvm_core::audit_emit!(
                    SessionStart,
                    vm: &vm_name,
                    "session={id},template={slot},mode={mode},kept_alive=true"
                );
            }
            observer.kept_alive(&vm_name, session_id.as_ref());
        }
        CallLifecycle::Transient => {
            end_transient_call(&booted, &backend_name, CallEnd::of(&result));
            deregister_call_session(session_id.as_ref());
        }
    }
    result
}

/// How a transient call ended, as the host observed it. Only a workload that
/// exited has an exit code; a call that failed, timed out, was killed or never
/// reached the workload records none, so it can never read as exit 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallEnd {
    exit_code: Option<i32>,
    completed: bool,
}

impl CallEnd {
    /// A call refused before anything was dispatched.
    const NOT_RUN: Self = Self {
        exit_code: None,
        completed: false,
    };

    fn of(result: &Result<CallOutcome>) -> Self {
        match result {
            Ok(CallOutcome {
                terminal: CallTerminal::Exited { code },
                ..
            }) => Self {
                exit_code: Some(*code),
                completed: true,
            },
            Ok(_) | Err(_) => Self::NOT_RUN,
        }
    }
}

/// Stop a transient call's VM, then close its audit session. A VM whose stop
/// failed may still be running, so its session is left open rather than
/// sealed over a guest that can still act.
fn end_transient_call(booted: &BootedEntrypoint, backend: &str, end: CallEnd) {
    if let Err(e) = stop_session_vm(&booted.vm) {
        record_unsealed_end(
            Some((&booted.admission.emitter, booted.admission.admitted.plan())),
            UnsealedEnd::new(&booted.vm.vm_name, UnsealedReason::StopFailed)
                .error(format!("{e:#}")),
        );
        return;
    }
    close_call_session(&booted.admission, &booted.vm.vm_name, backend, end);
}

/// Write `plan.exited` and the seal for a stopped transient call, under the
/// plan it was admitted with. Best-effort: the call already happened, and a
/// session that could not be sealed is reported `UNSEALED` by
/// `trust audit verify` rather than failing the call. `seal_transient_end`
/// records why it could not seal, so the error is not reported again here.
fn close_call_session(ctx: &AdmissionContext, vm_name: &str, backend: &str, end: CallEnd) {
    let _ = seal_transient_end(
        &ctx.emitter,
        ctx.admitted.plan(),
        TransientEnd {
            vm_name,
            backend,
            exit_code: end.exit_code,
            completed: end.completed,
        },
    );
}

/// Register a session record for a call. `None` when the record could not be
/// written: the call still runs, it just is not visible to `session ls`.
fn register_call_session(vm_name: &str, workload_id: &str, mode: SessionMode) -> Option<SessionId> {
    let record = mvm_core::session::SessionRecord::new_running(vm_name, workload_id, mode);
    let id = record.id.clone();
    match mvm_core::session::write_session(&record) {
        Ok(()) => Some(id),
        Err(e) => {
            tracing::warn!(err = %e, "failed to register entrypoint call session");
            None
        }
    }
}

/// Remove a call's session record — unless something already moved it off
/// `Running` (a kill or a reap), in which case it stays so an observer can see
/// how the lifecycle ended.
fn deregister_call_session(id: Option<&SessionId>) {
    let Some(id) = id else { return };
    match mvm_core::session::read_session(id) {
        Ok(Some(rec)) if rec.state == mvm_core::session::SessionState::Running => {
            if let Err(e) = mvm_core::session::remove_session(id) {
                tracing::warn!(err = %e, "failed to remove entrypoint call session record");
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(err = %e, "failed to read entrypoint call session record");
        }
    }
}

/// Count one more call against a session and stamp when it happened.
pub(crate) fn bump_invoke_count(id: &SessionId) {
    if let Err(e) = mvm_core::session::update_session(id, |r| {
        r.invoke_count = r.invoke_count.saturating_add(1);
        r.last_invoke_at = Some(rfc3339_now());
        Ok(())
    }) {
        tracing::warn!(err = %e, "failed to bump session invoke counter");
    }
}

pub(crate) fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Resolve the backend name an entrypoint boot runs on.
///
/// # Errors
/// A hypervisor this host cannot select.
pub fn backend_name_for(hypervisor: Option<&str>) -> Result<String> {
    Ok(super::boot::resolve_backend(hypervisor)
        .context("selecting the backend for the entrypoint VM")?
        .name()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::session::SessionState;
    use mvm_core::util::test_env::TestEnv;
    use mvm_hostd::stream::ShownChunk;

    #[derive(Default)]
    struct NamingObserver {
        named: Vec<String>,
    }

    impl CallObserver for NamingObserver {
        fn vm_named(&mut self, vm_name: &str) {
            self.named.push(vm_name.to_string());
        }

        fn output(&mut self, _chunk: &ShownChunk) {}

        fn control(&mut self, _header: &str, _payload_len: usize) {}
    }

    fn isolated() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    #[test]
    fn a_call_session_is_registered_running_and_removed_after() {
        let _home = isolated();
        let id = register_call_session("call-vm", "slot", SessionMode::Prod).expect("registered");
        let record = mvm_core::session::read_session(&id)
            .expect("read")
            .expect("present");
        assert_eq!(record.state, SessionState::Running);
        deregister_call_session(Some(&id));
        assert!(
            mvm_core::session::read_session(&id)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_killed_call_session_keeps_its_record() {
        let _home = isolated();
        let id = register_call_session("call-vm", "slot", SessionMode::Prod).expect("registered");
        mvm_core::session::update_session(&id, |r| {
            r.state = SessionState::Killed;
            Ok(())
        })
        .expect("mark killed");
        deregister_call_session(Some(&id));
        assert!(
            mvm_core::session::read_session(&id)
                .expect("read")
                .is_some(),
            "an observer must still see how the lifecycle ended"
        );
    }

    #[test]
    fn bumping_a_session_counts_the_call_and_stamps_it() {
        let _home = isolated();
        let id = register_call_session("call-vm", "slot", SessionMode::Prod).expect("registered");
        bump_invoke_count(&id);
        let record = mvm_core::session::read_session(&id)
            .expect("read")
            .expect("present");
        assert_eq!(record.invoke_count, 1);
        assert!(record.last_invoke_at.is_some());
    }

    #[test]
    fn a_call_into_an_unknown_slot_fails_before_any_vm_exists() {
        let _home = isolated();
        let slot = "f".repeat(64);
        let admission = EntrypointAdmission::builder("mock")
            .build()
            .expect("admission");
        let mut observer = NamingObserver::default();
        let error = run_entrypoint_call(
            EntrypointCall {
                vm: EntrypointVm {
                    slot: &slot,
                    vm_name: SessionVmName::Prefixed("invoke"),
                    cpus: 1,
                    memory_mib: 256,
                    admission,
                },
                stdin: CallStdin::OneShot(b"[[], {}]".to_vec()),
                timeout_secs: 5,
                lifecycle: CallLifecycle::Transient,
            },
            None,
            &mut observer,
        )
        .expect_err("nothing to boot");
        assert!(
            format!("{error:#}").contains("Loading template"),
            "{error:#}"
        );
        assert_eq!(observer.named.len(), 1);
        assert!(
            observer.named[0].starts_with("invoke-"),
            "the final generated name must be known before boot fails"
        );
        assert!(
            mvm_core::session::list_sessions().expect("list").is_empty(),
            "a call that never booted registers nothing"
        );
    }

    /// The session `trust audit verify <session>` would report for `ctx`.
    fn session_report(
        ctx: &AdmissionContext,
        audit_dir: &std::path::Path,
    ) -> mvm_hostd::audit::session::SessionVerification {
        mvm_hostd::audit::session::verify_session(
            audit_dir,
            "local",
            &ctx.admitted.plan().plan_id.0,
            &ctx.emitter.verifying_key(),
        )
    }

    /// The single seal on `ctx`'s session, failing unless it verifies.
    fn only_seal(
        ctx: &AdmissionContext,
        audit_dir: &std::path::Path,
    ) -> mvm_hostd::audit::session::SessionSeal {
        let report = session_report(ctx, audit_dir);
        assert_eq!(
            report.verdict,
            mvm_hostd::audit::session::Verdict::Verified,
            "{report:?}"
        );
        assert_eq!(report.late_entries, 0, "the seal covers the whole call");
        let [check] = report.seals.as_slice() else {
            panic!("exactly one seal: {:?}", report.seals);
        };
        check.seal.clone()
    }

    fn exited(code: i32) -> Result<CallOutcome> {
        Ok(CallOutcome {
            terminal: CallTerminal::Exited { code },
            capture: None,
        })
    }

    #[test]
    fn only_a_workload_exit_carries_an_exit_code() {
        assert_eq!(
            CallEnd::of(&exited(3)),
            CallEnd {
                exit_code: Some(3),
                completed: true
            }
        );
        let timed_out = Ok(CallOutcome {
            terminal: CallTerminal::Failed {
                kind: mvm_agentd::vsock::RunEntrypointError::Timeout,
                message: "timed out".to_string(),
            },
            capture: None,
        });
        assert_eq!(CallEnd::of(&timed_out), CallEnd::NOT_RUN);
        assert_eq!(
            CallEnd::of(&Err(anyhow::anyhow!("transport dropped"))),
            CallEnd::NOT_RUN
        );
    }

    #[test]
    fn an_entrypoint_call_exit_is_sealed_from_its_admitted_plan() {
        let _home = isolated();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let ctx = crate::admission::admit_plan_tests::admitted_into(
            keys_dir.path(),
            audit_dir.path(),
            "invoke-exit",
        );
        emit_launched(&ctx, "firecracker", true);

        close_call_session(&ctx, "invoke-exit", "firecracker", CallEnd::of(&exited(0)));

        let seal = only_seal(&ctx, audit_dir.path());
        assert_eq!(seal.reason, mvm_hostd::audit::session::SealReason::Exited);
        assert_eq!(seal.exit_code.as_deref(), Some("0"));
        let audit = std::fs::read_to_string(audit_dir.path().join("local.jsonl")).expect("chain");
        assert!(audit.contains("plan.exited"), "{audit}");
        assert!(audit.contains("\"backend\":\"firecracker\""), "{audit}");
    }

    #[test]
    fn a_failed_entrypoint_call_is_never_sealed_as_exit_zero() {
        let _home = isolated();
        let failures: [(&str, Result<CallOutcome>); 2] = [
            (
                "invoke-timeout",
                Ok(CallOutcome {
                    terminal: CallTerminal::Failed {
                        kind: mvm_agentd::vsock::RunEntrypointError::Timeout,
                        message: "timed out".to_string(),
                    },
                    capture: None,
                }),
            ),
            ("invoke-error", Err(anyhow::anyhow!("transport dropped"))),
        ];
        for (vm_name, result) in failures {
            let keys_dir = tempfile::tempdir().expect("keys dir");
            let audit_dir = tempfile::tempdir().expect("audit dir");
            let ctx = crate::admission::admit_plan_tests::admitted_into(
                keys_dir.path(),
                audit_dir.path(),
                vm_name,
            );
            emit_launched(&ctx, "firecracker", true);

            close_call_session(&ctx, vm_name, "firecracker", CallEnd::of(&result));

            let seal = only_seal(&ctx, audit_dir.path());
            assert_eq!(
                seal.reason,
                mvm_hostd::audit::session::SealReason::Failed,
                "{vm_name}"
            );
            assert_ne!(seal.exit_code.as_deref(), Some("0"), "{vm_name}");
            let audit =
                std::fs::read_to_string(audit_dir.path().join("local.jsonl")).expect("chain");
            assert!(audit.contains("\"exit_code\":\"none\""), "{audit}");
            assert!(!audit.contains("\"exit_code\":\"0\""), "{audit}");
        }
    }

    #[test]
    fn an_unselectable_hypervisor_is_refused_by_name() {
        let error = backend_name_for(Some("docker")).expect_err("refused");
        assert!(format!("{error:#}").contains("selecting the backend"));
    }
}
