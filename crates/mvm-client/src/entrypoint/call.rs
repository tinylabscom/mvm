//! Booting an admitted entrypoint VM, and running one call in it.
//!
//! [`boot_entrypoint_vm`] is the one boot a transient call and a session start
//! share: the plan is admitted, `plan.launched` or `plan.failed` is written
//! against it, and the booted VM comes back holding the admission so a
//! streamed stdin can be opened under the very plan it booted with.
//! [`run_entrypoint_call`] adds the rest of a transient call: a session record
//! so the call is visible while it runs, the agent wait, the dispatch, and the
//! teardown or the keep-alive.
//!
//! Native foreground calls retain [`OwnedTransientResult`] from preparation
//! through dispatch, original-owner quiescence, and audit closure. Only
//! [`OwnedTransientResult::projection`] exposes completed output. Keep the
//! entire result on failure; observer housekeeping is not a completion proof.

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
    /// Producer-owned release inputs for health. Ordinary consumers leave this
    /// unset and may not use it to repair an incomplete installed archive.
    pub portable_boot_assets: Option<&'a crate::portable_boot_assets::PreparedPortableBootAssets>,
}

/// A booted entrypoint VM and the admission it booted under.
pub struct BootedEntrypoint {
    /// The running VM.
    pub vm: SessionVm,
    /// The admitted plan and its audit emitter.
    pub admission: AdmissionContext,
}

/// Caller-owned host result, retained before any ABI/JSON mapping. A failed
/// stop never replaces the original outcome or drops its original owner.
/// This is resource custody, not a dispatch certificate or helper permit.
pub struct OwnedTransientResult<O = ()> {
    custody: Option<Box<TransientCustody<O>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeAuditClosure {
    Unattempted,
    Attempted,
    Complete,
}

struct TransientCustody<O> {
    observer: O,
    outcome: Option<CallOutcome>,
    call_error: Option<anyhow::Error>,
    flush_error: Option<anyhow::Error>,
    stop_error: Option<anyhow::Error>,
    cleanup_error: Option<anyhow::Error>,
    owner: Option<super::boot::OwnedClientBoot>,
    completion: Option<mvm_runtime::workload_runner::runner::NativeCompletion>,
    native_audit: NativeAuditClosure,
    legacy_terminal: bool,
    stopped: bool,
    started: bool,
}

impl<O> OwnedTransientResult<O> {
    pub fn prepare(observer: O) -> Self {
        Self {
            custody: Some(Box::new(TransientCustody {
                observer,
                outcome: None,
                call_error: None,
                flush_error: None,
                stop_error: None,
                cleanup_error: None,
                owner: None,
                completion: None,
                native_audit: NativeAuditClosure::Unattempted,
                legacy_terminal: false,
                stopped: true,
                started: false,
            })),
        }
    }

    pub fn outcome(&self) -> Option<&CallOutcome> {
        self.custody.as_ref()?.outcome.as_ref()
    }
    pub fn call_error(&self) -> Option<&anyhow::Error> {
        self.custody.as_ref()?.call_error.as_ref()
    }
    pub fn flush_error(&self) -> Option<&anyhow::Error> {
        self.custody.as_ref()?.flush_error.as_ref()
    }
    pub fn stop_error(&self) -> Option<&anyhow::Error> {
        self.custody.as_ref()?.stop_error.as_ref()
    }
    pub fn cleanup_error(&self) -> Option<&anyhow::Error> {
        self.custody.as_ref()?.cleanup_error.as_ref()
    }

    /// Retain the typed failed boot and its original uncertain owner.
    pub fn boot_failure(&self) -> Option<&super::boot::OwnedBootFailure> {
        self.call_error()?.downcast_ref()
    }

    /// Housekeeping access only; this cannot supply a completion witness.
    pub fn observer_mut(&mut self) -> Result<&mut O> {
        Ok(&mut self
            .custody
            .as_mut()
            .context("invocation already consumed")?
            .observer)
    }

    pub fn fail_preparation(&mut self, error: anyhow::Error) {
        if let Some(group) = self.custody.as_mut()
            && !group.started
        {
            group.started = true;
            group.call_error = Some(error);
        }
    }

    /// Observation only: these labels never identify or reconstruct an owner.
    pub fn recovery_details(&self) -> Option<(String, String)> {
        let group = self.custody.as_ref()?;
        if group.stopped {
            return None;
        }
        let resources = group.owner.as_ref()?.resources();
        Some((
            resources.config.name.clone(),
            resources.admission.admitted.plan_id().0.clone(),
        ))
    }

    /// Copies may be rendered only after the native owner's completion
    /// witness, never from a successful transport Result or caller status.
    pub fn projection(&self) -> Result<(&CallOutcome, &O)> {
        let group = self
            .custody
            .as_ref()
            .context("invocation already consumed")?;
        anyhow::ensure!(
            (group.completion.is_some() && group.native_audit == NativeAuditClosure::Complete)
                || group.legacy_terminal,
            "output is retained: original completion remains unconfirmed"
        );
        anyhow::ensure!(
            group.call_error.is_none()
                && group.flush_error.is_none()
                && group.stop_error.is_none()
                && group.cleanup_error.is_none(),
            "invocation failed; original errors remain retained"
        );
        Ok((
            group.outcome.as_ref().context("no completed call result")?,
            &group.observer,
        ))
    }

    pub fn succeeded(&self) -> bool {
        self.projection()
            .is_ok_and(|(outcome, _)| matches!(outcome.terminal, CallTerminal::Exited { code: 0 }))
    }

    pub fn close(&mut self) -> Result<()> {
        let group = self
            .custody
            .as_mut()
            .context("invocation already consumed")?;
        if let Some(failure) = group
            .call_error
            .as_mut()
            .and_then(|error| error.downcast_mut::<super::boot::OwnedBootFailure>())
        {
            failure.retry_stop()?;
        }
        if !group.stopped {
            if let Some(owner) = group.owner.as_mut()
                && let Err(error) = owner.quiesce()
            {
                retain_cleanup_error(group, error);
                anyhow::bail!("original owner cleanup remains unconfirmed");
            }
            group.stopped = true;
        }
        close_native_audit(group);
        Ok(())
    }

    pub fn retry_stop(&mut self) -> Result<()> {
        let group = self
            .custody
            .as_mut()
            .context("transient custody already consumed")?;
        if group.stopped {
            return self.close();
        }
        if let Some(owner) = group.owner.as_mut()
            && group.flush_error.is_none()
            && group.outcome.is_some()
        {
            match owner.complete() {
                Ok(completion) => {
                    let matches = group.outcome.as_ref().is_some_and(|outcome| {
                        outcome.terminal == CallTerminal::from_event(completion.terminal())
                    });
                    group.completion = Some(completion);
                    group.stopped = true;
                    if !matches {
                        if group.call_error.is_none() {
                            group.call_error = Some(anyhow::anyhow!(
                                "call result differs from original native terminal"
                            ));
                        }
                        close_native_audit(group);
                        anyhow::bail!("call result differs from original native terminal");
                    }
                    close_native_audit(group);
                    return Ok(());
                }
                Err(error) => {
                    retain_cleanup_error(group, error);
                    anyhow::bail!("original completion remains unconfirmed");
                }
            }
        }
        self.close()
    }

    /// No data-only conversion while native custody or an unresolved error
    /// would be lost. The host caller receives the whole object back.
    pub fn into_terminal_outcome(mut self) -> std::result::Result<CallOutcome, Self> {
        let Some(group) = self.custody.as_mut() else {
            return Err(self);
        };
        if group.completion.is_none()
            || group.native_audit != NativeAuditClosure::Complete
            || group.call_error.is_some()
            || group.flush_error.is_some()
            || group.stop_error.is_some()
            || group.cleanup_error.is_some()
        {
            return Err(self);
        }
        match group.outcome.take() {
            Some(outcome) => Ok(outcome),
            None => Err(self),
        }
    }
}

impl<O> Drop for OwnedTransientResult<O> {
    fn drop(&mut self) {
        if let Some(mut group) = self.custody.take()
            && let Some(owner) = group.owner.take()
            && let Err(owner) = owner.release_if_child_free()
        {
            group.owner = Some(owner);
            // Abandonment is not recovery. Keep the actual output, every
            // original error and the entire native/client group together.
            std::mem::forget(group);
        }
    }
}

fn retain_cleanup_error<O>(group: &mut TransientCustody<O>, error: anyhow::Error) {
    group.cleanup_error = Some(if let Some(prior) = group.cleanup_error.take() {
        error.context(prior)
    } else {
        error
    });
}

fn close_native_audit<O>(group: &mut TransientCustody<O>) {
    if !group.stopped || group.native_audit != NativeAuditClosure::Unattempted {
        return;
    }
    let Some(owner) = group.owner.as_ref() else {
        // Boot failures retain their own deferred failure audit.
        return;
    };
    let resources = owner.resources();
    let ctx = &resources.admission;
    let matching_completion = group.completion.as_ref().is_some_and(|proof| {
        group
            .outcome
            .as_ref()
            .is_some_and(|outcome| outcome.terminal == CallTerminal::from_event(proof.terminal()))
    });
    if !matching_completion
        && group.call_error.is_none()
        && group.flush_error.is_none()
        && group.stop_error.is_none()
        && group.cleanup_error.is_none()
    {
        group.call_error = Some(anyhow::anyhow!(
            "native audit closure has no matching original completion"
        ));
    }
    // An append/seal error can be ambiguous. Never retry it blindly.
    group.native_audit = NativeAuditClosure::Attempted;
    let failure = group
        .call_error
        .as_ref()
        .or(group.flush_error.as_ref())
        .or(group.stop_error.as_ref())
        .or(group.cleanup_error.as_ref());
    let closure = if let Some(error) = failure {
        ctx.emitter.batched(|| {
            ctx.emitter.emit_failed(
                ctx.admitted.plan(),
                "native-entrypoint",
                &format!("{error:#}"),
            )?;
            ctx.emitter.seal_session(
                ctx.admitted.plan(),
                mvm_hostd::audit::session::SealReason::Failed,
            )?;
            ctx.emitter.publish_root(&ctx.admitted.plan().tenant.0)?;
            Ok(())
        })
    } else {
        // Session closure owns its batch; record the completion before it.
        (|| {
            ctx.emitter.emit_native_completed(
                ctx.admitted.plan(),
                group
                    .completion
                    .as_ref()
                    .context("original native completion missing")?,
            )?;
            close_call_session_checked(
                ctx,
                &resources.config.name,
                resources.backend.name(),
                CallEnd::of(
                    &group
                        .outcome
                        .clone()
                        .context("native call returned no outcome"),
                ),
            )
        })()
    };
    match closure {
        Ok(()) => group.native_audit = NativeAuditClosure::Complete,
        Err(error) => {
            retain_cleanup_error(group, error);
        }
    }
}

trait FinalizeOperations {
    fn sync(&mut self) -> Result<()>;
    fn complete_original(
        &mut self,
    ) -> Result<Option<mvm_runtime::workload_runner::runner::NativeCompletion>>;
    fn quiesce_original(&mut self) -> Result<()>;
}

impl FinalizeOperations for super::boot::OwnedClientBoot {
    fn sync(&mut self) -> Result<()> {
        self.finalize_readonly_entrypoint()
    }
    fn complete_original(
        &mut self,
    ) -> Result<Option<mvm_runtime::workload_runner::runner::NativeCompletion>> {
        self.complete().map(Some)
    }
    fn quiesce_original(&mut self) -> Result<()> {
        self.quiesce()
    }
}

struct FinalizeState<'a> {
    outcome: &'a Option<CallOutcome>,
    call_error: &'a mut Option<anyhow::Error>,
    flush_error: &'a mut Option<anyhow::Error>,
    stop_error: &'a mut Option<anyhow::Error>,
    completion: &'a mut Option<mvm_runtime::workload_runner::runner::NativeCompletion>,
    stopped: &'a mut bool,
}

fn drive_finalization(state: FinalizeState<'_>, operations: &mut impl FinalizeOperations) {
    *state.flush_error = operations.sync().err();
    if state.flush_error.is_none() {
        match operations.complete_original() {
            Ok(completion) => {
                if let Some(proof) = &completion
                    && state.outcome.as_ref().is_none_or(|outcome| {
                        outcome.terminal != CallTerminal::from_event(proof.terminal())
                    })
                    && state.call_error.is_none()
                {
                    *state.call_error = Some(anyhow::anyhow!(
                        "call result differs from original native terminal"
                    ));
                }
                *state.completion = completion;
                *state.stopped = true;
            }
            Err(error) => *state.stop_error = Some(error),
        }
    } else {
        match operations.quiesce_original() {
            Ok(()) => *state.stopped = true,
            Err(error) => *state.stop_error = Some(error),
        }
    }
}

/// Retain the actual call value and the caller's actual owning context. This
/// does not authorize a request or change RunEntrypoint into Exec. Storage
/// finalization requires the original readonly preparation and terminal.
pub fn finish_owned_transient(
    owner: super::boot::OwnedClientBoot,
    call: Result<CallOutcome>,
) -> OwnedTransientResult {
    let (outcome, call_error) = match call {
        Ok(outcome) => (Some(outcome), None),
        Err(error) => (None, Some(error)),
    };
    // Install the entire group BEFORE either operation can fail or panic.
    let mut result = OwnedTransientResult {
        custody: Some(Box::new(TransientCustody {
            observer: (),
            outcome,
            call_error,
            flush_error: None,
            stop_error: None,
            cleanup_error: None,
            owner: Some(owner),
            completion: None,
            native_audit: NativeAuditClosure::Unattempted,
            legacy_terminal: false,
            stopped: false,
            started: true,
        })),
    };
    let group = result.custody.as_mut().expect("new transient custody");
    let owner = group.owner.as_mut().expect("original client owner");
    drive_finalization(
        FinalizeState {
            outcome: &group.outcome,
            call_error: &mut group.call_error,
            flush_error: &mut group.flush_error,
            stop_error: &mut group.stop_error,
            completion: &mut group.completion,
            stopped: &mut group.stopped,
        },
        owner,
    );
    close_native_audit(group);
    result
}

/// Compatibility refusal type for callers of the former unsupported seam.
/// Owner-preserving transient calls no longer return this refusal.
#[derive(Debug, thiserror::Error)]
#[error(
    "native owned invocation is unsupported until immutable verified rootfs/verity custody is available"
)]
pub struct NativeOwnedInvocationUnavailable;

/// The observer is moved BEFORE resolution, boot, callbacks and conversions.
/// Native transient calls retain their original owner through dispatch and
/// finalization. Kept-alive native calls remain unsupported.
pub fn run_owned_entrypoint_call<O: CallObserver>(
    call: EntrypointCall<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
    observer: O,
) -> OwnedTransientResult<O> {
    let mut result = OwnedTransientResult::prepare(observer);
    let _ = result.run(call, pair);
    result
}

impl<O: CallObserver> OwnedTransientResult<O> {
    pub fn run(
        &mut self,
        call: EntrypointCall<'_>,
        pair: Option<&mut PairArtifactSource<'_>>,
    ) -> Result<()> {
        let group = self
            .custody
            .as_mut()
            .expect("invocation custody remains present");
        if group.started {
            anyhow::bail!("owned invocation has already been used");
        }
        group.started = true;
        let operation = (|| {
            let backend = super::boot::resolve_backend(Some(call.vm.admission.backend_name()))?;
            anyhow::ensure!(
                matches!(call.lifecycle, CallLifecycle::Transient),
                "owned invocation requires one transient turn"
            );
            if backend.kind() == mvm_core::vm_backend::BackendKind::Hvf {
                let EntrypointCall {
                    mut vm,
                    stdin,
                    timeout_secs,
                    ..
                } = call;
                anyhow::ensure!(
                    matches!(&stdin, CallStdin::OneShot(_)),
                    "owned native entrypoint requires one-shot stdin before boot preparation"
                );
                vm.admission = vm.admission.with_stream_stdin(false);
                let named = vm.vm_name.resolve();
                group.owner = Some(boot_entrypoint_vm_owned(
                    EntrypointVm {
                        slot: vm.slot,
                        vm_name: SessionVmName::Exact(&named),
                        cpus: vm.cpus,
                        memory_mib: vm.memory_mib,
                        admission: vm.admission,
                        portable_boot_assets: vm.portable_boot_assets,
                    },
                    pair,
                )?);
                group.stopped = false;
                group.observer.vm_named(&named);
                let owner = group.owner.as_mut().expect("original client owner");
                group
                    .observer
                    .admitted(&named, &owner.resources().admission.admitted);
                match owner.entrypoint(stdin, timeout_secs, &mut group.observer) {
                    Ok(outcome) => group.outcome = Some(outcome),
                    Err(error) => group.call_error = Some(error),
                }
                drive_finalization(
                    FinalizeState {
                        outcome: &group.outcome,
                        call_error: &mut group.call_error,
                        flush_error: &mut group.flush_error,
                        stop_error: &mut group.stop_error,
                        completion: &mut group.completion,
                        stopped: &mut group.stopped,
                    },
                    owner,
                );
                let stopped = if group.stopped {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("original native stop remains unconfirmed"))
                };
                group.observer.vm_stop_finished(
                    &named,
                    &owner.resources().admission.admitted,
                    &stopped,
                );
                close_native_audit(group);
                anyhow::ensure!(
                    group.call_error.is_none()
                        && group.flush_error.is_none()
                        && group.stop_error.is_none()
                        && group.cleanup_error.is_none(),
                    "native invocation failed; original custody remains retained"
                );
                return group
                    .outcome
                    .clone()
                    .context("native call returned no outcome");
            }
            run_entrypoint_call_recording(call, pair, &mut group.observer, &mut group.outcome)
        })();
        match operation {
            Ok(outcome) => {
                group.outcome = Some(outcome);
                group.legacy_terminal = group.owner.is_none();
                Ok(())
            }
            Err(error) => {
                if group.call_error.is_none()
                    && group.flush_error.is_none()
                    && group.stop_error.is_none()
                    && group.cleanup_error.is_none()
                {
                    group.call_error = Some(error);
                }
                anyhow::bail!("owned invocation failed; original error remains retained")
            }
        }
    }
}

/// Native boot-only resource handoff. The host caller keeps original
/// admission and runtime custody; no SessionVm/name downgrade is made.
pub fn boot_entrypoint_vm_owned(
    vm: EntrypointVm<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<super::boot::OwnedClientBoot> {
    let backend_name = vm.admission.backend_name().to_string();
    let boot = SessionBoot::builder(vm.slot, vm.vm_name)
        .cpus(vm.cpus)
        .memory_mib(vm.memory_mib)
        .network_policy(vm.admission.network_policy().clone())
        .backend_name(&backend_name)
        .portable_boot_assets(vm.portable_boot_assets)
        .build();
    let owner = super::boot::boot_session_vm_owned(boot, &vm.admission, pair)?;
    emit_launched(&owner.resources().admission, &backend_name, true);
    Ok(owner)
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
        portable_boot_assets,
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
        .portable_boot_assets(portable_boot_assets)
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
/// dispatch or backend stop. A failed or unconfirmed stop leaves the session
/// record visible; a workload exit of zero does not override a stop failure.
pub fn run_entrypoint_call(
    call: EntrypointCall<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
    observer: &mut dyn CallObserver,
) -> Result<CallOutcome> {
    run_entrypoint_call_recording(call, pair, observer, &mut None)
}

fn run_entrypoint_call_recording(
    call: EntrypointCall<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
    observer: &mut dyn CallObserver,
    terminal: &mut Option<CallOutcome>,
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
            portable_boot_assets: vm.portable_boot_assets,
        },
        pair,
    )?;
    let vm_name = booted.vm.vm_name.clone();
    observer.admitted(&booted.vm.vm_name, &booted.admission.admitted);

    let mode = match lifecycle {
        CallLifecycle::Transient => SessionMode::Prod,
        CallLifecycle::KeepAlive { mode } => mode,
    };
    let session_id = register_call_session(&vm_name, slot, mode);
    // Agent-wait teardown is best-effort and does not return its stop result.
    // On failure retain the session record: removing it would hide a VM whose
    // stop is unconfirmed. This path emits no stop-acknowledgement observation.
    booted.await_agent(AGENT_WAIT_SECS)?;

    // The admitted plan is borrowed across the dispatch because a streamed
    // stdin is opened under it: the gate takes the proof-carrying type, so the
    // authority for every byte written is the plan this boot was admitted
    // under.
    let dispatch_stdin = match authorize_stdin(stdin, Some(&booted.admission.admitted)) {
        Ok(stdin) => stdin,
        Err(refusal) => {
            let stopped = end_transient_call(&booted, &backend_name, CallEnd::NOT_RUN, observer);
            return finish_transient_result(Err(refusal), stopped, session_id.as_ref());
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
    if let Ok(outcome) = &result {
        *terminal = Some(outcome.clone());
    }

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
            let stopped =
                end_transient_call(&booted, &backend_name, CallEnd::of(&result), observer);
            return finish_transient_result(result, stopped, session_id.as_ref());
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
fn end_transient_call(
    booted: &BootedEntrypoint,
    backend: &str,
    end: CallEnd,
    observer: &mut dyn CallObserver,
) -> Result<()> {
    end_transient_call_with(booted, backend, end, observer, stop_session_vm)
}

fn end_transient_call_with(
    booted: &BootedEntrypoint,
    backend: &str,
    end: CallEnd,
    observer: &mut dyn CallObserver,
    stop: impl FnOnce(&SessionVm) -> Result<()>,
) -> Result<()> {
    let stopped = stop(&booted.vm);
    observer.vm_stop_finished(&booted.vm.vm_name, &booted.admission.admitted, &stopped);
    if let Err(e) = stopped {
        record_unsealed_end(
            Some((&booted.admission.emitter, booted.admission.admitted.plan())),
            UnsealedEnd::new(&booted.vm.vm_name, UnsealedReason::StopFailed)
                .error(format!("{e:#}")),
        );
        return Err(e);
    }
    close_call_session(&booted.admission, &booted.vm.vm_name, backend, end);
    Ok(())
}

/// A workload's exit is not a clean lifecycle when its VM may still be alive.
/// Preserve the call error as well when transport/dispatch and stop both failed.
/// Remove the session record only after the backend acknowledged the stop.
fn finish_transient_result(
    result: Result<CallOutcome>,
    stopped: Result<()>,
    session_id: Option<&SessionId>,
) -> Result<CallOutcome> {
    if stopped.is_ok() {
        deregister_call_session(session_id);
    }
    match (result, stopped) {
        (result, Ok(())) => result,
        (Ok(outcome), Err(stop)) => Err(TransientStopFailure::AfterTerminal {
            _outcome: outcome,
            stop,
        }
        .into()),
        (Err(call), Err(stop)) => Err(TransientStopFailure::AfterError { call, stop }.into()),
    }
}

#[derive(Debug, thiserror::Error)]
enum TransientStopFailure {
    #[error("entrypoint call ended but VM stop was not acknowledged: {stop:#}")]
    AfterTerminal {
        _outcome: CallOutcome,
        #[source]
        stop: anyhow::Error,
    },
    #[error("{call:#}; VM stop was also not acknowledged: {stop:#}")]
    AfterError {
        #[source]
        call: anyhow::Error,
        stop: anyhow::Error,
    },
}

/// Write `plan.exited` and the seal for a stopped transient call, under the
/// plan it was admitted with. Best-effort: the call already happened, and a
/// session that could not be sealed is reported `UNSEALED` by
/// `trust audit verify` rather than failing the call. `seal_transient_end`
/// records why it could not seal, so the error is not reported again here.
fn close_call_session(ctx: &AdmissionContext, vm_name: &str, backend: &str, end: CallEnd) {
    let _ = close_call_session_checked(ctx, vm_name, backend, end);
}

fn close_call_session_checked(
    ctx: &AdmissionContext,
    vm_name: &str,
    backend: &str,
    end: CallEnd,
) -> Result<()> {
    seal_transient_end(
        &ctx.emitter,
        ctx.admitted.plan(),
        TransientEnd {
            vm_name,
            backend,
            exit_code: end.exit_code,
            completed: end.completed,
        },
    )?;
    Ok(())
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

    #[test]
    fn successive_cleanup_failures_preserve_completion_and_quiescence_errors() {
        let mut result = OwnedTransientResult::prepare(());
        let group = result.custody.as_mut().unwrap();
        retain_cleanup_error(group, anyhow::anyhow!("completion recovery failed"));
        retain_cleanup_error(group, anyhow::anyhow!("quiescence recovery failed"));
        let error = group.cleanup_error.as_ref().unwrap();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("completion recovery failed"));
        assert!(rendered.contains("quiescence recovery failed"));
        assert!(result.projection().is_err());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn native_streamed_stdin_refuses_before_boot_preparation() {
        let home = tempfile::tempdir().unwrap();
        let mut environment = TestEnv::new();
        environment.isolate_mvm_home(home.path());
        let mut result =
            OwnedTransientResult::prepare(crate::entrypoint::CapturedOutput::default());
        let call = EntrypointCall {
            vm: EntrypointVm {
                slot: "must-not-build",
                vm_name: SessionVmName::Exact("must-not-start"),
                cpus: 1,
                memory_mib: 512,
                admission: EntrypointAdmission::builder("hvf").build().unwrap(),
                portable_boot_assets: None,
            },
            stdin: CallStdin::Streaming(Box::new(std::io::Cursor::new(b"must-not-read"))),
            timeout_secs: 1,
            lifecycle: CallLifecycle::Transient,
        };
        assert!(result.run(call, None).is_err());
        assert!(
            result
                .call_error()
                .unwrap()
                .to_string()
                .contains("one-shot stdin")
        );
        assert!(result.recovery_details().is_none());
        assert!(result.projection().is_err());
        assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
    }

    #[test]
    fn native_audit_state_never_substitutes_for_original_completion() {
        for audit in [
            NativeAuditClosure::Unattempted,
            NativeAuditClosure::Attempted,
            NativeAuditClosure::Complete,
        ] {
            let mut result = OwnedTransientResult::prepare(());
            let group = result.custody.as_mut().unwrap();
            group.outcome = Some(CallOutcome {
                terminal: CallTerminal::Exited { code: 0 },
                capture: None,
            });
            group.native_audit = audit;
            assert!(result.projection().is_err());
            assert!(result.into_terminal_outcome().is_err());
        }
    }

    #[test]
    fn native_audit_without_original_owner_never_duplicates_boot_failure_audit() {
        let mut result = OwnedTransientResult::prepare(());
        let group = result.custody.as_mut().unwrap();
        group.call_error = Some(anyhow::anyhow!("original boot failure"));
        for stopped in [false, true] {
            group.stopped = stopped;
            close_native_audit(group);
            assert_eq!(group.native_audit, NativeAuditClosure::Unattempted);
            assert_eq!(
                group.call_error.as_ref().unwrap().to_string(),
                "original boot failure"
            );
            assert!(group.cleanup_error.is_none());
        }
    }

    #[test]
    fn uncertain_finalization_retains_every_terminal_without_minting_completion() {
        struct Uncertain;
        impl FinalizeOperations for Uncertain {
            fn sync(&mut self) -> Result<()> {
                anyhow::bail!("original flush failure")
            }
            fn complete_original(
                &mut self,
            ) -> Result<Option<mvm_runtime::workload_runner::runner::NativeCompletion>>
            {
                panic!("failed flush cannot supply completion")
            }
            fn quiesce_original(&mut self) -> Result<()> {
                anyhow::bail!("original stop uncertainty")
            }
        }
        let terminals = [
            CallTerminal::Exited { code: 0 },
            CallTerminal::Exited { code: 9 },
            CallTerminal::Failed {
                kind: mvm_agentd::vsock::RunEntrypointError::Timeout,
                message: "deadline".into(),
            },
            CallTerminal::Failed {
                kind: mvm_agentd::vsock::RunEntrypointError::Canceled,
                message: "cancelled".into(),
            },
        ];
        for terminal in terminals {
            let mut result = OwnedTransientResult::prepare(());
            let group = result.custody.as_mut().unwrap();
            group.stopped = false;
            group.outcome = Some(CallOutcome {
                terminal: terminal.clone(),
                capture: None,
            });
            drive_finalization(
                FinalizeState {
                    outcome: &group.outcome,
                    call_error: &mut group.call_error,
                    flush_error: &mut group.flush_error,
                    stop_error: &mut group.stop_error,
                    completion: &mut group.completion,
                    stopped: &mut group.stopped,
                },
                &mut Uncertain,
            );
            assert!(!group.stopped);
            assert_eq!(result.outcome().unwrap().terminal, terminal);
            assert_eq!(
                result.flush_error().unwrap().to_string(),
                "original flush failure"
            );
            assert_eq!(
                result.stop_error().unwrap().to_string(),
                "original stop uncertainty"
            );
            assert!(result.projection().is_err());
            assert!(result.into_terminal_outcome().is_err());
        }
    }

    #[test]
    fn consumer_keeps_typed_terminal_error_through_sync_cleanup_and_final_failure() {
        struct NoChildOperations(Vec<&'static str>);
        impl FinalizeOperations for NoChildOperations {
            fn sync(&mut self) -> Result<()> {
                self.0.push("sync");
                Ok(())
            }
            fn complete_original(
                &mut self,
            ) -> Result<Option<mvm_runtime::workload_runner::runner::NativeCompletion>>
            {
                self.0.extend(["stop", "cleanup"]);
                Ok(None) // no Child existed, so no opaque native witness exists
            }
            fn quiesce_original(&mut self) -> Result<()> {
                panic!("sync succeeded; completion branch must be used")
            }
        }
        let terminal = mvm_agentd::vsock::EntrypointEvent::Error {
            kind: mvm_agentd::vsock::RunEntrypointError::Timeout,
            message: "local terminal fixture".into(),
        };
        let mut result =
            OwnedTransientResult::prepare(super::super::dispatch::CapturedOutput::default());
        let group = result.custody.as_mut().unwrap();
        group.outcome = Some(CallOutcome {
            terminal: CallTerminal::from_event(&terminal),
            capture: None,
        });
        let mut operations = NoChildOperations(Vec::new());
        drive_finalization(
            FinalizeState {
                outcome: &group.outcome,
                call_error: &mut group.call_error,
                flush_error: &mut group.flush_error,
                stop_error: &mut group.stop_error,
                completion: &mut group.completion,
                stopped: &mut group.stopped,
            },
            &mut operations,
        );
        assert_eq!(operations.0, ["sync", "stop", "cleanup"]);
        assert_eq!(result.outcome().unwrap().exit_code(), 124);
        assert!(!result.succeeded());
        assert!(result.projection().is_err());
        // Exercise the existing nonnative result projection separately. This
        // does not construct NativeCompletion or authorize native output.
        result.custody.as_mut().unwrap().legacy_terminal = true;
        assert!(result.projection().is_ok());
        assert!(
            !result.succeeded(),
            "a delivered typed error is never success"
        );
        // Actual consumer control flow, adapted only at its side effects.
        // None never mints a native exit/output witness or success receipt.
    }

    #[test]
    fn child_free_transient_retry_preserves_actual_outcome_and_all_error_values() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        #[derive(Debug)]
        struct OriginalError(Arc<AtomicUsize>);
        impl std::fmt::Display for OriginalError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("original local error")
            }
        }
        impl std::error::Error for OriginalError {}
        impl Drop for OriginalError {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let mut result = OwnedTransientResult {
            custody: Some(Box::new(TransientCustody {
                observer: (),
                outcome: Some(CallOutcome {
                    terminal: CallTerminal::Exited { code: 7 },
                    capture: None,
                }),
                call_error: Some(anyhow::Error::new(OriginalError(Arc::clone(&drops)))),
                flush_error: Some(anyhow::Error::new(OriginalError(Arc::clone(&drops)))),
                stop_error: Some(anyhow::Error::new(OriginalError(Arc::clone(&drops)))),
                owner: None,
                cleanup_error: None,
                completion: None,
                native_audit: NativeAuditClosure::Unattempted,
                legacy_terminal: false,
                stopped: true,
                started: true,
            })),
        };
        result.retry_stop().unwrap();
        assert_eq!(result.outcome().unwrap().exit_code(), 7);
        assert!(result.call_error().unwrap().is::<OriginalError>());
        assert!(result.flush_error().unwrap().is::<OriginalError>());
        assert!(result.stop_error().unwrap().is::<OriginalError>());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(result);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        // This is a genuinely child-free aggregate, not native stop or a
        // manufactured uncertain/ConfirmedExit fixture.
    }

    #[derive(Default)]
    struct NamingObserver {
        named: Vec<String>,
        admitted: Vec<String>,
    }

    impl CallObserver for NamingObserver {
        fn vm_named(&mut self, vm_name: &str) {
            self.named.push(vm_name.to_string());
        }

        fn admitted(&mut self, _vm_name: &str, admitted: &mvm_hostd::plan_admission::AdmittedPlan) {
            self.admitted.push(admitted.plan().plan_id.0.clone());
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
                    portable_boot_assets: None,
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
            observer.admitted.is_empty(),
            "a failed boot must not emit a successful-boot admission observation"
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

    struct StopObserver<'a> {
        expected: &'a mvm_hostd::plan_admission::AdmittedPlan,
        stop_completed: &'a std::cell::Cell<bool>,
        stops: Vec<(String, bool)>,
    }

    impl CallObserver for StopObserver<'_> {
        fn output(&mut self, _chunk: &ShownChunk) {}

        fn control(&mut self, _header: &str, _payload_len: usize) {}

        fn vm_stop_finished(
            &mut self,
            vm_name: &str,
            admitted: &mvm_hostd::plan_admission::AdmittedPlan,
            result: &Result<()>,
        ) {
            assert!(
                self.stop_completed.get(),
                "observation must follow the stop"
            );
            assert!(self.stops.is_empty(), "one observation per stop attempt");
            assert!(
                std::ptr::eq(admitted, self.expected),
                "stop observation must borrow this boot's actual admission"
            );
            self.stops.push((vm_name.to_string(), result.is_ok()));
        }
    }

    #[test]
    fn stop_observation_uses_the_boot_admission_and_actual_backend_result() {
        let _home = isolated();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let booted = BootedEntrypoint {
            vm: SessionVm {
                vm_name: "observed-stop".into(),
            },
            admission: crate::admission::admit_plan_tests::admitted_into(
                keys_dir.path(),
                audit_dir.path(),
                "observed-stop",
            ),
        };
        emit_launched(&booted.admission, "mock", true);
        let session_id = register_call_session("observed-stop", "slot", SessionMode::Prod).unwrap();
        let stop_completed = std::cell::Cell::new(false);
        let mut observer = StopObserver {
            expected: &booted.admission.admitted,
            stop_completed: &stop_completed,
            stops: Vec::new(),
        };

        let stopped = end_transient_call_with(
            &booted,
            "mock",
            CallEnd::of(&exited(0)),
            &mut observer,
            |vm| {
                assert!(std::ptr::eq(vm, &booted.vm));
                stop_completed.set(true);
                Ok(())
            },
        );

        finish_transient_result(exited(0), stopped, Some(&session_id))
            .expect("call exited and backend acknowledged stop");
        assert_eq!(observer.stops, vec![("observed-stop".into(), true)]);
        assert!(
            mvm_core::session::read_session(&session_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            only_seal(&booted.admission, audit_dir.path())
                .exit_code
                .as_deref(),
            Some("0")
        );
    }

    #[test]
    fn exit_zero_with_failed_stop_is_observed_as_failed_and_left_unsealed() {
        let _home = isolated();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let booted = BootedEntrypoint {
            vm: SessionVm {
                vm_name: "unconfirmed-stop".into(),
            },
            admission: crate::admission::admit_plan_tests::admitted_into(
                keys_dir.path(),
                audit_dir.path(),
                "unconfirmed-stop",
            ),
        };
        emit_launched(&booted.admission, "mock", true);
        let session_id =
            register_call_session("unconfirmed-stop", "slot", SessionMode::Prod).unwrap();
        let stop_completed = std::cell::Cell::new(false);
        let mut observer = StopObserver {
            expected: &booted.admission.admitted,
            stop_completed: &stop_completed,
            stops: Vec::new(),
        };

        let stopped = end_transient_call_with(
            &booted,
            "mock",
            CallEnd::of(&exited(0)),
            &mut observer,
            |_| {
                stop_completed.set(true);
                Err(anyhow::anyhow!("backend stop was not acknowledged"))
            },
        );

        assert!(stopped.is_err());
        assert!(finish_transient_result(exited(0), stopped, Some(&session_id)).is_err());
        assert_eq!(observer.stops, vec![("unconfirmed-stop".into(), false)]);
        assert_eq!(
            mvm_core::session::read_session(&session_id)
                .unwrap()
                .expect("unconfirmed VM must remain visible")
                .state,
            SessionState::Running
        );
        assert_eq!(
            session_report(&booted.admission, audit_dir.path()).verdict,
            mvm_hostd::audit::session::Verdict::Unsealed
        );
        let audit = std::fs::read_to_string(audit_dir.path().join("local.jsonl")).unwrap();
        assert!(!audit.contains("session.sealed"));
        assert!(!audit.contains("plan.exited"));
    }

    #[test]
    fn a_transport_failure_and_stop_failure_are_both_retained() {
        let result = finish_transient_result(
            Err(anyhow::anyhow!("transport disconnected")),
            Err(anyhow::anyhow!("backend stop failed")),
            None,
        )
        .expect_err("neither a failed call nor a failed stop is success");
        let detail = format!("{result:#}");
        assert!(detail.contains("transport disconnected"), "{detail}");
        assert!(detail.contains("backend stop failed"), "{detail}");
    }

    #[test]
    fn acknowledged_stop_does_not_turn_a_failed_call_into_success() {
        let result =
            finish_transient_result(Err(anyhow::anyhow!("dispatch was refused")), Ok(()), None)
                .expect_err("a successful stop is not a successful command");
        assert!(result.to_string().contains("dispatch was refused"));
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
