//! Function-entrypoint calls: booting a workload's microVM under an admitted
//! plan, dispatching `RunEntrypoint` into it, and keeping it warm across
//! calls as a session.
//!
//! This is the production-safe call surface. The guest agent serves
//! `RunEntrypoint` only by spawning the program named in
//! `/etc/mvm/entrypoint`; there is no shell and no argv override, and the only
//! environment injected is the host-synthesized egress settings — never a raw
//! secret value.
//!
//! `mvmctl machine run --entrypoint`, `mvmctl machine session …` and the
//! host library's `entrypoint.*` / `session.*` methods all reach the guest
//! through these functions, so every surface is admitted, audited and torn
//! down the same way. What differs between them is presentation, and that is
//! behind [`dispatch::CallObserver`].

pub mod admission;
pub mod boot;
pub mod call;
pub mod dispatch;
pub mod envelope;
pub mod session;
pub mod stdin_stream;
pub mod verb_audit;
pub mod workload;

pub use admission::{AdmittedEntrypoint, EntrypointAdmission, EntrypointAdmissionBuilder};
pub use boot::{
    AdmitInputs, SessionAdmit, SessionAuditSubstrate, SessionBoot, SessionVm, SessionVmName,
    boot_session_vm, tear_down_session_vm,
};
pub use call::{
    AGENT_WAIT_SECS, BootedEntrypoint, CallLifecycle, EntrypointCall, EntrypointVm,
    backend_name_for, boot_entrypoint_vm, run_entrypoint_call,
};
pub use dispatch::{
    CallObserver, CallOutcome, CallStdin, CallTerminal, CaptureReport, CapturedOutput,
    DispatchStdin, EntrypointDispatch, NO_ARGUMENT_PAYLOAD, ONE_SHOT_PAYLOAD_LIMIT,
    RecordedDivergence, authorize_stdin, dispatch, install_output_capture, one_shot_payload,
    route_event,
};
pub use envelope::{RemoteErrorEnvelope, parse_last_envelope};
pub use session::{
    IdleTimeoutUpdate, SessionStart, call_session, kill_session, reap_expired_sessions,
    require_running_session, session_info, set_session_idle_timeout, start_session,
    update_idle_timeout,
};
pub use workload::{WorkloadSource, resolve_slot, resolve_workload_slot};
