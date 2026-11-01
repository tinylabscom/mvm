//! Agent-session store, record types and resume admission. Pure re-exports.

pub use mvm_hostd::plan_admission::{AdmittedPlan, InMemoryNonceLedger, SystemClock};
pub use mvm_hostd::session_resume::{
    BootedSession, ResumeOutcome, ResumePlanMaterial, ResumeRequest, resume_session,
};
pub use mvm_runtime::agent_session::{
    AgentSessionRecord, AgentSessionStore, GenerationFence, ParkInput, ParkReason, RenewRequest,
    RetentionStatus, SandboxResidency, StorageTier, TransitionResult,
};
