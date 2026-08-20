//! Admission-bound AI assurance sessions.
//!
//! An assurance campaign runs a declared attack narrative against a real guest
//! and reports whether the attempted effect crossed a boundary. An AI drives
//! the campaign from inside the workload. This module is the contract that
//! makes that safe to do.
//!
//! Three properties are structural rather than checked:
//!
//! - The provider's half of the input envelope ([`AssuranceSessionRequest`])
//!   cannot carry admission facts — `deny_unknown_fields` refuses them — and
//!   the assembled [`AiSessionInput`] cannot be built without an
//!   [`MvmBinding`] derived from a signed plan.
//! - The AI's result ([`TrialResultCandidate`]) has no outcome field, so it
//!   cannot report `PREVENTED`. [`evaluate`] derives outcomes from host
//!   evidence.
//! - Effective authority is one intersected value ([`EffectiveAuthority`]),
//!   not a set of checks spread across the dispatch path.
//!
//! Everything crossing into the session is an identifier, a digest, or a
//! reference. No secret value, host path, socket name, or log body appears in
//! any type here.

pub mod authority;
pub mod binding;
pub mod ids;
pub mod input;
pub mod outcome;
pub mod probe;
pub mod session;
pub mod wire;

#[cfg(test)]
mod tests;

pub use authority::{
    ApprovalSet, AuthorityCeiling, AuthorityError, AuthorityInputs, EffectiveAuthority,
};
pub use binding::{BindingError, MvmBinding, MvmBindingBuilder, RuntimeIdentity, SessionGrant};
pub use ids::{
    AssuranceId, AssuranceIdError, DigestError, EvidenceRef, EvidenceRefError, Sha256Digest,
};
pub use input::{
    AI_SESSION_INPUT_SCHEMA, AiSessionInput, AssuranceSessionRequest, Narrative, ObservationScope,
    OutputContract, RequestedAuthority, SessionInputError, SessionRef, Severity, SourceRef,
    SubjectKind, SyntheticInputs, ToolId,
};
pub use outcome::{
    CandidateError, EvaluationInputs, EvidenceIdentity, EvidenceSet, HostObservation,
    InconclusiveReason, TRIAL_EVIDENCE_SCHEMA, TRIAL_RESULT_CANDIDATE_SCHEMA, TRIAL_RESULT_SCHEMA,
    TrialEvidenceRecord, TrialOutcome, TrialResultCandidate, TrialVerdict, evaluate,
};
pub use probe::{
    PROBE_OBSERVATION_SCHEMA, PROBE_REQUEST_SCHEMA, ProbeInvocation, ProbeObservation,
    ProbeRefusal, ProbeRequest,
};
pub use session::{AdmittedAssuranceSession, DeclaredEdge, PlanIdentity};
pub use wire::{
    AuthorityWire, DeliveredSession, DeliveredSessionError, MvmBindingWire, TrialResultDocument,
    TrialResultIdentity, TrialResultSession,
};
