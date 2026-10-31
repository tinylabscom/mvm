//! The host's chain-signed audit machinery, for callers that render or drive
//! it, and the destruction-receipt overlay it verifies. Pure re-exports.

pub use mvm_hostd::audit::{
    active_signer, decisions, emitter, evidence, host_keypair, merkle, plan_persist,
    receipt_archive, receipt_archive_verify, receipt_export, session, transcript_retirement,
    witness,
};
pub use mvm_hostd::supervisor;
pub use mvm_runtime::vm::overlay;
