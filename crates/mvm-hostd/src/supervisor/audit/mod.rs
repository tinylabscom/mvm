//! Per-subsystem audit producers and compatibility paths to the audit-owned chain.

pub use crate::audit::{
    audit_checkpoint, audit_dedup, audit_file, audit_mirror, audit_recorder, bound_sink, signer,
    transcript_sink,
};

pub mod denial_stage;
pub mod icmp_audit;
/// Chain-signed `secret.substituted` / `secret.placeholder_dropped`
/// audit events (claim 13: metadata only, never the secret value).
pub mod secret_audit;
