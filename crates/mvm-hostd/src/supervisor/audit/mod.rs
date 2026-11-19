//! Per-subsystem audit producers and compatibility paths to the audit-owned chain.

pub use crate::audit::{
    audit_checkpoint, audit_dedup, audit_file, audit_mirror, audit_recorder, bound_sink, signer,
    transcript_sink,
};

pub mod denial_stage;
/// Chain-signed metadata audit for policy-gated DNS questions.
pub mod dns_audit;
/// Per-VM gateway flow-event subscriber sink: the gateway bridge emits each
/// FlowEvent through here in parallel with the signer mpsc.
pub mod gateway_audit;
pub mod icmp_audit;
/// Chain-signed `secret.substituted` / `secret.placeholder_dropped`
/// audit events (claim 13: metadata only, never the secret value).
pub mod secret_audit;
