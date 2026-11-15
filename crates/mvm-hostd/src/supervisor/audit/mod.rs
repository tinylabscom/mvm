//! Chain-signed audit: the signer, the on-disk chain, the recorder and its mirror, and the per-subsystem audit events (DNS, ICMP, secret substitution, gateway flows, transcripts).

pub mod audit_checkpoint;
pub mod audit_dedup;
pub mod audit_file;
pub mod audit_mirror;
pub mod audit_recorder;
/// Chain-signed metadata audit for policy-gated DNS questions.
pub mod dns_audit;
/// Per-VM gateway flow-event subscriber sink: the gateway bridge emits each
/// FlowEvent through here in parallel with the signer mpsc.
pub mod gateway_audit;
pub mod icmp_audit;
/// Chain-signed `secret.substituted` / `secret.placeholder_dropped`
/// audit events (claim 13: metadata only, never the secret value).
pub mod secret_audit;
pub mod signer;
/// Live forensic transcript capture sink — fills an armed capture's manifest
/// with encrypted byte chunks as they cross the host bridge.
pub mod transcript_sink;
