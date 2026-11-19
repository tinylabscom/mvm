//! Host-side audit chain, recording and binding: the chain-signed `AuditEmitter`,
//! host signing keypair, plan persistence, and checkpoint bind helpers. Library API so
//! both the CLI and fleet consumers emit identical chain entries.

pub mod active_signer;
pub mod assurance;
pub mod audit_checkpoint;
pub mod audit_client;
pub mod audit_dedup;
pub mod audit_file;
pub mod audit_mirror;
pub mod audit_recorder;
pub mod bind;
pub mod bound_sink;
/// Whether a run's `plan.admitted` entry is a control or a note — the one
/// place a failure to record an admission becomes a refused boot.
pub mod durability;
pub mod emitter;
pub mod evidence;
pub mod host_keypair;
/// RFC 6962 Merkle transparency-log root + inclusion-proof builder over a
/// tenant's chain-signed audit log.
pub mod leaf_cache;
pub mod merkle;
pub mod output_audit;
pub mod plan_persist;
#[cfg(unix)]
pub(crate) mod prune_pins;
#[cfg(unix)]
pub use prune_pins::validate_tenant as validate_prune_tenant;
/// Writer for `.mvmev` evidence archives over the chain-signed audit log.
pub mod receipt_archive;
/// Verifier for `.mvmev` evidence archives.
pub mod receipt_archive_verify;
/// Read-only exporter from chain-signed audit entries to signed
/// ExecutionReceipts.
pub mod receipt_export;
/// Persistent store for runtime-emitted signed ExecutionReceipts.
pub mod receipt_store;
/// Per-session seals, the session ledger derived from them, and the
/// per-session verdict.
pub mod session;
pub mod signer;
#[cfg(unix)]
pub mod transcript_retirement;
/// Live forensic transcript capture sink — fills an armed capture's manifest
/// with encrypted byte chunks as they cross the host bridge.
pub mod transcript_sink;
pub mod unsealed;
pub mod witness;

/// Content-addressed derived store for decision records.
pub mod decisions;
