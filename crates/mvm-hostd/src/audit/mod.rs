//! Host-side audit binding: the chain-signed `AuditEmitter`, the host signing
//! keypair, plan persistence, and the checkpoint bind helpers. Library API so
//! both the CLI and fleet consumers emit identical chain entries.

pub mod assurance;
pub mod bind;
/// Whether a run's `plan.admitted` entry is a control or a note — the one
/// place a failure to record an admission becomes a refused boot.
pub mod durability;
pub mod emitter;
pub mod evidence;
pub mod host_keypair;
/// RFC 6962 Merkle transparency-log root + inclusion-proof builder over a
/// tenant's chain-signed audit log.
pub mod merkle;
pub mod plan_persist;
/// Writer for `.mvmev` evidence archives over the chain-signed audit log.
pub mod receipt_archive;
/// Verifier for `.mvmev` evidence archives.
pub mod receipt_archive_verify;
/// Read-only exporter from chain-signed audit entries to signed
/// ExecutionReceipts.
pub mod receipt_export;
/// Persistent store for runtime-emitted signed ExecutionReceipts.
pub mod receipt_store;
pub mod witness;

/// Content-addressed derived store for decision records.
pub mod decisions;
