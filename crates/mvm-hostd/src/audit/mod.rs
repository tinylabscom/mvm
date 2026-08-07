//! Host-side audit binding: the chain-signed `AuditEmitter`, the host signing
//! keypair, plan persistence, and the checkpoint bind helpers. Library API so
//! both the CLI and fleet consumers emit identical chain entries.

pub mod bind;
pub mod emitter;
pub mod host_keypair;
/// RFC 6962 Merkle transparency-log root + inclusion-proof builder over a
/// tenant's chain-signed audit log.
pub mod merkle;
pub mod plan_persist;
/// Read-only exporter from chain-signed audit entries to signed
/// ExecutionReceipts.
pub mod receipt_export;
