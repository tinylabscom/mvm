//! Wire types and chain verification for captured workload output.
//!
//! A [`StreamRecord`] is one hash-chained chunk of stdout/stderr (or a
//! structured trace record) captured from a running microVM.
//! [`verify_chain`] walks a sequence of them and checks the chain is
//! unbroken — no gap, no reorder, no tamper — the same shape of guarantee
//! [`crate::verify`] gives the audit log, applied per output stream
//! instead of per tenant.

pub mod chain;
pub mod record;

pub use chain::{ChainError, verify_chain};
pub use record::{StreamKind, StreamRecord, StreamSource};
