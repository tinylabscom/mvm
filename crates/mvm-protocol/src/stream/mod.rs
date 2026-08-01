//! Wire types and chain verification for captured workload output.
//!
//! A [`StreamRecord`] is one hash-chained chunk of stdout/stderr (or a
//! structured trace record) captured from a running microVM.
//! [`verify_chain`] walks a sequence of them and checks the chain is
//! unbroken from genesis — no gap, no reorder, no tamper — the same shape
//! of guarantee [`crate::verify`] gives the audit log, applied per output
//! stream instead of per tenant. [`verify_chain_from`] is the same check
//! anchored at a caller-supplied hash instead of the zero genesis marker,
//! for verifying a pruned or partially-fetched window of a longer chain.

pub mod chain;
pub mod record;

pub use chain::{ChainError, verify_chain, verify_chain_from};
pub use record::{StreamKind, StreamRecord, StreamSource};
