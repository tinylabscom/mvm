//! Host-side capture of a workload's output: the one place it is redacted,
//! hash-chained, persisted, and handed to readers.
//!
//! A microVM's stdout, stderr, and structured trace records arrive from two
//! places — the guest agent's entrypoint pump and the backend's console
//! capture — and leave towards an arbitrary number of followers. Everything
//! in between happens once, in [`broker::StreamBroker`]:
//!
//! - **[`redact`] is the only seam.** Redaction runs before the chain, so
//!   the chain proves what was *shown*. Storing raw and redacting per
//!   consumer would make every new consumer a new leak path. A broker can
//!   only be built over a [`redact::StreamRedaction`], whose one production
//!   constructor installs the curated ruleset, so "the seam always runs" is
//!   a type, not a convention.
//! - **The host owns ordering.** The broker stamps `seq` and
//!   `host_unix_nanos`; the guest proposes neither.
//! - **[`fanout`] rings, it never blocks.** A follower that stops draining
//!   loses its own oldest records and stalls nobody. Bounded in bytes *and*
//!   in record count, because a byte-only bound leaves per-record overhead
//!   unbounded when a workload writes a byte at a time.
//! - **Audit records the attach, not the bytes.** One chain-signed entry per
//!   subscribe keeps the audit log payload-free.
//!
//! One broker per VM, resident in the per-tenant daemon — not a process per
//! VM.

pub mod broker;
pub mod console_source;
pub mod fanout;
pub mod redact;

pub use broker::{DEFAULT_CAPTURE_BOUNDS, StreamAudit, StreamBroker, StreamCounters};
pub use console_source::{ConsoleSource, ConsoleSourceHandle, SharedBroker};
pub use fanout::{
    DEFAULT_READER_BOUNDS, DEFAULT_READER_MAX_BYTES, DEFAULT_READER_MAX_RECORDS, ReaderHandle,
    ReaderStart,
};
pub use redact::{
    REDACTION_FAILED_EVENT, Redacted, RedactionFailed, StreamRedaction, StreamRedactor,
};
