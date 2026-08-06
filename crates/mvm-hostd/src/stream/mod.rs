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
//! - **[`serve`] is the only way out.** Followers reach the broker over one
//!   per-VM Unix socket, and what goes on that wire is the whole window plus
//!   the anchor that verifies it. Narrowing to a consumer's filter happens on
//!   the reading side, because a hole punched here would break the very chain
//!   the consumer is meant to check.
//!
//! One broker per VM, resident in the per-tenant daemon — not a process per
//! VM. [`plane`] is what assembles the pieces above into that per-VM
//! registration and takes it down again, and
//! [`install_host_console_streamer`] is where the host process wires it to
//! the workload runner's console hook.
//!
//! The other direction is [`input_gate`], and it is the mirror image of all
//! of the above: capture is always on and authorizes nobody, while a workload's
//! stdin is default-deny behind a signed plan grant, leased to one writer, and
//! scanned for the host's own secrets before a byte moves. [`input_route`] is
//! what carries the bytes it cleared to the guest, and [`plane`] owns one
//! route per VM beside that VM's broker — the same lock that arbitrates
//! concurrent writers is what keeps delivery order equal to the order the gate
//! accepted, which is the order its secret scan describes.
//!
//! Two sources feed one broker. [`console_source`] republishes the write-only
//! console capture, which covers boot and the window after the agent dies but
//! cannot separate the two channels. [`entrypoint_source`] takes the guest
//! agent's `stdout`/`stderr` frames, which can. Within either, order is exact;
//! between them it is host arrival order and nothing stronger, because the two
//! travel different transports at different latencies.

pub mod broker;
pub mod console_source;
pub mod durable;
pub mod edge_connector;
pub mod entrypoint_source;
pub mod fanout;
pub mod input_gate;
pub mod input_route;
mod journal;
pub mod plane;
pub mod redact;
pub(crate) mod secret_scan;
pub mod serve;

use std::sync::{Arc, OnceLock};

pub use broker::{DEFAULT_CAPTURE_BOUNDS, StreamAudit, StreamBroker, StreamCounters};
pub use console_source::{ConsoleSource, ConsoleSourceHandle, SharedBroker};
pub use edge_connector::{EdgeConnector, EdgeError, EdgeStep, servable};
pub use entrypoint_source::{EntrypointSink, RecordedCopy, ShownChunk};
pub use fanout::{
    DEFAULT_READER_BOUNDS, DEFAULT_READER_MAX_BYTES, DEFAULT_READER_MAX_RECORDS, DrainedWindow,
    ReaderHandle, ReaderStart,
};
pub use input_gate::{
    CATEGORY_HOST_SECRET, DEFAULT_IDLE_FLUSH_AFTER, DEFAULT_LEASE_TTL, InputAudit, InputAuditSink,
    InputBinding, InputGate, InputRefusal, InputSession,
};
pub use input_route::{
    DisplacedRoute, InputRoute, InputRouteError, InputTransport, MAX_UNDELIVERED_INPUT_BYTES,
    VsockInput, WireSequence,
};
pub use plane::StreamPlane;
pub use redact::{
    ClearOutcome, REDACTION_FAILED_EVENT, Redacted, RedactionFailed, StreamRedaction,
    StreamRedactor,
};
pub use serve::{StreamServerHandle, serve_stream};

/// Give this process a real output-stream plane: every workload the runtime
/// boots from here on gets a broker, a follower socket, and a durable
/// transcript, and every workload it stops gets them sealed and released.
///
/// Called once, early, by a host binary that starts workloads. It is a
/// registration rather than a direct call because the runtime crate sits
/// below this one and cannot name [`StreamPlane`] — see
/// `mvm_runtime::workload_runner::console_stream`.
///
/// Returns whether this call is the one that installed it; a second call is a
/// no-op. Idempotent so a binary that starts workloads from more than one
/// entry point can register defensively at each.
pub fn install_host_console_streamer() -> bool {
    let plane = Arc::new(StreamPlane::new());
    if !mvm_runtime::workload_runner::install_console_streamer(Arc::clone(&plane) as _) {
        return false;
    }
    // Only ever the plane the runtime actually took. A second, discarded plane
    // reachable through `host_stream_plane` would send this process's
    // entrypoint output to a broker no VM is attached to, which reads as a
    // workload that printed nothing.
    let _ = HOST_PLANE.set(plane);
    true
}

/// The plane [`install_host_console_streamer`] registered, for a producer that
/// is not the console follower — the entrypoint dispatch, which needs to reach
/// a running VM's broker by name.
///
/// `None` in a process that never registered one, which is every embedder that
/// does not start workloads.
pub fn host_stream_plane() -> Option<Arc<StreamPlane>> {
    HOST_PLANE.get().map(Arc::clone)
}

/// Set by [`install_host_console_streamer`], and only when the runtime
/// accepted the registration.
static HOST_PLANE: OnceLock<Arc<StreamPlane>> = OnceLock::new();
