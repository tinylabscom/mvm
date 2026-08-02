//! Read side of the workload stream plane: the trait every consumer reads
//! through, and the framed transport that fetches records from a VM's
//! host-side broker.
//!
//! `mvmctl`, the SDKs, and the fleet control plane all want the same three
//! things — records in order, proof the window was not tampered with, and a
//! filter — so they get one implementation rather than three. It lives here,
//! below both `mvm-client` and `mvm-sdk`, because `mvm-sdk` sits *under*
//! `mvm-hostd` which sits under `mvm-client`: a reader in `mvm-client` could
//! never be reached from the SDK without a dependency cycle. `mvm-client`
//! and `mvm-sdk` each re-export this module as their public surface, the same
//! way the `MvmClient` facade already lives here and is fronted there.
//!
//! Three properties are load-bearing:
//!
//! - **Verification happens before filtering.** A [`KindFilter`] or a
//!   `from_seq` resume removes records from the middle of a window, which
//!   breaks the hash chain by construction. So the reader verifies the whole
//!   delivered window first and only then drops what the caller did not ask
//!   for. Filtering can never weaken the check.
//! - **The anchored check, not the genesis one.** A broker prunes, and a
//!   follower that attached mid-stream or fell behind holds a *window*, not a
//!   chain from genesis. [`mvm_protocol::stream::verify_chain`] rejects that
//!   by design, so the reader uses `verify_chain_from` against the anchor the
//!   broker sampled with the window. A consumer never has to know an anchor
//!   exists.
//! - **A break is an error, never a short read.** A window that fails
//!   verification surfaces as [`StreamError::Chain`]. Truncating silently
//!   would make tampering look like the end of output.
//!
//! [`StreamReader`] is the *live* half. A broker attaches a follower at the
//! live head and an exited VM has no broker at all, so on its own it answers
//! neither "what has this VM already printed" nor "what did it print before it
//! died". [`output`] resolves both sources — the broker and the VM's durable
//! transcript — and is what a consumer wanting a workload's output reads
//! through.

mod console;
mod opts;
mod output;
mod reader;
mod wire;

pub use console::{ConsoleTail, ConsoleUnsupported};
pub use opts::{KindFilter, StreamOpts, StreamOptsBuilder};
pub use output::{
    EmptyHistory, OutputLocator, OutputRecord, OutputRequest, RecordOrigin, SpliceGap,
    StreamAvailability, Truncation, VmOutputStream, open_vm_output, open_vm_output_at,
};
pub use reader::{
    FramedStreamReader, StreamError, StreamReader, connect_stream, connect_stream_at,
};
pub use wire::{
    MAX_BATCH_PAYLOAD_BYTES, MAX_BATCH_RECORDS, MAX_FRAME_BYTES, MAX_RECORD_PAYLOAD_BYTES,
    StreamBatch, read_batch, write_batch,
};
