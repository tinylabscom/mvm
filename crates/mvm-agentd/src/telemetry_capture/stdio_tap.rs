//! Workload stdout/stderr into guest capture.
//!
//! Every path that reads a workload's pipes — the entrypoint output pump, the
//! streaming exec, and process control's detached processes — also offers
//! each chunk here as it reads it, so a workload's output reaches the host
//! collector for the VM's life — not only the CLI invocation that happens to
//! be attached — whether or not anyone is reading the call's stream, and
//! beyond any per-call buffer cap.
//!
//! Offering is one non-waiting admission per chunk of at most
//! [`MAX_STDIO_BYTES`]: a full capture queue sheds and counts, it never slows
//! the reader, and so never the workload. Nothing is offered until the agent
//! installs the tap, which it does only on a boot asserting telemetry.

use std::sync::{Arc, OnceLock};

use mvm_core::protocol::telemetry::{BoundedList, MAX_STDIO_BYTES, RecordBody, StdioStream};

use super::{CaptureState, ProducerId};

static TAP: OnceLock<Arc<CaptureState>> = OnceLock::new();

/// Route workload output into `state` from now on. The first install wins;
/// later calls are ignored, as is a second capture state.
pub fn install_stdio_tap(state: Arc<CaptureState>) {
    let _ = TAP.set(state);
}

/// Offer one workload output chunk to capture, when the tap is installed.
pub(crate) fn offer(stream: StdioStream, chunk: &[u8]) {
    if let Some(state) = TAP.get() {
        offer_to(state, stream, chunk);
    }
}

/// Offer `chunk` to `state` as stdio records of at most [`MAX_STDIO_BYTES`].
pub fn offer_to(state: &CaptureState, stream: StdioStream, chunk: &[u8]) {
    let producer = match stream {
        StdioStream::Stdout => ProducerId::Stdout,
        StdioStream::Stderr => ProducerId::Stderr,
    };
    for piece in chunk.chunks(MAX_STDIO_BYTES) {
        let Ok(bytes) = BoundedList::new(piece.to_vec()) else {
            continue;
        };
        let _ = state.emit(
            producer.default_source(),
            producer,
            RecordBody::Stdio { stream, bytes },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::net::telemetry::outbox::Outbox;
    use mvm_core::protocol::telemetry::MAX_RECORD_BYTES;

    fn state(records: usize) -> CaptureState {
        CaptureState::new(Arc::new(
            Outbox::new(records, records * MAX_RECORD_BYTES).unwrap(),
        ))
        .unwrap()
    }

    #[test]
    fn output_is_captured_per_stream_in_record_sized_pieces() {
        let state = state(16);
        offer_to(
            &state,
            StdioStream::Stdout,
            &vec![b'o'; MAX_STDIO_BYTES + 10],
        );
        offer_to(&state, StdioStream::Stderr, b"err");
        assert_eq!(state.losses(ProducerId::Stdout).attempts, 2);
        assert_eq!(state.losses(ProducerId::Stderr).attempts, 1);
        let mut seen = Vec::new();
        while let Ok(Some(prepared)) = state.outbox().take_for_test() {
            let record =
                mvm_core::protocol::telemetry::TelemetryRecord::decode(prepared.encoded_for_test())
                    .unwrap();
            if let RecordBody::Stdio { stream, bytes } = record.body() {
                seen.push((*stream, bytes.as_slice().len()));
            }
        }
        assert_eq!(
            seen,
            vec![
                (StdioStream::Stdout, MAX_STDIO_BYTES),
                (StdioStream::Stdout, 10),
                (StdioStream::Stderr, 3),
            ]
        );
    }

    #[test]
    fn a_full_queue_sheds_output_with_counted_loss_instead_of_waiting() {
        let state = state(1);
        for _ in 0..8 {
            offer_to(&state, StdioStream::Stdout, b"flood");
        }
        let losses = state.losses(ProducerId::Stdout);
        assert_eq!(losses.attempts, 8);
        assert!(losses.capacity.records >= 7, "{losses:?}");
    }
}
