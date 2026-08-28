//! One workload's output driven into another's stdin.
//!
//! ## Caller-driven, not a daemon
//!
//! [`EdgeConnector::step`] moves whatever is available and returns. It owns no
//! thread, no timer, and no lifecycle. The caller decides when to pump it,
//! when to stop, and what a failure means — which matters because the caller
//! is in another repository, and a connector that had picked those answers
//! here would have picked them blind.
//!
//! What it does own is the part that is genuinely local: acceptance order,
//! lease upkeep, gap handling, and making sure the withheld tail is delivered
//! rather than dropped.
//!
//! ## Acceptance order is the contract
//!
//! The input gate's secret scan concatenates frames in the order it accepts
//! them; it does not reassemble by `seq`. So frames must be written in the
//! order they were drained, with `seq` strictly increasing, or a secret split
//! across two records is scanned as two unrelated fragments and neither
//! matches. That is why this pumps in one pass and never reorders.
//!
//! ## The producer never stalls
//!
//! Nothing here can block the workload that is being read. The reader's queue
//! is already bounded and already rings; a consumer that falls behind loses
//! records *there*, and reports it as a gap. So backpressure is not a second
//! buffer, it is how the edge reacts to a gap the reader hands it:
//!
//! - [`EdgeBackpressure::Lossy`] marks the gap and carries on.
//! - [`EdgeBackpressure::Reliable`] fails the edge. A mode named `reliable`
//!   must never quietly drop a record, so when it cannot hold one it stops
//!   being an edge rather than becoming a lossy one under a reassuring name.
//!
//! ## Raw edges are refused here, not silently masked
//!
//! Redaction happens before hashing, so a record that reaches a reader has
//! already crossed the seam and no raw copy of it exists downstream. An edge
//! declared [`EdgeRedaction::Raw`] therefore cannot be served from this
//! reader. Handing over the masked bytes anyway would be worse than refusing:
//! the consumer asked for fidelity, was told it got fidelity, and got a
//! pipeline whose second stage is computing on `XXX`. Serving it needs a tap
//! on the pre-seam side, which is a different design and is not this.

use std::collections::VecDeque;

use mvm_contract::stream::edge::{EdgeBackpressure, EdgeRedaction, StreamEdge};
use mvm_contract::stream::input::InputFrame;

use super::fanout::ReaderHandle;
use super::input_gate::InputRefusal;
use super::input_route::{InputRoute, InputRouteError};

/// What one [`EdgeConnector::step`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeStep {
    /// Nothing was waiting. The lease was refreshed regardless, so an idle
    /// edge does not lose its slot to the TTL.
    Idle,
    /// Records moved to the consumer.
    Delivered {
        /// How many records were accepted.
        records: usize,
        /// How many payload bytes those records carried.
        bytes: usize,
    },
    /// Records were lost before the edge saw them, and the edge is lossy.
    /// Reported rather than swallowed so a consumer's operator can see that
    /// the stream it is reading has a hole in it.
    Gap {
        /// The last sequence number known to have been delivered before the
        /// loss.
        after_seq: u64,
        /// Records delivered in the same step, after the gap.
        records: usize,
    },
}

/// Why an edge stopped being an edge.
#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    /// The consumer's input gate refused a frame.
    #[error("the consumer's input gate refused the edge: {0}")]
    Refused(#[from] InputRefusal),
    /// The admitted route could not carry a frame to the guest.
    #[error("the consumer's input route failed: {0}")]
    Route(InputRouteError),
    /// A reliable edge lost records.
    #[error(
        "reliable edge lost records after seq {after_seq}: the consumer fell behind and the \
         reader's queue rang. A reliable edge fails rather than delivering a stream with a \
         hole in it; re-run the workflow."
    )]
    Lost {
        /// Where the loss began.
        after_seq: u64,
    },
    /// The edge asked for unmasked bytes, which this reader cannot serve.
    #[error(
        "edge {binding:?} asks for raw bytes, but records reaching a reader have already crossed \
         the redaction seam and no unmasked copy survives. Serving it needs a pre-seam tap, which \
         does not exist; delivering masked bytes under a raw label would be worse than refusing."
    )]
    RawUnavailable {
        /// The binding that asked.
        binding: String,
    },
}

/// Whether this reader can serve `edge` at all.
///
/// Separate from [`EdgeConnector::new`] so the refusal can be asserted without
/// standing up a gate, a plan and a lease to reach it.
///
/// # Errors
///
/// [`EdgeError::RawUnavailable`] for an edge asking for unmasked bytes.
pub fn servable(edge: &StreamEdge) -> Result<(), EdgeError> {
    if matches!(edge.redaction, EdgeRedaction::Raw) {
        return Err(EdgeError::RawUnavailable {
            binding: edge.binding.clone(),
        });
    }
    Ok(())
}

/// Pumps one producer's records into one consumer's stdin.
pub struct EdgeConnector {
    binding: String,
    route: InputRoute,
    reader: ReaderHandle,
    backpressure: EdgeBackpressure,
    /// Next frame sequence to hand the gate. Strictly increasing across the
    /// edge's whole life: the gate rejects a repeat, and a restart is a new
    /// edge rather than a resumption.
    next_seq: u64,
    /// Set once a gap has been reported, so a lossy edge marks each distinct
    /// loss rather than re-reporting one forever.
    reported_gap_at: Option<u64>,
    /// Records drained but not yet accepted, kept so a refusal mid-batch does
    /// not lose what was already taken off the reader.
    carry: VecDeque<Vec<u8>>,
}

impl EdgeConnector {
    /// Bind a reader to a consumer's admitted input route.
    ///
    /// # Errors
    ///
    /// [`EdgeError::RawUnavailable`] when the edge asks for unmasked bytes.
    pub fn new(
        edge: &StreamEdge,
        route: InputRoute,
        reader: ReaderHandle,
    ) -> Result<Self, EdgeError> {
        servable(edge)?;
        Ok(Self {
            binding: edge.binding.clone(),
            route,
            reader,
            backpressure: edge.backpressure,
            next_seq: 0,
            reported_gap_at: None,
            carry: VecDeque::new(),
        })
    }

    /// The binding this edge was declared under.
    #[must_use]
    pub fn binding(&self) -> &str {
        &self.binding
    }

    /// Move whatever is available, once.
    ///
    /// # Errors
    ///
    /// [`EdgeError::Refused`] when the gate declines a frame, and
    /// [`EdgeError::Lost`] when a reliable edge finds the reader rang.
    pub fn step(&mut self) -> Result<EdgeStep, EdgeError> {
        let window = self.reader.drain_verified();

        let mut gap_at = None;
        if let Some(marker) = window.gap {
            let after = marker.after_seq;
            if self.reported_gap_at != Some(after) {
                match self.backpressure {
                    EdgeBackpressure::Reliable => return Err(EdgeError::Lost { after_seq: after }),
                    EdgeBackpressure::Lossy => {
                        self.reported_gap_at = Some(after);
                        gap_at = Some(after);
                    }
                }
            }
        }

        // Anything carried from a refused batch goes first: dropping it would
        // put a hole in the stream that no gap marker accounts for.
        for record in window.records {
            self.carry.push_back(record.payload);
        }

        if self.carry.is_empty() {
            // Refresh even with nothing to send. An edge whose producer is
            // quiet must not lose the single-writer lease to the TTL and then
            // find another writer holding it.
            self.route.refresh().map_err(map_route_error)?;
            return Ok(match gap_at {
                Some(after_seq) => EdgeStep::Gap {
                    after_seq,
                    records: 0,
                },
                None => EdgeStep::Idle,
            });
        }

        let (mut records, mut bytes) = (0usize, 0usize);
        while let Some(payload) = self.carry.pop_front() {
            let len = payload.len();
            let frame = InputFrame {
                seq: self.next_seq,
                payload,
            };
            match self.route.write(frame) {
                Ok(()) => {
                    self.next_seq += 1;
                    records += 1;
                    bytes += len;
                }
                Err(err) => {
                    // Route errors end this edge. A supervisor re-runs the
                    // workflow rather than attempting to reconnect across a
                    // fresh scanner or guessing whether the guest observed a
                    // transport failure.
                    return Err(map_route_error(err));
                }
            }
        }

        Ok(match gap_at {
            Some(after_seq) => EdgeStep::Gap { after_seq, records },
            None => EdgeStep::Delivered { records, bytes },
        })
    }

    /// Close the consumer's stdin, delivering whatever the scan still holds.
    ///
    /// # Errors
    ///
    /// [`InputRouteError`] when the route cannot be closed cleanly.
    pub fn close(self) -> Result<(), InputRouteError> {
        // `InputRoute::close` flushes the scanner's withheld tail through the
        // guest transport before EOF. Dropping the route instead would
        // swallow it, which is a truncation the consumer cannot see.
        self.route.close()
    }
}

fn map_route_error(error: InputRouteError) -> EdgeError {
    match error {
        InputRouteError::Refused(refusal) => EdgeError::Refused(refusal),
        other => EdgeError::Route(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::stream::edge::StreamEdge;

    fn raw_edge() -> StreamEdge {
        StreamEdge {
            binding: "upstream".into(),
            redaction: EdgeRedaction::Raw,
            backpressure: EdgeBackpressure::Lossy,
        }
    }

    /// A raw edge must be refused, not served masked bytes. Serving them
    /// would tell a consumer it has fidelity while its second stage computes
    /// on the mask.
    #[test]
    fn a_raw_edge_is_refused_rather_than_quietly_masked() {
        let err = servable(&raw_edge()).expect_err("a raw edge cannot be served post-seam");
        match err {
            EdgeError::RawUnavailable { binding } => assert_eq!(binding, "upstream"),
            other => panic!("expected RawUnavailable, got {other}"),
        }
    }

    /// The default posture must remain servable, or the edge is useless.
    #[test]
    fn a_redacted_edge_is_servable() {
        servable(&StreamEdge::new("upstream")).expect("the default posture is servable");
    }

    /// The two modes must differ, and the difference must be that `reliable`
    /// refuses to deliver a holed stream rather than quietly ringing.
    #[test]
    fn the_error_text_names_the_recovery() {
        let err = EdgeError::Lost { after_seq: 41 };
        let text = err.to_string();
        assert!(text.contains("41"), "{text}");
        assert!(text.contains("re-run"), "the fix is named: {text}");
    }

    #[test]
    fn raw_refusal_explains_why_the_bytes_do_not_exist() {
        let text = EdgeError::RawUnavailable {
            binding: "b".into(),
        }
        .to_string();
        assert!(text.contains("redaction seam"), "{text}");
        assert!(
            text.contains("pre-seam tap"),
            "the missing piece is named: {text}"
        );
    }
}
