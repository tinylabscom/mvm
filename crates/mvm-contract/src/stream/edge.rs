//! Stream edges: one workload's output feeding another's input.
//!
//! ## A consumer names a binding, never a VM
//!
//! [`StreamEdge::binding`] is a name local to the consumer's own plan. The
//! host resolves it to a source workload; the guest never learns which one, or
//! that there was one. That is the whole reason this is not guest networking
//! by the back door: A and B never share a transport, never learn each other's
//! identity, and neither gains a NIC. Bytes cross in the host, between two
//! independent vsock channels, at the one place that was already the single
//! authorization point.
//!
//! A consumer naming a binding it was not granted is refused before boot, and
//! the refusal reaches the chain-signed log. "Not granted" and "no such
//! source" are deliberately the same answer: a consumer must not be able to
//! probe the fleet's shape by trying names.
//!
//! ## Two postures, both defaulting to the safe side
//!
//! [`EdgeRedaction`] defaults to `Redacted` and [`EdgeBackpressure`] to
//! `Lossy`. Both defaults are what a plan written before this field existed
//! deserializes to, so an old plan cannot acquire a raw edge by omission.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Environment variable an operator sets to accept raw, unredacted bytes on an
/// edge.
///
/// Shaped after `MVM_ACK_UNRESTRICTED_NETWORK` on purpose. A plan is signed on
/// behalf of whoever launched the workload, so a plan signature alone is the
/// wrong authority for this: it would let a careless or compromised workload
/// definition export raw PII to another workload with no human in the loop.
/// Between two workloads those are different trust domains, so the opt-out
/// needs a second, human-held key. Never set in CI.
pub const ACK_RAW_EDGE_ENV: &str = "MVM_ACK_RAW_STREAM_EDGE";

/// What a consumer receives on an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EdgeRedaction {
    /// Masked by the same seam every other consumer crosses. The default, and
    /// the only posture that needs no operator acknowledgement.
    #[default]
    Redacted,
    /// The consumer receives the producer's bytes unmasked.
    ///
    /// Exists because always-redact corrupts a pipeline whose second stage
    /// needs what the first computed — a masked value is not a value. The
    /// durable transcript still stores the redacted copy, so the artifact that
    /// outlives the run is unweakened and the divergence is audited. Requires
    /// [`ACK_RAW_EDGE_ENV`] in addition to the plan signature.
    Raw,
}

/// What happens when a consumer cannot keep up.
///
/// Neither mode stalls the producer. A workload that blocks because its reader
/// is slow is a workload whose behaviour depends on who is watching it, which
/// this plane refuses to allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EdgeBackpressure {
    /// Ring, evict oldest, mark the gap, audit it. The default: a workflow
    /// that would rather see recent output than none.
    #[default]
    Lossy,
    /// Fail the edge loudly when the buffer fills.
    ///
    /// A mode named `reliable` must never quietly drop a record, so when it
    /// cannot hold one it stops being an edge rather than becoming a lossy one
    /// under a reassuring name.
    Reliable,
}

/// One inbound edge on a consumer's signed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEdge {
    /// The binding name, resolved by the host. Not a VM name — see the module
    /// docs on why a guest never addresses another guest.
    pub binding: String,
    /// Redaction posture. Absent = [`EdgeRedaction::Redacted`].
    #[serde(default)]
    pub redaction: EdgeRedaction,
    /// Backpressure mode. Absent = [`EdgeBackpressure::Lossy`].
    #[serde(default)]
    pub backpressure: EdgeBackpressure,
}

impl StreamEdge {
    /// An edge with both postures at their defaults.
    #[must_use]
    pub fn new(binding: impl Into<String>) -> Self {
        Self {
            binding: binding.into(),
            redaction: EdgeRedaction::Redacted,
            backpressure: EdgeBackpressure::Lossy,
        }
    }

    /// Whether this edge hands the consumer unmasked bytes.
    #[must_use]
    pub fn is_raw(&self) -> bool {
        matches!(self.redaction, EdgeRedaction::Raw)
    }
}

/// Whether `edges` contains any edge that would carry unmasked bytes.
///
/// The admission check needs this before it can decide whether the operator
/// acknowledgement is required, and asking it in one place keeps the two from
/// disagreeing about what "raw" means.
#[must_use]
pub fn any_raw_edge(edges: &[StreamEdge]) -> bool {
    edges.iter().any(StreamEdge::is_raw)
}

/// Every distinct binding named by `edges`, in declaration order.
///
/// Duplicates are a plan defect rather than a topology question — the same
/// binding twice means two writers for one input slot, which E3 rules out —
/// so admission rejects them before the graph is built.
#[must_use]
pub fn duplicate_binding(edges: &[StreamEdge]) -> Option<&str> {
    for (i, edge) in edges.iter().enumerate() {
        if edges[..i].iter().any(|e| e.binding == edge.binding) {
            return Some(edge.binding.as_str());
        }
    }
    None
}

/// Bindings named by `edges`, in declaration order.
#[must_use]
pub fn binding_names(edges: &[StreamEdge]) -> Vec<&str> {
    edges.iter().map(|e| e.binding.as_str()).collect()
}

/// Why a plan's declared edges were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeRefusal {
    /// The same binding twice. Two edges into one input slot is fan-in, which
    /// E3 rules out — caught here on the single plan rather than left for the
    /// graph, because a plan can be wrong on its own.
    DuplicateBinding { binding: String },
    /// A raw edge without the operator acknowledgement.
    ///
    /// Deliberately not satisfiable by the plan signature: see
    /// [`ACK_RAW_EDGE_ENV`] on why a signature is the wrong authority for
    /// exporting unmasked bytes into a different trust domain.
    RawEdgeUnacknowledged { binding: String },
    /// The workload is fed by an edge *and* takes operator stdin.
    ///
    /// One input slot, one writer. This is the surprising one, so it is a
    /// diagnosable admission error rather than a runtime race for the lease.
    InputSlotContested { binding: String },
}

impl EdgeRefusal {
    /// An operator-facing description that names the binding at fault.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::DuplicateBinding { binding } => alloc::format!(
                "stream edge {binding:?} is declared twice: one input slot takes one writer, so                  declare a merge stage instead"
            ),
            Self::RawEdgeUnacknowledged { binding } => alloc::format!(
                "stream edge {binding:?} asks for unredacted bytes, which needs {ACK_RAW_EDGE_ENV}                  set by an operator — a plan signature is not that authority, because it is made                  on behalf of the workload rather than by a human accepting the export"
            ),
            Self::InputSlotContested { binding } => alloc::format!(
                "stream edge {binding:?} feeds this workload's stdin, so it cannot also be given                  operator input: there is one input slot and one writer"
            ),
        }
    }
}

/// Check one plan's declared edges, before boot and before the graph.
///
/// `raw_acknowledged` is whether the operator set [`ACK_RAW_EDGE_ENV`]; it is
/// passed in rather than read here so this stays a pure function that a host
/// can call from wherever it resolves environment. `operator_stdin` is whether
/// the same launch also hands the workload an operator-driven stdin.
///
/// This is the per-plan half. The cross-plan half — resolving bindings to
/// sources and refusing a cyclic graph — is
/// [`crate::stream::topology::validate`], and belongs to whoever holds the
/// whole declaration.
///
/// # Errors
///
/// One [`EdgeRefusal`] per the first problem found, in the order a reader
/// would want them: shape, then authority, then slot contention.
pub fn check_plan_edges(
    edges: &[StreamEdge],
    raw_acknowledged: bool,
    operator_stdin: bool,
) -> Result<(), EdgeRefusal> {
    if let Some(binding) = duplicate_binding(edges) {
        return Err(EdgeRefusal::DuplicateBinding {
            binding: String::from(binding),
        });
    }
    if !raw_acknowledged && let Some(edge) = edges.iter().find(|e| e.is_raw()) {
        return Err(EdgeRefusal::RawEdgeUnacknowledged {
            binding: edge.binding.clone(),
        });
    }
    if operator_stdin && let Some(edge) = edges.first() {
        return Err(EdgeRefusal::InputSlotContested {
            binding: edge.binding.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn defaults_are_the_safe_side() {
        let edge = StreamEdge::new("upstream");
        assert_eq!(edge.redaction, EdgeRedaction::Redacted);
        assert_eq!(edge.backpressure, EdgeBackpressure::Lossy);
        assert!(!edge.is_raw());
    }

    /// A plan written before this field existed must not acquire a raw edge by
    /// omission. Serde defaults are what enforce that, so they are pinned.
    #[test]
    fn an_edge_missing_both_postures_deserializes_to_the_safe_ones() {
        let edge: StreamEdge =
            serde_json::from_str(r#"{"binding":"upstream"}"#).expect("bare binding parses");
        assert_eq!(edge.redaction, EdgeRedaction::Redacted);
        assert_eq!(edge.backpressure, EdgeBackpressure::Lossy);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let err = serde_json::from_str::<StreamEdge>(r#"{"binding":"a","mode":"raw"}"#);
        assert!(err.is_err(), "deny_unknown_fields must reject a typo'd key");
    }

    /// `raw` is the wire spelling. A rename here silently downgrades every
    /// existing raw edge to redacted, which fails safe but would be a mystery.
    #[test]
    fn postures_roundtrip_through_their_wire_names() {
        let edge = StreamEdge {
            binding: "upstream".into(),
            redaction: EdgeRedaction::Raw,
            backpressure: EdgeBackpressure::Reliable,
        };
        let json = serde_json::to_string(&edge).expect("serialize");
        assert!(json.contains(r#""redaction":"raw""#), "{json}");
        assert!(json.contains(r#""backpressure":"reliable""#), "{json}");
        assert_eq!(
            serde_json::from_str::<StreamEdge>(&json).expect("roundtrip"),
            edge
        );
    }

    #[test]
    fn any_raw_edge_finds_one_among_redacted_siblings() {
        let edges = vec![
            StreamEdge::new("a"),
            StreamEdge {
                binding: "b".into(),
                redaction: EdgeRedaction::Raw,
                backpressure: EdgeBackpressure::Lossy,
            },
            StreamEdge::new("c"),
        ];
        assert!(any_raw_edge(&edges));
        assert!(!any_raw_edge(&edges[..1]));
    }

    #[test]
    fn duplicate_binding_names_the_repeat() {
        let edges = vec![
            StreamEdge::new("a"),
            StreamEdge::new("b"),
            StreamEdge::new("a"),
        ];
        assert_eq!(duplicate_binding(&edges), Some("a"));
        assert_eq!(duplicate_binding(&edges[..2]), None);
    }

    #[test]
    fn binding_names_preserves_declaration_order() {
        let edges = vec![StreamEdge::new("z"), StreamEdge::new("a")];
        assert_eq!(binding_names(&edges), vec!["z", "a"]);
    }

    #[test]
    fn a_plain_plan_admits() {
        check_plan_edges(&[StreamEdge::new("a")], false, false).expect("a redacted edge is fine");
    }

    #[test]
    fn a_duplicate_binding_is_refused() {
        let edges = vec![StreamEdge::new("a"), StreamEdge::new("a")];
        let err = check_plan_edges(&edges, false, false).expect_err("two writers, one slot");
        assert_eq!(
            err,
            EdgeRefusal::DuplicateBinding {
                binding: "a".into()
            }
        );
        assert!(err.describe().contains("merge stage"), "{}", err.describe());
    }

    /// The signature is deliberately not enough. If this ever starts passing
    /// with `false`, a workload definition can export unmasked bytes into
    /// another trust domain with no human in the loop.
    #[test]
    fn a_raw_edge_without_the_acknowledgement_is_refused() {
        let edges = vec![StreamEdge {
            binding: "a".into(),
            redaction: EdgeRedaction::Raw,
            backpressure: EdgeBackpressure::Lossy,
        }];
        let err = check_plan_edges(&edges, false, false).expect_err("needs the operator ack");
        assert_eq!(
            err,
            EdgeRefusal::RawEdgeUnacknowledged {
                binding: "a".into()
            }
        );
        assert!(
            err.describe().contains(ACK_RAW_EDGE_ENV),
            "{}",
            err.describe()
        );

        check_plan_edges(&edges, true, false).expect("acknowledged, so admitted");
    }

    /// The consequence most likely to surprise someone: an edge consumes
    /// the single input slot, so the workload cannot also take operator stdin.
    /// A diagnosable refusal, not a runtime race for the lease.
    #[test]
    fn an_edge_and_operator_stdin_together_are_refused() {
        let edges = vec![StreamEdge::new("a")];
        let err = check_plan_edges(&edges, false, true).expect_err("one slot, one writer");
        assert_eq!(
            err,
            EdgeRefusal::InputSlotContested {
                binding: "a".into()
            }
        );
    }

    /// Operator stdin with no edge is the ordinary case and must stay allowed —
    /// a check that refused it would break `machine run --stdin -`.
    #[test]
    fn operator_stdin_without_an_edge_admits() {
        check_plan_edges(&[], false, true).expect("no edge, no contention");
    }
}
