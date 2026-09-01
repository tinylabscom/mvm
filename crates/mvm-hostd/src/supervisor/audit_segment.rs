//! Authenticated handoff between segments of a rotated audit chain.
//!
//! A chain-signed audit log that only ever grows eventually costs more to
//! verify than anyone is willing to pay, so it has to be split. Splitting it
//! naively destroys the property the log exists for: verification seeds
//! `prev_hash` with 32 zero bytes and requires line 0 to claim them, which is
//! precisely what makes removed history detectable. Rename the file, start a
//! fresh one, and either the new file never verifies or the genesis anchor has
//! been thrown away.
//!
//! So rotation establishes a *new authenticated starting point* rather than
//! discarding the old one. The retiring segment ends with a signed
//! [`CHAIN_SEALED`] record; the fresh segment opens with a signed
//! [`CHAIN_CONTINUED`] record whose envelope `prev_hash` is the retired
//! segment's final line hash, and which repeats that hash — plus the
//! predecessor's sequence number and entry count — inside the signed entry
//! body.
//!
//! Saying it twice is the point. The envelope `prev_hash` is what the chain
//! walk consumes; the copy in the body is what makes the walk's decision
//! *authenticated*, because the signature covers the body. A verifier reaching
//! a non-genesis line 0 accepts it only when the body names the identical hash,
//! so forging a handoff costs exactly what forging any other line costs: the
//! signing key.
//!
//! What this buys, and what it does not: re-ordering segments, splicing one
//! behind a different predecessor, or deleting a segment from the middle or the
//! front are all caught, and a deletion is *named* — the survivor says which
//! sequence number it continues and that segment is absent. Deleting the newest
//! segments is not caught. That is tail truncation; it is undetectable today
//! for the same reason (no external anchor, and the host holds the key), and
//! rotation does not change it either way.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::supervisor::audit::PlanAuditEntry;

/// Terminal record of a retired segment. Its presence is what distinguishes a
/// segment that was *sealed* from one that was truncated at a convenient point.
pub const CHAIN_SEALED: &str = "chain.sealed";

/// Opening record of every segment after the first, carrying the authenticated
/// handoff from its predecessor.
pub const CHAIN_CONTINUED: &str = "chain.continued";

/// This segment's sequence number. On both record kinds.
pub const LABEL_SEGMENT: &str = "chain.segment";

/// Sequence number of the segment that follows. On [`CHAIN_SEALED`].
pub const LABEL_NEXT_SEGMENT: &str = "chain.next_segment";

/// Number of entries in this segment, counting the sealing record itself. On
/// [`CHAIN_SEALED`].
pub const LABEL_ENTRIES: &str = "chain.entries";

/// Sequence number of the segment this one continues. On [`CHAIN_CONTINUED`].
pub const LABEL_PREV_SEGMENT: &str = "chain.prev_segment";

/// base64 url-safe-no-pad of the predecessor's final line hash — the same 32
/// bytes as the envelope's `prev_hash`, but inside the signed body. On
/// [`CHAIN_CONTINUED`].
pub const LABEL_PREV_TIP: &str = "chain.prev_tip";

/// Entry count the predecessor's sealing record claimed. On [`CHAIN_CONTINUED`].
pub const LABEL_PREV_ENTRIES: &str = "chain.prev_entries";

/// The parsed content of a [`CHAIN_SEALED`] record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    /// Sequence number of the segment this record closes.
    pub segment: u64,
    /// Sequence number of the segment that continues it.
    pub next_segment: u64,
    /// Entries in the closed segment, including this record.
    pub entries: u64,
}

/// The parsed content of a [`CHAIN_CONTINUED`] record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation {
    /// Sequence number of the segment this record opens.
    pub segment: u64,
    /// Sequence number of the segment it continues.
    pub prev_segment: u64,
    /// The predecessor's final line hash, as claimed inside the signed body.
    pub prev_tip: [u8; 32],
    /// Entries the predecessor's sealing record claimed.
    pub prev_entries: u64,
}

/// Labels for a sealing record closing `segment` after `entries` entries.
///
/// `entries` counts this record, so the count a reader compares against a
/// directory listing needs no off-by-one adjustment at any call site.
#[must_use]
pub fn sealed_labels(segment: u64, entries: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_SEGMENT.to_string(), segment.to_string()),
        (LABEL_NEXT_SEGMENT.to_string(), (segment + 1).to_string()),
        (LABEL_ENTRIES.to_string(), entries.to_string()),
    ])
}

/// Labels for a continuation record opening the segment after `sealed`.
#[must_use]
pub fn continuation_labels(sealed: &Sealed, prev_tip: [u8; 32]) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_SEGMENT.to_string(), sealed.next_segment.to_string()),
        (LABEL_PREV_SEGMENT.to_string(), sealed.segment.to_string()),
        (LABEL_PREV_TIP.to_string(), URL_SAFE_NO_PAD.encode(prev_tip)),
        (LABEL_PREV_ENTRIES.to_string(), sealed.entries.to_string()),
    ])
}

fn label_u64(labels: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    labels.get(key)?.parse().ok()
}

/// Read a [`CHAIN_SEALED`] record, or `None` if `entry` is not one or is
/// missing a field.
///
/// A record that claims the event name but not the content is *not* treated as
/// a lenient partial: a sealing record with no entry count cannot be checked
/// against its successor, and silently accepting it would make the count check
/// optional in exactly the case where someone tampered with it.
#[must_use]
pub fn sealed_from_entry(entry: &PlanAuditEntry) -> Option<Sealed> {
    if entry.event != CHAIN_SEALED {
        return None;
    }
    let segment = label_u64(&entry.labels, LABEL_SEGMENT)?;
    let next_segment = label_u64(&entry.labels, LABEL_NEXT_SEGMENT)?;
    // A segment must be followed by its immediate successor. Anything else is
    // a gap asserted by the writer, and the ordering stops being total.
    if next_segment != segment + 1 {
        return None;
    }
    Some(Sealed {
        segment,
        next_segment,
        entries: label_u64(&entry.labels, LABEL_ENTRIES)?,
    })
}

/// Read a [`CHAIN_CONTINUED`] record, or `None` if `entry` is not one or is
/// missing a field.
#[must_use]
pub fn continuation_from_entry(entry: &PlanAuditEntry) -> Option<Continuation> {
    if entry.event != CHAIN_CONTINUED {
        return None;
    }
    let segment = label_u64(&entry.labels, LABEL_SEGMENT)?;
    let prev_segment = label_u64(&entry.labels, LABEL_PREV_SEGMENT)?;
    if segment != prev_segment + 1 {
        return None;
    }
    let raw = URL_SAFE_NO_PAD
        .decode(entry.labels.get(LABEL_PREV_TIP)?)
        .ok()?;
    Some(Continuation {
        segment,
        prev_segment,
        prev_tip: raw.try_into().ok()?,
        prev_entries: label_u64(&entry.labels, LABEL_PREV_ENTRIES)?,
    })
}

/// Record that a prefix of the chain's segments was deliberately removed.
///
/// Rotation made the log splittable; this makes a *deletion* accountable rather
/// than merely detectable. Without it, an operator who prunes leaves a chain
/// that reports `TruncatedFront` forever with no way to say the removal was
/// intended — which makes pruning strictly worse than not pruning, so nobody
/// ever does it and "keep everything" stops being a choice.
pub const CHAIN_PRUNED: &str = "chain.pruned";

/// Highest segment sequence number removed. The range is always `1..=this`.
pub const LABEL_PRUNED_THROUGH: &str = "chain.pruned_through";

/// base64 url-safe-no-pad of the final line hash of segment
/// [`LABEL_PRUNED_THROUGH`] — the one fact the surviving chain can still check.
pub const LABEL_PRUNED_TIP: &str = "chain.pruned_tip";

/// Total entries removed across the pruned prefix.
pub const LABEL_PRUNED_ENTRIES: &str = "chain.pruned_entries";

/// The parsed content of a [`CHAIN_PRUNED`] record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pruned {
    /// Highest sequence number removed; the range is `1..=through`.
    pub through: u64,
    /// Final line hash of segment `through`, as claimed inside the signed body.
    pub tip: [u8; 32],
    /// Total entries removed.
    pub entries: u64,
}

/// Labels for a prune record covering `1..=through`.
#[must_use]
pub fn pruned_labels(pruned: &Pruned) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_PRUNED_THROUGH.to_string(), pruned.through.to_string()),
        (
            LABEL_PRUNED_TIP.to_string(),
            URL_SAFE_NO_PAD.encode(pruned.tip),
        ),
        (LABEL_PRUNED_ENTRIES.to_string(), pruned.entries.to_string()),
    ])
}

/// Read a [`CHAIN_PRUNED`] record, or `None` if `entry` is not one or is
/// missing a field.
///
/// Only a prefix can be pruned, so `through` is the whole range and a record
/// claiming `through = 0` is refused: it would describe removing nothing while
/// still being offered as an explanation for a gap.
#[must_use]
pub fn pruned_from_entry(entry: &PlanAuditEntry) -> Option<Pruned> {
    if entry.event != CHAIN_PRUNED {
        return None;
    }
    let through = label_u64(&entry.labels, LABEL_PRUNED_THROUGH)?;
    if through == 0 {
        return None;
    }
    let raw = URL_SAFE_NO_PAD
        .decode(entry.labels.get(LABEL_PRUNED_TIP)?)
        .ok()?;
    Some(Pruned {
        through,
        tip: raw.try_into().ok()?,
        entries: label_u64(&entry.labels, LABEL_PRUNED_ENTRIES)?,
    })
}

/// The starting chain hash a segment's opening entry authorizes, if it is a
/// well-formed continuation.
///
/// This is the whole of the line-0 rule. The caller has *not* yet verified the
/// signature when it calls this, so the answer is a claim, not a fact — it
/// becomes a fact when the signature over `signed_bytes || prev_tip` checks
/// out. Handing back the tip rather than a boolean is what forces that: the
/// caller has to feed it into the signature check to use it.
#[must_use]
pub fn continuation_start_hash(entry: &PlanAuditEntry) -> Option<[u8; 32]> {
    continuation_from_entry(entry).map(|c| c.prev_tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::PlanAuditEntry;
    use mvm_core::plan::{PlanId, TenantId};

    fn entry(event: &str, labels: BTreeMap<String, String>) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: TenantId("local".to_string()),
            plan_id: PlanId("00000000-0000-0000-0000-000000000000".to_string()),
            plan_version: 0,
            bundle_id: None,
            bundle_version: None,
            image_name: "<unbound>".to_string(),
            image_sha256: "0".repeat(64),
            event: event.to_string(),
            caller_commitment: None,
            labels,
        }
    }

    #[test]
    fn a_sealing_record_round_trips() {
        let parsed = sealed_from_entry(&entry(CHAIN_SEALED, sealed_labels(3, 4096)));
        assert_eq!(
            parsed,
            Some(Sealed {
                segment: 3,
                next_segment: 4,
                entries: 4096
            })
        );
    }

    #[test]
    fn a_continuation_round_trips_and_carries_the_tip_verbatim() {
        let tip = [9u8; 32];
        let sealed = Sealed {
            segment: 3,
            next_segment: 4,
            entries: 4096,
        };
        let parsed =
            continuation_from_entry(&entry(CHAIN_CONTINUED, continuation_labels(&sealed, tip)));
        assert_eq!(
            parsed,
            Some(Continuation {
                segment: 4,
                prev_segment: 3,
                prev_tip: tip,
                prev_entries: 4096
            })
        );
        assert_eq!(
            continuation_start_hash(&entry(CHAIN_CONTINUED, continuation_labels(&sealed, tip))),
            Some(tip)
        );
    }

    /// An ordinary entry must never be mistaken for a handoff, or any line
    /// could authorize an arbitrary chain restart.
    #[test]
    fn an_ordinary_entry_is_not_a_handoff() {
        assert_eq!(
            continuation_start_hash(&entry("plan.launched", BTreeMap::new())),
            None
        );
        assert_eq!(
            sealed_from_entry(&entry("plan.launched", BTreeMap::new())),
            None
        );
    }

    /// The record kinds must not be interchangeable: a sealing record parsed
    /// as a continuation would hand back a start hash it never committed to.
    #[test]
    fn the_two_record_kinds_do_not_parse_as_each_other() {
        let sealed = entry(CHAIN_SEALED, sealed_labels(1, 2));
        assert_eq!(continuation_from_entry(&sealed), None);
        let cont = entry(
            CHAIN_CONTINUED,
            continuation_labels(
                &Sealed {
                    segment: 1,
                    next_segment: 2,
                    entries: 2,
                },
                [0u8; 32],
            ),
        );
        assert_eq!(sealed_from_entry(&cont), None);
    }

    /// A handoff missing any field is refused outright rather than parsed
    /// leniently. A continuation with no `prev_entries` still yields a usable
    /// start hash, so a lenient parse would let a tamper drop the one label
    /// that cross-checks the predecessor's length.
    #[test]
    fn a_handoff_missing_a_field_is_refused() {
        let full = continuation_labels(
            &Sealed {
                segment: 1,
                next_segment: 2,
                entries: 7,
            },
            [1u8; 32],
        );
        for key in [
            LABEL_SEGMENT,
            LABEL_PREV_SEGMENT,
            LABEL_PREV_TIP,
            LABEL_PREV_ENTRIES,
        ] {
            let mut labels = full.clone();
            labels.remove(key);
            assert_eq!(
                continuation_from_entry(&entry(CHAIN_CONTINUED, labels)),
                None,
                "a continuation missing {key} must be refused"
            );
        }
    }

    /// A tip that is not 32 bytes cannot seed a chain walk. Accepting a short
    /// one would compare against a truncated hash.
    #[test]
    fn a_tip_of_the_wrong_length_is_refused() {
        let mut labels = continuation_labels(
            &Sealed {
                segment: 1,
                next_segment: 2,
                entries: 1,
            },
            [1u8; 32],
        );
        labels.insert(
            LABEL_PREV_TIP.to_string(),
            URL_SAFE_NO_PAD.encode([1u8; 16]),
        );
        assert_eq!(
            continuation_from_entry(&entry(CHAIN_CONTINUED, labels)),
            None
        );
    }

    /// Sequence numbers must be contiguous within the record itself. A record
    /// that claims to continue segment 1 while calling itself segment 9 would
    /// otherwise assert its own gap and still be accepted.
    #[test]
    fn a_non_contiguous_handoff_is_refused() {
        let mut labels = continuation_labels(
            &Sealed {
                segment: 1,
                next_segment: 2,
                entries: 1,
            },
            [1u8; 32],
        );
        labels.insert(LABEL_SEGMENT.to_string(), "9".to_string());
        assert_eq!(
            continuation_from_entry(&entry(CHAIN_CONTINUED, labels)),
            None
        );

        let mut sealed = sealed_labels(1, 1);
        sealed.insert(LABEL_NEXT_SEGMENT.to_string(), "9".to_string());
        assert_eq!(sealed_from_entry(&entry(CHAIN_SEALED, sealed)), None);
    }
}
