//! Verification across the whole segment set of a rotated audit chain.
//!
//! [`crate::supervisor::audit_file::verify_audit_chain`] answers a question
//! about one file. After rotation that is no longer the whole question: a
//! segment can verify perfectly and still be the only survivor of a set someone
//! deleted the rest of. The per-file walk cannot see that, because a segment's
//! opening handoff names its predecessor but cannot conjure it.
//!
//! So the set has its own checks, and they are what turn removed history from
//! silence into a named absence: the survivor says which sequence number it
//! continues, and the report says that segment is missing.
//!
//! Two entry points, because the two callers want genuinely different things
//! and conflating them is what made this expensive in the first place:
//!
//! - [`verify_segment_topology`] — full walk of the *active* segment, plus the
//!   boundary lines of every sealed one. `O(active + segments)`, no cache and
//!   no trust-on-first-use. A real cryptographic answer to a narrower question.
//! - [`verify_segment_set`] — every interior of every segment, end to end, at
//!   full cost. What `mvmctl trust audit verify` is for.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

use mvm_contract::verify::hash_line;

use crate::supervisor::audit_file::{SignedEnvelope, VerifyError, verify_chain_bytes};
use crate::supervisor::audit_segment::{
    Continuation, Sealed, continuation_from_entry, sealed_from_entry,
};

/// What went wrong across the set, as opposed to within one file.
#[derive(Debug, Error)]
pub enum SegmentSetError {
    #[error("io error: {0}")]
    Io(String),
    #[error("segment {seq} ({path}) failed verification: {source}")]
    Segment {
        /// Sequence number of the offending segment.
        seq: u64,
        /// Its path, so an operator can go and look at it.
        path: String,
        /// The per-file failure.
        #[source]
        source: VerifyError,
    },
    /// The headline case. A segment names the predecessor it continues, and
    /// that predecessor is not on disk.
    #[error(
        "segment {seq} continues segment {missing}, which is absent: \
         history between them has been removed"
    )]
    MissingSegment {
        /// The surviving successor.
        seq: u64,
        /// The sequence number it points at, which nothing provides.
        missing: u64,
    },
    #[error(
        "segment {seq} claims to continue a chain ending {claimed}, \
         but segment {prev} ends {actual}: these segments are not consecutive"
    )]
    Spliced {
        /// The successor.
        seq: u64,
        /// Its declared predecessor.
        prev: u64,
        /// The tip it claims, hex.
        claimed: String,
        /// The tip its predecessor actually has, hex.
        actual: String,
    },
    #[error(
        "segment {prev} sealed at {sealed} entries but segment {seq} \
         claims it held {claimed}"
    )]
    EntryCountMismatch {
        /// The successor making the claim.
        seq: u64,
        /// Its predecessor.
        prev: u64,
        /// What the predecessor's own sealing record said.
        sealed: u64,
        /// What the successor claimed it said.
        claimed: u64,
    },
    #[error(
        "segment {seq} ({path}) is retired but carries no sealing record: it was truncated, not rotated"
    )]
    Unsealed {
        /// The offending segment.
        seq: u64,
        /// Its path.
        path: String,
    },
    #[error("segment {seq} ({path}) does not open with a handoff naming its predecessor")]
    MissingHandoff {
        /// The offending segment.
        seq: u64,
        /// Its path.
        path: String,
    },
    #[error(
        "the chain begins at segment {seq}, which continues segment {missing}: \
         the earliest history has been removed"
    )]
    TruncatedFront {
        /// The lowest segment present.
        seq: u64,
        /// What it continues, which is absent.
        missing: u64,
    },
    #[error("no audit chain for {base} in {dir}")]
    NoChain {
        /// The chain's filename stem.
        base: String,
        /// Where it was looked for.
        dir: String,
    },
}

/// What one segment contributed to the set.
#[derive(Debug, Clone)]
pub struct SegmentReport {
    /// Sequence number.
    pub seq: u64,
    /// Path on disk.
    pub path: PathBuf,
    /// Whether this is the live segment (`<base>.jsonl`) rather than a retired
    /// one.
    pub active: bool,
    /// Entries verified. `None` when only the segment's boundaries were checked
    /// (a sealed segment under [`verify_segment_topology`]), so a caller can
    /// never report an interior it did not walk as though it had.
    pub entries: Option<usize>,
}

/// One segment as located on disk, before anything has been read from it.
struct Located {
    seq: u64,
    path: PathBuf,
    active: bool,
}

/// Ordered segment set for `base` in `dir`: every `<base>.seg-NNNNNN.jsonl`
/// followed by the active `<base>.jsonl`.
fn locate(dir: &Path, base: &str) -> Result<Vec<Located>, SegmentSetError> {
    let mut sealed: Vec<Located> = Vec::new();
    let listing = match std::fs::read_dir(dir) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SegmentSetError::NoChain {
                base: base.to_string(),
                dir: dir.display().to_string(),
            });
        }
        Err(e) => return Err(SegmentSetError::Io(e.to_string())),
    };
    for entry in listing {
        let entry = entry.map_err(|e| SegmentSetError::Io(e.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(seq) = mvm_core::config::audit_segment_seq(name, base) {
            sealed.push(Located {
                seq,
                path: entry.path(),
                active: false,
            });
        }
    }
    sealed.sort_by_key(|s| s.seq);

    let active_path = dir.join(format!("{base}.jsonl"));
    if active_path.exists() {
        // The active segment's own sequence number is whatever its opening
        // handoff claims, or 1 when it opens at genesis. Reading it here keeps
        // the set's ordering derived from the files rather than from the count
        // of sealed ones, which would go wrong the moment one is missing.
        let seq = active_seq(&active_path)?;
        sealed.push(Located {
            seq,
            path: active_path,
            active: true,
        });
    }
    if sealed.is_empty() {
        return Err(SegmentSetError::NoChain {
            base: base.to_string(),
            dir: dir.display().to_string(),
        });
    }
    Ok(sealed)
}

/// The active segment's own sequence number, from its opening handoff.
///
/// Deliberately tolerant of a first line it cannot parse: this runs during
/// *location*, before verification, and a file full of garbage must be reported
/// by the chain verifier — which names the line and the reason — rather than as
/// an I/O error from the code that was only trying to order the set. Answering
/// "1" for an unreadable head costs nothing, because the verifier refuses that
/// segment moments later.
fn active_seq(path: &Path) -> Result<u64, SegmentSetError> {
    let content = std::fs::read_to_string(path).map_err(|e| SegmentSetError::Io(e.to_string()))?;
    let Some(first) = content.lines().find(|l| !l.is_empty()) else {
        return Ok(1);
    };
    Ok(serde_json::from_str::<SignedEnvelope>(first)
        .ok()
        .and_then(|e| continuation_from_entry(&e.entry))
        .map_or(1, |c| c.segment))
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One segment, read exactly once.
///
/// Everything downstream — the boundary checks, the interior walk, and the
/// Merkle leaves — is derived from `content`, so there is no read → verify →
/// re-read window in which the bytes attested could differ from the bytes used.
pub struct SegmentContent {
    /// Sequence number.
    pub seq: u64,
    /// Path on disk.
    pub path: PathBuf,
    /// Whether this is the live segment.
    pub active: bool,
    /// The file's bytes.
    pub content: String,
    /// Authenticated entries, when this segment's interior was walked. `None`
    /// for a sealed segment under [`verify_segment_topology`], so a caller can
    /// never present an interior it did not read as though it had.
    pub entries: Option<Vec<crate::supervisor::audit::AuditEntry>>,
}

impl SegmentContent {
    /// Non-empty lines, in file order — the Merkle leaf bytes.
    #[must_use]
    pub fn lines(&self) -> Vec<&str> {
        self.content.lines().filter(|l| !l.is_empty()).collect()
    }
}

/// A segment's first and last envelope, and the hash of its last line.
struct Ends {
    first: SignedEnvelope,
    last: SignedEnvelope,
    tip: [u8; 32],
    lines: usize,
}

/// A segment's boundary envelopes.
///
/// A boundary line that will not parse is reported as a per-line
/// [`VerifyError::Malformed`], not as an I/O failure: it is a statement about
/// the file's contents, and an operator triaging it needs the line number and
/// the reason, exactly as the single-file verifier has always given them.
fn read_ends(path: &Path, content: &str, seq: u64) -> Result<Ends, SegmentSetError> {
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    let (Some(first), Some(last)) = (lines.first(), lines.last()) else {
        return Err(SegmentSetError::Io(format!("{} is empty", path.display())));
    };
    let parse = |line: &str, idx: usize| {
        serde_json::from_str::<SignedEnvelope>(line).map_err(|e| SegmentSetError::Segment {
            seq,
            path: path.display().to_string(),
            source: VerifyError::Malformed {
                line: idx,
                reason: e.to_string(),
            },
        })
    };
    Ok(Ends {
        first: parse(first, 0)?,
        last: parse(last, lines.len() - 1)?,
        tip: hash_line(last.as_bytes()),
        lines: lines.len(),
    })
}

/// Verify one line's signature against the chain hash it claims.
///
/// The boundary check needs this because it does not walk the interior: a
/// boundary line whose signature was never checked would let anyone rewrite a
/// handoff by hand and have the topology still "pass".
fn verify_line(
    envelope: &SignedEnvelope,
    vk: &VerifyingKey,
    seq: u64,
    path: &Path,
) -> Result<(), SegmentSetError> {
    let fail = |source| SegmentSetError::Segment {
        seq,
        path: path.display().to_string(),
        source,
    };
    let prev = base64_32(&envelope.prev_hash).ok_or_else(|| {
        fail(VerifyError::Malformed {
            line: 0,
            reason: "prev_hash".to_string(),
        })
    })?;
    let sig = base64_64(&envelope.signature).ok_or_else(|| {
        fail(VerifyError::Malformed {
            line: 0,
            reason: "signature".to_string(),
        })
    })?;
    // Same rule the chain walk uses: a line carrying `canonical` is verified
    // over those exact bytes, and a pre-`canonical` line falls back to
    // re-serializing the entry. Boundary lines must not be checked by a
    // different rule from interior lines, or a segment could pass one walk and
    // fail the other.
    let canonical = envelope
        .canonical
        .as_deref()
        .and_then(|c| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .ok()
        })
        .unwrap_or_else(|| serde_json::to_vec(&envelope.entry).unwrap_or_default());
    let mut to_verify = canonical;
    to_verify.extend_from_slice(&prev);
    vk.verify(&to_verify, &Signature::from_bytes(&sig))
        .map_err(|_| fail(VerifyError::SignatureInvalid { line: 0 }))
}

fn base64_32(s: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?
        .try_into()
        .ok()
}

fn base64_64(s: &str) -> Option<[u8; 64]> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?
        .try_into()
        .ok()
}

/// The structural checks between two adjacent segments.
fn check_boundary(
    prev_seq: u64,
    prev_sealed: &Sealed,
    prev_tip: [u8; 32],
    seq: u64,
    cont: &Continuation,
) -> Result<(), SegmentSetError> {
    if cont.prev_segment != prev_seq {
        return Err(SegmentSetError::MissingSegment {
            seq,
            missing: cont.prev_segment,
        });
    }
    if cont.prev_tip != prev_tip {
        return Err(SegmentSetError::Spliced {
            seq,
            prev: prev_seq,
            claimed: hex(&cont.prev_tip),
            actual: hex(&prev_tip),
        });
    }
    if cont.prev_entries != prev_sealed.entries {
        return Err(SegmentSetError::EntryCountMismatch {
            seq,
            prev: prev_seq,
            sealed: prev_sealed.entries,
            claimed: cont.prev_entries,
        });
    }
    Ok(())
}

/// The lowest segment present must either be the genesis segment or be honest
/// that it is not the beginning.
fn check_front(first: &Located, ends: &Ends) -> Result<(), SegmentSetError> {
    match continuation_from_entry(&ends.first.entry) {
        Some(cont) => Err(SegmentSetError::TruncatedFront {
            seq: first.seq,
            missing: cont.prev_segment,
        }),
        None if first.seq == 1 => Ok(()),
        None => Err(SegmentSetError::MissingHandoff {
            seq: first.seq,
            path: first.path.display().to_string(),
        }),
    }
}

/// Verify the *structure* of the whole set without walking any interior.
///
/// Reads the boundary lines of each segment and verifies their signatures, so
/// every handoff is cryptographically checked and a removed segment is still
/// named — at `O(number of segments)` rather than `O(entire history)`. No
/// interior is walked, including the active segment's, so every report comes
/// back with `entries: None`.
///
/// This is half of what a routine health check wants. The other half is the
/// live segment's contents, which the caller walks itself — `doctor` resumes
/// that one from a checkpoint, which is a different trade (a stored value's
/// word instead of the genesis anchor) and has to be reported as its own
/// statement rather than folded into this one. [`verify_segment_set`] is what
/// attests everything, from the anchor, at full cost.
pub fn verify_segment_topology(
    dir: &Path,
    base: &str,
    vk: &VerifyingKey,
) -> Result<Vec<SegmentReport>, SegmentSetError> {
    walk(dir, base, vk, false).map(reports_of)
}

fn reports_of(segments: Vec<SegmentContent>) -> Vec<SegmentReport> {
    segments
        .into_iter()
        .map(|s| SegmentReport {
            seq: s.seq,
            path: s.path,
            active: s.active,
            entries: s.entries.map(|e| e.len()),
        })
        .collect()
}

/// Every authenticated entry across the whole set, in chain order.
///
/// This is what a reader of the log wants: rotation is an implementation
/// detail of how the evidence is stored, not of what the evidence says. A
/// consumer that enumerated segment files itself would have to re-derive the
/// ordering and the handoff checks, and the first one to get it slightly wrong
/// would read a spliced set as a chronology.
pub fn verify_segment_entries(
    dir: &Path,
    base: &str,
    vk: &VerifyingKey,
) -> Result<Vec<crate::supervisor::audit::AuditEntry>, SegmentSetError> {
    Ok(walk(dir, base, vk, true)?
        .into_iter()
        .flat_map(|s| s.entries.unwrap_or_default())
        .collect())
}

/// Verify every segment end to end, in order, including every handoff.
pub fn verify_segment_set(
    dir: &Path,
    base: &str,
    vk: &VerifyingKey,
) -> Result<Vec<SegmentReport>, SegmentSetError> {
    walk(dir, base, vk, true).map(reports_of)
}

/// Verify every segment end to end and hand back the verified bytes, in chain
/// order.
///
/// This is what the Merkle root builder needs: leaves have to come from the
/// same buffers the verification ran over, and they have to span the whole set.
/// A root built over the active segment alone would silently attest less than
/// it used to the first time a host rotated.
pub fn read_verified_set(
    dir: &Path,
    base: &str,
    vk: &VerifyingKey,
) -> Result<Vec<SegmentContent>, SegmentSetError> {
    walk(dir, base, vk, true)
}

fn walk(
    dir: &Path,
    base: &str,
    vk: &VerifyingKey,
    interiors: bool,
) -> Result<Vec<SegmentContent>, SegmentSetError> {
    let located = locate(dir, base)?;
    let mut contents = Vec::with_capacity(located.len());
    let mut prev: Option<(u64, Sealed, [u8; 32])> = None;

    for (idx, seg) in located.iter().enumerate() {
        // One read per segment. Every check below — boundaries, interior walk,
        // leaf bytes — is derived from this buffer, so what is attested and
        // what is used are provably the same bytes.
        let content =
            std::fs::read_to_string(&seg.path).map_err(|e| SegmentSetError::Io(e.to_string()))?;
        let fail = |source| SegmentSetError::Segment {
            seq: seg.seq,
            path: seg.path.display().to_string(),
            source,
        };

        // An empty *active* file is a chain that has not been written to yet —
        // a real, clean state that predates rotation and must keep verifying as
        // zero entries. An empty *sealed* segment is not: a retired segment
        // always carries at least its own sealing record, so emptiness there
        // means the file was emptied after it was sealed.
        if content.lines().all(str::is_empty) {
            if !seg.active {
                return Err(SegmentSetError::Unsealed {
                    seq: seg.seq,
                    path: seg.path.display().to_string(),
                });
            }
            contents.push(SegmentContent {
                seq: seg.seq,
                path: seg.path.clone(),
                active: true,
                content,
                entries: interiors.then(Vec::new),
            });
            continue;
        }
        // The chain walk runs before any structural check, so its precise
        // per-line verdict wins.
        //
        // The structural checks below read the segment's boundary lines, and on
        // a garbage or half-written file they would trip first — reporting "this
        // set is malformed somewhere" where the verifier reports "line 1 is a
        // truncated tail". The reader turns that verdict into the refusal an
        // operator triages, and telling a crashed writer from a tampered log is
        // precisely what they need it for.
        let entries = if interiors {
            Some(verify_chain_bytes(&content, vk).map_err(fail)?.entries)
        } else {
            None
        };

        let ends = read_ends(&seg.path, &content, seg.seq)?;

        if idx == 0 {
            check_front(seg, &ends)?;
        } else {
            let (prev_seq, prev_sealed, prev_tip) = prev.take().expect("set after first segment");
            // A gap in the sequence is reported against what the successor
            // *claims* to continue rather than against arithmetic on the
            // filenames, so the message names the segment that is actually
            // missing rather than the next number up.
            let cont = continuation_from_entry(&ends.first.entry).ok_or(
                SegmentSetError::MissingHandoff {
                    seq: seg.seq,
                    path: seg.path.display().to_string(),
                },
            )?;
            check_boundary(prev_seq, &prev_sealed, prev_tip, seg.seq, &cont)?;
            verify_line(&ends.first, vk, seg.seq, &seg.path)?;
        }

        if !seg.active {
            let sealed = sealed_from_entry(&ends.last.entry).ok_or(SegmentSetError::Unsealed {
                seq: seg.seq,
                path: seg.path.display().to_string(),
            })?;
            if sealed.segment != seg.seq {
                return Err(SegmentSetError::Unsealed {
                    seq: seg.seq,
                    path: seg.path.display().to_string(),
                });
            }
            // The sealing record is a boundary line too: without checking it,
            // its entry count could be edited freely.
            verify_line(&ends.last, vk, seg.seq, &seg.path)?;
            // The claimed length is checked against the file even when the
            // interior is not walked, so adding or removing a line from a
            // sealed segment is caught by the cheap check too.
            if ends.lines as u64 != sealed.entries {
                return Err(SegmentSetError::EntryCountMismatch {
                    seq: seg.seq,
                    prev: seg.seq,
                    sealed: sealed.entries,
                    claimed: ends.lines as u64,
                });
            }
            prev = Some((seg.seq, sealed, ends.tip));
        }

        contents.push(SegmentContent {
            seq: seg.seq,
            path: seg.path.clone(),
            active: seg.active,
            content,
            entries,
        });
    }
    Ok(contents)
}
