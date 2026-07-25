//! Generic, namespace-agnostic hash-linked lineage verification shared by the
//! checkpoint store and the image-lineage store. The walk is written once here
//! over three small traits; [`crate::checkpoint`] and [`crate::image_lineage`]
//! supply the record/store/anchor impls and delegate to it rather than forking
//! a second copy.
//!
//! Both lineages share the same guarantee and the same fail-closed posture:
//! each record's recomputed content-address must equal both its stored digest
//! (catching a post-seal edit) AND the digest the host signed into the audit
//! chain at creation (catching a fully self-consistent local re-forge, which
//! survives recompute alone but not the signed chain it cannot re-sign). The
//! parent hash-link is followed by content-address, so editing any ancestor's
//! sealed record is caught from any descendant.

use anyhow::Result;
use mvm_core::checkpoint::CheckpointDigest;

/// One record in a content-addressed lineage: it carries its own stored
/// content-address, can recompute that address from its load-bearing fields,
/// and hash-links to its predecessor by content-address.
pub(crate) trait LineageRecord {
    /// The content-address stored on disk for this record.
    fn stored_digest(&self) -> &CheckpointDigest;
    /// Recompute the content-address from the record's current fields. Equal to
    /// [`Self::stored_digest`] iff the record was not edited after sealing.
    fn recompute_digest(&self) -> CheckpointDigest;
    /// The predecessor's content-address, or `None` at genesis.
    fn parent_link(&self) -> Option<&CheckpointDigest>;
    /// Human noun for error messages, e.g. `"checkpoint"` / `"image node"`.
    fn kind(&self) -> &'static str;
    /// The record's own identifier for error messages (checkpoint id / node
    /// digest).
    fn id_label(&self) -> String;
    /// The on-disk digest field's name, for drift messages (`"meta_digest"` /
    /// `"node_digest"`).
    fn digest_field(&self) -> &'static str;
}

/// A store the walk reads records from: by a start id, or by content-address to
/// resolve a parent hash-link.
pub(crate) trait LineageGraph {
    type Record: LineageRecord;
    type Id;
    /// Read the record the walk starts at.
    fn read(&self, id: &Self::Id) -> Result<Self::Record>;
    /// The record whose stored content-address is `digest`, or `None` if no
    /// stored record carries it. Returning only a record whose own digest equals
    /// the link is what makes resolving a parent by content-address *be* the
    /// hash-link check.
    fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<Self::Record>>;
}

/// Resolves the signature-authenticated content-address a record's creation was
/// recorded under in the chain-signed audit log. An implementation MUST verify
/// the audit chain's signatures before trusting any digest it returns.
pub(crate) trait LineageAnchor<R> {
    fn recorded_creation_digest(&self, record: &R) -> Result<Option<CheckpointDigest>>;
}

/// Verify one record against the signed chain: its stored digest must equal a
/// recomputation of its own fields (catches a post-seal edit that left the
/// digest stale) AND must equal the signature-verified digest the audit chain
/// recorded at creation (catches a full local re-forge). Fails closed on a
/// drift, a mismatch against the chain, or the absence of any signed creation
/// entry.
pub(crate) fn verify_record_against_chain<R, A>(anchor: &A, record: &R) -> Result<()>
where
    R: LineageRecord,
    A: LineageAnchor<R> + ?Sized,
{
    let recomputed = record.recompute_digest();
    if &recomputed != record.stored_digest() {
        anyhow::bail!(
            "{} '{}' {} drift: stored {}, recomputed {} \
             (its on-disk record was edited after sealing)",
            record.kind(),
            record.id_label(),
            record.digest_field(),
            record.stored_digest(),
            recomputed
        );
    }
    match anchor.recorded_creation_digest(record)? {
        Some(recorded) if recorded == recomputed => Ok(()),
        Some(recorded) => anyhow::bail!(
            "{} '{}' content-address {recomputed} does not match the signed audit \
             chain, which recorded {recorded} at creation \
             (the on-disk record was edited after it was audited)",
            record.kind(),
            record.id_label()
        ),
        None => anyhow::bail!(
            "{} '{}' has no signed audit entry to anchor its content-address; \
             refusing to treat an un-audited record as verified",
            record.kind(),
            record.id_label()
        ),
    }
}

/// Walk a record's lineage from `start` up to its genesis root, verifying each
/// record against the signed audit chain via `anchor`. Fails closed on: a drift
/// or chain mismatch (via [`verify_record_against_chain`]), a parent hash-link
/// that resolves to no stored record (dangling lineage), or a revisited digest
/// (a would-be cycle — cryptographically infeasible for genuine
/// content-addresses, refused rather than looped on).
pub(crate) fn verify_lineage_chain<G, A>(graph: &G, start: &G::Id, anchor: &A) -> Result<()>
where
    G: LineageGraph,
    A: LineageAnchor<G::Record> + ?Sized,
{
    let mut current = graph.read(start)?;
    let mut seen: Vec<CheckpointDigest> = Vec::new();
    loop {
        verify_record_against_chain(anchor, &current)?;
        if seen.contains(current.stored_digest()) {
            anyhow::bail!(
                "{} '{}' lineage revisits digest {}: refusing a cyclic chain",
                current.kind(),
                current.id_label(),
                current.stored_digest()
            );
        }
        seen.push(current.stored_digest().clone());

        let kind = current.kind();
        let parent_digest = match current.parent_link() {
            // Genesis root: no parent to chain to, the walk terminates clean.
            None => return Ok(()),
            Some(d) => d.clone(),
        };
        // Resolving the parent by its content-address *is* the hash-link check:
        // by_digest only returns a record whose stored digest equals the link,
        // and that record's own digest is re-verified on the next iteration.
        current = graph.by_digest(&parent_digest)?.ok_or_else(|| {
            anyhow::anyhow!(
                "{kind} lineage is broken: no {kind} has parent-linked digest {parent_digest}"
            )
        })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn digest(seed: char) -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", seed.to_string().repeat(64))).unwrap()
    }

    /// A fully controllable record: its stored digest, recompute result, and
    /// parent link are all set by the test, so cases impossible to construct
    /// with a real content-address (a genuine cycle) are reachable here.
    #[derive(Clone)]
    struct MockRecord {
        stored: CheckpointDigest,
        recompute: CheckpointDigest,
        parent: Option<CheckpointDigest>,
    }

    impl LineageRecord for MockRecord {
        fn stored_digest(&self) -> &CheckpointDigest {
            &self.stored
        }
        fn recompute_digest(&self) -> CheckpointDigest {
            self.recompute.clone()
        }
        fn parent_link(&self) -> Option<&CheckpointDigest> {
            self.parent.as_ref()
        }
        fn kind(&self) -> &'static str {
            "mock"
        }
        fn id_label(&self) -> String {
            self.stored.to_string()
        }
        fn digest_field(&self) -> &'static str {
            "mock_digest"
        }
    }

    struct MockGraph {
        by_stored: HashMap<String, MockRecord>,
    }

    impl MockGraph {
        fn new(records: Vec<MockRecord>) -> Self {
            let by_stored = records
                .into_iter()
                .map(|r| (r.stored.to_string(), r))
                .collect();
            Self { by_stored }
        }
    }

    impl LineageGraph for MockGraph {
        type Record = MockRecord;
        type Id = CheckpointDigest;
        fn read(&self, id: &CheckpointDigest) -> Result<MockRecord> {
            self.by_stored
                .get(id.as_str())
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no record {id}"))
        }
        fn by_digest(&self, d: &CheckpointDigest) -> Result<Option<MockRecord>> {
            Ok(self.by_stored.get(d.as_str()).cloned())
        }
    }

    /// Anchor that echoes each record's own recompute — the honest case.
    struct AgreeingAnchor;
    impl LineageAnchor<MockRecord> for AgreeingAnchor {
        fn recorded_creation_digest(&self, r: &MockRecord) -> Result<Option<CheckpointDigest>> {
            Ok(Some(r.recompute_digest()))
        }
    }

    struct UnauditedAnchor;
    impl LineageAnchor<MockRecord> for UnauditedAnchor {
        fn recorded_creation_digest(&self, _r: &MockRecord) -> Result<Option<CheckpointDigest>> {
            Ok(None)
        }
    }

    struct DisagreeingAnchor(CheckpointDigest);
    impl LineageAnchor<MockRecord> for DisagreeingAnchor {
        fn recorded_creation_digest(&self, _r: &MockRecord) -> Result<Option<CheckpointDigest>> {
            Ok(Some(self.0.clone()))
        }
    }

    fn record(stored: char, parent: Option<char>) -> MockRecord {
        MockRecord {
            stored: digest(stored),
            recompute: digest(stored),
            parent: parent.map(digest),
        }
    }

    #[test]
    fn genesis_and_multi_generation_chains_verify() {
        let g0 = record('a', None);
        let g1 = record('b', Some('a'));
        let g2 = record('c', Some('b'));
        let graph = MockGraph::new(vec![g0, g1, g2]);
        verify_lineage_chain(&graph, &digest('c'), &AgreeingAnchor).unwrap();
        verify_lineage_chain(&graph, &digest('a'), &AgreeingAnchor).unwrap();
    }

    #[test]
    fn drift_between_stored_and_recompute_is_rejected() {
        let mut r = record('a', None);
        r.recompute = digest('e'); // stored != recompute (valid but different hex)
        let graph = MockGraph::new(vec![r]);
        let err = verify_lineage_chain(&graph, &digest('a'), &AgreeingAnchor).unwrap_err();
        assert!(err.to_string().contains("mock_digest drift"), "{err}");
    }

    #[test]
    fn chain_recorded_digest_mismatch_is_rejected() {
        let graph = MockGraph::new(vec![record('a', None)]);
        let err = verify_lineage_chain(&graph, &digest('a'), &DisagreeingAnchor(digest('f')))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "{err}"
        );
    }

    #[test]
    fn node_with_no_signed_entry_is_rejected() {
        let graph = MockGraph::new(vec![record('a', None)]);
        let err = verify_lineage_chain(&graph, &digest('a'), &UnauditedAnchor).unwrap_err();
        assert!(err.to_string().contains("no signed audit entry"), "{err}");
    }

    #[test]
    fn dangling_parent_is_rejected() {
        // Child links to a parent digest no stored record carries.
        let graph = MockGraph::new(vec![record('a', Some('e'))]);
        let err = verify_lineage_chain(&graph, &digest('a'), &AgreeingAnchor).unwrap_err();
        assert!(err.to_string().contains("lineage is broken"), "{err}");
    }

    #[test]
    fn a_genuine_cycle_is_refused_not_looped_on() {
        // Only reachable with hand-set digests: a real content-address cannot
        // encode a cycle. a→b→a; the anchor agrees so drift/mismatch don't fire
        // first, isolating the cycle guard.
        let a = MockRecord {
            stored: digest('a'),
            recompute: digest('a'),
            parent: Some(digest('b')),
        };
        let b = MockRecord {
            stored: digest('b'),
            recompute: digest('b'),
            parent: Some(digest('a')),
        };
        let graph = MockGraph::new(vec![a, b]);

        // The cycle guard must terminate the walk (a hang here would time the
        // test out) and refuse rather than loop.
        let err = verify_lineage_chain(&graph, &digest('a'), &AgreeingAnchor).unwrap_err();
        assert!(err.to_string().contains("cyclic chain"), "{err}");
    }
}
