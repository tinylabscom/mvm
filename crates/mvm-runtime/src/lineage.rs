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

/// A store the walk reads records from: by a start id, by content-address to
/// resolve a parent hash-link, or by parent digest to enumerate forward
/// children.
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
    /// Every stored record whose parent hash-link is `parent_digest`. Forward
    /// lineage is a tree: a node may have several children (forks), so this
    /// returns a set rather than an `Option`.
    fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<Self::Record>>;
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

/// The verification verdict for one enumerated lineage node, checked against the
/// signed audit chain. Unlike [`verify_lineage_chain`] — which bails on the
/// first failure — enumeration *records* a failure so a read-only navigator can
/// render the whole lineage while marking the bad hop. Marking, never hiding:
/// the caller must not present a `Failed` node as a valid one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopStatus {
    /// The node's content-address matched both its recompute and the signed
    /// chain's recorded creation digest.
    Verified,
    /// Verification failed; the string is the fail-closed reason
    /// ([`verify_record_against_chain`]'s error: drift, chain mismatch, or no
    /// signed entry).
    Failed(String),
}

impl HopStatus {
    /// `true` only for [`HopStatus::Verified`].
    pub fn is_verified(&self) -> bool {
        matches!(self, HopStatus::Verified)
    }

    /// The failure reason, or `None` when verified.
    pub fn error(&self) -> Option<&str> {
        match self {
            HopStatus::Verified => None,
            HopStatus::Failed(reason) => Some(reason),
        }
    }
}

/// One enumerated lineage node paired with its chain-verification verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNode<R> {
    pub record: R,
    pub status: HopStatus,
}

/// A record's ancestry: the record itself plus every ancestor up to genesis,
/// each verified against the signed chain, ordered start → genesis. `broken`
/// carries a fail-closed reason when the walk could not reach genesis (a
/// dangling parent hash-link or a would-be cycle); `None` means it terminated
/// cleanly at a genesis root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestry<R> {
    pub nodes: Vec<VerifiedNode<R>>,
    pub broken: Option<String>,
}

impl<R> Ancestry<R> {
    /// `true` iff every node verified AND the walk reached genesis without a
    /// structural break. A single failed hop or a break makes the whole
    /// ancestry unverified — fail closed.
    pub fn fully_verified(&self) -> bool {
        self.broken.is_none() && self.nodes.iter().all(|n| n.status.is_verified())
    }
}

/// Enumerate a record's ancestry from `start` up to its genesis root, verifying
/// each node against the signed audit chain via `anchor`. The read-only
/// enumeration analog of [`verify_lineage_chain`]: it reuses the same
/// content-address hash-link walk and the same guards, but instead of bailing on
/// the first bad node it records the node's [`HopStatus`] and keeps walking, so a
/// navigator can render the full chain with the failing hop marked. It still
/// fails closed on the *structural* breaks a verdict cannot express — a dangling
/// parent hash-link or a would-be cycle — by terminating the walk and reporting
/// the reason in [`Ancestry::broken`] rather than looping or fabricating a link.
///
/// The initial [`LineageGraph::read`] of `start` is the one hard error: a start
/// that cannot even be read is returned as `Err` (there is no lineage to show).
pub(crate) fn collect_ancestry<G, A>(
    graph: &G,
    start: &G::Id,
    anchor: &A,
) -> Result<Ancestry<G::Record>>
where
    G: LineageGraph,
    A: LineageAnchor<G::Record> + ?Sized,
{
    let mut current = graph.read(start)?;
    let mut nodes: Vec<VerifiedNode<G::Record>> = Vec::new();
    let mut seen: Vec<CheckpointDigest> = Vec::new();
    let broken = loop {
        // Cycle guard first: a genuine content-address chain cannot revisit a
        // digest, so a revisit is a forged/broken set — stop before re-adding it
        // (which would also loop forever).
        if seen.contains(current.stored_digest()) {
            break Some(format!(
                "{} '{}' lineage revisits digest {}: refusing a cyclic chain",
                current.kind(),
                current.id_label(),
                current.stored_digest()
            ));
        }
        let status = match verify_record_against_chain(anchor, &current) {
            Ok(()) => HopStatus::Verified,
            Err(e) => HopStatus::Failed(format!("{e:#}")),
        };
        seen.push(current.stored_digest().clone());

        let kind = current.kind();
        let parent_digest = current.parent_link().cloned();
        nodes.push(VerifiedNode {
            record: current,
            status,
        });

        let Some(parent_digest) = parent_digest else {
            // Genesis root: no parent to chain to, the walk terminates clean.
            break None;
        };
        // Resolving the parent by its content-address *is* the hash-link check:
        // by_digest only returns a record whose stored digest equals the link,
        // and that record's own digest is re-verified on the next iteration.
        match graph.by_digest(&parent_digest)? {
            Some(parent) => current = parent,
            None => {
                break Some(format!(
                    "{kind} lineage is broken: no {kind} has parent-linked digest {parent_digest}"
                ));
            }
        }
    };
    Ok(Ancestry { nodes, broken })
}

/// Enumerate a record's immediate children (forward is a tree — a node may have
/// several forks), each verified against the signed chain via `anchor`. Verifies
/// but does not recurse: one generation of forward branches, each marked with its
/// own [`HopStatus`] so a tampered / un-audited child is surfaced, never hidden.
pub(crate) fn verified_children<G, A>(
    graph: &G,
    parent_digest: &CheckpointDigest,
    anchor: &A,
) -> Result<Vec<VerifiedNode<G::Record>>>
where
    G: LineageGraph,
    A: LineageAnchor<G::Record> + ?Sized,
{
    let mut out = Vec::new();
    for child in graph.children_of(parent_digest)? {
        let status = match verify_record_against_chain(anchor, &child) {
            Ok(()) => HopStatus::Verified,
            Err(e) => HopStatus::Failed(format!("{e:#}")),
        };
        out.push(VerifiedNode {
            record: child,
            status,
        });
    }
    Ok(out)
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
        fn children_of(&self, parent: &CheckpointDigest) -> Result<Vec<MockRecord>> {
            let mut kids: Vec<MockRecord> = self
                .by_stored
                .values()
                .filter(|r| r.parent.as_ref() == Some(parent))
                .cloned()
                .collect();
            // Deterministic order for assertions (HashMap iteration is not).
            kids.sort_by(|a, b| a.stored.as_str().cmp(b.stored.as_str()));
            Ok(kids)
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

    // ── enumeration: collect_ancestry ────────────────────────────────────────

    /// Digests carried by the ancestry, in walk order (start → genesis).
    fn ancestry_order(a: &Ancestry<MockRecord>) -> Vec<String> {
        a.nodes
            .iter()
            .map(|n| n.record.stored.to_string())
            .collect()
    }

    #[test]
    fn ancestry_collects_start_to_genesis_in_order_each_verified() {
        let graph = MockGraph::new(vec![
            record('a', None),
            record('b', Some('a')),
            record('c', Some('b')),
        ]);
        let ancestry = collect_ancestry(&graph, &digest('c'), &AgreeingAnchor).unwrap();
        assert_eq!(
            ancestry_order(&ancestry),
            vec![
                digest('c').to_string(),
                digest('b').to_string(),
                digest('a').to_string()
            ],
            "nodes must be ordered start → genesis"
        );
        assert!(ancestry.broken.is_none(), "a clean chain reaches genesis");
        assert!(ancestry.fully_verified());
        assert!(ancestry.nodes.iter().all(|n| n.status.is_verified()));
    }

    #[test]
    fn ancestry_of_a_genesis_node_is_just_itself() {
        let graph = MockGraph::new(vec![record('a', None)]);
        let ancestry = collect_ancestry(&graph, &digest('a'), &AgreeingAnchor).unwrap();
        assert_eq!(ancestry.nodes.len(), 1);
        assert!(ancestry.nodes[0].record.parent.is_none());
        assert!(ancestry.broken.is_none());
        assert!(ancestry.fully_verified());
    }

    #[test]
    fn a_tampered_hop_is_surfaced_as_failed_not_dropped() {
        // Middle node drifts (stored != recompute); the walk must still list all
        // three nodes and mark exactly the drifted one Failed.
        let mut mid = record('b', Some('a'));
        mid.recompute = digest('e');
        let graph = MockGraph::new(vec![record('a', None), mid, record('c', Some('b'))]);
        let ancestry = collect_ancestry(&graph, &digest('c'), &AgreeingAnchor).unwrap();
        assert_eq!(
            ancestry.nodes.len(),
            3,
            "the failed hop must NOT be dropped"
        );
        assert!(
            ancestry.nodes[0].status.is_verified(),
            "target 'c' verifies"
        );
        let failed = &ancestry.nodes[1];
        assert_eq!(failed.record.stored, digest('b'));
        assert!(!failed.status.is_verified());
        assert!(
            failed.status.error().unwrap().contains("drift"),
            "the failure reason is preserved: {:?}",
            failed.status.error()
        );
        assert!(
            !ancestry.fully_verified(),
            "one failed hop fails the whole chain"
        );
        // The walk still reached genesis past the tampered node.
        assert!(ancestry.broken.is_none());
    }

    #[test]
    fn an_unaudited_hop_is_surfaced_as_failed() {
        let graph = MockGraph::new(vec![record('a', None)]);
        let ancestry = collect_ancestry(&graph, &digest('a'), &UnauditedAnchor).unwrap();
        assert!(!ancestry.nodes[0].status.is_verified());
        assert!(
            ancestry.nodes[0]
                .status
                .error()
                .unwrap()
                .contains("no signed audit entry")
        );
        assert!(!ancestry.fully_verified());
    }

    #[test]
    fn ancestry_reports_a_dangling_parent_as_broken() {
        // Child links to a parent digest no stored record carries.
        let graph = MockGraph::new(vec![record('a', Some('e'))]);
        let ancestry = collect_ancestry(&graph, &digest('a'), &AgreeingAnchor).unwrap();
        // The reachable node is still listed and verified...
        assert_eq!(ancestry.nodes.len(), 1);
        assert!(ancestry.nodes[0].status.is_verified());
        // ...but the walk could not reach genesis, so it fails closed.
        assert!(
            ancestry
                .broken
                .as_ref()
                .unwrap()
                .contains("lineage is broken")
        );
        assert!(!ancestry.fully_verified());
    }

    #[test]
    fn ancestry_refuses_a_cycle_without_looping() {
        // a→b→a; a hang here (no cycle guard) would time the test out.
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
        let ancestry = collect_ancestry(&graph, &digest('a'), &AgreeingAnchor).unwrap();
        assert!(ancestry.broken.as_ref().unwrap().contains("cyclic chain"));
        // Each distinct node is listed exactly once, not re-added on revisit.
        assert_eq!(ancestry.nodes.len(), 2);
        assert!(!ancestry.fully_verified());
    }

    // ── enumeration: verified_children ───────────────────────────────────────

    #[test]
    fn children_are_enumerated_and_each_verified() {
        // genesis 'a' forks into two children 'b' and 'c'.
        let graph = MockGraph::new(vec![
            record('a', None),
            record('b', Some('a')),
            record('c', Some('a')),
        ]);
        let kids = verified_children(&graph, &digest('a'), &AgreeingAnchor).unwrap();
        let digests: Vec<String> = kids.iter().map(|k| k.record.stored.to_string()).collect();
        assert_eq!(
            digests,
            vec![digest('b').to_string(), digest('c').to_string()]
        );
        assert!(kids.iter().all(|k| k.status.is_verified()));
    }

    #[test]
    fn a_node_with_no_children_enumerates_empty() {
        let graph = MockGraph::new(vec![record('a', None)]);
        assert!(
            verified_children(&graph, &digest('a'), &AgreeingAnchor)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_tampered_child_is_marked_failed_not_dropped() {
        let mut child = record('b', Some('a'));
        child.recompute = digest('e'); // drift
        let graph = MockGraph::new(vec![record('a', None), child]);
        let kids = verified_children(&graph, &digest('a'), &AgreeingAnchor).unwrap();
        assert_eq!(kids.len(), 1, "the tampered child is listed, not hidden");
        assert!(!kids[0].status.is_verified());
        assert!(kids[0].status.error().unwrap().contains("drift"));
    }
}
