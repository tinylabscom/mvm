//! The signed-audit-chain anchors checkpoint and image lineage verify against.

use anyhow::{Context, Result};

use mvm_core::checkpoint::{CheckpointDigest, CheckpointMeta};
use mvm_core::image_lineage::ImageNode;
use mvm_runtime::checkpoint::CheckpointChainAnchor;
use mvm_runtime::image_lineage::ImageChainAnchor;

/// A [`CheckpointChainAnchor`] backed by the host-signed audit chains on disk.
///
/// Verifies every host-lifecycle chain's signatures up front (skipping the
/// per-VM workload chains, which use a different format) and indexes the
/// content-address each checkpoint's creation entry recorded. Only entries from
/// chains that verify clean are indexed: an entry stranded behind a tampered
/// line is not trusted, so the checkpoint it names fails closed as un-anchored.
///
/// A chain that fails verification is skipped but *remembered*, because the two
/// ways a lookup can come back empty are not the same finding and must not
/// share a message. With every chain clean, an empty lookup means the record
/// was never audited — a step someone skipped, fixable by re-capturing with a
/// signer present. With a chain unreadable, an empty lookup means only that the
/// ledger cannot answer: the record may be perfectly well audited behind the
/// broken line. Reporting the second as the first buries a tamper signal under
/// a routine-looking message. Both fail closed; only the reason differs, and
/// only one of them tells you to investigate.
pub struct SignedChainAnchor {
    /// `<namespace>:<id>` -> content-address the signed chain recorded at
    /// creation. The namespace tag (`checkpoint` / `image`) keeps the checkpoint
    /// and image key spaces structurally disjoint in one map, rather than
    /// relying on their raw id/digest strings happening not to collide.
    recorded: std::collections::HashMap<String, RecordedCreation>,
    /// Host-lifecycle chains whose signatures did not verify, in the order
    /// encountered. Non-empty turns a lookup miss from "never audited" into
    /// "cannot tell" — see the type docs.
    unverifiable: Vec<std::path::PathBuf>,
}

/// What a signed creation entry recorded about one record.
#[derive(Debug, Clone)]
struct RecordedCreation {
    /// The content-address the entry recorded.
    digest: CheckpointDigest,
    /// The tenant whose chain the entry was signed into.
    tenant: String,
    plan_id: String,
}

/// Namespace tag for a checkpoint-id key in [`SignedChainAnchor::recorded`].
const CHECKPOINT_NS: &str = "checkpoint";
/// Namespace tag for an image-node-digest key in [`SignedChainAnchor::recorded`].
const IMAGE_NS: &str = "image";

/// Compose a namespaced anchor-map key so the checkpoint and image key spaces
/// cannot collide. The same composition is used by the indexer (writer) and
/// both `recorded_creation_digest` lookups (readers), so the key cannot drift.
fn anchor_key(namespace: &str, id: &str) -> String {
    format!("{namespace}:{id}")
}

impl SignedChainAnchor {
    /// Plan identity recorded by the verified creation entry for a checkpoint.
    pub fn checkpoint_plan_id(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.plan_id))
    }

    /// Construct an intentionally empty anchor for resident claims whose
    /// signed snapshot manifest is the publication witness. Saved-state
    /// restores must use [`Self::load`] and verify the full audit chain.
    pub fn empty() -> Self {
        Self {
            recorded: std::collections::HashMap::new(),
            unverifiable: Vec::new(),
        }
    }

    pub fn load() -> Result<Self> {
        use mvm_hostd::audit::emitter::default_audit_dir;

        let dir = default_audit_dir()?;
        let mut recorded = std::collections::HashMap::new();
        let mut unverifiable = Vec::new();
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // No audit dir yet → nothing to anchor; every lookup is None (fail closed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    recorded,
                    unverifiable,
                });
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };

        // All lifecycle chains are signed under the one host key.
        let signer = mvm_hostd::audit::host_keypair::load_or_init()
            .context("loading host signer to anchor checkpoint lineage")?;

        for entry in read_dir {
            let path = entry?.path();
            if !mvm_core::config::is_host_lifecycle_chain(&path) {
                continue;
            }
            // A chain we cannot verify cannot anchor anything: skip it whole so a
            // tampered line strands (rather than silently trusts) its entries.
            // Recorded, not just logged — a later lookup miss has to be able to
            // say "cannot tell" instead of "never audited".
            if let Err(e) = mvm_hostd::supervisor::verify_audit_chain(&path, &signer.verifying) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "audit chain failed verification; its entries will not anchor any checkpoint"
                );
                unverifiable.push(path);
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            for line in content.lines() {
                if line.is_empty() {
                    continue;
                }
                let envelope: mvm_hostd::supervisor::SignedEnvelope = serde_json::from_str(line)
                    .with_context(|| format!("parsing audit line in {}", path.display()))?;
                index_creation_digest(&mut recorded, &envelope)?;
            }
        }
        Ok(Self {
            recorded,
            unverifiable,
        })
    }

    /// Resolve one namespaced anchor key.
    ///
    /// A hit is a hit regardless of what else on disk is broken — it came from a
    /// chain that verified. A miss is only honestly "never audited" when every
    /// chain verified; with one unreadable, the honest answer is that we cannot
    /// tell, which is an `Err` rather than a `None`. Both refuse the record, so
    /// this changes no verdict — it changes what the operator is told to do
    /// about it.
    fn lookup(&self, key: &str) -> Result<Option<RecordedCreation>> {
        if let Some(recorded) = self.recorded.get(key) {
            return Ok(Some(recorded.clone()));
        }
        if self.unverifiable.is_empty() {
            return Ok(None);
        }
        let paths = self
            .unverifiable
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "{}: {} audit chain(s) unverifiable: {paths}. The record may well be audited — the \
             ledger is what cannot be read, so this is a damaged integrity chain and not a \
             missing audit entry. Run `mvmctl trust audit verify` to see where the chain breaks. \
             Recovery is deliberate and manual: quarantine the file under a new name so the \
             evidence survives. Do not delete it, and do not re-sign it — a chain that can be \
             reset on demand cannot detect tampering.",
            mvm_runtime::lineage::LEDGER_UNVERIFIABLE,
            self.unverifiable.len()
        )
    }
}

/// Index one signed audit entry's creation content-address, when it is a
/// checkpoint or image-node creation event. `checkpoint.created` keys on
/// `checkpoint_id`/`meta_digest`; `checkpoint.forked` is a child's creation, so
/// it keys on `child_id`/`child_digest`. `image.created` has no separate id —
/// the node's identity *is* its content-address — so it keys the digest under
/// itself.
fn index_creation_digest(
    recorded: &mut std::collections::HashMap<String, RecordedCreation>,
    envelope: &mvm_hostd::supervisor::SignedEnvelope,
) -> Result<()> {
    index_creation_entry(recorded, &envelope.entry)
}

/// The (id-label, digest-label, namespace) a creation event keys on, or `None`
/// for an event that records no creation.
fn creation_keys(event: &str) -> Option<(&'static str, &'static str, &'static str)> {
    use mvm_hostd::audit::emitter::checkpoint_audit as k;
    use mvm_hostd::audit::emitter::image_audit as ik;
    if event == k::CREATED_EVENT {
        Some((k::LABEL_CHECKPOINT_ID, k::LABEL_META_DIGEST, CHECKPOINT_NS))
    } else if event == k::FORKED_EVENT {
        Some((k::LABEL_CHILD_ID, k::LABEL_CHILD_DIGEST, CHECKPOINT_NS))
    } else if event == ik::CREATED_EVENT {
        Some((ik::LABEL_NODE_DIGEST, ik::LABEL_NODE_DIGEST, IMAGE_NS))
    } else {
        None
    }
}

/// [`index_creation_digest`] for an entry already authenticated.
fn index_creation_entry(
    recorded: &mut std::collections::HashMap<String, RecordedCreation>,
    entry: &mvm_core::audit_verify::PlanAuditEntry,
) -> Result<()> {
    let Some((id_key, digest_key, namespace)) = creation_keys(entry.event.as_str()) else {
        return Ok(());
    };
    let labels = &entry.labels;
    if let (Some(id), Some(digest)) = (labels.get(id_key), labels.get(digest_key)) {
        recorded.insert(
            anchor_key(namespace, id),
            RecordedCreation {
                digest: CheckpointDigest::parse(digest.clone())?,
                tenant: entry.tenant.0.clone(),
                plan_id: entry.plan_id.0.clone(),
            },
        );
    }
    Ok(())
}

/// The anchor a warm claim verifies its parent against.
///
/// [`SignedChainAnchor::load`] verifies every host-lifecycle chain end to end,
/// and that walk grows with every entry the host has ever written: on a host
/// with about 11 MB of audit history it alone put warm claims past the 300 ms
/// ceiling. A claim needs one answer — the creation entry of the parent it is
/// about to restore — and that parent was captured and audited recently, so its
/// entry is almost always in a live segment. This anchor authenticates that one
/// entry in place ([`mvm_core::audit_verify::live::authenticate_live_entries`]):
/// its host signature over the exact signed bytes and its chain link to the
/// line before it. Any other question, and the parent's own question whenever
/// the live segments do not answer it with exactly one authenticated creation
/// entry, falls back to the full walk, so every verdict the full anchor would
/// reach on those paths is unchanged.
///
/// What a claim no longer does is re-attest the rest of the history on every
/// launch. That stays verified where history is the question:
/// `mvmctl trust audit verify`, doctor's chain check, `mvmctl vm checkpoint
/// verify`, and the pool refill, which still use [`SignedChainAnchor::load`].
pub struct ClaimChainAnchor {
    /// Creation entries authenticated in place in a live segment.
    preverified: std::collections::HashMap<String, RecordedCreation>,
    /// The full walk, loaded only when a lookup is not answered above.
    full: std::sync::OnceLock<std::result::Result<SignedChainAnchor, String>>,
}

impl ClaimChainAnchor {
    /// An anchor that answers `checkpoint`'s creation from the live segments
    /// when they hold exactly one authenticated creation entry for it.
    pub fn for_checkpoint(checkpoint: &mvm_core::checkpoint::CheckpointId) -> Result<Self> {
        use mvm_hostd::audit::emitter::default_audit_dir;
        let dir = default_audit_dir()?;
        let signer = mvm_hostd::audit::host_keypair::load_or_init()
            .context("loading host signer to anchor a warm claim's parent")?;
        let mut preverified = std::collections::HashMap::new();
        if let Some(found) = live_creation_entry(&dir, &signer.verifying, checkpoint.as_str()) {
            preverified.insert(anchor_key(CHECKPOINT_NS, checkpoint.as_str()), found);
        }
        Ok(Self {
            preverified,
            full: std::sync::OnceLock::new(),
        })
    }

    /// Whether a lookup for `checkpoint` will be answered without the full walk.
    #[cfg(test)]
    fn answers_in_place(&self, checkpoint: &str) -> bool {
        self.preverified
            .contains_key(&anchor_key(CHECKPOINT_NS, checkpoint))
    }

    fn lookup(&self, key: &str) -> Result<Option<RecordedCreation>> {
        if let Some(recorded) = self.preverified.get(key) {
            return Ok(Some(recorded.clone()));
        }
        match self
            .full
            .get_or_init(|| SignedChainAnchor::load().map_err(|e| format!("{e:#}")))
        {
            Ok(full) => full.lookup(key),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }
}

/// The one authenticated creation entry for `checkpoint` across every tenant's
/// live segment, or `None` when there is not exactly one — no entry, several,
/// or one that cannot be read or authenticated. `None` sends the caller to the
/// full walk, which reaches its own verdict on every one of those cases.
fn live_creation_entry(
    dir: &std::path::Path,
    key: &ed25519_dalek::VerifyingKey,
    checkpoint: &str,
) -> Option<RecordedCreation> {
    let tenants = live_chain_tenants(dir).ok()?;
    let mut found = Vec::new();
    for tenant in tenants {
        let matches = mvm_core::audit_verify::live::authenticate_live_entries(
            dir,
            &tenant,
            key,
            checkpoint,
            |entry| creation_keys(&entry.event).is_some(),
        )
        .ok()?;
        for entry in matches.entries {
            let mut recorded = std::collections::HashMap::new();
            index_creation_entry(&mut recorded, &entry).ok()?;
            if let Some(hit) = recorded.remove(&anchor_key(CHECKPOINT_NS, checkpoint)) {
                found.push(hit);
            }
        }
    }
    let only = found.pop()?;
    found.is_empty().then_some(only)
}

/// Every tenant with a live host-lifecycle chain in `dir`.
fn live_chain_tenants(dir: &std::path::Path) -> std::io::Result<Vec<String>> {
    let mut tenants = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !mvm_core::config::is_host_lifecycle_chain(&path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.contains(mvm_core::config::AUDIT_SEGMENT_INFIX) {
            continue;
        }
        if let Some(tenant) = name.strip_suffix(".jsonl") {
            tenants.push(tenant.to_string());
        }
    }
    Ok(tenants)
}

impl CheckpointChainAnchor for ClaimChainAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.digest))
    }

    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.tenant))
    }
}

impl CheckpointChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.digest))
    }

    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(self
            .lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))?
            .map(|recorded| recorded.tenant))
    }
}

/// The same signed host-lifecycle chains anchor image-lineage nodes. An image
/// node's identity is its own content-address, so the lookup key is the node
/// digest the `image.created` entry recorded, under the image namespace.
impl ImageChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .lookup(&anchor_key(IMAGE_NS, node.node_digest.as_str()))?
            .map(|recorded| recorded.digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, ContentBlob};
    use mvm_core::util::test_env::TestEnv;
    use mvm_hostd::audit::emitter::AuditEmitter;
    use mvm_hostd::audit::host_keypair::load_or_init;

    /// A checkpoint record whose stored digest matches its own recomputation,
    /// so a lookup outcome is the only thing under test.
    fn meta(id: &str) -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new(id),
            CheckpointClass::FsQuick,
            "vm-under-test",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "a".repeat(64),
        }])
        .created_unix(1)
        .build()
    }

    /// Emit one real `checkpoint.created` entry into `<MVM_HOME>/audit/local.jsonl`
    /// under the host signer, and return the content-address it recorded. The
    /// chain is genuinely signed — every test below either leaves it that way or
    /// damages it deliberately, so nothing depends on the developer's `~/.mvm`.
    fn seed_signed_chain(id: &str) -> CheckpointDigest {
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-lineage-test")
            .build();
        let meta = meta(id);
        let digest = meta.compute_meta_digest();
        let emitter = AuditEmitter::new(load_or_init().unwrap().signing).unwrap();
        emitter
            .emit_checkpoint_created(
                &plan,
                id,
                "fs_quick",
                digest.as_str(),
                meta.vm_name.as_str(),
            )
            .unwrap();
        digest
    }

    fn chain_path(home: &std::path::Path) -> std::path::PathBuf {
        home.join("audit").join("local.jsonl")
    }

    /// Damage a signed chain the way a concurrent writer or a partial write
    /// does: the bytes still parse as JSON, but the signed content no longer
    /// matches its signature. This is a *forgery-shaped* break, not a syntax
    /// error — the case the anchor used to silently skip.
    fn break_chain(path: &std::path::Path) {
        let content = std::fs::read_to_string(path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert!(
            !lines.is_empty(),
            "fixture chain must have entries to break"
        );
        lines[0] = lines[0].replace("fs_quick", "vm_full");
        assert!(
            lines[0].contains("vm_full"),
            "the tampered field must actually be present in the fixture"
        );
        std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn checkpoint_plan_identity_comes_only_from_a_verified_creation_entry() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-plan-bound");

        let anchor = SignedChainAnchor::load().expect("signed chain");
        assert_eq!(
            anchor
                .checkpoint_plan_id(&meta("cp-plan-bound"))
                .expect("plan identity"),
            Some("plan-lineage-test".to_string())
        );
        assert_eq!(
            anchor
                .checkpoint_plan_id(&meta("cp-absent"))
                .expect("absent plan identity"),
            None
        );

        break_chain(&chain_path(tmp.path()));
        let damaged = SignedChainAnchor::load().expect("damaged chain recorded");
        assert!(damaged.checkpoint_plan_id(&meta("cp-plan-bound")).is_err());
    }

    /// The regression. A miss against a damaged ledger must not be reported as
    /// "never audited": the record may be perfectly well audited behind the
    /// break. Both answers refuse, so this is about which finding the operator
    /// is handed — a skipped step, or a damaged integrity chain.
    #[test]
    fn a_miss_against_an_unverifiable_chain_is_an_error_not_a_silent_none() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");
        break_chain(&chain_path(tmp.path()));

        let anchor = SignedChainAnchor::load().unwrap();
        let err = CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent"))
            .expect_err("a miss with a damaged ledger cannot claim the record was never audited");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(mvm_runtime::lineage::LEDGER_UNVERIFIABLE),
            "must report an unreadable ledger: {msg}"
        );
        assert!(
            msg.contains("local.jsonl"),
            "must name the chain that failed so it can be found: {msg}"
        );
        assert!(
            !msg.contains(mvm_runtime::lineage::NO_SIGNED_ENTRY),
            "must not also claim the record was never audited: {msg}"
        );
    }

    /// The tenant a checkpoint belongs to is the one whose signed chain carries
    /// its creation entry, read from the entry itself rather than from the
    /// chain's file name or the record on disk.
    #[test]
    fn the_recorded_tenant_is_the_one_the_creation_entry_was_signed_under() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("acme")
            .plan_id("plan-lineage-tenant")
            .build();
        let record = meta("cp-acme");
        let emitter = AuditEmitter::new(load_or_init().unwrap().signing).unwrap();
        emitter
            .emit_checkpoint_created(
                &plan,
                "cp-acme",
                "fs_quick",
                record.compute_meta_digest().as_str(),
                record.vm_name.as_str(),
            )
            .unwrap();

        let anchor = SignedChainAnchor::load().unwrap();
        assert_eq!(
            CheckpointChainAnchor::recorded_creation_tenant(&anchor, &record).unwrap(),
            Some("acme".to_string())
        );
        assert_eq!(
            CheckpointChainAnchor::recorded_creation_tenant(&anchor, &meta("cp-absent")).unwrap(),
            None,
            "no creation entry, no owning tenant"
        );
    }

    /// The other half of the fix: with every chain readable, a miss keeps
    /// today's message, which is now true rather than merely usual.
    #[test]
    fn a_miss_against_clean_chains_still_reports_never_audited() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");

        let anchor = SignedChainAnchor::load().unwrap();
        let found = CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent"))
            .expect("a clean ledger can answer the question");
        assert!(
            found.is_none(),
            "a clean ledger that records nothing for this id is an honest None"
        );
    }

    /// A damaged chain must not poison lookups it has nothing to do with. An
    /// entry that came from a chain that verified is still trustworthy, so the
    /// hit resolves — only the *unanswerable* case escalates.
    #[test]
    fn a_hit_still_resolves_even_when_another_chain_is_unverifiable() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let digest = seed_signed_chain("cp-anchored");
        // A second lifecycle chain, damaged. `local.jsonl` stays clean.
        let other = tmp.path().join("audit").join("other-tenant.jsonl");
        std::fs::copy(chain_path(tmp.path()), &other).unwrap();
        break_chain(&other);

        let anchor = SignedChainAnchor::load().unwrap();
        let found =
            CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-anchored")).unwrap();
        assert_eq!(
            found,
            Some(digest),
            "an entry from a chain that verified stays usable"
        );
        // ...while the unanswerable lookup still escalates.
        assert!(
            CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent")).is_err(),
            "the damaged sibling still makes a miss unanswerable"
        );
    }

    /// The image-lineage half of the anchor answers the same way. Both impls go
    /// through one `lookup`, and this pins that they cannot drift apart —
    /// `image.created` entries live in the very same chains.
    #[test]
    fn the_image_anchor_reports_an_unverifiable_ledger_the_same_way() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");
        break_chain(&chain_path(tmp.path()));

        let node = mvm_core::image_lineage::ImageNode::builder(
            mvm_core::image_lineage::ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            mvm_core::image_lineage::ImageIdentity {
                canonical: mvm_core::image_lineage::ImageCanonicalId::Flake {
                    revision_hash: "rev-1".into(),
                },
                artifacts: vec![ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "b".repeat(64),
                }],
            },
            mvm_core::image_lineage::ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .created_unix(1)
        .build();

        let anchor = SignedChainAnchor::load().unwrap();
        let err = ImageChainAnchor::recorded_creation_digest(&anchor, &node)
            .expect_err("the image anchor must escalate an unreadable ledger too");
        assert!(
            format!("{err:#}").contains(mvm_runtime::lineage::LEDGER_UNVERIFIABLE),
            "{err:#}"
        );
    }

    /// The unsigned `secrets.jsonl` operator log lives in the same directory and
    /// matches the `<tenant>.jsonl` shape, but it is not a chain — no envelope,
    /// no `prev_hash`, no signature. Admitting it makes it fail verification
    /// permanently, and after this change that turns every un-anchored record on
    /// the host into "cannot determine whether this was audited" forever.
    ///
    /// Found on a real host, not hypothesised: `mvmctl doctor` reported
    /// "1 of 3 chain(s) FAIL verification" against it with the message
    /// `unknown field `action``, which is what a plain operator-log line looks
    /// like to a chain parser.
    #[test]
    fn the_unsigned_secrets_operator_log_never_makes_a_lookup_unanswerable() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        seed_signed_chain("cp-seeded");
        // Verbatim shape of the real operator log: plain JSON, no envelope.
        std::fs::write(
            tmp.path().join("audit").join("secrets.jsonl"),
            "{\"action\":\"list\",\"error\":null,\"name\":\"*\",\"outcome\":\"ok\",\
             \"pid\":24117,\"tenant\":\"local\",\"timestamp\":\"2026-05-15T04:25:53Z\"}\n",
        )
        .unwrap();

        let anchor = SignedChainAnchor::load().unwrap();
        let found = CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-absent"))
            .expect("an unsigned operator log is not an unverifiable chain");
        assert!(
            found.is_none(),
            "a clean ledger beside the operator log still answers honestly"
        );
    }

    /// An anchor built for a resident claim carries no chains at all, so it must
    /// keep answering `None` rather than inventing an unverifiable one.
    #[test]
    fn an_empty_anchor_reports_no_entry_rather_than_an_unreadable_ledger() {
        let anchor = SignedChainAnchor::empty();
        assert!(
            CheckpointChainAnchor::recorded_creation_digest(&anchor, &meta("cp-any"))
                .unwrap()
                .is_none()
        );
    }

    /// Append `count` copies of the chain's first line: valid-looking signed
    /// entries that no longer chain, so any walk over them fails, standing in
    /// for a long history the claim must not walk. None names a checkpoint.
    fn pad_history(path: &std::path::Path, count: usize) {
        use std::io::Write as _;
        let content = std::fs::read_to_string(path).unwrap();
        let first = content.lines().next().unwrap().to_string();
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        for _ in 0..count {
            writeln!(file, "{first}").unwrap();
        }
    }

    /// A warm claim answers its parent's creation from the live segment and
    /// does not walk the history before it: with that history damaged, the
    /// full anchor can no longer answer, and the claim anchor still does.
    #[test]
    fn a_claim_answers_its_parent_in_place_without_walking_the_history() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-old");
        break_chain(&chain_path(tmp.path()));
        let digest = seed_signed_chain("cp-parent");

        let parent = meta("cp-parent");
        assert!(
            CheckpointChainAnchor::recorded_creation_digest(
                &SignedChainAnchor::load().unwrap(),
                &parent
            )
            .is_err(),
            "only a walk of the history sees the damaged entry"
        );
        let claim = ClaimChainAnchor::for_checkpoint(&parent.id).unwrap();
        assert!(claim.answers_in_place("cp-parent"));
        assert_eq!(
            claim.recorded_creation_digest(&parent).unwrap(),
            Some(digest)
        );
        assert_eq!(
            claim.recorded_creation_tenant(&parent).unwrap(),
            Some("local".to_string())
        );
    }

    /// The claim-path work grows with the entries that name the parent, not
    /// with the history: about 10 MB of history before the parent's entry is
    /// searched but never parsed or verified.
    #[test]
    fn a_large_history_adds_no_parsing_or_verification_to_a_claim() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-history");
        let chain = chain_path(tmp.path());
        let line_len = std::fs::metadata(&chain).unwrap().len() as usize;
        pad_history(&chain, (10 * 1024 * 1024) / line_len.max(1));
        assert!(std::fs::metadata(&chain).unwrap().len() >= 10 * 1024 * 1024 - 2 * line_len as u64);
        let digest = seed_signed_chain("cp-parent");

        let key = load_or_init().unwrap().verifying;
        let live = mvm_core::audit_verify::live::authenticate_live_entries(
            &tmp.path().join("audit"),
            "local",
            &key,
            "cp-parent",
            |entry| creation_keys(&entry.event).is_some(),
        )
        .unwrap();
        assert_eq!(live.parsed, 1, "only the line naming the parent is parsed");
        assert_eq!(live.entries.len(), 1);

        let parent = meta("cp-parent");
        let claim = ClaimChainAnchor::for_checkpoint(&parent.id).unwrap();
        assert!(claim.answers_in_place("cp-parent"));
        assert_eq!(
            claim.recorded_creation_digest(&parent).unwrap(),
            Some(digest)
        );
    }

    /// A parent entry that does not authenticate is never answered in place:
    /// the claim falls back to the full walk, which refuses it exactly as it
    /// always has.
    #[test]
    fn a_tampered_parent_entry_falls_back_to_the_full_walk_and_is_refused() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-parent");
        break_chain(&chain_path(tmp.path()));

        let parent = meta("cp-parent");
        let claim = ClaimChainAnchor::for_checkpoint(&parent.id).unwrap();
        assert!(!claim.answers_in_place("cp-parent"));
        let err = claim
            .recorded_creation_digest(&parent)
            .expect_err("a forged parent entry must not anchor a claim");
        assert!(format!("{err:#}").contains(mvm_runtime::lineage::LEDGER_UNVERIFIABLE));
    }

    /// Anything the live segments do not answer is the full walk's question,
    /// with the full walk's verdict: an unaudited parent is still refused as
    /// never audited.
    #[test]
    fn a_parent_the_live_segment_does_not_name_gets_the_full_walks_verdict() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        seed_signed_chain("cp-other");

        let absent = meta("cp-unaudited");
        let claim = ClaimChainAnchor::for_checkpoint(&absent.id).unwrap();
        assert!(!claim.answers_in_place("cp-unaudited"));
        assert_eq!(claim.recorded_creation_digest(&absent).unwrap(), None);
    }
}
