use anyhow::{Context, Result};
use serde::Serialize;

use mvm_core::checkpoint::{CheckpointDigest, CheckpointMeta};
use mvm_core::image_lineage::ImageNode;
use mvm_runtime::checkpoint::{CheckpointChainAnchor, CheckpointStore, verify_lineage};
use mvm_runtime::image_lineage::ImageChainAnchor;

use super::validated_checkpoint_id;
use crate::ui;

#[derive(Serialize)]
struct CheckpointVerifyJson<'a> {
    schema_version: u8,
    action: &'static str,
    id: &'a str,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

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
    recorded: std::collections::HashMap<String, CheckpointDigest>,
    /// Host-lifecycle chains whose signatures did not verify, in the order
    /// encountered. Non-empty turns a lookup miss from "never audited" into
    /// "cannot tell" — see the type docs.
    unverifiable: Vec<std::path::PathBuf>,
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
        let signer = super::super::host_signer::load_or_init()
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
    fn lookup(&self, key: &str) -> Result<Option<CheckpointDigest>> {
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
    recorded: &mut std::collections::HashMap<String, CheckpointDigest>,
    envelope: &mvm_hostd::supervisor::SignedEnvelope,
) -> Result<()> {
    use mvm_hostd::audit::emitter::checkpoint_audit as k;
    use mvm_hostd::audit::emitter::image_audit as ik;
    let event = envelope.entry.event.as_str();
    // The (id-label, digest-label, namespace) a creation event keys on;
    // non-creation events carry none.
    let keys = if event == k::CREATED_EVENT {
        Some((k::LABEL_CHECKPOINT_ID, k::LABEL_META_DIGEST, CHECKPOINT_NS))
    } else if event == k::FORKED_EVENT {
        Some((k::LABEL_CHILD_ID, k::LABEL_CHILD_DIGEST, CHECKPOINT_NS))
    } else if event == ik::CREATED_EVENT {
        Some((ik::LABEL_NODE_DIGEST, ik::LABEL_NODE_DIGEST, IMAGE_NS))
    } else {
        None
    };
    let Some((id_key, digest_key, namespace)) = keys else {
        return Ok(());
    };
    let labels = &envelope.entry.labels;
    if let (Some(id), Some(digest)) = (labels.get(id_key), labels.get(digest_key)) {
        recorded.insert(
            anchor_key(namespace, id),
            CheckpointDigest::parse(digest.clone())?,
        );
    }
    Ok(())
}

impl CheckpointChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        self.lookup(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))
    }
}

/// The same signed host-lifecycle chains anchor image-lineage nodes. An image
/// node's identity is its own content-address, so the lookup key is the node
/// digest the `image.created` entry recorded, under the image namespace.
impl ImageChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>> {
        self.lookup(&anchor_key(IMAGE_NS, node.node_digest.as_str()))
    }
}

/// `mvmctl vm checkpoint verify <id>`: chain-anchored lineage verification.
/// Exits nonzero on any failure so it is scriptable.
pub(super) fn verify(id: &str, json: bool) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let store = CheckpointStore::open();
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to anchor lineage verification")?;

    match verify_lineage(&store, &checkpoint, &anchor) {
        Ok(()) => {
            if json {
                crate::json_out::emit_json(&CheckpointVerifyJson {
                    schema_version: 1,
                    action: "verify",
                    id: checkpoint.as_str(),
                    verified: true,
                    error: None,
                })?;
            } else {
                ui::success(&format!(
                    "checkpoint {} lineage verifies against the signed audit chain",
                    checkpoint.as_str()
                ));
            }
            Ok(())
        }
        Err(e) => {
            if json {
                crate::json_out::emit_json(&CheckpointVerifyJson {
                    schema_version: 1,
                    action: "verify",
                    id: checkpoint.as_str(),
                    verified: false,
                    error: Some(format!("{e:#}")),
                })?;
            }
            Err(e.context(format!(
                "checkpoint {} lineage verification failed",
                checkpoint.as_str()
            )))
        }
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
}
