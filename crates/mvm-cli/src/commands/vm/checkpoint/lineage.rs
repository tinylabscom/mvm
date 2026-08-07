use std::path::Path;

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
pub struct SignedChainAnchor {
    /// `<namespace>:<id>` -> content-address the signed chain recorded at
    /// creation. The namespace tag (`checkpoint` / `image`) keeps the checkpoint
    /// and image key spaces structurally disjoint in one map, rather than
    /// relying on their raw id/digest strings happening not to collide.
    recorded: std::collections::HashMap<String, CheckpointDigest>,
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
        }
    }

    pub fn load() -> Result<Self> {
        use mvm_hostd::audit::emitter::default_audit_dir;

        let dir = default_audit_dir()?;
        let mut recorded = std::collections::HashMap::new();
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // No audit dir yet → nothing to anchor; every lookup is None (fail closed).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { recorded });
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };

        // All lifecycle chains are signed under the one host key.
        let signer = super::super::host_signer::load_or_init()
            .context("loading host signer to anchor checkpoint lineage")?;

        for entry in read_dir {
            let path = entry?.path();
            if !is_host_lifecycle_chain(&path) {
                continue;
            }
            // A chain we cannot verify cannot anchor anything: skip it whole so a
            // tampered line strands (rather than silently trusts) its entries.
            if mvm_hostd::supervisor::verify_audit_chain(&path, &signer.verifying).is_err() {
                tracing::warn!(
                    path = %path.display(),
                    "audit chain failed verification; its entries will not anchor any checkpoint"
                );
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
        Ok(Self { recorded })
    }
}

/// A host-lifecycle audit chain is `<tenant>.jsonl` — NOT a per-VM workload
/// chain (`<tenant>.<vm>.workload.jsonl`), which carries a different envelope
/// format that `verify_audit_chain` does not parse.
fn is_host_lifecycle_chain(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".jsonl") && !name.ends_with(mvm_core::config::WORKLOAD_AUDIT_SUFFIX)
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
        Ok(self
            .recorded
            .get(&anchor_key(CHECKPOINT_NS, meta.id.as_str()))
            .cloned())
    }
}

/// The same signed host-lifecycle chains anchor image-lineage nodes. An image
/// node's identity is its own content-address, so the lookup key is the node
/// digest the `image.created` entry recorded, under the image namespace.
impl ImageChainAnchor for SignedChainAnchor {
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>> {
        Ok(self
            .recorded
            .get(&anchor_key(IMAGE_NS, node.node_digest.as_str()))
            .cloned())
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
