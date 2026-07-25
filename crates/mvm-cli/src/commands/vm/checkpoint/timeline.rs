//! `mvmctl machine timeline <id|digest>` — a read-only navigator over the
//! checkpoint and image lineage DAGs.
//!
//! It resolves a target in EITHER store, then renders its ancestry (backward to
//! genesis) plus its immediate children (the forward fork tree), verifying every
//! hop against the signed audit chain via [`SignedChainAnchor`]. It is strictly
//! read-only: no restore, no admission, no VM launch, no store writes.
//!
//! Verification is surfaced, never enforced. Each hop is marked verified or not,
//! and the whole timeline carries an overall verdict, but no trust decision is
//! made from it — the pass/fail gate is `machine checkpoint verify`. A tampered
//! or un-audited hop is marked, so the chain is never presented as if valid; the
//! command still renders (exit 0) so it stays usable for navigation.

use anyhow::{Context, Result, bail};
use serde::Serialize;

use mvm_core::checkpoint::{CheckpointClass, CheckpointDigest, CheckpointMeta};
use mvm_core::image_lineage::{ImageBuildIdentity, ImageNode};
use mvm_runtime::checkpoint::{CheckpointStore, checkpoint_ancestry, checkpoint_children};
use mvm_runtime::image_lineage::{ImageStore, image_ancestry, image_children};
use mvm_runtime::lineage::{Ancestry, VerifiedNode};

use super::SignedChainAnchor;
use super::validated_checkpoint_id;

#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct TimelineArgs {
    /// Checkpoint id, or a `sha256:<hex>` content-address that names a
    /// checkpoint or an image lineage node.
    pub target: String,
    /// Disambiguate a `sha256:<hex>` digest that exists in BOTH the checkpoint
    /// and image stores. Not needed for a checkpoint id.
    #[arg(long, value_enum)]
    pub kind: Option<LineageKind>,
    /// Output the timeline as JSON.
    #[arg(long)]
    pub json: bool,
}

/// Which lineage DAG a `sha256:<hex>` digest refers to. Only used to resolve the
/// rare cross-store collision where one digest names both a checkpoint and an
/// image node.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum LineageKind {
    Checkpoint,
    Image,
}

impl LineageKind {
    fn as_str(self) -> &'static str {
        match self {
            LineageKind::Checkpoint => "checkpoint",
            LineageKind::Image => "image",
        }
    }
}

/// The record a target string resolved to, in one of the two stores. Shared
/// with the revert engine, which resolves a target identically before restoring.
#[derive(Debug)]
pub(in crate::commands::vm::checkpoint) enum ResolvedTarget {
    Checkpoint(CheckpointMeta),
    Image(ImageNode),
}

pub(in crate::commands) fn run_timeline(args: TimelineArgs) -> Result<()> {
    let checkpoint_store = CheckpointStore::open();
    let image_store = ImageStore::open();
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to anchor lineage verification")?;

    let resolved = resolve_target(&checkpoint_store, &image_store, &args.target, args.kind)?;
    let timeline = match resolved {
        ResolvedTarget::Checkpoint(meta) => {
            build_checkpoint_timeline(&checkpoint_store, &anchor, meta)?
        }
        ResolvedTarget::Image(node) => build_image_timeline(&image_store, &anchor, node)?,
    };

    if args.json {
        crate::json_out::emit_json(&timeline)?;
    } else {
        println!("{}", render_human(&timeline));
    }
    Ok(())
}

/// Resolve `target` to a record in one of the two stores. A `sha256:<hex>`
/// addresses either store (disambiguated by `kind` on a collision); anything
/// else is a checkpoint id (image nodes have no id — their identity is their
/// digest). Shared with the revert engine so a target resolves identically
/// whether it is being navigated (timeline) or restored (revert).
pub(in crate::commands::vm::checkpoint) fn resolve_target(
    checkpoint_store: &CheckpointStore,
    image_store: &ImageStore,
    target: &str,
    kind: Option<LineageKind>,
) -> Result<ResolvedTarget> {
    match CheckpointDigest::parse(target) {
        Ok(digest) => resolve_digest(checkpoint_store, image_store, &digest, kind),
        Err(_) => resolve_checkpoint_id(checkpoint_store, target, kind),
    }
}

/// A `sha256:<hex>` digest may name a checkpoint, an image node, or (structurally
/// possible) both. `kind` restricts the lookup to one store; without it, a
/// both-stores hit is refused as ambiguous rather than silently picking one.
fn resolve_digest(
    checkpoint_store: &CheckpointStore,
    image_store: &ImageStore,
    digest: &CheckpointDigest,
    kind: Option<LineageKind>,
) -> Result<ResolvedTarget> {
    let checkpoint_hit = match kind {
        Some(LineageKind::Image) => None,
        _ => checkpoint_store.by_digest(digest)?,
    };
    let image_hit = match kind {
        Some(LineageKind::Checkpoint) => None,
        _ => image_store.by_digest(digest)?,
    };
    match (checkpoint_hit, image_hit) {
        // Only reachable with `kind == None` (a set `kind` forces one side off),
        // so pointing at `--kind` is always the right remedy here.
        (Some(_), Some(_)) => bail!(
            "digest {digest} names BOTH a checkpoint and an image node; \
             disambiguate with `--kind checkpoint` or `--kind image`"
        ),
        (Some(meta), None) => Ok(ResolvedTarget::Checkpoint(meta)),
        (None, Some(node)) => Ok(ResolvedTarget::Image(node)),
        (None, None) => match kind {
            Some(k) => bail!("no {} lineage record found for digest {digest}", k.as_str()),
            None => bail!("no checkpoint or image lineage record found for digest {digest}"),
        },
    }
}

/// A non-digest target is a checkpoint id. `--kind image` is incompatible: image
/// nodes are addressed only by their `sha256:<hex>` content-address.
fn resolve_checkpoint_id(
    store: &CheckpointStore,
    raw: &str,
    kind: Option<LineageKind>,
) -> Result<ResolvedTarget> {
    if kind == Some(LineageKind::Image) {
        bail!(
            "`--kind image` needs a sha256:<hex> node digest; \
             an image node has no id and {raw:?} is not a digest"
        );
    }
    let id = validated_checkpoint_id(raw)?;
    let meta = store
        .read_meta(&id)
        .with_context(|| format!("no checkpoint {raw:?} found"))?;
    Ok(ResolvedTarget::Checkpoint(meta))
}

// ── timeline model (shared by both DAGs) ─────────────────────────────────────

/// A rendered lineage: ancestors (genesis → the target's parent), the target,
/// and its immediate children. Common shape for both the checkpoint and image
/// DAGs; per-store presentation feeds this one struct.
#[derive(Serialize, Debug)]
struct Timeline {
    schema_version: u8,
    action: &'static str,
    /// `"checkpoint"` or `"image"`.
    kind: &'static str,
    /// What identifies the target: a checkpoint id, or an image node digest.
    target: String,
    /// Ancestors ordered genesis → the target's immediate parent (excludes the
    /// target itself).
    ancestors: Vec<TimelineNode>,
    /// The target node.
    node: TimelineNode,
    /// The target's immediate children — forward is a tree, so this may fork.
    children: Vec<TimelineNode>,
    /// A structural break that stopped the ancestry walk before genesis (a
    /// dangling parent hash-link or a would-be cycle), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    lineage_broken: Option<String>,
    /// Overall verdict: every rendered hop verified AND the ancestry reached
    /// genesis with no structural break. Surfaced, never enforced.
    verified: bool,
}

/// One node in a rendered timeline plus its per-hop verification verdict.
#[derive(Serialize, Debug)]
struct TimelineNode {
    /// The node's content-address (checkpoint `meta_digest` / image
    /// `node_digest`).
    digest: String,
    /// Checkpoint id; absent for image nodes (identity is the digest).
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    /// Parent hash-link (content-address); absent at genesis.
    #[serde(skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    created_unix: u64,
    /// A short human descriptor (checkpoint: class + vm + tag; image: build
    /// identity).
    label: String,
    /// Per-hop verdict against the signed audit chain.
    verified: bool,
    /// The fail-closed reason when `verified` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn build_checkpoint_timeline(
    store: &CheckpointStore,
    anchor: &SignedChainAnchor,
    meta: CheckpointMeta,
) -> Result<Timeline> {
    let target_id = meta.id.to_string();
    let target_digest = meta.meta_digest.clone();
    let ancestry: Ancestry<CheckpointMeta> = checkpoint_ancestry(store, &meta.id, anchor)?;
    let children = checkpoint_children(store, &target_digest, anchor)?;
    Ok(assemble(
        "checkpoint",
        target_id,
        ancestry,
        children,
        checkpoint_node,
    ))
}

fn build_image_timeline(
    store: &ImageStore,
    anchor: &SignedChainAnchor,
    node: ImageNode,
) -> Result<Timeline> {
    let target_digest = node.node_digest.clone();
    let ancestry: Ancestry<ImageNode> = image_ancestry(store, &target_digest, anchor)?;
    let children = image_children(store, &target_digest, anchor)?;
    Ok(assemble(
        "image",
        target_digest.to_string(),
        ancestry,
        children,
        image_node,
    ))
}

/// Fold an enumerated ancestry + children into the presentation [`Timeline`].
/// The ancestry's first node is the target; the rest are its ancestors in
/// start→genesis order, which we reverse so the render reads genesis → target.
fn assemble<R>(
    kind: &'static str,
    target: String,
    ancestry: Ancestry<R>,
    children: Vec<VerifiedNode<R>>,
    to_node: fn(&VerifiedNode<R>) -> TimelineNode,
) -> Timeline {
    let children_verified = children.iter().all(|c| c.status.is_verified());
    let verified = ancestry.fully_verified() && children_verified;

    let mut nodes = ancestry.nodes;
    // The target is the walk's first node; ancestors are the tail.
    let target_node = to_node(&nodes.remove(0));
    let mut ancestors: Vec<TimelineNode> = nodes.iter().map(to_node).collect();
    ancestors.reverse(); // start→genesis becomes genesis→parent

    Timeline {
        schema_version: 1,
        action: "timeline",
        kind,
        target,
        ancestors,
        node: target_node,
        children: children.iter().map(to_node).collect(),
        lineage_broken: ancestry.broken,
        verified,
    }
}

fn checkpoint_node(vn: &VerifiedNode<CheckpointMeta>) -> TimelineNode {
    let m = &vn.record;
    TimelineNode {
        digest: m.meta_digest.to_string(),
        id: Some(m.id.to_string()),
        parent: m.parent.as_ref().map(ToString::to_string),
        created_unix: m.created_unix,
        label: checkpoint_label(m),
        verified: vn.status.is_verified(),
        error: vn.status.error().map(str::to_string),
    }
}

fn checkpoint_label(m: &CheckpointMeta) -> String {
    let class = match m.class {
        CheckpointClass::FsQuick => "fs_quick",
        CheckpointClass::VmFull => "vm_full",
    };
    match &m.tag {
        Some(tag) => format!("{class} {} [{tag}]", m.vm_name),
        None => format!("{class} {}", m.vm_name),
    }
}

fn image_node(vn: &VerifiedNode<ImageNode>) -> TimelineNode {
    let n = &vn.record;
    TimelineNode {
        digest: n.node_digest.to_string(),
        id: None,
        parent: n.parent.as_ref().map(ToString::to_string),
        created_unix: n.created_unix,
        label: image_label(n),
        verified: vn.status.is_verified(),
        error: vn.status.error().map(str::to_string),
    }
}

fn image_label(n: &ImageNode) -> String {
    match &n.build_identity {
        ImageBuildIdentity::Flake { slot_hash } => format!("flake {slot_hash}"),
        ImageBuildIdentity::Oci {
            registry,
            repository,
        } => format!("oci {registry}/{repository}"),
    }
}

// ── human rendering ──────────────────────────────────────────────────────────

/// `sha256:<64hex>` abbreviated to `sha256:<first 12 hex>…` for the table; the
/// full digest stays in `--json` for scripting.
fn short_digest(digest: &str) -> String {
    match digest.strip_prefix(CheckpointDigest::PREFIX) {
        Some(hex) if hex.len() > 12 => format!("{}{}…", CheckpointDigest::PREFIX, &hex[..12]),
        _ => digest.to_string(),
    }
}

/// One rendered node line. `marker` prefixes the row (`▶` for the target, blank
/// otherwise); the verdict trails so an UNVERIFIED hop reads loudly.
fn node_line(marker: &str, node: &TimelineNode) -> String {
    let verdict = match &node.error {
        None => "verified".to_string(),
        Some(reason) => format!("UNVERIFIED: {reason}"),
    };
    let id = node.id.as_deref().unwrap_or("-");
    format!(
        "  {marker:<2} {}  {:<10}  {}  {verdict}",
        short_digest(&node.digest),
        id,
        node.label
    )
}

/// Pure, testable human render of the whole timeline.
fn render_human(timeline: &Timeline) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "timeline for {} {}",
        timeline.kind, timeline.target
    ));
    lines.push(String::new());

    lines.push("ancestors (genesis → target):".to_string());
    if timeline.ancestors.is_empty() {
        lines.push("  (target is a genesis root)".to_string());
    } else {
        for a in &timeline.ancestors {
            lines.push(node_line("", a));
        }
    }
    if let Some(reason) = &timeline.lineage_broken {
        lines.push(format!("  ! lineage incomplete: {reason}"));
    }

    lines.push(String::new());
    lines.push("target:".to_string());
    lines.push(node_line("▶", &timeline.node));

    lines.push(String::new());
    lines.push("children (forks):".to_string());
    if timeline.children.is_empty() {
        lines.push("  (no children)".to_string());
    } else {
        for c in &timeline.children {
            lines.push(node_line("", c));
        }
    }

    lines.push(String::new());
    lines.push(timeline_footer(timeline));
    lines.join("\n")
}

/// The overall-verdict footer. A failed verdict has two independent causes that
/// read very differently, so the footer names which one(s) apply rather than
/// blaming every failure on a bad hop: a *structural* break (a dangling or
/// cyclic parent hash-link that stopped the walk before genesis) versus a
/// *per-hop* verification failure (a hop present in the chain that did not
/// verify against the signed audit log). Both can hold at once.
fn timeline_footer(timeline: &Timeline) -> String {
    if timeline.verified {
        return "lineage verified against the signed audit chain".to_string();
    }
    let structural_break = timeline.lineage_broken.is_some();
    let has_failed_hop = !timeline.node.verified
        || timeline.ancestors.iter().any(|n| !n.verified)
        || timeline.children.iter().any(|n| !n.verified);
    match (structural_break, has_failed_hop) {
        (true, true) => "lineage is structurally broken (dangling or cyclic parent link) AND \
             has unverified hop(s) — see the incompleteness note and the UNVERIFIED marks above"
            .to_string(),
        (true, false) => "lineage is structurally broken (dangling or cyclic parent link): the \
             walk could not reach genesis — see the incompleteness note above"
            .to_string(),
        // structural_break is false here, so the only remaining cause is a failed hop.
        (false, _) => "lineage has unverified hop(s) — see the UNVERIFIED marks above".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, ContentBlob};
    use mvm_core::image_lineage::{ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance};
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_hostd::audit::bind::bind_checkpoint_created;
    use mvm_hostd::audit::emitter::AuditEmitter;

    // ── seed helpers: a store record + its host-signed creation entry ─────────

    fn emitter() -> (AuditEmitter, mvm_core::plan::ExecutionPlan) {
        let signer = crate::commands::vm::host_signer::load_or_init().unwrap();
        let em = AuditEmitter::new(signer.signing).unwrap();
        let plan = PlanFixture::new()
            .tenant("local")
            .plan_id("plan-timeline")
            .build();
        (em, plan)
    }

    fn seed_ckpt(
        store: &CheckpointStore,
        em: &AuditEmitter,
        plan: &mvm_core::plan::ExecutionPlan,
        id: &str,
        parent: Option<CheckpointDigest>,
    ) -> CheckpointMeta {
        let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .parent(parent)
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        store.write_meta(&meta).unwrap();
        bind_checkpoint_created(em, plan, &meta).unwrap();
        meta
    }

    fn image_of(slot: &str, revision: &str, parent: Option<CheckpointDigest>) -> ImageNode {
        ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: slot.into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: revision.into(),
                },
                artifacts: vec![ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: revision.into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .parent(parent)
        .created_unix(1)
        .build()
    }

    fn seed_image(
        store: &ImageStore,
        em: &AuditEmitter,
        plan: &mvm_core::plan::ExecutionPlan,
        node: &ImageNode,
    ) {
        store.save(node).unwrap();
        em.emit_image_created(plan, node).unwrap();
    }

    fn digest_of(hex_char: char) -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", hex_char.to_string().repeat(64))).unwrap()
    }

    // ── pure helpers ─────────────────────────────────────────────────────────

    #[test]
    fn short_digest_abbreviates_long_hex() {
        let full = format!("sha256:{}", "a".repeat(64));
        assert_eq!(short_digest(&full), "sha256:aaaaaaaaaaaa…");
        // A non-digest string is left untouched.
        assert_eq!(short_digest("not-a-digest"), "not-a-digest");
    }

    #[test]
    fn render_human_marks_an_unverified_hop_loudly() {
        let timeline = Timeline {
            schema_version: 1,
            action: "timeline",
            kind: "checkpoint",
            target: "c-target".into(),
            ancestors: vec![TimelineNode {
                digest: format!("sha256:{}", "a".repeat(64)),
                id: Some("c-genesis".into()),
                parent: None,
                created_unix: 1,
                label: "fs_quick vm".into(),
                verified: false,
                error: Some("meta_digest drift".into()),
            }],
            node: TimelineNode {
                digest: format!("sha256:{}", "b".repeat(64)),
                id: Some("c-target".into()),
                parent: Some(format!("sha256:{}", "a".repeat(64))),
                created_unix: 2,
                label: "fs_quick vm".into(),
                verified: true,
                error: None,
            },
            children: vec![],
            lineage_broken: None,
            verified: false,
        };
        let out = render_human(&timeline);
        assert!(out.contains("UNVERIFIED: meta_digest drift"), "{out}");
        assert!(out.contains("unverified hop(s)"), "{out}");
        assert!(out.contains("(no children)"), "{out}");
    }

    // ── resolution ───────────────────────────────────────────────────────────

    #[test]
    fn resolves_a_checkpoint_by_id() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let meta = seed_ckpt(&cstore, &em, &plan, "ckpt-by-id", None);

        match resolve_target(&cstore, &istore, "ckpt-by-id", None).unwrap() {
            ResolvedTarget::Checkpoint(m) => assert_eq!(m.id, meta.id),
            ResolvedTarget::Image(_) => panic!("id must resolve to a checkpoint"),
        }
    }

    #[test]
    fn unknown_checkpoint_id_is_an_error() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let err = resolve_target(&cstore, &istore, "no-such-ckpt", None).unwrap_err();
        assert!(err.to_string().contains("no checkpoint"), "{err}");
    }

    #[test]
    fn digest_only_in_checkpoint_store_resolves_to_checkpoint() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let meta = seed_ckpt(&cstore, &em, &plan, "ckpt-dig", None);

        match resolve_target(&cstore, &istore, meta.meta_digest.as_str(), None).unwrap() {
            ResolvedTarget::Checkpoint(m) => assert_eq!(m.meta_digest, meta.meta_digest),
            ResolvedTarget::Image(_) => panic!("digest is only in the checkpoint store"),
        }
    }

    #[test]
    fn digest_only_in_image_store_resolves_to_image() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let node = image_of("slot-a", "rev-1", None);
        seed_image(&istore, &em, &plan, &node);

        match resolve_target(&cstore, &istore, node.node_digest.as_str(), None).unwrap() {
            ResolvedTarget::Image(n) => assert_eq!(n.node_digest, node.node_digest),
            ResolvedTarget::Checkpoint(_) => panic!("digest is only in the image store"),
        }
    }

    /// Plant the SAME digest string in both stores (content-addresses can't
    /// collide naturally, so the records are hand-filed under one digest) to
    /// exercise the cross-store ambiguity refusal + `--kind` disambiguation.
    fn plant_collision(cstore: &CheckpointStore, istore: &ImageStore) -> CheckpointDigest {
        let d = digest_of('c');
        let mut meta =
            CheckpointMeta::builder(CheckpointId::new("collide"), CheckpointClass::FsQuick, "vm")
                .content(vec![])
                .supervisor_config_digest("d")
                .created_unix(1)
                .build();
        meta.meta_digest = d.clone();
        cstore.write_meta(&meta).unwrap();

        let mut node = image_of("slot-a", "rev-1", None);
        node.node_digest = d.clone();
        istore.save(&node).unwrap();
        d
    }

    #[test]
    fn a_digest_in_both_stores_is_refused_as_ambiguous() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let d = plant_collision(&cstore, &istore);

        let err = resolve_target(&cstore, &istore, d.as_str(), None).unwrap_err();
        assert!(err.to_string().contains("BOTH"), "{err}");
        assert!(err.to_string().contains("--kind"), "{err}");
    }

    #[test]
    fn kind_disambiguates_a_cross_store_collision() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let d = plant_collision(&cstore, &istore);

        assert!(matches!(
            resolve_target(&cstore, &istore, d.as_str(), Some(LineageKind::Checkpoint)).unwrap(),
            ResolvedTarget::Checkpoint(_)
        ));
        assert!(matches!(
            resolve_target(&cstore, &istore, d.as_str(), Some(LineageKind::Image)).unwrap(),
            ResolvedTarget::Image(_)
        ));
    }

    #[test]
    fn kind_image_with_a_non_digest_is_an_error() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let err =
            resolve_target(&cstore, &istore, "some-id", Some(LineageKind::Image)).unwrap_err();
        assert!(err.to_string().contains("node digest"), "{err}");
    }

    // ── checkpoint timeline build (real signed chain) ─────────────────────────

    #[test]
    fn checkpoint_timeline_orders_ancestors_and_lists_children_verified() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let store = CheckpointStore::open();
        let (em, plan) = emitter();

        let g0 = seed_ckpt(&store, &em, &plan, "g0", None);
        let g1 = seed_ckpt(&store, &em, &plan, "g1", Some(g0.meta_digest.clone()));
        let g2 = seed_ckpt(&store, &em, &plan, "g2", Some(g1.meta_digest.clone()));
        // g2 forks into two children.
        let c1 = seed_ckpt(&store, &em, &plan, "c1", Some(g2.meta_digest.clone()));
        let c2 = seed_ckpt(&store, &em, &plan, "c2", Some(g2.meta_digest.clone()));

        let anchor = SignedChainAnchor::load().unwrap();
        let timeline = build_checkpoint_timeline(&store, &anchor, g2.clone()).unwrap();

        assert_eq!(timeline.kind, "checkpoint");
        assert_eq!(timeline.node.id.as_deref(), Some("g2"));
        // Ancestors are genesis → parent: [g0, g1].
        let anc: Vec<&str> = timeline
            .ancestors
            .iter()
            .map(|a| a.id.as_deref().unwrap())
            .collect();
        assert_eq!(anc, vec!["g0", "g1"]);
        assert!(timeline.ancestors.iter().all(|a| a.verified));
        // Children are both forks (order is store-scan order; assert as a set).
        let kids: std::collections::BTreeSet<&str> = timeline
            .children
            .iter()
            .map(|c| c.id.as_deref().unwrap())
            .collect();
        assert_eq!(
            kids,
            ["c1", "c2"].into_iter().collect(),
            "both forks are enumerated"
        );
        let _ = (c1, c2);
        assert!(timeline.children.iter().all(|c| c.verified));
        assert!(timeline.node.verified);
        assert!(timeline.verified, "a fully-audited chain verifies");
        assert!(timeline.lineage_broken.is_none());
    }

    #[test]
    fn tampered_ancestor_is_marked_unverified_but_timeline_still_builds() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let store = CheckpointStore::open();
        let (em, plan) = emitter();

        let g0 = seed_ckpt(&store, &em, &plan, "g0", None);
        let g1 = seed_ckpt(&store, &em, &plan, "g1", Some(g0.meta_digest.clone()));
        let g2 = seed_ckpt(&store, &em, &plan, "g2", Some(g1.meta_digest.clone()));

        let anchor = SignedChainAnchor::load().unwrap();

        // Tamper genesis g0's meta.json: change a load-bearing field but keep the
        // stored meta_digest, so its recompute now drifts.
        let path = store.dir_for(&g0.id).join("meta.json");
        let mut tampered: CheckpointMeta =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered.created_unix = 999;
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        // The timeline STILL builds (read-only navigation never bails)...
        let timeline = build_checkpoint_timeline(&store, &anchor, g2).unwrap();
        // ...listing all three nodes, with the tampered genesis marked unverified.
        let g0_node = timeline
            .ancestors
            .iter()
            .find(|a| a.id.as_deref() == Some("g0"))
            .expect("tampered genesis is NOT dropped");
        assert!(!g0_node.verified);
        assert!(g0_node.error.as_ref().unwrap().contains("drift"));
        // g1 (untouched) still verifies.
        let g1_node = timeline
            .ancestors
            .iter()
            .find(|a| a.id.as_deref() == Some("g1"))
            .unwrap();
        assert!(g1_node.verified);
        // Overall verdict is failed, and the walk still reached genesis.
        assert!(!timeline.verified);
        assert!(timeline.lineage_broken.is_none());
    }

    #[test]
    fn dangling_ancestry_sets_lineage_broken_and_renders_a_structural_break() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let store = CheckpointStore::open();
        let (em, plan) = emitter();

        // A checkpoint whose parent hash-link names a digest no stored record
        // carries: the node itself is audited and verifies, but the walk cannot
        // reach genesis — a genuine structural break, not a per-hop failure.
        let missing_parent = digest_of('e');
        let target = seed_ckpt(&store, &em, &plan, "orphan", Some(missing_parent));

        let anchor = SignedChainAnchor::load().unwrap();
        let timeline = build_checkpoint_timeline(&store, &anchor, target).unwrap();

        // The reachable node is listed and verified...
        assert!(timeline.node.verified);
        // ...but the walk fails closed with a structural break, not a bad hop.
        assert!(
            timeline.lineage_broken.is_some(),
            "a dangling parent must surface as a structural break"
        );
        assert!(!timeline.verified, "a broken lineage is not verified");

        let out = render_human(&timeline);
        assert!(out.contains("lineage incomplete"), "{out}");
        // The footer names the STRUCTURAL cause, not a phantom unverified hop.
        assert!(out.contains("structurally broken"), "{out}");
        assert!(
            !out.contains("unverified hop(s)"),
            "a purely structural break must not be reported as an unverified hop: {out}"
        );
    }

    #[test]
    fn timeline_json_shape_is_stable() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let store = CheckpointStore::open();
        let (em, plan) = emitter();
        let g0 = seed_ckpt(&store, &em, &plan, "g0", None);

        let anchor = SignedChainAnchor::load().unwrap();
        let timeline = build_checkpoint_timeline(&store, &anchor, g0).unwrap();
        let v: serde_json::Value = serde_json::to_value(&timeline).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["action"], "timeline");
        assert_eq!(v["kind"], "checkpoint");
        assert_eq!(v["target"], "g0");
        assert_eq!(v["verified"], true);
        assert!(v["ancestors"].as_array().unwrap().is_empty());
        assert!(v["children"].as_array().unwrap().is_empty());
        assert_eq!(v["node"]["id"], "g0");
        assert_eq!(v["node"]["verified"], true);
        // genesis node carries no parent key
        assert!(v["node"].get("parent").is_none());
    }

    // ── image timeline build (real signed chain) ──────────────────────────────

    #[test]
    fn image_timeline_resolves_by_digest_and_verifies() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();
        let (em, plan) = emitter();

        let g0 = image_of("slot-a", "rev-1", None);
        seed_image(&istore, &em, &plan, &g0);
        let g1 = image_of("slot-a", "rev-2", Some(g0.node_digest.clone()));
        seed_image(&istore, &em, &plan, &g1);

        // Resolve the tip by its node digest, then build its timeline.
        let resolved = resolve_target(&cstore, &istore, g1.node_digest.as_str(), None).unwrap();
        let ResolvedTarget::Image(node) = resolved else {
            panic!("digest must resolve to an image node");
        };
        let anchor = SignedChainAnchor::load().unwrap();
        let timeline = build_image_timeline(&istore, &anchor, node).unwrap();

        assert_eq!(timeline.kind, "image");
        assert_eq!(timeline.node.digest, g1.node_digest.to_string());
        assert!(timeline.node.id.is_none(), "image nodes have no id");
        // One ancestor (genesis g0), verified.
        assert_eq!(timeline.ancestors.len(), 1);
        assert_eq!(timeline.ancestors[0].digest, g0.node_digest.to_string());
        assert!(timeline.verified);
    }
}
