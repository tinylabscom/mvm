//! Command arguments and rendering for client-owned lineage navigation.

use anyhow::Result;
use mvm_client::checkpoint::{Checkpoints, Timeline, TimelineNode};
use mvm_core::checkpoint::CheckpointDigest;

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

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum LineageKind {
    Checkpoint,
    Image,
}

impl From<LineageKind> for mvm_client::checkpoint::LineageKind {
    fn from(kind: LineageKind) -> Self {
        match kind {
            LineageKind::Checkpoint => Self::Checkpoint,
            LineageKind::Image => Self::Image,
        }
    }
}

pub(in crate::commands) fn run_timeline(args: TimelineArgs) -> Result<()> {
    let timeline = Checkpoints::open().timeline(&args.target, args.kind.map(Into::into))?;
    if args.json {
        crate::json_out::emit_json(&timeline)?;
    } else {
        println!("{}", render_human(&timeline));
    }
    Ok(())
}

fn short_digest(digest: &str) -> String {
    match digest.strip_prefix(CheckpointDigest::PREFIX) {
        Some(hex) if hex.len() > 12 => format!("{}{}…", CheckpointDigest::PREFIX, &hex[..12]),
        _ => digest.to_string(),
    }
}

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
        (false, _) => "lineage has unverified hop(s) — see the UNVERIFIED marks above".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_digest_abbreviates_long_hex() {
        let full = format!("sha256:{}", "a".repeat(64));
        assert_eq!(short_digest(&full), "sha256:aaaaaaaaaaaa…");
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
}
