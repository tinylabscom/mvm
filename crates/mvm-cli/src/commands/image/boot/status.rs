//! `mvmctl image boot status` — what the cache holds, read-only and offline.

use anyhow::Result;
use serde_json::json;

use super::cache::{self, BootImageEntry};

pub(super) fn run(json_output: bool) -> Result<()> {
    let entries = cache::survey();
    if json_output {
        println!("{}", serde_json::to_string_pretty(&as_json(&entries))?);
        return Ok(());
    }
    render_text(&entries);
    Ok(())
}

fn as_json(entries: &[BootImageEntry]) -> serde_json::Value {
    json!({
        "cache_root": cache::cache_root().display().to_string(),
        "variants": entries.iter().map(|e| json!({
            "variant": e.variant.cache_subdir(),
            "dir": e.dir.display().to_string(),
            "present": e.sidecar.is_some(),
            "complete": e.complete,
            "would_use": e.would_use(),
            "image_tag": e.image_tag(),
            "source": e.source(),
            "acquired_at": e.acquired_at(),
            "protocol_version": e.protocol_version(),
            "generator_rev": e.generator_rev(),
            "size_bytes": e.size_bytes,
        })).collect::<Vec<_>>(),
    })
}

fn render_text(entries: &[BootImageEntry]) {
    // Deliberately not `ui::info`: that channel is opt-in chatter, and the
    // cache root is part of the report, not commentary on it.
    println!("Boot image cache: {}", cache::cache_root().display());
    for entry in entries {
        println!();
        println!("{}", entry.variant.cache_subdir());
        for (label, value) in rows(entry) {
            println!("  {label:<18}{value}");
        }
    }
}

/// One entry as label/value pairs. Split out so the wording is decided in one
/// place and a field cannot appear in the text view but not the JSON one.
fn rows(entry: &BootImageEntry) -> Vec<(&'static str, String)> {
    vec![
        ("tag", unrecorded(entry.image_tag())),
        ("source", unrecorded(entry.source())),
        ("acquired", unrecorded(entry.acquired_at())),
        (
            "protocol",
            entry
                .protocol_version()
                .map_or_else(|| UNRECORDED.to_string(), |v| v.to_string()),
        ),
        ("generator rev", unrecorded(entry.generator_rev())),
        ("size", human_size(entry.size_bytes)),
        (
            "would use",
            if entry.would_use() {
                "yes".to_string()
            } else {
                "no — incomplete; the next run in this mode replaces it".to_string()
            },
        ),
    ]
}

/// Never rendered as an empty column: a blank reads as "no tag", which is a
/// different claim from "this producer recorded none".
const UNRECORDED: &str = "(unrecorded)";

fn unrecorded(value: Option<&str>) -> String {
    value.unwrap_or(UNRECORDED).to_string()
}

fn human_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} B")
    }
}
