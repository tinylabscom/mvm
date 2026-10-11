//! Terminal rendering only; cache operations and validation live in the client.

use std::collections::BTreeMap;

use mvm_client::image_admin::{ImageListRow, InspectOutput};

use super::super::shared::human_bytes;

pub(super) fn render_list(rows: &[ImageListRow]) {
    if rows.is_empty() {
        println!("No cached OCI images.");
        return;
    }
    println!(
        "{:<38} {:<20} {:<18} {:>10}",
        "REFERENCE", "DIGEST", "FETCHED", "SIZE"
    );
    for row in rows {
        println!(
            "{:<38} {:<20} {:<18} {:>10}",
            truncate(&row.reference, 38),
            truncate(&row.resolved_digest, 20),
            truncate(&row.fetched_at, 18),
            human_bytes(row.size_bytes)
        );
    }
}

pub(super) fn render_inspect(output: &InspectOutput) {
    let image = &output.image;
    println!("Reference: {}", image.reference);
    println!("Registry: {}", image.registry);
    println!("Repository: {}", image.repository);
    if let Some(tag) = &image.tag {
        println!("Tag: {tag}");
    }
    println!("Resolved digest: {}", image.resolved_digest);
    println!("Fetched at: {}", image.fetched_at);
    println!("Size: {}", human_bytes(output.size_bytes));
    println!("Manifest: {}", image.manifest_path);
    if let Some(path) = &image.config_path {
        println!("Config: {path}");
    }
    if let Some(path) = &image.rootfs_path {
        println!("Rootfs: {path}");
    }
    println!(
        "mvm-claims.json: {}",
        if output.claims.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    println!("Layers:");
    for layer in &image.layers {
        let path = layer.path.as_deref().unwrap_or("-");
        println!(
            "  {}  {}  {}",
            layer.digest,
            human_bytes(layer.size_bytes),
            path
        );
    }
    if let Some(claims) = &output.claims
        && let Some(labels) = claims.as_object().and_then(|obj| obj.get("labels"))
    {
        let labels: BTreeMap<_, _> = labels
            .as_object()
            .into_iter()
            .flat_map(|obj| obj.iter())
            .collect();
        if !labels.is_empty() {
            println!("Claim labels:");
            for (key, value) in labels {
                println!("  {key}: {value}");
            }
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut s: String = value.chars().take(max.saturating_sub(1)).collect();
    s.push('~');
    s
}
