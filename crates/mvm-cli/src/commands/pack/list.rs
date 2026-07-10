//! `mvmctl pack list`.

use anyhow::Result;
use serde::Serialize;

use mvm_core::arch::GuestArch;
use mvm_core::packs::{PackBackend, PackKind};

use crate::ui;

use super::PackKindArg;

/// One row of `pack list` — a flattened, JSON-friendly view of a
/// `PackListEntry` (the facade type carries a `PackKey`, not individually
/// serializable columns).
#[derive(Debug, Serialize)]
struct PackListRow {
    pack_hash: String,
    kind: PackKind,
    arch: GuestArch,
    backend: PackBackend,
    channel: String,
    release_version: String,
    promoted_at_unix: u64,
    active: bool,
}

pub(in crate::commands) fn run(kind: Option<PackKindArg>, json: bool) -> Result<()> {
    let filter = kind.map(PackKindArg::to_pack_kind);
    let mut versions = mvm_core::pack_cache::list_versions(filter)?;
    // Stable, human-friendly ordering: by key (kind/arch/backend), newest
    // version first within a key. `PackKind`/`GuestArch` carry no `Ord`, so
    // key on their `Debug` text (stable, just not enum-declaration order).
    versions.sort_by_key(|entry| {
        (
            format!("{:?}", entry.key.kind),
            format!("{:?}", entry.key.arch),
            entry.key.backend.clone(),
            std::cmp::Reverse(entry.promoted_at_unix),
        )
    });

    if json {
        let rows: Vec<PackListRow> = versions
            .iter()
            .map(|entry| PackListRow {
                pack_hash: entry.pack_hash.as_str().to_string(),
                kind: entry.key.kind.clone(),
                arch: entry.key.arch,
                backend: entry.key.backend.clone(),
                channel: entry.channel.clone(),
                release_version: entry.release_version.clone(),
                promoted_at_unix: entry.promoted_at_unix,
                active: entry.active,
            })
            .collect();
        crate::json_out::emit_json(&rows)?;
        return Ok(());
    }

    if versions.is_empty() {
        ui::info("No pack versions recorded.");
        return Ok(());
    }

    for entry in &versions {
        let short_hash = &entry.pack_hash.as_str()[..entry.pack_hash.as_str().len().min(12)];
        let marker = if entry.active { "*" } else { " " };
        println!(
            "{marker} {short_hash:<12}  {:<10?}  {:<8?}  {:<12}  {:<10}  {}",
            entry.key.kind,
            entry.key.arch,
            entry.key.backend.to_string(),
            entry.release_version,
            entry.channel,
        );
    }
    ui::info("(* marks the active version for its kind/arch/backend)");
    Ok(())
}
