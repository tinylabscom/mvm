//! Manifest-keyed slot primitives.
//!
//! They operate on
//! `~/.mvm/templates/<sha256(canonical_manifest_path)>/manifest.json` —
//! `PersistedManifest` is the slot-resident JSON record.

use anyhow::{Context, Result};
use mvm_core::manifest::{
    PersistedManifest, is_slot_hash_dirname, slot_dir, slot_dir_for_manifest_path,
};
use tracing::instrument;

/// One row produced by [`template_list_slots`]. Contains just the
/// fields a UI caller needs without re-loading every slot's
/// `manifest.json` per query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotEntry {
    pub slot_hash: String,
    pub manifest_path: String,
    pub name: Option<String>,
    pub updated_at: String,
}

/// Persist a [`PersistedManifest`] to its registry slot. The slot
/// directory is derived from the record's `manifest_hash`. Atomic
/// (write-temp-then-rename via [`PersistedManifest::write_to_slot`]).
#[instrument(skip_all, fields(slot_hash = %persisted.manifest_hash))]
pub fn template_persist_slot(persisted: &PersistedManifest) -> Result<()> {
    let dir = slot_dir(&persisted.manifest_hash);
    persisted.write_to_slot(std::path::Path::new(&dir))
}

/// Load the slot record for a given `slot_hash`. Returns the
/// deserialised [`PersistedManifest`] from
/// `~/.mvm/templates/<slot_hash>/manifest.json`.
#[instrument(skip_all, fields(slot_hash = slot_hash))]
pub fn template_load_slot(slot_hash: &str) -> Result<PersistedManifest> {
    let dir = slot_dir(slot_hash);
    PersistedManifest::read_from_slot(std::path::Path::new(&dir))
}

/// Convenience: load the slot record for a given manifest filesystem
/// path. Computes `sha256(canonical_path)` then delegates to
/// [`template_load_slot`].
#[instrument(skip_all, fields(manifest_path = %path.display()))]
pub fn template_load_slot_for_manifest_path(path: &std::path::Path) -> Result<PersistedManifest> {
    let dir = slot_dir_for_manifest_path(path)?;
    PersistedManifest::read_from_slot(std::path::Path::new(&dir))
}

/// Remove a slot directory by hash. With `force = true`, a missing
/// slot is not an error (idempotent cleanup). Mirrors today's
/// [`super::crud::template_delete`] behaviour for the slot-keyed world.
#[instrument(skip_all, fields(slot_hash = slot_hash, force))]
pub fn template_delete_slot(slot_hash: &str, force: bool) -> Result<()> {
    let dir = slot_dir(slot_hash);
    let path = std::path::Path::new(&dir);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && force => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to delete slot {}", slot_hash)),
    }
}

/// Pure helper: keep only the slot-hash directory entries from
/// `~/.mvm/templates/`. Independent of the filesystem so it is
/// straightforwardly unit-testable.
///
/// Anything else in that directory is not a slot. It used to be sorted into a
/// second "name-keyed" bucket that a lister exposed; there are no name-keyed
/// slots any more, so a non-hash entry is simply skipped.
fn slot_hash_dirnames<I>(entries: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut hashes: Vec<String> = entries
        .into_iter()
        .filter(|n| is_slot_hash_dirname(n))
        .collect();
    hashes.sort();
    hashes
}

/// Read the immediate child directory names under
/// `~/.mvm/templates/`. Returns an empty vec when the base dir
/// doesn't exist yet (fresh install).
fn read_templates_base_subdir_names() -> Result<Vec<String>> {
    let base = mvm_core::template::templates_base_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to list templates dir {}", base));
        }
    };
    let names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    Ok(names)
}

/// List modern hash-keyed slot directory names. Use
/// [`template_list_slots`] when you also need each slot's metadata.
#[instrument(skip_all)]
pub fn template_list_slot_hashes() -> Result<Vec<String>> {
    let names = read_templates_base_subdir_names()?;
    let hashes = slot_hash_dirnames(names);
    Ok(hashes)
}

/// Cleanup pass — remove slots whose source manifest file is missing
/// on disk (e.g. the user `rm`'d their project directory or moved it
/// elsewhere, leaving the slot dangling under `~/.mvm/templates/`).
///
/// Returns `(removed_count, slots_removed)`. Errors on individual
/// slot deletes are logged at warn but don't abort the sweep — a
/// single corrupted slot shouldn't block cleaning up the rest.
///
/// Slots whose `manifest.json` is missing or unparseable are also
/// considered orphaned (we can't cross-reference them, so we treat
/// them as garbage to clean up).
#[instrument(skip_all)]
pub fn template_prune_orphan_slots() -> Result<(usize, Vec<String>)> {
    let mut removed = Vec::new();
    for slot_hash in template_list_slot_hashes()? {
        let persisted = match template_load_slot(&slot_hash) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(slot = %slot_hash, error = %e, "removing slot with unreadable manifest.json");
                if let Err(rm_err) = template_delete_slot(&slot_hash, true) {
                    tracing::warn!(slot = %slot_hash, error = %rm_err, "failed to remove unreadable slot");
                    continue;
                }
                removed.push(slot_hash);
                continue;
            }
        };

        if !std::path::Path::new(&persisted.manifest_path).exists() {
            tracing::info!(
                slot = %slot_hash,
                manifest_path = %persisted.manifest_path,
                "removing orphaned slot (manifest file gone)"
            );
            if let Err(e) = template_delete_slot(&slot_hash, true) {
                tracing::warn!(slot = %slot_hash, error = %e, "failed to remove orphaned slot");
                continue;
            }
            removed.push(slot_hash);
        }
    }
    let count = removed.len();
    Ok((count, removed))
}

/// List modern slots with their metadata (manifest path, optional
/// display name, last-updated timestamp). Slots whose
/// `manifest.json` is missing or unparseable are skipped with a
/// warn log — listing should never fail end-to-end on a single
/// corrupt slot.
#[instrument(skip_all)]
pub fn template_list_slots() -> Result<Vec<SlotEntry>> {
    let mut out = Vec::new();
    for slot_hash in template_list_slot_hashes()? {
        match template_load_slot(&slot_hash) {
            Ok(persisted) => out.push(SlotEntry {
                slot_hash,
                manifest_path: persisted.manifest_path,
                name: persisted.name,
                updated_at: persisted.updated_at,
            }),
            Err(e) => {
                tracing::warn!(slot = %slot_hash, error = %e, "skipping unreadable slot");
            }
        }
    }
    out.sort_by(|a, b| a.slot_hash.cmp(&b.slot_hash));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // slot_hash_dirnames (pure helper).
    //
    // Filesystem-independent unit tests. The slot-keyed
    // persist/load/delete/list_* wrappers are thin delegations to
    // mvm_core::manifest primitives that already have full coverage
    // against tempdir-backed scenarios, so we intentionally don't
    // re-test the env-driven path resolution here: doing so would force
    // MVM_HOME mutation and serialise tests.
    // -----------------------------------------------------------------

    fn hex_dirname() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn only_slot_hash_dirnames_survive() {
        let h = hex_dirname();
        let entries = vec![
            "openclaw".to_string(),
            h.clone(),
            "agent-foo".to_string(),
            "claude-code-vm".to_string(),
        ];
        // Only the slot hash survives; the three non-hash entries are not
        // slots and are skipped rather than bucketed.
        assert_eq!(slot_hash_dirnames(entries), vec![h]);
    }

    #[test]
    fn slot_hashes_come_back_sorted() {
        let h1 = "f".repeat(64);
        let h2 = "0".repeat(64);
        let entries = vec![
            h1.clone(),
            "z-tpl".to_string(),
            h2.clone(),
            "a-tpl".to_string(),
        ];
        assert_eq!(slot_hash_dirnames(entries), vec![h2, h1]);
    }

    #[test]
    fn classify_handles_empty_input() {
        assert!(slot_hash_dirnames(Vec::<String>::new()).is_empty());
    }

    #[test]
    fn a_64_char_non_hex_dirname_is_not_a_slot() {
        // 64 chars but contains non-hex characters → not a slot hash.
        let almost = "G".repeat(64);
        assert!(slot_hash_dirnames(vec![almost]).is_empty());
    }

    #[test]
    fn an_uppercase_hex_dirname_is_not_a_slot() {
        // is_slot_hash_dirname requires LOWERCASE hex; uppercase rejects.
        let upper = "ABCDEF0123456789".repeat(4);
        assert_eq!(upper.len(), 64);
        assert!(slot_hash_dirnames(vec![upper]).is_empty());
    }

    #[test]
    fn classify_rejects_short_or_long_dirnames() {
        let short = "a".repeat(63);
        let long = "a".repeat(65);
        assert!(slot_hash_dirnames(vec![short, long]).is_empty());
    }

    #[test]
    fn slot_entry_clone_and_eq() {
        // Sanity: SlotEntry derives Clone/PartialEq for callers that
        // need to dedupe/compare in template list output.
        let a = SlotEntry {
            slot_hash: "abc".to_string(),
            manifest_path: "/abs/mvm.toml".to_string(),
            name: Some("openclaw".to_string()),
            updated_at: "2026-05-01T00:00:00Z".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
