//! Snapshot metadata lookups, and the `*_dispatched` resolvers that
//! fan a caller-supplied id/key out to the legacy name-keyed, modern
//! slot-keyed, or bundle-sha256 path depending on its shape.

use anyhow::{Context, Result};
use mvm_core::manifest::{PersistedManifest, is_slot_hash_dirname, slot_dir, slot_revision_dir};
use mvm_core::template::{
    SnapshotInfo, TemplateRevision, TemplateSpec, template_revision_dir, template_snapshot_dir,
};
use tracing::instrument;

use super::artifacts::{
    bundle_artifacts_for_sha, current_revision_id, current_revision_id_for_slot,
    template_artifacts, template_artifacts_for_slot,
};
use super::crud::template_load;
use super::slots::template_load_slot;

/// Whether the slot's current revision has a Firecracker snapshot.
pub fn template_has_snapshot_for_slot(slot_hash: &str) -> Result<bool> {
    let rev = current_revision_id_for_slot(slot_hash)?;
    let snap_dir = mvm_core::manifest::slot_snapshot_dir(slot_hash, &rev);
    let vmstate = std::path::Path::new(&snap_dir).join("vmstate.bin");
    let mem = std::path::Path::new(&snap_dir).join("mem.bin");
    Ok(vmstate.exists() && mem.exists())
}

/// Load snapshot metadata for the slot's current revision.
pub fn template_snapshot_info_for_slot(slot_hash: &str) -> Result<Option<SnapshotInfo>> {
    let rev = current_revision_id_for_slot(slot_hash)?;
    let rev_dir = slot_revision_dir(slot_hash, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    let data = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read revision.json for slot {}", slot_hash))?;
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for slot {}", slot_hash))?;
    Ok(revision.snapshot)
}

/// Synthesize a [`TemplateSpec`] from a [`PersistedManifest`] so the
/// dispatched functions below can return a single shape regardless of
/// whether the caller passed a name or a slot hash.
///
/// `template_id` is set to the manifest hash; `role` is empty (manifest
/// schema doesn't carry a role); `default_network_policy` is `None`
/// (the manifest schema doesn't carry network policy either —
/// runtime policy comes from CLI flags / `~/.mvm/config.toml` / mvmd).
fn persisted_to_synthetic_spec(p: &PersistedManifest) -> TemplateSpec {
    TemplateSpec {
        schema_version: p.schema_version,
        template_id: p.manifest_hash.clone(),
        flake_ref: p.flake_ref.clone(),
        profile: p.profile.clone(),
        role: String::new(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        mem_initial_mib: p.mem_initial_mib,
        data_disk_mib: p.data_disk_mib,
        created_at: p.created_at.clone(),
        updated_at: p.updated_at.clone(),
        default_network_policy: None,
    }
}

/// Unified entry point that dispatches by id/key shape:
///
/// 1. **Legacy name** (e.g. `claude-code-vm`) → `template_artifacts`.
/// 2. **Slot hash** (`sha256(canonical_manifest_path)`, 64-char hex,
///    and the slot dir exists under `~/.mvm/templates/`) →
///    `template_artifacts_for_slot`.
/// 3. **Bundle sha256** (also 64-char hex, but the slot dir doesn't
///    exist; the bundle registry under `~/.mvm/bundles/<sha>/` does)
///    → `bundle_artifacts_for_sha`. Bundles are content-addressed
///    images fetched + installed via `mvmctl bundle install`.
///
/// Used by `mvmctl up` / `mvmctl exec` so the CLI can resolve a
/// `--manifest <PATH>` argument to a slot hash and pass it through
/// unchanged. Returns the same shape as [`super::artifacts::template_artifacts`].
#[instrument(skip_all, fields(id_or_slot = id_or_slot))]
pub fn template_artifacts_dispatched(
    id_or_slot: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    if is_slot_hash_dirname(id_or_slot) {
        // A 64-char hex string is ambiguous: it could be a templates/
        // slot hash OR a bundle sha256. Resolve by checking which
        // directory actually exists. Templates-slot wins when both
        // are present (legacy build-on-this-host stays the primary
        // path).
        let slot_path = std::path::Path::new(&slot_dir(id_or_slot)).to_path_buf();
        if slot_path.exists() {
            let (persisted, vmlinux, initrd, rootfs, rev) =
                template_artifacts_for_slot(id_or_slot)?;
            Ok((
                persisted_to_synthetic_spec(&persisted),
                vmlinux,
                initrd,
                rootfs,
                rev,
            ))
        } else {
            bundle_artifacts_for_sha(id_or_slot)
        }
    } else {
        template_artifacts(id_or_slot)
    }
}

/// Dispatched variant of [`super::crud::template_load`] / [`super::slots::template_load_slot`].
/// Returns a [`TemplateSpec`] regardless of which key shape was used.
///
/// Bundle-sha256 fallthrough mirrors `template_artifacts_dispatched`:
/// when the 64-char hex name doesn't have a templates/ slot dir,
/// look it up in the bundle registry.
pub fn template_load_dispatched(id_or_slot: &str) -> Result<TemplateSpec> {
    if is_slot_hash_dirname(id_or_slot) {
        let slot_path = std::path::Path::new(&slot_dir(id_or_slot)).to_path_buf();
        if slot_path.exists() {
            let persisted = template_load_slot(id_or_slot)?;
            Ok(persisted_to_synthetic_spec(&persisted))
        } else {
            // Reuse the artifact-resolver to derive a TemplateSpec
            // from an installed bundle — same fields, same defaults.
            let (spec, _vm, _ir, _rf, _rev) = bundle_artifacts_for_sha(id_or_slot)?;
            Ok(spec)
        }
    } else {
        template_load(id_or_slot)
    }
}

/// Dispatched variant of [`template_snapshot_info`] /
/// [`template_snapshot_info_for_slot`]. Bundles don't ship
/// snapshots today (the snapshot is a per-host FC artifact tied to
/// the machine that built it); the bundle fallthrough returns
/// `None` rather than erroring.
pub fn template_snapshot_info_dispatched(id_or_slot: &str) -> Result<Option<SnapshotInfo>> {
    if is_slot_hash_dirname(id_or_slot) {
        let slot_path = std::path::Path::new(&slot_dir(id_or_slot)).to_path_buf();
        if slot_path.exists() {
            template_snapshot_info_for_slot(id_or_slot)
        } else {
            Ok(None)
        }
    } else {
        template_snapshot_info(id_or_slot)
    }
}

/// Dispatched variant of [`template_has_snapshot`] /
/// [`template_has_snapshot_for_slot`]. Same bundle-fallthrough
/// shape as `template_snapshot_info_dispatched`: bundles never
/// have snapshots in v1.
pub fn template_has_snapshot_dispatched(id_or_slot: &str) -> Result<bool> {
    if is_slot_hash_dirname(id_or_slot) {
        let slot_path = std::path::Path::new(&slot_dir(id_or_slot)).to_path_buf();
        if slot_path.exists() {
            template_has_snapshot_for_slot(id_or_slot)
        } else {
            Ok(false)
        }
    } else {
        template_has_snapshot(id_or_slot)
    }
}

/// Check if the current revision of a template has a snapshot.
pub fn template_has_snapshot(id: &str) -> Result<bool> {
    let rev = current_revision_id(id)?;
    let snap_dir = template_snapshot_dir(id, &rev);
    let vmstate = std::path::Path::new(&snap_dir).join("vmstate.bin");
    let mem = std::path::Path::new(&snap_dir).join("mem.bin");
    Ok(vmstate.exists() && mem.exists())
}

/// Load the snapshot metadata for a template revision.
pub fn template_snapshot_info(id: &str) -> Result<Option<SnapshotInfo>> {
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    // Read directly from host filesystem
    let data = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read revision.json for template {}", id))?;
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for template {}", id))?;
    Ok(revision.snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::manifest::Provenance;
    use mvm_core::util::test_env::TestEnv;

    fn test_persisted_manifest(slot_hash: &str) -> PersistedManifest {
        PersistedManifest {
            schema_version: mvm_core::manifest::MANIFEST_SCHEMA_VERSION,
            manifest_path: "/tmp/mvm-test/mvm.toml".to_string(),
            manifest_hash: slot_hash.to_string(),
            flake_ref: ".".to_string(),
            profile: "default".to_string(),
            vcpus: 1,
            mem_mib: 256,
            mem_initial_mib: None,
            data_disk_mib: 0,
            name: Some("valid-template".to_string()),
            backend: "test".to_string(),
            provenance: Provenance {
                toolchain_version: "test".to_string(),
                builder_image_digest: None,
                host_arch: "test-host".to_string(),
                built_at: "2026-06-16T00:00:00Z".to_string(),
                ir_hash: None,
            },
            created_at: "2026-06-16T00:00:00Z".to_string(),
            updated_at: "2026-06-16T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn template_load_dispatched_accepts_real_slot_hash() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let slot_hash = "0123456789abcdef".repeat(4);
        assert!(is_slot_hash_dirname(&slot_hash));
        let slot = test_persisted_manifest(&slot_hash);
        slot.write_to_slot(std::path::Path::new(&slot_dir(&slot_hash)))
            .expect("write persisted slot");

        let loaded = template_load_dispatched(&slot_hash).expect("load slot hash");
        assert_eq!(loaded.template_id, slot_hash);
    }
}
