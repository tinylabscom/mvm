//! Snapshot metadata lookups, and the `*_dispatched` resolvers that
//! fan a caller-supplied id/key out to the legacy name-keyed, modern
//! slot-keyed, or bundle-sha256 path depending on its shape.

use anyhow::{Context, Result};
use mvm_core::manifest::{PersistedManifest, is_slot_hash_dirname, slot_dir, slot_revision_dir};
use mvm_core::template::{SnapshotInfo, TemplateRevision, TemplateSpec};
use tracing::instrument;

use super::artifacts::{
    bundle_artifacts_for_sha, current_revision_id_for_slot, template_artifacts_for_slot,
};
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
    // A 64-char hex string is ambiguous: it could be a templates/ slot hash OR
    // a bundle sha256. Resolve by checking which directory actually exists; the
    // templates slot wins when both are present.
    let slot_path = require_slot_key(id_or_slot)?;
    if slot_path.exists() {
        let (persisted, vmlinux, initrd, rootfs, rev) = template_artifacts_for_slot(id_or_slot)?;
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
}

/// Every template key is a slot hash or a bundle sha256 — both 64-char
/// lowercase hex. Anything else used to fall through to a name-keyed lookup;
/// there are no name-keyed slots, so it is rejected here with the shape it
/// failed, rather than as a missing directory further down.
fn require_slot_key(id_or_slot: &str) -> Result<std::path::PathBuf> {
    if !is_slot_hash_dirname(id_or_slot) {
        anyhow::bail!(
            "{id_or_slot:?} is not a template slot: expected a 64-character \
             lowercase-hex slot hash or bundle sha256"
        );
    }
    Ok(std::path::Path::new(&slot_dir(id_or_slot)).to_path_buf())
}

/// Boot-path variant of [`template_artifacts_dispatched`].
///
/// Identical, plus one refusal: when the key resolves to an *installed bundle*,
/// a bundle whose declared architecture is not this host's is refused here
/// rather than deep in the backend, where it surfaces as an unrelated-looking
/// kernel or boot failure.
///
/// This is a separate entry point rather than a check inside
/// [`template_artifacts_dispatched`] on purpose. That resolver is shared with
/// callers that legitimately resolve foreign-arch artifacts without booting
/// them — `bundle export` and `manifest export-oci` both reach it — so gating
/// it there breaks cross-arch export. Boot sites call this; everyone else keeps
/// calling the un-suffixed function.
#[instrument(skip_all, fields(id_or_slot = id_or_slot))]
pub fn template_artifacts_for_boot(
    id_or_slot: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    if let Some(declared) = installed_bundle_arch(id_or_slot)? {
        mvm_core::arch::GuestArch::require_host(&declared).map_err(|e| {
            anyhow::anyhow!(
                "bundle {id_or_slot} {e} — install a {} build of this workload                  (`mvmctl bundle fetch` / `mvmctl bundle install`), or run it on                  a {declared} host",
                mvm_core::arch::GuestArch::host(),
            )
        })?;
    }
    template_artifacts_dispatched(id_or_slot)
}

/// The declared arch of an installed bundle, or `None` when `id_or_slot` is not
/// one (a named template, or a slot — a slot wins over a same-named bundle, and
/// carries no manifest to check).
///
/// Reuses the same slot-or-bundle decision `template_artifacts_dispatched`
/// makes, so the gate cannot drift from what actually gets resolved.
pub fn installed_bundle_arch(id_or_slot: &str) -> Result<Option<String>> {
    if !is_slot_hash_dirname(id_or_slot) {
        return Ok(None);
    }
    if std::path::Path::new(&slot_dir(id_or_slot)).exists() {
        return Ok(None);
    }
    let registry = mvm_core::plan::bundle::BundleRegistry::default_path()?;
    // A registry we cannot read must not silently skip the gate: propagate,
    // so an unparseable manifest refuses the boot rather than admitting it
    // unchecked.
    Ok(registry
        .find(id_or_slot)?
        .map(|installed| installed.manifest.arch))
}

/// The declared arch of an installed bundle, for the *export* path, which
/// prefers a best-effort answer over a refusal — a bundle it cannot read is
/// simply not a bundle whose arch it can carry through.
pub fn installed_bundle_arch_for_export(id_or_slot: &str) -> Option<String> {
    installed_bundle_arch(id_or_slot).ok().flatten()
}

/// Dispatched variant of [`super::crud::template_load`] / [`super::slots::template_load_slot`].
/// Returns a [`TemplateSpec`] regardless of which key shape was used.
///
/// Bundle-sha256 fallthrough mirrors `template_artifacts_dispatched`:
/// when the 64-char hex name doesn't have a templates/ slot dir,
/// look it up in the bundle registry.
pub fn template_load_dispatched(id_or_slot: &str) -> Result<TemplateSpec> {
    let slot_path = require_slot_key(id_or_slot)?;
    if slot_path.exists() {
        let persisted = template_load_slot(id_or_slot)?;
        Ok(persisted_to_synthetic_spec(&persisted))
    } else {
        // Reuse the artifact-resolver to derive a TemplateSpec from an
        // installed bundle — same fields, same defaults.
        let (spec, _vm, _ir, _rf, _rev) = bundle_artifacts_for_sha(id_or_slot)?;
        Ok(spec)
    }
}

/// Dispatched variant of [`template_snapshot_info`] /
/// [`template_snapshot_info_for_slot`]. Bundles don't ship
/// snapshots today (the snapshot is a per-host FC artifact tied to
/// the machine that built it); the bundle fallthrough returns
/// `None` rather than erroring.
pub fn template_snapshot_info_dispatched(id_or_slot: &str) -> Result<Option<SnapshotInfo>> {
    let slot_path = require_slot_key(id_or_slot)?;
    if slot_path.exists() {
        template_snapshot_info_for_slot(id_or_slot)
    } else {
        Ok(None)
    }
}

/// Dispatched variant of [`template_has_snapshot`] /
/// [`template_has_snapshot_for_slot`]. Same bundle-fallthrough
/// shape as `template_snapshot_info_dispatched`: bundles never
/// have snapshots in v1.
pub fn template_has_snapshot_dispatched(id_or_slot: &str) -> Result<bool> {
    let slot_path = require_slot_key(id_or_slot)?;
    if slot_path.exists() {
        template_has_snapshot_for_slot(id_or_slot)
    } else {
        Ok(false)
    }
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

    /// Write a minimal installed-bundle manifest so `BundleRegistry::find`
    /// resolves it. Only `manifest.json` is read for the arch decision — no
    /// signature, no install step.
    fn install_bundle_manifest(sha: &str, arch: &str) {
        let dir = std::path::PathBuf::from(mvm_core::config::mvm_home())
            .join("bundles")
            .join(sha);
        std::fs::create_dir_all(&dir).expect("bundle dir");
        let manifest = serde_json::json!({
            "schema_version": mvm_core::plan::bundle::BUNDLE_SCHEMA_VERSION,
            "publisher": "test",
            "key_id": "test-key",
            "arch": arch,
            "created_at": "2026-01-01T00:00:00Z",
            "artifacts": [],
        });
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("encode manifest"),
        )
        .expect("write manifest");
    }

    fn other_arch() -> &'static str {
        match mvm_core::arch::GuestArch::host() {
            mvm_core::arch::GuestArch::X86_64 => "aarch64",
            mvm_core::arch::GuestArch::Aarch64 => "x86_64",
        }
    }

    /// The G2 witness: a bundle built for the other architecture is refused at
    /// the boot resolver, naming both sides.
    #[test]
    fn template_artifacts_for_boot_refuses_a_foreign_arch_bundle() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let sha = "abcdef0123456789".repeat(4);
        install_bundle_manifest(&sha, other_arch());

        let err = template_artifacts_for_boot(&sha)
            .expect_err("a foreign-arch bundle must not resolve for boot");
        let msg = format!("{err:#}");
        assert!(msg.contains("but this host is"), "{msg}");
        assert!(msg.contains(other_arch()), "{msg}");
    }

    /// The same call on a host-arch bundle gets past the gate. It still fails —
    /// the fixture has no artifacts — but *not* with an architecture refusal,
    /// which is what distinguishes the gate from a blanket rejection.
    #[test]
    fn template_artifacts_for_boot_does_not_refuse_a_host_arch_bundle_on_arch() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let sha = "beefcafe01234567".repeat(4);
        install_bundle_manifest(&sha, &mvm_core::arch::GuestArch::host().to_string());

        let msg = match template_artifacts_for_boot(&sha) {
            Ok(_) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            !msg.contains("but this host is"),
            "host-arch bundle must not be refused on architecture: {msg}"
        );
    }

    /// A slot wins over an identically-named bundle, and a slot carries no
    /// manifest — so the gate must not invent an architecture for it. Locks the
    /// dispatch precedence into the gate's behaviour.
    #[test]
    fn template_artifacts_for_boot_ignores_arch_for_a_slot() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let sha = "0123456789abcdef".repeat(4);
        // Both a slot and a foreign-arch bundle under the same name.
        let slot = test_persisted_manifest(&sha);
        slot.write_to_slot(std::path::Path::new(&slot_dir(&sha)))
            .expect("write persisted slot");
        install_bundle_manifest(&sha, other_arch());

        assert_eq!(installed_bundle_arch_for_export(&sha), None);
        let msg = match template_artifacts_for_boot(&sha) {
            Ok(_) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            !msg.contains("but this host is"),
            "a slot must not be gated on a same-named bundle's arch: {msg}"
        );
    }

    /// The regression the first attempt at this gate broke: `bundle export` and
    /// `manifest export-oci` legitimately resolve foreign-arch artifacts
    /// without booting them, and reach the registry through the *un-suffixed*
    /// resolver. Placing the gate in the shared path blocked them.
    #[test]
    fn the_un_suffixed_resolver_still_admits_a_foreign_arch_bundle() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let sha = "feedface89abcdef".repeat(4);
        install_bundle_manifest(&sha, other_arch());

        let msg = match template_artifacts_dispatched(&sha) {
            Ok(_) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            !msg.contains("but this host is"),
            "export paths must not be gated on architecture: {msg}"
        );
    }

    /// `bundle export` re-stamping the exporting host's arch onto a re-exported
    /// foreign-arch bundle would produce a mislabelled `.mvmpkg` — and the label
    /// is exactly what the boot gate above trusts.
    #[test]
    fn a_re_exported_bundle_keeps_its_own_arch() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

        let sha = "0f0f0f0f89abcdef".repeat(4);
        install_bundle_manifest(&sha, other_arch());

        assert_eq!(
            installed_bundle_arch_for_export(&sha).as_deref(),
            Some(other_arch()),
            "export must carry the source bundle's arch, not this host's"
        );
    }
}
