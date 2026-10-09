//! Read and verify built manifest slots through the same surface as `mvmctl`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::domain::template_tags::TemplateTags;
use mvm_core::manifest::{PersistedManifest, canonical_key_for_path, resolve_manifest_config_path};
use mvm_core::template::SnapshotInfo;
use mvm_runtime::vm::template::lifecycle as tmpl;
use serde::{Deserialize, Serialize};

/// Filters for built slots. Tags have intersection semantics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    #[serde(default)]
    pub orphans: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A manifest file or directory; absent paths discover a manifest from cwd.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct InfoRequest {
    #[serde(default)]
    pub path: Option<String>,
}

/// Checksum verification of a built slot, optionally at a specific revision.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub check_signature: bool,
}

/// One built slot, preserving the manifest-list JSON representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SlotRow {
    pub slot_hash: String,
    pub manifest_path: String,
    pub name: Option<String>,
    pub updated_at: String,
    pub orphan: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub tags: BTreeSet<String>,
}

/// Persisted manifest and best-effort snapshot details.
#[derive(Debug, Serialize)]
pub struct SlotInfo {
    pub slot_hash: String,
    pub persisted: PersistedManifest,
    pub snapshot: Option<SnapshotInfo>,
}

/// Identity of a slot whose runtime checksum verification succeeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VerifiedSlot {
    pub slot_hash: String,
    pub manifest_path: PathBuf,
}

/// List built slots in runtime order, loading tags by optional template name.
pub fn list(request: &ListRequest) -> Result<Vec<SlotRow>> {
    let want_tags: BTreeSet<_> = request.tags.iter().collect();
    Ok(tmpl::template_list_slots()?
        .into_iter()
        .map(|entry| {
            let tags = entry
                .name
                .as_deref()
                .filter(|name| mvm_core::naming::validate_template_name(name).is_ok())
                .and_then(|name| TemplateTags::load(name).ok())
                .map(|catalog| catalog.tags)
                .unwrap_or_default();
            SlotRow {
                orphan: !Path::new(&entry.manifest_path).exists(),
                slot_hash: entry.slot_hash,
                manifest_path: entry.manifest_path,
                name: entry.name,
                updated_at: entry.updated_at,
                tags,
            }
        })
        .filter(|row| !request.orphans || row.orphan)
        .filter(|row| want_tags.iter().all(|tag| row.tags.contains(*tag)))
        .collect())
}

fn resolve(path: Option<&str>, no_manifest: &str) -> Result<(PathBuf, String)> {
    let manifest_path = match path {
        Some(path) => resolve_manifest_config_path(Path::new(path))?,
        None => {
            let cwd = std::env::current_dir().context("Failed to read cwd")?;
            mvm_core::manifest::discover_manifest_from_dir(&cwd)?
                .ok_or_else(|| anyhow::anyhow!("{no_manifest}"))?
        }
    };
    let canonical = std::fs::canonicalize(&manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;
    let slot_hash = canonical_key_for_path(&canonical)?;
    Ok((canonical, slot_hash))
}

/// Load a built manifest. Missing or unreadable snapshot metadata is optional.
pub fn info(request: &InfoRequest) -> Result<SlotInfo> {
    let (canonical, slot_hash) = resolve(
        request.path.as_deref(),
        "No manifest found from cwd. Run `mvmctl init` to create one, or pass a path explicitly.",
    )?;
    let persisted = tmpl::template_load_slot(&slot_hash).with_context(|| {
        format!(
            "Manifest at {} has no built slot — run `mvmctl build {}` first",
            canonical.display(),
            canonical.display()
        )
    })?;
    let snapshot = tmpl::template_snapshot_info_for_slot(&slot_hash)
        .ok()
        .flatten();
    Ok(SlotInfo {
        slot_hash,
        persisted,
        snapshot,
    })
}

/// Verify checksums using the runtime verifier. Signature checking is refused,
/// not silently downgraded to checksum-only verification.
pub fn verify(request: &VerifyRequest) -> Result<VerifiedSlot> {
    if request.check_signature {
        anyhow::bail!(
            "--check-signature is reserved for plan 36 (sealed-signed-builder-image) and is not yet wired. Run without the flag for the checksum-only path."
        );
    }
    if let Some(revision) = request.revision.as_deref() {
        tmpl::validate_slot_revision(revision)?;
    }
    let (manifest_path, slot_hash) = resolve(
        request.path.as_deref(),
        "No manifest found from cwd. Pass a path explicitly via the positional arg.",
    )?;
    let revision = match &request.revision {
        Some(revision) => revision.clone(),
        None => tmpl::current_revision_id_for_slot(&slot_hash)?,
    };
    tmpl::validate_slot_revision(&revision)?;
    tmpl::template_verify_slot(&slot_hash, Some(&revision))?;
    Ok(VerifiedSlot {
        slot_hash,
        manifest_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::manifest::{
        Manifest, Provenance, slot_current_symlink, slot_dir, slot_revision_dir,
    };
    use mvm_core::util::test_env::TestEnv;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn fixture(root: &Path, name: Option<&str>) -> (PathBuf, PersistedManifest) {
        std::fs::create_dir_all(root).unwrap();
        let path = root.join("mvm.toml");
        std::fs::write(
            &path,
            "flake = \".\"\nprofile = \"default\"\nvcpus = 2\nmem = \"1G\"\n",
        )
        .unwrap();
        let canonical = path.canonicalize().unwrap();
        let manifest = Manifest::read_file(&path).unwrap();
        let mut persisted = PersistedManifest::from_manifest(
            &manifest,
            &canonical,
            "firecracker",
            Provenance::current(),
        )
        .unwrap();
        persisted.name = name.map(str::to_string);
        persisted
            .write_to_slot(Path::new(&slot_dir(&persisted.manifest_hash)))
            .unwrap();
        (canonical, persisted)
    }

    #[test]
    fn request_defaults_roundtrip_and_strict_fields() {
        let list: ListRequest = serde_json::from_value(json!({})).unwrap();
        assert!(!list.orphans);
        assert!(list.tags.is_empty());
        assert!(
            serde_json::from_value::<InfoRequest>(json!({}))
                .unwrap()
                .path
                .is_none()
        );
        let verify: VerifyRequest = serde_json::from_value(json!({})).unwrap();
        assert!(verify.path.is_none() && verify.revision.is_none() && !verify.check_signature);
        let wire = json!({"path":"project", "revision":"abc12345", "check_signature":true});
        let request: VerifyRequest = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap(), wire);
        for malformed in [json!({"unknown":1}), json!({"path":42})] {
            assert!(serde_json::from_value::<InfoRequest>(malformed.clone()).is_err());
            assert!(serde_json::from_value::<VerifyRequest>(malformed).is_err());
        }
        for malformed in [
            json!({"unknown":1}),
            json!({"orphans":"yes"}),
            json!({"tags":[3]}),
        ] {
            assert!(serde_json::from_value::<ListRequest>(malformed).is_err());
        }
    }

    #[test]
    fn list_loads_catalog_filters_intersection_and_preserves_runtime_order() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        assert!(list(&ListRequest::default()).unwrap().is_empty());
        let (live, _) = fixture(&temp.path().join("live"), Some("live"));
        let (orphan, _) = fixture(&temp.path().join("orphan"), Some("orphan"));
        fixture(&temp.path().join("unnamed"), None);
        let mut catalog = TemplateTags::default();
        catalog.add_tag("a").unwrap();
        catalog.add_tag("b").unwrap();
        catalog.save("live").unwrap();
        catalog.save("orphan").unwrap();
        std::fs::remove_file(&orphan).unwrap();

        let all = list(&ListRequest::default()).unwrap();
        let expected: Vec<_> = tmpl::template_list_slots()
            .unwrap()
            .into_iter()
            .map(|e| e.slot_hash)
            .collect();
        assert_eq!(
            all.iter().map(|r| r.slot_hash.clone()).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(all.len(), 3);
        let unnamed = all.iter().find(|r| r.name.is_none()).unwrap();
        assert!(serde_json::to_value(unnamed).unwrap().get("tags").is_none());
        let filtered = list(&ListRequest {
            orphans: true,
            tags: vec!["b".into(), "a".into(), "a".into()],
        })
        .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].manifest_path, orphan.to_str().unwrap());
        assert!(filtered[0].orphan);
        assert_eq!(
            serde_json::to_value(&filtered[0]).unwrap()["tags"],
            json!(["a", "b"])
        );
        assert!(
            list(&ListRequest {
                tags: vec!["a".into(), "missing".into()],
                ..Default::default()
            })
            .unwrap()
            .is_empty()
        );
        assert!(
            all.iter()
                .any(|r| r.manifest_path == live.to_str().unwrap() && !r.orphan)
        );
    }

    #[test]
    fn list_does_not_load_tags_through_an_invalid_persisted_name() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        let (_, mut persisted) = fixture(&temp.path().join("project"), Some("demo"));
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("tags.json"),
            br#"{"tags":["outside"],"aliases":{}}"#,
        )
        .unwrap();
        persisted.name = Some("../outside".into());
        persisted
            .write_to_slot(Path::new(&slot_dir(&persisted.manifest_hash)))
            .unwrap();

        let rows = list(&ListRequest::default()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name.as_deref(), Some("../outside"));
        assert!(rows[0].tags.is_empty());
        assert!(
            list(&ListRequest {
                tags: vec!["outside".into()],
                ..Default::default()
            })
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn info_resolves_file_and_directory_and_snapshot_is_best_effort() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        let (path, persisted) = fixture(&temp.path().join("project"), Some("demo"));
        for input in [&path, path.parent().unwrap()] {
            let report = info(&InfoRequest {
                path: Some(input.display().to_string()),
            })
            .unwrap();
            assert_eq!(report.slot_hash, persisted.manifest_hash);
            assert!(report.snapshot.is_none());
            assert_eq!(
                serde_json::to_value(&report).unwrap(),
                json!({
                    "slot_hash": persisted.manifest_hash, "persisted": persisted, "snapshot": null
                })
            );
        }
        let request = InfoRequest {
            path: Some(path.display().to_string()),
        };
        let revision = PathBuf::from(slot_revision_dir(&persisted.manifest_hash, "abc12345"));
        std::fs::create_dir_all(&revision).unwrap();
        std::os::unix::fs::symlink(
            "artifacts/revisions/abc12345",
            slot_current_symlink(&persisted.manifest_hash),
        )
        .unwrap();
        let snapshot = SnapshotInfo {
            created_at: "2026-06-16T00:00:00Z".into(),
            vmstate_size_bytes: 1024,
            mem_size_bytes: 1048576,
            boot_args: "console=ttyS0".into(),
            vcpus: 2,
            mem_mib: 1024,
            compatibility: None,
        };
        let metadata = json!({
            "schema_version":1, "revision_hash":"abc12345", "flake_ref":".",
            "flake_lock_hash":"lock", "profile":"default", "vcpus":2,
            "mem_mib":1024, "data_disk_mib":0, "built_at":snapshot.created_at,
            "artifact_paths":{"vmlinux":"vmlinux","rootfs":"rootfs.ext4","fc_base_config":"fc-base.json"},
            "snapshot":snapshot
        });
        std::fs::write(
            revision.join("revision.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        let report = info(&request).unwrap();
        assert_eq!(
            serde_json::to_value(report.snapshot.unwrap()).unwrap(),
            serde_json::to_value(snapshot).unwrap()
        );
        let outside = PathBuf::from(slot_dir(&persisted.manifest_hash)).join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("revision.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        let current = slot_current_symlink(&persisted.manifest_hash);
        std::fs::remove_file(&current).unwrap();
        std::os::unix::fs::symlink("artifacts/revisions/../../outside", &current).unwrap();
        assert!(info(&request).unwrap().snapshot.is_none());
        std::fs::remove_file(&current).unwrap();
        std::os::unix::fs::symlink("artifacts/revisions/abc12345", &current).unwrap();
        std::fs::write(revision.join("revision.json"), "broken").unwrap();
        assert!(info(&request).unwrap().snapshot.is_none());
        std::fs::write(
            Path::new(&slot_dir(&persisted.manifest_hash)).join("manifest.json"),
            "broken",
        )
        .unwrap();
        let error = info(&InfoRequest {
            path: Some(path.display().to_string()),
        })
        .unwrap_err();
        assert!(error.to_string().contains("has no built slot"));
        assert!(error.chain().count() > 1);
        std::fs::remove_file(path).unwrap();
        assert!(info(&request).is_err());
        assert!(
            verify(&VerifyRequest {
                path: request.path,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn verify_runtime_success_and_failure_meanings() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        let (path, persisted) = fixture(&temp.path().join("project"), None);
        let mut request = VerifyRequest {
            path: Some(path.display().to_string()),
            ..Default::default()
        };
        assert!(
            verify(&request)
                .unwrap_err()
                .to_string()
                .contains("Slot has no current revision")
        );
        request.revision = Some("abc12345".into());
        assert!(
            verify(&request)
                .unwrap_err()
                .to_string()
                .contains("checksums are written")
        );
        let revision = PathBuf::from(slot_revision_dir(&persisted.manifest_hash, "abc12345"));
        std::fs::create_dir_all(&revision).unwrap();
        let sums = revision.join("checksums.json");
        std::fs::write(&sums, "broken").unwrap();
        assert!(
            verify(&request)
                .unwrap_err()
                .to_string()
                .contains("Corrupt")
        );
        std::fs::write(revision.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(&sums, serde_json::to_vec(&json!({
            "schema_version":1, "template_id":persisted.manifest_hash,
            "revision_hash":"abc12345", "files":{"vmlinux":hex::encode(Sha256::digest(b"kernel"))}
        })).unwrap()).unwrap();
        let verified = verify(&request).unwrap();
        assert_eq!(verified.slot_hash, persisted.manifest_hash);
        assert_eq!(verified.manifest_path, path);
        assert_eq!(
            serde_json::to_value(&verified).unwrap(),
            json!({"slot_hash":persisted.manifest_hash,"manifest_path":path})
        );
        std::os::unix::fs::symlink(
            "artifacts/revisions/abc12345",
            slot_current_symlink(&persisted.manifest_hash),
        )
        .unwrap();
        request.revision = None;
        verify(&request).unwrap();
        std::fs::write(revision.join("vmlinux"), b"tampered").unwrap();
        let error = verify(&request).unwrap_err().to_string();
        assert!(error.contains("failed verification") && error.contains("vmlinux: expected"));
        std::fs::remove_file(revision.join("vmlinux")).unwrap();
        assert!(
            verify(&request)
                .unwrap_err()
                .to_string()
                .contains("vmlinux: missing")
        );
    }

    #[test]
    fn signature_and_revision_traversal_are_refused_at_the_boundary() {
        let error = verify(&VerifyRequest {
            check_signature: true,
            ..Default::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("not yet wired"));
        for revision in [
            "",
            ".",
            "..",
            "../outside",
            "/tmp/outside",
            "abc/def",
            "abc\\def",
        ] {
            let error = verify(&VerifyRequest {
                revision: Some(revision.into()),
                ..Default::default()
            })
            .unwrap_err();
            assert!(
                error.to_string().contains("invalid slot revision hash"),
                "{error:#}"
            );
        }
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        let (path, persisted) = fixture(&temp.path().join("project"), None);
        std::os::unix::fs::symlink(
            "artifacts/revisions/../../outside",
            slot_current_symlink(&persisted.manifest_hash),
        )
        .unwrap();
        let error = verify(&VerifyRequest {
            path: Some(path.display().to_string()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("invalid slot revision hash"));
    }
}
