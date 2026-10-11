use super::*;
use mvm_core::util::test_env::TestEnv;

fn touch(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, vec![0u8; 4096]).unwrap();
}

fn disk_request(apply: bool) -> CachePruneRequest {
    CachePruneRequest {
        apply,
        no_reap_orphans: true,
        ..Default::default()
    }
}

#[test]
fn requests_default_to_preview() {
    assert!(!CachePruneRequest::default().apply);
    assert!(!RepairRequest::default().apply);
    assert!(!RepairRequest::default().force);
    assert_eq!(RepairRequest::default().scope, RepairScope::BuilderStore);
}

#[test]
fn the_stage0_store_is_kept_unless_asked_for() {
    assert_eq!(
        stage0_store_reclaim_action(false, false, false),
        Stage0StoreReclaim::Keep
    );
    assert_eq!(
        stage0_store_reclaim_action(false, false, true),
        Stage0StoreReclaim::Keep
    );
}

#[test]
fn the_stage0_store_is_cleared_when_named_or_swept_by_deep() {
    assert_eq!(
        stage0_store_reclaim_action(true, false, false),
        Stage0StoreReclaim::Clear
    );
    assert_eq!(
        stage0_store_reclaim_action(false, true, false),
        Stage0StoreReclaim::Clear
    );
}

#[test]
fn a_running_bootstrap_refuses_an_explicit_request_and_is_skipped_by_deep() {
    assert_eq!(
        stage0_store_reclaim_action(true, false, true),
        Stage0StoreReclaim::Refuse
    );
    assert_eq!(
        stage0_store_reclaim_action(true, true, true),
        Stage0StoreReclaim::Refuse,
        "naming it explicitly still refuses under --deep"
    );
    assert_eq!(
        stage0_store_reclaim_action(false, true, true),
        Stage0StoreReclaim::SkipInFlight
    );
}

#[test]
fn regenerable_targets_only_existing_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    touch(&root.join("stage0/blob"));
    std::fs::create_dir_all(root.join("oci")).unwrap();
    let targets = regenerable_cache_targets(root);
    let names: Vec<_> = targets
        .iter()
        .map(|(e, _)| e.path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["stage0", "oci"]);
    assert!(targets[0].0.bytes >= 4096);
    for (name, _) in REGENERABLE_CACHE_ENTRIES {
        assert!(
            !super::super::RETIRED_CACHE_ENTRIES.contains(name),
            "{name} is reclaimed by --deep and must not also be retired"
        );
    }
}

#[test]
fn reclaim_entries_dry_run_is_a_noop() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let victim = home.path().join("cache/stage0");
    touch(&victim.join("blob"));
    let mut request = disk_request(false);
    request.deep = true;
    let preview = prune(&request, |_| {}).unwrap();
    assert!(preview.removed >= 1);
    assert!(preview.freed_bytes >= 4096);
    assert!(victim.exists(), "dry-run must not remove anything");
    assert!(!home.path().join("state/log/audit.jsonl").exists());
    request.apply = true;
    let applied = prune(&request, |_| {}).unwrap();
    assert!(applied.removed >= 1);
    assert!(!victim.exists(), "live run must remove the entry");
}

#[test]
fn prune_removes_the_retired_hvf_builder_images() {
    let cache = tempfile::tempdir().unwrap();
    let hvf = cache.path().join(RETIRED_HVF_IMAGE_DIR);
    touch(&hvf.join("abc123/rootfs.ext4"));
    std::fs::create_dir_all(hvf.join("def456.partial")).unwrap();
    assert_eq!(
        sweep_retired_hvf_builder_images(&hvf, true, &mut |_| {}).unwrap(),
        (0, 0)
    );
    assert!(hvf.join("abc123").exists(), "a dry run removes nothing");
    let (removed, freed) = sweep_retired_hvf_builder_images(&hvf, false, &mut |_| {}).unwrap();
    assert_eq!(removed, 2);
    assert!(freed >= 4096, "{freed}");
    assert!(!hvf.exists());
    assert_eq!(
        sweep_retired_hvf_builder_images(&hvf, false, &mut |_| {}).unwrap(),
        (0, 0)
    );
}

#[cfg(unix)]
#[test]
fn dir_size_does_not_inflate_a_tree_full_of_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let payload = root.join("layer");
    std::fs::create_dir_all(payload.join("bin")).unwrap();
    std::fs::write(payload.join("bin/busybox"), vec![0u8; 256 * 1024]).unwrap();
    let real_bytes = dir_size(root);
    for applet in ["sh", "ls", "cat", "cp", "mv", "rm", "sed", "awk"] {
        std::os::unix::fs::symlink(
            payload.join("bin/busybox"),
            payload.join("bin").join(applet),
        )
        .unwrap();
    }
    std::os::unix::fs::symlink(payload.join("bin"), root.join("usr-bin")).unwrap();
    let with_links = dir_size(root);
    assert!(
        with_links < real_bytes + 256 * 1024,
        "symlinks must not multiply the estimate: {real_bytes} bytes of payload measured {with_links} once linked"
    );
}

#[cfg(unix)]
#[test]
fn walkdir_does_not_descend_through_a_symlinked_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    touch(&outside.join("precious.tmp"));
    let cache = tmp.path().join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::os::unix::fs::symlink(&outside, cache.join("link")).unwrap();
    let reached: Vec<_> = walkdir(&cache)
        .unwrap()
        .iter()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(reached, vec!["link"], "the link is yielded, not followed");
}

#[test]
fn configured_prune_applies_temp_and_retired_hvf_preserves_identity_and_audits_summary() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    for name in [
        "cache/a.tmp",
        "cache/mvm-lima-old/blob",
        "cache/builder-vm/hvf/old/rootfs",
        "cache/stage0/blob",
        "keys/host-signer",
        "secrets/value",
        "cache/unknown/blob",
    ] {
        touch(&home.path().join(name));
    }
    let key = std::fs::read(home.path().join("keys/host-signer")).unwrap();
    let preview = prune(&disk_request(false), |_| {}).unwrap();
    assert!(preview.removed >= 2);
    assert!(home.path().join("cache/a.tmp").exists());
    assert!(home.path().join("cache/builder-vm/hvf/old/rootfs").exists());
    let applied = prune(&disk_request(true), |_| {}).unwrap();
    assert!(applied.removed >= 3);
    for name in ["cache/a.tmp", "cache/mvm-lima-old", "cache/builder-vm/hvf"] {
        assert!(!home.path().join(name).exists(), "{name}");
    }
    assert_eq!(
        std::fs::read(home.path().join("keys/host-signer")).unwrap(),
        key
    );
    for name in ["secrets/value", "cache/stage0/blob", "cache/unknown/blob"] {
        assert!(home.path().join(name).exists(), "{name}");
    }
    let audit = std::fs::read_to_string(home.path().join("state/log/audit.jsonl")).unwrap();
    assert!(
        audit.contains(&format!(
            "removed={} freed_bytes={}",
            applied.removed, applied.freed_bytes
        )),
        "{audit}"
    );
}

#[cfg(unix)]
#[test]
fn temp_and_deep_symlinks_do_not_delete_outside_bytes() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    touch(&outside.path().join("precious.tmp"));
    let before = std::fs::read(outside.path().join("precious.tmp")).unwrap();
    std::fs::create_dir_all(home.path().join("cache")).unwrap();
    for name in ["temp.tmp", "stage0", "link"] {
        std::os::unix::fs::symlink(outside.path(), home.path().join("cache").join(name)).unwrap();
    }
    let mut request = disk_request(true);
    request.deep = true;
    prune(&request, |_| {}).unwrap();
    assert_eq!(
        std::fs::read(outside.path().join("precious.tmp")).unwrap(),
        before
    );
    assert!(
        home.path()
            .join("cache/link")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!home.path().join("cache/temp.tmp").exists());
    assert!(!home.path().join("cache/stage0").exists());
}

#[cfg(unix)]
#[test]
fn configured_root_symlink_refuses_before_outside_writes() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    touch(&outside.path().join("precious.tmp"));
    std::os::unix::fs::symlink(outside.path(), home.path().join("cache")).unwrap();
    assert!(prune(&disk_request(true), |_| {}).is_err());
    assert!(
        repair(&RepairRequest {
            apply: true,
            ..Default::default()
        })
        .is_err()
    );
    assert!(outside.path().join("precious.tmp").exists());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn pack_index_staging_symlink_and_hardlink_never_overwrite_outside_bytes() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    touch(&outside.path().join("precious"));
    let before = std::fs::read(outside.path().join("precious")).unwrap();
    touch(&home.path().join("cache/inside.tmp"));
    std::fs::create_dir_all(home.path().join("cache/packs")).unwrap();
    let staging = home.path().join("cache/packs/index.json.tmp");
    for hardlink in [false, true] {
        touch(&home.path().join("cache/inside.tmp"));
        if hardlink {
            std::fs::hard_link(outside.path().join("precious"), &staging).unwrap();
        } else {
            std::os::unix::fs::symlink(outside.path().join("precious"), &staging).unwrap();
        }
        prune(&disk_request(true), |_| {}).unwrap();
        assert_eq!(
            std::fs::read(outside.path().join("precious")).unwrap(),
            before
        );
        assert!(!home.path().join("cache/inside.tmp").exists());
        assert!(
            !staging.exists(),
            "ordinary temp cleanup still unlinks stale staging"
        );
        assert!(home.path().join("cache/packs/index.json").is_file());
    }
}

#[test]
fn held_stage0_lock_refuses_explicit_prune_and_repair_before_removal() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let builder = home.path().join("cache/builder-vm");
    touch(&builder.join("keep"));
    touch(&home.path().join("cache/remove.tmp"));
    let guard = mvm_core::atomic_io::FileLock::try_acquire(&builder.join("stage0"))
        .unwrap()
        .unwrap();
    let mut request = disk_request(true);
    request.stage0_store = true;
    assert!(
        prune(&request, |_| {})
            .unwrap_err()
            .to_string()
            .contains("bootstrap")
    );
    assert!(home.path().join("cache/remove.tmp").exists());
    assert!(
        repair(&RepairRequest {
            apply: true,
            ..Default::default()
        })
        .unwrap_err()
        .to_string()
        .contains("bootstrap")
    );
    assert!(builder.join("keep").exists());
    // Deep is deliberately weaker than an explicit stage0-store request:
    // reclaim the other tiers while sparing the running bootstrap's image.
    let stage0_image = builder.join(mvm_build::builder_vm::stage0_store_image_name_for(
        mvm_build::builder_vm::host_arch_tag(),
    ));
    touch(&stage0_image);
    request.stage0_store = false;
    request.deep = true;
    let mut skipped = false;
    prune(&request, |event| {
        if matches!(event, CachePruneEvent::Stage0StoreSkipped) {
            skipped = true;
        }
    })
    .unwrap();
    assert!(skipped);
    assert!(stage0_image.exists());
    assert!(!home.path().join("cache/remove.tmp").exists());
    // Established force override remains available; it is not a global lease.
    let report = repair(&RepairRequest {
        apply: true,
        force: true,
        ..Default::default()
    })
    .unwrap();
    assert!(report.existed);
    assert!(!builder.exists());
    drop(guard);
}

#[test]
fn store_only_repair_preview_and_apply_preserve_other_artifacts_and_identity() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let builder = home.path().join("cache/builder-vm");
    let image = builder.join(format!(
        "nix-store-{}.img",
        mvm_build::builder_vm::host_arch_tag()
    ));
    touch(&image);
    touch(&builder.join("kernel"));
    touch(&home.path().join("keys/identity"));
    let mut request = RepairRequest {
        scope: RepairScope::StoreImage,
        ..Default::default()
    };
    let preview = repair(&request).unwrap();
    assert!(preview.dry_run && preview.existed);
    assert!(image.exists());
    assert!(!home.path().join("state/log/audit.jsonl").exists());
    request.apply = true;
    let applied = repair(&request).unwrap();
    assert!(!applied.dry_run);
    assert!(!image.exists());
    assert!(builder.join("kernel").exists());
    assert!(home.path().join("keys/identity").exists());
    let audit = std::fs::read_to_string(home.path().join("state/log/audit.jsonl")).unwrap();
    assert!(audit.contains("op=builder_store_repair"), "{audit}");
    assert!(!repair(&request).unwrap().existed);
}

#[test]
fn pack_version_sweep_keeps_active_and_two_newest_and_audits_only_apply() {
    use mvm_core::pack_cache::{PackEntry, PackIndex, PackKey};
    use mvm_core::packs::{PackBackend, PackKind, Sha256Hex};
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let cache = home.path().join("cache");
    let mut index = PackIndex::default();
    let key = PackKey {
        kind: PackKind::Builder,
        arch: mvm_core::arch::GuestArch::host(),
        backend: PackBackend::Hvf,
    };
    let hashes: Vec<_> = (0u8..4).map(|i| Sha256Hex::from_bytes(&[i])).collect();
    for (i, hash) in hashes.iter().enumerate() {
        touch(&cache.join("packs").join(hash.as_str()).join("blob"));
        index.record(PackEntry {
            pack_hash: hash.clone(),
            key: key.clone(),
            channel: "stable".into(),
            release_version: format!("v{i}"),
            promoted_at_unix: i as u64,
        });
    }
    mvm_core::pack_cache::save_index(&cache, &index).unwrap();
    let before = std::fs::read(cache.join("packs/index.json")).unwrap();
    let mut version_count = 0;
    prune(&disk_request(false), |event| {
        if let CachePruneEvent::PackVersions(count) = event {
            version_count = count;
        }
    })
    .unwrap();
    assert_eq!(version_count, 1);
    assert_eq!(
        std::fs::read(cache.join("packs/index.json")).unwrap(),
        before
    );
    prune(&disk_request(true), |_| {}).unwrap();
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(cache.join("packs").join(hash.as_str()).exists(), i != 1);
    }
    let after = mvm_core::pack_cache::load_index(&cache);
    assert_eq!(after.active_for(&key), Some(&hashes[0]));
    assert_eq!(after.entries().len(), 3);
    let audit = std::fs::read_to_string(home.path().join("state/log/audit.jsonl")).unwrap();
    assert!(
        audit.contains("source=pack_version_prune count=1"),
        "{audit}"
    );
}

#[test]
fn expired_pack_sweep_preserves_fresh_pack_and_status_describes_both() {
    use mvm_core::packs::{
        PackBuilder, PackInputs, PackKind, PackMetadata, PackOutputHashes, PackProvenanceMeta,
        PackTrustMeta, PolicyCompatibility, ReproducibilityStatus, SbomReference, Sha256Hex,
        SignatureValidity,
    };
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let now = chrono::Utc::now();
    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let hash = Sha256Hex::from_bytes(b"fixture");
    let mut roots = Vec::new();
    for expired in [true, false] {
        let staged = home.path().join(if expired { "expired" } else { "fresh" });
        touch(&staged.join("kernel"));
        std::fs::write(staged.join("kernel"), if expired { b"old" } else { b"new" }).unwrap();
        let expires_at = now + chrono::Duration::days(if expired { -1 } else { 30 });
        let manifest = PackBuilder::new(
            &staged,
            PackMetadata {
                kind: PackKind::Builder,
                target_arch: mvm_core::arch::GuestArch::host(),
                backend_compatibility: vec![mvm_core::packs::PackBackend::Hvf],
                required_host_capabilities: vec![],
                policy_compatibility: PolicyCompatibility {
                    policy_hash: hash.clone(),
                    local_rebuild_required: false,
                    allowed_channels: vec!["stable".into()],
                },
                inputs: PackInputs {
                    flake_locks: vec![],
                    derivations: vec![],
                    nar_hashes: vec![],
                    oci_images: vec![],
                    setup_commands: vec![],
                    source_revisions: vec![],
                    toolchain_versions: Default::default(),
                },
                provenance: PackProvenanceMeta {
                    builder_identity: "fixture".into(),
                    build_environment_identity: "test".into(),
                    build_timestamp: now - chrono::Duration::days(3),
                    reproducibility: ReproducibilityStatus::Reproduced,
                    sbom: SbomReference {
                        uri: "https://example.test/sbom".into(),
                        sha256: hash.clone(),
                    },
                },
                trust: PackTrustMeta {
                    expires_at,
                    revocation_channel: "https://example.test/revocations.json".into(),
                    channel_identity: "stable".into(),
                    mirror_identity: None,
                    transparency_log: None,
                },
                signature: SignatureValidity {
                    signed_at: now - chrono::Duration::days(2),
                    expires_at,
                },
            },
            &key,
        )
        .files(["kernel"])
        .output_hashes(PackOutputHashes::default())
        .build()
        .unwrap();
        let root = home
            .path()
            .join("cache/packs")
            .join(manifest.outputs.pack_hash.as_str());
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::rename(staged, &root).unwrap();
        std::fs::write(
            root.join(".pack-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        roots.push(root);
    }
    let status = super::super::status().unwrap();
    assert_eq!(status.packs.len(), 2);
    assert_eq!(status.packs.iter().filter(|p| p.expired).count(), 1);
    let mut expired_count = 0;
    prune(&disk_request(false), |event| {
        if let CachePruneEvent::ExpiredPacks(count) = event {
            expired_count = count;
        }
    })
    .unwrap();
    assert_eq!(expired_count, 1);
    assert!(roots.iter().all(|root| root.exists()));
    prune(&disk_request(true), |_| {}).unwrap();
    assert!(!roots[0].exists());
    assert!(roots[1].exists());
    let audit = std::fs::read_to_string(home.path().join("state/log/audit.jsonl")).unwrap();
    assert!(audit.contains("source=pack_cache_prune count=1"), "{audit}");
}
