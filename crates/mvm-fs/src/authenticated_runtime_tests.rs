//! Synthetic archives test assembly only; the vendored signed root tests
//! publisher authentication separately. Neither is a released/native boot.

use super::*;
use mvm_core::image_set::published_root_fixture as published_root;
use mvm_core::packs::RevocationStatus;
use mvm_core::plan::bundle::KeyId;
use std::io::Write;

struct Revocations(bool);
impl PackRevocationChecker for Revocations {
    fn status(&self, _: &KeyId, _: &Sha256Hex) -> RevocationStatus {
        if self.0 {
            RevocationStatus::Good
        } else {
            RevocationStatus::Revoked {
                reason: "test refusal".into(),
            }
        }
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn archive(mut files: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let checksums: String = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", Sha256Hex::from_bytes(bytes).as_str()))
        .collect();
    files.push(("checksums-sha256.txt", checksums.into_bytes()));
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    gzip(&tar.into_inner().unwrap())
}

fn synthetic_overlay() -> Vec<u8> {
    use crate::ext4::{Node, Owner};
    let nodes = crate::overlay::REQUIRED_OVERLAY_GUEST_PATHS
        .iter()
        .map(|path| Node::File {
            path: (*path).into(),
            mode: 0o555,
            data: b"synthetic".to_vec(),
            owner: Owner::ROOT,
            xattrs: Vec::new(),
        })
        .collect();
    let image = crate::ext4::build_image(nodes, &Default::default()).unwrap();
    archive(vec![
        ("overlay.ext4", image),
        ("overlay.verity", b"synthetic tree".to_vec()),
        (
            "overlay.roothash",
            format!("{}\n", "1".repeat(64)).into_bytes(),
        ),
        ("VERSION", b"synthetic-1".to_vec()),
        ("mvm-guest-agent", b"synthetic".to_vec()),
        ("mvm-guest-netinit", b"synthetic".to_vec()),
        ("mvm-egress-client", b"synthetic".to_vec()),
        ("mvm-oci-entrypoint", b"synthetic".to_vec()),
    ])
}

fn synthetic_initramfs() -> Vec<u8> {
    let payload = b"synthetic cpio";
    let image = gzip(payload);
    archive(vec![
        ("initramfs.size", image.len().to_string().into_bytes()),
        ("initramfs.cpio.gz", image),
        (
            "initramfs.hash",
            Sha256Hex::from_bytes(payload).as_str().as_bytes().to_vec(),
        ),
        ("VERSION", b"synthetic-1".to_vec()),
    ])
}

fn synthetic_sidecar() -> Vec<u8> {
    use crate::ext4::{Node, Owner};
    let nodes = vec![
        Node::Dir {
            path: "/lib".into(),
            mode: 0o555,
            owner: Owner::ROOT,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/lib/libmvm_host_services.so".into(),
            mode: 0o555,
            data: crate::elf::test_fixture::shared_object(&["libc.so.6"]),
            owner: Owner::ROOT,
            xattrs: Vec::new(),
        },
    ];
    archive(vec![
        (
            "sdk.ext4",
            crate::ext4::build_image(nodes, &Default::default()).unwrap(),
        ),
        ("VERSION", b"synthetic-1".to_vec()),
    ])
}

fn host() -> HostProtocolSupport {
    HostProtocolSupport {
        guest_agent_protocol: mvm_core::image_set::ProtocolRange::new(2, 2).unwrap(),
        builder_cache_contract: 5,
        builder_boot_abi: mvm_core::image_set::BuilderBootAbiRange::WITH_PAYLOAD,
    }
}

fn synthetic_manifest(cache: &Path) -> ImageSetManifest {
    let mut manifest: ImageSetManifest = serde_json::from_slice(published_root::MANIFEST).unwrap();
    for (role, bytes) in [
        (ImageSetRole::RuntimeOverlay, synthetic_overlay()),
        (ImageSetRole::Initramfs, synthetic_initramfs()),
        (
            ImageSetRole::SdkSidecar(GuestLibc::Glibc),
            synthetic_sidecar(),
        ),
    ] {
        let member = manifest
            .members
            .iter_mut()
            .find(|member| {
                member.role == role && member.target == MemberTarget::Arch(GuestArch::Aarch64)
            })
            .unwrap();
        let artifact = &mut member.artifacts[0];
        artifact.size = bytes.len() as u64;
        artifact.sha256 = Sha256Hex::from_bytes(&bytes);
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), bytes).unwrap();
        crate::runtime_archive_cache::retain_runtime_archive(cache, source.path(), artifact)
            .unwrap();
    }
    manifest
}

#[test]
fn synthetic_materialization_binds_exact_final_files_not_writable_checksums() {
    let cache = tempfile::tempdir().unwrap();
    let manifest = synthetic_manifest(cache.path());
    let lock = &mvm_core::image_set::image_train_lock().image_set;
    let host = host();
    let request =
        RuntimeAttachmentRequest::new(lock, &host, &Revocations(true), GuestArch::Aarch64)
            .with_caches(cache.path().join("no-proof"), cache.path().to_owned())
            .with_sidecar(GuestLibc::Glibc);
    // The production entry point cannot turn synthetic declarations into proof.
    assert!(AuthenticatedRuntimeAttachments::open(&request).is_err());
    let root = Sha256Hex::from_bytes(b"synthetic root, not publisher proof");
    let files = AuthenticatedRuntimeAttachments::materialize(&manifest, &root, &request).unwrap();
    let mut config = VmStartConfig::default();
    files.attach(&mut config).unwrap();
    files
        .verify_config(&config, &root, GuestArch::Aarch64)
        .unwrap();
    assert!(
        files
            .verify_config(
                &config,
                &Sha256Hex::from_bytes(b"wrong"),
                GuestArch::Aarch64
            )
            .is_err()
    );
    assert!(
        files
            .verify_config(&config, &root, GuestArch::X86_64)
            .is_err()
    );
    for changed in [
        VmStartConfig {
            initrd_path: None,
            ..config.clone()
        },
        VmStartConfig {
            runtime_overlay_verity_path: None,
            ..config.clone()
        },
        VmStartConfig {
            runtime_overlay_roothash: Some("2".repeat(64)),
            ..config.clone()
        },
        VmStartConfig {
            runtime_overlay_version: Some("substituted".into()),
            ..config.clone()
        },
        VmStartConfig {
            volumes: Vec::new(),
            ..config.clone()
        },
    ] {
        assert!(
            files
                .verify_config(&changed, &root, GuestArch::Aarch64)
                .is_err()
        );
    }
    let mut changed = config.clone();
    changed.volumes.push(changed.volumes[0].clone());
    assert!(
        files
            .verify_config(&changed, &root, GuestArch::Aarch64)
            .is_err()
    );
    for file in [
        &files.verity,
        &files.initramfs,
        files.sidecar.as_ref().unwrap(),
    ] {
        let original = std::fs::read(&file.path).unwrap();
        std::fs::write(&file.path, b"substituted").unwrap();
        assert!(
            files
                .verify_config(&config, &root, GuestArch::Aarch64)
                .is_err()
        );
        std::fs::write(&file.path, original).unwrap();
    }
    let substitute = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(&files.overlay.path, substitute.path()).unwrap();
    let changed = VmStartConfig {
        runtime_overlay_path: Some(substitute.path().to_str().unwrap().into()),
        ..config.clone()
    };
    assert!(
        files
            .verify_config(&changed, &root, GuestArch::Aarch64)
            .is_err(),
        "even identical bytes at a caller-selected path are not the owned attachment"
    );
    // Replacing BOTH the extracted file and its adjacent integrity record
    // cannot change the identities sealed from the authenticated source.
    std::fs::write(&files.overlay.path, b"substituted").unwrap();
    std::fs::write(
        files.sources[0].stage.path().join("checksums-sha256.txt"),
        format!(
            "{}  overlay.ext4\n",
            Sha256Hex::from_bytes(b"substituted").as_str()
        ),
    )
    .unwrap();
    assert!(
        files
            .verify_config(&config, &root, GuestArch::Aarch64)
            .is_err()
    );
    // Reconstruction ignores that mutable extraction entirely.
    let fresh = AuthenticatedRuntimeAttachments::materialize(&manifest, &root, &request).unwrap();
    assert_ne!(fresh.overlay.path, files.overlay.path);
    let path = fresh.overlay.path.clone();
    drop(fresh);
    assert!(!path.exists(), "owner controls staging lifetime");
}

#[test]
fn synthetic_selection_and_archive_substitution_refuse() {
    let cache = tempfile::tempdir().unwrap();
    let mut manifest = synthetic_manifest(cache.path());
    let role = ImageSetRole::RuntimeOverlay;
    let arch = GuestArch::Aarch64;
    let artifact = select_archive(&manifest, role, arch).unwrap().clone();
    let path = cache.path().join(artifact.sha256.as_str());
    std::fs::write(&path, vec![0u8; artifact.size as usize]).unwrap();
    assert!(snapshot(cache.path(), &artifact).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(snapshot(cache.path(), &artifact).is_err());
    let member = manifest
        .members
        .iter_mut()
        .find(|m| m.role == role && m.target == MemberTarget::Arch(arch))
        .unwrap();
    member.artifacts[0].format = ArtifactFormat::Ext4;
    assert!(select_archive(&manifest, role, arch).is_err());
    manifest
        .members
        .retain(|m| !(m.role == role && m.target == MemberTarget::Arch(arch)));
    assert!(select_archive(&manifest, role, arch).is_err());
}

#[test]
fn real_signed_root_is_not_itself_attachment_authority() {
    use mvm_core::image_set::*;
    let tag = ReleaseTag::new("image-set/v0.2.4").unwrap();
    let lock = ImageLock {
        schema_version: IMAGE_LOCK_SCHEMA_VERSION,
        repository: RepositorySlug::new("tinylabscom/mvm-images").unwrap(),
        release_tag: tag.clone(),
        manifest_asset: ArtifactName::new("image-set.json").unwrap(),
        manifest_sha256: Sha256Hex::from_bytes(published_root::MANIFEST),
        signing_identity: SigningIdentity {
            workflow: WorkflowPath::new(".github/workflows/release.yml").unwrap(),
            tag_ref: TagRef::for_tag(&tag),
        },
    };
    let host = host();
    let cache = tempfile::tempdir().unwrap();
    // Store the exact real public fixture. Production re-verifies its signature.
    std::fs::write(
        cache
            .path()
            .join(format!("{}.json", lock.manifest_sha256.as_str())),
        serde_json::to_vec(&serde_json::json!({
            "manifest": std::str::from_utf8(published_root::MANIFEST).unwrap(),
            "signature_bundle": std::str::from_utf8(published_root::BUNDLE).unwrap(),
        }))
        .unwrap(),
    )
    .unwrap();
    let request =
        RuntimeAttachmentRequest::new(&lock, &host, &Revocations(true), GuestArch::Aarch64)
            .with_caches(cache.path().to_owned(), cache.path().join("no-archives"));
    let error = AuthenticatedRuntimeAttachments::open(&request).unwrap_err();
    if cfg!(feature = "manifest-verify") {
        assert!(
            matches!(error, AuthenticatedRuntimeError::Archive(_)),
            "{error}"
        );
    } else {
        // Dependencies may enable the core verifier through feature unification.
        // Without it, this must refuse at the proof rather than trust a hash.
        assert!(matches!(
            error,
            AuthenticatedRuntimeError::Archive(_) | AuthenticatedRuntimeError::Proof(_)
        ));
    }
    let refused =
        RuntimeAttachmentRequest::new(&lock, &host, &Revocations(false), GuestArch::Aarch64)
            .with_caches(cache.path().to_owned(), cache.path().join("no-archives"));
    assert!(matches!(
        AuthenticatedRuntimeAttachments::open(&refused),
        Err(AuthenticatedRuntimeError::Proof(_))
    ));
}
