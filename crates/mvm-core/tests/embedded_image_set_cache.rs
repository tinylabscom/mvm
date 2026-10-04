//! The content-addressed cache a verified bundle publishes its embedded image
//! sets into: where it lives, that an intact entry is re-verified and reused,
//! and how publishing behaves when the destination is already taken.

use std::path::{Path, PathBuf};
use std::sync::Barrier;

use chrono::{TimeZone, Utc};
use ed25519_dalek::SigningKey;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ArtifactFormat, ArtifactName, BootProtocol, GitCommit, GuestDeviceRequirement,
    IMAGE_SET_SCHEMA_VERSION, ImageSetCompatibility, ImageSetManifest, ImageSetMember,
    ImageSetProducer, ImageSetRequirement, ImageSetRole, ImageSetVersion, MemberArtifact,
    MemberTarget, NixInputs, ProtocolRange, ReleaseProducer, ReleaseTag, RepositorySlug,
    RevocationChannel, WorkflowPath,
};
use mvm_core::kernel_format::KernelFormat;
use mvm_core::packs::{FlakeLockIdentity, SbomReference, Sha256Hex, SourceRevisionIdentity};
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, BundleMember,
    BundleRegistry, FsTrustStore, VerifiedBundle, bundle_sha256, key_id_from_pubkey,
    read_and_verify_bundle, sha256_hex, write_bundle,
};

fn member_artifact(name: &str, format: ArtifactFormat) -> (MemberArtifact, Vec<u8>) {
    let bytes = format!("embedded bytes for {name}").into_bytes();
    (
        MemberArtifact {
            name: ArtifactName::new(name).expect("artifact name"),
            format,
            sha256: Sha256Hex::from_bytes(&bytes),
            size: bytes.len() as u64,
        },
        bytes,
    )
}

/// One member of the current train, with artifacts of the shape its role
/// requires and the bytes they hash to.
fn member(role: ImageSetRole, target: MemberTarget) -> (ImageSetMember, Vec<(String, Vec<u8>)>) {
    use GuestDeviceRequirement::{DmVerity, VirtioBlk, VirtioVsock};
    let suffix = match target {
        MemberTarget::Arch(arch) => format!("-{arch}"),
        MemberTarget::ArchIndependent => String::new(),
    };
    let kernel = match target {
        MemberTarget::Arch(GuestArch::X86_64) => ArtifactFormat::Kernel(KernelFormat::Elf),
        _ => ArtifactFormat::Kernel(KernelFormat::Image),
    };
    let archive = |stem: &str| (format!("{stem}.tar.gz"), ArtifactFormat::TarGz);
    let (specs, boot_protocol, required_capabilities) = match role {
        ImageSetRole::BuilderVm => (
            vec![
                (format!("builder-vmlinux{suffix}"), kernel),
                (format!("builder-rootfs{suffix}.ext4"), ArtifactFormat::Ext4),
            ],
            Some(BootProtocol::LinuxDirect),
            vec![VirtioVsock, VirtioBlk],
        ),
        ImageSetRole::WorkloadKernel(profile) => (
            vec![(format!("{profile}-vmlinux{suffix}"), kernel)],
            Some(BootProtocol::LinuxDirect),
            vec![VirtioVsock],
        ),
        ImageSetRole::WorkloadRootfs(profile) => (
            vec![
                (
                    format!("{profile}-rootfs{suffix}.ext4"),
                    ArtifactFormat::Ext4,
                ),
                (
                    format!("{profile}-rootfs{suffix}.verity"),
                    ArtifactFormat::VerityHashTree,
                ),
                (
                    format!("{profile}-rootfs{suffix}.roothash"),
                    ArtifactFormat::VerityRootHash,
                ),
            ],
            None,
            vec![VirtioBlk, DmVerity],
        ),
        ImageSetRole::RuntimeOverlay => (
            vec![archive(&format!("runtime-overlay{suffix}"))],
            None,
            vec![],
        ),
        ImageSetRole::SdkSidecar(libc) => (
            vec![archive(&format!("sdk-sidecar{suffix}-{libc}"))],
            None,
            vec![],
        ),
        ImageSetRole::Stage0BootstrapKernel => (
            vec![(format!("stage0-vmlinux{suffix}"), kernel)],
            Some(BootProtocol::LinuxDirect),
            vec![VirtioVsock],
        ),
        ImageSetRole::Initramfs => (vec![archive(&format!("initramfs{suffix}"))], None, vec![]),
        ImageSetRole::QemuWasmSmokePack => (vec![archive("qemu-wasm-smoke")], None, vec![]),
    };
    let (artifacts, bytes): (Vec<_>, Vec<_>) = specs
        .into_iter()
        .map(|(name, format)| {
            let (artifact, bytes) = member_artifact(&name, format);
            (artifact, (name, bytes))
        })
        .unzip();
    (
        ImageSetMember {
            role,
            target,
            build_mode: None,
            source_fingerprint: None,
            boot_protocol,
            artifacts,
            required_capabilities,
            pack_hash: Some(Sha256Hex::from_bytes(
                format!("pack:{role}:{target}").as_bytes(),
            )),
            sbom: Some(SbomReference {
                uri: format!("https://example.test/{role}/{target}.cdx.json"),
                sha256: Sha256Hex::from_bytes(format!("sbom:{role}:{target}").as_bytes()),
            }),
        },
        bytes,
    )
}

/// A release image set carrying every member the current train requires —
/// anything less is refused before it reaches the cache.
fn complete_image_set() -> (ImageSetManifest, Vec<(String, Vec<u8>)>) {
    let (members, bytes): (Vec<_>, Vec<_>) = ImageSetRequirement::current_train()
        .members()
        .iter()
        .map(|required| member(required.role, required.target))
        .unzip();
    let manifest = ImageSetManifest {
        schema_version: IMAGE_SET_SCHEMA_VERSION,
        set_version: ImageSetVersion::new("1.0.0").expect("version"),
        issued_at: Utc
            .with_ymd_and_hms(2026, 9, 23, 0, 0, 0)
            .single()
            .expect("timestamp"),
        producer: ImageSetProducer::Release(ReleaseProducer {
            repository: RepositorySlug::new("tinylabscom/mvm-images").expect("repo"),
            workflow: WorkflowPath::new(".github/workflows/release.yml").expect("workflow"),
            release_tag: ReleaseTag::new("v1.0.0").expect("tag"),
            source_commit: GitCommit::new("a".repeat(40)).expect("commit"),
        }),
        mvm_source_commit: GitCommit::new("b".repeat(40)).expect("commit"),
        compatibility: ImageSetCompatibility {
            guest_agent_protocol: ProtocolRange::new(2, 2).expect("protocol"),
            builder_cache_contract: 4,
            builder_boot_abi: None,
        },
        nix_inputs: NixInputs {
            flake_locks: vec![FlakeLockIdentity {
                reference: "nix/images".to_string(),
                lock_hash: Sha256Hex::from_bytes(b"lock"),
            }],
            source_revisions: vec![SourceRevisionIdentity {
                repository: "https://github.com/NixOS/nixpkgs".to_string(),
                revision: "c".repeat(40),
                tree_hash: Sha256Hex::from_bytes(b"tree"),
            }],
        },
        revocation_channel: Some(
            RevocationChannel::new("https://example.test/revocations.json")
                .expect("revocation channel"),
        ),
        supersedes: None,
        members,
    };
    (manifest, bytes.into_iter().flatten().collect())
}

fn bundle_artifact(name: &str, path: &str, bytes: &[u8]) -> BundleArtifact {
    BundleArtifact {
        name: name.to_string(),
        role: ArtifactRole::Other,
        path: path.to_string(),
        sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
    }
}

/// A signed bundle whose only content is one embedded image set.
fn embedded_bundle(sk: &SigningKey) -> Vec<u8> {
    let (image_set, image_bytes) = complete_image_set();
    let image_manifest = serde_json::to_vec(&image_set).expect("image-set JSON");
    let mut artifacts = vec![bundle_artifact(
        "image-set.json",
        "artifacts/image-set.json",
        &image_manifest,
    )];
    let mut payload = vec![("artifacts/image-set.json".to_string(), image_manifest)];
    for (name, bytes) in image_bytes {
        let path = format!("artifacts/{name}");
        artifacts.push(bundle_artifact(&name, &path, &bytes));
        payload.push((path, bytes));
    }
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "test-publisher".to_string(),
        key_id: key_id_from_pubkey(&sk.verifying_key()),
        arch: GuestArch::host().to_string(),
        kernel_version: None,
        profile: None,
        workload_label: None,
        created_at: "2026-09-23T00:00:00Z".to_string(),
        labels: Default::default(),
        artifacts,
        members: vec![BundleMember::EmbeddedImageSet {
            manifest_artifact: "image-set.json".to_string(),
        }],
        verity: None,
        resources: None,
    };
    write_bundle(&manifest, sk, payload).expect("embedded bundle")
}

/// A registry rooted at `<root>/bundles` and a verified embedded bundle.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    registry: BundleRegistry,
    verified: VerifiedBundle,
    sha: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let sk = SigningKey::from_bytes(&[42; 32]);
        let trust_dir = root.join("trusted-publishers");
        std::fs::create_dir_all(&trust_dir).expect("trust dir");
        std::fs::write(
            trust_dir.join(format!("{}.pub", key_id_from_pubkey(&sk.verifying_key()).0)),
            sk.verifying_key().to_bytes(),
        )
        .expect("enrol publisher");
        let archive = embedded_bundle(&sk);
        let verified =
            read_and_verify_bundle(&archive, &FsTrustStore::new(&trust_dir)).expect("verify");
        assert_eq!(verified.embedded_image_sets.len(), 1);
        Self {
            registry: BundleRegistry::new(root.join("bundles")),
            sha: bundle_sha256(&archive),
            verified,
            root,
            _dir: dir,
        }
    }

    fn cache(&self) -> Result<(), String> {
        self.registry
            .cache_embedded_image_sets(&self.verified, &self.sha)
            .map_err(|error| error.to_string())
    }

    /// Where the one embedded set is published.
    fn destination(&self) -> PathBuf {
        self.registry.embedded_image_set_cache_root().join(
            self.verified.embedded_image_sets[0]
                .manifest_sha256
                .as_str(),
        )
    }
}

fn assert_published(destination: &Path, verified: &VerifiedBundle) {
    let embedded = &verified.embedded_image_sets[0];
    let manifest = std::fs::read(destination.join("image-set.json")).expect("cached manifest");
    assert_eq!(
        Sha256Hex::from_bytes(&manifest),
        embedded.manifest_sha256,
        "the cached manifest is the verified one"
    );
    for (name, bundle_path) in &embedded.artifact_paths {
        let cached = std::fs::read(destination.join("artifacts").join(name)).expect("artifact");
        assert_eq!(&cached, &verified.artifacts[bundle_path], "{name}");
    }
}

/// The image-set cache is a sibling of the bundle registry, so a registry at
/// `~/.mvm/bundles` publishes into `~/.mvm/image-sets` — the directory the
/// boot path reads sets from — and never into the process's working
/// directory.
#[test]
fn embedded_image_sets_are_cached_beside_the_bundle_registry() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.registry.embedded_image_set_cache_root(),
        fixture.root.join("image-sets")
    );

    fixture.cache().expect("publish");
    assert_published(&fixture.destination(), &fixture.verified);
    assert!(
        fixture
            .destination()
            .starts_with(fixture.root.join("image-sets"))
    );
}

/// A second publish of the same set finds it already cached, re-verifies it
/// byte for byte, and succeeds without rewriting it. Refusing an intact entry
/// would make every repeat `bundle fetch` fail.
#[test]
fn an_intact_cached_image_set_is_reverified_and_reused() {
    let fixture = Fixture::new();
    fixture.cache().expect("first publish");
    fixture.cache().expect("an intact cached set is accepted");
    assert_published(&fixture.destination(), &fixture.verified);
}

/// A destination occupied by something that is not a published set — here a
/// dangling symlink, which reads as absent but cannot be renamed over — is a
/// publish failure, reported as one, not misread as a cached set.
#[cfg(unix)]
#[test]
fn a_destination_that_cannot_be_published_over_is_refused() {
    let fixture = Fixture::new();
    let destination = fixture.destination();
    std::fs::create_dir_all(destination.parent().expect("cache root")).expect("cache root");
    std::os::unix::fs::symlink(fixture.root.join("nowhere"), &destination)
        .expect("dangling symlink");

    let error = fixture
        .cache()
        .expect_err("the occupied destination refuses");
    assert!(
        error.contains("publishing embedded image-set cache"),
        "unexpected error: {error}"
    );
}

/// Publishers racing on one set — two `bundle fetch`es of the same bundle —
/// all succeed: whichever rename loses finds the winner's entry, re-verifies
/// it, and accepts it. Several rounds of released-together threads make it
/// overwhelmingly likely at least one publisher loses the rename.
#[test]
fn concurrent_publishers_of_one_image_set_all_succeed() {
    const PUBLISHERS: usize = 8;
    const ROUNDS: usize = 8;
    for _ in 0..ROUNDS {
        let fixture = Fixture::new();
        let start = Barrier::new(PUBLISHERS);
        let outcomes: Vec<Result<(), String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..PUBLISHERS)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        fixture.cache()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("publisher thread"))
                .collect()
        });
        for outcome in outcomes {
            outcome.expect("a racing publisher accepts the winner's entry");
        }
        assert_published(&fixture.destination(), &fixture.verified);
    }
}
