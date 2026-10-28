//! Contract/unit-Ed archive tests with injected descriptor authentication.
//! Not published-publisher, admission or native boot evidence.
use super::*;
use crate::image_set::{ImageSetRole, MemberBuildMode, MemberTarget};
use crate::plan::{AssetIdentity, EnvironmentRef};
use crate::registry_pack_image::BuiltImageAsset;

#[cfg(unix)]
struct ApplicationFixture {
    _directory: tempfile::TempDir,
    _environment: crate::util::test_env::TestEnv,
    candidate: crate::registry_pack::application_bundle::VerifiedApplicationBundle,
    plan: ExecutionPlan,
    config: VmStartConfig,
}

#[cfg(unix)]
fn application_fixture(
    change: impl FnOnce(&mut crate::plan::bundle::BundleManifest, &mut Vec<(String, Vec<u8>)>),
) -> Result<ApplicationFixture> {
    use crate::crypto::image_verify::VerifiedSigner;
    use crate::plan::bundle::{
        ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, BundleRegistry,
        FsTrustStore, VerityInfo, key_id_from_pubkey, sha256_hex, write_bundle,
    };
    use crate::registry_pack::{
        PackLockfile, RegistryPackPublisher, RegistryPackPublisherPolicy, RegistryPackVerification,
        VerifiedRegistryManifest, verify_registry_manifest_with,
    };
    use ed25519_dalek::SigningKey;
    let directory = tempfile::tempdir()?;
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let key = SigningKey::from_bytes(&[91; 32]);
    let key_id = key_id_from_pubkey(&key.verifying_key());
    let trust = FsTrustStore::new(directory.path().join("trust"));
    std::fs::create_dir(trust.root())?;
    std::fs::write(
        trust.root().join(format!("{}.pub", key_id.0)),
        key.verifying_key().as_bytes(),
    )?;
    let hash = "a".repeat(64);
    let assets = [
        ("rootfs.ext4", ArtifactRole::Rootfs, vec![7; 128 * 1024]),
        (
            "rootfs.verity",
            ArtifactRole::VerityHashSidecar,
            b"unit verity".to_vec(),
        ),
        ("mvm-meta.json", ArtifactRole::Other, b"{}".to_vec()),
        (
            "rootfs.roothash",
            ArtifactRole::Other,
            format!("{hash}\n").into_bytes(),
        ),
    ];
    let mut manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "byte-expectation-unit".into(),
        key_id: key_id.clone(),
        arch: GuestArch::host().to_string(),
        kernel_version: None,
        profile: None,
        workload_label: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        labels: Default::default(),
        artifacts: assets
            .iter()
            .map(|(name, role, bytes)| BundleArtifact {
                name: (*name).into(),
                role: role.clone(),
                path: format!("artifacts/{name}"),
                sha256: sha256_hex(bytes),
                size_bytes: bytes.len() as u64,
            })
            .collect(),
        members: Vec::new(),
        verity: Some(VerityInfo {
            roothash: hash.clone(),
            sidecar_artifact: "rootfs.verity".into(),
        }),
        resources: None,
    };
    let mut payload = assets
        .into_iter()
        .map(|(name, _, bytes)| (format!("artifacts/{name}"), bytes))
        .collect();
    change(&mut manifest, &mut payload);
    let archive = write_bundle(&manifest, &key, payload)?;
    let archive_path = directory.path().join("input.mvmpkg");
    std::fs::write(&archive_path, &archive)?;
    let descriptor = serde_json::to_vec(&serde_json::json!({
        "schema_version": 2, "kind": "application",
        "reference": "runtime/byte-expectations@1.0.0", "description": "Unit byte facts only",
        "application": {"schema_version": 1, "guest_arch": GuestArch::host().to_string(),
            "bundle": {"source": "https://example.test/unit.mvmpkg",
                "archive_sha256": sha256_hex(&archive), "archive_size": archive.len(), "key_id": key_id}}
    }))?;
    let pin = PackPin::new(
        "runtime/byte-expectations@1.0.0".parse()?,
        Sha256Hex::from_bytes(&descriptor),
    )?;
    let lock = PackLockfile::new(vec![pin.clone()])?;
    let policy = RegistryPackPublisherPolicy::new(vec![RegistryPackPublisher::new(
        "runtime",
        "unit issuer",
        vec!["unit identity".into()],
    )?])?;
    // This seam authenticates only the synthetic descriptor, not a real publisher.
    let verified = verify_registry_manifest_with(
        &RegistryPackVerification::new(
            pin.reference(),
            &descriptor,
            b"unit descriptor signature",
            &lock,
            &policy,
        ),
        |_, _, _| {
            Ok(VerifiedSigner {
                identity: "unit identity".into(),
                issuer: "unit issuer".into(),
            })
        },
    )?;
    let VerifiedRegistryManifest::Application(application) = verified else {
        anyhow::bail!("unit application expected");
    };
    let candidate = crate::registry_pack::application_bundle::verify_application_bundle(
        &application,
        &archive_path,
        &trust,
    )?;
    let installed = BundleRegistry::default_path()?.install_dir(&candidate.bundle().bundle_sha256);
    let mut plan = crate::plan::test_support::PlanFixture::new().build();
    plan.image.sha256 = sha256_hex(&vec![7; 128 * 1024]);
    plan.bundle = Some(candidate.bundle().plan_artifact());
    plan.asset_identities.push(AssetIdentity::new(
        AssetKind::RegistryPack,
        pin.reference().to_string(),
        pin.manifest_sha256().as_str(),
    )?);
    let config = VmStartConfig {
        rootfs_path: installed
            .join("artifacts/rootfs.ext4")
            .display()
            .to_string(),
        verity_path: Some(
            installed
                .join("artifacts/rootfs.verity")
                .display()
                .to_string(),
        ),
        roothash: Some(hash),
        ..Default::default()
    };
    Ok(ApplicationFixture {
        _directory: directory,
        _environment: environment,
        candidate,
        plan,
        config,
    })
}

#[cfg(unix)]
#[test]
fn application_expectations_bind_signed_members_original_pin_and_effective_config() {
    let f = application_fixture(|_, _| {}).unwrap();
    let facts =
        AuthenticatedBootImageExpectations::for_application(&f.candidate, &f.plan, &f.config)
            .unwrap();
    assert_eq!(facts.root_hash(), "a".repeat(64));
    assert_eq!(facts.expected_size(BootImageAsset::RootHash), 65);
    assert_eq!(
        facts.expected_sha256(BootImageAsset::RootHash),
        &Sha256Hex::from_bytes(format!("{}\n", "a".repeat(64)).as_bytes())
    );
    let exact = f.plan.asset_identities.last().unwrap().clone();
    let mut conflicting = exact.clone();
    conflicting.digest = "f".repeat(64);
    for duplicate in [exact.clone(), conflicting.clone()] {
        let mut plan = f.plan.clone();
        plan.asset_identities.push(duplicate);
        let error =
            AuthenticatedBootImageExpectations::for_application(&f.candidate, &plan, &f.config)
                .unwrap_err();
        assert!(error.to_string().contains("ambiguous"), "{error:#}");
    }
    let mut wrong = f.plan.clone();
    wrong
        .asset_identities
        .retain(|asset| !(asset.kind == AssetKind::RegistryPack && asset.name == exact.name));
    wrong.asset_identities.push(conflicting);
    assert!(
        AuthenticatedBootImageExpectations::for_application(&f.candidate, &wrong, &f.config)
            .is_err()
    );
    let mut other = f.plan.clone();
    other.asset_identities.push(
        AssetIdentity::new(
            AssetKind::RegistryPack,
            "agent/distinct-policy@1.0.0",
            "c".repeat(64),
        )
        .unwrap(),
    );
    AuthenticatedBootImageExpectations::for_application(&f.candidate, &other, &f.config).unwrap();
    for case in ["signature", "archive", "author", "rootfs", "descriptor"] {
        let mut wrong = f.plan.clone();
        match case {
            "signature" => wrong.bundle.as_mut().unwrap().manifest_sig_base64 = "changed".into(),
            "archive" => wrong.bundle.as_mut().unwrap().bundle_sha256.push('0'),
            "author" => wrong.bundle.as_mut().unwrap().key_id.0.push_str("-changed"),
            "rootfs" => wrong.image.sha256 = "0".repeat(64),
            "descriptor" => wrong.asset_identities.clear(),
            _ => unreachable!(),
        }
        assert!(
            AuthenticatedBootImageExpectations::for_application(&f.candidate, &wrong, &f.config)
                .is_err(),
            "{case}"
        );
    }
    for case in ["rootfs", "verity", "roothash"] {
        let mut config = f.config.clone();
        match case {
            "rootfs" => config.rootfs_path.push_str("-substituted"),
            "verity" => config.verity_path = None,
            "roothash" => config.roothash = Some("b".repeat(64)),
            _ => unreachable!(),
        }
        assert!(
            AuthenticatedBootImageExpectations::for_application(&f.candidate, &f.plan, &config)
                .is_err(),
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn application_expectations_refuse_missing_mismatched_and_ambiguous_members() {
    for case in [
        "missing",
        "mismatch",
        "role",
        "duplicate-role",
        "duplicate-path",
        "tamper",
    ] {
        let fixture = application_fixture(|manifest, payload| {
            let index = manifest
                .artifacts
                .iter()
                .position(|a| a.name == "rootfs.roothash")
                .unwrap();
            match case {
                "missing" => {
                    let removed = manifest.artifacts.remove(index);
                    payload.retain(|(path, _)| path != &removed.path);
                }
                "mismatch" => manifest.verity.as_mut().unwrap().roothash = "b".repeat(64),
                "role" => {
                    manifest.artifacts[index].role = crate::plan::bundle::ArtifactRole::Initrd
                }
                "duplicate-role" => {
                    let mut second = manifest.artifacts[0].clone();
                    second.name = "alternate-root".into();
                    second.path = "artifacts/alternate-root".into();
                    payload.push((second.path.clone(), vec![7; 128 * 1024]));
                    manifest.artifacts.push(second);
                }
                "duplicate-path" => {
                    let mut second = manifest.artifacts[index].clone();
                    second.name = "alias-root-hash".into();
                    manifest.artifacts.push(second);
                }
                "tamper" => {
                    let path = &manifest.artifacts[index].path;
                    payload.iter_mut().find(|(name, _)| name == path).unwrap().1[0] = b'b';
                }
                _ => unreachable!(),
            }
        });
        match fixture {
            Ok(f) => assert!(
                AuthenticatedBootImageExpectations::for_application(
                    &f.candidate,
                    &f.plan,
                    &f.config
                )
                .is_err(),
                "{case}"
            ),
            Err(error) => {
                if case == "tamper" {
                    assert!(
                        format!("{error:#}").to_lowercase().contains("mismatch"),
                        "{error:#}"
                    );
                } else {
                    assert!(
                        matches!(case, "duplicate-path" | "duplicate-role"),
                        "{case}: {error:#}"
                    );
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn application_root_hash_reader_refuses_non65_byte_declarations_before_capture() {
    for size in [0, 64, 66, 70 * 1024] {
        let f = application_fixture(|manifest, payload| {
            let member = manifest
                .artifacts
                .iter_mut()
                .find(|a| a.name == "rootfs.roothash")
                .unwrap();
            let bytes = vec![b'a'; size];
            member.size_bytes = size as u64;
            member.sha256 = crate::plan::bundle::sha256_hex(&bytes);
            payload
                .iter_mut()
                .find(|(path, _)| path == &member.path)
                .unwrap()
                .1 = bytes;
        })
        .unwrap();
        let error = f.candidate.application_root_hash_member().unwrap_err();
        assert!(error.to_string().contains("65"), "{size}: {error}");
    }
}

#[cfg(unix)]
#[test]
fn application_root_hash_reader_is_bounded_and_repeatable_across_independent_reads() {
    let f = application_fixture(|_, _| {}).unwrap();
    let expected = format!("{}\n", "a".repeat(64)).into_bytes();
    let original = f._directory.path().join("input.mvmpkg");
    let mut poisoned = std::fs::read(&original).unwrap();
    let last = poisoned.len() - 1;
    poisoned[last] ^= 1;
    std::fs::write(&original, poisoned).unwrap();
    let error = f
        .candidate
        .bundle()
        .read_small_verified_member(
            std::fs::File::open(&original).unwrap(),
            APPLICATION_ROOT_HASH_MEMBER_NAME,
            65,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("original archive pin"),
        "{error}"
    );
    assert_eq!(
        f.candidate.application_root_hash_member().unwrap(),
        expected
    );
    assert_eq!(
        f.candidate.application_root_hash_member().unwrap(),
        expected
    );
    let application = &f.candidate;
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let expected = &expected;
            scope.spawn(move || {
                for _ in 0..8 {
                    assert_eq!(
                        application.application_root_hash_member().unwrap(),
                        *expected
                    );
                }
            });
        }
    });
}

struct Fixture {
    _directory: tempfile::TempDir,
    contract: BuiltPackBootContract,
    plan: ExecutionPlan,
    config: VmStartConfig,
}

fn fixture(arch: GuestArch) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().to_owned();
    let mut image = crate::registry_pack_image::tests::descriptor();
    image.platform = match arch {
        GuestArch::Aarch64 => BuiltImagePlatform::LinuxAarch64,
        GuestArch::X86_64 => BuiltImagePlatform::LinuxX86_64,
    };
    let write = |asset: &mut BuiltImageAsset, bytes: &[u8]| {
        std::fs::write(payload.join(asset.name.as_str()), bytes).unwrap();
        asset.size = bytes.len() as u64;
        asset.sha256 = Sha256Hex::from_bytes(bytes);
    };
    write(&mut image.assets.rootfs, b"synthetic-rootfs");
    write(&mut image.assets.verity, b"synthetic-verity");
    write(
        &mut image.assets.mvm_meta,
        br#"{"overlayAware":true,"runtimeLean":true}"#,
    );
    write(
        &mut image.assets.roothash,
        format!("{}\n", "a".repeat(64)).as_bytes(),
    );
    let mut base = synthetic_base(arch);
    let role = ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant);
    let member = base
        .members
        .iter_mut()
        .find(|m| m.role == role && m.target == MemberTarget::Arch(arch) && m.build_mode.is_none())
        .unwrap();
    let kernel = &mut member.artifacts[0];
    kernel.sha256 = Sha256Hex::from_bytes(b"synthetic-kernel");
    kernel.size = b"synthetic-kernel".len() as u64;
    std::fs::write(payload.join("kernel"), b"synthetic-kernel").unwrap();
    let kernel_sha = kernel.sha256.clone();
    let pin = PackPin::new(
        "runtime/python@1.0.0".parse().unwrap(),
        Sha256Hex::from_bytes(b"synthetic-pin"),
    )
    .unwrap();
    let mut plan = crate::plan::test_support::PlanFixture::new().build();
    plan.image.sha256 = image.assets.rootfs.sha256.as_str().to_owned();
    plan.environment = Some(EnvironmentRef {
        kernel_sha256: kernel_sha.as_str().to_owned(),
    });
    plan.asset_identities.push(
        AssetIdentity::new(
            AssetKind::RegistryPack,
            pin.reference().to_string(),
            pin.manifest_sha256().as_str(),
        )
        .unwrap(),
    );
    let config = VmStartConfig {
        rootfs_path: payload.join("rootfs.ext4").display().to_string(),
        kernel_path: Some(payload.join("kernel").display().to_string()),
        verity_path: Some(payload.join("rootfs.verity").display().to_string()),
        roothash: Some("a".repeat(64)),
        ..Default::default()
    };
    Fixture {
        _directory: directory,
        contract: BuiltPackBootContract {
            pin,
            payload,
            image,
            base,
        },
        plan,
        config,
    }
}

fn synthetic_base(arch: GuestArch) -> ImageSetManifest {
    let format = match arch {
        GuestArch::X86_64 => KernelFormat::Elf,
        GuestArch::Aarch64 => KernelFormat::Image,
    };
    serde_json::from_value(serde_json::json!({
        "schema_version": 2,
        "set_version": "0.2.4",
        "issued_at": "2026-10-04T00:00:00Z",
        "producer": {
            "repository": "tinylabscom/mvm-images",
            "workflow": ".github/workflows/release.yml",
            "release_tag": "image-set/v0.2.4",
            "source_commit": "a".repeat(40)
        },
        "mvm_source_commit": "b".repeat(40),
        "compatibility": {
            "guest_agent_protocol": {"min": 2, "max": 2},
            "builder_cache_contract": 5,
            "builder_boot_abi": 1
        },
        "nix_inputs": {"flake_locks": [], "source_revisions": []},
        "revocation_channel": "https://example.test/revocations.json",
        "members": [
            {
                "role": {"workload_kernel": "default_tenant"},
                "target": {"arch": arch},
                "boot_protocol": "linux_direct",
                "artifacts": [{
                    "name": "kernel", "format": {"kernel": format},
                    "sha256": "a".repeat(64), "size": 1
                }],
                "required_capabilities": ["virtio_vsock"]
            },
            {
                "role": {"workload_rootfs": "default_tenant"},
                "target": {"arch": arch},
                "artifacts": [{
                    "name": "base.ext4", "format": "ext4",
                    "sha256": "b".repeat(64), "size": 1
                }],
                "required_capabilities": ["virtio_blk", "dm_verity"]
            }
        ]
    }))
    .unwrap()
}

impl Fixture {
    fn check(&self) -> Result<()> {
        self.contract.verify_image_config(
            &self.plan,
            &self.config,
            GuestArch::X86_64,
            BackendKind::Firecracker,
        )
    }
}

fn synthetic_expectations(f: &Fixture) -> AuthenticatedBootImageExpectations {
    f.contract
        .image_expectations(
            &f.plan,
            &f.config,
            GuestArch::X86_64,
            BackendKind::Firecracker,
        )
        .unwrap()
}

fn capture_from_fixture(
    f: &Fixture,
    reader: impl Read,
) -> Result<AuthenticatedBootImageExpectations> {
    f.contract.capture_image_expectations(
        &f.plan,
        &f.config,
        GuestArch::X86_64,
        BackendKind::Firecracker,
        reader,
    )
}

#[test]
fn synthetic_capture_reader_binds_signed_bytes_and_rejects_length_or_digest_changes() {
    let f = fixture(GuestArch::X86_64);
    let bytes = format!("{}\n", "a".repeat(64)).into_bytes();
    let captured = capture_from_fixture(&f, bytes.as_slice()).unwrap();
    assert_eq!(captured.root_hash(), "a".repeat(64));
    for role in [
        BootImageAsset::Rootfs,
        BootImageAsset::Verity,
        BootImageAsset::Metadata,
        BootImageAsset::RootHash,
    ] {
        let old = synthetic_expectations(&f);
        assert_eq!(captured.expected_size(role), old.expected_size(role));
        assert_eq!(captured.expected_sha256(role), old.expected_sha256(role));
    }
    let mut changed = bytes.clone();
    changed[0] = b'b';
    let mut extra = bytes.clone();
    extra.push(0);
    for invalid in [&[][..], &bytes[..64], changed.as_slice(), extra.as_slice()] {
        assert!(capture_from_fixture(&f, invalid).is_err());
    }
    let mut endless = std::io::repeat(b'a');
    assert!(capture_from_fixture(&f, &mut endless).is_err());
    // Bounded signed size + 1: an endless untrusted source is never drained.
    struct CountReader(usize);
    impl Read for CountReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            out.fill(b'a');
            self.0 += out.len();
            Ok(out.len())
        }
    }
    let mut reader = CountReader(0);
    assert!(capture_from_fixture(&f, &mut reader).is_err());
    assert_eq!(reader.0, bytes.len() + 1);
}

#[test]
fn synthetic_capture_reader_does_not_reopen_replaced_sidecar() {
    use std::io::{Seek, SeekFrom};
    let f = fixture(GuestArch::X86_64);
    let path = f._directory.path().join("rootfs.roothash");
    let mut held = std::fs::File::open(&path).unwrap();
    let moved = f._directory.path().join("held-original");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::write(&path, format!("{}\n", "b".repeat(64))).unwrap();
    assert_eq!(
        capture_from_fixture(&f, &mut held).unwrap().root_hash(),
        "a".repeat(64)
    );
    assert!(
        f.contract
            .image_expectations(
                &f.plan,
                &f.config,
                GuestArch::X86_64,
                BackendKind::Firecracker,
            )
            .is_err()
    );
    std::fs::write(moved, format!("{}\n", "b".repeat(64))).unwrap();
    held.seek(SeekFrom::Start(0)).unwrap();
    assert!(capture_from_fixture(&f, held).is_err());
    // Holding the original readonly descriptor is not immutable-byte custody.
}

#[test]
fn synthetic_capture_reader_preserves_original_plan_config_and_platform_checks() {
    let mut f = fixture(GuestArch::X86_64);
    let bytes = format!("{}\n", "a".repeat(64));
    f.config.roothash = Some("b".repeat(64));
    assert!(capture_from_fixture(&f, bytes.as_bytes()).is_err());
    f.config.roothash = None;
    assert!(capture_from_fixture(&f, bytes.as_bytes()).is_err());
    f.config.roothash = Some("a".repeat(64));
    f.plan.image.sha256 = "0".repeat(64);
    assert!(capture_from_fixture(&f, bytes.as_bytes()).is_err());
    f.plan.image.sha256 = f.contract.rootfs_sha256().as_str().to_owned();
    for (arch, backend) in [
        (GuestArch::Aarch64, BackendKind::Firecracker),
        (GuestArch::X86_64, BackendKind::Libkrun),
    ] {
        assert!(
            f.contract
                .capture_image_expectations(&f.plan, &f.config, arch, backend, bytes.as_bytes(),)
                .is_err()
        );
    }
}

#[test]
fn synthetic_capture_reader_requires_whole_member_origin_and_canonical_hash() {
    use std::io::{Cursor, Seek, SeekFrom};
    let mut f = fixture(GuestArch::X86_64);
    let bytes = format!("{}\n", "a".repeat(64));
    let mut reader = Cursor::new(bytes.as_bytes());
    reader.seek(SeekFrom::Start(1)).unwrap();
    assert!(capture_from_fixture(&f, &mut reader).is_err());
    assert_eq!(reader.position(), bytes.len() as u64);
    reader.seek(SeekFrom::Start(0)).unwrap();
    assert!(capture_from_fixture(&f, reader).is_ok());
    // Even a synthetic signed declaration of noncanonical bytes cannot mint.
    for invalid in [
        format!("{}\n", "A".repeat(64)),
        format!("{}\n", "g".repeat(64)),
        "a".repeat(63),
        "a".repeat(65),
    ] {
        f.contract.image.assets.roothash.size = invalid.len() as u64;
        f.contract.image.assets.roothash.sha256 = Sha256Hex::from_bytes(invalid.as_bytes());
        f.config.roothash = Some(invalid.trim().to_owned());
        assert!(capture_from_fixture(&f, invalid.as_bytes()).is_err());
    }
    f.contract.image.assets.roothash.size = 129;
    assert!(capture_from_fixture(&f, &[][..]).is_err());
}

#[test]
fn synthetic_expectations_verify_each_original_role_and_reject_mutation() {
    let f = fixture(GuestArch::X86_64);
    let expectations = synthetic_expectations(&f);
    for (role, name) in [
        (BootImageAsset::Rootfs, "rootfs.ext4"),
        (BootImageAsset::Verity, "rootfs.verity"),
        (BootImageAsset::Metadata, "mvm-meta.json"),
        (BootImageAsset::RootHash, "rootfs.roothash"),
    ] {
        let bytes = std::fs::read(f._directory.path().join(name)).unwrap();
        assert_eq!(expectations.expected_size(role), bytes.len() as u64);
        assert_eq!(
            expectations.expected_sha256(role),
            &Sha256Hex::from_bytes(&bytes)
        );
        expectations.verify_reader(role, bytes.as_slice()).unwrap();
        let mut changed = bytes;
        changed[0] ^= 1;
        assert!(
            expectations
                .verify_reader(role, changed.as_slice())
                .is_err()
        );
    }
    assert_eq!(expectations.root_hash(), "a".repeat(64));
    // The fixture directly constructs its contract: synthetic verification
    // semantics only, not genuine signed-open, admission, or native evidence.
}

#[test]
fn synthetic_readers_refuse_truncation_extra_bytes_wrong_role_and_bound_reads() {
    let f = fixture(GuestArch::X86_64);
    let expectations = synthetic_expectations(&f);
    let bytes = std::fs::read(&f.config.rootfs_path).unwrap();
    assert!(
        expectations
            .verify_reader(BootImageAsset::Rootfs, &bytes[..bytes.len() - 1])
            .is_err()
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(
        expectations
            .verify_reader(BootImageAsset::Rootfs, extra.as_slice())
            .is_err()
    );
    assert!(
        expectations
            .verify_reader(BootImageAsset::Verity, bytes.as_slice())
            .is_err()
    );
    let mut endless = std::io::repeat(0);
    assert!(
        expectations
            .verify_reader(BootImageAsset::Rootfs, &mut endless)
            .is_err()
    );
    // A malicious unending reader is bounded by original signed size + 1.
}

#[test]
fn synthetic_expectations_bind_original_plan_and_authenticated_captured_hash() {
    let mut f = fixture(GuestArch::X86_64);
    let expectations = synthetic_expectations(&f);
    std::fs::write(f._directory.path().join("rootfs.roothash"), "b".repeat(64)).unwrap();
    assert_eq!(expectations.root_hash(), "a".repeat(64));
    assert!(
        f.contract
            .image_expectations(
                &f.plan,
                &f.config,
                GuestArch::X86_64,
                BackendKind::Firecracker,
            )
            .is_err()
    );
    let hash = format!("{}\n", "a".repeat(64));
    std::fs::write(f._directory.path().join("rootfs.roothash"), hash).unwrap();
    f.config.roothash = Some("b".repeat(64));
    assert!(
        f.contract
            .image_expectations(
                &f.plan,
                &f.config,
                GuestArch::X86_64,
                BackendKind::Firecracker,
            )
            .is_err()
    );
    f.config.roothash = Some("a".repeat(64));
    f.plan.image.sha256 = "0".repeat(64);
    assert!(
        f.contract
            .image_expectations(
                &f.plan,
                &f.config,
                GuestArch::X86_64,
                BackendKind::Firecracker,
            )
            .is_err()
    );
}

#[test]
fn synthetic_held_reader_survives_path_replacement_but_not_inode_mutation() {
    use std::io::{Seek, SeekFrom};
    let f = fixture(GuestArch::X86_64);
    let expectations = synthetic_expectations(&f);
    let source = f._directory.path().join("mvm-meta.json");
    let original = source.with_extension("original");
    let mut held = std::fs::File::open(&source).unwrap();
    std::fs::rename(&source, &original).unwrap();
    std::fs::write(&source, b"replacement").unwrap();
    expectations
        .verify_reader(BootImageAsset::Metadata, &mut held)
        .unwrap();
    assert!(
        expectations
            .verify_reader(
                BootImageAsset::Metadata,
                std::fs::File::open(&source).unwrap(),
            )
            .is_err()
    );
    std::fs::write(&original, b"in-place mutation").unwrap();
    held.seek(SeekFrom::Start(0)).unwrap();
    assert!(
        expectations
            .verify_reader(BootImageAsset::Metadata, &mut held)
            .is_err()
    );
    // A held readonly original FD is not immutable-byte custody.
}

#[test]
fn both_architectures_bind_the_existing_config_to_production_members() {
    for (arch, backend) in [
        (GuestArch::X86_64, BackendKind::Firecracker),
        (GuestArch::Aarch64, BackendKind::Hvf),
    ] {
        let f = fixture(arch);
        f.contract
            .verify_image_config(&f.plan, &f.config, arch, backend)
            .unwrap();
        let resolved = f
            .contract
            .image_config(
                Path::new(f.config.kernel_path.as_deref().unwrap()),
                arch,
                backend,
            )
            .unwrap();
        assert_eq!(resolved.rootfs_path, f.config.rootfs_path);
        assert_eq!(resolved.verity_path, f.config.verity_path);
        assert_eq!(resolved.roothash, f.config.roothash);
        assert_eq!(resolved.revision_hash, f.plan.image.sha256);
    }
}

#[test]
fn caller_chosen_plan_rootfs_and_kernel_are_not_authority() {
    for field in ["rootfs", "kernel", "pin"] {
        let mut f = fixture(GuestArch::X86_64);
        match field {
            "rootfs" => f.plan.image.sha256 = "0".repeat(64),
            "kernel" => f.plan.environment.as_mut().unwrap().kernel_sha256 = "0".repeat(64),
            "pin" => f.plan.asset_identities.clear(),
            _ => unreachable!(),
        }
        assert!(f.check().is_err(), "{field}");
    }
}

#[test]
fn every_actual_file_is_hashed_again_at_use() {
    for name in [
        "kernel",
        "rootfs.ext4",
        "rootfs.verity",
        "rootfs.roothash",
        "mvm-meta.json",
    ] {
        for missing in [false, true] {
            let f = fixture(GuestArch::X86_64);
            f.check().unwrap();
            let path = f.contract.payload.join(name);
            if missing {
                std::fs::remove_file(path).unwrap();
            } else {
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[0] ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
            assert!(f.check().is_err(), "{name}, missing={missing}");
        }
    }
}

#[test]
fn substituted_paths_and_missing_verity_fields_are_refused() {
    for field in ["rootfs", "kernel", "verity", "roothash"] {
        let mut f = fixture(GuestArch::X86_64);
        let wrong = f.contract.payload.join("wrong");
        std::fs::write(&wrong, b"wrong").unwrap();
        match field {
            "rootfs" => f.config.rootfs_path = wrong.display().to_string(),
            "kernel" => f.config.kernel_path = Some(wrong.display().to_string()),
            "verity" => f.config.verity_path = None,
            "roothash" => f.config.roothash = Some("b".repeat(64)),
            _ => unreachable!(),
        }
        assert!(f.check().is_err(), "{field}");
    }
}

#[test]
fn dev_or_rootless_members_cannot_replace_the_default_tenant_kernel() {
    for profile in ["dev", "rootless", "wrong-format"] {
        let mut f = fixture(GuestArch::X86_64);
        for member in &mut f.contract.base.members {
            if member.role == ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant) {
                match profile {
                    "dev" => member.build_mode = Some(MemberBuildMode::Dev),
                    "rootless" => {
                        member.role =
                            ImageSetRole::WorkloadKernel(WorkloadImageProfile::RootlessTenant)
                    }
                    "wrong-format" => {
                        member.artifacts[0].format = ArtifactFormat::Kernel(KernelFormat::ImageGz)
                    }
                    _ => unreachable!(),
                }
            }
        }
        assert!(f.check().is_err(), "{profile}");
    }
}

#[test]
fn a_dev_member_cannot_shadow_the_production_member() {
    let mut f = fixture(GuestArch::X86_64);
    let mut dev = f.contract.base.members[0].clone();
    dev.build_mode = Some(MemberBuildMode::Dev);
    dev.artifacts[0].sha256 = Sha256Hex::from_bytes(b"wrong-dev-kernel");
    f.contract.base.members.insert(0, dev);
    f.check().unwrap();
}

#[test]
fn ambiguous_signed_kernel_formats_are_refused() {
    let mut f = fixture(GuestArch::X86_64);
    let duplicate = f.contract.base.members[0].artifacts[0].clone();
    f.contract.base.members[0].artifacts.push(duplicate);
    assert!(f.check().is_err());
}

#[test]
fn wrong_architecture_and_unsupported_backends_are_refused() {
    let f = fixture(GuestArch::X86_64);
    assert!(
        f.contract
            .kernel(GuestArch::Aarch64, BackendKind::Hvf)
            .is_err()
    );
    for backend in [
        BackendKind::Libkrun,
        BackendKind::Wasm,
        BackendKind::Mock,
        BackendKind::Hvf,
    ] {
        assert!(
            f.contract.kernel(GuestArch::X86_64, backend).is_err(),
            "{backend:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_verified_regular_boot_artifacts() {
    let f = fixture(GuestArch::X86_64);
    let path = f.contract.payload.join("kernel");
    let target = f.contract.payload.join("kernel-real");
    std::fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(target, path).unwrap();
    assert!(f.check().is_err());
}

fn refused_admission(store_root: &std::path::Path) -> String {
    let pin = PackPin::new(
        "runtime/python@1.0.0".parse().unwrap(),
        Sha256Hex::from_bytes(b"synthetic-pin"),
    )
    .unwrap();
    let error = BuiltPackBootContract::open_with_store(
        &pin,
        &HostProtocolSupport {
            base_image_contract: crate::image_set::BaseImageContractRange::SUPPORTED,
            builder_cache_contract: 5,
            builder_boot_abi: crate::image_set::BuilderBootAbiRange::WITH_PAYLOAD,
        },
        &ImageSetRevocationStore::new(store_root.to_owned()),
        Utc::now(),
    )
    .expect_err("admission without an applied image-set list must refuse");
    format!("{error:#}")
}

#[test]
fn admission_without_an_applied_image_set_list_refuses_and_names_the_fix() {
    let home = tempfile::tempdir().unwrap();
    let message = refused_admission(&home.path().join("image-set-revocations"));
    assert!(message.contains("image-set revocation list"), "{message}");
    assert!(
        message.contains("mvmctl image revocations update"),
        "{message}"
    );
}

#[test]
fn a_modified_image_set_list_is_not_read_as_empty_at_admission() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("image-set-revocations");
    let feed = crate::signed_feed_store::SignedFeedStore::new(root.clone());
    std::fs::create_dir_all(&root).unwrap();
    // An unsigned, empty-looking list and a matching-looking checkpoint where
    // a prepared list would live. Neither is authenticated.
    let empty = br#"{"schema_version":1,"issued_at":"2026-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","revocations":[]}"#;
    let state = serde_json::json!({
        "document": String::from_utf8_lossy(empty),
        "bundle": "{}",
        "checkpoint": {"publication": 1, "issued_at": "2026-01-01T00:00:00Z",
                       "sha256": Sha256Hex::from_bytes(empty).as_str()},
    });
    std::fs::write(feed.state_path(), state.to_string()).unwrap();
    std::fs::write(feed.checkpoint_path(), state["checkpoint"].to_string()).unwrap();
    let message = refused_admission(&root);
    assert!(message.contains("image-set revocation"), "{message}");
}
