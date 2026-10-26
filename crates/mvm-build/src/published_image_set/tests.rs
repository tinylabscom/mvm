#![cfg(test)]

use super::fixture::ImageSetFixture;
use super::*;
use mvm_core::util::test_env::TestEnv;

const ARCH: GuestArch = GuestArch::Aarch64;
const MEMBER: &str = "stage0-vmlinux-aarch64";

#[test]
fn workload_acquisition_does_not_require_or_authorize_builder_support() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let mut source = with_member(b"stage0").serve_from(served.path());
    let path = served.path().join("image-set.json");
    let mut manifest: ImageSetManifest =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest.compatibility.builder_cache_contract += 1;
    source.train.compatibility = manifest.compatibility.clone();
    let bytes = serde_json::to_vec(&manifest).unwrap();
    source.train.image_set.manifest_sha256 = Sha256Hex::from_bytes(&bytes);
    std::fs::write(&path, bytes).unwrap();
    let full_source = ImageSetSource::new(source.train.clone(), source.base_url.clone())
        .with_download(source.download);
    assert!(PublishedImageSet::acquire_from(full_source).is_err());
    let set = PublishedImageSet::acquire_workload_from(source).unwrap();
    let destination = served.path().join("stage0");
    set.fetch_member_artifact(
        ImageSetRole::Stage0BootstrapKernel,
        ARCH,
        MEMBER,
        &destination,
    )
    .unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), b"stage0");
    let builder = set
        .manifest()
        .members
        .iter()
        .find(|member| member.role == ImageSetRole::BuilderVm)
        .unwrap();
    let artifact = &builder.artifacts[0];
    assert!(
        set.artifact(builder.role, builder.target, artifact.name.as_str())
            .is_err()
    );
    assert!(
        set.fetch_artifact(artifact, &served.path().join("builder"))
            .is_err()
    );
}

#[test]
fn workload_acquisition_preserves_pin_completeness_and_base_contract_checks() {
    let _env = unsigned_env();
    for failure in ["pin", "complete", "base"] {
        let served = tempfile::tempdir().unwrap();
        let fixture = match failure {
            "complete" => ImageSetFixture::complete().without_member(
                ImageSetRole::WorkloadRootfs(WorkloadImageProfile::RootlessTenant),
                MemberTarget::Arch(ARCH),
            ),
            "base" => ImageSetFixture::complete()
                .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::new(99))),
            _ => ImageSetFixture::complete(),
        };
        let source = fixture.serve_from(served.path());
        if failure == "pin" {
            let path = served.path().join("image-set.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
        }
        assert!(
            PublishedImageSet::acquire_workload_from(source).is_err(),
            "{failure}"
        );
    }
}

#[test]
fn workload_acquisition_preserves_member_digest_checks() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let source = with_member(b"stage0").serve_from(served.path());
    std::fs::write(served.path().join(MEMBER), b"tamper").unwrap();
    let set = PublishedImageSet::acquire_workload_from(source).unwrap();
    assert!(matches!(
        set.fetch_member_artifact(
            ImageSetRole::Stage0BootstrapKernel,
            ARCH,
            MEMBER,
            &served.path().join("download"),
        ),
        Err(ImageSetMemberError::DigestMismatch { .. })
    ));
}

#[test]
fn portable_publisher_proof_requires_current_feed_even_for_fixture_acquisition() {
    let mut env = unsigned_env();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let served = tempfile::tempdir().unwrap();
    for acquire in [
        PublishedImageSet::acquire_from,
        PublishedImageSet::acquire_workload_from,
    ] {
        let fixture = ImageSetFixture::complete();
        let set = acquire(fixture.serve_from(served.path())).unwrap();
        let error = set.retained_publisher_proof().unwrap_err();
        assert!(format!("{error:#}").contains("current signed image-set revocations required"));
    }
    assert!(!mvm_core::image_set::image_set_root_proof_cache().exists());
}

#[test]
fn cached_compatibility_binding_accepts_matching_authenticated_contract_shape() {
    let expected = ImageSetFixture::complete()
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER))
        .into_manifest()
        .compatibility;
    let actual = expected.clone();

    verify_cached_compatibility_binding(&expected, &actual).unwrap();
}

#[test]
fn cached_compatibility_binding_rejects_mismatching_base_contract() {
    let expected = ImageSetFixture::complete()
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER))
        .into_manifest()
        .compatibility;
    let mut actual = expected.clone();
    actual.base_image_contract = None;

    let error = verify_cached_compatibility_binding(&expected, &actual).unwrap_err();
    assert_eq!(
        error.to_string(),
        "cached authenticated image-set compatibility does not match images.lock"
    );
}

#[test]
fn cached_compatibility_binding_rejects_mismatching_builder_boot_abi() {
    let expected = ImageSetFixture::complete()
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER))
        .into_manifest()
        .compatibility;
    let mut actual = expected.clone();
    actual.builder_boot_abi = None;

    let error = verify_cached_compatibility_binding(&expected, &actual).unwrap_err();
    assert_eq!(
        error.to_string(),
        "cached authenticated image-set compatibility does not match images.lock"
    );
}

fn contract_root(marker: Option<&[u8]>, symlink: Option<&str>) -> Vec<u8> {
    contract_root_with_mode(marker, symlink, 0o444)
}

fn contract_root_with_mode(marker: Option<&[u8]>, symlink: Option<&str>, mode: u16) -> Vec<u8> {
    use mvm_fs::ext4::{Node, Owner};
    let mut nodes = ["/etc", "/etc/mvm"]
        .into_iter()
        .map(|path| Node::Dir {
            path: path.into(),
            mode: 0o755,
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        })
        .collect::<Vec<_>>();
    if let Some(bytes) = marker {
        nodes.push(Node::File {
            path: "/etc/mvm/base-image-contract".into(),
            mode,
            data: bytes.to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        });
    }
    if let Some(path) = symlink {
        nodes.retain(|node| node.path() != path && !node.path().starts_with(&format!("{path}/")));
        nodes.push(Node::Symlink {
            path: path.into(),
            target: "/somewhere".into(),
            owner: Owner::ROOT,
        });
    }
    mvm_fs::ext4::build_image(nodes, &Default::default()).unwrap()
}

#[test]
fn new_base_markers_are_checked_after_authentication_for_each_profile_and_arch() {
    let _env = unsigned_env();
    for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
        for profile in [
            WorkloadImageProfile::DefaultTenant,
            WorkloadImageProfile::RootlessTenant,
        ] {
            for marker in [
                Some(b"1\n".as_slice()),
                None,
                Some(b"2\n".as_slice()),
                Some(b"1".as_slice()),
                Some(b"01\n".as_slice()),
                Some(b"1\njunk".as_slice()),
            ] {
                let served = tempfile::tempdir().unwrap();
                let root = contract_root(marker, None);
                let fixture = ImageSetFixture::complete()
                    .with_base_image_contract(Some(
                        mvm_core::image_set::BaseImageContract::LINUX_LAYER,
                    ))
                    .publish(
                        ImageSetRole::WorkloadRootfs(profile),
                        MemberTarget::Arch(arch),
                        "contract-root.ext4",
                        root,
                    );
                for acquire in [
                    PublishedImageSet::acquire_from,
                    PublishedImageSet::acquire_workload_from,
                ] {
                    let set = acquire(fixture.serve_from(served.path())).unwrap();
                    let out = tempfile::tempdir().unwrap();
                    let destination = out.path().join("root.ext4");
                    let result = set.fetch_member_artifact(
                        ImageSetRole::WorkloadRootfs(profile),
                        arch,
                        "contract-root.ext4",
                        &destination,
                    );
                    if marker == Some(b"1\n".as_slice()) {
                        result.unwrap();
                        assert!(destination.exists());
                    } else {
                        assert!(matches!(
                            result,
                            Err(ImageSetMemberError::BaseImageContract { .. })
                        ));
                        assert!(!destination.exists());
                    }
                }
            }
        }
    }
}

#[test]
fn installed_cache_hits_recheck_declaration_marker_and_bytes_for_prod_and_dev() {
    let _env = unsigned_env();
    for build_mode in [None, Some(MemberBuildMode::Dev)] {
        for marker in [Some(b"1\n".as_slice()), None, Some(b"2\n".as_slice())] {
            let served = tempfile::tempdir().unwrap();
            let root = contract_root(marker, None);
            let profile = WorkloadImageProfile::DefaultTenant;
            let target = MemberTarget::Arch(ARCH);
            let fixture = ImageSetFixture::complete().with_base_image_contract(Some(
                mvm_core::image_set::BaseImageContract::LINUX_LAYER,
            ));
            let fixture = if build_mode.is_some() {
                fixture
                    .publish_dev(
                        ImageSetRole::WorkloadKernel(profile),
                        target,
                        "dev-vmlinux",
                        b"kernel".to_vec(),
                    )
                    .publish_dev(
                        ImageSetRole::WorkloadRootfs(profile),
                        target,
                        "dev-root.ext4",
                        root.clone(),
                    )
            } else {
                fixture
                    .publish(
                        ImageSetRole::WorkloadKernel(profile),
                        target,
                        "prod-vmlinux",
                        b"kernel".to_vec(),
                    )
                    .publish(
                        ImageSetRole::WorkloadRootfs(profile),
                        target,
                        "prod-root.ext4",
                        root.clone(),
                    )
            };
            let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
            let out = tempfile::tempdir().unwrap();
            std::fs::write(out.path().join("vmlinux"), b"kernel").unwrap();
            let path = out.path().join("rootfs.ext4");
            std::fs::write(&path, &root).unwrap();
            let verify = || {
                verify_installed_workload_files(
                    set.manifest(),
                    out.path(),
                    ARCH,
                    profile,
                    build_mode,
                )
            };
            if marker != Some(b"1\n".as_slice()) {
                assert!(
                    verify().is_err(),
                    "an existing cache cannot waive the marker"
                );
                continue;
            }
            let started = std::time::Instant::now();
            verify().unwrap();
            eprintln!(
                "warm contract verification of {} bytes: {:?}",
                root.len(),
                started.elapsed()
            );
            assert!(
                verify_installed_workload_files(
                    set.manifest(),
                    out.path(),
                    GuestArch::X86_64,
                    profile,
                    build_mode
                )
                .is_err()
            );
            let mut tampered = root.clone();
            *tampered.last_mut().unwrap() ^= 1;
            std::fs::write(&path, tampered).unwrap();
            // Even a perfectly forged size/mtime sidecar must not authorize
            // a cached root whose bytes differ from the signed declaration.
            mvm_core::crypto::image_verify::sha256_file_cached(&path).unwrap();
            let metadata = std::fs::metadata(&path).unwrap();
            let mtime = metadata
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::fs::write(
                mvm_core::crypto::image_verify::sha256_cache_path(&path),
                format!(
                    "{} {} {}\n",
                    mvm_core::packs::Sha256Hex::from_bytes(&root).as_str(),
                    metadata.len(),
                    mtime
                ),
            )
            .unwrap();
            assert!(verify().is_err(), "mutable digest cache is not proof");
            std::fs::remove_file(&path).unwrap();
            assert!(verify().is_err());
        }
    }
}

#[test]
fn renamed_ext4_payload_still_requires_the_marker_and_installs_by_authenticated_format() {
    use mvm_core::image_set::ArtifactFormat;
    let _env = unsigned_env();
    let profile = WorkloadImageProfile::DefaultTenant;
    let target = MemberTarget::Arch(ARCH);
    for marker in [Some(b"1\n".as_slice()), None, Some(b"2\n".as_slice())] {
        let served = tempfile::tempdir().unwrap();
        let root = contract_root(marker, None);
        let fixture = ImageSetFixture::complete()
            .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER))
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                target,
                "kernel-no-extension",
                b"kernel".to_vec(),
            )
            .publish(
                ImageSetRole::WorkloadRootfs(profile),
                target,
                "root-no-extension",
                root,
            )
            .publish_extra(
                ImageSetRole::WorkloadRootfs(profile),
                target,
                "hash-tree",
                b"verity".to_vec(),
            )
            .with_artifact_format("hash-tree", ArtifactFormat::VerityHashTree)
            .publish_extra(
                ImageSetRole::WorkloadRootfs(profile),
                target,
                "root-hash",
                b"roothash".to_vec(),
            )
            .with_artifact_format("root-hash", ArtifactFormat::VerityRootHash);
        let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
        let installed = tempfile::tempdir().unwrap();
        let result = set.fetch_default_workload(ARCH, installed.path());
        if marker == Some(b"1\n".as_slice()) {
            result.unwrap();
            let sidecar = crate::builder_vm::GuestSidecar::read_from_dir(installed.path())
                .unwrap()
                .unwrap();
            assert_eq!(sidecar.protocol_version, 0);
            assert_eq!(sidecar.init_system, "cli-initramfs");
            assert!(sidecar.agent_binary.is_empty());
        } else {
            assert!(result.is_err(), "renaming cannot bypass the marker");
            assert!(!installed.path().join("rootfs.ext4").exists());
        }
    }
}

#[test]
fn base_marker_requires_exact_readonly_mode_in_every_admission_path() {
    let mut compatibility = mvm_core::image_set::image_train_lock()
        .compatibility
        .clone();
    compatibility.base_image_contract = Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER);
    for mode in [0o444, 0o644, 0o400, 0o4444, 0o2444, 0o1444] {
        let image = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            image.path(),
            contract_root_with_mode(Some(b"1\n"), None, mode),
        )
        .unwrap();
        assert_eq!(
            verify_base_image_contract(image.path(), &compatibility).is_ok(),
            mode == 0o444,
            "marker mode {mode:o}"
        );
    }
}

#[test]
fn base_marker_never_trusts_symlink_components() {
    let mut compatibility = mvm_core::image_set::image_train_lock()
        .compatibility
        .clone();
    compatibility.base_image_contract = Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER);
    for path in ["/etc", "/etc/mvm", "/etc/mvm/base-image-contract"] {
        let image = tempfile::NamedTempFile::new().unwrap();
        // Parents may be replaced by a symlink only when their children are
        // omitted; the writer correctly refuses descendants of a symlink.
        let bytes = contract_root(None, Some(path));
        std::fs::write(image.path(), bytes).unwrap();
        assert!(verify_base_image_contract(image.path(), &compatibility).is_err());
    }
}

#[test]
fn unknown_base_contract_is_refused_before_member_acquisition() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"not requested")
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::new(99)));
    fn never_download(_: &str, _: &Path) -> Result<()> {
        panic!("unsupported locked contract must refuse before acquisition");
    }
    let error = PublishedImageSet::acquire_from(
        fixture
            .serve_from(served.path())
            .with_download(never_download),
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("base-image contract 99"));
}

/// A fixture carries no publisher signature, so every acquisition below skips
/// that rung; `acquire_refuses_a_root_without_a_signature` is the one that
/// does not.
fn unsigned_env() -> TestEnv {
    let mut env = TestEnv::new();
    env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
    env
}

fn with_member(bytes: &[u8]) -> ImageSetFixture {
    ImageSetFixture::complete().publish(
        ImageSetRole::Stage0BootstrapKernel,
        MemberTarget::Arch(ARCH),
        MEMBER,
        bytes.to_vec(),
    )
}

/// A set published while the image repository still built the guest runtime
/// lists an overlay, two sidecars and an initramfs per architecture, the
/// sidecars with a source fingerprint. A CLI that no longer requires them
/// acquires that set, and its Linux-layer members deliver as before.
#[test]
fn a_set_still_carrying_the_guest_runtime_is_acquired_and_serves_its_linux_layer() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"stage0").with_retired_guest_runtime();
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .expect("a set carrying retired guest-runtime members must be accepted");
    assert_eq!(
        set.manifest()
            .members
            .iter()
            .filter(|member| member.role.is_retired())
            .count(),
        8
    );

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("kernel");
    set.fetch_member_artifact(ImageSetRole::Stage0BootstrapKernel, ARCH, MEMBER, &dest)
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"stage0");
}

/// A set that no longer lists any guest-runtime member is complete.
#[test]
fn a_set_without_any_guest_runtime_member_is_acquired() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set = PublishedImageSet::acquire_from(with_member(b"stage0").serve_from(served.path()))
        .expect("the guest runtime is not part of the image-set contract");
    assert!(!set.manifest().members.iter().any(|m| m.role.is_retired()));
}

/// The pinned `image-set/v0.2.4` records a guest-agent protocol range and no
/// base-image contract. The lock copies neither, the range decides nothing,
/// and the absent contract is checked as the legacy contract 0, which this
/// CLI boots.
#[test]
fn a_set_recording_only_the_retired_guest_agent_range_is_acquired_as_the_legacy_contract() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"stage0")
        .with_retired_guest_runtime()
        .with_retired_guest_agent_protocol(mvm_core::image_set::ProtocolRange::new(9, 9).unwrap())
        .with_base_image_contract(None);
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .expect("a legacy set must be acquired");
    assert_eq!(
        set.manifest().compatibility.base_image_contract_or_legacy(),
        mvm_core::image_set::BaseImageContract::LEGACY
    );
}

#[test]
fn a_set_declaring_the_linux_layer_contract_is_acquired() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"stage0")
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER));
    PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .expect("a set declaring the Linux-layer contract must be acquired");
}

/// A base-image contract this CLI does not boot is refused at acquisition,
/// before any member is fetched, so nothing from the set can boot.
#[test]
fn a_set_declaring_a_base_image_contract_this_cli_does_not_boot_is_refused() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"stage0")
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::new(2)));
    let err = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .err()
        .expect("an unknown base-image contract must be refused");
    assert!(
        format!("{err:#}").contains("base-image contract 2"),
        "{err:#}"
    );
}

#[test]
fn development_signature_bypass_cannot_seed_an_authenticated_root_cache() {
    let mut env = unsigned_env();
    let home = tempfile::tempdir().unwrap();
    env.set("MVM_HOME", home.path().to_str().unwrap());
    let served = tempfile::tempdir().unwrap();
    PublishedImageSet::acquire_from(with_member(b"overlay").serve_from(served.path()))
        .expect("the explicit development bypass retains its acquisition behavior");
    assert!(!mvm_core::image_set::image_set_root_proof_cache().exists());
}

#[test]
fn a_member_named_by_the_signed_root_is_delivered_verbatim() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set = PublishedImageSet::acquire_from(with_member(b"overlay").serve_from(served.path()))
        .expect("a complete, locked, compatible root must be accepted");

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    set.fetch_member_artifact(ImageSetRole::Stage0BootstrapKernel, ARCH, MEMBER, &dest)
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"overlay");
}

#[test]
fn the_authenticated_manifest_bytes_retain_the_original_root() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let mut source = with_member(b"overlay").serve_from(served.path());
    let path = served
        .path()
        .join(source.train.image_set.manifest_asset.as_str());
    let mut original = std::fs::read(&path).unwrap();
    original.extend_from_slice(b"\n  ");
    std::fs::write(&path, &original).unwrap();
    source.train.image_set.manifest_sha256 = Sha256Hex::from_bytes(&original);

    let set = PublishedImageSet::acquire_from(source).expect("authenticated original manifest");

    assert_eq!(set.manifest_bytes(), original);
    assert_eq!(
        &Sha256Hex::from_bytes(set.manifest_bytes()),
        set.member_cache().root()
    );
    assert_ne!(serde_json::to_vec(set.manifest()).unwrap(), original);
}

/// A set that also publishes the dev variant of the default tenant must not
/// confuse the production selectors: the default-workload fetch still takes
/// exactly the four production artifacts, and the generic artifact lookup
/// never reaches the dev member.
/// The dev-slot fetch installs the complete pair-build layout — kernel,
/// rootfs, meta — from the dev members alone.
#[test]
fn fetch_dev_workload_installs_the_pair_build_layout() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = ImageSetFixture::complete()
        .publish_dev(
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-dev-vmlinux-aarch64",
            b"dev-kernel".to_vec(),
        )
        .publish_dev(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-dev-rootfs-aarch64.ext4",
            b"dev-rootfs".to_vec(),
        )
        .publish_dev_extra(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-dev-meta-aarch64.json",
            br#"{"sealed": false}"#.to_vec(),
        );
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).expect("acquire");

    let out = tempfile::tempdir().unwrap();
    set.fetch_dev_workload(ARCH, out.path()).expect("dev fetch");
    assert_eq!(
        std::fs::read(out.path().join("vmlinux")).unwrap(),
        b"dev-kernel"
    );
    assert_eq!(
        std::fs::read(out.path().join("rootfs.ext4")).unwrap(),
        b"dev-rootfs"
    );
    assert_eq!(
        std::fs::read(out.path().join("mvm-meta.json")).unwrap(),
        br#"{"sealed": false}"#
    );
}

#[test]
fn dev_root_selection_uses_format_without_a_legacy_filename_escape() {
    use mvm_core::image_set::ArtifactFormat;
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let role = ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant);
    let target = MemberTarget::Arch(ARCH);
    let root = contract_root(Some(b"1\n"), None);
    let fixture = ImageSetFixture::complete()
        .with_base_image_contract(Some(mvm_core::image_set::BaseImageContract::LINUX_LAYER))
        .publish_dev(
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
            target,
            "dev-kernel",
            b"kernel".to_vec(),
        )
        .publish_dev(role, target, "not-a-root.ext4", b"decoy".to_vec())
        .publish_dev_extra(role, target, "root-payload", root.clone())
        .publish_dev_extra(role, target, "meta.json", b"{}".to_vec())
        .with_artifact_format("not-a-root.ext4", ArtifactFormat::Text)
        .with_artifact_format("root-payload", ArtifactFormat::Ext4)
        .with_artifact_format("meta.json", ArtifactFormat::Json);
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
    let out = tempfile::tempdir().unwrap();
    set.fetch_dev_workload(ARCH, out.path()).unwrap();
    assert_eq!(std::fs::read(out.path().join("rootfs.ext4")).unwrap(), root);
    assert_eq!(
        std::fs::read(out.path().join("mvm-meta.json")).unwrap(),
        b"{}"
    );
}

#[test]
fn installed_workload_requires_each_half_of_the_selected_pair() {
    use mvm_core::image_set::ArtifactFormat;
    let profile = WorkloadImageProfile::DefaultTenant;
    let target = MemberTarget::Arch(ARCH);
    for missing_role in [
        ImageSetRole::WorkloadKernel(profile),
        ImageSetRole::WorkloadRootfs(profile),
    ] {
        let manifest = ImageSetFixture::complete()
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                target,
                "kernel",
                b"kernel".to_vec(),
            )
            .publish(
                ImageSetRole::WorkloadRootfs(profile),
                target,
                "root.ext4",
                b"root".to_vec(),
            )
            .with_artifact_format(
                "kernel",
                ArtifactFormat::Kernel(mvm_core::kernel_format::KernelFormat::Image),
            )
            .with_artifact_format("root.ext4", ArtifactFormat::Ext4)
            .without_member(missing_role, target)
            .into_manifest();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("vmlinux"), b"kernel").unwrap();
        std::fs::write(out.path().join("rootfs.ext4"), b"root").unwrap();
        let error = verify_installed_workload_files(&manifest, out.path(), ARCH, profile, None)
            .expect_err("one authenticated member is not a complete workload");
        assert!(error.to_string().contains("no complete"), "{error:#}");
    }
}

#[test]
fn installed_workload_refuses_a_symlink_even_when_its_size_and_target_digest_match() {
    use mvm_core::image_set::ArtifactFormat;
    let profile = WorkloadImageProfile::DefaultTenant;
    let target = MemberTarget::Arch(ARCH);
    let manifest = ImageSetFixture::complete()
        .publish(
            ImageSetRole::WorkloadKernel(profile),
            target,
            "kernel",
            b"kernel".to_vec(),
        )
        .publish(
            ImageSetRole::WorkloadRootfs(profile),
            target,
            "root.ext4",
            b"root".to_vec(),
        )
        .with_artifact_format(
            "kernel",
            ArtifactFormat::Kernel(mvm_core::kernel_format::KernelFormat::Image),
        )
        .with_artifact_format("root.ext4", ArtifactFormat::Ext4)
        .into_manifest();
    let out = tempfile::tempdir().unwrap();
    std::fs::write(out.path().join("target"), b"kernel").unwrap();
    std::os::unix::fs::symlink("target", out.path().join("vmlinux")).unwrap();
    std::fs::write(out.path().join("rootfs.ext4"), b"root").unwrap();
    assert_eq!(
        std::fs::symlink_metadata(out.path().join("vmlinux"))
            .unwrap()
            .len(),
        6,
        "the symlink length deliberately equals the declared kernel size"
    );
    let error = verify_installed_workload_files(&manifest, out.path(), ARCH, profile, None)
        .expect_err("matching target bytes cannot turn a symlink into a regular file");
    assert!(
        error.to_string().contains("not the declared regular file"),
        "{error:#}"
    );
}

/// A set without dev members refuses the dev fetch with NoMember, so the
/// caller falls back to a pair build.
#[test]
fn fetch_dev_workload_refuses_a_set_without_dev_members() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set =
        PublishedImageSet::acquire_from(ImageSetFixture::complete().serve_from(served.path()))
            .expect("acquire");
    let out = tempfile::tempdir().unwrap();
    let err = set
        .fetch_dev_workload(ARCH, out.path())
        .expect_err("no dev members, no fetch");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("default_tenant") && rendered.contains("aarch64"),
        "the refusal names the missing member: {rendered}"
    );
}

#[test]
fn a_dev_variant_member_is_invisible_to_production_selection() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let kernel = "default-microvm-vmlinux-aarch64";
    let fixture = ImageSetFixture::complete()
        .publish(
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            kernel,
            b"prod-kernel".to_vec(),
        )
        .publish(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-rootfs-aarch64.ext4",
            b"prod-rootfs".to_vec(),
        )
        .publish_extra(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-rootfs-aarch64.verity",
            b"prod-verity".to_vec(),
        )
        .publish_extra(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-rootfs-aarch64.roothash",
            b"prod-roothash".to_vec(),
        )
        .publish_dev(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-dev-rootfs-aarch64.ext4",
            b"dev-rootfs".to_vec(),
        );
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).expect("acquire");

    let out = tempfile::tempdir().unwrap();
    set.fetch_default_workload(ARCH, out.path())
        .expect("prod fetch");
    assert_eq!(
        std::fs::read(out.path().join("vmlinux")).unwrap(),
        b"prod-kernel"
    );
    assert_eq!(
        std::fs::read(out.path().join("rootfs.ext4")).unwrap(),
        b"prod-rootfs",
        "the dev member's rootfs must not reach the production cache"
    );

    let err = set
        .artifact(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(ARCH),
            "default-microvm-dev-rootfs-aarch64.ext4",
        )
        .expect_err("the generic lookup must not select the dev member");
    assert!(
        matches!(err, ImageSetMemberError::NoArtifact { .. }),
        "the production member is selected and it does not carry the dev artifact: {err}"
    );
}

#[test]
fn a_member_whose_bytes_differ_from_the_root_is_refused_and_removed() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"declared").serve_instead(MEMBER, b"tampered".to_vec());
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    let err = set
        .fetch_member_artifact(ImageSetRole::Stage0BootstrapKernel, ARCH, MEMBER, &dest)
        .unwrap_err();
    assert!(
        matches!(err, ImageSetMemberError::DigestMismatch { ref name, .. } if name == MEMBER),
        "same-size substitution must fail the digest check: {err}"
    );
    assert!(!dest.exists(), "refused bytes must not stay on disk");
}

/// `MVM_SKIP_HASH_VERIFY` waives the kernel-fetch checks, not this path: a
/// member the signed root does not describe is refused with the hatch set.
#[test]
fn the_hash_skip_hatch_does_not_admit_a_member_the_root_does_not_describe() {
    let mut env = unsigned_env();
    env.set(crate::runtime_overlay::SKIP_HASH_VERIFY_ENV, "1");
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"declared").serve_instead(MEMBER, b"tampered".to_vec());
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    let err = set
        .fetch_member_artifact(ImageSetRole::Stage0BootstrapKernel, ARCH, MEMBER, &dest)
        .unwrap_err();
    assert!(
        matches!(err, ImageSetMemberError::DigestMismatch { .. }),
        "{err}"
    );
    assert!(!dest.exists(), "refused bytes must not stay on disk");
}

#[test]
fn a_member_of_another_size_is_refused_before_it_is_hashed() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_member(b"declared").serve_instead(MEMBER, b"longer bytes".to_vec());
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    let err = set
        .fetch_member_artifact(ImageSetRole::Stage0BootstrapKernel, ARCH, MEMBER, &dest)
        .unwrap_err();
    assert!(
        matches!(err, ImageSetMemberError::SizeMismatch { .. }),
        "{err}"
    );
    assert!(!dest.exists());
}

/// Every role is a required member, so an absent one is refused when the set
/// is acquired, named by role and architecture, rather than at lookup.
#[test]
fn a_set_missing_a_required_member_is_refused_naming_it() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = ImageSetFixture::complete()
        .without_member(ImageSetRole::BuilderVm, MemberTarget::Arch(ARCH));

    let err = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .err()
        .expect("a set missing a required member must be refused");

    let rendered = format!("{err:#}");
    assert!(rendered.contains("incomplete"), "{rendered}");
    assert!(rendered.contains("builder_vm/aarch64"), "{rendered}");
}

#[test]
fn an_undeclared_artifact_of_a_present_member_is_refused() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set =
        PublishedImageSet::acquire_from(with_member(b"overlay").serve_from(served.path())).unwrap();

    let err = set
        .artifact(
            ImageSetRole::Stage0BootstrapKernel,
            MemberTarget::Arch(ARCH),
            "stage0-vmlinux-x86_64",
        )
        .unwrap_err();
    assert!(
        matches!(err, ImageSetMemberError::NoArtifact { .. }),
        "{err}"
    );
}

#[test]
fn acquire_refuses_a_root_other_than_the_locked_one() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let source = with_member(b"overlay").serve_from(served.path());
    // Replace the root after its digest was pinned.
    let root = served.path().join("image-set.json");
    let mut bytes = std::fs::read(&root).unwrap();
    bytes.push(b'\n');
    std::fs::write(&root, bytes).unwrap();

    let err = PublishedImageSet::acquire_from(source)
        .err()
        .expect("a root that is not the pinned one must be refused");
    assert!(
        format!("{err:#}").contains("manifest digest mismatch"),
        "{err:#}"
    );
}

#[test]
fn acquire_refuses_a_partial_release_naming_what_it_lacks() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = ImageSetFixture::complete().without_member(
        ImageSetRole::WorkloadRootfs(mvm_core::image_set::WorkloadImageProfile::RootlessTenant),
        MemberTarget::Arch(ARCH),
    );

    let err = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .err()
        .expect("a set missing a required member must be refused");
    assert!(
        format!("{err:#}").contains("rootless_tenant_workload_rootfs/aarch64"),
        "{err:#}"
    );
}

#[test]
fn acquire_refuses_a_root_without_a_signature() {
    let mut env = TestEnv::new();
    env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);
    let served = tempfile::tempdir().unwrap();

    for acquire in [
        PublishedImageSet::acquire_from,
        PublishedImageSet::acquire_workload_from,
    ] {
        let err = acquire(with_member(b"o").serve_from(served.path()))
            .err()
            .expect("an unsigned root must be refused even when its digest is pinned");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("publisher identity"),
            "the refusal must be the signature rung: {rendered}"
        );
    }
}

/// The two hatches are independent: waiving digest checks must not waive the
/// publisher signature on the pinned root.
#[test]
fn the_hash_skip_hatch_does_not_waive_the_root_signature() {
    let mut env = TestEnv::new();
    env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);
    env.set(crate::runtime_overlay::SKIP_HASH_VERIFY_ENV, "1");
    let served = tempfile::tempdir().unwrap();

    let err = PublishedImageSet::acquire_from(with_member(b"o").serve_from(served.path()))
        .err()
        .expect("an unsigned root must be refused whatever the hash hatch says");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("publisher identity"),
        "the refusal must be the signature rung: {rendered}"
    );
}

#[test]
fn the_locked_source_names_the_pinned_release_directory() {
    let mut env = TestEnv::new();
    env.remove("MVM_UPDATE_DOWNLOAD_URL");
    let source = ImageSetSource::locked();
    let train = mvm_core::image_set::image_train_lock();
    assert_eq!(
        format!("{}/{}", source.base_url, train.image_set.manifest_asset),
        train.manifest_url(),
        "the default source must fetch exactly the URL the lock composes"
    );

    env.set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:9/");
    assert!(
        ImageSetSource::locked()
            .base_url
            .starts_with("http://127.0.0.1:9/"),
        "a mirror moves the host and nothing else"
    );
}
