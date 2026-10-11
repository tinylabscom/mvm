//! Offline witnesses through the production image-set verifier and cache installer.
//! Synthetic fixture roots waive only publisher signatures; signature-refusal
//! tests do not. Root pins, member pins, sizes, selection and promotion are real.

use super::*;
use crate::builder_images::bootstrap::builder_vm_host_arch;
use mvm_build::published_image_set::{ImageSetSource, PublishedImageSet, fixture::ImageSetFixture};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, MemberTarget};
use mvm_core::util::test_env::TestEnv;
use std::cell::Cell;
use std::path::PathBuf;

fn assets(arch: &str) -> [(String, &'static str); 3] {
    [
        (format!("builder-vm-vmlinux-{arch}"), "vmlinux"),
        (format!("builder-vm-{arch}.kernel.config"), "kernel.config"),
        (format!("builder-vm-rootfs-{arch}.ext4"), "rootfs.ext4"),
    ]
}

fn fixture(arch: GuestArch) -> ImageSetFixture {
    let [(kernel, _), (config, _), (rootfs, _)] = assets(&arch.to_string());
    let mut rootfs_bytes = vec![0u8; 4 * 1024 * 1024 + 1];
    rootfs_bytes[1024 + 56] = 0x53;
    rootfs_bytes[1024 + 57] = 0xef;
    ImageSetFixture::complete()
        .publish(
            ImageSetRole::BuilderVm,
            MemberTarget::Arch(arch),
            &kernel,
            vec![0x7f; 1024 * 1024 + 1],
        )
        .publish_extra(
            ImageSetRole::BuilderVm,
            MemberTarget::Arch(arch),
            &config,
            b"# CONFIG_NETDEVICES is not set\nCONFIG_VSOCKETS=y\nCONFIG_VIRTIO_VSOCKETS=y\n"
                .to_vec(),
        )
        .publish_extra(
            ImageSetRole::BuilderVm,
            MemberTarget::Arch(arch),
            &rootfs,
            rootfs_bytes,
        )
}

struct Host {
    env: TestEnv,
    root: tempfile::TempDir,
    cache: PathBuf,
}

impl Host {
    fn new(existed: bool) -> Self {
        let mut env = TestEnv::new();
        env.remove("MVM_SKIP_HASH_VERIFY");
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        let root = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(root.path().join("home"));
        let cache = root.path().join("builder-vm").join(builder_vm_host_arch());
        if existed {
            std::fs::create_dir_all(&cache).unwrap();
            std::fs::write(cache.join("vmlinux"), b"previous kernel").unwrap();
            std::fs::write(cache.join("previous-marker"), b"kept").unwrap();
        }
        Self { env, root, cache }
    }

    fn serve(&self, fixture: &ImageSetFixture) -> ImageSetSource {
        fixture.serve_from(&self.root.path().join("release"))
    }

    fn fetch(&self, source: ImageSetSource) -> Result<()> {
        download_builder_vm_image_with(builder_vm_host_arch(), &self.cache, || {
            PublishedImageSet::acquire_from(source)
        })
    }

    fn staging_dirs(&self) -> Vec<PathBuf> {
        let prefix = format!(".{}.stage0-", builder_vm_host_arch());
        std::fs::read_dir(self.cache.parent().unwrap())
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                    .map(|entry| entry.path())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assert_unchanged(&self, existed: bool) {
        assert!(
            self.staging_dirs().is_empty(),
            "refusal must remove staging: {:?}",
            self.staging_dirs()
        );
        if existed {
            assert_eq!(
                std::fs::read(self.cache.join("vmlinux")).unwrap(),
                b"previous kernel"
            );
            assert!(self.cache.join("previous-marker").exists());
            assert!(!self.cache.join("rootfs.ext4").exists());
        } else {
            assert!(!self.cache.exists(), "refusal must not create the cache");
        }
    }
}

fn assert_refused_without_promotion(
    edit: impl Fn(&Host, ImageSetSource) -> ImageSetSource,
    needle: &str,
) {
    for existed in [false, true] {
        let host = Host::new(existed);
        let source = edit(&host, host.serve(&fixture(GuestArch::host())));
        let err = host.fetch(source).expect_err("fetch must refuse");
        let chain = format!("{err:#}");
        assert!(
            chain.contains(needle),
            "refusal must mention {needle}: {chain}"
        );
        host.assert_unchanged(existed);
    }
}

#[test]
fn a_verified_fetch_promotes_every_artifact_with_provenance_and_removes_staging() {
    let host = Host::new(false);
    host.fetch(host.serve(&fixture(GuestArch::host()))).unwrap();
    for (asset, file) in assets(builder_vm_host_arch()) {
        assert_eq!(
            std::fs::read(host.cache.join(file)).unwrap(),
            std::fs::read(host.root.path().join("release").join(asset)).unwrap(),
            "{file} must hold the verified published bytes",
        );
    }
    assert_eq!(
        std::fs::read_to_string(host.cache.join("cmdline.txt")).unwrap(),
        synthesized_builder_vm_cmdline()
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(host.cache.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["cache_contract_version"],
        mvm_build::builder_vm::BUILDER_VM_CACHE_CONTRACT_VERSION
    );
    for field in [
        "runtime_overlay_ready",
        "vsock_egress_ready",
        "no_network_devices_ready",
    ] {
        assert_eq!(manifest[field], true);
    }
    let provenance: serde_json::Value = serde_json::from_slice(
        &std::fs::read(host.cache.join(BUILDER_VM_PROVENANCE_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(provenance["source_kind"], "fetched");
    assert_eq!(
        provenance["image_tag"],
        mvm_core::image_set::image_train_lock()
            .image_set
            .release_tag
            .as_str()
    );
    assert!(
        provenance.get("source_fingerprint").is_none(),
        "fetched image has no source fingerprint: {provenance}"
    );
    assert!(host.staging_dirs().is_empty());
    validate_builder_vm_stage0_artifacts(&host.cache).unwrap();
}

#[test]
fn a_verified_fetch_replaces_a_previous_cache_whole() {
    let host = Host::new(true);
    host.fetch(host.serve(&fixture(GuestArch::host()))).unwrap();
    assert!(!host.cache.join("previous-marker").exists());
    assert!(host.staging_dirs().is_empty());
    validate_builder_vm_stage0_artifacts(&host.cache).unwrap();
}

#[test]
fn builder_vm_artifact_names_match_the_image_set_for_both_architectures() {
    let host = Host::new(false);
    for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
        let image_set = PublishedImageSet::acquire_from(host.serve(&fixture(arch))).unwrap();
        let staging = host.root.path().join(format!("staged-{arch}"));
        stage_locked_builder_vm_image(arch, &staging, &image_set).unwrap();
        for (asset, file) in assets(&arch.to_string()) {
            assert_eq!(
                std::fs::read(staging.join(file)).unwrap(),
                std::fs::read(host.root.path().join("release").join(asset)).unwrap(),
                "{arch}/{file} must select its own published asset"
            );
        }
        validate_builder_vm_stage0_artifacts(&staging).unwrap();
    }
}

fn assert_digest_mismatch(index: usize) {
    let asset = assets(builder_vm_host_arch())[index].0.clone();
    assert_refused_without_promotion(
        |host, source| {
            let path = host.root.path().join("release").join(&asset);
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 0xff;
            std::fs::write(path, bytes).unwrap();
            source
        },
        &asset,
    );
}

#[test]
fn a_kernel_digest_mismatch_refuses_and_promotes_nothing() {
    assert_digest_mismatch(0);
}

#[test]
fn a_rootfs_digest_mismatch_refuses_and_promotes_nothing() {
    assert_digest_mismatch(2);
}

#[test]
fn a_kernel_config_digest_mismatch_refuses_and_promotes_nothing() {
    assert_digest_mismatch(1);
}

#[test]
fn a_missing_asset_refuses_names_it_and_promotes_nothing() {
    for (asset, _) in assets(builder_vm_host_arch()) {
        assert_refused_without_promotion(
            |host, source| {
                std::fs::remove_file(host.root.path().join("release").join(&asset)).unwrap();
                source
            },
            &asset,
        );
    }
}

#[test]
fn a_member_whose_size_disagrees_with_the_root_is_refused() {
    for (asset, _) in assets(builder_vm_host_arch()) {
        assert_refused_without_promotion(
            |host, source| {
                std::fs::write(host.root.path().join("release").join(&asset), b"wrong size")
                    .unwrap();
                source
            },
            &asset,
        );
    }
}

#[test]
fn a_root_digest_mismatch_refuses_and_promotes_nothing() {
    assert_refused_without_promotion(
        |host, source| {
            let path = host.root.path().join("release").join(
                mvm_core::image_set::image_train_lock()
                    .image_set
                    .manifest_asset
                    .as_str(),
            );
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
            source
        },
        "manifest digest mismatch",
    );
}

#[test]
fn a_signature_refusal_stops_before_any_artifact_is_fetched() {
    for existed in [false, true] {
        let mut host = Host::new(existed);
        host.env.remove("MVM_SKIP_COSIGN_VERIFY");
        let source = host
            .serve(&fixture(GuestArch::host()))
            .with_download(root_only_download);
        let err = host.fetch(source).unwrap_err();
        assert!(format!("{err:#}").contains("publisher identity"), "{err:#}");
        host.assert_unchanged(existed);
    }
}

#[cfg(feature = "manifest-verify")]
#[test]
fn a_valid_cli_signature_is_refused_before_image_set_parsing_or_member_fetch() {
    use mvm_build::release_signature::{
        ReleaseSignatureRequest, ReleaseTrain, bundle_asset_name, fixture as signed,
        verify_release_archive_signature,
    };
    use mvm_build::runtime_overlay::RuntimeOverlayError;
    use mvm_core::image_set::{ReleaseTag, TagRef};
    use mvm_core::packs::Sha256Hex;

    for existed in [false, true] {
        let mut host = Host::new(existed);
        host.env.remove("MVM_SKIP_COSIGN_VERIFY");
        let mut train = mvm_core::image_set::image_train_lock().clone();
        train.image_set.manifest_sha256 = Sha256Hex::from_bytes(signed::PAYLOAD);
        train.image_set.release_tag =
            ReleaseTag::new(format!("image-set/v{}", signed::VERSION)).unwrap();
        train.image_set.signing_identity.tag_ref = TagRef::for_tag(&train.image_set.release_tag);
        let asset = train.image_set.manifest_asset.as_str();
        let release = host.root.path().join("release");
        std::fs::create_dir_all(&release).unwrap();
        let payload_path = release.join(asset);
        std::fs::write(&payload_path, signed::PAYLOAD).unwrap();
        std::fs::write(release.join(bundle_asset_name(asset)), signed::BUNDLE).unwrap();
        let base_url = format!("file://{}", release.display());

        // Verify the same served bytes and bundle first, without a waiver,
        // under the actual CLI publisher. Renaming an asset cannot change who
        // signed it. This control excludes corrupt/absent/disabled verification.
        verify_release_archive_signature(&ReleaseSignatureRequest {
            base_url: &base_url,
            asset,
            archive_path: &payload_path,
            version: signed::VERSION,
            train: ReleaseTrain::Cli,
        })
        .expect("the published CLI checksum payload must verify under its own release identity");

        // These are checksum text, not a valid image-set JSON manifest. The
        // refusal must therefore specifically precede the manifest parser.
        assert!(serde_json::from_slice::<serde_json::Value>(signed::PAYLOAD).is_err());
        let expected_identity =
            mvm_core::release_trust::accepted_image_set_identities(signed::VERSION);
        let actual_identity = mvm_core::release_trust::accepted_release_identities(signed::VERSION);
        let asset = asset.to_string();
        let source = ImageSetSource::new(train, base_url).with_download(root_only_download);
        let err = host
            .fetch(source)
            .expect_err("a CLI signer cannot publish an image set");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("verify the locked image-set publisher identity"),
            "{chain}"
        );
        let Some(RuntimeOverlayError::SignatureInvalid {
            asset: refused_asset,
            reason,
        }) = err.downcast_ref::<RuntimeOverlayError>()
        else {
            panic!("must reach signature policy, not a missing bundle or JSON parser: {chain}");
        };
        assert_eq!(refused_asset, &asset);
        assert!(reason.contains("identity mismatch"), "{reason}");
        assert!(reason.contains(&expected_identity[0]), "{reason}");
        assert!(reason.contains(&actual_identity[0]), "{reason}");
        assert!(
            !chain.contains("the signed image-set root is not a supported manifest"),
            "signature policy must refuse before parsing: {chain}"
        );
        host.assert_unchanged(existed);
    }
}

fn root_only_download(url: &str, dest: &std::path::Path) -> Result<()> {
    assert!(
        url.ends_with(
            mvm_core::image_set::image_train_lock()
                .image_set
                .manifest_asset
                .as_str()
        ),
        "no member may be requested before publisher verification: {url}",
    );
    mvm_build::artifact_download::download(url, dest)
}

#[test]
fn a_set_missing_the_host_architecture_is_refused() {
    for existed in [false, true] {
        let host = Host::new(existed);
        let source = host.serve(&fixture(GuestArch::host()).without_member(
            ImageSetRole::BuilderVm,
            MemberTarget::Arch(GuestArch::host()),
        ));
        let err = host.fetch(source).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("builder_vm") && chain.contains(builder_vm_host_arch()),
            "{chain}"
        );
        host.assert_unchanged(existed);
    }
}

#[test]
fn a_non_host_architecture_is_refused_before_any_network_request() {
    let host = Host::new(false);
    let foreign = if builder_vm_host_arch() == "aarch64" {
        "x86_64"
    } else {
        "aarch64"
    };
    let requests = Cell::new(0);
    let err = download_builder_vm_image_with(foreign, &host.cache, || {
        requests.set(requests.get() + 1);
        anyhow::bail!("acquisition must not run")
    })
    .unwrap_err();
    let chain = format!("{err:#}");
    assert!(
        chain.contains(foreign) && chain.contains(builder_vm_host_arch()),
        "{chain}"
    );
    assert_eq!(
        requests.get(),
        0,
        "no request may precede the architecture check"
    );
    host.assert_unchanged(false);
}

#[test]
fn the_provenance_line_is_stable_and_admits_a_waived_check() {
    const TAG: &str = "boot-image/v0.1.5";
    assert_eq!(
        fetched_builder_vm_image_line(TAG, &[]),
        "Builder VM image source: fetched (boot-image/v0.1.5), signature and digests verified"
    );
    let waived = fetched_builder_vm_image_line(TAG, &["MVM_SKIP_COSIGN_VERIFY"]);
    assert!(
        waived.starts_with("Builder VM image source: fetched (boot-image/v0.1.5)")
            && waived.contains("MVM_SKIP_COSIGN_VERIFY")
            && !waived.contains("signature and digests verified"),
        "a waived check must not be reported as verified: {waived}"
    );
}
