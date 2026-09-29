use super::fixture::ImageSetFixture;
use super::*;
use mvm_core::util::test_env::TestEnv;

const ARCH: GuestArch = GuestArch::Aarch64;
const OVERLAY: &str = "runtime-overlay-aarch64.tar.gz";

/// A fixture carries no publisher signature, so every acquisition below skips
/// that rung; `acquire_refuses_a_root_without_a_signature` is the one that
/// does not.
fn unsigned_env() -> TestEnv {
    let mut env = TestEnv::new();
    env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
    env
}

fn with_overlay(bytes: &[u8]) -> ImageSetFixture {
    ImageSetFixture::complete().publish(
        ImageSetRole::RuntimeOverlay,
        MemberTarget::Arch(ARCH),
        OVERLAY,
        bytes.to_vec(),
    )
}

#[test]
fn a_member_named_by_the_signed_root_is_delivered_verbatim() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set = PublishedImageSet::acquire_from(with_overlay(b"overlay").serve_from(served.path()))
        .expect("a complete, locked, compatible root must be accepted");

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    set.fetch_member_artifact(ImageSetRole::RuntimeOverlay, ARCH, OVERLAY, &dest)
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"overlay");
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
    let fixture = with_overlay(b"declared").serve_instead(OVERLAY, b"tampered".to_vec());
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    let err = set
        .fetch_member_artifact(ImageSetRole::RuntimeOverlay, ARCH, OVERLAY, &dest)
        .unwrap_err();
    assert!(
        matches!(err, ImageSetMemberError::DigestMismatch { ref name, .. } if name == OVERLAY),
        "same-size substitution must fail the digest check: {err}"
    );
    assert!(!dest.exists(), "refused bytes must not stay on disk");
}

#[test]
fn a_member_of_another_size_is_refused_before_it_is_hashed() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let fixture = with_overlay(b"declared").serve_instead(OVERLAY, b"longer bytes".to_vec());
    let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join("archive");
    let err = set
        .fetch_member_artifact(ImageSetRole::RuntimeOverlay, ARCH, OVERLAY, &dest)
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
        .without_member(ImageSetRole::Initramfs, MemberTarget::Arch(ARCH));

    let err = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .err()
        .expect("a set missing a required member must be refused");

    let rendered = format!("{err:#}");
    assert!(rendered.contains("incomplete"), "{rendered}");
    assert!(rendered.contains("initramfs/aarch64"), "{rendered}");
}

#[test]
fn an_undeclared_artifact_of_a_present_member_is_refused() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set = PublishedImageSet::acquire_from(with_overlay(b"overlay").serve_from(served.path()))
        .unwrap();

    let err = set
        .artifact(
            ImageSetRole::RuntimeOverlay,
            MemberTarget::Arch(ARCH),
            "runtime-overlay-x86_64.tar.gz",
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
    let source = with_overlay(b"overlay").serve_from(served.path());
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
    let fixture = ImageSetFixture::complete()
        .without_member(ImageSetRole::RuntimeOverlay, MemberTarget::Arch(ARCH));

    let err = PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
        .err()
        .expect("a set missing a required member must be refused");
    assert!(
        format!("{err:#}").contains("runtime_overlay/aarch64"),
        "{err:#}"
    );
}

#[test]
fn acquire_refuses_a_root_without_a_signature() {
    let mut env = TestEnv::new();
    env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);
    let served = tempfile::tempdir().unwrap();

    let err = PublishedImageSet::acquire_from(with_overlay(b"o").serve_from(served.path()))
        .err()
        .expect("an unsigned root must be refused even when its digest is pinned");
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
