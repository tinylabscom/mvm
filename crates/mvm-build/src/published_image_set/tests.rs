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

#[test]
fn an_absent_member_is_named_by_role_and_arch() {
    let _env = unsigned_env();
    let served = tempfile::tempdir().unwrap();
    let set =
        PublishedImageSet::acquire_from(ImageSetFixture::complete().serve_from(served.path()))
            .unwrap();

    let err = set
        .artifact(ImageSetRole::Initramfs, MemberTarget::Arch(ARCH), "x")
        .unwrap_err();
    assert!(
        matches!(
            err,
            ImageSetMemberError::NoMember {
                role: ImageSetRole::Initramfs,
                target: MemberTarget::Arch(GuestArch::Aarch64),
                ..
            }
        ),
        "{err}"
    );
    let rendered = err.to_string();
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
