use super::*;
use crate::published_image_set::fixture::ImageSetFixture;
use crate::published_image_set::{ImageSetMemberError, ImageSetSource};
use crate::sdk_sidecar::SdkSidecarArtifactNames;
use crate::sdk_sidecar::tests::well_formed_archive;
use mvm_core::image_set::ProtocolRange;
use mvm_core::util::test_env::TestEnv;

/// The sidecar fixtures resolve an ELF built for the host, so every test that
/// installs one uses the host's architecture.
fn arch() -> GuestArch {
    GuestArch::host()
}

fn fingerprint(fill: &str) -> String {
    fill.repeat(32)
}

/// A fixture root carries no publisher signature; the signature rung has its
/// own witnesses in `crate::release_signature`.
fn unsigned_env() -> TestEnv {
    let mut env = TestEnv::new();
    env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
    env
}

fn request(mode: FetchMode, members: PinnedMembers) -> ArmRequest {
    ArmRequest {
        mode,
        members,
        arch: arch(),
    }
}

/// A fixture set and the directory it is served from, kept alive together.
struct Served {
    _dir: tempfile::TempDir,
    source: Option<ImageSetSource>,
}

impl Served {
    fn new(fixture: &ImageSetFixture) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = fixture.serve_from(dir.path());
        Self {
            _dir: dir,
            source: Some(source),
        }
    }

    /// The acquisition `choose_arm` runs, against this fixture instead of the
    /// locked release.
    fn acquire(&mut self) -> impl FnOnce() -> anyhow::Result<PublishedImageSet> + '_ {
        let source = self.source.take().expect("each fixture is acquired once");
        move || PublishedImageSet::acquire_from(source)
    }
}

fn sidecar_archive_name(libc: GuestLibc) -> String {
    SdkSidecarArtifactNames::for_target(&arch().to_string(), libc).archive
}

/// A complete set whose two sidecars are sound archives declaring
/// `fingerprint`.
fn set_with_sidecars(fingerprint: Option<String>) -> ImageSetFixture {
    let mut fixture = ImageSetFixture::complete();
    for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
        fixture = fixture.publish(
            ImageSetRole::SdkSidecar(libc),
            MemberTarget::Arch(arch()),
            &sidecar_archive_name(libc),
            well_formed_archive("0.0.1-member", libc),
        );
    }
    fixture.with_sidecar_fingerprints(arch(), fingerprint)
}

fn with_dev_members(fixture: ImageSetFixture) -> ImageSetFixture {
    let kernel = format!("default-microvm-dev-vmlinux-{}", arch());
    let rootfs = format!("default-microvm-dev-rootfs-{}.ext4", arch());
    let meta = format!("default-microvm-dev-meta-{}.json", arch());
    fixture
        .publish_dev(
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(arch()),
            &kernel,
            b"dev-kernel".to_vec(),
        )
        .publish_dev(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(arch()),
            &rootfs,
            b"dev-rootfs".to_vec(),
        )
        .publish_dev_extra(
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
            MemberTarget::Arch(arch()),
            &meta,
            b"{}".to_vec(),
        )
}

fn adopted(arm: Arm) -> (PublishedImageSet, SourceComparison) {
    match arm {
        Arm::Adopt { set, comparison } => (*set, comparison),
        Arm::BuildLocally { reason } => {
            panic!("expected the adopt arm, got a local build: {reason}")
        }
    }
}

fn built_locally(arm: Arm) -> String {
    match arm {
        Arm::BuildLocally { reason } => reason,
        Arm::Adopt { set, .. } => panic!(
            "expected a local build, got the adopt arm for {}",
            set.release_tag()
        ),
    }
}

#[test]
fn the_knob_defaults_off_and_names_two_modes() {
    let mut env = TestEnv::new();
    env.remove(FETCH_UNCHANGED_ENV);
    assert_eq!(FetchMode::from_env(), FetchMode::Off);
    env.set(FETCH_UNCHANGED_ENV, "1");
    assert_eq!(FetchMode::from_env(), FetchMode::WhenUnchanged);
    env.set(FETCH_UNCHANGED_ENV, "pinned");
    assert_eq!(FetchMode::from_env(), FetchMode::Pinned);

    for (value, mode) in [
        ("", FetchMode::Off),
        ("0", FetchMode::Off),
        (" 1 ", FetchMode::WhenUnchanged),
        ("Pinned", FetchMode::Pinned),
        (" PINNED\n", FetchMode::Pinned),
        // Unrecognised values adopt nothing.
        ("true", FetchMode::Off),
        ("pin", FetchMode::Off),
    ] {
        assert_eq!(FetchMode::parse(value), mode, "{value:?}");
    }
}

#[test]
fn matching_fingerprints_on_both_libcs_adopt_the_set() {
    let _env = unsigned_env();
    let fp = fingerprint("ab");
    let mut served = Served::new(&set_with_sidecars(Some(fp.clone())));
    let arm = choose_arm(
        request(FetchMode::WhenUnchanged, PinnedMembers::SdkSidecars),
        Ok(fp),
        served.acquire(),
    )
    .expect("fetch-when-unchanged never refuses");
    let (_, comparison) = adopted(arm);
    assert_eq!(comparison, SourceComparison::Matches);
}

/// The mode the release lane does not use keeps its old behaviour: a
/// mismatched or absent fingerprint builds locally and says why.
#[test]
fn when_unchanged_builds_locally_on_a_mismatched_or_absent_fingerprint() {
    let _env = unsigned_env();
    let mut served = Served::new(&set_with_sidecars(Some(fingerprint("cd"))));
    let reason = built_locally(
        choose_arm(
            request(FetchMode::WhenUnchanged, PinnedMembers::SdkSidecars),
            Ok(fingerprint("ab")),
            served.acquire(),
        )
        .unwrap(),
    );
    assert!(reason.contains("differs from the set's"), "{reason}");

    let mut served = Served::new(&set_with_sidecars(None));
    let reason = built_locally(
        choose_arm(
            request(FetchMode::WhenUnchanged, PinnedMembers::SdkSidecars),
            Ok(fingerprint("ab")),
            served.acquire(),
        )
        .unwrap(),
    );
    assert!(reason.contains("declare no source fingerprint"), "{reason}");
}

/// With the knob unset nothing is acquired at all.
#[test]
fn an_unset_knob_builds_locally_without_acquiring_the_set() {
    let arm = choose_arm(
        request(FetchMode::Off, PinnedMembers::SdkSidecars),
        Ok(fingerprint("ab")),
        || panic!("the set must not be acquired when the knob is unset"),
    )
    .unwrap();
    assert!(built_locally(arm).contains(FETCH_UNCHANGED_ENV));
}

/// The release lane's case: the tree has moved on since the set was built.
/// The pinned members are adopted anyway, the report says the fingerprints
/// differ, and both libcs install with their digests held to the signed root.
#[test]
fn pinned_adopts_mismatched_sidecars_and_verifies_their_digests() {
    let _env = unsigned_env();
    let tree = fingerprint("ab");
    let set_fp = fingerprint("cd");
    let mut served = Served::new(&set_with_sidecars(Some(set_fp.clone())));
    let req = request(FetchMode::Pinned, PinnedMembers::SdkSidecars);

    let arm = choose_arm(req, Ok(tree.clone()), served.acquire()).expect("pinned adopts");
    let report = arm.report(req);
    let (set, comparison) = adopted(arm);
    assert_eq!(comparison, SourceComparison::Differs { tree, set: set_fp });
    assert!(
        report.contains("MVM_FETCH_UNCHANGED_IMAGES=pinned"),
        "{report}"
    );
    assert!(report.contains(set.release_tag().as_str()), "{report}");
    assert!(report.contains("differs from the set's"), "{report}");

    let cache = tempfile::tempdir().unwrap();
    fetch_sidecars_from_set(&set, arch(), cache.path()).expect("both members install");
    let members = set.member_cache();
    for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
        crate::sdk_sidecar::image_set_sidecar_resolver(cache.path(), &members, arch(), libc)
            .unwrap_or_else(|e| panic!("the {libc} install is recorded: {e}"))
            .resolve(&arch().to_string(), libc)
            .unwrap_or_else(|e| panic!("the {libc} member resolves: {e}"));
    }
}

/// A tree whose fingerprint cannot be computed still adopts under `pinned`;
/// the report carries the reason instead of a comparison.
#[test]
fn pinned_adopts_when_the_tree_cannot_be_fingerprinted() {
    let _env = unsigned_env();
    let mut served = Served::new(&set_with_sidecars(Some(fingerprint("cd"))));
    let req = request(FetchMode::Pinned, PinnedMembers::SdkSidecars);
    let arm = choose_arm(
        req,
        Err("no source workspace to fingerprint".to_string()),
        served.acquire(),
    )
    .unwrap();
    assert!(arm.report(req).contains("could not be computed"));
}

/// A set whose signed compatibility excludes this CLI is refused under
/// `pinned`, naming the declared range — never answered by a local build.
#[test]
fn pinned_refuses_a_set_whose_declared_protocol_excludes_this_cli() {
    let _env = unsigned_env();
    let incompatible = ProtocolRange::new(99, 99).unwrap();
    let fixture =
        set_with_sidecars(Some(fingerprint("cd"))).with_guest_agent_protocol(incompatible);

    for members in [PinnedMembers::SdkSidecars, PinnedMembers::DevDefaultImage] {
        let mut served = Served::new(&fixture);
        let err = match choose_arm(
            request(FetchMode::Pinned, members),
            Ok(fingerprint("ab")),
            served.acquire(),
        ) {
            Err(err) => err,
            Ok(arm) => panic!(
                "an incompatible set must be refused: {}",
                arm.report(request(FetchMode::Pinned, members))
            ),
        };
        assert!(matches!(err, PinnedSetRefused::SetRefused { .. }), "{err}");
        let rendered = err.to_string();
        assert!(
            rendered.contains("99..=99"),
            "the declared range: {rendered}"
        );
        assert!(rendered.contains("never builds"), "{rendered}");
    }

    // The fetch-when-unchanged mode keeps building locally, as it always has.
    let mut served = Served::new(&fixture);
    let reason = built_locally(
        choose_arm(
            request(FetchMode::WhenUnchanged, PinnedMembers::SdkSidecars),
            Ok(fingerprint("cd")),
            served.acquire(),
        )
        .unwrap(),
    );
    assert!(reason.contains("99..=99"), "{reason}");
}

/// A member whose bytes are not the ones the signed root declares is refused
/// at fetch and leaves nothing installed.
#[test]
fn pinned_refuses_a_tampered_sidecar_member() {
    let _env = unsigned_env();
    let name = sidecar_archive_name(GuestLibc::Musl);
    let mut tampered = well_formed_archive("0.0.1-member", GuestLibc::Musl);
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let fixture = set_with_sidecars(Some(fingerprint("cd"))).serve_instead(&name, tampered);
    let mut served = Served::new(&fixture);

    let (set, _) = adopted(
        choose_arm(
            request(FetchMode::Pinned, PinnedMembers::SdkSidecars),
            Ok(fingerprint("ab")),
            served.acquire(),
        )
        .unwrap(),
    );
    let cache = tempfile::tempdir().unwrap();
    let err = fetch_sidecars_from_set(&set, arch(), cache.path())
        .expect_err("a substituted member must be refused");
    assert!(err.to_string().contains(&name), "{err}");
    assert!(
        crate::sdk_sidecar::image_set_sidecar_resolver(
            cache.path(),
            &set.member_cache(),
            arch(),
            GuestLibc::Musl
        )
        .is_err(),
        "the refused member must not be recorded as installed"
    );
}

/// Sidecars are required members of every set, so a set lacking one is
/// refused when it is acquired — under `pinned`, as a refusal.
#[test]
fn pinned_refuses_a_set_without_a_sidecar_member() {
    let _env = unsigned_env();
    let fixture = set_with_sidecars(Some(fingerprint("cd"))).without_member(
        ImageSetRole::SdkSidecar(GuestLibc::Musl),
        MemberTarget::Arch(arch()),
    );
    let mut served = Served::new(&fixture);
    let err = match choose_arm(
        request(FetchMode::Pinned, PinnedMembers::SdkSidecars),
        Ok(fingerprint("ab")),
        served.acquire(),
    ) {
        Err(err) => err,
        Ok(_) => panic!("a set without a sidecar member must be refused"),
    };
    assert!(
        err.to_string()
            .contains(&format!("sdk_sidecar_musl/{}", arch())),
        "{err}"
    );
}

/// Dev members are optional. A set without them builds locally under `1` (the
/// existing behaviour) and is refused under `pinned`, naming the release.
#[test]
fn a_set_without_dev_members_builds_locally_when_unchanged_and_refuses_when_pinned() {
    let _env = unsigned_env();
    let fp = fingerprint("ab");
    let fixture = set_with_sidecars(Some(fp.clone()));

    let mut served = Served::new(&fixture);
    let reason = built_locally(
        choose_arm(
            request(FetchMode::WhenUnchanged, PinnedMembers::DevDefaultImage),
            Ok(fp.clone()),
            served.acquire(),
        )
        .unwrap(),
    );
    assert!(
        reason.contains("publishes no dev default image"),
        "{reason}"
    );

    let mut served = Served::new(&fixture);
    let err = match choose_arm(
        request(FetchMode::Pinned, PinnedMembers::DevDefaultImage),
        Ok(fp),
        served.acquire(),
    ) {
        Err(err) => err,
        Ok(_) => panic!("a set without dev members must be refused under `pinned`"),
    };
    assert!(
        matches!(err, PinnedSetRefused::MembersMissing { .. }),
        "{err}"
    );
    let rendered = err.to_string();
    let tag = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .to_string();
    assert!(rendered.contains(&tag), "{rendered}");
    assert!(rendered.contains("nothing is built"), "{rendered}");
}

/// The dev image under `pinned`: adopted with a mismatched fingerprint, and
/// installed as the dev slot's layout from digest-checked members; a
/// substituted rootfs is refused.
#[test]
fn pinned_adopts_the_dev_image_and_refuses_a_tampered_rootfs() {
    let _env = unsigned_env();
    let fixture = with_dev_members(set_with_sidecars(Some(fingerprint("cd"))));
    let mut served = Served::new(&fixture);
    let (set, comparison) = adopted(
        choose_arm(
            request(FetchMode::Pinned, PinnedMembers::DevDefaultImage),
            Ok(fingerprint("ab")),
            served.acquire(),
        )
        .unwrap(),
    );
    assert!(matches!(comparison, SourceComparison::Differs { .. }));
    let dir = tempfile::tempdir().unwrap();
    set.fetch_dev_workload(arch(), dir.path())
        .expect("the dev members install");
    assert_eq!(
        std::fs::read(dir.path().join("rootfs.ext4")).unwrap(),
        b"dev-rootfs"
    );

    let rootfs = format!("default-microvm-dev-rootfs-{}.ext4", arch());
    let tampered = fixture.serve_instead(&rootfs, b"dev-rootfX".to_vec());
    let mut served = Served::new(&tampered);
    let (set, _) = adopted(
        choose_arm(
            request(FetchMode::Pinned, PinnedMembers::DevDefaultImage),
            Ok(fingerprint("ab")),
            served.acquire(),
        )
        .unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let err = set
        .fetch_dev_workload(arch(), dir.path())
        .expect_err("a substituted dev rootfs must be refused");
    assert!(
        err.downcast_ref::<ImageSetMemberError>()
            .is_some_and(|e| matches!(e, ImageSetMemberError::DigestMismatch { .. })),
        "{err:#}"
    );
    assert!(!dir.path().join("rootfs.ext4").exists());
}

#[test]
fn dev_members_match_only_with_both_variants_and_a_matching_fingerprint() {
    let _env = unsigned_env();
    let fp = fingerprint("ab");
    let mut served = Served::new(&set_with_sidecars(Some(fp.clone())));
    let set = served.acquire()().unwrap();
    assert!(
        !set_dev_members_match_tree(&set, arch(), &fp),
        "the current train has no dev members, so nothing adopts"
    );

    let mut served = Served::new(&with_dev_members(set_with_sidecars(Some(fp.clone()))));
    let set = served.acquire()().unwrap();
    assert!(set_dev_members_match_tree(&set, arch(), &fp));
    assert!(
        !set_dev_members_match_tree(&set, arch(), &fingerprint("cd")),
        "a fingerprint mismatch must not adopt the dev slot either"
    );
}
