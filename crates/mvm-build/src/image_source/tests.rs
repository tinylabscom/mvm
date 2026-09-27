use std::path::Path;
use std::process::Command;

use mvm_core::util::test_env::TestEnv;

use super::*;
use mvm_core::image_set::ImageTrustTier;

/// Runs `git` in `dir` isolated from the developer's configuration and from
/// any repository the test process itself runs inside.
fn git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=mvm-test",
            "-c",
            "user.email=mvm-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
    ] {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

/// A committed directory carrying every marker an `mvm-images` checkout has.
fn images_checkout(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for marker in IMAGES_CHECKOUT_MARKERS {
        write(&dir.join(marker), &format!("# {marker}\n"));
    }
    git(dir, &["init", "-q"]);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "images"]);
}

fn open(path: &Path) -> Result<LocalImageCheckout, ImageSourceError> {
    LocalImageCheckout::open(path)
}

#[test]
fn a_sibling_checkout_is_the_contributor_default_when_nothing_is_configured() {
    let tmp = tempfile::tempdir().unwrap();
    // <tmp>/work/mvm with a sibling <tmp>/mvm-images.
    let workspace = tmp.path().join("mvm");
    std::fs::create_dir_all(&workspace).unwrap();
    let sibling = tmp.path().join("mvm-images");
    images_checkout(&sibling);

    let source = select_with_discovery(DistributionChannel::Source, None, Some(&workspace))
        .expect("the sibling resolves");
    assert!(
        matches!(source, ImageSource::LocalCheckout(_)),
        "a valid sibling is the contributor default: {source:?}"
    );
}

#[test]
fn the_configured_checkout_outranks_the_sibling_and_stays_strict() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("mvm");
    std::fs::create_dir_all(&workspace).unwrap();
    let sibling = tmp.path().join("mvm-images");
    images_checkout(&sibling);
    let chosen = tmp.path().join("chosen-images");
    images_checkout(&chosen);

    let source =
        select_with_discovery(DistributionChannel::Source, Some(&chosen), Some(&workspace))
            .expect("the configured checkout wins");
    match source {
        ImageSource::LocalCheckout(checkout) => {
            assert_eq!(
                checkout.root(),
                std::fs::canonicalize(&chosen).unwrap().as_path()
            );
        }
        other => panic!("expected the configured checkout, got {other:?}"),
    }

    let err = select_with_discovery(
        DistributionChannel::Source,
        Some(Path::new("/nonexistent")),
        Some(&workspace),
    )
    .expect_err("an unusable configured path is still an error, never a fall-through");
    assert!(err.to_string().contains(MVM_IMAGES_DIR_ENV), "{err}");
}

#[test]
fn a_discovered_sibling_that_is_not_usable_warns_and_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("mvm");
    std::fs::create_dir_all(&workspace).unwrap();
    let sibling = tmp.path().join("mvm-images");
    std::fs::create_dir_all(&sibling).unwrap();
    // Names itself (flake.nix) but is not a git checkout.
    write(&sibling.join("flake.nix"), "# not a checkout\n");

    // Not the contributor default's concern on a release channel: discovery
    // never runs there.
    let released = select_with_discovery(DistributionChannel::Release, None, Some(&workspace))
        .expect("release ignores the sibling");
    assert!(matches!(released, ImageSource::Released), "{released:?}");

    // A contributor build falls back to the in-tree answer rather than
    // breaking: the warning carries the reason.
    let source = select_with_discovery(DistributionChannel::Source, None, Some(&workspace))
        .expect("an unusable discovered sibling falls back, never hard-fails");
    assert!(
        !matches!(source, ImageSource::LocalCheckout(_)),
        "fell back instead of selecting the unusable sibling: {source:?}"
    );
}

#[test]
fn no_sibling_and_nothing_configured_keeps_the_in_tree_window() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("mvm");
    std::fs::create_dir_all(&workspace).unwrap();
    let source = select_with_discovery(DistributionChannel::Source, None, Some(&workspace))
        .expect("no sibling resolves without error");
    // The tests' own checkout carries the in-tree flakes, so this is InTree
    // here; the assertion that matters is that nothing discovered a
    // nonexistent sibling.
    assert!(
        !matches!(source, ImageSource::LocalCheckout(_)),
        "{source:?}"
    );
}

#[test]
fn recorded_tier_reads_the_default_image_sidecar_and_fails_closed() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.set("MVM_HOME", home.path());
    let variant = home.path().join("cache/default-microvm/prod");
    std::fs::create_dir_all(&variant).unwrap();
    let rootfs = variant.join("rootfs.ext4");
    write(&rootfs, "rootfs\n");

    // Nothing cached yet: no sidecar records a tier.
    assert_eq!(recorded_tier_for(&rootfs), None);

    let sidecar = |source: &str| {
        format!(
            "{{\"name\": \"mvm-default-microvm\", \"accessible\": false, \"sealed\": true, \"entrypointKind\": \"command\", \"initSystem\": \"busybox\", \"expectedBootMs\": 300, \"agentBinary\": \"real\", \"rootlessEntrypoint\": true, \"hypervisor\": \"libkrun\", \"protocolVersion\": 2, \"generatorRev\": \"abc\", \"source\": \"{source}\" }}"
        )
    };
    write(&variant.join("mvm-meta.json"), &sidecar("fetched"));
    assert_eq!(
        recorded_tier_for(&rootfs),
        Some(ImageTrustTier::VerifiedRelease)
    );
    for local in ["built-local", "local-pair", "something-unrecognized"] {
        write(&variant.join("mvm-meta.json"), &sidecar(local));
        assert_eq!(
            recorded_tier_for(&rootfs),
            Some(ImageTrustTier::LocalDev),
            "{local}"
        );
    }
}

#[test]
fn recorded_tier_reads_the_builder_cache_provenance_and_scopes_to_the_caches() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.set("MVM_HOME", home.path());
    let arch_dir = home.path().join("cache/builder-vm/aarch64");
    std::fs::create_dir_all(&arch_dir).unwrap();
    let vmlinux = arch_dir.join("vmlinux");
    write(&vmlinux, "kernel\n");

    // No provenance yet: unrecognized as a managed entry.
    assert_eq!(recorded_tier_for(&vmlinux), None);

    let provenance = |kind: &str| format!("{{\"schema_version\": 1, \"source_kind\": \"{kind}\"}}");
    write(
        &arch_dir.join(".mvm-provenance.json"),
        &provenance("fetched"),
    );
    assert_eq!(
        recorded_tier_for(&vmlinux),
        Some(ImageTrustTier::VerifiedRelease)
    );
    for local in ["local_pair", "source_checkout_stage0", "unrecognized"] {
        write(&arch_dir.join(".mvm-provenance.json"), &provenance(local));
        assert_eq!(
            recorded_tier_for(&vmlinux),
            Some(ImageTrustTier::LocalDev),
            "{local}"
        );
    }

    // Outside the managed caches there is no recorded tier.
    let outside = home.path().join("elsewhere/rootfs.ext4");
    write(&outside, "rootfs\n");
    assert_eq!(recorded_tier_for(&outside), None);
}

#[test]
fn an_mvm_checkout_is_the_workspace_manifest_not_the_image_flakes() {
    // The probe that keys automatic builds must not hinge on the in-tree
    // image flakes: removing them (the end state of the extraction) must
    // not turn a contributor build into an installed one.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("mvm");
    std::fs::create_dir_all(&root).unwrap();
    write(&root.join("Cargo.toml"), "[workspace]\n");
    assert_eq!(
        mvm_source_checkout_at(&root).as_deref(),
        Some(root.as_path())
    );

    let bare = tmp.path().join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    assert!(
        mvm_source_checkout_at(&bare).is_none(),
        "a directory with no workspace manifest is not an mvm checkout"
    );
}

#[test]
fn a_clean_checkout_records_its_canonical_root_commit_and_state() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);

    let checkout = open(&dir).unwrap();

    assert_eq!(checkout.root(), std::fs::canonicalize(&dir).unwrap());
    assert_eq!(checkout.identity().worktree, WorktreeState::Clean);
    assert_eq!(checkout.identity().commit.as_str().len(), 40);
    checkout.reverify().unwrap();
}

#[test]
fn a_dirty_checkout_is_fingerprinted_by_what_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);

    write(&dir.join("flake.nix"), "# edited\n");
    let edited = open(&dir).unwrap().identity().clone();
    assert!(edited.worktree.is_dirty());

    write(&dir.join("flake.nix"), "# edited differently\n");
    let edited_again = open(&dir).unwrap().identity().clone();
    assert_eq!(edited.commit, edited_again.commit);
    assert_ne!(
        edited.worktree, edited_again.worktree,
        "two different dirty trees on one commit must not share a fingerprint"
    );
}

#[test]
fn an_untracked_file_contributes_its_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);

    write(&dir.join("images/new.nix"), "a\n");
    let first = open(&dir).unwrap().identity().worktree.clone();
    write(&dir.join("images/new.nix"), "b\n");
    let second = open(&dir).unwrap().identity().worktree.clone();

    assert!(first.is_dirty());
    assert_ne!(first, second);
}

#[test]
fn a_path_that_does_not_exist_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let err = open(&tmp.path().join("absent")).unwrap_err();
    assert!(
        matches!(err, ImageSourceError::Unresolvable { .. }),
        "{err}"
    );
}

#[test]
fn a_file_is_not_a_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("flake.nix");
    write(&file, "{}\n");
    let err = open(&file).unwrap_err();
    assert!(
        matches!(err, ImageSourceError::NotADirectory { .. }),
        "{err}"
    );
}

#[test]
fn a_directory_without_the_image_sources_is_not_a_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm");
    // What an mvm checkout looks like from here: a flake, but its images live
    // under nix/images rather than images/.
    write(&dir.join("flake.nix"), "{}\n");
    write(&dir.join("flake.lock"), "{}\n");
    write(&dir.join("nix/images/builder-vm/flake.nix"), "{}\n");
    git(&dir, &["init", "-q"]);

    let err = open(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            ImageSourceError::NotAnImagesCheckout {
                marker: "kernel/flake.nix",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn traversal_is_resolved_before_the_checkout_is_judged() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);
    std::fs::create_dir_all(tmp.path().join("elsewhere")).unwrap();

    // Leaving the checkout through `..` lands somewhere that is judged on its
    // own merits, not on the checkout it was spelled through.
    let escaped = dir.join("images").join("..").join("..").join("elsewhere");
    let err = open(&escaped).unwrap_err();
    assert!(
        matches!(err, ImageSourceError::NotAnImagesCheckout { .. }),
        "{err}"
    );

    // Staying inside it resolves to the canonical root, with no `..` left.
    let inside = open(&dir.join("images").join("..")).unwrap();
    assert_eq!(inside.root(), std::fs::canonicalize(&dir).unwrap());
    assert!(
        !inside
            .root()
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    );
}

#[test]
fn a_subdirectory_of_a_checkout_is_not_its_root() {
    let tmp = tempfile::tempdir().unwrap();
    let outer = tmp.path().join("outer");
    // A tree that carries the markers but sits inside another repository.
    for marker in IMAGES_CHECKOUT_MARKERS {
        write(&outer.join("nested").join(marker), "#\n");
    }
    git(&outer, &["init", "-q"]);

    let err = open(&outer.join("nested")).unwrap_err();
    assert!(
        matches!(err, ImageSourceError::NotTheRepositoryRoot { .. }),
        "{err}"
    );
}

#[test]
fn markers_without_a_repository_are_not_a_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("copied");
    for marker in IMAGES_CHECKOUT_MARKERS {
        write(&dir.join(marker), "#\n");
    }
    // Keep git from finding a repository above the tempdir.
    let mut env = TestEnv::new();
    env.set(
        "GIT_CEILING_DIRECTORIES",
        std::fs::canonicalize(tmp.path()).unwrap(),
    );

    let err = open(&dir).unwrap_err();
    assert!(
        matches!(err, ImageSourceError::NotAGitCheckout { .. }),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_marker_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);
    let outside = tmp.path().join("outside.nix");
    write(&outside, "# not in the checkout\n");
    std::fs::remove_file(dir.join("flake.nix")).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("flake.nix")).unwrap();

    let err = open(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            ImageSourceError::SymlinkedMarker {
                marker: "flake.nix",
                ..
            }
        ),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn a_retargeted_selection_symlink_is_caught_on_reverify() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    images_checkout(&first);
    images_checkout(&second);
    let link = tmp.path().join("mvm-images");
    std::os::unix::fs::symlink(&first, &link).unwrap();

    let selected = open(&link).unwrap();
    assert_eq!(selected.root(), std::fs::canonicalize(&first).unwrap());

    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&second, &link).unwrap();

    let err = selected.reverify().unwrap_err();
    assert!(matches!(err, ImageSourceError::Substituted { .. }), "{err}");
}

#[test]
fn an_edit_after_selection_is_caught_on_reverify() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);
    let selected = open(&dir).unwrap();

    write(&dir.join("images/builder-vm/image.nix"), "# changed\n");

    let err = selected.reverify().unwrap_err();
    assert!(matches!(err, ImageSourceError::Changed { .. }), "{err}");
}

#[test]
fn no_configured_path_and_no_in_tree_images_selects_the_released_set() {
    for channel in [DistributionChannel::Source, DistributionChannel::Release] {
        let source = select_image_source(channel, None, None).unwrap();
        assert_eq!(source, ImageSource::Released);
        assert_eq!(source.tier(), ImageTrustTier::VerifiedRelease);
    }
}

#[test]
fn a_contributor_build_defaults_to_its_in_tree_images_as_local_dev() {
    let root = PathBuf::from("/src/mvm");
    let source =
        select_image_source(DistributionChannel::Source, None, Some(root.clone())).unwrap();
    assert_eq!(source, ImageSource::InTree { root });
    assert_eq!(source.tier(), ImageTrustTier::LocalDev);
}

#[test]
fn a_release_build_never_selects_in_tree_images() {
    let source = select_image_source(
        DistributionChannel::Release,
        None,
        Some(PathBuf::from("/src/mvm")),
    )
    .unwrap();
    assert_eq!(source, ImageSource::Released);
}

#[test]
fn a_configured_checkout_outranks_the_in_tree_images() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);

    let source = select_image_source(
        DistributionChannel::Source,
        Some(&dir),
        Some(PathBuf::from("/src/mvm")),
    )
    .unwrap();
    assert!(
        matches!(source, ImageSource::LocalCheckout(_)),
        "{source:?}"
    );
}

#[test]
fn this_contributor_build_finds_its_in_tree_images() {
    let root = in_tree_images(DistributionChannel::Source).expect("tests run from source");
    assert!(root.join(IN_TREE_IMAGE_MARKER).is_file());
    assert_eq!(in_tree_images(DistributionChannel::Release), None);
}

#[test]
fn a_contributor_build_selects_a_valid_checkout_as_local_dev() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);

    let source = resolve_image_source(DistributionChannel::Source, Some(&dir)).unwrap();

    assert!(matches!(source, ImageSource::LocalCheckout(_)));
    assert_eq!(source.tier(), ImageTrustTier::LocalDev);
}

#[test]
fn a_bad_configured_path_is_an_error_not_the_released_set() {
    let tmp = tempfile::tempdir().unwrap();
    let got = select_image_source(
        DistributionChannel::Source,
        Some(&tmp.path().join("missing")),
        Some(PathBuf::from("/src/mvm")),
    );
    assert!(got.is_err(), "fell back to {got:?}");
}

#[test]
fn a_release_build_refuses_even_a_valid_checkout() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("mvm-images");
    images_checkout(&dir);

    let err = resolve_image_source(DistributionChannel::Release, Some(&dir)).unwrap_err();
    assert!(
        matches!(err, ImageSourceError::RefusedInReleaseBuild),
        "{err}"
    );
    // Refused before the path is examined: a missing path is refused the same
    // way, so a release build's answer never depends on the local filesystem.
    let err = resolve_image_source(
        DistributionChannel::Release,
        Some(&tmp.path().join("missing")),
    )
    .unwrap_err();
    assert!(
        matches!(err, ImageSourceError::RefusedInReleaseBuild),
        "{err}"
    );
}

#[test]
fn production_admission_refuses_any_configured_checkout() {
    let path = Path::new("/nonexistent/mvm-images");
    assert!(matches!(
        refuse_in_production(Variant::Prod, Some(path)),
        Err(ImageSourceError::RefusedInProduction)
    ));
    refuse_in_production(Variant::Prod, None).unwrap();
    refuse_in_production(Variant::Dev, Some(path)).unwrap();
}

#[test]
fn the_variable_is_read_explicitly_and_empty_means_unset() {
    let mut env = TestEnv::new();
    env.remove(MVM_IMAGES_DIR_ENV);
    assert_eq!(configured_images_dir(), None);
    env.set(MVM_IMAGES_DIR_ENV, "");
    assert_eq!(configured_images_dir(), None);
    env.set(MVM_IMAGES_DIR_ENV, "../mvm-images");
    assert_eq!(
        configured_images_dir().as_deref(),
        Some(Path::new("../mvm-images"))
    );
}

#[test]
fn a_contributor_build_knows_its_own_checkout() {
    assert!(mvm_source_checkout(DistributionChannel::Release).is_none());
    let root = mvm_source_checkout(DistributionChannel::Source).expect("tests run from source");
    assert!(root.join("crates").join("mvm-build").is_dir());
}

/// The fingerprint is a wire format shared with the image repository's
/// manifest emitter, which computes it in Python. Both pin this value for the
/// same tree: one tracked edit, one untracked file, one untracked link.
#[cfg(unix)]
#[test]
fn the_dirty_fingerprint_matches_the_emitters_for_a_fixed_tree() {
    const EMITTER_FINGERPRINT: &str =
        "952dbae933d34ca2625e9964a3e919b48271a821117b03daf9a606382f7490f1";
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("r");
    write(&dir.join("a.txt"), "tracked\n");
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "fixture"]);
    write(&dir.join("a.txt"), "tracked\nchanged\n");
    write(&dir.join("u.txt"), "untracked\n");
    std::os::unix::fs::symlink("a.txt", dir.join("link")).unwrap();

    let identity = probe_identity(&dir).unwrap();

    assert_eq!(
        identity.worktree,
        WorktreeState::Dirty {
            fingerprint: mvm_core::packs::Sha256Hex::new(EMITTER_FINGERPRINT).unwrap()
        }
    );
}

mod builder_key;
mod cache;
mod local_set;
