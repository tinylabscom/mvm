//! Where guest images come from, and how far they are trusted.
//!
//! One line carries everything a bug report about an image needs to be
//! reproduced: the trust tier, the selected source, and the identity of both
//! repositories involved — commit and working-tree state for the image
//! checkout when one is selected, and for the mvm checkout this binary was
//! built from.

use mvm_build::artifact_acquisition::{DistributionChannel, compiled_channel};
use mvm_build::image_source::{
    ImageSource, ImageSourceError, MVM_IMAGES_DIR_ENV, RepoIdentity, configured_images_dir,
    mvm_source_checkout, probe_identity, resolve_image_source,
};

use super::Check;

/// What this binary was built from.
#[derive(Debug)]
enum MvmOrigin {
    ReleaseBuild,
    Checkout(RepoIdentity),
    Unreadable(String),
}

impl MvmOrigin {
    fn detect(channel: DistributionChannel) -> Self {
        match mvm_source_checkout(channel) {
            None => Self::ReleaseBuild,
            Some(root) => match probe_identity(&root) {
                Ok(identity) => Self::Checkout(identity),
                Err(detail) => Self::Unreadable(detail),
            },
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::ReleaseBuild => "mvm release build".to_string(),
            Self::Checkout(identity) => format!("mvm {identity}"),
            Self::Unreadable(detail) => format!("mvm checkout identity unreadable: {detail}"),
        }
    }
}

pub(super) fn image_source_check() -> Check {
    let channel = compiled_channel();
    let configured = configured_images_dir();
    let selected = resolve_image_source(channel, configured.as_deref());
    image_source_line(&selected, &MvmOrigin::detect(channel))
}

/// `<tier> — <source> — <identities>`, the same three-segment shape as the
/// builder backend and boot image lines. A refused selection fails the check:
/// the variable is set and the images it asks for cannot be used.
fn image_source_line(selected: &Result<ImageSource, ImageSourceError>, mvm: &MvmOrigin) -> Check {
    let (ok, info) = match selected {
        Ok(source @ ImageSource::Released) => (
            true,
            format!(
                "{} — released image set pinned by the image lock — {}",
                source.tier(),
                mvm.describe()
            ),
        ),
        Ok(source @ ImageSource::LocalCheckout(checkout)) => (
            true,
            format!(
                "{} — ${MVM_IMAGES_DIR_ENV}={} — mvm-images {}, {}; image builds do not \
                 consume this selection yet and still use the in-tree nix/images",
                source.tier(),
                checkout.root().display(),
                checkout.identity(),
                mvm.describe()
            ),
        ),
        Ok(source @ ImageSource::InTree { root }) => (
            true,
            format!(
                "{} — in-tree image flakes under {}/nix/images — {}",
                source.tier(),
                root.display(),
                mvm.describe()
            ),
        ),
        Err(error) => (false, format!("refused — {error} — {}", mvm.describe())),
    };
    Check {
        name: "image source",
        category: "platform",
        ok,
        info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::image_source::{LocalImageCheckout, WorktreeState};
    use mvm_core::image_set::GitCommit;
    use mvm_core::util::test_env::TestEnv;

    fn mvm_checkout() -> MvmOrigin {
        MvmOrigin::Checkout(RepoIdentity {
            commit: GitCommit::new("a".repeat(40)).unwrap(),
            worktree: WorktreeState::Clean,
        })
    }

    #[test]
    fn the_released_default_reports_the_release_tier_and_the_mvm_commit() {
        let c = image_source_line(&Ok(ImageSource::Released), &mvm_checkout());
        assert!(c.ok);
        assert_eq!(c.name, "image source");
        assert!(c.info.starts_with("verified-release — "), "{}", c.info);
        assert!(c.info.contains(&"a".repeat(40)), "{}", c.info);
        assert!(c.info.contains("(clean)"), "{}", c.info);
        assert_eq!(c.info.matches(" — ").count(), 2, "{}", c.info);
    }

    #[test]
    fn a_contributor_build_reports_its_in_tree_images_as_local_dev() {
        let c = image_source_line(
            &Ok(ImageSource::InTree {
                root: std::path::PathBuf::from("/src/mvm"),
            }),
            &mvm_checkout(),
        );
        assert!(c.ok);
        assert!(c.info.starts_with("local-dev — in-tree"), "{}", c.info);
        assert!(c.info.contains("/src/mvm/nix/images"), "{}", c.info);
    }

    #[test]
    fn a_release_build_says_so_instead_of_a_commit() {
        let c = image_source_line(&Ok(ImageSource::Released), &MvmOrigin::ReleaseBuild);
        assert!(c.info.ends_with("mvm release build"), "{}", c.info);
    }

    #[test]
    fn a_refused_selection_fails_the_check_and_names_why() {
        let c = image_source_line(
            &Err(ImageSourceError::RefusedInReleaseBuild),
            &MvmOrigin::ReleaseBuild,
        );
        assert!(!c.ok);
        assert!(c.info.starts_with("refused — "), "{}", c.info);
        assert!(c.info.contains(MVM_IMAGES_DIR_ENV), "{}", c.info);
    }

    /// End to end through the environment: a configured path that is not a
    /// checkout is reported as refused, never as the released set.
    #[test]
    fn a_configured_path_that_is_not_a_checkout_is_reported_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set(MVM_IMAGES_DIR_ENV, tmp.path().join("missing"));

        let c = image_source_check();

        assert!(!c.ok, "{}", c.info);
        assert!(!c.info.contains("verified-release"), "{}", c.info);
    }

    #[test]
    fn a_local_checkout_reports_both_identities_and_the_local_tier() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for marker in mvm_build::image_source::IMAGES_CHECKOUT_MARKERS {
            let path = dir.join(marker);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "#\n").unwrap();
        }
        for args in [
            &["init", "-q"][..],
            &["add", "-A"][..],
            &["commit", "-q", "-m", "images"][..],
        ] {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                ])
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env_remove("GIT_DIR")
                .env_remove("GIT_WORK_TREE")
                .env_remove("GIT_INDEX_FILE")
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        let checkout = LocalImageCheckout::open(dir).unwrap();
        let commit = checkout.identity().commit.to_string();

        let c = image_source_line(&Ok(ImageSource::LocalCheckout(checkout)), &mvm_checkout());

        assert!(c.ok);
        assert!(c.info.starts_with("local-dev — "), "{}", c.info);
        assert!(
            c.info.contains(&format!("mvm-images {commit} (clean)")),
            "{}",
            c.info
        );
        assert!(
            c.info.contains(&format!("mvm {}", "a".repeat(40))),
            "{}",
            c.info
        );
    }
}
