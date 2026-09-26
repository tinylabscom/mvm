//! The end-to-end reader for a set built from the selected checkout, over
//! real git checkouts.

use std::path::PathBuf;

use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ImageSetError, ImageSetRole, ImageSetStage, ImageTrustTier, LOCAL_SET_MANIFEST_NAME,
    LocalImageSet, RepoIdentity, WorkloadImageProfile,
};
use mvm_core::packs::Sha256Hex;

use super::*;

const KERNEL: &[u8] = b"kernel bytes\n";
const KERNEL_NAME: &str = "workload-kernel-aarch64-vmlinux";

/// An image checkout, a paired mvm checkout, and a set directory beside
/// them, all in one temporary directory.
struct Pair {
    tmp: tempfile::TempDir,
    images: LocalImageCheckout,
}

impl Pair {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        images_checkout(&tmp.path().join("mvm-images"));
        let mvm = tmp.path().join("mvm");
        write(&mvm.join("Cargo.toml"), "[workspace]\n");
        git(&mvm, &["init", "-q"]);
        git(&mvm, &["add", "-A"]);
        git(&mvm, &["commit", "-q", "-m", "mvm"]);
        let images = open(&tmp.path().join("mvm-images")).unwrap();
        Self { tmp, images }
    }

    fn mvm(&self) -> PathBuf {
        self.tmp.path().join("mvm")
    }

    fn set_dir(&self) -> PathBuf {
        self.tmp.path().join("set")
    }

    /// Write a one-member set recording `images` and `mvm` as the
    /// identities it was built from.
    fn emit(&self, images: &RepoIdentity, mvm: &RepoIdentity) {
        let dir = self.set_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(KERNEL_NAME), KERNEL).unwrap();
        let manifest = serde_json::json!({
            "schema_version": 2,
            "set_version": "0.0.0-local",
            "issued_at": "2026-01-01T00:00:00Z",
            "producer": {"local_checkouts": {"images": images, "mvm": mvm}},
            "mvm_source_commit": mvm.commit,
            "compatibility": {
                "guest_agent_protocol": {"min": 2, "max": 2},
                "builder_cache_contract": 1,
                "builder_boot_abi": 0
            },
            "nix_inputs": {
                "flake_locks": [{
                    "reference": "mvm-images:flake.lock",
                    "lock_hash": Sha256Hex::from_bytes(b"lock").as_str()
                }],
                "source_revisions": []
            },
            "members": [{
                "role": {"workload_kernel": "default_tenant"},
                "target": {"arch": "aarch64"},
                "boot_protocol": "linux_direct",
                "artifacts": [{
                    "name": KERNEL_NAME,
                    "format": {"kernel": "image"},
                    "sha256": Sha256Hex::from_bytes(KERNEL).as_str(),
                    "size": KERNEL.len()
                }],
                "required_capabilities": ["virtio_vsock"]
            }]
        });
        std::fs::write(
            dir.join(LOCAL_SET_MANIFEST_NAME),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    /// A set recording both checkouts exactly as they are now.
    fn emit_current(&self) {
        let mvm = probe_identity(&self.mvm()).unwrap();
        self.emit(self.images.identity(), &mvm);
    }

    fn read_with(
        &self,
        mvm: &Path,
        roles: &[ImageSetRole],
    ) -> Result<LocalImageSet, LocalSetError> {
        self.images.read_local_image_set(&LocalSetRequest {
            mvm_checkout: mvm,
            set_dir: &self.set_dir(),
            arch: GuestArch::Aarch64,
            roles,
        })
    }

    fn read(&self) -> Result<LocalImageSet, LocalSetError> {
        self.read_with(
            &self.mvm(),
            &[ImageSetRole::WorkloadKernel(
                WorkloadImageProfile::DefaultTenant,
            )],
        )
    }
}

fn refusal(err: &LocalSetError) -> &ImageSetError {
    err.refusal()
        .unwrap_or_else(|| panic!("expected a verifier refusal, got: {err}"))
}

#[test]
fn a_set_built_from_the_pair_as_it_is_reads_at_the_local_dev_tier() {
    let pair = Pair::new();
    pair.emit_current();

    let set = pair.read().unwrap();

    assert_eq!(set.tier(), ImageTrustTier::LocalDev);
    assert_eq!(&set.checkouts.images, pair.images.identity());
    assert_eq!(set.checkouts.mvm, probe_identity(&pair.mvm()).unwrap());
    assert_eq!(set.artifacts.len(), 1);
}

#[test]
fn an_mvm_edit_after_the_build_makes_the_set_stale() {
    let pair = Pair::new();
    pair.emit_current();
    write(&pair.mvm().join("Cargo.toml"), "[workspace]\n# edited\n");

    let err = pair.read().unwrap_err();

    assert!(
        matches!(
            refusal(&err),
            ImageSetError::StaleLocalSet {
                checkout: "mvm",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(refusal(&err).stage(), ImageSetStage::Freshness);
}

#[test]
fn an_mvm_commit_after_the_build_makes_the_set_stale() {
    let pair = Pair::new();
    pair.emit_current();
    write(&pair.mvm().join("new.rs"), "fn main() {}\n");
    git(&pair.mvm(), &["add", "-A"]);
    git(&pair.mvm(), &["commit", "-q", "-m", "more"]);

    let err = pair.read().unwrap_err();

    assert!(
        matches!(
            refusal(&err),
            ImageSetError::StaleLocalSet {
                checkout: "mvm",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn a_set_recording_another_image_state_is_stale() {
    let pair = Pair::new();
    let mvm = probe_identity(&pair.mvm()).unwrap();
    let other = RepoIdentity {
        commit: pair.images.identity().commit.clone(),
        worktree: WorktreeState::Dirty {
            fingerprint: Sha256Hex::from_bytes(b"another tree"),
        },
    };
    pair.emit(&other, &mvm);

    let err = pair.read().unwrap_err();

    assert!(
        matches!(
            refusal(&err),
            ImageSetError::StaleLocalSet {
                checkout: "mvm-images",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn an_image_edit_after_selection_is_refused_before_the_set_is_read() {
    let pair = Pair::new();
    pair.emit_current();
    write(&pair.tmp.path().join("mvm-images/flake.nix"), "# edited\n");

    let err = pair.read().unwrap_err();

    assert!(
        matches!(
            err,
            LocalSetError::Selection(ImageSourceError::Changed { .. })
        ),
        "{err}"
    );
}

#[test]
fn a_role_the_set_lacks_is_refused() {
    let pair = Pair::new();
    pair.emit_current();

    let err = pair
        .read_with(&pair.mvm(), &[ImageSetRole::BuilderVm])
        .unwrap_err();

    assert!(
        matches!(refusal(&err), ImageSetError::Incomplete { .. }),
        "{err}"
    );
}

#[test]
fn a_set_for_another_architecture_is_refused() {
    let pair = Pair::new();
    pair.emit_current();

    let err = pair
        .images
        .read_local_image_set(&LocalSetRequest {
            mvm_checkout: &pair.mvm(),
            set_dir: &pair.set_dir(),
            arch: GuestArch::X86_64,
            roles: &[],
        })
        .unwrap_err();

    assert!(
        matches!(refusal(&err), ImageSetError::WrongArchitecture { .. }),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_manifest_is_refused() {
    let pair = Pair::new();
    pair.emit_current();
    let manifest = pair.set_dir().join(LOCAL_SET_MANIFEST_NAME);
    let elsewhere = pair.tmp.path().join("elsewhere.json");
    std::fs::rename(&manifest, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &manifest).unwrap();

    let err = pair.read().unwrap_err();

    assert!(
        matches!(err, LocalSetError::ManifestNotRegularFile { .. }),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_artifact_is_refused() {
    let pair = Pair::new();
    pair.emit_current();
    let artifact = pair.set_dir().join(KERNEL_NAME);
    let elsewhere = pair.tmp.path().join("kernel-elsewhere");
    std::fs::rename(&artifact, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &artifact).unwrap();

    let err = pair.read().unwrap_err();

    assert!(
        matches!(refusal(&err), ImageSetError::ArtifactNotRegularFile { .. }),
        "{err}"
    );
}

#[test]
fn a_missing_manifest_is_refused() {
    let pair = Pair::new();

    let err = pair.read().unwrap_err();

    assert!(
        matches!(err, LocalSetError::ManifestUnreadable { .. }),
        "{err}"
    );
}

#[test]
fn an_mvm_path_that_is_not_a_checkout_root_is_refused() {
    let pair = Pair::new();
    pair.emit_current();
    std::fs::create_dir_all(pair.mvm().join("crates")).unwrap();

    let err = pair.read_with(&pair.mvm().join("crates"), &[]).unwrap_err();

    assert!(
        matches!(&err, LocalSetError::MvmCheckout { detail, .. }
            if detail.contains("not the root of its git checkout")),
        "{err}"
    );
}
