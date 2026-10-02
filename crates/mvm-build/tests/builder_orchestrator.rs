//! A flake build through the orchestrator, against a builder that writes its
//! outputs the way the real ones do and never boots anything.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use mvm_build::builder_orchestrator::{BuildRequest, run_builder_for_request_on};
use mvm_build::builder_vm::{
    BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError,
    SIDECAR_FILENAME,
};

/// What the stub builder writes, and what it returns.
#[derive(Clone, Copy)]
enum Outcome {
    /// Rootfs, kernel and sidecar, as a complete flake build leaves them.
    Complete,
    /// Rootfs and kernel, no sidecar.
    NoSidecar,
    /// The nix build itself failed.
    BuildFails,
    /// Install-volume artifacts, which no flake build should return.
    InstallVolume,
}

struct StubBuilder {
    outcome: Outcome,
    seen: Mutex<Option<(BuilderJob, BuilderMounts)>>,
}

impl StubBuilder {
    fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> (BuilderJob, BuilderMounts) {
        self.seen
            .lock()
            .unwrap()
            .clone()
            .expect("run_build was called")
    }
}

impl BuilderVm for StubBuilder {
    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        *self.seen.lock().unwrap() = Some((job.clone(), mounts.clone()));
        let out = &mounts.artifact_out;
        match self.outcome {
            Outcome::BuildFails => {
                return Err(BuilderVmError::NixBuildFailed(
                    "attribute missing".to_string(),
                ));
            }
            Outcome::InstallVolume => {
                return Ok(BuilderArtifacts::InstallVolume {
                    volume_dir: out.join("volume"),
                    result_json_path: out.join("result.json"),
                });
            }
            Outcome::Complete | Outcome::NoSidecar => {}
        }
        std::fs::write(out.join("rootfs.ext4"), b"rootfs").unwrap();
        std::fs::write(out.join("vmlinux"), b"kernel").unwrap();
        if matches!(self.outcome, Outcome::Complete) {
            std::fs::write(out.join(SIDECAR_FILENAME), b"{}").unwrap();
        }
        Ok(BuilderArtifacts::Image {
            rootfs_path: out.join("rootfs.ext4"),
            kernel_path: Some(out.join("vmlinux")),
            revision_hash: "deadbeefcafebabe".to_string(),
            lock_hash: Some("lock-sha".to_string()),
            accessible: Some(false),
        })
    }

    fn run_stage0(
        &self,
        _guest_root_dir: &Path,
        _entry_path: &str,
        _workspace_dir: &Path,
        _artifact_out: &Path,
        _host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError> {
        Err(BuilderVmError::NotYetImplemented)
    }

    fn capabilities(&self) -> BuilderCapabilities {
        BuilderCapabilities::default()
    }
}

struct Dirs {
    _tmp: tempfile::TempDir,
    workspace: PathBuf,
    out: PathBuf,
    bins: PathBuf,
}

impl Dirs {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Self {
            workspace: tmp.path().join("workspace"),
            out: tmp.path().join("out"),
            bins: tmp.path().join("bins"),
            _tmp: tmp,
        };
        for dir in [&dirs.workspace, &dirs.out, &dirs.bins] {
            std::fs::create_dir_all(dir).unwrap();
        }
        dirs
    }

    fn request(&self) -> BuildRequest {
        BuildRequest {
            workspace_root: self.workspace.clone(),
            flake_ref: "/work".to_string(),
            attr_path: "packages.aarch64-linux.default".to_string(),
            artifact_out: self.out.clone(),
            host_nix_store: None,
            host_bin_dir: self.bins.clone(),
        }
    }
}

#[test]
fn a_complete_build_reports_every_artifact() {
    let dirs = Dirs::new();
    let builder = StubBuilder::new(Outcome::Complete);

    let result = run_builder_for_request_on(&dirs.request(), &builder).expect("build");

    assert_eq!(result.rootfs_path, dirs.out.join("rootfs.ext4"));
    assert_eq!(result.kernel_path, Some(dirs.out.join("vmlinux")));
    assert_eq!(result.sidecar_path, dirs.out.join(SIDECAR_FILENAME));
    assert_eq!(result.revision_hash, "deadbeefcafebabe");
    assert_eq!(result.lock_hash.as_deref(), Some("lock-sha"));
    assert_eq!(result.accessible, Some(false));
}

#[test]
fn the_request_becomes_one_flake_job_with_its_mounts() {
    let dirs = Dirs::new();
    let store = dirs.workspace.join("store");
    let request = BuildRequest {
        host_nix_store: Some(store.clone()),
        ..dirs.request()
    };
    let builder = StubBuilder::new(Outcome::Complete);

    run_builder_for_request_on(&request, &builder).expect("build");

    let (job, mounts) = builder.seen();
    assert_eq!(
        job,
        BuilderJob::Flake {
            flake_ref: "/work".to_string(),
            attr_path: "packages.aarch64-linux.default".to_string(),
        }
    );
    assert_eq!(
        mounts,
        BuilderMounts {
            flake_src: dirs.workspace.clone(),
            host_nix_store: Some(store),
            artifact_out: dirs.out.clone(),
            host_bin_dir: dirs.bins.clone(),
            staged_user_flake: None,
        }
    );
}

#[test]
fn a_build_without_a_sidecar_is_refused() {
    let dirs = Dirs::new();

    let err = run_builder_for_request_on(&dirs.request(), &StubBuilder::new(Outcome::NoSidecar))
        .expect_err("no sidecar");

    let message = format!("{err:#}");
    assert!(message.contains(SIDECAR_FILENAME), "{message}");
    assert!(message.contains("refuses to boot"), "{message}");
}

#[test]
fn a_builder_failure_keeps_its_typed_error() {
    let dirs = Dirs::new();

    let err = run_builder_for_request_on(&dirs.request(), &StubBuilder::new(Outcome::BuildFails))
        .expect_err("build fails");

    // The backend fallback reads the typed error out of the chain to tell a
    // VMM failure from a build failure, so it must not be flattened to text.
    assert!(
        err.chain().any(|cause| matches!(
            cause.downcast_ref::<BuilderVmError>(),
            Some(BuilderVmError::NixBuildFailed(_))
        )),
        "{err:#}"
    );
}

#[test]
fn install_volume_artifacts_from_a_flake_build_are_refused() {
    let dirs = Dirs::new();

    let err =
        run_builder_for_request_on(&dirs.request(), &StubBuilder::new(Outcome::InstallVolume))
            .expect_err("wrong artifact kind");

    assert!(format!("{err:#}").contains("install-volume"), "{err:#}");
}
