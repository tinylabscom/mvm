//! One flake build through a builder VM, as a request and a result.
//!
//! [`dev_build`](crate::pipeline::dev_build) builds a flake for `mvmctl
//! build`: it picks the attribute from a profile, stages the output into the
//! dev build cache, and reports through a shell environment. A caller that
//! already knows its flake attribute and wants the artifacts where it asked
//! for them needs none of that. This is the narrower path: mounts and job from
//! a [`BuildRequest`], one [`BuilderVm::run_build`], and a [`BuilderResult`]
//! naming what was produced.
//!
//! The result always has a guest sidecar. The runtime refuses to boot a rootfs
//! without one, so a build that produced a rootfs and no sidecar is reported
//! here, where the build log is, and not at a boot some time later.
//!
//! A result also says how long the build took and where its logs are; a
//! failure carries a stable [`FailureCategory`], read with
//! [`failure_category`], so a caller can choose a message or a retry posture
//! without parsing the error text.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;

use crate::builder_backend_select as bbs;
use crate::builder_job_contract::{
    BOOT_TIMINGS_FILE, FailureCategory, NIX_STDERR_LOG, NIX_STDOUT_LOG, bounded_tail,
};
use crate::builder_protocol::BootTimingsWire;
use crate::builder_vm::{
    BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError, SIDECAR_FILENAME,
};

/// One flake attribute to build, and where its inputs and outputs live on the
/// host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    /// The flake's source directory, mounted read-only at `/work`.
    pub workspace_root: PathBuf,
    /// The flake reference as the builder sees it, for example `/work`.
    pub flake_ref: String,
    /// The attribute to build, for example
    /// `packages.aarch64-linux.default`.
    pub attr_path: String,
    /// Where the builder writes the rootfs, the kernel, and the sidecar.
    pub artifact_out: PathBuf,
    /// A host directory to reuse as the builder's Nix store, if any.
    pub host_nix_store: Option<PathBuf>,
    /// The directory holding mvm's builder binaries, mounted at `/mvm-bins`.
    pub host_bin_dir: PathBuf,
}

/// What a flake build left on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderResult {
    pub rootfs_path: PathBuf,
    /// Absent when the flake emits no kernel of its own.
    pub kernel_path: Option<PathBuf>,
    /// The guest sidecar beside the rootfs. Always present on disk.
    pub sidecar_path: PathBuf,
    /// The leading hash segment of the build's Nix store path.
    pub revision_hash: String,
    /// SHA-256 of the flake's lock file, when the builder recorded one.
    pub lock_hash: Option<String>,
    /// Whether the image allows console access, when the flake says.
    pub accessible: Option<bool>,
    /// How long the build took.
    pub timings: BuildTimings,
    /// Where the build's logs are.
    pub logs: BuildLogs,
}

/// How long a build took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildTimings {
    /// The whole builder run as the host saw it: boot, build and teardown.
    pub total_ms: u64,
    /// How long the job ran inside the guest, when the guest reported it.
    pub build_ms: Option<u64>,
    /// The guest's boot phases, when it recorded them.
    pub boot: Option<BootTimingsWire>,
}

/// Where a build's logs are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildLogs {
    /// The build's full stderr, when the builder kept it.
    pub stderr: Option<PathBuf>,
    /// The build's full stdout, when the builder kept it.
    pub stdout: Option<PathBuf>,
    /// The end of the job's stderr, bounded by the job contract.
    pub stderr_tail: String,
}

/// The stable category of a failure from [`run_builder_for_request`] or
/// [`run_builder_for_request_on`]. An error that did not come from the
/// builder is [`FailureCategory::Unknown`].
pub fn failure_category(err: &anyhow::Error) -> FailureCategory {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<BuilderVmError>())
        .map_or(FailureCategory::Unknown, BuilderVmError::failure_category)
}

/// Build `request` on the builder backend this host resolves to.
///
/// The backend is chosen the way every other build chooses it: `--builder`,
/// then `MVM_BUILDER_BACKEND`, then auto-detect. A backend this process has no
/// constructor for refuses by name.
pub fn run_builder_for_request(request: &BuildRequest) -> Result<BuilderResult> {
    let selected = bbs::resolve_choice(None);
    let explicit = bbs::resolve_env_override().is_some();
    bbs::run_with_builder_fallback_anyhow(selected, explicit, |choice| {
        let builder = bbs::try_resolve_builder_backend(Some(choice)).map_err(anyhow::Error::new)?;
        run_builder_for_request_on(request, builder.as_ref())
    })
}

/// Build `request` on `builder`.
pub fn run_builder_for_request_on(
    request: &BuildRequest,
    builder: &dyn BuilderVm,
) -> Result<BuilderResult> {
    let started = Instant::now();
    let artifacts = builder
        .run_build(&job_for(request), &mounts_for(request))
        // Kept as a downcastable source, not a string, so the backend
        // fallback can still tell a VMM failure from a build failure, and
        // `failure_category` can read the category back.
        .map_err(|e| anyhow::Error::new(e).context("builder VM"))?;
    let total_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    result_from(artifacts, &request.artifact_out, total_ms)
}

fn job_for(request: &BuildRequest) -> BuilderJob {
    BuilderJob::Flake {
        flake_ref: request.flake_ref.clone(),
        attr_path: request.attr_path.clone(),
    }
}

fn mounts_for(request: &BuildRequest) -> BuilderMounts {
    BuilderMounts {
        flake_src: request.workspace_root.clone(),
        host_nix_store: request.host_nix_store.clone(),
        artifact_out: request.artifact_out.clone(),
        host_bin_dir: request.host_bin_dir.clone(),
        staged_user_flake: None,
    }
}

fn result_from(
    artifacts: BuilderArtifacts,
    artifact_out: &Path,
    total_ms: u64,
) -> Result<BuilderResult> {
    let BuilderArtifacts::Image {
        rootfs_path,
        kernel_path,
        revision_hash,
        lock_hash,
        accessible,
    } = artifacts
    else {
        return Err(output_contract(
            "builder VM returned install-volume artifacts for a flake build".to_string(),
        ));
    };
    let sidecar_path = sidecar_beside(&rootfs_path)?;
    // The outcome was already checked against the job contract when the
    // backend finalized the build; a builder that reports over another channel
    // leaves none, and then there is no guest-side time or tail to report.
    let outcome = crate::builder_vm_runtime::parse_job_result(artifact_out).ok();
    Ok(BuilderResult {
        rootfs_path,
        kernel_path,
        sidecar_path,
        revision_hash,
        lock_hash,
        accessible,
        timings: BuildTimings {
            total_ms,
            build_ms: outcome.as_ref().and_then(|o| o.build_ms),
            boot: read_boot_timings(artifact_out),
        },
        logs: BuildLogs {
            stderr: existing(artifact_out.join(NIX_STDERR_LOG)),
            stdout: existing(artifact_out.join(NIX_STDOUT_LOG)),
            stderr_tail: outcome
                .map(|o| bounded_tail(&o.stderr_tail).to_string())
                .unwrap_or_default(),
        },
    })
}

fn read_boot_timings(artifact_out: &Path) -> Option<BootTimingsWire> {
    let body = std::fs::read_to_string(artifact_out.join(BOOT_TIMINGS_FILE)).ok()?;
    serde_json::from_str(&body).ok()
}

fn existing(path: PathBuf) -> Option<PathBuf> {
    path.is_file().then_some(path)
}

fn output_contract(detail: String) -> anyhow::Error {
    anyhow::Error::new(BuilderVmError::JobFailed {
        category: FailureCategory::OutputContract,
        detail,
    })
}

fn sidecar_beside(rootfs: &Path) -> Result<PathBuf> {
    let dir = rootfs.parent().ok_or_else(|| {
        output_contract(format!(
            "rootfs path {} has no parent directory",
            rootfs.display()
        ))
    })?;
    let sidecar = dir.join(SIDECAR_FILENAME);
    if !sidecar.is_file() {
        return Err(output_contract(format!(
            "the build wrote {} without {SIDECAR_FILENAME} beside it; the runtime refuses to boot \
             a rootfs with no sidecar, so this flake's output cannot be used as built",
            rootfs.display(),
        )));
    }
    Ok(sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder_job_contract::{BUILDER_JOB_CONTRACT_VERSION, JobOutcome, RESULT_FILE};
    use crate::builder_vm::BuilderCapabilities;

    /// Writes what a one-shot guest leaves in the output directory.
    struct GuestOutput {
        sidecar: bool,
        fail: Option<FailureCategory>,
    }

    impl BuilderVm for GuestOutput {
        fn run_build(
            &self,
            _job: &BuilderJob,
            mounts: &BuilderMounts,
        ) -> Result<BuilderArtifacts, BuilderVmError> {
            if let Some(category) = self.fail {
                return Err(BuilderVmError::JobFailed {
                    category,
                    detail: "the guest classified this failure".to_string(),
                });
            }
            let out = &mounts.artifact_out;
            std::fs::write(out.join("rootfs.ext4"), b"rootfs").unwrap();
            if self.sidecar {
                std::fs::write(out.join(SIDECAR_FILENAME), b"{}").unwrap();
            }
            let outcome = JobOutcome {
                contract_version: BUILDER_JOB_CONTRACT_VERSION,
                exit_code: 0,
                stderr_tail: "built".to_string(),
                failure: None,
                build_ms: Some(1500),
            };
            std::fs::write(
                out.join(RESULT_FILE),
                serde_json::to_string(&outcome).unwrap(),
            )
            .unwrap();
            std::fs::write(out.join(NIX_STDERR_LOG), b"building\n").unwrap();
            std::fs::write(
                out.join(BOOT_TIMINGS_FILE),
                serde_json::to_string(&BootTimingsWire {
                    job_start_ms: Some(100),
                    job_end_ms: Some(1600),
                    ..BootTimingsWire::default()
                })
                .unwrap(),
            )
            .unwrap();
            Ok(BuilderArtifacts::Image {
                rootfs_path: out.join("rootfs.ext4"),
                kernel_path: None,
                revision_hash: "abc".to_string(),
                lock_hash: None,
                accessible: None,
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

    fn request(root: &Path) -> BuildRequest {
        BuildRequest {
            workspace_root: root.to_path_buf(),
            flake_ref: "/work".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
            artifact_out: root.to_path_buf(),
            host_nix_store: None,
            host_bin_dir: root.to_path_buf(),
        }
    }

    #[test]
    fn a_result_carries_the_guest_timings_and_log_locations() {
        let dir = tempfile::tempdir().unwrap();
        let builder = GuestOutput {
            sidecar: true,
            fail: None,
        };
        let result = run_builder_for_request_on(&request(dir.path()), &builder).unwrap();
        assert_eq!(result.timings.build_ms, Some(1500));
        assert_eq!(result.timings.boot.and_then(|b| b.job_end_ms), Some(1600));
        assert_eq!(result.logs.stderr, Some(dir.path().join(NIX_STDERR_LOG)));
        assert_eq!(result.logs.stdout, None);
        assert_eq!(result.logs.stderr_tail, "built");
    }

    #[test]
    fn a_result_without_a_guest_outcome_still_reports_host_time() {
        // A builder that reports over its own channel leaves no outcome file.
        struct NoOutcome;
        impl BuilderVm for NoOutcome {
            fn run_build(
                &self,
                _job: &BuilderJob,
                mounts: &BuilderMounts,
            ) -> Result<BuilderArtifacts, BuilderVmError> {
                let out = &mounts.artifact_out;
                std::fs::write(out.join("rootfs.ext4"), b"rootfs").unwrap();
                std::fs::write(out.join(SIDECAR_FILENAME), b"{}").unwrap();
                Ok(BuilderArtifacts::Image {
                    rootfs_path: out.join("rootfs.ext4"),
                    kernel_path: None,
                    revision_hash: "abc".to_string(),
                    lock_hash: None,
                    accessible: None,
                })
            }
            fn run_stage0(
                &self,
                _: &Path,
                _: &str,
                _: &Path,
                _: &Path,
                _: &Path,
            ) -> Result<(), BuilderVmError> {
                Err(BuilderVmError::NotYetImplemented)
            }
            fn capabilities(&self) -> BuilderCapabilities {
                BuilderCapabilities::default()
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let result = run_builder_for_request_on(&request(dir.path()), &NoOutcome).unwrap();
        assert_eq!(result.timings.build_ms, None);
        assert_eq!(result.timings.boot, None);
        assert_eq!(result.logs.stderr_tail, "");
    }

    #[test]
    fn a_rootfs_without_a_sidecar_is_an_output_contract_failure() {
        let dir = tempfile::tempdir().unwrap();
        let builder = GuestOutput {
            sidecar: false,
            fail: None,
        };
        let err = run_builder_for_request_on(&request(dir.path()), &builder).unwrap_err();
        assert_eq!(failure_category(&err), FailureCategory::OutputContract);
        assert!(err.to_string().contains(SIDECAR_FILENAME), "{err}");
    }

    #[test]
    fn a_guest_classified_failure_keeps_its_category_through_the_error_chain() {
        let dir = tempfile::tempdir().unwrap();
        let builder = GuestOutput {
            sidecar: true,
            fail: Some(FailureCategory::Fetch),
        };
        let err = run_builder_for_request_on(&request(dir.path()), &builder).unwrap_err();
        assert_eq!(failure_category(&err), FailureCategory::Fetch);
    }

    #[test]
    fn an_error_from_outside_the_builder_is_unknown() {
        assert_eq!(
            failure_category(&anyhow::anyhow!("not a builder error")),
            FailureCategory::Unknown
        );
    }
}
