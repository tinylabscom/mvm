//! `HvfBuilderVm` — the HVF builder as a `mvm_build::builder_vm::
//! BuilderVm`, so it plugs into the existing builder dispatch (approach A). It
//! reuses the backend-agnostic runtime helpers (`stage_job_dir` renders the
//! flake `cmd.sh`, `acquire_nix_store_image_lock` allocates the persistent Nix
//! store, `finalize_flake_job` reads the artifact) and drives the boot + disk
//! transport through [`BuilderRunner`].
//!
//! The adapter lives here (not in mvm-build) because `BuilderRunner`/`VmmDriver`
//! sit above mvm-build; mvm-cli — which sees both crates — selects it for
//! `--builder hvf`.
//!
//! Image resolution (an HVF-bootable kernel + a rootfs whose baked
//! `mvm-host-vm-init` speaks the disk transport) is supplied by the caller. The
//! self-hosting bootstrap (`mvm_build::rootfs_inject`) produces such a rootfs;
//! wiring an auto-resolver that re-bakes on demand is the remaining follow-up.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mvm_build::builder_vm::{
    BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError, builder_vm_cache_dir,
};
use mvm_build::builder_vm_runtime::{
    acquire_nix_store_image_lock, finalize_flake_job, read_job_result_with_diagnostics,
    shell_job_exit_error, stage_job_dir, stage_shell_job_dir,
};

use super::runner::{BuilderBuild, BuilderRunner};
use mvm_backends::driver::hvf::HvfDriver;

/// Default persistent nix-store disk size (GiB → MiB). Matches the other
/// builders' generous sparse allocation; the guest formats + seeds it.
const DEFAULT_NIX_STORE_MIB: u32 = 64 * 1024;
/// Default output-disk size (MiB): must exceed the built rootfs + sidecars tar.
const DEFAULT_OUTPUT_MIB: u32 = 4 * 1024;
/// Default builder resources.
const DEFAULT_VCPUS: u32 = 4;
const DEFAULT_MEMORY_MIB: u32 = 16 * 1024;

/// The HVF builder VM, exposed through the `BuilderVm` seam.
pub struct HvfBuilderVm {
    /// arm64 boot `Image` for the builder VM (HVF-bootable).
    kernel: PathBuf,
    /// Builder rootfs whose baked `mvm-host-vm-init` speaks the disk transport.
    rootfs: PathBuf,
    /// Optional seeded Nix store closure NAR, resolved alongside the builder
    /// image when it carries one. `None` (the common case today) attaches no
    /// closure-seed share at all.
    closure_nar: Option<PathBuf>,
    nix_store_mib: u32,
    output_mib: u32,
    vcpus: u32,
    memory_mib: u32,
}

impl HvfBuilderVm {
    /// Build against a resolved HVF builder image (kernel + disk-transport rootfs).
    pub fn new(kernel: PathBuf, rootfs: PathBuf) -> Self {
        Self {
            kernel,
            rootfs,
            closure_nar: None,
            nix_store_mib: DEFAULT_NIX_STORE_MIB,
            output_mib: DEFAULT_OUTPUT_MIB,
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
        }
    }

    /// Override the builder VM resources (vcpus, RAM in MiB).
    pub fn with_resources(mut self, vcpus: u32, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    /// Run a narrow builder shell job on the HVF builder backend.
    ///
    /// This mirrors the qemu/libkrun shell-job contract closely enough to reuse
    /// the same live read-only runtime-overlay proof shape: `/work` is the
    /// caller-supplied tree, `/out` receives proof artifacts, and `/job/cmd.sh`
    /// runs under the builder guest's `mvm-host-vm-init`.
    pub fn run_shell_script(
        &self,
        job: &mvm_build::libkrun_builder::BuilderShellJob,
    ) -> Result<mvm_build::libkrun_builder::BuilderShellResult, BuilderVmError> {
        validate_shell_job(job)?;

        let cache = builder_vm_cache_dir();
        let nix_store_lock = acquire_nix_store_image_lock(
            &cache,
            std::env::consts::ARCH,
            u64::from(self.nix_store_mib),
        )?;

        let job_id = unique_job_id();
        let job_dir = cache.join("jobs").join(&job_id);
        stage_shell_job_dir(&job_dir, &job.script)?;

        let host_bin_dir = cache.join("shell-job-empty-mvm-bins");
        std::fs::create_dir_all(&host_bin_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating HVF builder shell-job host bin dir {}: {e}",
                host_bin_dir.display()
            ))
        })?;

        let name = mvm_core::naming::builder_shell_vm_name(&job_id);
        let runtime_overlay = require_runtime_overlay_ext4()?;
        let outcome = BuilderRunner::new(HvfDriver::new())
            .build(&BuilderBuild {
                name: &name,
                kernel: &self.kernel,
                rootfs: &self.rootfs,
                nix_store: nix_store_lock.path(),
                job_dir: &job_dir,
                work_src: &job.work_dir,
                host_bin_dir: &host_bin_dir,
                runtime_overlay: Some(runtime_overlay.as_path()),
                closure_nar: None,
                output_size: u64::from(self.output_mib) << 20,
                vcpus: self.vcpus,
                memory_mib: self.memory_mib,
            })
            .map_err(|e| map_runner_failure(format!("hvf builder shell job: {e}")))?;
        if !outcome.stopped {
            return Err(map_runner_failure(
                "hvf builder VM shell job did not power off within the deadline".into(),
            ));
        }

        let vm_state_dir = mvm_core::config::vm_state_dir(&name);
        let result = read_job_result_with_diagnostics(&outcome.output_dir, &vm_state_dir)?;
        if result.exit_code != 0 {
            return Err(shell_job_exit_error(result.exit_code, &result.stderr_tail));
        }

        Ok(mvm_build::libkrun_builder::BuilderShellResult {
            job_dir: outcome.output_dir,
            vm_state_dir,
        })
    }

    /// Attach a seeded Nix store closure NAR resolved from the builder image.
    /// Every `run_build` after this call packs the NAR onto the input disk
    /// under `closure-seed/`; omitting this call (the default) attaches
    /// nothing, so a builder image without a closure boots exactly as before
    /// this seam existed.
    pub fn with_closure_nar(mut self, closure_nar: Option<PathBuf>) -> Self {
        self.closure_nar = closure_nar;
        self
    }
}

/// A unique per-build job id (pid + monotonic-ish nanos); mirrors the other
/// builders' `unique_job_id`, which is `pub(crate)` to mvm-build.
fn unique_job_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

/// Boot / disk-transport / power-off failures are VMM-level (the builder VM
/// could not run the build), so the auto-detect fallback retries the next
/// backend rather than surfacing a false build error.
fn map_runner_failure(detail: String) -> BuilderVmError {
    BuilderVmError::HvfVmmFailed { detail }
}

/// Resolve (or build) the runtime overlay the lean HVF builder rootfs sources
/// its guest binaries from, failing closed when it is unavailable.
///
/// The HVF builder is always a lean `Rootfs` builder (kernel + rootfs whose
/// baked image bakes no guest binaries), so a missing overlay silently strands
/// the guest agent — it must be fatal. Reuses the shared resolver so the cache
/// layout and source-checkout rebuild policy stay single-sourced. Mapped to
/// [`BuilderVmError::RuntimeOverlayUnavailable`] (not a VMM-level failure), so
/// it surfaces unchanged with no auto-fallback to another builder backend.
fn require_runtime_overlay_ext4() -> Result<PathBuf, BuilderVmError> {
    mvm_build::libkrun_builder::require_runtime_overlay_ext4()
        .map_err(|e| BuilderVmError::RuntimeOverlayUnavailable(format!("{e:#}")))
}

fn validate_shell_job(
    job: &mvm_build::libkrun_builder::BuilderShellJob,
) -> Result<(), BuilderVmError> {
    if !job.work_dir.is_dir() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "shell job work_dir must be a directory: {}",
            job.work_dir.display()
        )));
    }
    std::fs::create_dir_all(&job.artifact_out).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating artifact_out {}: {e}",
            job.artifact_out.display()
        ))
    })?;
    if job.script.trim().is_empty() {
        return Err(BuilderVmError::NixBuildFailed(
            "builder shell script is empty".to_string(),
        ));
    }
    if !job.extra_disks.is_empty() {
        return Err(BuilderVmError::NotYetImplemented);
    }
    Ok(())
}

/// Recursively mirror `src` directory contents into `dst` (created if absent).
/// The HVF builder extracts artifacts to its own VM output dir; downstream code
/// (the dev-build pipeline and slot registration) reads from the caller's
/// `artifact_out`, so the artifacts must be copied across.
fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

impl BuilderVm for HvfBuilderVm {
    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // The install pipeline isn't wired for any backend yet.
        if matches!(job, BuilderJob::Install { .. }) {
            return Err(BuilderVmError::NotYetImplemented);
        }

        let cache = builder_vm_cache_dir();
        // Persistent nix-store disk (the guest formats + seeds it, reuses it warm).
        let nix_store_lock = acquire_nix_store_image_lock(
            &cache,
            std::env::consts::ARCH,
            u64::from(self.nix_store_mib),
        )?;

        // Stage the job dir: renders the flake `cmd.sh` (the same one the
        // libkrun builder runs). Override mode threads the workspace src.
        let job_id = unique_job_id();
        let job_dir = cache.join("jobs").join(&job_id);
        stage_job_dir(
            &job_dir,
            job,
            mounts.staged_user_flake.as_deref(),
            mounts
                .staged_user_flake
                .as_ref()
                .map(|_| mounts.flake_src.as_path()),
        )?;

        // Boot the builder VM over the hvf VMM + disk transport; the guest
        // runs cmd.sh and tars its artifacts back onto the output disk.
        let name = format!("mvm-hvf-builder-{job_id}");
        let runtime_overlay = require_runtime_overlay_ext4()?;
        let outcome = BuilderRunner::new(HvfDriver::new())
            .build(&BuilderBuild {
                name: &name,
                kernel: &self.kernel,
                rootfs: &self.rootfs,
                nix_store: nix_store_lock.path(),
                job_dir: &job_dir,
                work_src: &mounts.flake_src,
                host_bin_dir: &mounts.host_bin_dir,
                runtime_overlay: Some(runtime_overlay.as_path()),
                closure_nar: self.closure_nar.as_deref(),
                output_size: u64::from(self.output_mib) << 20,
                vcpus: self.vcpus,
                memory_mib: self.memory_mib,
            })
            .map_err(|e| map_runner_failure(format!("hvf builder run: {e}")))?;
        if !outcome.stopped {
            return Err(map_runner_failure(
                "hvf builder VM did not power off within the deadline".into(),
            ));
        }

        // The output tar (extracted into `output_dir`) carries rootfs.ext4 +
        // meta + result + boot-timings. The disk-transport path lands them in
        // the VM's own `output_dir`, so mirror them into the caller's requested
        // `artifact_out` — the dev-build pipeline and slot registration read
        // `artifact_out`, not `output_dir`.
        if outcome.output_dir != mounts.artifact_out {
            copy_tree(&outcome.output_dir, &mounts.artifact_out).map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "mirroring builder artifacts {} -> {}: {e}",
                    outcome.output_dir.display(),
                    mounts.artifact_out.display()
                ))
            })?;
        }
        finalize_flake_job(&outcome.output_dir, &mounts.artifact_out, &job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::libkrun_builder::BuilderShellJob;

    #[test]
    fn install_jobs_are_not_yet_implemented() {
        let b = HvfBuilderVm::new("/img/Image".into(), "/img/rootfs.ext4".into());
        let job = BuilderJob::Install {
            spec_path: "/tmp/spec.json".into(),
        };
        let mounts = BuilderMounts {
            flake_src: "/work".into(),
            host_nix_store: None,
            artifact_out: "/out".into(),
            host_bin_dir: "/mvm-bins".into(),
            staged_user_flake: None,
        };
        assert!(matches!(
            b.run_build(&job, &mounts),
            Err(BuilderVmError::NotYetImplemented)
        ));
    }

    #[test]
    fn copy_tree_mirrors_files_and_subdirs() {
        let src = tempfile::TempDir::new().unwrap();
        let dst = tempfile::TempDir::new().unwrap();
        std::fs::write(src.path().join("rootfs.ext4"), b"root").unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub").join("meta.json"), b"{}").unwrap();

        copy_tree(src.path(), dst.path()).unwrap();

        assert_eq!(
            std::fs::read(dst.path().join("rootfs.ext4")).unwrap(),
            b"root"
        );
        assert_eq!(
            std::fs::read(dst.path().join("sub").join("meta.json")).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn unique_job_id_carries_the_pid() {
        let id = unique_job_id();
        assert!(id.starts_with(&std::process::id().to_string()));
        assert!(id.contains('-'));
    }

    #[test]
    fn with_resources_overrides_vcpus_and_memory() {
        let b = HvfBuilderVm::new("/k".into(), "/r".into()).with_resources(2, 2048);
        assert_eq!(b.vcpus, 2);
        assert_eq!(b.memory_mib, 2048);
    }

    #[test]
    fn closure_nar_defaults_to_none_and_is_settable() {
        let b = HvfBuilderVm::new("/k".into(), "/r".into());
        assert_eq!(b.closure_nar, None);
        let with_closure =
            HvfBuilderVm::new("/k".into(), "/r".into()).with_closure_nar(Some("/nar".into()));
        assert_eq!(with_closure.closure_nar, Some(PathBuf::from("/nar")));
    }

    #[test]
    fn runner_failure_maps_to_vmm_level_error() {
        let e = map_runner_failure("hvf builder VM did not power off".into());
        assert!(matches!(e, BuilderVmError::HvfVmmFailed { .. }));
    }

    #[test]
    fn shell_job_validation_rejects_missing_work_dir() {
        let out = tempfile::tempdir().expect("out");
        let job = BuilderShellJob {
            work_dir: out.path().join("missing"),
            artifact_out: out.path().to_path_buf(),
            script: "true".to_string(),
            extra_disks: Vec::new(),
        };
        let err = validate_shell_job(&job).expect_err("missing work dir refused");
        assert!(err.to_string().contains("work_dir must be a directory"));
    }

    #[test]
    fn shell_job_validation_rejects_extra_disks_for_now() {
        let work = tempfile::tempdir().expect("work");
        let out = tempfile::tempdir().expect("out");
        let disk = out.path().join("disk.ext4");
        std::fs::write(&disk, b"disk").expect("write disk");
        let job = BuilderShellJob {
            work_dir: work.path().to_path_buf(),
            artifact_out: out.path().to_path_buf(),
            script: "true".to_string(),
            extra_disks: vec![mvm_build::libkrun_builder::BuilderExtraDisk {
                id: "x".to_string(),
                path: disk,
                read_only: true,
            }],
        };
        assert!(matches!(
            validate_shell_job(&job),
            Err(BuilderVmError::NotYetImplemented)
        ));
    }
}
