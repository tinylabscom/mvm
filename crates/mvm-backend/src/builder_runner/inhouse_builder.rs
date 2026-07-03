//! `InHouseBuilderVm` — the in-house HVF builder as a `mvm_build::builder_vm::
//! BuilderVm`, so it plugs into the existing builder dispatch (approach A). It
//! reuses the backend-agnostic runtime helpers (`stage_job_dir` renders the
//! flake `cmd.sh`, `acquire_nix_store_image_lock` allocates the persistent Nix
//! store, `finalize_flake_job` reads the artifact) and drives the boot + disk
//! transport through [`BuilderRunner`].
//!
//! The adapter lives here (not in mvm-build) because `BuilderRunner`/`VmmDriver`
//! sit above mvm-build; mvm-cli — which sees both crates — selects it for
//! `--builder inhouse`.
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
    acquire_nix_store_image_lock, finalize_flake_job, stage_job_dir,
};

use super::runner::{BuilderBuild, BuilderRunner};
use crate::driver::InHouseDriver;

/// Default persistent nix-store disk size (GiB → MiB). Matches the other
/// builders' generous sparse allocation; the guest formats + seeds it.
const DEFAULT_NIX_STORE_MIB: u32 = 64 * 1024;
/// Default output-disk size (MiB): must exceed the built rootfs + sidecars tar.
const DEFAULT_OUTPUT_MIB: u32 = 4 * 1024;
/// Default builder resources.
const DEFAULT_VCPUS: u32 = 4;
const DEFAULT_MEMORY_MIB: u32 = 8 * 1024;

/// The in-house HVF builder VM, exposed through the `BuilderVm` seam.
pub struct InHouseBuilderVm {
    /// arm64 boot `Image` for the builder VM (HVF-bootable).
    kernel: PathBuf,
    /// Builder rootfs whose baked `mvm-host-vm-init` speaks the disk transport.
    rootfs: PathBuf,
    nix_store_mib: u32,
    output_mib: u32,
    vcpus: u32,
    memory_mib: u32,
}

impl InHouseBuilderVm {
    /// Build against a resolved HVF builder image (kernel + disk-transport rootfs).
    pub fn new(kernel: PathBuf, rootfs: PathBuf) -> Self {
        Self {
            kernel,
            rootfs,
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
    BuilderVmError::InHouseVmmFailed { detail }
}

impl BuilderVm for InHouseBuilderVm {
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
        // libkrun/vz builders run). Override mode threads the workspace src.
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

        // Boot the builder VM over the in-house VMM + disk transport; the guest
        // runs cmd.sh and tars its artifacts back onto the output disk.
        let name = format!("mvm-inhouse-builder-{job_id}");
        let outcome = BuilderRunner::new(InHouseDriver::new())
            .build(&BuilderBuild {
                name: &name,
                kernel: &self.kernel,
                rootfs: &self.rootfs,
                nix_store: nix_store_lock.path(),
                job_dir: &job_dir,
                work_src: &mounts.flake_src,
                host_bin_dir: &mounts.host_bin_dir,
                output_size: u64::from(self.output_mib) << 20,
                vcpus: self.vcpus,
                memory_mib: self.memory_mib,
            })
            .map_err(|e| map_runner_failure(format!("in-house builder run: {e}")))?;
        if !outcome.stopped {
            return Err(map_runner_failure(
                "in-house builder VM did not power off within the deadline".into(),
            ));
        }

        // The output tar (extracted into `output_dir`) carries rootfs.ext4 +
        // result + boot-timings — exactly what finalize reads.
        finalize_flake_job(&outcome.output_dir, &outcome.output_dir, &job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_jobs_are_not_yet_implemented() {
        let b = InHouseBuilderVm::new("/img/Image".into(), "/img/rootfs.ext4".into());
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
    fn unique_job_id_carries_the_pid() {
        let id = unique_job_id();
        assert!(id.starts_with(&std::process::id().to_string()));
        assert!(id.contains('-'));
    }

    #[test]
    fn with_resources_overrides_vcpus_and_memory() {
        let b = InHouseBuilderVm::new("/k".into(), "/r".into()).with_resources(2, 2048);
        assert_eq!(b.vcpus, 2);
        assert_eq!(b.memory_mib, 2048);
    }

    #[test]
    fn runner_failure_maps_to_vmm_level_error() {
        let e = map_runner_failure("in-house builder VM did not power off".into());
        assert!(matches!(e, BuilderVmError::InHouseVmmFailed { .. }));
    }
}
