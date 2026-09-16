//! `HvfStage0Vm` — bootstrapping a builder VM on the HVF VMM.
//!
//! A distinct type from [`HvfBuilderVm`](super::hvf_builder::HvfBuilderVm)
//! rather than another method on it, because the two need opposite things.
//! `HvfBuilderVm` is constructed *from* a builder image and cannot exist without
//! one; Stage 0 runs when no builder image exists, and produces the one that
//! type will later be built from. Folding both into one struct would mean a
//! kernel and rootfs field that are meaningless in half its lifetime.
//!
//! All the actual work is shared. The boot goes through
//! [`BuilderRunner`](super::runner::BuilderRunner), so this file holds only what
//! is specific to bootstrapping on this host: resolve a bootstrap kernel,
//! materialize the seed root, take the Stage 0 store lock, and turn the guest's
//! console into a result.

use std::path::{Path, PathBuf};

use mvm_build::builder_vm::{
    BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError,
    builder_vm_cache_dir,
};
use mvm_build::builder_vm_runtime::acquire_nix_store_image_lock_named;
use mvm_build::libkrun_builder::BuilderVmImage;
use mvm_build::stage0_host::{
    materialize_stage0_root_disk, prepopulate_stage0_nix_store_image, stage0_nix_store_image_name,
    stage0_result_from_console,
};

use super::hvf_builder::{copy_tree, unique_job_id};
use super::runner::{BuilderRunner, Stage0Run};
use mvm_backends::driver::hvf::HvfDriver;

/// Stage 0's dedicated persistent Nix store, sized to hold a kernel source tree
/// plus the builder closure.
const STAGE0_NIX_STORE_MIB: u64 = 64 * 1024;

/// Stage 0 builds in a tmpfs whose capacity is half of guest RAM, and the
/// builder image closure plus its final rootfs copy exceeds what the
/// steady-state builder is given. Matches the libkrun Stage 0 budget.
const STAGE0_MEMORY_MIB: u32 = 24 * 1024;
const STAGE0_VCPUS: u32 = 4;

/// The guest PID 1 Stage 0 boots. The seed carries exactly this path, and the
/// shared spec hardcodes it, so a caller asking for anything else is asking for
/// a boot that would panic on a missing init.
const STAGE0_ENTRY_PATH: &str = "/init";

/// Bootstraps a builder VM on the HVF VMM.
#[derive(Debug, Default)]
pub struct HvfStage0Vm {
    closure_nar: Option<PathBuf>,
}

impl HvfStage0Vm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a seeded Nix store closure NAR, which rides the existing input
    /// disk rather than adding a device.
    pub fn with_closure_nar(mut self, closure_nar: Option<PathBuf>) -> Self {
        self.closure_nar = closure_nar;
        self
    }
}

impl BuilderVm for HvfStage0Vm {
    /// Bootstrap-only. This type exists precisely for the window in which no
    /// builder image exists, so it cannot serve jobs that need one.
    fn capabilities(&self) -> BuilderCapabilities {
        BuilderCapabilities {
            stage0_bootstrap: true,
            dependency_install: false,
        }
    }

    fn run_build(
        &self,
        _job: &BuilderJob,
        _mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        Err(BuilderVmError::VmmUnavailable {
            requested: "hvf-stage0-build".to_string(),
            reason: "the hvf Stage 0 bootstrapper runs no build jobs; it exists to \
                     produce the builder image that HvfBuilderVm then builds with"
                .to_string(),
        })
    }

    fn run_stage0(
        &self,
        guest_root_dir: &Path,
        entry_path: &str,
        workspace_dir: &Path,
        artifact_out: &Path,
        host_bin_dir: &Path,
    ) -> Result<(), BuilderVmError> {
        if entry_path != STAGE0_ENTRY_PATH {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "the hvf Stage 0 boots {STAGE0_ENTRY_PATH} (the seed's PID 1); \
                 asked for {entry_path}"
            )));
        }
        validate_inputs(guest_root_dir, workspace_dir, host_bin_dir)?;
        std::fs::create_dir_all(artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating artifact_out {}: {e}",
                artifact_out.display()
            ))
        })?;

        // The one kernel that can be neither built nor resolved by the ordinary
        // policy: Stage 0 is what makes local kernel builds possible. Fetched
        // and digest-verified as a bootstrap seed.
        let cache_dir = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let kernel =
            mvm_build::stage0_kernel::resolve_bootstrap_kernel(&cache_dir, std::env::consts::ARCH)
                .map_err(|e| BuilderVmError::VmmUnavailable {
                    requested: "hvf-stage0-kernel".to_string(),
                    reason: e.to_string(),
                })?;

        let name = format!("mvm-stage0-hvf-{}", unique_job_id());
        let vm_state_dir = mvm_core::config::vm_state_dir(&name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Stage 0 state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;

        let root_disk = materialize_stage0_root_disk(guest_root_dir, &vm_state_dir)?;

        // Stage 0's store is separate from the steady-state builder's so a
        // bootstrap and a concurrent build never contend on the same flock.
        let builder_cache = builder_vm_cache_dir();
        let store_lock = acquire_nix_store_image_lock_named(
            &builder_cache,
            &stage0_nix_store_image_name(),
            STAGE0_NIX_STORE_MIB,
        )?;
        let seed_image =
            BuilderVmImage::new_root_dir(guest_root_dir.to_path_buf(), STAGE0_ENTRY_PATH);
        prepopulate_stage0_nix_store_image(&seed_image, store_lock.path())?;

        let outcome = BuilderRunner::new(HvfDriver::new())
            .stage0(&Stage0Run {
                name: &name,
                kernel: kernel.path(),
                root_disk: &root_disk,
                nix_store: store_lock.path(),
                workspace_src: workspace_dir,
                host_bin_dir,
                conf_dir: artifact_out,
                closure_nar: self.closure_nar.as_deref(),
                output_size: mvm_build::builder_disk_transport::OUTPUT_DISK_BYTES,
                vcpus: STAGE0_VCPUS,
                memory_mib: STAGE0_MEMORY_MIB,
            })
            .map_err(|e| BuilderVmError::HvfVmmFailed {
                detail: format!("hvf Stage 0: {e}"),
            })?;

        // Artifacts first, result second. The guest powers off on success and
        // failure alike, so a run that produced a kernel and rootfs before an
        // untidy teardown still has them worth keeping.
        if outcome.output_dir != artifact_out {
            copy_tree(&outcome.output_dir, artifact_out).map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "mirroring Stage 0 artifacts {} -> {}: {e}",
                    outcome.output_dir.display(),
                    artifact_out.display()
                ))
            })?;
        }

        // The console is the result channel: the VMM exit code only says the
        // guest powered off, which it does either way.
        stage0_result_from_console(&vm_state_dir.join("console.log"))
    }
}

/// Refuse a malformed request before any disk is materialized, so a caller
/// error does not surface as a boot failure deep in the run.
fn validate_inputs(
    guest_root_dir: &Path,
    workspace_dir: &Path,
    host_bin_dir: &Path,
) -> Result<(), BuilderVmError> {
    for (label, dir) in [
        ("guest_root_dir", guest_root_dir),
        ("workspace_dir", workspace_dir),
        ("host_bin_dir", host_bin_dir),
    ] {
        if !dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "hvf Stage 0 {label} must be an existing directory: {}",
                dir.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stage0_bootstrapper_declares_bootstrap_and_refuses_builds() {
        let vm = HvfStage0Vm::new();
        assert!(vm.capabilities().stage0_bootstrap);
        assert!(!vm.capabilities().dependency_install);

        // It exists for the window before a builder image exists, so a build
        // job has to be refused by name rather than attempted.
        match vm.run_build(
            &BuilderJob::Flake {
                flake_ref: "path:/work".into(),
                attr_path: "default".into(),
            },
            &BuilderMounts {
                flake_src: PathBuf::from("/work"),
                host_nix_store: Some(PathBuf::from("/nix")),
                artifact_out: PathBuf::from("/out"),
                host_bin_dir: PathBuf::from("/bins"),
                staged_user_flake: None,
            },
        ) {
            Err(BuilderVmError::VmmUnavailable { requested, .. }) => {
                assert_eq!(requested, "hvf-stage0-build");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    /// The seed carries exactly one PID 1 and the shared spec hardcodes it, so
    /// a mismatched request must refuse rather than boot into a missing init.
    #[test]
    fn a_non_seed_entry_path_is_refused_before_any_work() {
        let tmp = tempfile::tempdir().unwrap();
        let err = HvfStage0Vm::new()
            .run_stage0(
                tmp.path(),
                "/sbin/mvm-host-vm-init",
                tmp.path(),
                &tmp.path().join("out"),
                tmp.path(),
            )
            .expect_err("only the seed's own init is bootable here");
        assert!(err.to_string().contains("/init"), "{err}");
    }

    #[test]
    fn a_missing_input_directory_is_named_rather_than_failing_at_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let err = HvfStage0Vm::new()
            .run_stage0(
                &tmp.path().join("no-such-seed"),
                STAGE0_ENTRY_PATH,
                tmp.path(),
                &tmp.path().join("out"),
                tmp.path(),
            )
            .expect_err("a missing seed dir cannot bootstrap");
        assert!(err.to_string().contains("guest_root_dir"), "{err}");
    }
}
