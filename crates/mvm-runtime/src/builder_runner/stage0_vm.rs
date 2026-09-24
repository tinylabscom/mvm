//! `Stage0Vm<D>` — bootstrapping a builder VM on any `VmmDriver`.
//!
//! Stage 0 builds the builder VM from nothing. It is the one builder path that
//! runs when no builder image exists, which is why it is a type of its own
//! rather than a method on [`DriverBuilderVm`](super::driver_builder::DriverBuilderVm):
//! that type is constructed *from* a builder image and cannot exist without
//! one, and folding both together would mean kernel and rootfs fields that are
//! meaningless for half its lifetime.
//!
//! Generic over the driver, because nothing about bootstrapping is
//! backend-specific. The boot goes through
//! [`BuilderRunner`](super::runner::BuilderRunner), which is itself generic, so
//! this file holds only the host-side work: resolve a bootstrap kernel,
//! materialize the seed root, take the Stage 0 store lock, and turn the guest's
//! console into a result. A backend that can boot a builder can bootstrap one —
//! HVF on macOS, Firecracker on Linux, QEMU anywhere, and a future Windows
//! driver for free.
//!
//! What a driver has to satisfy is small, and already true of all of them: a
//! writable ext4 root at `vda`, four more virtio-blk slots, one vsock channel
//! for egress, and a captured console. No virtio-fs, no guest NIC.

use std::path::{Path, PathBuf};

use mvm_build::builder_vm::BuilderVmImage;
use mvm_build::builder_vm::{
    BuilderArtifacts, BuilderCapabilities, BuilderJob, BuilderMounts, BuilderVm, BuilderVmError,
    builder_vm_cache_dir,
};
use mvm_build::builder_vm_image::unique_job_id;
use mvm_build::builder_vm_runtime::acquire_nix_store_image_lock_named;
use mvm_build::stage0_host::{
    invalidate_stage0_store_after_ext4_error, materialize_stage0_root_disk,
    prepopulate_stage0_nix_store_image, stage0_nix_store_image_name, stage0_result_from_console,
};

use super::driver_builder::copy_tree;
use super::runner::{BuilderRunner, Stage0Run};
use crate::driver::VmmDriver;

/// Stage 0's dedicated persistent Nix store, sized to hold a kernel source tree
/// plus the builder closure.
const STAGE0_NIX_STORE_MIB: u64 = 64 * 1024;

/// Stage 0 builds in a tmpfs whose capacity is half of guest RAM, and the
/// builder image closure plus its final rootfs copy exceeds what the
/// steady-state builder is given.
const STAGE0_MEMORY_MIB: u32 = 24 * 1024;
const STAGE0_VCPUS: u32 = 4;

/// The guest PID 1 Stage 0 boots. The seed carries exactly this path, and the
/// shared spec hardcodes it, so a caller asking for anything else is asking for
/// a boot that would panic on a missing init.
const STAGE0_ENTRY_PATH: &str = "/init";

/// Bootstraps a builder VM on `D`.
///
/// `D: Clone` because each run hands a driver to the `BuilderRunner` that owns
/// it for the boot, while this type is reusable. Every shipped driver is a
/// stateless handle, so the clone is free.
pub struct Stage0Vm<D: VmmDriver + Clone> {
    driver: D,
    closure_nar: Option<PathBuf>,
}

impl<D: VmmDriver + Clone + 'static> Stage0Vm<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            closure_nar: None,
        }
    }

    /// Attach a seeded Nix store closure NAR, which rides the existing input
    /// disk rather than adding a device.
    pub fn with_closure_nar(mut self, closure_nar: Option<PathBuf>) -> Self {
        self.closure_nar = closure_nar;
        self
    }
}

impl<D: VmmDriver + Clone + 'static> BuilderVm for Stage0Vm<D> {
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
            requested: format!("{}-stage0-build", self.driver.name()),
            reason: "the Stage 0 bootstrapper runs no build jobs; it exists to produce \
                     the builder image an ordinary builder then builds with"
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
                "Stage 0 boots {STAGE0_ENTRY_PATH} (the seed's PID 1); asked for {entry_path}"
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
                    requested: format!("{}-stage0-kernel", self.driver.name()),
                    reason: e.to_string(),
                })?;

        let name = format!("mvm-stage0-{}-{}", self.driver.name(), unique_job_id());
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

        let outcome = BuilderRunner::new(self.driver.clone()).stage0(&Stage0Run {
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
        });

        // Before anything can return: a guest that reported ext4 errors on its
        // store must not have that store handed to the next bootstrap, however
        // this run ends. The superblock alone does not say so when the store
        // is journaled.
        let console_log = vm_state_dir.join("console.log");
        invalidate_stage0_store_after_ext4_error(&console_log, store_lock.path())?;
        let outcome = outcome.map_err(|e| BuilderVmError::VmmFailed {
            detail: format!("{} Stage 0: {e}", self.driver.name()),
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
        stage0_result_from_console(&console_log)
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
                "Stage 0 {label} must be an existing directory: {}",
                dir.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_backends::driver::{fc::FcDriver, hvf::HvfDriver, qemu::QemuDriver};
    use mvm_backends::mock::MockDriver;

    #[test]
    fn the_stage0_bootstrapper_declares_bootstrap_and_refuses_builds() {
        let vm = Stage0Vm::new(MockDriver::default());
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
                assert!(requested.ends_with("-stage0-build"), "{requested}");
            }
            other => panic!("expected a named refusal, got {other:?}"),
        }
    }

    /// The point of the type being generic: the same bootstrapper exists for
    /// every shipped driver, so Linux/Firecracker and a future Windows backend
    /// need no Stage 0 of their own.
    #[test]
    fn a_stage0_bootstrapper_exists_for_every_shipped_driver() {
        let declared: Vec<BuilderCapabilities> = vec![
            Stage0Vm::new(HvfDriver::new()).capabilities(),
            Stage0Vm::new(FcDriver::new()).capabilities(),
            Stage0Vm::new(QemuDriver::new()).capabilities(),
            Stage0Vm::new(MockDriver::default()).capabilities(),
        ];
        assert!(
            declared.iter().all(|c| c.stage0_bootstrap),
            "every driver's Stage 0 must declare the bootstrap capability: {declared:?}"
        );
    }

    /// Each run names the backend it ran on, so a failure in a multi-backend
    /// host does not have to be attributed by guesswork.
    #[test]
    fn the_refusal_names_the_backend_it_was_asked_of() {
        let hvf = Stage0Vm::new(HvfDriver::new());
        let fc = Stage0Vm::new(FcDriver::new());
        let name_of = |vm: &dyn BuilderVm| match vm.run_build(
            &BuilderJob::Flake {
                flake_ref: "path:/work".into(),
                attr_path: "default".into(),
            },
            &BuilderMounts {
                flake_src: PathBuf::from("/work"),
                host_nix_store: None,
                artifact_out: PathBuf::from("/out"),
                host_bin_dir: PathBuf::from("/bins"),
                staged_user_flake: None,
            },
        ) {
            Err(BuilderVmError::VmmUnavailable { requested, .. }) => requested,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_ne!(
            name_of(&hvf),
            name_of(&fc),
            "two backends must not report the same Stage 0 identity"
        );
    }

    /// The seed carries exactly one PID 1 and the shared spec hardcodes it, so
    /// a mismatched request must refuse rather than boot into a missing init.
    #[test]
    fn a_non_seed_entry_path_is_refused_before_any_work() {
        let tmp = tempfile::tempdir().unwrap();
        let err = Stage0Vm::new(MockDriver::default())
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
        let err = Stage0Vm::new(MockDriver::default())
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
