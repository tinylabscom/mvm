//! Actual final-config handoff and conservative canonical-kernel retention.
//! The disk record is a private resource index, never execution authority.

use anyhow::{Context, Result, ensure};
use mvm_core::protocol::vm_backend::{BackendKind, VmStartConfig};
use mvm_vmm::driver::spec::{KernelImage, VmmSpec};
use mvm_vmm::driver::traits::RunningVm;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::runtime_evidence::RuntimeLifecycleLease;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelUse {
    version: u32,
    vm: String,
    generation: String,
    device: u64,
    inode: u64,
    #[cfg(unix)]
    instance: Option<mvm_core::protocol::hvf_control::HvfInstance>,
    /// Firecracker's lifetime evidence: the observed process, judged against
    /// the process table at release. Never set together with `instance`.
    #[serde(default)]
    process: Option<mvm_vmm::host::process_identity::ProcessIdentity>,
}

/// Owns the exact final config subsequently borrowed for endpoint/spec/boot.
pub(crate) struct KernelBoundLaunch {
    config: VmStartConfig,
    backend: BackendKind,
    record: PathBuf,
    #[cfg(unix)]
    kernel: Option<mvm_vmm::host::restore_image::VerifiedRestoreFile>,
}

impl KernelBoundLaunch {
    pub(crate) fn bind(
        config: VmStartConfig,
        backend: BackendKind,
        lifecycle: &RuntimeLifecycleLease,
    ) -> Result<Self> {
        let record = lifecycle.canonical_kernel_record();
        ensure!(
            !record_exists(&record)?,
            "a canonical kernel generation is still retained for this VM; stop/absence must be resolved before reuse"
        );
        #[cfg(unix)]
        let mut kernel = None;
        if let Some(digest) = &config.kernel_read_sha256 {
            ensure!(
                config.canonical_kernel.is_none(),
                "cannot mix producer byte continuity and canonical bundle custody"
            );
            ensure!(
                (cfg!(unix) && backend == BackendKind::Hvf)
                    || (cfg!(target_os = "linux") && backend == BackendKind::Firecracker),
                "this backend does not support producer kernel descriptor custody"
            );
            #[cfg(unix)]
            {
                // This is a data-continuity constraint, NOT an admission
                // capability. HVF still consumes the actual caller launch
                // registration; Firecracker retains its existing admission
                // and synchronous API startup path on the same Linux host.
                let source = Path::new(
                    config
                        .kernel_path
                        .as_deref()
                        .context("producer kernel missing")?,
                );
                kernel = Some(mvm_vmm::host::restore_image::VerifiedRestoreFile::prepare(
                    source,
                    record
                        .parent()
                        .context("kernel lifecycle directory missing")?,
                    digest,
                )?);
            }
        }
        if let Some(owner) = &config.canonical_kernel {
            // Other backends retain their existing explicit refusal until
            // they provide equally instance-bound lifetime evidence.
            ensure!(
                mvm_core::canonical_linux::supports_lifetime_custody(backend),
                "this backend does not support canonical kernel lifetime custody"
            );
            let host = mvm_build::stage0_kernel::current_image_set_protocol_support();
            // This layer owns artifact mechanics, not plan-admission authority.
            // The native supervisor requires the existing consumed caller
            // launch capability before using a canonical kernel descriptor.
            owner.retain_for_native_handoff(&config, backend, &host)?;
            #[cfg(unix)]
            {
                // Reuse the existing unlinked, read-only descriptor custody:
                // hash the private clone that the native child will consume.
                kernel = Some(mvm_vmm::host::restore_image::VerifiedRestoreFile::prepare(
                    &owner.kernel_path(),
                    owner.generation_dir(),
                    owner.kernel_sha256(),
                )?);
            }
            let generation = owner
                .generation_dir()
                .file_name()
                .and_then(|n| n.to_str())
                .context("kernel generation identity missing")?
                .to_owned();
            let (device, inode) = directory_identity(owner.generation_dir())?;
            let pending = KernelUse {
                version: 1,
                vm: config.name.clone(),
                generation,
                device,
                inode,
                #[cfg(unix)]
                instance: None,
                process: None,
            };
            mvm_core::util::atomic_io::write_private_new(&record, &serde_json::to_vec(&pending)?)?;
        }
        Ok(Self {
            config,
            backend,
            record,
            #[cfg(unix)]
            kernel,
        })
    }

    pub(crate) fn config(&self) -> &VmStartConfig {
        &self.config
    }

    #[cfg(unix)]
    pub(crate) fn verified_kernel(
        &self,
    ) -> Option<&mvm_vmm::host::restore_image::VerifiedRestoreFile> {
        self.kernel.as_ref()
    }

    #[cfg(not(unix))]
    pub(crate) fn boot(
        &self,
        driver: &dyn mvm_vmm::driver::traits::VmmDriver,
        spec: &VmmSpec,
    ) -> Result<Box<dyn RunningVm>> {
        self.before_boot(spec)?;
        driver.boot(spec)
    }

    #[cfg(unix)]
    pub(crate) fn boot_with_prepared_disks(
        &self,
        driver: &dyn mvm_vmm::driver::traits::VmmDriver,
        spec: &VmmSpec,
        disks: mvm_vmm::driver::prepared_disks::PreparedWritableDisks,
    ) -> Result<Box<dyn RunningVm>> {
        self.before_boot(spec)?;
        disks.validate_spec(spec)?;
        driver.boot_with_prepared_disks(spec, self.kernel.as_ref(), disks)
    }

    /// Validate the physical recipe passed to the driver, not a reconstructed
    /// client path or an author-supplied digest.
    pub(crate) fn before_boot(&self, spec: &VmmSpec) -> Result<()> {
        if self.config.kernel_read_sha256.is_some() {
            ensure!(
                spec.name == self.config.name
                    && spec.kernel
                        == KernelImage::Path(PathBuf::from(
                            self.config
                                .kernel_path
                                .as_deref()
                                .context("producer kernel missing")?,
                        )),
                "physical VMM recipe substituted the producer kernel or VM"
            );
        }
        if let Some(owner) = &self.config.canonical_kernel {
            owner.verify_config(
                &self.config,
                self.backend,
                &mvm_build::stage0_kernel::current_image_set_protocol_support(),
            )?;
            ensure!(
                spec.name == self.config.name
                    && spec.kernel == KernelImage::Path(owner.kernel_path()),
                "physical VMM recipe substituted the bound kernel or VM"
            );
        }
        Ok(())
    }

    pub(crate) fn observe_booted(&self, vm: &dyn RunningVm) -> Result<()> {
        let Some(_) = &self.config.canonical_kernel else {
            return Ok(());
        };
        ensure!(vm.id().0 == self.config.name, "driver returned another VM");
        #[cfg(unix)]
        {
            if self.backend == BackendKind::Firecracker {
                let process = vm
                    .process_identity()?
                    .context("started VM has no observable process identity; kernel retained")?;
                return self.observe_process(process);
            }
            let instance = vm
                .authenticated_hvf_instance()?
                .context("started VM has no authenticated lifetime identity; kernel retained")?;
            self.observe_instance(&instance)
        }
        #[cfg(not(unix))]
        anyhow::bail!("canonical kernel lifetime observation unsupported")
    }

    #[cfg(unix)]
    pub(crate) fn observe_instance(
        &self,
        instance: &mvm_core::protocol::hvf_control::HvfInstance,
    ) -> Result<()> {
        let Some(owner) = &self.config.canonical_kernel else {
            return Ok(());
        };
        ensure!(
            instance.vm_id == self.config.name,
            "kernel reader identity belongs to another VM"
        );
        let mut record = read_record(&self.record)?;
        ensure!(
            record.process.is_none()
                && record.instance.as_ref().is_none_or(|held| held == instance),
            "kernel generation is already bound to another native instance"
        );
        ensure!(
            record.generation
                == owner
                    .generation_dir()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy(),
            "kernel generation index changed during start"
        );
        record.instance = Some(instance.clone());
        mvm_core::util::atomic_io::atomic_write_durable(
            &self.record,
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }
}

impl KernelBoundLaunch {
    #[cfg(unix)]
    pub(crate) fn observe_process(
        &self,
        process: mvm_vmm::host::process_identity::ProcessIdentity,
    ) -> Result<()> {
        let Some(owner) = &self.config.canonical_kernel else {
            return Ok(());
        };
        ensure!(
            process.vm_id == self.config.name,
            "kernel reader identity belongs to another VM"
        );
        let mut record = read_record(&self.record)?;
        ensure!(
            record.instance.is_none()
                && record.process.as_ref().is_none_or(|held| held == &process),
            "kernel generation is already bound to another instance"
        );
        ensure!(
            record.generation
                == owner
                    .generation_dir()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy(),
            "kernel generation index changed during start"
        );
        record.process = Some(process);
        mvm_core::util::atomic_io::atomic_write_durable(
            &self.record,
            &serde_json::to_vec(&record)?,
        )?;
        Ok(())
    }
}

fn read_record(path: &Path) -> Result<KernelUse> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 16 * 1024,
        "kernel lifetime index is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "kernel lifetime index grew beyond its bound"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn directory_identity(path: &Path) -> Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "kernel generation is not a directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments and observes this process only.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "kernel generation is not owner-private"
        );
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    anyhow::bail!("kernel generation identity is unsupported")
}

/// Only a real opaque driver exit proof can release a recorded generation.
/// No stop ack, PID-file absence or caller boolean reaches this deletion.
#[cfg(unix)]
pub(crate) fn release_after_confirmed_exit(
    lifecycle: &RuntimeLifecycleLease,
    proof: &mvm_vmm::host::hvf_stop::ConfirmedExit,
) -> Result<()> {
    release_generation(lifecycle, proof.instance(), || proof.verify_current())
}

/// Firecracker's release: the recorded process must be positively gone from
/// the process table. The stop that preceded this is not evidence; a PID file
/// absence or a signal acknowledgment never reaches deletion.
#[cfg(unix)]
pub(crate) fn release_after_process_exit(lifecycle: &RuntimeLifecycleLease) -> Result<()> {
    let process = read_record(&lifecycle.canonical_kernel_record())?
        .process
        .context("kernel generation is not bound to a process; retained")?;
    release_process_generation(lifecycle, &process, || {
        ensure!(
            process.has_exited()?,
            "Firecracker process is still running; kernel retained"
        );
        Ok(())
    })
}

#[cfg(unix)]
fn release_process_generation(
    lifecycle: &RuntimeLifecycleLease,
    exited: &mvm_vmm::host::process_identity::ProcessIdentity,
    recheck_exit: impl Fn() -> Result<()>,
) -> Result<()> {
    release_matching(
        lifecycle,
        &exited.vm_id,
        |record| record.instance.is_none() && record.process.as_ref() == Some(exited),
        recheck_exit,
    )
}

// Resource deletion mechanics only. The sole production callers above supply
// the existing opaque exit proof or a process-table check, never a
// deserialized record or a stop result.
#[cfg(unix)]
fn release_generation(
    lifecycle: &RuntimeLifecycleLease,
    exited: &mvm_core::protocol::hvf_control::HvfInstance,
    recheck_exit: impl Fn() -> Result<()>,
) -> Result<()> {
    release_matching(
        lifecycle,
        &exited.vm_id,
        |record| record.process.is_none() && record.instance.as_ref() == Some(exited),
        recheck_exit,
    )
}

#[cfg(unix)]
fn release_matching(
    lifecycle: &RuntimeLifecycleLease,
    vm_id: &str,
    bound_to_exit: impl Fn(&KernelUse) -> bool,
    recheck_exit: impl Fn() -> Result<()>,
) -> Result<()> {
    let path = lifecycle.canonical_kernel_record();
    if !record_exists(&path)? {
        return Ok(());
    }
    recheck_exit()?;
    let record = read_record(&path)?;
    ensure!(
        record.version == 1 && record.vm == vm_id && bound_to_exit(&record),
        "kernel generation is not bound to this confirmed VM exit; retained"
    );
    ensure!(
        record.generation.starts_with("kernel-")
            && record.generation.len() <= 96
            && record
                .generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid kernel generation index"
    );
    let parent = mvm_core::config::mvm_home_strict()?.join("canonical-kernel-generations");
    let generation = parent.join(&record.generation);
    let generation_present = match std::fs::symlink_metadata(&generation) {
        Ok(_) => {
            ensure!(
                directory_identity(&generation)? == (record.device, record.inode),
                "kernel generation directory identity changed; retained"
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    recheck_exit()?;
    if generation_present {
        std::fs::remove_dir_all(&generation)?;
    }
    std::fs::remove_file(&path)?;
    Ok(())
}

pub(crate) fn has_retained_kernel(lifecycle: &RuntimeLifecycleLease) -> Result<bool> {
    record_exists(&lifecycle.canonical_kernel_record())
}

fn record_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, unix, feature = "manifest-verify"))]
#[path = "kernel_custody/native_handoff_tests.rs"]
mod native_handoff_tests;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn producer_kernel_descriptor_survives_replacement_after_final_check() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let source = home.path().join("slot-kernel");
        let original = b"producer kernel continuity fixture, not a bootable image";
        std::fs::write(&source, original).unwrap();
        let config = VmStartConfig {
            name: "producer-descriptor-unit".into(),
            kernel_path: Some(source.to_str().unwrap().into()),
            kernel_read_sha256: Some(mvm_core::plan::bundle::sha256_hex(original)),
            ..Default::default()
        };
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        assert!(KernelBoundLaunch::bind(config.clone(), BackendKind::Qemu, &lease).is_err());
        let firecracker = KernelBoundLaunch::bind(config.clone(), BackendKind::Firecracker, &lease);
        if cfg!(target_os = "linux") {
            let firecracker = firecracker.unwrap();
            assert!(firecracker.kernel.is_some());
            assert!(firecracker.config().canonical_kernel.is_none());
            assert!(!has_retained_kernel(&lease).unwrap());
        } else {
            assert!(firecracker.is_err());
        }
        let mut wrong = config.clone();
        wrong.kernel_read_sha256 = Some("0".repeat(64));
        assert!(KernelBoundLaunch::bind(wrong, BackendKind::Hvf, &lease).is_err());
        let bound = KernelBoundLaunch::bind(config, BackendKind::Hvf, &lease).unwrap();
        let mut spec = VmmSpec {
            name: bound.config().name.clone(),
            kernel: KernelImage::Path(source.clone()),
            initramfs: None,
            cmdline: String::new(),
            vcpus: 1,
            cpu_grant: None,
            memory_mib: 512,
            mem_initial_mib: None,
            blocks: vec![],
            vsock: vec![],
            console: mvm_vmm::driver::spec::ConsoleCapture {
                log_path: home.path().join("unused.log"),
            },
            shares: vec![],
            trusted_builder: false,
            builder_egress_endpoint: None,
            plan_binding: None,
        };
        bound.before_boot(&spec).unwrap();
        std::fs::remove_file(&source).unwrap();
        std::fs::write(&source, b"replacement AFTER final verification").unwrap();
        // The same held object goes to boot_verified_kernel, whose actual
        // inherited-FD loader has its own mapping regression. No VM here.
        let held = bound.kernel.as_ref().unwrap();
        let mut bytes = vec![0; original.len()];
        std::os::unix::fs::FileExt::read_exact_at(held.file(), &mut bytes, 0).unwrap();
        assert_eq!(bytes, original);
        spec.kernel = KernelImage::Path(home.path().join("other"));
        assert!(bound.before_boot(&spec).is_err());
        let driver = crate::driver::MockDriver::default();
        let error = bound
            .boot_with_prepared_disks(
                &driver,
                &spec,
                mvm_vmm::driver::prepared_disks::PreparedWritableDisks::empty(),
            )
            .err()
            .expect("changed kernel must refuse before driver dispatch");
        assert!(error.to_string().contains("physical VMM recipe"));
        assert!(driver.booted_specs().is_empty());
        assert!(
            !has_retained_kernel(&lease).unwrap(),
            "a continuity digest must not mint canonical bundle authority"
        );
    }

    #[test]
    fn pending_or_corrupt_lifetime_blocks_reuse_without_deleting_evidence() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-retention-unit").unwrap();
        let record = lease.canonical_kernel_record();
        let pending = KernelUse {
            version: 1,
            vm: "kernel-retention-unit".into(),
            generation: "kernel-unit".into(),
            device: 1,
            inode: 2,
            instance: None,
            process: None,
        };
        let bytes = serde_json::to_vec(&pending).unwrap();
        mvm_core::util::atomic_io::write_private_new(&record, &bytes).unwrap();
        let config = VmStartConfig {
            name: pending.vm,
            ..Default::default()
        };
        assert!(KernelBoundLaunch::bind(config.clone(), BackendKind::Hvf, &lease).is_err());
        assert_eq!(std::fs::read(&record).unwrap(), bytes);
        std::fs::write(&record, b"uncertain interrupted write").unwrap();
        assert!(has_retained_kernel(&lease).unwrap());
        assert!(KernelBoundLaunch::bind(config, BackendKind::Hvf, &lease).is_err());
        assert!(read_record(&record).is_err());
        assert_eq!(
            std::fs::read(&record).unwrap(),
            b"uncertain interrupted write"
        );
    }

    #[test]
    fn dangling_lifetime_index_is_not_absence_and_is_never_followed() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-symlink-unit").unwrap();
        let record = lease.canonical_kernel_record();
        symlink(home.path().join("absent-target"), &record).unwrap();
        assert!(has_retained_kernel(&lease).unwrap());
        assert!(read_record(&record).is_err());
        assert!(
            KernelBoundLaunch::bind(
                VmStartConfig {
                    name: "kernel-symlink-unit".into(),
                    ..Default::default()
                },
                BackendKind::Hvf,
                &lease,
            )
            .is_err()
        );
        assert!(
            std::fs::symlink_metadata(&record)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn generation_identity_rejects_substitution_symlink_and_public_directory() {
        let directory = tempfile::tempdir().unwrap();
        let generation = directory.path().join("kernel-selected");
        std::fs::create_dir(&generation).unwrap();
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = directory_identity(&generation).unwrap();
        let held = directory.path().join("kernel-held");
        std::fs::rename(&generation, &held).unwrap();
        std::fs::create_dir(&generation).unwrap();
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(directory_identity(&generation).unwrap(), first);
        let link = directory.path().join("kernel-link");
        symlink(&held, &link).unwrap();
        assert!(directory_identity(&link).is_err());
        std::fs::set_permissions(&generation, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(directory_identity(&generation).is_err());
    }

    #[test]
    fn cleanup_mechanics_retry_partial_removal_and_refuse_replacement_or_corruption() {
        use mvm_core::protocol::hvf_control::HvfInstance;
        for case in 0..3 {
            let home = tempfile::tempdir().unwrap();
            let mut env = TestEnv::new();
            env.isolate_mvm_home(home.path());
            let lease = RuntimeLifecycleLease::acquire("kernel-partial-unit").unwrap();
            let generation = home
                .path()
                .join("canonical-kernel-generations/kernel-partial");
            mvm_core::config::create_private_dir(&generation).unwrap();
            let (device, inode) = directory_identity(&generation).unwrap();
            let instance = HvfInstance {
                vm_id: "kernel-partial-unit".into(),
                boot_nonce: [8; 32],
            };
            let record = KernelUse {
                version: 1,
                vm: instance.vm_id.clone(),
                generation: "kernel-partial".into(),
                device,
                inode,
                instance: Some(instance.clone()),
                process: None,
            };
            let path = lease.canonical_kernel_record();
            let bytes = serde_json::to_vec(&record).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            match case {
                0 => {
                    std::fs::remove_dir_all(&generation).unwrap();
                    release_generation(&lease, &instance, || Ok(())).unwrap();
                    assert!(!path.exists());
                }
                1 => {
                    std::fs::rename(&generation, generation.with_extension("held")).unwrap();
                    mvm_core::config::create_private_dir(&generation).unwrap();
                    assert!(release_generation(&lease, &instance, || Ok(())).is_err());
                    assert_eq!(std::fs::read(&path).unwrap(), bytes);
                    assert!(generation.exists());
                }
                _ => {
                    std::fs::write(&path, b"corrupt index").unwrap();
                    assert!(release_generation(&lease, &instance, || Ok(())).is_err());
                    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt index");
                    assert!(generation.exists());
                }
            }
            // Resource mechanics only. The closure cannot create an opaque
            // ConfirmedExit or a native output/receipt completion witness.
        }
    }

    #[test]
    fn cleanup_mechanics_retain_uncertainty_and_release_only_matching_generation() {
        use mvm_core::protocol::hvf_control::HvfInstance;
        use std::cell::Cell;
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-cleanup-unit").unwrap();
        let generation = home.path().join("canonical-kernel-generations/kernel-unit");
        mvm_core::config::create_private_dir(&generation).unwrap();
        std::fs::write(generation.join("selected-kernel"), b"unit payload").unwrap();
        let (device, inode) = directory_identity(&generation).unwrap();
        let instance = HvfInstance {
            vm_id: "kernel-cleanup-unit".into(),
            boot_nonce: [3; 32],
        };
        let mut record = KernelUse {
            version: 1,
            vm: instance.vm_id.clone(),
            generation: "kernel-unit".into(),
            device,
            inode,
            instance: None,
            process: None,
        };
        let path = lease.canonical_kernel_record();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        // These closures model exit-proof outcomes for deletion mechanics;
        // they do not construct an opaque proof or claim a process has exited.
        assert!(release_generation(&lease, &instance, || Ok(())).is_err());
        record.instance = Some(instance.clone());
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let mut other = instance.clone();
        other.boot_nonce = [4; 32];
        assert!(release_generation(&lease, &other, || Ok(())).is_err());
        let checks = Cell::new(0);
        assert!(
            release_generation(&lease, &instance, || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    anyhow::bail!("unit identity advanced during cleanup")
                }
                Ok(())
            })
            .is_err()
        );
        assert!(generation.exists());
        assert!(path.exists());
        let checks = Cell::new(0);
        release_generation(&lease, &instance, || {
            checks.set(checks.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(checks.get(), 2);
        assert!(!generation.exists());
        assert!(!path.exists());
    }

    fn process_record(
        home: &Path,
        lease: &RuntimeLifecycleLease,
        process: Option<mvm_vmm::host::process_identity::ProcessIdentity>,
    ) -> (PathBuf, PathBuf) {
        let generation = home.join("canonical-kernel-generations/kernel-fc");
        mvm_core::config::create_private_dir(&generation).unwrap();
        std::fs::write(generation.join("selected-kernel"), b"unit payload").unwrap();
        let (device, inode) = directory_identity(&generation).unwrap();
        let record = KernelUse {
            version: 1,
            vm: "kernel-fc-unit".into(),
            generation: "kernel-fc".into(),
            device,
            inode,
            instance: None,
            process,
        };
        let path = lease.canonical_kernel_record();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        (generation, path)
    }

    fn fc_process(start_ticks: u64) -> mvm_vmm::host::process_identity::ProcessIdentity {
        mvm_vmm::host::process_identity::ProcessIdentity {
            vm_id: "kernel-fc-unit".into(),
            pid: 4242,
            start_ticks,
            boot_id: "boot".into(),
        }
    }

    #[test]
    fn firecracker_generation_is_released_only_for_the_recorded_exited_process() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-fc-unit").unwrap();
        let (generation, path) = process_record(home.path(), &lease, None);
        // Never bound to a process (aborted before start): nothing to release.
        assert!(release_process_generation(&lease, &fc_process(1), || Ok(())).is_err());
        assert!(release_after_process_exit(&lease).is_err());
        assert!(generation.exists() && path.exists());

        std::fs::remove_file(&path).unwrap();
        let (generation, path) = process_record(home.path(), &lease, Some(fc_process(1)));
        // A process that is still running (recheck refuses) keeps everything.
        let running = || anyhow::bail!("Firecracker process is still running; kernel retained");
        assert!(release_process_generation(&lease, &fc_process(1), running).is_err());
        // A different generation of the same pid is not the recorded process.
        assert!(release_process_generation(&lease, &fc_process(2), || Ok(())).is_err());
        assert!(generation.exists() && path.exists());

        release_process_generation(&lease, &fc_process(1), || Ok(())).unwrap();
        assert!(!generation.exists() && !path.exists());
    }

    #[test]
    fn a_retained_firecracker_generation_blocks_the_vm_name_until_resolved() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-fc-unit").unwrap();
        let config = VmStartConfig {
            name: "kernel-fc-unit".into(),
            ..Default::default()
        };
        // Both record shapes a failed start leaves behind: never bound to a
        // process, and bound to one that has not been confirmed gone.
        for process in [None, Some(fc_process(1))] {
            let (generation, path) = process_record(home.path(), &lease, process);
            assert!(has_retained_kernel(&lease).unwrap());
            let error = KernelBoundLaunch::bind(config.clone(), BackendKind::Firecracker, &lease)
                .err()
                .expect("a retained generation must block reuse of the VM name");
            assert!(format!("{error:#}").contains("still retained"), "{error:#}");
            assert!(generation.exists() && path.exists());
            std::fs::remove_file(&path).unwrap();
        }
        assert!(!has_retained_kernel(&lease).unwrap());
    }

    #[test]
    fn a_native_instance_record_cannot_be_released_by_process_exit() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-fc-unit").unwrap();
        let (generation, path) = process_record(home.path(), &lease, Some(fc_process(1)));
        let mut record = read_record(&path).unwrap();
        record.instance = Some(mvm_core::protocol::hvf_control::HvfInstance {
            vm_id: "kernel-fc-unit".into(),
            boot_nonce: [1; 32],
        });
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(release_process_generation(&lease, &fc_process(1), || Ok(())).is_err());
        assert!(generation.exists() && path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_process_retains_the_generation_until_it_is_really_gone() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let lease = RuntimeLifecycleLease::acquire("kernel-fc-unit").unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let identity =
            mvm_vmm::host::process_identity::ProcessIdentity::capture("kernel-fc-unit", child.id())
                .unwrap();
        let (generation, path) = process_record(home.path(), &lease, Some(identity));
        assert!(release_after_process_exit(&lease).is_err());
        assert!(generation.exists() && path.exists());
        child.kill().unwrap();
        child.wait().unwrap();
        release_after_process_exit(&lease).unwrap();
        assert!(!generation.exists() && !path.exists());
    }
}
