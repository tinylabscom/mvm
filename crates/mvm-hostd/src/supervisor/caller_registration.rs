//! Cold-start caller registration at the trusted launcher/supervisor boundary.
//!
//! The startup transport is trusted under the host's authorized-launcher policy.
//! A generic signed plan is not registration authority. No producer endpoint or
//! warm handoff may call this installation path with producer-selected bytes.

use std::io::Read as _;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_core::crypto::entrypoint_delegation::{RegistrationChallenge, VerifiedCallerProof};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
use mvm_core::vm_backend::caller_registration::CallerRegistration;
use mvm_core::{atomic_io, config};

use crate::audit::host_keypair;
use crate::plan_admission::AdmittedPlan;

#[path = "caller_replay.rs"]
mod replay;

/// Fixed, payload-free category emitted only when durable replay consumption
/// rejects an already-spent registration.
pub const CALLER_REGISTRATION_REPLAY_DENIED: &str = "MVM_CALLER_REGISTRATION_REPLAY_DENIED";

/// Immutable verified registration, owned by exactly one capture owner.
/// Deliberately not deserializable, cloneable, or constructible by a producer.
pub struct RegisteredCaller {
    proof: VerifiedCallerProof,
}

impl RegisteredCaller {
    pub fn challenge(&self) -> &RegistrationChallenge {
        self.proof.challenge()
    }

    /// Preserve the existing numeric-only protected routing format without
    /// weakening its path validation. Decimal u128 is a lossless UUID encoding.
    pub(crate) fn capture_run(&self) -> String {
        self.challenge().binding.run.as_u128().to_string()
    }
}

/// Verified cold-start state. This still must consume its one-shot startup slot.
pub struct VerifiedCallerLaunch {
    plan: ExecutionPlan,
    caller: RegisteredCaller,
    vm: String,
}

/// Only durable consumption can mint this non-cloneable owner capability.
pub struct ConsumedCallerLaunch {
    plan: ExecutionPlan,
    caller: RegisteredCaller,
    vm: String,
    consumed_at: chrono::DateTime<chrono::Utc>,
}

pub struct PreparedCallerStartup {
    pub launch: Box<ConsumedCallerLaunch>,
    pub initramfs: Option<Vec<u8>>,
}

/// Adopted inputs remain untrusted until the original consumed caller binds them.
pub struct StartupFiles {
    kernel: Option<std::fs::File>,
    images: Option<[std::fs::File; 4]>,
    writable: Vec<(usize, mvm_core::util::writable_image::LockedWritableImage)>,
}

/// Sidecars stay here after their backings move into the actual disk devices.
pub struct WritableStartupFiles {
    disks: Vec<WritableStartupDisk>,
}

struct WritableStartupDisk {
    disk: usize,
    backing: Option<std::fs::File>,
    _sidecar: std::fs::File,
}

impl WritableStartupFiles {
    /// Consume a backing only for its declared persistent-writable table slot.
    pub fn take_disk(&mut self, disk: usize) -> Result<Option<std::fs::File>> {
        let Some(entry) = self.disks.iter_mut().find(|entry| entry.disk == disk) else {
            return Ok(None);
        };
        entry
            .backing
            .take()
            .map(Some)
            .context("writable backing already consumed")
    }
}

/// Original caller, original kernel and authenticated image files, still owned.
/// No DTO or raw-file constructor can mint this group.
pub struct BoundCallerBoot {
    launch: Box<ConsumedCallerLaunch>,
    kernel: std::fs::File,
    images: CheckedBootImageFiles,
}

/// Verified files for fixed disk slots; metadata/hash remain held, not attached.
pub struct CheckedBootImageFiles {
    rootfs: Option<std::fs::File>,
    verity: Option<std::fs::File>,
    _metadata: std::fs::File,
    _root_hash: std::fs::File,
    _facts: mvm_core::registry_pack_boot::AuthenticatedBootImageExpectations,
    cmdline: String,
}

impl CheckedBootImageFiles {
    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    /// A checked slot may be consumed once; absence never permits path fallback.
    pub fn take_disk(&mut self, index: usize) -> Result<Option<std::fs::File>> {
        match index {
            0 => self
                .rootfs
                .take()
                .map(Some)
                .context("checked rootfs already consumed"),
            1 => self
                .verity
                .take()
                .map(Some)
                .context("checked verity already consumed"),
            _ => Ok(None),
        }
    }
}

impl BoundCallerBoot {
    pub fn into_startup(
        self,
    ) -> (
        Box<ConsumedCallerLaunch>,
        std::fs::File,
        CheckedBootImageFiles,
    ) {
        (self.launch, self.kernel, self.images)
    }
}

/// Validate the COMPLETE locator set without adopting or closing any input.
pub fn preflight_startup_files(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> Result<()> {
    let mut readonly = cfg.kernel_fd.into_iter().collect::<Vec<_>>();
    if let Some(table) = cfg.boot_image_fds {
        anyhow::ensure!(
            cfg.kernel_fd.is_some(),
            "image table requires original kernel descriptor"
        );
        readonly.extend(table.descriptors());
    }
    if let Some(restore) = cfg.restore_fds {
        readonly.extend([restore.ram, restore.frame]);
    }
    let writable = cfg
        .writable_disk_fds
        .iter()
        .flat_map(|disk| [disk.backing, disk.sidecar])
        .collect::<Vec<_>>();
    let all = readonly
        .iter()
        .chain(&writable)
        .copied()
        .collect::<Vec<_>>();
    validate_descriptor_namespace(&all)?;
    validate_startup_descriptors(&readonly)?;
    validate_writable_descriptors(&writable)?;
    validate_writable_disk_table(cfg)?;
    validate_diagnostics_descriptor(
        &all,
        std::env::var_os("MVM_HVF_STARTUP_DIAGNOSTICS_FD").as_deref(),
    )?;
    if cfg.boot_image_fds.is_some() {
        anyhow::ensure!(
            cfg.restore_fds.is_none() && cfg.restore_ram.is_none() && cfg.restore_frame.is_none(),
            "checked boot images cannot enter restore"
        );
        cfg.boot_image_claims().map_err(anyhow::Error::msg)?;
        mvm_vmm::host::hvf_supervisor::refuse_bootarg_overrides()?;
    }
    Ok(())
}

/// Preflight the complete set again, then adopt each descriptor exactly once.
pub fn adopt_startup_files(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> Result<StartupFiles> {
    use mvm_vmm::host::restore_image::adopt_inherited;

    preflight_startup_files(cfg)?;
    let kernel = cfg.kernel_fd.map(adopt_inherited).transpose()?;
    let images = cfg
        .boot_image_fds
        .map(|table| {
            let [rootfs, verity, metadata, hash] = table.descriptors();
            Ok::<_, anyhow::Error>([
                adopt_inherited(rootfs)?,
                adopt_inherited(verity)?,
                adopt_inherited(metadata)?,
                adopt_inherited(hash)?,
            ])
        })
        .transpose()?;
    let writable = cfg
        .writable_disk_fds
        .iter()
        .map(|disk| {
            // SAFETY: the complete preflight established live, distinct descriptors
            // assigned to this startup; no other owner adopts these numbers.
            let backing = unsafe { std::os::fd::FromRawFd::from_raw_fd(disk.backing) };
            // SAFETY: same single-adoption contract as `backing` above.
            let sidecar = unsafe { std::os::fd::FromRawFd::from_raw_fd(disk.sidecar) };
            let image =
                mvm_core::util::writable_image::LockedWritableImage::acquire(backing, sidecar)?;
            Ok((disk.disk, image))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(StartupFiles {
        kernel,
        images,
        writable,
    })
}

fn validate_diagnostics_descriptor(fds: &[i32], value: Option<&std::ffi::OsStr>) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    let text = value
        .to_str()
        .context("invalid diagnostics descriptor encoding")?;
    let fd: i32 = text
        .parse()
        .context("invalid diagnostics descriptor locator")?;
    anyhow::ensure!(
        fd > 2 && text == fd.to_string() && !fds.contains(&fd),
        "diagnostics descriptor collides with startup files"
    );
    // SAFETY: metadata inspection only; neither rejection nor success adopts/closes.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is inspected without ownership conversion.
    let flags = unsafe {
        if libc::fstat(fd, &mut stat) != 0 {
            -1
        } else {
            libc::fcntl(fd, libc::F_GETFL)
        }
    };
    anyhow::ensure!(
        flags >= 0
            && flags & libc::O_ACCMODE == libc::O_WRONLY
            && stat.st_mode & libc::S_IFMT == libc::S_IFIFO,
        "invalid diagnostics pipe"
    );
    Ok(())
}

fn validate_descriptor_namespace(fds: &[i32]) -> Result<()> {
    let mut numbers = std::collections::BTreeSet::new();
    let mut inodes = std::collections::BTreeSet::new();
    for fd in fds {
        anyhow::ensure!(
            *fd > 2 && numbers.insert(*fd),
            "duplicate or reserved startup descriptor"
        );
        // SAFETY: fstat initializes this plain data; it is read only on success.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: only descriptor metadata is inspected, without taking ownership.
        anyhow::ensure!(
            unsafe { libc::fstat(*fd, &mut stat) } == 0
                && inodes.insert((stat.st_dev, stat.st_ino)),
            "startup descriptors alias an underlying object"
        );
    }
    Ok(())
}

fn descriptor_role(fd: i32) -> Result<(libc::stat, i32)> {
    // SAFETY: fstat initializes this plain data; it is read only on success.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: only descriptor metadata is inspected, without taking ownership.
    let status = unsafe {
        if libc::fstat(fd, &mut stat) != 0 {
            -1
        } else {
            libc::fcntl(fd, libc::F_GETFL)
        }
    };
    Ok((stat, status))
}

fn validate_startup_descriptors(fds: &[i32]) -> Result<()> {
    validate_descriptor_namespace(fds)?;
    for fd in fds {
        let (stat, status) = descriptor_role(*fd)?;
        anyhow::ensure!(
            status >= 0
                && (status & libc::O_ACCMODE) == libc::O_RDONLY
                && (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
                && stat.st_nlink == 0,
            "startup descriptor is not a distinct private read-only file"
        );
    }
    Ok(())
}

fn validate_writable_descriptors(fds: &[i32]) -> Result<()> {
    validate_descriptor_namespace(fds)?;
    for fd in fds {
        let (stat, status) = descriptor_role(*fd)?;
        anyhow::ensure!(
            status >= 0
                && (status & libc::O_ACCMODE) == libc::O_RDWR
                && status & libc::O_APPEND == 0
                && (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
                && stat.st_nlink > 0,
            "writable startup descriptor is not a linked non-append read-write file"
        );
    }
    Ok(())
}

fn validate_writable_disk_table(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> Result<()> {
    if cfg.writable_disk_fds.is_empty()
        && (cfg.exclusive_image_lock.is_some() || cfg.trusted_builder_egress)
    {
        return Ok(());
    }
    let expected = cfg
        .disks
        .iter()
        .enumerate()
        .filter(|(_, disk)| !disk.read_only && !disk.ephemeral)
        .map(|(index, _)| index)
        .collect::<std::collections::BTreeSet<_>>();
    let supplied = cfg
        .writable_disk_fds
        .iter()
        .map(|disk| disk.disk)
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        supplied.len() == cfg.writable_disk_fds.len() && supplied == expected,
        "writable descriptor table does not cover the exact persistent disk set"
    );
    Ok(())
}

struct BootReader<'a> {
    file: &'a std::fs::File,
    offset: u64,
}

impl std::io::Read for BootReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let count = self.file.read_at(out, self.offset)?;
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("boot reader offset overflow"))?;
        Ok(count)
    }
}

impl StartupFiles {
    /// Split writer custody from kernel/caller consumption without reopening anything.
    pub fn take_writable(&mut self) -> WritableStartupFiles {
        WritableStartupFiles {
            disks: std::mem::take(&mut self.writable)
                .into_iter()
                .map(|(disk, image)| {
                    let (backing, sidecar) = image.into_files();
                    WritableStartupDisk {
                        disk,
                        backing: Some(backing),
                        _sidecar: sidecar,
                    }
                })
                .collect(),
        }
    }

    pub fn into_legacy_kernel(self) -> Result<Option<std::fs::File>> {
        anyhow::ensure!(
            self.images.is_none(),
            "checked images cannot use legacy startup"
        );
        Ok(self.kernel)
    }

    pub fn bind(
        self,
        launch: Box<ConsumedCallerLaunch>,
        cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
    ) -> Result<BoundCallerBoot> {
        use mvm_core::registry_pack_boot::BootImageAsset as Role;
        anyhow::ensure!(
            launch.vm == cfg.vm_name,
            "boot image caller identity mismatch"
        );
        let claims = cfg.boot_image_claims().map_err(anyhow::Error::msg)?;
        mvm_vmm::host::hvf_supervisor::refuse_bootarg_overrides()?;
        let kernel = self.kernel.context("original kernel missing")?;
        let [rootfs, verity, metadata, root_hash] =
            self.images.context("checked image files missing")?;
        // Only the verifier-consumed roothash field is projected; unused defaults
        // are NOT resource, runtime, helper, or admission facts.
        let projection = mvm_core::vm_backend::VmStartConfig {
            roothash: Some(claims.root_hash().to_owned()),
            ..Default::default()
        };
        let (facts, declaration) =
            reopen_caller_image(&launch.plan, &launch.vm, &projection, &root_hash)?;
        verify_kernel_contents(&kernel, &declaration)?;
        for (role, file) in [
            (Role::Rootfs, &rootfs),
            (Role::Verity, &verity),
            (Role::Metadata, &metadata),
            (Role::RootHash, &root_hash),
        ] {
            facts.verify_reader(role, BootReader { file, offset: 0 })?;
        }
        Ok(BoundCallerBoot {
            launch,
            kernel,
            images: CheckedBootImageFiles {
                rootfs: Some(rootfs),
                verity: Some(verity),
                _metadata: metadata,
                _root_hash: root_hash,
                _facts: facts,
                cmdline: claims.cmdline().to_owned(),
            },
        })
    }
}

fn verify_kernel_contents(
    file: &std::fs::File,
    declaration: &mvm_core::image_set::MemberArtifact,
) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() == declaration.size,
        "held kernel differs from the authenticated size"
    );
    verify_kernel_digest(BootReader { file, offset: 0 }, declaration)
}

fn verify_kernel_digest(
    reader: impl std::io::Read,
    declaration: &mvm_core::image_set::MemberArtifact,
) -> Result<()> {
    let bound = declaration
        .size
        .checked_add(1)
        .context("kernel size overflow")?;
    let mut bounded = reader.take(bound);
    let digest = mvm_core::crypto::image_verify::sha256_reader(&mut bounded)?;
    anyhow::ensure!(
        bound.checked_sub(bounded.limit()) == Some(declaration.size)
            && digest == declaration.sha256.as_str(),
        "held kernel differs from its authenticated bytes"
    );
    Ok(())
}

fn reopen_caller_image(
    plan: &ExecutionPlan,
    vm: &str,
    projection: &mvm_core::vm_backend::VmStartConfig,
    root_hash: &std::fs::File,
) -> Result<(
    mvm_core::registry_pack_boot::AuthenticatedBootImageExpectations,
    mvm_core::image_set::MemberArtifact,
)> {
    use mvm_core::registry_pack::{
        AuthenticatedRegistryManifest as _, PackPin, RegistryPackImage, VerifiedRegistryManifest,
    };
    use mvm_core::registry_pack_boot::{AuthenticatedBootImageExpectations, BuiltPackBootContract};
    use mvm_core::vm_backend::BackendKind;
    let arch = mvm_core::arch::GuestArch::Aarch64;
    let backend = BackendKind::Hvf;
    let protocols = mvm_build::stage0_kernel::current_image_set_protocol_support();
    let mut selected = None;
    for asset in plan
        .asset_identities
        .iter()
        .filter(|asset| asset.kind == mvm_core::plan::AssetKind::RegistryPack)
    {
        let pin = PackPin::new(
            asset.name.parse()?,
            mvm_core::packs::Sha256Hex::new(&asset.digest)?,
        )?;
        let lock =
            mvm_core::registry_pack_store::load_pack_lockfile(&config::pack_lockfile_path())?;
        let policy = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
            &config::registry_pack_publisher_policy_path(),
        )?;
        let (_, verified) = mvm_core::registry_pack_store::open_installed_registry_manifest(
            &config::registry_pack_cache_dir(),
            &lock,
            &policy.policy,
            pin.reference(),
        )?;
        anyhow::ensure!(
            verified.manifest_sha256() == pin.manifest_sha256(),
            "caller pack pin changed"
        );
        match verified {
            VerifiedRegistryManifest::Legacy(verified) => {
                if matches!(verified.manifest().image, Some(RegistryPackImage::Built(_))) {
                    anyhow::ensure!(selected.is_none(), "ambiguous caller boot image");
                    let contract = BuiltPackBootContract::open_for_admission(&pin, &protocols)?;
                    contract.verify_plan(plan, arch, backend)?;
                    selected = Some((
                        contract.capture_image_expectations(
                            plan,
                            projection,
                            arch,
                            backend,
                            BootReader {
                                file: root_hash,
                                offset: 0,
                            },
                        )?,
                        contract.kernel(arch, backend)?,
                    ));
                }
            }
            VerifiedRegistryManifest::Application(_) => {
                use mvm_core::plan::bundle::{
                    ArtifactRole, BundleRegistry, FsBundleResolver, FsTrustStore,
                    verify_canonical_plan_bundle,
                };
                anyhow::ensure!(selected.is_none(), "ambiguous caller boot image");
                let registry = BundleRegistry::default_path()?;
                let store =
                    mvm_core::registry_pack::application_bundle::ApplicationInstallStore::new(
                        config::registry_pack_cache_dir(),
                        config::pack_lockfile_path(),
                        registry.root(),
                    );
                let trust = FsTrustStore::default_path()?;
                let application =
                    mvm_core::registry_pack::application_bundle::resolve_installed_application_bundle(
                        pin.reference(),
                        &store,
                        &config::registry_pack_publisher_policy_path(),
                        &trust,
                    )?;
                let original = application.bundle().plan_artifact();
                anyhow::ensure!(
                    plan.bundle.as_ref() == Some(&original),
                    "caller application differs from original bundle"
                );
                let owner =
                    std::sync::Arc::new(mvm_core::canonical_linux::prepare_canonical_linux(
                        &registry.archive_path(&original.bundle_sha256),
                        &original,
                        backend,
                        protocols,
                    )?);
                anyhow::ensure!(owner.arch() == arch, "caller kernel architecture differs");
                // This projection is only for independent byte authentication.
                // It cannot recreate admission or claim a native handoff.
                let mut config = mvm_core::vm_backend::VmStartConfig {
                    name: vm.into(),
                    roothash: projection.roothash.clone(),
                    ..Default::default()
                };
                owner.bind_to_config(&mut config)?;
                // Reuse the admission verifier: schema, signature, pin and
                // canonical-proof errors must not be treated as a legacy bundle.
                let verified = verify_canonical_plan_bundle(
                    &original,
                    &FsBundleResolver::new(registry.root()),
                    &trust,
                    &owner,
                    &config,
                    backend,
                    &protocols,
                )?;
                owner.verify_bundle_manifest(&verified.manifest)?;
                let installed = registry.install_dir(&original.bundle_sha256);
                for artifact in &application.bundle().manifest.artifacts {
                    match artifact.role {
                        ArtifactRole::Rootfs => {
                            config.rootfs_path =
                                installed.join(&artifact.path).display().to_string();
                        }
                        ArtifactRole::VerityHashSidecar => {
                            config.verity_path =
                                Some(installed.join(&artifact.path).display().to_string());
                        }
                        _ => {}
                    }
                }
                let facts = AuthenticatedBootImageExpectations::for_application(
                    &application,
                    plan,
                    &config,
                )?;
                anyhow::ensure!(
                    plan.environment.as_ref().is_some_and(
                        |environment| environment.kernel_sha256 == owner.kernel_sha256()
                    ),
                    "caller plan kernel differs from canonical declaration"
                );
                selected = Some((facts, owner.kernel_declaration().clone()));
            }
        }
    }
    selected.context("caller plan has no authenticated boot image")
}

/// Verify and durably consume opt-in before any boot setup, status publication,
/// timers, PID, or guest execution. Later input/setup failures remain spent.
/// Opt-out returns without touching its legacy setup order.
pub fn prepare_startup(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> Result<Option<PreparedCallerStartup>> {
    let Some(registration) = cfg.caller_registration.as_ref() else {
        anyhow::ensure!(
            cfg.kernel_fd.is_none() && cfg.boot_image_fds.is_none(),
            "verified boot descriptors require actual consumed caller admission"
        );
        return Ok(None);
    };
    anyhow::ensure!(
        !cfg.trusted_builder_egress
            && cfg.handoff_socket.is_none()
            && cfg.restore_ram.is_none()
            && cfg.restore_frame.is_none()
            && cfg.restore_fds.is_none(),
        "caller registration currently requires a cold workload launch"
    );
    mvm_core::naming::validate_vm_name(&cfg.vm_name)?;
    anyhow::ensure!(
        cfg.pid_file.parent() == Some(config::vm_state_dir(&cfg.vm_name).as_path()),
        "caller startup state does not match its instance"
    );
    let signed = serde_json::from_value(
        cfg.plan
            .clone()
            .context("caller registration requires a signed plan")?,
    )
    .map_err(|_| anyhow::anyhow!("caller registration requires a signed plan"))?;
    let launch = verify_cold_start(&cfg.vm_name, &signed, registration)?.consume(&cfg.vm_name)?;
    let initramfs = load_boot_inputs(cfg)?;
    Ok(Some(PreparedCallerStartup { launch, initramfs }))
}

/// The actual supervisor input read, shared with opt-out startup at its existing
/// point in that path. No capture owner or guest is created by this function.
pub fn load_boot_inputs(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> Result<Option<Vec<u8>>> {
    if cfg.kernel_fd.is_none() {
        anyhow::ensure!(
            cfg.kernel.is_file(),
            "kernel {} is not a readable file",
            cfg.kernel.display()
        );
    }
    cfg.initramfs
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read initramfs")
}

/// Mint only after actual plan admission and possession of the pinned native key.
/// The result is launch data, not a reusable authorization token.
pub fn admit_caller(
    admitted: &AdmittedPlan,
    vm: &str,
    expected: RegistrationChallenge,
    proof: VerifiedCallerProof,
) -> Result<CallerRegistration> {
    let now = unix_now()?;
    let registration = CallerRegistration {
        vm: vm.into(),
        expected,
        proof: proof.proof().clone(),
    };
    registration.verify_context(vm, admitted.plan(), now)?;
    Ok(registration)
}

/// Verify only a trusted cold-launch record, never a later producer request.
/// The root comes from the canonical host public-key location, not the config's
/// audit signing-key path or any root supplied alongside the signed plan.
pub fn verify_cold_start(
    vm: &str,
    signed: &SignedExecutionPlan,
    registration: &CallerRegistration,
) -> Result<VerifiedCallerLaunch> {
    let now = unix_now()?;
    let key = canonical_public_key()?;
    let plan =
        mvm_core::plan::verify_plan(signed, &[(host_keypair::host_signer_id().as_str(), &key)])
            .map_err(|_| anyhow::anyhow!("caller launch plan signature rejected"))?;
    mvm_core::plan::content_id::verify_plan_id(&plan)
        .map_err(|_| anyhow::anyhow!("caller launch plan content rejected"))?;
    mvm_core::plan::validity::check_window(&plan, chrono::Utc::now())
        .map_err(|_| anyhow::anyhow!("caller launch plan validity rejected"))?;
    let proof = registration
        .verify_context(vm, &plan, now)
        .map_err(|_| anyhow::anyhow!("caller launch possession or binding rejected"))?;
    Ok(VerifiedCallerLaunch {
        plan,
        caller: RegisteredCaller { proof },
        vm: vm.into(),
    })
}

impl VerifiedCallerLaunch {
    pub(crate) fn consume(self, vm: &str) -> Result<Box<ConsumedCallerLaunch>> {
        anyhow::ensure!(self.vm == vm, "caller launch owner mismatch");
        let consumed_at = chrono::Utc::now();
        let consumed_secs =
            u64::try_from(consumed_at.timestamp()).context("caller launch clock is invalid")?;
        mvm_core::plan::validity::check_window(&self.plan, consumed_at)
            .map_err(|_| anyhow::anyhow!("caller launch expired before installation"))?;
        self.caller
            .proof
            .proof()
            .verify(self.caller.challenge(), consumed_secs)
            .map_err(|_| anyhow::anyhow!("caller launch expired before installation"))?;
        mvm_core::naming::validate_vm_name(vm)?;
        let state = config::vm_state_dir(vm);
        match std::fs::symlink_metadata(&state) {
            Ok(metadata) => anyhow::ensure!(
                metadata.file_type().is_dir(),
                "caller launch state must be a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        config::create_private_dir(&state)?;
        let parent = state
            .parent()
            .context("caller launch state has no parent")?;
        anyhow::ensure!(
            std::fs::canonicalize(&state)? == std::fs::canonicalize(parent)?.join(vm),
            "caller launch state is not contained"
        );
        replay::consume(&self.caller, consumed_secs)?;
        // One fixed private replay slot per managed VM, not attacker-selected
        // filenames or an unbounded nonce directory. Failed setup stays spent:
        // retrying those same launch bytes must never restore authority. Normal
        // instance teardown removes the slot with the rest of managed VM state.
        // This marker is replay bookkeeping, never registration authority.
        let marker = state.join("caller-registration.used");
        let run = self.caller.challenge().binding.run.to_string();
        anyhow::ensure!(
            matches!(
                atomic_io::write_private_new(&marker, run.as_bytes())?,
                atomic_io::NewFile::Created
            ),
            "caller launch was already consumed; tear down the failed instance and obtain fresh admission"
        );
        Ok(Box::new(ConsumedCallerLaunch {
            plan: self.plan,
            caller: self.caller,
            vm: self.vm,
            consumed_at,
        }))
    }
}

impl ConsumedCallerLaunch {
    pub(crate) fn into_owner(self, vm: &str) -> Result<(ExecutionPlan, RegisteredCaller)> {
        self.into_owner_at(vm, chrono::Utc::now())
    }

    fn into_owner_at(
        self,
        vm: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(ExecutionPlan, RegisteredCaller)> {
        anyhow::ensure!(self.vm == vm, "consumed caller launch owner mismatch");
        let now_secs =
            u64::try_from(now.timestamp()).context("caller activation clock is invalid")?;
        anyhow::ensure!(
            now >= self.consumed_at,
            "caller activation clock moved backwards"
        );
        mvm_core::plan::validity::check_window(&self.plan, now)
            .map_err(|_| anyhow::anyhow!("caller launch expired during boot setup"))?;
        self.caller
            .proof
            .proof()
            .verify(self.caller.challenge(), now_secs)
            .map_err(|_| anyhow::anyhow!("caller registration expired during boot setup"))?;
        Ok((self.plan, self.caller))
    }
}

fn canonical_public_key() -> Result<VerifyingKey> {
    let path = config::mvm_keys_dir().join(host_keypair::PUBLIC_FILENAME);
    let metadata = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.len() == 32,
        "canonical host public key is invalid"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let mut bytes = [0; 32];
    file.read_exact(&mut bytes)?;
    anyhow::ensure!(
        file.read(&mut [0; 1])? == 0,
        "canonical host public key is invalid"
    );
    VerifyingKey::from_bytes(&bytes).context("canonical host public key is invalid")
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

#[cfg(test)]
#[path = "caller_registration_tests.rs"]
mod tests;
