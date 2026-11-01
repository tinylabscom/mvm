//! Live writable image resources bound to a final physical disk recipe.
//!
//! This carries cooperating writer exclusion, not admission or native ownership
//! proof. Nothing here is serializable or recoverable from a pathname or VM name.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, ensure};
use mvm_core::util::writable_image::LockedWritableImage;

use super::spec::{BlockDev, VmmSpec};

#[derive(Debug)]
struct PreparedDisk {
    block: BlockDev,
    image: LockedWritableImage,
}

/// Bounded original file owners, assigned to the final spec's writable slots.
#[must_use = "retain prepared files through original-writer handoff"]
#[derive(Debug)]
pub struct PreparedWritableDisks {
    disks: Vec<PreparedDisk>,
}

impl PreparedWritableDisks {
    /// No supplied resources: preserves the driver's existing boot contract.
    pub fn empty() -> Self {
        Self { disks: Vec::new() }
    }

    /// Open and lock every persistent writable disk in the final physical spec.
    pub fn open(spec: &VmmSpec) -> Result<Self> {
        let images = spec
            .blocks
            .iter()
            .filter(|block| !block.read_only && !block.ephemeral)
            .map(|block| {
                LockedWritableImage::open(
                    &block.source,
                    &mvm_core::util::writable_image::sidecar_lock_path(&block.source),
                )
                .map(|image| (block.slot, image))
                .with_context(|| format!("preparing writable disk {}", block.source.display()))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::bind(spec, images)
    }

    /// Bind already-locked images to every persistent writable disk in `spec`.
    ///
    /// The selected paths are inspected once to check object correspondence.
    /// Actual I/O and handoff keep using the supplied files, never those paths.
    ///
    /// # Errors
    ///
    /// Refuses missing/duplicate slots, wrong access or ephemeral disks, object
    /// aliases across any backing/sidecar roles, and a source that does not name
    /// the exact held backing. No file is written or native child started.
    pub fn bind(spec: &VmmSpec, images: Vec<(u8, LockedWritableImage)>) -> Result<Self> {
        ensure!(
            spec.blocks.len() <= usize::from(u8::MAX) + 1,
            "physical disk count exceeds slot namespace"
        );
        let mut slots = BTreeSet::new();
        ensure!(
            spec.blocks.iter().all(|block| slots.insert(block.slot)),
            "physical spec contains duplicate disk slots"
        );
        let expected = spec
            .blocks
            .iter()
            .filter(|block| !block.read_only && !block.ephemeral)
            .count();
        ensure!(
            images.len() == expected,
            "prepared resources do not cover the final writable disk set"
        );
        let mut supplied_slots = BTreeSet::new();
        let mut objects = BTreeSet::new();
        let mut disks = Vec::with_capacity(images.len());
        for (slot, image) in images {
            ensure!(
                supplied_slots.insert(slot),
                "duplicate prepared writable slot"
            );
            let block = spec
                .blocks
                .iter()
                .find(|block| block.slot == slot)
                .context("prepared writable slot is absent from final spec")?;
            ensure!(
                !block.read_only && !block.ephemeral,
                "prepared writable slot does not describe a persistent writable disk"
            );
            let selected = std::fs::symlink_metadata(&block.source)
                .context("inspecting final writable disk source")?;
            let held = image.backing().metadata()?;
            ensure!(
                selected.is_file() && (selected.dev(), selected.ino()) == (held.dev(), held.ino()),
                "final writable source differs from the held backing object"
            );
            for file in [image.backing(), image.sidecar()] {
                let metadata = file.metadata()?;
                ensure!(
                    objects.insert((metadata.dev(), metadata.ino())),
                    "prepared disk descriptors alias another backing or sidecar"
                );
            }
            disks.push(PreparedDisk {
                block: block.clone(),
                image,
            });
        }
        disks.sort_by_key(|disk| disk.block.slot);
        Ok(Self { disks })
    }

    /// Whether the caller supplied no writable resources.
    pub fn is_empty(&self) -> bool {
        self.disks.is_empty()
    }

    /// Borrow the original owners in final physical-slot order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (u8, &LockedWritableImage)> {
        self.disks.iter().map(|disk| (disk.block.slot, &disk.image))
    }

    /// Original diagnostic paths by final slot, never the transport projections.
    pub fn original_sources(&self) -> std::collections::BTreeMap<u8, std::path::PathBuf> {
        self.disks
            .iter()
            .map(|disk| (disk.block.slot, disk.block.source.clone()))
            .collect()
    }

    /// Project writable backings through the launching process's procfs entries.
    /// The caller retains `self` until the synchronous open/configuration returns.
    pub fn project_for_proc_opener(&self, spec: &VmmSpec) -> Result<VmmSpec> {
        self.validate_spec(spec)?;
        let mut projected = spec.clone();
        for disk in &self.disks {
            let block = projected
                .blocks
                .iter_mut()
                .find(|block| block.slot == disk.block.slot)
                .context("projected writable slot missing")?;
            block.source = format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                std::os::fd::AsRawFd::as_raw_fd(disk.image.backing())
            )
            .into();
        }
        Ok(projected)
    }

    /// Project writable backings through descriptors inherited by the writer.
    pub fn project_for_inherited_writer(&self, spec: &VmmSpec) -> Result<VmmSpec> {
        self.validate_spec(spec)?;
        let mut projected = spec.clone();
        for disk in &self.disks {
            let block = projected
                .blocks
                .iter_mut()
                .find(|block| block.slot == disk.block.slot)
                .context("projected writable slot missing")?;
            block.source = format!(
                "/dev/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(disk.image.backing())
            )
            .into();
        }
        Ok(projected)
    }

    /// Descriptor numbers the projected writer must inherit under the same names.
    pub fn inherited_descriptors(spec: &VmmSpec) -> Result<Vec<std::os::fd::RawFd>> {
        let mut descriptors = Vec::new();
        for block in spec
            .blocks
            .iter()
            .filter(|block| !block.read_only && !block.ephemeral)
        {
            let text = block
                .source
                .to_str()
                .context("inherited writable descriptor path is not UTF-8")?;
            let Some(descriptor) = text.strip_prefix("/dev/fd/") else {
                anyhow::ensure!(
                    spec.trusted_builder,
                    "persistent writable disk lacks inherited descriptor projection"
                );
                continue;
            };
            let fd = descriptor.parse::<std::os::fd::RawFd>()?;
            anyhow::ensure!(fd > 2, "reserved writable descriptor");
            descriptors.push(fd);
        }
        let unique = descriptors.iter().collect::<BTreeSet<_>>();
        anyhow::ensure!(
            unique.len() == descriptors.len(),
            "duplicate inherited writable descriptors"
        );
        Ok(descriptors)
    }

    /// Refuse substitution of the physical recipe after resources were bound.
    ///
    /// Empty resources preserve legacy dispatch. Nonempty resources must still
    /// cover the exact writable recipe; this never reopens a diagnostic path.
    ///
    /// # Errors
    ///
    /// Returns an error when the final writable slot set or recipe changed.
    pub fn validate_spec(&self, spec: &VmmSpec) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let mut slots = BTreeSet::new();
        ensure!(
            spec.blocks.len() <= usize::from(u8::MAX) + 1
                && spec.blocks.iter().all(|block| slots.insert(block.slot)),
            "invalid physical disk slot set"
        );
        let writable: Vec<_> = spec
            .blocks
            .iter()
            .filter(|block| !block.read_only && !block.ephemeral)
            .collect();
        ensure!(
            writable.len() == self.disks.len()
                && self
                    .disks
                    .iter()
                    .all(|disk| writable.contains(&&disk.block)),
            "physical writable recipe changed after resource binding"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::traits::{RunningVm, VmmDriver};
    use crate::host::restore_image::VerifiedRestoreFile;
    use mvm_core::vm_backend::{
        BackendKind, BackendSecurityProfile, GuestChannelInfo, VmCapabilities, VmId,
    };
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct DispatchRecorder {
        ordinary: AtomicUsize,
        verified: AtomicUsize,
    }

    impl VmmDriver for DispatchRecorder {
        fn name(&self) -> &str {
            "dispatch-recorder"
        }

        fn kind(&self) -> BackendKind {
            BackendKind::Hvf
        }

        fn is_available(&self) -> Result<bool> {
            Ok(true)
        }

        fn capabilities(&self) -> VmCapabilities {
            VmCapabilities::default()
        }

        fn security_profile(&self) -> BackendSecurityProfile {
            panic!("dispatch-only test must not ask for a security profile")
        }

        fn boot(&self, _: &VmmSpec) -> Result<Box<dyn RunningVm>> {
            self.ordinary.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("ordinary dispatch witness")
        }

        fn boot_verified_kernel(
            &self,
            _: &VmmSpec,
            _: &VerifiedRestoreFile,
        ) -> Result<Box<dyn RunningVm>> {
            self.verified.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("verified dispatch witness")
        }

        fn workload_base_bootargs(&self, _: bool) -> String {
            panic!("dispatch-only test must not build boot arguments")
        }

        fn attach(&self, _: &VmId) -> Result<Box<dyn RunningVm>> {
            anyhow::bail!("dispatch-only test cannot attach")
        }

        fn guest_channel_info(&self, _: &VmId) -> Result<GuestChannelInfo> {
            anyhow::bail!("dispatch-only test has no guest")
        }
    }

    fn writable(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .unwrap()
    }

    fn kernel(root: &Path, bytes: &[u8]) -> VerifiedRestoreFile {
        let private = root.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = private.join("kernel");
        std::fs::write(&source, bytes).unwrap();
        VerifiedRestoreFile::prepare(
            &source,
            &private,
            &mvm_core::plan::bundle::sha256_hex(bytes),
        )
        .unwrap()
    }

    fn spec(blocks: Vec<BlockDev>) -> VmmSpec {
        VmmSpec {
            name: "prepared-test".into(),
            kernel: super::super::spec::KernelImage::Bundled,
            initramfs: None,
            cmdline: String::new(),
            vcpus: 1,
            cpu_grant: None,
            memory_mib: 64,
            mem_initial_mib: None,
            blocks,
            vsock: Vec::new(),
            console: super::super::spec::ConsoleCapture {
                log_path: "/unused".into(),
            },
            shares: Vec::new(),
            trusted_builder: false,
            builder_egress_endpoint: None,
            plan_binding: None,
        }
    }

    fn block(path: &Path, slot: u8) -> BlockDev {
        BlockDev {
            source: path.to_owned(),
            read_only: false,
            ephemeral: false,
            slot,
        }
    }

    #[test]
    fn binding_retains_the_actual_file_when_its_path_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        let image =
            LockedWritableImage::acquire(writable(&path), writable(&tmp.path().join("lock")))
                .unwrap();
        let original = image.backing().metadata().unwrap();
        let spec = spec(vec![block(&path, 3)]);
        let disks = PreparedWritableDisks::bind(&spec, vec![(3, image)]).unwrap();
        std::fs::rename(&path, tmp.path().join("renamed")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();

        disks.validate_spec(&spec).unwrap();
        let (slot, held) = disks.iter().next().unwrap();
        assert_eq!(slot, 3);
        assert_eq!(held.backing().metadata().unwrap().ino(), original.ino());
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), original.ino());
    }

    #[test]
    fn wrong_object_or_changed_final_recipe_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        let other = tmp.path().join("other");
        let image =
            LockedWritableImage::acquire(writable(&path), writable(&tmp.path().join("lock")))
                .unwrap();
        writable(&other);
        assert!(
            PreparedWritableDisks::bind(&spec(vec![block(&other, 1)]), vec![(1, image)]).is_err()
        );
        let image =
            LockedWritableImage::acquire(writable(&path), writable(&tmp.path().join("lock")))
                .unwrap();
        let mut spec = spec(vec![block(&path, 1)]);
        let disks = PreparedWritableDisks::bind(&spec, vec![(1, image)]).unwrap();
        spec.blocks[0].source = other;
        assert!(disks.validate_spec(&spec).is_err());
        spec.blocks[0].read_only = true;
        assert!(disks.validate_spec(&spec).is_err());
    }

    #[test]
    fn aliased_backings_with_distinct_descriptors_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        let first =
            LockedWritableImage::acquire(writable(&path), writable(&tmp.path().join("lock-a")))
                .unwrap();
        let second = LockedWritableImage::acquire(
            first.backing().try_clone().unwrap(),
            writable(&tmp.path().join("lock-b")),
        )
        .unwrap();
        assert!(
            PreparedWritableDisks::bind(
                &spec(vec![block(&path, 1), block(&path, 2)]),
                vec![(1, first), (2, second)],
            )
            .is_err()
        );
    }

    #[test]
    fn exec_child_retains_lock_custody_after_parent_drops_originals() {
        use std::io::Read as _;
        use std::os::fd::AsRawFd;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        let sidecar = tmp.path().join("image.lock");
        let held = LockedWritableImage::acquire(writable(&path), writable(&sidecar)).unwrap();
        let fds = vec![held.backing().as_raw_fd(), held.sidecar().as_raw_fd()];
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf x; exec sleep 30"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        crate::host::restore_image::inherit_descriptors(&mut command, fds);
        let mut child = command.spawn().unwrap();
        drop(held);
        let mut ready = [0_u8; 1];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .unwrap();
        assert_eq!(
            LockedWritableImage::open(&path, &sidecar)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        child.kill().unwrap();
        child.wait().unwrap();
        let _restarted = LockedWritableImage::open(&path, &sidecar).unwrap();
    }

    #[test]
    fn projection_preserves_read_only_paths_and_exact_backing_descriptors() {
        use std::os::fd::AsRawFd;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        let readonly = tmp.path().join("readonly");
        let image =
            LockedWritableImage::acquire(writable(&path), writable(&tmp.path().join("lock")))
                .unwrap();
        let expected_fd = image.backing().as_raw_fd();
        let mut readonly_block = block(&readonly, 2);
        readonly_block.read_only = true;
        let spec = spec(vec![block(&path, 1), readonly_block]);
        let disks = PreparedWritableDisks::bind(&spec, vec![(1, image)]).unwrap();

        let inherited = disks.project_for_inherited_writer(&spec).unwrap();
        assert_eq!(
            inherited.blocks[0].source,
            std::path::PathBuf::from(format!("/dev/fd/{expected_fd}"))
        );
        assert_eq!(inherited.blocks[1].source, readonly);
        assert_eq!(
            PreparedWritableDisks::inherited_descriptors(&inherited).unwrap(),
            vec![expected_fd]
        );
        let proc = disks.project_for_proc_opener(&spec).unwrap();
        assert_eq!(
            proc.blocks[0].source,
            std::path::PathBuf::from(format!("/proc/{}/fd/{expected_fd}", std::process::id()))
        );
        assert_eq!(proc.blocks[1].source, readonly);
    }

    #[test]
    fn read_only_specs_need_no_sidecar_or_backing_descriptor() {
        let tmp = tempfile::tempdir().unwrap();
        let mut readonly = block(&tmp.path().join("missing-read-only"), 0);
        readonly.read_only = true;
        let spec = spec(vec![readonly]);
        assert!(PreparedWritableDisks::open(&spec).unwrap().is_empty());
    }

    #[test]
    fn empty_resources_preserve_the_exact_kernel_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = kernel(tmp.path(), b"dispatch fixture, not a bootable kernel");
        let driver = DispatchRecorder::default();
        let spec = spec(Vec::new());
        let disks = PreparedWritableDisks::empty();

        let error = driver
            .boot_with_prepared_disks(&spec, Some(&kernel), &disks)
            .err()
            .expect("recorded verified route");
        assert_eq!(error.to_string(), "verified dispatch witness");
        assert_eq!(driver.verified.load(Ordering::SeqCst), 1);
        assert_eq!(driver.ordinary.load(Ordering::SeqCst), 0);

        let error = driver
            .boot_with_prepared_disks(&spec, None, &disks)
            .err()
            .expect("recorded ordinary route");
        assert_eq!(error.to_string(), "ordinary dispatch witness");
        assert_eq!(driver.verified.load(Ordering::SeqCst), 1);
        assert_eq!(driver.ordinary.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unsupported_nonempty_handoff_never_calls_either_boot_route() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("image");
        let image =
            LockedWritableImage::acquire(writable(&path), writable(&tmp.path().join("lock")))
                .unwrap();
        let spec = spec(vec![block(&path, 1)]);
        let disks = PreparedWritableDisks::bind(&spec, vec![(1, image)]).unwrap();
        let driver = DispatchRecorder::default();
        let kernel = kernel(tmp.path(), b"unsupported handoff fixture");

        for kernel in [None, Some(&kernel)] {
            let error = driver
                .boot_with_prepared_disks(&spec, kernel, &disks)
                .err()
                .expect("unsupported handoff");
            assert!(error.to_string().contains("prepared writable descriptor"));
        }
        assert_eq!(driver.ordinary.load(Ordering::SeqCst), 0);
        assert_eq!(driver.verified.load(Ordering::SeqCst), 0);
        assert!(
            writable(&path).try_lock().is_err(),
            "refusal must not unlock caller-owned preparation"
        );
    }
}
