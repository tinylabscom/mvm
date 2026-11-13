//! Resident, kernel-only publication mechanics. No VMM handoff or warm claim.

use std::collections::BTreeMap;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{self, Read, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, ensure};
use mvm_core::canonical_linux::PreparedCanonicalLinux;
use mvm_core::vm_backend::{BackendKind, VmStartConfig};
use mvm_fs::snapshot_store::SnapshotId;
use uuid::Uuid;

use super::TrustedSnapshotService;

/// Operator-supplied ceilings for resident kernel bytes and owner descriptors.
#[derive(Debug, Clone, Copy)]
pub struct BootInputBudget {
    bytes: u64,
    descriptors: u32,
}

impl BootInputBudget {
    /// Reject absent capacity rather than silently selecting an unbounded budget.
    ///
    /// # Errors
    /// Both capacity dimensions must be positive.
    pub fn new(bytes: u64, descriptors: u32) -> Result<Self> {
        ensure!(
            bytes > 0 && descriptors > 0,
            "boot-input budget must be positive"
        );
        Ok(Self { bytes, descriptors })
    }
}

/// Service-local, generation-bound reference; never a launch or plan grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootInputHandle {
    id: SnapshotId,
    generation: Uuid,
    owner_epoch: Uuid,
}

/// In-process read custody. It exposes no descriptor or duplicable file.
///
/// Dropping this value releases a claim, not a detached VMM. No production
/// launch path may use this type until it also retains the budget through the
/// actual VMM's confirmed last-child exit.
#[must_use = "keep the claim alive until its reader has stopped"]
pub struct BootInputReadLease {
    registry: Arc<BootInputRegistry>,
    handle: BootInputHandle,
}

impl std::fmt::Debug for BootInputReadLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootInputReadLease")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl BootInputReadLease {
    /// Read the sealed object without handing a duplicable descriptor to the caller.
    ///
    /// # Errors
    /// Refuses an invalid range, lost ownership, or an unavailable sealed object.
    pub fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let state = self
                .registry
                .state
                .lock()
                .map_err(|_| anyhow!("boot-input owner poisoned"))?;
            let Some(Entry::Published { input, .. }) = state.entries.get(self.handle.id.id())
            else {
                anyhow::bail!("boot-input publication was lost");
            };
            ensure!(
                input.handle == self.handle
                    && offset
                        .checked_add(u64::try_from(buffer.len())?)
                        .is_some_and(|end| end <= input.bytes),
                "boot-input read exceeds the owned generation"
            );
            verify_seals(&input.file, input.bytes)?;
            input.file.read_exact_at(buffer, offset)?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (buffer, offset);
            anyhow::bail!("sealed boot inputs require Linux")
        }
    }
}

impl Drop for BootInputReadLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.registry.state.lock()
            && let Some(Entry::Published { input, claims, .. }) =
                state.entries.get_mut(self.handle.id.id())
            && input.handle == self.handle
        {
            *claims -= 1;
        }
        // A poisoned registry remains unavailable; it must not reissue a
        // budget reservation or claim after an uncertain release.
    }
}

pub(super) struct BootInputRegistry {
    budget: BootInputBudget,
    epoch: Uuid,
    state: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    bytes: u64,
    descriptors: u32,
    entries: BTreeMap<String, Entry>,
}

enum Entry {
    Reserved {
        bytes: u64,
    },
    Published {
        input: SealedKernel,
        claims: usize,
        state: ReadState,
    },
}

enum ReadState {
    Available,
    Removing,
}

struct SealedKernel {
    handle: BootInputHandle,
    bytes: u64,
    file: File,
    owner: Arc<PreparedCanonicalLinux>,
    vm: String,
}

struct Reservation<'a> {
    registry: &'a BootInputRegistry,
    key: String,
    committed: bool,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.committed
            && let Ok(mut state) = self.registry.state.lock()
            && let Some(Entry::Reserved { bytes }) = state.entries.get(&self.key)
        {
            let bytes = *bytes;
            state.entries.remove(&self.key);
            state.bytes -= bytes;
            state.descriptors -= 1;
        }
    }
}

impl BootInputRegistry {
    pub(super) fn new(budget: BootInputBudget) -> Self {
        Self {
            budget,
            epoch: Uuid::new_v4(),
            state: Mutex::new(RegistryState::default()),
        }
    }

    fn reserve(&self, id: &SnapshotId, bytes: u64) -> Result<Reservation<'_>> {
        ensure!(bytes > 0, "empty kernel cannot be published");
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("boot-input owner poisoned"))?;
        ensure!(
            !state.entries.contains_key(id.id()),
            "boot-input ID already reserved"
        );
        ensure!(
            state
                .bytes
                .checked_add(bytes)
                .is_some_and(|total| total <= self.budget.bytes)
                && state
                    .descriptors
                    .checked_add(1)
                    .is_some_and(|total| total <= self.budget.descriptors),
            "boot-input byte or descriptor budget exhausted"
        );
        state.bytes += bytes;
        state.descriptors += 1;
        let key = id.id().to_owned();
        state.entries.insert(key.clone(), Entry::Reserved { bytes });
        Ok(Reservation {
            registry: self,
            key,
            committed: false,
        })
    }

    fn publish(
        &self,
        id: SnapshotId,
        owner: Arc<PreparedCanonicalLinux>,
        config: &VmStartConfig,
    ) -> Result<BootInputHandle> {
        let bytes = owner.kernel_declaration().size;
        let mut reservation = self.reserve(&id, bytes)?;
        owner.verify_lease_authority(
            config,
            BackendKind::Firecracker,
            &mvm_build::stage0_kernel::current_image_set_protocol_support(),
        )?;
        let source = owner
            .kernel_file()
            .context("authenticate selected kernel bytes")?;
        let sealed = seal_kernel(&source, bytes, owner.kernel_sha256())?;
        let handle = BootInputHandle {
            id,
            generation: Uuid::new_v4(),
            owner_epoch: self.epoch,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("boot-input owner poisoned"))?;
        ensure!(
            matches!(state.entries.get(&reservation.key), Some(Entry::Reserved { bytes: reserved }) if *reserved == bytes),
            "boot-input reservation changed during publication"
        );
        state.entries.insert(
            reservation.key.clone(),
            Entry::Published {
                input: SealedKernel {
                    handle: handle.clone(),
                    bytes,
                    file: sealed,
                    owner,
                    vm: config.name.clone(),
                },
                claims: 0,
                state: ReadState::Available,
            },
        );
        reservation.committed = true;
        Ok(handle)
    }

    fn claim(
        self: &Arc<Self>,
        handle: &BootInputHandle,
        config: &VmStartConfig,
    ) -> Result<BootInputReadLease> {
        ensure!(
            handle.owner_epoch == self.epoch,
            "boot-input owner has changed"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("boot-input owner poisoned"))?;
        let Some(Entry::Published {
            input,
            claims,
            state: ReadState::Available,
        }) = state.entries.get_mut(handle.id.id())
        else {
            anyhow::bail!("boot-input handle is not claimable");
        };
        ensure!(
            input.handle == *handle && input.vm == config.name,
            "stale or foreign boot-input handle"
        );
        input.owner.verify_lease_authority(
            config,
            BackendKind::Firecracker,
            &mvm_build::stage0_kernel::current_image_set_protocol_support(),
        )?;
        verify_seals(&input.file, input.bytes)?;
        *claims = claims
            .checked_add(1)
            .context("too many boot-input claims")?;
        Ok(BootInputReadLease {
            registry: Arc::clone(self),
            handle: handle.clone(),
        })
    }

    fn remove(&self, handle: &BootInputHandle) -> Result<()> {
        ensure!(
            handle.owner_epoch == self.epoch,
            "boot-input owner has changed"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("boot-input owner poisoned"))?;
        let entry = state
            .entries
            .get_mut(handle.id.id())
            .context("boot-input handle is unknown")?;
        let Entry::Published {
            input,
            claims,
            state: phase,
        } = entry
        else {
            anyhow::bail!("boot-input handle is not published");
        };
        ensure!(
            input.handle == *handle,
            "stale or foreign boot-input handle"
        );
        *phase = ReadState::Removing;
        ensure!(
            *claims == 0,
            "boot-input has active readers; removal retained"
        );
        let Some(Entry::Published { input, .. }) = state.entries.remove(handle.id.id()) else {
            anyhow::bail!("boot-input removal changed unexpectedly");
        };
        let bytes = input.bytes;
        drop(input);
        state.bytes -= bytes;
        state.descriptors -= 1;
        Ok(())
    }
}

impl TrustedSnapshotService {
    /// Publish a canonical signed kernel under the explicitly budgeted owner.
    ///
    /// This is not a full boot closure or permission to start or warm a VM.
    /// # Errors
    /// Refuses missing budgets, unsupported platforms, stale evidence, and
    /// insufficient capacity before issuing a handle.
    pub fn publish_canonical_kernel(
        &self,
        id: SnapshotId,
        config: &VmStartConfig,
    ) -> Result<BootInputHandle> {
        ensure!(
            cfg!(target_os = "linux"),
            "sealed boot inputs require Linux"
        );
        let registry = self
            .boot_inputs
            .as_ref()
            .context("boot-input budget is not configured")?;
        let owner = config
            .canonical_kernel
            .as_ref()
            .context("canonical kernel owner required")?;
        registry.publish(id, Arc::clone(owner), config)
    }

    /// Claim an existing sealed input without granting launch authority.
    ///
    /// # Errors
    /// Refuses stale handles, revoked evidence, changed configuration or seals.
    pub fn claim_boot_input(
        &self,
        handle: &BootInputHandle,
        config: &VmStartConfig,
    ) -> Result<BootInputReadLease> {
        ensure!(
            cfg!(target_os = "linux"),
            "sealed boot inputs require Linux"
        );
        self.boot_inputs
            .as_ref()
            .context("boot-input budget is not configured")?
            .claim(handle, config)
    }

    /// Retire a publication only after all in-process claims have ended.
    ///
    /// # Errors
    /// A busy publication stays unclaimable and must be retried.
    pub fn remove_boot_input(&self, handle: &BootInputHandle) -> Result<()> {
        self.boot_inputs
            .as_ref()
            .context("boot-input budget is not configured")?
            .remove(handle)
    }
}

#[cfg(target_os = "linux")]
fn seal_kernel(source: &File, len: u64, digest: &str) -> Result<File> {
    use std::ffi::CString;
    struct Positional<'a>(&'a File, u64);
    impl Read for Positional<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.0.read_at(buffer, self.1)?;
            self.1 = self
                .1
                .checked_add(u64::try_from(count).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("kernel reader offset overflow"))?;
            Ok(count)
        }
    }
    let name = CString::new("mvm-canonical-kernel")?;
    // SAFETY: name is NUL-terminated and the returned descriptor is owned only
    // after a nonnegative syscall result.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("create sealed kernel");
    }
    // SAFETY: memfd_create just returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let copied = io::copy(&mut Positional(source, 0).take(len), &mut file)?;
    ensure!(copied == len, "canonical kernel changed during publication");
    // SAFETY: no writable mapping is created and the only writable description
    // is this owned memfd; sealing is checked before publication.
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error()).context("seal canonical kernel");
    }
    verify_seals(&file, len)?;
    file.seek(SeekFrom::Start(0))?;
    let observed = mvm_core::crypto::image_verify::sha256_reader(Read::by_ref(&mut file))?;
    ensure!(
        observed == digest,
        "canonical kernel copy differs from signed declaration"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn seal_kernel(_source: &File, _len: u64, _digest: &str) -> Result<File> {
    anyhow::bail!("sealed boot inputs require Linux")
}

#[cfg(target_os = "linux")]
fn verify_seals(file: &File, len: u64) -> Result<()> {
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: F_GET_SEALS only inspects the live owned descriptor.
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    ensure!(
        actual >= 0 && actual & required == required && file.metadata()?.len() == len,
        "sealed kernel descriptor lost its immutable identity"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_seals(_file: &File, _len: u64) -> Result<()> {
    anyhow::bail!("sealed boot inputs require Linux")
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use mvm_fs::trusted_snapshot::UnsupportedTrustedSnapshotBackend;

    #[test]
    fn missing_or_zero_budget_never_publishes() {
        assert!(BootInputBudget::new(0, 1).is_err());
        assert!(BootInputBudget::new(1, 0).is_err());
        let service = TrustedSnapshotService::new(Arc::new(UnsupportedTrustedSnapshotBackend));
        let error = service
            .publish_canonical_kernel(SnapshotId::new("not-published"), &VmStartConfig::default())
            .unwrap_err();
        assert!(error.to_string().contains(if cfg!(target_os = "linux") {
            "budget is not configured"
        } else {
            "require Linux"
        }));
        if cfg!(target_os = "linux") {
            let budgeted = TrustedSnapshotService::with_boot_input_budget(
                Arc::new(UnsupportedTrustedSnapshotBackend),
                BootInputBudget::new(1, 1).unwrap(),
            );
            let error = budgeted
                .publish_canonical_kernel(
                    SnapshotId::new("not-authenticated"),
                    &VmStartConfig::default(),
                )
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("canonical kernel owner required")
            );
        }
    }

    #[test]
    fn reservations_bound_bytes_and_descriptors_before_copy_and_cancel_cleanly() {
        let registry = Arc::new(BootInputRegistry::new(BootInputBudget::new(10, 1).unwrap()));
        let first = SnapshotId::new("first");
        let reservation = registry.reserve(&first, 7).unwrap();
        assert!(registry.reserve(&first, 1).is_err(), "duplicate ID");
        assert!(
            registry.reserve(&SnapshotId::new("second"), 1).is_err(),
            "FD budget"
        );
        assert!(
            registry.reserve(&SnapshotId::new("too-large"), 11).is_err(),
            "byte budget"
        );
        let parallel = {
            let registry = Arc::clone(&registry);
            std::thread::spawn(move || registry.reserve(&SnapshotId::new("race"), 5).is_err())
        };
        assert!(parallel.join().unwrap());
        drop(reservation);
        let next = registry.reserve(&SnapshotId::new("second"), 10).unwrap();
        drop(next);
        let state = registry.state.lock().unwrap();
        assert_eq!(
            (state.bytes, state.descriptors, state.entries.len()),
            (0, 0, 0)
        );
        let byte_bound = BootInputRegistry::new(BootInputBudget::new(10, 2).unwrap());
        let _first = byte_bound.reserve(&first, 7).unwrap();
        assert!(
            byte_bound
                .reserve(&SnapshotId::new("byte-exhaustion"), 4)
                .is_err(),
            "aggregate bytes must be checked before copying"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;

    #[test]
    fn sealed_kernel_rejects_mutation_and_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernel");
        std::fs::write(&path, b"original kernel").unwrap();
        let original = File::open(&path).unwrap();
        let digest = mvm_core::plan::bundle::sha256_hex(b"original kernel");
        assert!(seal_kernel(&original, 15, &"0".repeat(64)).is_err());
        let sealed = seal_kernel(&original, 15, &digest).unwrap();
        let renamed = dir.path().join("old-kernel");
        std::fs::rename(&path, &renamed).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        std::fs::write(renamed, b"modified original inode").unwrap();
        let mut bytes = [0; 15];
        sealed.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"original kernel");
        assert!(sealed.write_at(b"changed", 0).is_err());
        assert!(sealed.set_len(0).is_err());
        verify_seals(&sealed, 15).unwrap();
        assert!(verify_seals(&sealed, 14).is_err());
    }

    #[test]
    fn failed_sealing_releases_a_reservation_before_the_next_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernel");
        std::fs::write(&path, b"kernel bytes").unwrap();
        let source = File::open(path).unwrap();
        let registry = BootInputRegistry::new(BootInputBudget::new(12, 1).unwrap());
        let id = SnapshotId::new("attempt");
        let reservation = registry.reserve(&id, 12).unwrap();
        assert!(seal_kernel(&source, 12, &"0".repeat(64)).is_err());
        drop(reservation);
        assert!(registry.reserve(&id, 12).is_ok());
    }
}
