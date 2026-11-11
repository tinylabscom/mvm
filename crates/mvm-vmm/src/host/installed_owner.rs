//! Local installation exclusion and resource-holder epoch leases.
//! Every installed resource must actually retain a lease before this component
//! can establish recovery of that resource. It grants no mailbox/boot authority.
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const STATE: &str = "state.bin";
const NEXT: &str = ".state.next";
const INTENT: &str = ".state.intent";
const OWNER: &str = "owner.lock";
const HOLDERS: &str = "holders.lock";
const RECORD_BYTES: usize = 176;
const BODY_BYTES: usize = 144;
const DOMAIN: &[u8] = b"spiralcore/installed-owner/v1\0";

#[cfg(test)]
#[path = "installed_owner/binding_tests.rs"]
mod binding_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallationKey {
    pub installation: [u8; 32],
    pub profile: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch {
    key: InstallationKey,
    generation: u64,
}
/// Fresh provisioning facts for library consumers holding an owner and its
/// original Epoch. These values are not credentials or a worker activation
/// grant, and cannot reconstruct an owner or resource descriptor.
pub struct InstallationBinding {
    pub root: PathBuf,
    pub key: InstallationKey,
    pub generation: u64,
}
impl Epoch {
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Clean,
    Active,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerSnapshot {
    pub phase: Phase,
    pub epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    AlreadyClean,
    Retired { epoch: u64 },
}
#[derive(Debug)]
pub enum OwnerError {
    Busy,
    RecoveryRequired,
    InvalidStorage,
    StaleEpoch,
    EpochExhausted,
    Fenced,
    Io(io::Error),
}
impl fmt::Display for OwnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "installed owner: {self:?}")
    }
}
impl std::error::Error for OwnerError {}
impl From<io::Error> for OwnerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
type Result<T> = std::result::Result<T, OwnerError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObjectId {
    device: u64,
    inode: u64,
}
fn object_id(file: &File) -> Result<ObjectId> {
    let m = file.metadata()?;
    Ok(ObjectId {
        device: m.dev(),
        inode: m.ino(),
    })
}
fn check_key(key: InstallationKey) -> Result<()> {
    if key.installation == [0; 32] || key.profile == [0; 32] {
        return Err(OwnerError::InvalidStorage);
    }
    Ok(())
}
fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| OwnerError::InvalidStorage)
}
fn storage_open_error(error: io::Error) -> OwnerError {
    match error.raw_os_error() {
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::EISDIR) => {
            OwnerError::InvalidStorage
        }
        _ => OwnerError::Io(error),
    }
}
fn open_root(path: &Path) -> Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err(OwnerError::InvalidStorage);
    }
    let path = c_path(path)?;
    // SAFETY: live NUL-terminated path; open returns a new owned descriptor.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(storage_open_error(io::Error::last_os_error()));
    }
    // SAFETY: successful open returned a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    check_private(&file, true)?;
    check_filesystem(&file)?;
    Ok(file)
}
fn check_private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata()?;
    // SAFETY: geteuid has no inputs and does not change process credentials.
    let uid = unsafe { libc::geteuid() };
    if m.uid() != uid
        || m.mode() & 0o777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(OwnerError::InvalidStorage);
    }
    check_acl(file)
}

#[cfg(not(target_os = "macos"))]
fn check_acl(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_acl(file: &File) -> Result<()> {
    // Apple sys/acl.h: ACL_TYPE_EXTENDED=0x100, ACL_FIRST_ENTRY=0.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry: libc::c_int,
            out: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_free(value: *mut libc::c_void) -> libc::c_int;
    }
    // SAFETY: borrowed live descriptor, supported extended ACL type.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // Apple Libc obtains FILESEC_ACL from fstatx_np. An absent ACL
        // property returns ENOENT even when the descriptor's object exists;
        // check_private already validated this live descriptor's metadata.
        return if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOATTR)) {
            Ok(())
        } else {
            Err(error.into())
        };
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: kernel-produced ACL, valid first index and writable output.
    let found = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = io::Error::last_os_error();
    // SAFETY: release the sole copy returned by acl_get_fd_np exactly once.
    let freed = unsafe { acl_free(acl) };
    if freed != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // Darwin returns zero for an entry, -1/EINVAL for an empty valid ACL.
    if found == 0 {
        return Err(OwnerError::InvalidStorage);
    }
    if found == -1 && error.raw_os_error() == Some(libc::EINVAL) {
        Ok(())
    } else {
        Err(error.into())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn check_filesystem(file: &File) -> Result<()> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: live directory descriptor and appropriately sized writable output.
    if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful fstatfs initialized the whole structure.
    let info = unsafe { info.assume_init() };
    #[cfg(target_os = "linux")]
    let supported = matches!(
        info.f_type,
        libc::EXT4_SUPER_MAGIC
            | libc::XFS_SUPER_MAGIC
            | libc::BTRFS_SUPER_MAGIC
            | libc::TMPFS_MAGIC
            | libc::OVERLAYFS_SUPER_MAGIC
    );
    #[cfg(target_os = "macos")]
    let supported = {
        let name: Vec<_> = info
            .f_fstypename
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        info.f_flags & libc::MNT_LOCAL as u32 != 0 && matches!(name.as_slice(), b"apfs" | b"hfs")
    };
    if supported {
        Ok(())
    } else {
        Err(OwnerError::InvalidStorage)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn check_filesystem(_file: &File) -> Result<()> {
    Err(OwnerError::InvalidStorage)
}
fn open_at(dir: &File, name: &str, flags: i32) -> Result<File> {
    let name = CString::new(name).map_err(|_| OwnerError::InvalidStorage)?;
    // SAFETY: live directory/path, fixed flags/mode; fresh descriptor on success.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(storage_open_error(io::Error::last_os_error()));
    }
    // SAFETY: this successful openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    check_private(&file, false)?;
    Ok(file)
}
fn lock(file: &File, shared: bool) -> Result<()> {
    let result = if shared {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    result.map_err(|e| match e {
        fs::TryLockError::WouldBlock => OwnerError::Busy,
        fs::TryLockError::Error(e) => OwnerError::Io(e),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    key: InstallationKey,
    generation: u64,
    phase: Phase,
    directory: ObjectId,
    owner: ObjectId,
    holders: ObjectId,
}
impl Record {
    fn encode(self) -> [u8; RECORD_BYTES] {
        let mut b = [0; RECORD_BYTES];
        b[..8].copy_from_slice(b"SCOWNER1");
        b[8] = u8::from(self.phase == Phase::Active);
        b[16..24].copy_from_slice(&self.generation.to_be_bytes());
        b[24..56].copy_from_slice(&self.key.installation);
        b[56..88].copy_from_slice(&self.key.profile);
        for (offset, id) in [(88, self.directory), (104, self.owner), (120, self.holders)] {
            b[offset..offset + 8].copy_from_slice(&id.device.to_be_bytes());
            b[offset + 8..offset + 16].copy_from_slice(&id.inode.to_be_bytes());
        }
        b[136..144].copy_from_slice(b"ENDOWN01");
        let digest = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&b[..BODY_BYTES])
            .finalize();
        b[BODY_BYTES..].copy_from_slice(&digest);
        b
    }
    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != RECORD_BYTES
            || &b[..8] != b"SCOWNER1"
            || b[8] > 1
            || b[9..16] != [0; 7]
            || &b[136..144] != b"ENDOWN01"
        {
            return Err(OwnerError::InvalidStorage);
        }
        let digest = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&b[..BODY_BYTES])
            .finalize();
        if digest[..] != b[BODY_BYTES..] {
            return Err(OwnerError::InvalidStorage);
        }
        let number =
            |at| u64::from_be_bytes(b[at..at + 8].try_into().expect("checked fixed record"));
        let id = |at| ObjectId {
            device: number(at),
            inode: number(at + 8),
        };
        let key = InstallationKey {
            installation: b[24..56].try_into().expect("fixed"),
            profile: b[56..88].try_into().expect("fixed"),
        };
        check_key(key)?;
        Ok(Self {
            key,
            generation: number(16),
            phase: if b[8] == 0 {
                Phase::Clean
            } else {
                Phase::Active
            },
            directory: id(88),
            owner: id(104),
            holders: id(120),
        })
    }
}

struct Storage {
    root: PathBuf,
    directory: File,
    key: InstallationKey,
    ids: [ObjectId; 3],
}
impl Storage {
    fn open(root: &Path, key: InstallationKey) -> Result<(Arc<Self>, File)> {
        check_key(key)?;
        let directory = open_root(root)?;
        let owner = open_at(&directory, OWNER, libc::O_RDWR)?;
        let holders = open_at(&directory, HOLDERS, libc::O_RDWR)?;
        let ids = [
            object_id(&directory)?,
            object_id(&owner)?,
            object_id(&holders)?,
        ];
        Ok((
            Arc::new(Self {
                root: root.to_path_buf(),
                directory,
                key,
                ids,
            }),
            owner,
        ))
    }
    fn check(&self) -> Result<()> {
        if object_id(&open_root(&self.root)?)? != self.ids[0] {
            return Err(OwnerError::InvalidStorage);
        }
        check_private(&self.directory, true)?;
        for (name, id) in [(OWNER, self.ids[1]), (HOLDERS, self.ids[2])] {
            if object_id(&open_at(&self.directory, name, libc::O_RDWR)?)? != id {
                return Err(OwnerError::InvalidStorage);
            }
        }
        Ok(())
    }
    fn no_temp(&self) -> Result<()> {
        for name in [NEXT, INTENT] {
            let name = CString::new(name).expect("fixed name");
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: live directory/name, writable output; output is not read.
            let result = unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                return Err(OwnerError::Fenced);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error.into());
            }
        }
        Ok(())
    }
    fn read(&self) -> Result<Record> {
        self.check()?;
        self.no_temp()?;
        let mut b = Vec::with_capacity(RECORD_BYTES + 1);
        open_at(&self.directory, STATE, libc::O_RDONLY)?
            .take((RECORD_BYTES + 1) as u64)
            .read_to_end(&mut b)?;
        let r = Record::decode(&b)?;
        if r.key != self.key || [r.directory, r.owner, r.holders] != self.ids {
            return Err(OwnerError::InvalidStorage);
        }
        Ok(r)
    }
    fn publish(&self, record: Record) -> Result<()> {
        self.check()?;
        self.no_temp()?;
        let intent = self.start_intent(record)?;
        let mut next = open_at(
            &self.directory,
            NEXT,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        next.write_all(&record.encode())?;
        next.sync_all()?;
        let from = CString::new(NEXT).expect("fixed name");
        let to = CString::new(STATE).expect("fixed name");
        self.check()?;
        // SAFETY: both fixed names are relative to the live validated directory.
        if unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                from.as_ptr(),
                self.directory.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        #[cfg(test)]
        tests::before_state_directory_sync(self)?;
        self.directory.sync_all()?;
        self.clear_intent(intent)?;
        Ok(())
    }
    fn start_intent(&self, record: Record) -> Result<File> {
        let mut file = open_at(
            &self.directory,
            INTENT,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        file.write_all(b"SCINT001")?;
        file.write_all(&record.generation.to_be_bytes())?;
        file.write_all(&record.encode()[BODY_BYTES..])?;
        #[cfg(test)]
        tests::before_intent_file_sync(self)?;
        file.sync_all()?;
        #[cfg(test)]
        tests::before_intent_directory_sync(self)?;
        self.directory.sync_all()?;
        // No state mutation precedes this confirmed intent-directory barrier.
        Ok(file)
    }
    fn clear_intent(&self, intent: File) -> Result<()> {
        self.check()?;
        let path_file = open_at(&self.directory, INTENT, libc::O_RDONLY)?;
        if object_id(&path_file)? != object_id(&intent)? {
            return Err(OwnerError::Fenced);
        }
        let name = CString::new(INTENT).expect("fixed name");
        // SAFETY: fixed private name in the retained validated directory.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // Marker removal is post-commit: state-directory sync already succeeded.
        #[cfg(test)]
        tests::before_intent_cleanup_directory_sync(self)?;
        self.directory.sync_all()?;
        Ok(())
    }
    fn exclusive_holders(&self) -> Result<File> {
        self.locked_holders(false)
    }
    fn locked_holders(&self, shared: bool) -> Result<File> {
        self.check()?;
        #[cfg(test)]
        tests::before_holders_open(self)?;
        let file = open_at(&self.directory, HOLDERS, libc::O_RDWR)?;
        #[cfg(test)]
        tests::after_holders_open(self)?;
        if object_id(&file)? != self.ids[2] {
            return Err(OwnerError::InvalidStorage);
        }
        lock(&file, shared)?;
        self.check()?;
        Ok(file)
    }
}

/// Owned resources for the fixed local backend handoff, not boot authority.
pub struct HolderHandoff {
    pub directory: File,
    pub holder: File,
    pub state_bytes: u16,
    pub state_sha256: [u8; 32],
}

pub struct HolderLease {
    _storage: Arc<Storage>,
    _holder: File,
    generation: u64,
}
impl HolderLease {
    pub fn acquire(root: &Path, key: InstallationKey, expected_generation: u64) -> Result<Self> {
        let (storage, _unlocked_owner) = Storage::open(root, key)?;
        Self::from_storage(storage, expected_generation)
    }
    fn from_storage(storage: Arc<Storage>, expected_generation: u64) -> Result<Self> {
        let holder = storage.locked_holders(true)?;
        let record = storage.read()?;
        if record.phase != Phase::Active || record.generation != expected_generation {
            return Err(OwnerError::StaleEpoch);
        }
        Ok(Self {
            _storage: storage,
            _holder: holder,
            generation: expected_generation,
        })
    }

    /// Revalidate the acquired epoch before exporting duplicate descriptions.
    /// Their shared lock lasts until the final holder description is closed.
    pub fn prepare_handoff(&self) -> Result<HolderHandoff> {
        let record = self._storage.read()?;
        if record.phase != Phase::Active || record.generation != self.generation {
            return Err(OwnerError::StaleEpoch);
        }
        let directory = self._storage.directory.try_clone()?;
        let holder = self._holder.try_clone()?;
        if object_id(&directory)? != self._storage.ids[0]
            || object_id(&holder)? != self._storage.ids[2]
        {
            return Err(OwnerError::InvalidStorage);
        }
        Ok(HolderHandoff {
            directory,
            holder,
            state_bytes: RECORD_BYTES as u16,
            state_sha256: Sha256::digest(record.encode()).into(),
        })
    }
}

#[cfg(test)]
#[path = "installed_owner/tests.rs"]
mod tests;

pub struct InstallationOwner {
    storage: Arc<Storage>,
    record: Record,
    fenced: AtomicBool,
    supervisor: Option<HolderLease>,
    // Drop owner authority last, after this owner's SH lease. Never unlock a
    // borrowed/inherited descriptor or publish Clean in Drop.
    _owner: File,
}
impl InstallationOwner {
    /// Fresh local provisioning facts for the original active epoch. This is
    /// neither a resource descriptor nor permission to activate a worker.
    pub fn active_binding(&self, expected: Epoch) -> Result<InstallationBinding> {
        let record = self.current()?;
        if record.phase != Phase::Active
            || record.key != expected.key
            || record.generation != expected.generation
        {
            return Err(OwnerError::StaleEpoch);
        }
        Ok(InstallationBinding {
            root: self.storage.root.clone(),
            key: record.key,
            generation: record.generation,
        })
    }

    /// Fresh local provisioning identity; it conveys no guest boot permission.
    pub fn profile_hash(&self) -> Result<[u8; 32]> {
        Ok(self.current()?.key.profile)
    }

    pub fn initialize(root: &Path, key: InstallationKey) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        check_key(key)?;
        let parent = open_root(root.parent().ok_or(OwnerError::InvalidStorage)?)?;
        fs::DirBuilder::new().mode(0o700).create(root)?;
        let directory = open_root(root)?;
        for name in [OWNER, HOLDERS] {
            open_at(
                &directory,
                name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            )?
            .sync_all()?;
        }
        let (storage, owner) = Storage::open(root, key)?;
        lock(&owner, false)?;
        let record = Record {
            key,
            generation: 0,
            phase: Phase::Clean,
            directory: storage.ids[0],
            owner: storage.ids[1],
            holders: storage.ids[2],
        };
        storage.publish(record)?;
        parent.sync_all()?;
        Ok(Self {
            storage,
            record,
            fenced: AtomicBool::new(false),
            supervisor: None,
            _owner: owner,
        })
    }
    pub fn open(root: &Path, key: InstallationKey) -> Result<Self> {
        let (storage, owner) = Storage::open(root, key)?;
        lock(&owner, false)?;
        let record = storage.read()?;
        Ok(Self {
            storage,
            record,
            fenced: AtomicBool::new(false),
            supervisor: None,
            _owner: owner,
        })
    }
    fn current(&self) -> Result<Record> {
        if self.fenced.load(Ordering::Acquire) {
            return Err(OwnerError::Fenced);
        }
        match self.storage.read() {
            Ok(record) if record == self.record => Ok(record),
            Ok(_) => {
                self.fenced.store(true, Ordering::Release);
                Err(OwnerError::Fenced)
            }
            Err(OwnerError::InvalidStorage | OwnerError::Fenced) => {
                self.fenced.store(true, Ordering::Release);
                Err(OwnerError::Fenced)
            }
            Err(e) => {
                self.fenced.store(true, Ordering::Release);
                Err(e)
            }
        }
    }
    fn commit(&mut self, record: Record) -> Result<()> {
        if let Err(e) = self.storage.publish(record) {
            self.fenced.store(true, Ordering::Release);
            return Err(e);
        }
        self.record = record;
        Ok(())
    }
    fn holders_for_transition(&self) -> Result<File> {
        match self.storage.exclusive_holders() {
            Ok(file) => Ok(file),
            Err(OwnerError::Busy) => Err(OwnerError::Busy),
            Err(OwnerError::InvalidStorage | OwnerError::Fenced) => {
                self.fenced.store(true, Ordering::Release);
                Err(OwnerError::Fenced)
            }
            Err(error) => {
                self.fenced.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
    pub fn snapshot(&self) -> Result<OwnerSnapshot> {
        let record = self.current()?;
        Ok(OwnerSnapshot {
            phase: record.phase,
            epoch: record.generation,
        })
    }
    pub fn begin(&mut self) -> Result<Epoch> {
        let mut record = self.current()?;
        if record.phase != Phase::Clean {
            return Err(OwnerError::RecoveryRequired);
        }
        let exclusive = self.holders_for_transition()?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(OwnerError::EpochExhausted)?;
        record.phase = Phase::Active;
        self.commit(record)?;
        drop(exclusive);
        match HolderLease::from_storage(self.storage.clone(), record.generation) {
            Ok(lease) => self.supervisor = Some(lease),
            Err(e) => {
                self.fenced.store(true, Ordering::Release);
                return Err(e);
            }
        }
        Ok(Epoch {
            key: record.key,
            generation: record.generation,
        })
    }
    pub fn finish(&mut self, epoch: Epoch) -> Result<()> {
        let mut record = self.current()?;
        if epoch.key != record.key
            || epoch.generation != record.generation
            || record.phase != Phase::Active
        {
            return Err(OwnerError::StaleEpoch);
        }
        self.supervisor.take();
        let _exclusive = self.holders_for_transition()?;
        record.phase = Phase::Clean;
        self.commit(record)
    }
    pub fn reconcile(&mut self) -> Result<Recovery> {
        let mut record = self.current()?;
        if record.phase == Phase::Clean {
            return Ok(Recovery::AlreadyClean);
        }
        self.supervisor.take();
        let _exclusive = self.holders_for_transition()?;
        record.phase = Phase::Clean;
        self.commit(record)?;
        Ok(Recovery::Retired {
            epoch: record.generation,
        })
    }
}
