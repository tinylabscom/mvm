use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use crate::core::{MAX_RECORDS, Object, Record, Storage};
use crate::durable::{Publication, commit};
use crate::identity::{MAX_FRAME, decode_record, path_is_valid, trusted_metadata};
use crate::protocol::RegistrationId;
use crate::{Error, REGISTRY, Result};

pub(super) fn object(metadata: &Metadata) -> Object {
    Object {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    }
}

fn cstring(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::Refused)
}

pub(super) fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = cstring(name)?;
    // SAFETY: parent is live; name is NUL-terminated; return value is owned once.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Descriptor-relative walk; reject symlinks, ambiguous names, unsafe ancestors.
/// Workload paths may have ancestors owned by the asserted UID, never others.
pub(super) fn open_path(path: &str, owner: Option<u32>, flags: i32) -> Result<File> {
    if !path_is_valid(path) {
        return Err(Error::Refused);
    }
    let mut directory = File::open("/")?;
    trusted_metadata(directory.metadata()?.uid(), directory.metadata()?.mode())?;
    let components: Vec<_> = path[1..].split('/').collect();
    for (index, name) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let file = open_at(
            &directory,
            name,
            if last {
                flags
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY
            },
            0,
        )?;
        let metadata = file.metadata()?;
        if (!last || owner.is_none())
            && (metadata.uid() != 0 && Some(metadata.uid()) != owner
                || metadata.mode() & 0o6022 != 0 && !(last && metadata.file_type().is_socket()))
        {
            return Err(Error::Refused);
        }
        if !last && !metadata.is_dir() {
            return Err(Error::Refused);
        }
        directory = file;
    }
    Ok(directory)
}

pub(super) fn trusted_file(path: &str) -> Result<File> {
    let file = open_path(path, None, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let metadata = file.metadata()?;
    trusted_metadata(metadata.uid(), metadata.mode())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o111 == 0 {
        return Err(Error::Refused);
    }
    Ok(file)
}

pub(super) fn bounded_read(file: File) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((MAX_FRAME + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    Ok(bytes)
}

pub(crate) struct RootStorage {
    directory: File,
    _lock: File,
}

impl RootStorage {
    /// The operator must precreate the fixed private registry. Never install it.
    pub fn open() -> Result<Self> {
        let directory = open_path(REGISTRY, None, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if directory.metadata()?.mode() & 0o077 != 0 {
            return Err(Error::Refused);
        }
        let lock = open_at(
            &directory,
            ".lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        check_record_metadata(&lock.metadata()?)?;
        // SAFETY: flock operates on the live lock descriptor; nonblocking exclusive.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory.sync_all()?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }
}

fn check_record_metadata(metadata: &Metadata) -> Result<()> {
    trusted_metadata(metadata.uid(), metadata.mode())?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_FRAME as u64
    {
        return Err(Error::Refused);
    }
    Ok(())
}

impl Storage for RootStorage {
    fn load(&self) -> Result<Vec<Record>> {
        // readdir is bound to the directory descriptor, not a re-resolved pathname.
        let mut records = Vec::new();
        let path = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Refused)?;
            if name == ".lock" {
                continue;
            }
            if records.len() >= MAX_RECORDS {
                return Err(Error::Limit);
            }
            let id: RegistrationId =
                serde_json::from_value(serde_json::Value::String(name.clone()))
                    .map_err(|_| Error::Refused)?;
            let file = open_at(&self.directory, &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
            check_record_metadata(&file.metadata()?)?;
            let record = decode_record(&bounded_read(file)?)?;
            if record.id != id {
                return Err(Error::Refused);
            }
            records.push(record);
        }
        Ok(records)
    }

    fn insert(&self, record: &Record) -> Result<()> {
        let bytes = serde_json::to_vec(record).map_err(|_| Error::Refused)?;
        decode_record(&bytes)?;
        // An unnamed inode in the pinned registry cannot be loaded as authority.
        // Unsupported O_TMPFILE/AT_EMPTY_PATH refuses, with no weaker fallback.
        let stage = open_at(&self.directory, ".", libc::O_RDWR | libc::O_TMPFILE, 0o600)?;
        let metadata = stage.metadata()?;
        trusted_metadata(metadata.uid(), metadata.mode())?;
        if !metadata.is_file() || metadata.nlink() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(Error::Refused);
        }
        commit(
            &mut StagedRecord {
                directory: &self.directory,
                stage,
                name: record.id.as_str(),
            },
            &bytes,
        )
    }

    fn random_id(&self) -> Result<RegistrationId> {
        let mut bytes = [0; 32];
        // SAFETY: getrandom writes no more than the initialized buffer length.
        // Nonblocking entropy refusal never falls back to predictable IDs.
        let count =
            unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if usize::try_from(count).ok() != Some(bytes.len()) {
            return Err(Error::Refused);
        }
        Ok(RegistrationId::from_bytes(bytes))
    }
}

struct StagedRecord<'a> {
    directory: &'a File,
    stage: File,
    name: &'a str,
}

impl Publication for StagedRecord<'_> {
    fn write_stage(&mut self, bytes: &[u8]) -> Result<()> {
        self.stage.write_all(bytes)?;
        Ok(())
    }
    fn sync_stage(&mut self) -> Result<()> {
        self.stage.sync_all()?;
        Ok(())
    }
    fn publish_noreplace(&mut self) -> Result<()> {
        let name = cstring(self.name)?;
        // SAFETY: both descriptors are live; empty source selects the unnamed
        // inode. linkat never replaces an existing destination.
        if unsafe {
            libc::linkat(
                self.stage.as_raw_fd(),
                c"".as_ptr(),
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn sync_directory(&mut self) -> Result<()> {
        self.directory.sync_all()?;
        Ok(())
    }
}
