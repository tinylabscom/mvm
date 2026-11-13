//! Budgeted Linux memfds for immutable boot input bytes.
//!
//! Sealing an input proves byte immutability, not its signature, admission,
//! VMM custody or permission to reuse a warm parent.

#![allow(unsafe_code)]

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

#[derive(Debug, Default)]
struct Usage {
    bytes: u64,
    files: usize,
}

/// Page-rounded memfd data and file-count limits shared by one owner.
#[derive(Debug, Clone)]
pub struct SealedBootBudget {
    max_bytes: u64,
    max_files: usize,
    usage: Arc<Mutex<Usage>>,
}

impl SealedBootBudget {
    /// Set the maximum charged data bytes and owned files.
    pub fn new(max_bytes: u64, max_files: usize) -> Self {
        Self {
            max_bytes,
            max_files,
            usage: Arc::new(Mutex::new(Usage::default())),
        }
    }

    fn reserve(&self, bytes: u64) -> io::Result<Reservation> {
        // SAFETY: sysconf only queries the host page size.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::last_os_error());
        }
        let page = page as u64;
        let charged = bytes
            .checked_add(page - 1)
            .map(|rounded| rounded / page * page)
            .ok_or_else(|| io::Error::other("sealed boot input size overflow"))?;
        let mut usage = self
            .usage
            .lock()
            .map_err(|_| io::Error::other("boot budget poisoned"))?;
        if bytes == 0
            || usage
                .bytes
                .checked_add(charged)
                .is_none_or(|sum| sum > self.max_bytes)
            || usage.files >= self.max_files
        {
            return Err(io::Error::other(
                "sealed boot input exceeds resident budget",
            ));
        }
        usage.bytes += charged;
        usage.files += 1;
        Ok(Reservation {
            usage: Arc::clone(&self.usage),
            bytes: charged,
        })
    }

    /// Copy one already authenticated file into a sealed, inode-independent view.
    ///
    /// The digest expectation must come from an independently verified signed
    /// closure; a caller-supplied digest alone does not authorize a boot.
    ///
    /// # Errors
    ///
    /// Refuses size/digest mismatch, non-files, quota exhaustion or failed
    /// kernel sealing without exposing an unsealed descriptor.
    pub fn seal(
        &self,
        source: &File,
        expected_size: u64,
        expected_sha256: &str,
    ) -> io::Result<SealedBootFile> {
        let mut expected = [0u8; 32];
        hex::decode_to_slice(expected_sha256, &mut expected)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid SHA-256 digest"))?;
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.len() != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "boot input is not a regular file of the expected size",
            ));
        }
        let reservation = self.reserve(expected_size)?;
        // SAFETY: `memfd_create` receives a constant NUL-terminated name;
        // the returned descriptor is owned only when the syscall succeeds.
        let fd = unsafe {
            libc::memfd_create(
                c"mvm-sealed-boot".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful memfd_create returned a fresh owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut hash = Sha256::new();
        let mut offset = 0;
        let mut buffer = [0u8; 64 * 1024];
        while offset < expected_size {
            let remaining = (expected_size - offset).min(buffer.len() as u64) as usize;
            let read = match source.read_at(&mut buffer[..remaining], offset) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "boot input shrank",
                ));
            }
            hash.update(&buffer[..read]);
            file.write_all(&buffer[..read])?;
            offset += read as u64;
        }
        let actual: [u8; 32] = hash.finalize().into();
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "boot input digest changed",
            ));
        }
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: these calls only seal and inspect the owned memfd.
        let applied = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) };
        if applied != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_GET_SEALS reads the seal mask from the same owned memfd.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } != seals {
            return Err(io::Error::other(
                "sealed boot input lost its required seals",
            ));
        }
        Ok(SealedBootFile {
            file,
            _reservation: reservation,
            sha256: expected,
        })
    }
}

#[derive(Debug)]
struct Reservation {
    usage: Arc<Mutex<Usage>>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut usage) = self.usage.lock() {
            usage.bytes -= self.bytes;
            usage.files -= 1;
        }
    }
}

/// An immutable file and its resident reservation, not an admitted VM lease.
#[derive(Debug)]
#[must_use = "retain the sealed file until every VMM inheriting it has exited"]
pub struct SealedBootFile {
    file: File,
    _reservation: Reservation,
    sha256: [u8; 32],
}

impl SealedBootFile {
    /// Borrow the original while retaining this owner through the VMM's exit.
    ///
    /// Duplicating the descriptor without retaining this value would release
    /// its memory reservation while another process still holds those pages.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Return the digest verified while copying, not a publisher identity.
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_bytes_refuse_mutation_and_release_the_reservation() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("kernel");
        std::fs::write(&source, b"authenticated-by-caller").unwrap();
        let input = File::open(&source).unwrap();
        let digest = hex::encode(Sha256::digest(b"authenticated-by-caller"));
        // SAFETY: sysconf only queries the page size for this test's budget.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let budget = SealedBootBudget::new(page, 1);
        let sealed = budget.seal(&input, 23, &digest).unwrap();
        assert_eq!(
            sealed.sha256(),
            <[u8; 32]>::from(Sha256::digest(b"authenticated-by-caller"))
        );
        assert!(budget.seal(&input, 23, &digest).is_err());
        assert_eq!(
            sealed
                .file()
                .write_at(b"tamper", 0)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        std::fs::write(&source, b"changed-after-sealing").unwrap();
        let mut bytes = [0u8; 23];
        sealed.file().read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"authenticated-by-caller");
        drop(sealed);
        std::fs::write(&source, b"authenticated-by-caller").unwrap();
        assert!(budget.seal(&input, 23, &digest).is_ok());
    }

    #[test]
    fn bad_input_cannot_allocate_or_publish_a_sealed_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("input");
        std::fs::write(&path, b"valid").unwrap();
        let input = File::open(&path).unwrap();
        let digest = hex::encode(Sha256::digest(b"valid"));
        // SAFETY: sysconf only queries the page size for this test's budget.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let budget = SealedBootBudget::new(page, 1);
        assert!(
            SealedBootBudget::new(page - 1, 1)
                .seal(&input, 5, &digest)
                .is_err()
        );
        assert!(budget.seal(&input, 4, &digest).is_err());
        assert!(budget.seal(&input, 5, &"0".repeat(64)).is_err());
        assert!(budget.seal(&input, 5, "not-a-digest").is_err());
        assert!(
            budget
                .seal(&File::open(tmp.path()).unwrap(), 5, &digest)
                .is_err()
        );
        let sealed = budget.seal(&input, 5, &digest).unwrap();
        assert_eq!(sealed.sha256(), <[u8; 32]>::from(Sha256::digest(b"valid")));
    }
}
