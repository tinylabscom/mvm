//! Errors returned by the ext4rs driver.

use std::io;

#[derive(Debug)]
pub enum Error {
    /// Underlying device I/O failure.
    Io(io::Error),
    /// Magic number mismatch — not an ext4 filesystem.
    BadMagic { found: u16, expected: u16 },
    /// On-disk structure failed checksum validation.
    BadChecksum { what: &'static str },
    /// Filesystem uses an INCOMPAT feature we don't implement.
    UnsupportedIncompat(u32),
    /// Filesystem uses a RO_COMPAT feature we don't implement (read-only mount required anyway).
    UnsupportedRoCompat(u32),
    /// Path component or inode not found.
    NotFound,
    /// Path resolution hit a non-directory mid-walk.
    NotADirectory,
    /// Operation refused because the target is a directory and the syscall
    /// only operates on regular files (POSIX EISDIR — used by `unlink(2)`,
    /// `truncate(2)`, etc).
    IsADirectory,
    /// Target already exists (POSIX EEXIST — used by `create(2)`, `mkdir(2)`,
    /// `rename(2)` when no-replace is requested).
    AlreadyExists,
    /// Directory must be empty (POSIX ENOTEMPTY — used by `rmdir(2)`,
    /// `rename(2)` replacing a non-empty dir).
    DirectoryNotEmpty,
    /// Write attempted on a device opened read-only (POSIX EROFS).
    ReadOnly,
    /// Path component longer than EXT4_NAME_LEN (255 bytes) — POSIX
    /// ENAMETOOLONG.
    NameTooLong,
    /// Container (xattr in-inode region, xattr block, etc.) has no free
    /// space for the requested entry — POSIX ENOSPC.
    NoSpaceLeftOnDevice,
    /// Caller passed a malformed argument or attempted a semantically
    /// invalid mutation (POSIX EINVAL — e.g. truncate-grow, moving a dir
    /// into its own subtree, operating on a legacy non-EXTENTS inode).
    InvalidArgument(&'static str),
    /// Inode number is invalid (0, > total inodes, etc.).
    InvalidInode(u32),
    /// Block number is invalid (> total blocks).
    InvalidBlock(u64),
    /// Read/write past end of file.
    OutOfBounds,
    /// Extent tree structure is corrupt.
    CorruptExtentTree(&'static str),
    /// Directory entry corrupt (rec_len out of range, name too long, etc.).
    CorruptDirEntry(&'static str),
    /// Generic spec-violation error.
    Corrupt(&'static str),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::BadMagic { found, expected } => {
                write!(f, "bad magic: 0x{found:04x} (expected 0x{expected:04x})")
            }
            Error::BadChecksum { what } => write!(f, "{what} checksum mismatch"),
            Error::UnsupportedIncompat(bits) => {
                write!(f, "unsupported INCOMPAT features: 0x{bits:08x}")
            }
            Error::UnsupportedRoCompat(bits) => {
                write!(f, "unsupported RO_COMPAT features: 0x{bits:08x}")
            }
            Error::NotFound => write!(f, "not found"),
            Error::NotADirectory => write!(f, "not a directory"),
            Error::IsADirectory => write!(f, "is a directory"),
            Error::AlreadyExists => write!(f, "already exists"),
            Error::DirectoryNotEmpty => write!(f, "directory not empty"),
            Error::ReadOnly => write!(f, "read-only filesystem"),
            Error::NameTooLong => write!(f, "name too long"),
            Error::NoSpaceLeftOnDevice => write!(f, "no space left on device"),
            Error::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Error::InvalidInode(n) => write!(f, "invalid inode number {n}"),
            Error::InvalidBlock(n) => write!(f, "invalid block number {n}"),
            Error::OutOfBounds => write!(f, "out of bounds"),
            Error::CorruptExtentTree(msg) => write!(f, "corrupt extent tree: {msg}"),
            Error::CorruptDirEntry(msg) => write!(f, "corrupt directory entry: {msg}"),
            Error::Corrupt(msg) => write!(f, "corrupt: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Map an error to a POSIX errno suitable for the C ABI / FSKit.
    ///
    /// Values are macOS POSIX errno numbers (which match Linux for every
    /// code used here — the divergence only starts at ENOTSUP).
    pub fn to_errno(&self) -> i32 {
        match self {
            Error::Io(e) => e.raw_os_error().unwrap_or(EIO),
            Error::NotFound => ENOENT,
            Error::NotADirectory => ENOTDIR,
            Error::IsADirectory => EISDIR,
            Error::AlreadyExists => EEXIST,
            Error::DirectoryNotEmpty => ENOTEMPTY,
            Error::ReadOnly => EROFS,
            Error::NameTooLong => ENAMETOOLONG,
            Error::NoSpaceLeftOnDevice => ENOSPC,
            Error::InvalidArgument(_) => EINVAL,
            Error::InvalidInode(_) | Error::InvalidBlock(_) | Error::OutOfBounds => EINVAL,
            Error::BadMagic { .. }
            | Error::BadChecksum { .. }
            | Error::CorruptExtentTree(_)
            | Error::CorruptDirEntry(_)
            | Error::Corrupt(_) => EIO,
            Error::UnsupportedIncompat(_) | Error::UnsupportedRoCompat(_) => ENOTSUP,
        }
    }
}

/// POSIX errno values (macOS). Also match Linux for all codes referenced here
/// except ENOTSUP (Linux uses 95, macOS uses 45). We target FSKit on macOS.
pub mod errno {
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const EROFS: i32 = 30;
    pub const ENOSPC: i32 = 28;
    pub const ENAMETOOLONG: i32 = 63; // macOS POSIX value
    pub const ENOTSUP: i32 = 45;
    pub const ENOTEMPTY: i32 = 66; // macOS POSIX value
    pub const ENOSYS: i32 = 78; // macOS POSIX value (Linux: 38). Surfaced
                                // by capi when a feature isn't implemented yet.
}

use errno::*;
