//! Refusals on hosts without the supported Unix owner-only permission model.

use super::{OpenOptionsModeExt, unsupported_platform_error};
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io;
use std::path::Path;

/// Refuse ownership validation on hosts without the supported Unix model.
pub fn require_current_owner(_metadata: &Metadata) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "effective-user ownership validation is unsupported on this host",
    ))
}

impl OpenOptionsModeExt for OpenOptions {
    fn open_with_mode(&self, _mode: u32, path: impl AsRef<Path>) -> io::Result<File> {
        Err(unsupported_platform_error(path.as_ref()))
    }
}

/// Refuse permission changes on hosts without Unix permission bits.
pub fn set_mode(path: impl AsRef<Path>, _mode: u32) -> io::Result<()> {
    Err(unsupported_platform_error(path.as_ref()))
}

/// Refuse permission creation on hosts without Unix permission bits.
pub fn permissions(subject: &Path, _mode: u32) -> io::Result<Permissions> {
    Err(unsupported_platform_error(subject))
}

/// Refuse permission inspection on hosts without Unix permission bits.
pub fn mode_bits(path: &Path, _meta: &Metadata) -> io::Result<u32> {
    Err(unsupported_platform_error(path))
}

/// Refuse directory creation on hosts without Unix permission bits.
pub fn ensure_private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    Err(unsupported_platform_error(dir.as_ref()))
}

/// Refuse directory creation on hosts without Unix permission bits.
pub fn create_owned_private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    Err(unsupported_platform_error(dir.as_ref()))
}

/// Refuse managed-directory sync on hosts without Unix permission bits.
pub fn sync_managed_directory_chain(root: &Path, _directory: &Path) -> io::Result<()> {
    Err(unsupported_platform_error(root))
}
