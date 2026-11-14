//! Transport-wrapper decompression for signed application archives.
//!
//! The signed object stays the uncompressed tar named by the descriptor's
//! `archive_sha256` and `archive_size`. When a descriptor carries a
//! [`RegistryBundleTransport`], the acquisition path fetches the compressed
//! asset, pins it to `compressed_sha256`/`compressed_size`, then recovers the
//! signed tar through [`decompress_transport_archive`]. Every step fails
//! closed: a missing, truncated, oversized or mismatched asset is an error,
//! never a degraded plain download.

use std::io::Read;
use std::path::Path;

use sha2::Digest as _;
use thiserror::Error;

use super::application::{RegistryApplicationBundle, RegistryBundleTransport};
use crate::plan::bundle::HashingWriter;

/// Why a compressed transport asset could not be recovered as the signed tar.
#[derive(Debug, Error)]
pub enum RegistryTransportError {
    #[error("transport asset i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("compressed asset size differs from its signed transport declaration")]
    CompressedSize,
    #[error("compressed asset digest differs from its signed transport declaration")]
    CompressedDigest,
    #[error("decompressed archive exceeds its signed size")]
    Size,
    #[error("decompressed archive digest differs from its signed descriptor")]
    Digest,
}

/// Recover the signed uncompressed tar from a compressed transport asset.
///
/// The compressed bytes are pinned to `transport.compressed_sha256` and
/// `transport.compressed_size`, then decompressed under a hard cap of
/// `bundle.archive_size` bytes (a decompression-bomb bound), and the
/// decompressed bytes must hash to `bundle.archive_sha256`. The result is a
/// temporary file holding exactly the signed tar, suitable for the ordinary
/// bundle-verification path.
pub fn decompress_transport_archive(
    compressed: &Path,
    transport: &RegistryBundleTransport,
    bundle: &RegistryApplicationBundle,
) -> Result<tempfile::TempPath, RegistryTransportError> {
    let input = super::local_input::open_sized_regular(compressed, transport.compressed_size)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::Other {
                RegistryTransportError::CompressedSize
            } else {
                RegistryTransportError::Io(error)
            }
        })?;
    let mut pinned = input.take(transport.compressed_size.saturating_add(1));
    let mut hasher = sha2::Sha256::new();
    let mut compressed_size = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = pinned.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        compressed_size = compressed_size.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    if compressed_size != transport.compressed_size {
        return Err(RegistryTransportError::CompressedSize);
    }
    if hex::encode(hasher.finalize()) != transport.compressed_sha256.as_str() {
        return Err(RegistryTransportError::CompressedDigest);
    }
    let cap = bundle
        .archive_size
        .checked_add(1)
        .ok_or(RegistryTransportError::Size)?;
    let input = super::local_input::open_sized_regular(compressed, transport.compressed_size)
        .map_err(RegistryTransportError::Io)?;
    let mut decoded: Box<dyn Read> = match transport.compression {
        super::application::RegistryTransportCompression::Gzip => {
            Box::new(flate2::read::GzDecoder::new(input).take(cap))
        }
    };
    let mut snapshot = tempfile::NamedTempFile::new()?;
    let mut writer = HashingWriter::new(snapshot.as_file_mut());
    std::io::copy(&mut decoded, &mut writer)?;
    let (size, digest) = writer.finish();
    if size > bundle.archive_size {
        return Err(RegistryTransportError::Size);
    }
    if digest != bundle.archive_sha256.as_str() {
        return Err(RegistryTransportError::Digest);
    }
    snapshot.as_file().sync_all()?;
    Ok(snapshot.into_temp_path())
}

#[cfg(test)]
mod tests;
