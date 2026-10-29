// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Adapted from apple-codesign 0.29.0, Copyright Gregory Szorc.
// See ../PROVENANCE.md.

//! Byte-only ad-hoc signing. Native signature authority stays with the caller.
//! No filesystem, process, signing key, CMS, notarization, or network operations.

mod der;
mod macho;
mod signature;

#[cfg(test)]
mod tests;

pub use der::{decode_entitlements_der, encode_entitlements_der};
pub use macho::{Slice, slices, universal_binary};
pub use signature::{CodeDirectory, signature_blobs};

/// A layout refusal is distinct from malformed input: callers must not relink
/// or shift existing data to create room for a signature command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NoSignatureCommandRoom,
    Invalid(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSignatureCommandRoom => f.write_str("no unused space for LC_CODE_SIGNATURE"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for Error {}
impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::Invalid(value.into())
    }
}
impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Replace entitlements on every architecture, retaining compatibility metadata.
/// A failure produces no partially signed output.
pub fn sign(data: &[u8], entitlements: &plist::Value) -> Result<Vec<u8>> {
    let parsed = slices(data)?;
    // Upstream selects legacy compatibility for the entire universal binary.
    let legacy = parsed.iter().any(Slice::needs_sha1);
    let mut xml = Vec::new();
    entitlements
        .to_writer_xml(&mut xml)
        .map_err(|e| Error::from(e.to_string()))?;
    let der = encode_entitlements_der(entitlements)?;
    let mut identifier = None;
    for slice in &parsed {
        if let Some(cd) = slice.code_directory()? {
            identifier = Some(cd.identifier);
            break;
        }
    }
    let identifier = identifier.as_deref().unwrap_or("com.mvm.prepared");
    let signed = parsed
        .iter()
        .map(|slice| signature::sign_slice(slice, &xml, &der, identifier, legacy))
        .collect::<Result<Vec<_>>>()?;
    if parsed[0].offset != 0 {
        universal_binary(&signed)
    } else {
        signed.into_iter().next().ok_or_else(|| "no slices".into())
    }
}
fn range(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset.checked_add(length).ok_or("offset overflow")?;
    data.get(offset..end)
        .ok_or_else(|| "truncated binary".into())
}
fn be32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        range(data, offset, 4)?
            .try_into()
            .map_err(|_| "invalid u32")?,
    ))
}
fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
fn size32(value: usize) -> Result<u32> {
    value
        .try_into()
        .map_err(|_| "Mach-O exceeds 32-bit signature offsets".into())
}
