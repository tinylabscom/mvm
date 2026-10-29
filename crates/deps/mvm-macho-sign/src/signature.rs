// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Adapted from apple-codesign 0.29.0 code_directory.rs, macho_signing.rs,
// embedded_signature.rs and embedded_signature_builder.rs, Copyright Gregory
// Szorc. See ../PROVENANCE.md.

use crate::{Error, Result, Slice, be32, put32, put64, range, size32};
use sha1::Digest as _;
use sha2::Digest as _;
use std::collections::BTreeMap;

/// Compatibility metadata, not certificate or entitlement authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeDirectory {
    pub identifier: String,
    pub flags: u32,
    pub runtime: Option<u32>,
    pub digest_type: u8,
}
impl CodeDirectory {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if be32(data, 0)? != 0xfade_0c02 || be32(data, 4)? as usize != data.len() {
            return Err("invalid CodeDirectory blob".into());
        }
        range(data, 0, 44)?;
        let version = be32(data, 8)?;
        let minimum = match version {
            0x20600.. => 108,
            0x20500.. => 96,
            0x20400.. => 88,
            0x20300.. => 64,
            0x20200.. => 52,
            0x20100.. => 48,
            _ => 44,
        };
        range(data, 0, minimum)?;
        if version < 0x20000 {
            return Err("unsupported CodeDirectory version".into());
        }
        let hash_size = data[36] as usize;
        if !matches!(
            (data[37], hash_size),
            (1, 20) | (2, 32) | (3, 20) | (4, 48) | (5, 64)
        ) {
            return Err("unsupported CodeDirectory digest type or size".into());
        }
        let hash_offset = be32(data, 16)? as usize;
        let special_bytes = (be32(data, 24)? as usize)
            .checked_mul(hash_size)
            .ok_or("special digest overflow")?;
        let special_start = hash_offset
            .checked_sub(special_bytes)
            .ok_or("special digests precede header")?;
        let code_bytes = (be32(data, 28)? as usize)
            .checked_mul(hash_size)
            .ok_or("code digest overflow")?;
        if special_start < minimum {
            return Err("special digests overlap header".into());
        }
        range(data, hash_offset, code_bytes)?;
        let at = be32(data, 20)? as usize;
        if at < minimum {
            return Err("identifier overlaps CodeDirectory header".into());
        }
        let identifier_data = range(
            data,
            at,
            special_start
                .checked_sub(at)
                .ok_or("invalid identifier offset")?,
        )?;
        let end = identifier_data
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated identifier")?;
        let identifier = std::str::from_utf8(&identifier_data[..end])
            .map_err(|e| Error::from(e.to_string()))?
            .to_owned();
        Ok(Self {
            identifier,
            flags: be32(data, 12)?,
            runtime: if version >= 0x20500 {
                Some(be32(data, 88)?)
            } else {
                None
            },
            digest_type: data[37],
        })
    }
}
/// Read raw slots; duplicate, overlapping, truncated blobs are refused.
pub fn signature_blobs(data: &[u8]) -> Result<BTreeMap<u32, &[u8]>> {
    if be32(data, 0)? != 0xfade_0cc0 {
        return Err("invalid signature SuperBlob".into());
    }
    let length = be32(data, 4)? as usize;
    let data = range(data, 0, length)?;
    let count = be32(data, 8)? as usize;
    let table_end = 12usize
        .checked_add(count.checked_mul(8).ok_or("blob count overflow")?)
        .ok_or("blob table overflow")?;
    range(data, 0, table_end)?;
    let mut result = BTreeMap::new();
    let mut extents = Vec::new();
    for index in 0..count {
        let slot = be32(data, 12 + index * 8)?;
        let at = be32(data, 16 + index * 8)? as usize;
        if at < table_end {
            return Err("blob overlaps signature table".into());
        }
        range(data, at, 8)?;
        let length = be32(data, at + 4)? as usize;
        if length < 8 {
            return Err("invalid blob length".into());
        }
        let blob = range(data, at, length)?;
        let end = at + length;
        if extents
            .iter()
            .any(|(start, stop)| at < *stop && end > *start)
        {
            return Err("overlapping signature blobs".into());
        }
        extents.push((at, end));
        if result.insert(slot, blob).is_some() {
            return Err("duplicate signature slot".into());
        }
    }
    Ok(result)
}
fn blob(magic: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let len = payload.len().checked_add(8).ok_or("blob overflow")?;
    let mut data = vec![0; 8];
    put32(&mut data, 0, magic);
    put32(&mut data, 4, size32(len)?);
    data.extend_from_slice(payload);
    Ok(data)
}
fn superblob(blobs: &BTreeMap<u32, Vec<u8>>) -> Result<Vec<u8>> {
    let table_len = 12usize
        .checked_add(blobs.len().checked_mul(8).ok_or("blob table overflow")?)
        .ok_or("blob table overflow")?;
    let mut output = vec![0; table_len];
    put32(&mut output, 0, 0xfade_0cc0);
    put32(&mut output, 8, size32(blobs.len())?);
    for (index, (slot, blob)) in blobs.iter().enumerate() {
        put32(&mut output, 12 + index * 8, *slot);
        let offset = size32(output.len())?;
        put32(&mut output, 16 + index * 8, offset);
        output.extend_from_slice(blob);
    }
    let length = size32(output.len())?;
    put32(&mut output, 4, length);
    Ok(output)
}
fn digest(data: &[u8], legacy: bool) -> Vec<u8> {
    if legacy {
        sha1::Sha1::digest(data).to_vec()
    } else {
        sha2::Sha256::digest(data).to_vec()
    }
}
struct DirectoryInput<'a> {
    slice: &'a Slice<'a>,
    metadata: &'a CodeDirectory,
    specials: &'a BTreeMap<u32, Vec<u8>>,
    legacy: bool,
    entitlement_flags: u64,
}
fn directory(input: DirectoryInput<'_>) -> Result<Vec<u8>> {
    let DirectoryInput {
        slice,
        metadata,
        specials,
        legacy,
        entitlement_flags,
    } = input;
    let code_limit = slice.code_limit()?;
    let code = range(slice.data, 0, code_limit)?;
    let hash_len = if legacy { 20 } else { 32 };
    let runtime = metadata.runtime.or_else(|| {
        if metadata.flags & 0x10000 != 0 {
            slice.sdk()
        } else {
            None
        }
    });
    let mut cd = vec![0; if runtime.is_some() { 96 } else { 88 }];
    put32(&mut cd, 0, 0xfade_0c02);
    put32(
        &mut cd,
        8,
        if runtime.is_some() { 0x20500 } else { 0x20400 },
    );
    put32(&mut cd, 12, (metadata.flags | 2) & !0x20000);
    let ident_offset = size32(cd.len())?;
    put32(&mut cd, 20, ident_offset);
    let highest = specials
        .keys()
        .filter(|slot| **slot <= 11)
        .copied()
        .max()
        .unwrap_or(0)
        .max(if slice.info().is_some() { 1 } else { 0 });
    put32(&mut cd, 24, highest);
    put32(&mut cd, 28, size32(code.len().div_ceil(4096))?);
    put32(&mut cd, 32, size32(code_limit)?);
    cd[36] = hash_len;
    cd[37] = if legacy { 1 } else { 2 };
    cd[39] = 12;
    let (base, limit) = slice.text_boundary()?;
    put64(&mut cd, 64, base);
    put64(&mut cd, 72, limit);
    put64(
        &mut cd,
        80,
        if slice.is_executable()? {
            1 | entitlement_flags
        } else {
            0
        },
    );
    if let Some(runtime) = runtime {
        put32(&mut cd, 88, runtime);
    }
    cd.extend_from_slice(metadata.identifier.as_bytes());
    cd.push(0);
    // Absent negative-indexed special slots contain zero digests.
    for slot in (1..=highest).rev() {
        let source = if slot == 1 {
            slice.info()
        } else {
            specials.get(&slot).map(Vec::as_slice)
        };
        if let Some(source) = source {
            cd.extend_from_slice(&digest(source, legacy));
        } else {
            cd.resize(cd.len() + hash_len as usize, 0);
        }
    }
    let hash_offset = size32(cd.len())?;
    put32(&mut cd, 16, hash_offset);
    for page in code.chunks(4096) {
        cd.extend_from_slice(&digest(page, legacy));
    }
    let length = size32(cd.len())?;
    put32(&mut cd, 4, length);
    Ok(cd)
}
pub(crate) fn sign_slice(
    slice: &Slice<'_>,
    xml: &[u8],
    der: &[u8],
    identifier: &str,
    legacy: bool,
) -> Result<Vec<u8>> {
    let old = slice.signature_blobs()?;
    let metadata = slice.code_directory()?.unwrap_or(CodeDirectory {
        identifier: identifier.into(),
        flags: 0,
        runtime: None,
        digest_type: 2,
    });
    let entitlements =
        plist::Value::from_reader_xml(xml).map_err(|e| Error::from(e.to_string()))?;
    let dict = entitlements
        .as_dictionary()
        .ok_or("entitlements must be a dictionary")?;
    let entitlement_flags = [
        ("get-task-allow", 0x10),
        ("run-unsigned-code", 0x10),
        ("com.apple.private.cs.debugger", 0x20),
        ("dynamic-codesigning", 0x40),
        ("com.apple.private.skip-library-validation", 0x80),
        ("com.apple.private.amfi.can-load-cdhash", 0x100),
        ("com.apple.private.amfi.can-execute-cdhash", 0x200),
    ]
    .into_iter()
    .fold(0, |flags, (key, flag)| {
        if dict.get(key) == Some(&plist::Value::Boolean(true)) {
            flags | flag
        } else {
            flags
        }
    });
    let mut specials = BTreeMap::new();
    specials.insert(2, blob(0xfade_0c01, &0u32.to_be_bytes())?);
    specials.insert(5, blob(0xfade_7171, xml)?);
    specials.insert(7, blob(0xfade_7172, der)?);
    for slot in 8..=11 {
        if let Some(value) = old.get(&slot) {
            if be32(value, 0)? != 0xfade_8181 {
                return Err("invalid constraints blob".into());
            }
            specials.insert(slot, value.to_vec());
        }
    }
    let create = |macho: &Slice<'_>| -> Result<Vec<u8>> {
        let mut blobs = specials.clone();
        blobs.insert(
            0,
            directory(DirectoryInput {
                slice: macho,
                metadata: &metadata,
                specials: &specials,
                legacy,
                entitlement_flags,
            })?,
        );
        if legacy {
            blobs.insert(
                0x1000,
                directory(DirectoryInput {
                    slice: macho,
                    metadata: &metadata,
                    specials: &specials,
                    legacy: false,
                    entitlement_flags,
                })?,
            );
        }
        blobs.insert(0x10000, blob(0xfade_0b01, &[])?);
        superblob(&blobs)
    };
    // First size and rewrite the hashed headers; then hash precisely those bytes.
    let aligned_limit = slice
        .code_limit()?
        .checked_add(15)
        .ok_or("code limit overflow")?
        & !15;
    let pages = aligned_limit.div_ceil(4096);
    let initial_pages = slice.code_limit()?.div_ceil(4096);
    let initial = create(slice)?;
    let extra = (pages - initial_pages) * if legacy { 52 } else { 32 };
    let intermediate = slice.rewrite(&vec![0; initial.len() + extra])?;
    let parsed = crate::slices(&intermediate)?;
    let signature = create(&parsed[0])?;
    if signature.len() != initial.len() + extra {
        return Err("signature size changed during hashing".into());
    }
    parsed[0].rewrite(&signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_preserves_distinct_existing_slice_identifiers() {
        let empty = plist::Value::Dictionary(plist::Dictionary::new());
        let mut seeds = Vec::new();
        for (wide, identifier) in [(true, "com.mvm.first"), (false, "com.mvm.second")] {
            let original = crate::tests::fixture(true, wide, 0x000e_0000);
            let parsed = crate::slices(&original).unwrap();
            let metadata = CodeDirectory {
                identifier: identifier.into(),
                flags: 0,
                runtime: None,
                digest_type: 2,
            };
            let specials = BTreeMap::new();
            let cd = directory(DirectoryInput {
                slice: &parsed[0],
                metadata: &metadata,
                specials: &specials,
                legacy: false,
                entitlement_flags: 0,
            })
            .unwrap();
            let mut blobs = BTreeMap::new();
            blobs.insert(0, cd);
            seeds.push(parsed[0].rewrite(&superblob(&blobs).unwrap()).unwrap());
        }
        let fat = crate::universal_binary(&seeds).unwrap();
        let signed = crate::sign(&fat, &empty).unwrap();
        let parsed = crate::slices(&signed).unwrap();
        for (slice, identifier) in parsed.iter().zip(["com.mvm.first", "com.mvm.second"]) {
            assert_eq!(
                slice.code_directory().unwrap().unwrap().identifier,
                identifier
            );
            crate::tests::assert_hashes(slice);
        }
    }

    #[test]
    fn identifiers_hardening_constraints_and_runtime_sdk_survive_with_fresh_hashes() {
        let original = crate::tests::fixture(true, true, 0x000e_0000);
        let parsed = crate::slices(&original).unwrap();
        for runtime in [None, Some(0x000e_0200)] {
            let metadata = CodeDirectory {
                identifier: "com.mvm.metadata".into(),
                flags: 0x30102,
                runtime,
                digest_type: 2,
            };
            let empty = plist::Value::Dictionary(plist::Dictionary::new());
            let constraint = blob(
                0xfade_8181,
                &crate::encode_entitlements_der(&empty).unwrap(),
            )
            .unwrap();
            let mut specials = BTreeMap::new();
            for slot in 8..=11 {
                specials.insert(slot, constraint.clone());
            }
            let cd = directory(DirectoryInput {
                slice: &parsed[0],
                metadata: &metadata,
                specials: &specials,
                legacy: false,
                entitlement_flags: 0,
            })
            .unwrap();
            specials.insert(0, cd);
            // Stale seed digests are intentionally not signature authority.
            let seeded = parsed[0].rewrite(&superblob(&specials).unwrap()).unwrap();
            let signed = crate::sign(&seeded, &empty).unwrap();
            let output = crate::slices(&signed).unwrap();
            let cd = output[0].code_directory().unwrap().unwrap();
            assert_eq!(cd.identifier, metadata.identifier);
            assert_eq!(cd.flags, 0x10102);
            assert_eq!(cd.runtime, Some(runtime.unwrap_or(0x000e_0000)));
            let blobs = output[0].signature_blobs().unwrap();
            for slot in 8..=11 {
                assert_eq!(blobs[&slot], constraint);
            }
            crate::tests::assert_hashes(&output[0]);
        }
    }
}
