//! Just enough ELF64 to read a shared object's `DT_NEEDED` list.
//!
//! One question is asked of this module: which libraries does this object
//! require at load time. That answers which libc an artifact was really built
//! against, which is the only reliable way to tell the two SDK-sidecar variants
//! apart — naming a `*-linux-musl` target while linking through the host `cc`
//! produces a clean build of a *glibc* object, so a build's exit code, its
//! target triple and its file name all agree with each other and are all wrong.
//! The `NEEDED` soname is the one thing that comes from the artifact itself.
//!
//! Deliberately not a general ELF crate. It reads little-endian ELF64, which is
//! both guest architectures mvm targets, and refuses everything else rather than
//! growing arms nothing calls.

use thiserror::Error;

/// Failure reading an object's dynamic requirements.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ElfError {
    /// The bytes are not a little-endian ELF64 object.
    #[error("not a little-endian ELF64 object: {reason}")]
    NotElf64Le {
        /// What about the header disagreed.
        reason: String,
    },

    /// A header or table pointed outside the bytes supplied.
    #[error("ELF structure out of bounds: {what}")]
    OutOfBounds {
        /// The structure whose bounds check failed.
        what: String,
    },

    /// The object records dynamic entries but no string table to resolve them.
    #[error("ELF has a dynamic section with no resolvable DT_STRTAB")]
    NoStringTable,
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;

/// One program header, in the two fields this module needs from each kind.
#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

/// The `DT_NEEDED` sonames `object` records, in the order the object lists them.
///
/// An object with no dynamic section needs nothing and returns empty — a fully
/// static object is a legitimate answer to the question, not an error.
pub fn needed_sonames(object: &[u8]) -> Result<Vec<String>, ElfError> {
    let headers = program_headers(object)?;
    let Some(dynamic) = headers.iter().find(|h| h.kind == PT_DYNAMIC) else {
        return Ok(Vec::new());
    };
    let entries = dynamic_entries(object, *dynamic)?;

    let strtab_vaddr = entries
        .iter()
        .find_map(|(tag, val)| (*tag == DT_STRTAB).then_some(*val));
    let needed: Vec<u64> = entries
        .iter()
        .filter_map(|(tag, val)| (*tag == DT_NEEDED).then_some(*val))
        .collect();
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let strtab_vaddr = strtab_vaddr.ok_or(ElfError::NoStringTable)?;
    let strtab = vaddr_to_offset(&headers, strtab_vaddr).ok_or(ElfError::NoStringTable)?;

    needed
        .into_iter()
        .map(|name_offset| read_c_string(object, strtab.saturating_add(name_offset)))
        .collect()
}

/// Parse the program header table, validating the identity bytes first.
fn program_headers(object: &[u8]) -> Result<Vec<ProgramHeader>, ElfError> {
    if object.len() < 64 {
        return Err(ElfError::NotElf64Le {
            reason: format!("only {} bytes; an ELF64 header is 64", object.len()),
        });
    }
    if object[0..4] != ELF_MAGIC {
        return Err(ElfError::NotElf64Le {
            reason: "missing the \\x7fELF magic".to_string(),
        });
    }
    if object[4] != ELFCLASS64 {
        return Err(ElfError::NotElf64Le {
            reason: format!("EI_CLASS {} is not ELFCLASS64", object[4]),
        });
    }
    if object[5] != ELFDATA2LSB {
        return Err(ElfError::NotElf64Le {
            reason: format!("EI_DATA {} is not little-endian", object[5]),
        });
    }

    let phoff = read_u64(object, 0x20)?;
    let phentsize = u64::from(read_u16(object, 0x36)?);
    let phnum = u64::from(read_u16(object, 0x38)?);
    if phentsize < 56 {
        return Err(ElfError::NotElf64Le {
            reason: format!("e_phentsize {phentsize} is smaller than an ELF64 program header"),
        });
    }

    let mut headers = Vec::with_capacity(usize::try_from(phnum).unwrap_or_default());
    for index in 0..phnum {
        let base = phoff
            .checked_add(index.checked_mul(phentsize).ok_or(ElfError::OutOfBounds {
                what: "program header table extent".to_string(),
            })?)
            .ok_or(ElfError::OutOfBounds {
                what: "program header table extent".to_string(),
            })?;
        headers.push(ProgramHeader {
            kind: read_u32(object, base)?,
            offset: read_u64(object, base + 0x08)?,
            vaddr: read_u64(object, base + 0x10)?,
            filesz: read_u64(object, base + 0x20)?,
        });
    }
    Ok(headers)
}

/// The `(tag, value)` pairs of the dynamic section, stopping at `DT_NULL`.
fn dynamic_entries(object: &[u8], dynamic: ProgramHeader) -> Result<Vec<(u64, u64)>, ElfError> {
    let mut entries = Vec::new();
    let mut cursor = dynamic.offset;
    let end = dynamic
        .offset
        .checked_add(dynamic.filesz)
        .ok_or(ElfError::OutOfBounds {
            what: "dynamic section extent".to_string(),
        })?;
    while cursor + 16 <= end {
        let tag = read_u64(object, cursor)?;
        if tag == DT_NULL {
            break;
        }
        entries.push((tag, read_u64(object, cursor + 8)?));
        cursor += 16;
    }
    Ok(entries)
}

/// Translate a virtual address to a file offset through the `PT_LOAD` map.
///
/// `DT_STRTAB` holds an address in the object's own address space, not a file
/// offset. For a freshly linked shared object the two often coincide, which is
/// exactly why translating matters: a reader that assumed they were equal would
/// work on every object it was tested against and then misread a linker's.
fn vaddr_to_offset(headers: &[ProgramHeader], vaddr: u64) -> Option<u64> {
    headers
        .iter()
        .filter(|h| h.kind == PT_LOAD)
        .find(|h| vaddr >= h.vaddr && vaddr - h.vaddr < h.filesz)
        .map(|h| h.offset + (vaddr - h.vaddr))
}

fn read_c_string(object: &[u8], offset: u64) -> Result<String, ElfError> {
    let start = usize::try_from(offset).map_err(|_| ElfError::OutOfBounds {
        what: format!("string table offset {offset}"),
    })?;
    let tail = object.get(start..).ok_or(ElfError::OutOfBounds {
        what: format!("string table offset {offset}"),
    })?;
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or(ElfError::OutOfBounds {
            what: format!("unterminated string at offset {offset}"),
        })?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn read_u16(object: &[u8], offset: u64) -> Result<u16, ElfError> {
    Ok(u16::from_le_bytes(read_array(object, offset)?))
}

fn read_u32(object: &[u8], offset: u64) -> Result<u32, ElfError> {
    Ok(u32::from_le_bytes(read_array(object, offset)?))
}

fn read_u64(object: &[u8], offset: u64) -> Result<u64, ElfError> {
    Ok(u64::from_le_bytes(read_array(object, offset)?))
}

fn read_array<const N: usize>(object: &[u8], offset: u64) -> Result<[u8; N], ElfError> {
    let start = usize::try_from(offset).map_err(|_| ElfError::OutOfBounds {
        what: format!("offset {offset}"),
    })?;
    let end = start.checked_add(N).ok_or(ElfError::OutOfBounds {
        what: format!("offset {offset} + {N}"),
    })?;
    let slice = object.get(start..end).ok_or(ElfError::OutOfBounds {
        what: format!("bytes {start}..{end} of a {}-byte object", object.len()),
    })?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_fixture {
    /// Build a little-endian ELF64 shared object recording `needed`.
    ///
    /// Real enough for the reader under test: one `PT_LOAD` covering the whole
    /// file, one `PT_DYNAMIC`, and a string table the dynamic entries index
    /// into. The load segment is given a non-zero base address so the
    /// address-to-offset translation is genuinely exercised rather than passing
    /// because the two happened to be equal.
    #[must_use]
    pub fn shared_object(needed: &[&str]) -> Vec<u8> {
        const LOAD_VADDR: u64 = 0x1000;
        let mut strtab = vec![0u8];
        let mut name_offsets = Vec::new();
        for name in needed {
            name_offsets.push(strtab.len() as u64);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        let ehsize = 64u64;
        let phentsize = 56u64;
        let phnum = 2u64;
        let dyn_offset = ehsize + phentsize * phnum;
        let dyn_size = ((name_offsets.len() as u64) + 2) * 16;
        let strtab_offset = dyn_offset + dyn_size;

        let mut out = vec![0u8; usize::try_from(strtab_offset).unwrap()];
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // little-endian
        out[6] = 1; // EV_CURRENT
        out[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        out[0x20..0x28].copy_from_slice(&ehsize.to_le_bytes()); // e_phoff
        out[0x36..0x38].copy_from_slice(&(phentsize as u16).to_le_bytes());
        out[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());

        let total = strtab_offset + strtab.len() as u64;
        write_phdr(&mut out, ehsize, 1, 0, LOAD_VADDR, total); // PT_LOAD
        write_phdr(
            &mut out,
            ehsize + phentsize,
            2, // PT_DYNAMIC
            dyn_offset,
            LOAD_VADDR + dyn_offset,
            dyn_size,
        );

        let mut dynamic = Vec::new();
        for offset in &name_offsets {
            dynamic.extend_from_slice(&1u64.to_le_bytes()); // DT_NEEDED
            dynamic.extend_from_slice(&offset.to_le_bytes());
        }
        dynamic.extend_from_slice(&5u64.to_le_bytes()); // DT_STRTAB
        dynamic.extend_from_slice(&(LOAD_VADDR + strtab_offset).to_le_bytes());
        dynamic.extend_from_slice(&0u64.to_le_bytes()); // DT_NULL
        dynamic.extend_from_slice(&0u64.to_le_bytes());
        let at = usize::try_from(dyn_offset).unwrap();
        out[at..at + dynamic.len()].copy_from_slice(&dynamic);

        out.extend_from_slice(&strtab);
        out
    }

    fn write_phdr(out: &mut [u8], at: u64, kind: u32, offset: u64, vaddr: u64, size: u64) {
        let at = usize::try_from(at).unwrap();
        out[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        out[at + 0x08..at + 0x10].copy_from_slice(&offset.to_le_bytes());
        out[at + 0x10..at + 0x18].copy_from_slice(&vaddr.to_le_bytes());
        out[at + 0x20..at + 0x28].copy_from_slice(&size.to_le_bytes()); // p_filesz
        out[at + 0x28..at + 0x30].copy_from_slice(&size.to_le_bytes()); // p_memsz
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_musl_object_records_the_musl_soname() {
        let object = test_fixture::shared_object(&["libgcc_s.so.1", "libc.so"]);
        assert_eq!(
            needed_sonames(&object).unwrap(),
            vec!["libgcc_s.so.1".to_string(), "libc.so".to_string()]
        );
    }

    /// The glibc bundle records three, including its loader. Order is the
    /// object's own, so a reader cannot be written against a sorted list.
    #[test]
    fn a_glibc_object_records_the_glibc_soname_and_loader() {
        let object =
            test_fixture::shared_object(&["libgcc_s.so.1", "libc.so.6", "ld-linux-aarch64.so.1"]);
        let needed = needed_sonames(&object).unwrap();
        assert_eq!(needed[1], "libc.so.6");
        assert!(needed.contains(&"ld-linux-aarch64.so.1".to_string()));
    }

    /// An object needing nothing is a real answer, not a parse failure.
    #[test]
    fn an_object_with_no_dependencies_needs_nothing() {
        assert!(
            needed_sonames(&test_fixture::shared_object(&[]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_non_elf_blob_is_refused_rather_than_read() {
        let err = needed_sonames(&[0u8; 128]).unwrap_err();
        assert!(matches!(err, ElfError::NotElf64Le { .. }), "{err}");
    }

    #[test]
    fn a_truncated_object_is_refused_rather_than_read() {
        let err = needed_sonames(b"\x7fELF").unwrap_err();
        assert!(matches!(err, ElfError::NotElf64Le { .. }), "{err}");
    }

    /// A 32-bit object is not something this reader can answer for, and
    /// guessing at its layout would read arbitrary bytes as sonames.
    #[test]
    fn a_32_bit_object_is_refused() {
        let mut object = test_fixture::shared_object(&["libc.so"]);
        object[4] = 1; // ELFCLASS32
        assert!(matches!(
            needed_sonames(&object).unwrap_err(),
            ElfError::NotElf64Le { .. }
        ));
    }

    /// A program header table pointing past the end must fail closed rather
    /// than read whatever follows in memory.
    #[test]
    fn a_program_header_table_out_of_bounds_is_refused() {
        let mut object = test_fixture::shared_object(&["libc.so"]);
        object[0x20..0x28].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            needed_sonames(&object).unwrap_err(),
            ElfError::OutOfBounds { .. }
        ));
    }
}
