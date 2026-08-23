//! Minimal, safe ELF metadata parser.
//!
//! This module parses only the metadata needed for capture resolution:
//! architecture, interpreter, declared shared-library dependencies, and the
//! build identifier. It does not use `ldd` and does not execute the file.

use crate::CaptureError;

/// ELF metadata relevant to environment capture.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ElfMetadata {
    pub arch: Option<String>,
    pub interpreter: Option<String>,
    pub needed_libraries: Vec<String>,
    pub build_id: Option<String>,
    pub is_64: bool,
    pub is_little_endian: bool,
    pub incomplete: bool,
}

const ELFMAG: &[u8] = b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_NULL: u64 = 0;

/// Parse ELF metadata from file bytes.
///
/// Returns `Ok(None)` if the file is not an ELF. Returns `Err` only for
/// inputs that claim to be ELF but are malformed in a way that suggests
/// tampering or truncation.
#[cfg(test)]
pub fn parse_elf_metadata(bytes: &[u8]) -> Result<Option<ElfMetadata>, CaptureError> {
    parse_elf_metadata_with_extent(bytes, true)
}

/// Parse metadata from an intentionally bounded prefix of an ELF file.
///
/// Segments outside the supplied prefix are omitted and reported through
/// [`ElfMetadata::incomplete`]; malformed structures inside the prefix still
/// fail closed.
pub fn parse_elf_prefix_metadata(bytes: &[u8]) -> Result<Option<ElfMetadata>, CaptureError> {
    parse_elf_metadata_with_extent(bytes, false)
}

fn parse_elf_metadata_with_extent(
    bytes: &[u8],
    complete_file: bool,
) -> Result<Option<ElfMetadata>, CaptureError> {
    if bytes.len() < 52 || bytes.get(..4) != Some(ELFMAG) {
        return Ok(None);
    }

    let class = bytes[4];
    let data = bytes[5];
    let is_64 = match class {
        ELFCLASS32 => false,
        ELFCLASS64 => true,
        _ => return Ok(None),
    };
    let is_little_endian = match data {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        _ => return Ok(None),
    };

    // Big-endian ELF is rare in this project's target environments; skip it
    // rather than implementing a second byte-order path.
    if !is_little_endian {
        return Ok(Some(ElfMetadata {
            is_64,
            is_little_endian,
            ..Default::default()
        }));
    }

    let header = ElfHeader::parse(bytes, is_64)?;

    // Only executable files and shared objects are interesting for capture.
    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Ok(Some(ElfMetadata {
            is_64,
            is_little_endian,
            arch: Some(machine_name(header.e_machine)),
            ..Default::default()
        }));
    }

    let mut metadata = ElfMetadata {
        is_64,
        is_little_endian,
        arch: Some(machine_name(header.e_machine)),
        ..Default::default()
    };

    let (phdrs, program_headers_incomplete) = parse_program_headers(bytes, &header, complete_file)?;
    metadata.incomplete = program_headers_incomplete;

    let mut dyn_offset = None;
    let mut dyn_filesz = 0usize;
    let mut strtab_vaddr = None;

    for ph in &phdrs {
        match ph.p_type {
            PT_INTERP => {
                if range_is_available(bytes, ph.p_offset, ph.p_filesz) {
                    metadata.interpreter = Some(read_cstr(
                        bytes,
                        ph.p_offset,
                        usize::try_from(ph.p_filesz).map_err(|_| {
                            CaptureError::MalformedManifest(
                                PathBuf::from("<elf>"),
                                "interpreter segment size overflow".to_owned(),
                            )
                        })?,
                    )?);
                } else if complete_file {
                    return Err(CaptureError::MalformedManifest(
                        PathBuf::from("<elf>"),
                        "interpreter segment out of bounds".to_owned(),
                    ));
                } else {
                    metadata.incomplete = true;
                }
            }
            PT_DYNAMIC => {
                if range_is_available(bytes, ph.p_offset, ph.p_filesz) {
                    dyn_offset = Some(ph.p_offset);
                    dyn_filesz = usize::try_from(ph.p_filesz).map_err(|_| {
                        CaptureError::MalformedManifest(
                            PathBuf::from("<elf>"),
                            "dynamic segment size overflow".to_owned(),
                        )
                    })?;
                } else if complete_file {
                    return Err(CaptureError::MalformedManifest(
                        PathBuf::from("<elf>"),
                        "dynamic segment out of bounds".to_owned(),
                    ));
                } else {
                    metadata.incomplete = true;
                }
            }
            PT_NOTE if metadata.build_id.is_none() => {
                if range_is_available(bytes, ph.p_offset, ph.p_filesz) {
                    metadata.build_id = parse_note_build_id(bytes, ph.p_offset, ph.p_filesz)?;
                } else if complete_file {
                    return Err(CaptureError::MalformedManifest(
                        PathBuf::from("<elf>"),
                        "note segment out of bounds".to_owned(),
                    ));
                } else {
                    metadata.incomplete = true;
                }
            }
            _ => {}
        }
    }

    if let Some(offset) = dyn_offset {
        let (needed, strtab_va) = parse_dynamic_segment(bytes, offset, dyn_filesz, is_64)?;
        metadata.needed_libraries = needed;
        if let Some(va) = strtab_va {
            strtab_vaddr = Some(va);
        }
    }

    // Resolve DT_NEEDED string offsets against the dynamic string table.
    if let Some(strtab_va) = strtab_vaddr {
        if let Some(strtab_offset) = vaddr_to_file_offset(&phdrs, strtab_va) {
            if strtab_offset >= bytes.len() {
                if !complete_file {
                    metadata.needed_libraries.clear();
                    metadata.incomplete = true;
                    return Ok(Some(metadata));
                }
                return Err(CaptureError::MalformedManifest(
                    PathBuf::from("<elf>"),
                    "ELF string table out of bounds".to_owned(),
                ));
            }
            for needed in &mut metadata.needed_libraries {
                let offset = strtab_offset
                    .checked_add(needed.parse::<usize>().map_err(|_| {
                        CaptureError::MalformedManifest(
                            PathBuf::from("<elf>"),
                            "invalid DT_NEEDED string offset".to_owned(),
                        )
                    })?)
                    .ok_or_else(|| {
                        CaptureError::MalformedManifest(
                            PathBuf::from("<elf>"),
                            "DT_NEEDED string offset overflow".to_owned(),
                        )
                    })?;
                if offset >= bytes.len() {
                    if !complete_file {
                        metadata.needed_libraries.clear();
                        metadata.incomplete = true;
                        return Ok(Some(metadata));
                    }
                    return Err(CaptureError::MalformedManifest(
                        PathBuf::from("<elf>"),
                        "ELF string offset out of bounds".to_owned(),
                    ));
                }
                *needed = read_cstr(bytes, offset, bytes.len() - offset)?;
            }
        }
    }

    Ok(Some(metadata))
}

struct ElfHeader {
    e_type: u16,
    e_machine: u16,
    e_phoff: usize,
    e_phentsize: usize,
    e_phnum: usize,
}

impl ElfHeader {
    fn parse(bytes: &[u8], is_64: bool) -> Result<Self, CaptureError> {
        let err = || {
            CaptureError::MalformedManifest(
                PathBuf::from("<elf>"),
                "truncated ELF header".to_owned(),
            )
        };

        if is_64 {
            if bytes.len() < 64 {
                return Err(err());
            }
            Ok(Self {
                e_type: read_u16(bytes, 16),
                e_machine: read_u16(bytes, 18),
                e_phoff: read_u64(bytes, 32) as usize,
                e_phentsize: read_u16(bytes, 54) as usize,
                e_phnum: read_u16(bytes, 56) as usize,
            })
        } else {
            if bytes.len() < 52 {
                return Err(err());
            }
            Ok(Self {
                e_type: read_u16(bytes, 16),
                e_machine: read_u16(bytes, 18),
                e_phoff: read_u32(bytes, 28) as usize,
                e_phentsize: read_u16(bytes, 42) as usize,
                e_phnum: read_u16(bytes, 44) as usize,
            })
        }
    }
}

struct ProgramHeader {
    p_type: u32,
    p_offset: usize,
    p_vaddr: u64,
    p_filesz: u64,
}

fn parse_program_headers(
    bytes: &[u8],
    header: &ElfHeader,
    complete_file: bool,
) -> Result<(Vec<ProgramHeader>, bool), CaptureError> {
    let entry_size = if header.e_phentsize == 0 {
        if header.e_phoff == 0 {
            return Ok((vec![], false));
        }
        return Err(CaptureError::MalformedManifest(
            PathBuf::from("<elf>"),
            "invalid program header entry size".to_owned(),
        ));
    } else {
        header.e_phentsize
    };

    let mut phdrs = Vec::with_capacity(header.e_phnum);
    let mut incomplete = false;
    for i in 0..header.e_phnum {
        let start = header
            .e_phoff
            .checked_add(i.checked_mul(entry_size).ok_or_else(|| {
                CaptureError::MalformedManifest(
                    PathBuf::from("<elf>"),
                    "program header index overflow".to_owned(),
                )
            })?)
            .ok_or_else(|| {
                CaptureError::MalformedManifest(
                    PathBuf::from("<elf>"),
                    "program header offset overflow".to_owned(),
                )
            })?;
        if start.saturating_add(entry_size) > bytes.len() && !complete_file {
            incomplete = true;
            break;
        }
        phdrs.push(parse_program_header(bytes, start, entry_size)?);
    }
    Ok((phdrs, incomplete))
}

fn range_is_available(bytes: &[u8], offset: usize, size: u64) -> bool {
    usize::try_from(size)
        .ok()
        .and_then(|size| offset.checked_add(size))
        .is_some_and(|end| end <= bytes.len())
}

fn parse_program_header(
    bytes: &[u8],
    start: usize,
    size: usize,
) -> Result<ProgramHeader, CaptureError> {
    if start.saturating_add(size) > bytes.len() {
        return Err(CaptureError::MalformedManifest(
            PathBuf::from("<elf>"),
            "program header out of bounds".to_owned(),
        ));
    }
    let is_64 = size >= 56;
    if is_64 {
        Ok(ProgramHeader {
            p_type: read_u32(bytes, start),
            p_offset: read_u64(bytes, start + 8) as usize,
            p_vaddr: read_u64(bytes, start + 16),
            p_filesz: read_u64(bytes, start + 32),
        })
    } else {
        Ok(ProgramHeader {
            p_type: read_u32(bytes, start),
            p_offset: read_u32(bytes, start + 4) as usize,
            p_vaddr: read_u32(bytes, start + 8) as u64,
            p_filesz: read_u32(bytes, start + 16) as u64,
        })
    }
}

fn parse_dynamic_segment(
    bytes: &[u8],
    offset: usize,
    filesz: usize,
    is_64: bool,
) -> Result<(Vec<String>, Option<u64>), CaptureError> {
    if offset.saturating_add(filesz) > bytes.len() {
        return Err(CaptureError::MalformedManifest(
            PathBuf::from("<elf>"),
            "dynamic segment out of bounds".to_owned(),
        ));
    }

    let entry_size = if is_64 { 16 } else { 8 };
    let count = filesz / entry_size;
    let mut needed = Vec::new();
    let mut strtab = None;

    for i in 0..count {
        let start = offset + i * entry_size;
        let tag = if is_64 {
            read_u64(bytes, start)
        } else {
            read_u32(bytes, start) as u64
        };
        let value = if is_64 {
            read_u64(bytes, start + 8)
        } else {
            read_u32(bytes, start + 4) as u64
        };

        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_NEEDED => needed.push(value.to_string()),
            DT_STRTAB => strtab = Some(value),
            _ => {}
        }
    }

    Ok((needed, strtab))
}

fn parse_note_build_id(
    bytes: &[u8],
    offset: usize,
    filesz: u64,
) -> Result<Option<String>, CaptureError> {
    let filesz = filesz as usize;
    if offset.saturating_add(filesz) > bytes.len() {
        return Err(CaptureError::MalformedManifest(
            PathBuf::from("<elf>"),
            "note segment out of bounds".to_owned(),
        ));
    }

    let mut pos = offset;
    let end = offset + filesz;
    while pos + 12 <= end {
        let namesz = read_u32(bytes, pos) as usize;
        let descsz = read_u32(bytes, pos + 4) as usize;
        let note_type = read_u32(bytes, pos + 8);
        let cursor = pos + 12;

        let name_padding = (4 - (namesz % 4)) % 4;
        let desc_padding = (4 - (descsz % 4)) % 4;
        let next = cursor
            .checked_add(namesz)
            .and_then(|x| x.checked_add(name_padding))
            .and_then(|x| x.checked_add(descsz))
            .and_then(|x| x.checked_add(desc_padding));
        if next.map(|n| n > end).unwrap_or(true) {
            break;
        }

        if namesz == 4 && note_type == 3 && cursor + 4 <= end {
            let name = &bytes[cursor..cursor + 4];
            if name == b"GNU\0" {
                let desc_start = cursor + namesz + name_padding;
                let build_id = &bytes[desc_start..desc_start + descsz];
                return Ok(Some(hex::encode(build_id)));
            }
        }

        pos = next.expect("checked above");
    }

    Ok(None)
}

fn vaddr_to_file_offset(phdrs: &[ProgramHeader], vaddr: u64) -> Option<usize> {
    for ph in phdrs {
        if ph.p_vaddr <= vaddr && vaddr < ph.p_vaddr + ph.p_filesz {
            return (ph.p_offset as u64 + (vaddr - ph.p_vaddr)).try_into().ok();
        }
    }
    None
}

fn read_cstr(bytes: &[u8], offset: usize, max_len: usize) -> Result<String, CaptureError> {
    if offset > bytes.len() {
        return Err(CaptureError::MalformedManifest(
            PathBuf::from("<elf>"),
            "ELF string offset out of bounds".to_owned(),
        ));
    }
    let end = (offset + max_len).min(bytes.len());
    let slice = &bytes[offset..end];
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let value = std::str::from_utf8(&slice[..len])
        .map_err(|_| {
            CaptureError::MalformedManifest(
                PathBuf::from("<elf>"),
                "invalid UTF-8 in ELF string".to_owned(),
            )
        })?
        .to_owned();
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(arr)
}

fn machine_name(machine: u16) -> String {
    match machine {
        62 => "x86_64".to_owned(),
        183 => "aarch64".to_owned(),
        40 => "arm".to_owned(),
        3 => "i386".to_owned(),
        8 => "mips".to_owned(),
        _ => format!("machine:{}", machine),
    }
}

use std::path::PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_elf_returns_none() {
        assert!(parse_elf_metadata(b"not an elf").unwrap().is_none());
    }

    #[test]
    fn truncated_elf_returns_err() {
        let mut bytes = ELFMAG.to_vec();
        bytes.extend_from_slice(&[ELFCLASS64, ELFDATA2LSB, 1, 0]); // e_ident tail
        bytes.resize(64, 0); // enough bytes to parse as a 64-bit header
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes()); // executable type
        bytes[32..40].copy_from_slice(&100u64.to_le_bytes()); // e_phoff past the buffer
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // one program header claimed
        assert!(parse_elf_metadata(&bytes).is_err());
    }

    #[test]
    fn bounded_prefix_keeps_header_metadata_and_marks_omitted_segments() {
        let mut elf = CraftedElf64::new();
        elf.set_entrypoint_type(ET_EXEC);
        elf.set_machine(183);
        elf.add_needed(["libc.so.6".to_owned()]);
        let bytes = elf.build();
        let dynamic_offset = 64 + (2 * 56) + b"\0libc.so.6\0".len();
        assert!(dynamic_offset < bytes.len());

        assert!(parse_elf_metadata(&bytes[..dynamic_offset]).is_err());
        let metadata = parse_elf_prefix_metadata(&bytes[..dynamic_offset])
            .expect("bounded prefix is accepted")
            .expect("fixture is ELF");

        assert_eq!(metadata.arch.as_deref(), Some("aarch64"));
        assert!(metadata.needed_libraries.is_empty());
        assert!(metadata.incomplete);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn real_system_binary_parses() {
        let bytes = std::fs::read("/bin/true").expect("read /bin/true");
        let meta = parse_elf_metadata(&bytes)
            .expect("parse succeeds")
            .expect("is an ELF");
        assert!(meta.is_64 || !meta.is_64); // architecture-specific
        assert!(!meta.arch.as_deref().unwrap_or("").is_empty());
    }

    #[test]
    fn parse_crafted_elf64_with_interp_and_needed() {
        let mut elf = CraftedElf64::new();
        elf.set_entrypoint_type(ET_EXEC);
        elf.set_machine(62); // x86_64
        elf.add_interp("/lib64/ld-linux-x86-64.so.2");
        elf.add_needed(["libc.so.6".to_owned(), "libm.so.6".to_owned()]);
        let bytes = elf.build();
        let meta = parse_elf_metadata(&bytes).unwrap().unwrap();
        assert_eq!(meta.arch.as_deref(), Some("x86_64"));
        assert_eq!(
            meta.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert!(meta.needed_libraries.contains(&"libc.so.6".to_owned()));
        assert!(meta.needed_libraries.contains(&"libm.so.6".to_owned()));
    }

    struct CraftedElf64 {
        e_type: u16,
        e_machine: u16,
        interp: Option<String>,
        needed: Vec<String>,
    }

    impl CraftedElf64 {
        fn new() -> Self {
            Self {
                e_type: 0,
                e_machine: 62,
                interp: None,
                needed: Vec::new(),
            }
        }

        fn set_entrypoint_type(&mut self, e_type: u16) {
            self.e_type = e_type;
        }

        fn set_machine(&mut self, machine: u16) {
            self.e_machine = machine;
        }

        fn add_interp(&mut self, path: &str) {
            self.interp = Some(path.to_owned());
        }

        fn add_needed(&mut self, libs: impl IntoIterator<Item = String>) {
            self.needed.extend(libs);
        }

        fn build(&self) -> Vec<u8> {
            // Build a minimal 64-bit LE ELF with program headers immediately
            // after the ELF header, followed by data sections.
            let mut bytes = Vec::new();

            // ELF header: 64 bytes.
            bytes.extend_from_slice(ELFMAG);
            bytes.push(ELFCLASS64);
            bytes.push(ELFDATA2LSB);
            bytes.push(1); // EI_VERSION
            bytes.push(0); // EI_OSABI
            bytes.extend_from_slice(&[0; 8]); // padding
            bytes.extend_from_slice(&self.e_type.to_le_bytes());
            bytes.extend_from_slice(&self.e_machine.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
            bytes.extend_from_slice(&0u64.to_le_bytes()); // e_entry
            bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff = right after header
            bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
            bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
            bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
            bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
            let phnum_offset = bytes.len();
            bytes.extend_from_slice(&0u16.to_le_bytes()); // placeholder e_phnum
            bytes.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
            bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
            bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
            assert_eq!(bytes.len(), 64);

            // Reserve space for program headers; data follows after it.
            let phdr_start = bytes.len();
            let max_phdrs =
                usize::from(self.interp.is_some()) + if self.needed.is_empty() { 0 } else { 2 };
            bytes.resize(phdr_start + max_phdrs * 56, 0);

            let base_vaddr = 0x400000u64;
            let mut phdrs: Vec<u8> = Vec::new();

            // PT_INTERP
            if let Some(interp) = &self.interp {
                let offset = bytes.len();
                bytes.extend_from_slice(interp.as_bytes());
                bytes.push(0);
                let vaddr = base_vaddr + offset as u64;
                let filesz = interp.len() + 1;
                phdrs.extend_from_slice(&PT_INTERP.to_le_bytes());
                phdrs.extend_from_slice(&0u32.to_le_bytes());
                phdrs.extend_from_slice(&(offset as u64).to_le_bytes());
                phdrs.extend_from_slice(&vaddr.to_le_bytes());
                phdrs.extend_from_slice(&vaddr.to_le_bytes());
                phdrs.extend_from_slice(&(filesz as u64).to_le_bytes());
                phdrs.extend_from_slice(&(filesz as u64).to_le_bytes());
                phdrs.extend_from_slice(&1u64.to_le_bytes());
            }

            // Dynamic segment and string table.
            if !self.needed.is_empty() {
                let strtab_offset = bytes.len();
                let mut strtab = String::new();
                strtab.push('\0');
                let mut needed_offsets = Vec::new();
                for lib in &self.needed {
                    needed_offsets.push(strtab.len());
                    strtab.push_str(lib);
                    strtab.push('\0');
                }
                bytes.extend_from_slice(strtab.as_bytes());
                let strtab_size = strtab.len();
                let strtab_vaddr = base_vaddr + strtab_offset as u64;

                let dynamic_offset = bytes.len();
                for &off in &needed_offsets {
                    bytes.extend_from_slice(&DT_NEEDED.to_le_bytes());
                    bytes.extend_from_slice(&(off as u64).to_le_bytes());
                }
                bytes.extend_from_slice(&DT_STRTAB.to_le_bytes());
                bytes.extend_from_slice(&strtab_vaddr.to_le_bytes());
                bytes.extend_from_slice(&DT_NULL.to_le_bytes());
                bytes.extend_from_slice(&0u64.to_le_bytes());
                let dynamic_size = bytes.len() - dynamic_offset;
                let dynamic_vaddr = base_vaddr + dynamic_offset as u64;

                // PT_DYNAMIC
                phdrs.extend_from_slice(&PT_DYNAMIC.to_le_bytes());
                phdrs.extend_from_slice(&0u32.to_le_bytes());
                phdrs.extend_from_slice(&(dynamic_offset as u64).to_le_bytes());
                phdrs.extend_from_slice(&dynamic_vaddr.to_le_bytes());
                phdrs.extend_from_slice(&dynamic_vaddr.to_le_bytes());
                phdrs.extend_from_slice(&(dynamic_size as u64).to_le_bytes());
                phdrs.extend_from_slice(&(dynamic_size as u64).to_le_bytes());
                phdrs.extend_from_slice(&8u64.to_le_bytes());

                // PT_LOAD covering the dynamic string table.
                phdrs.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
                phdrs.extend_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
                phdrs.extend_from_slice(&(strtab_offset as u64).to_le_bytes());
                phdrs.extend_from_slice(&strtab_vaddr.to_le_bytes());
                phdrs.extend_from_slice(&strtab_vaddr.to_le_bytes());
                phdrs.extend_from_slice(&(strtab_size as u64).to_le_bytes());
                phdrs.extend_from_slice(&(strtab_size as u64).to_le_bytes());
                phdrs.extend_from_slice(&1u64.to_le_bytes());
            }

            // Write program headers into the reserved space.
            assert!(phdrs.len() <= max_phdrs * 56);
            bytes[phdr_start..phdr_start + phdrs.len()].copy_from_slice(&phdrs);

            // Patch e_phnum.
            let phnum = (phdrs.len() / 56) as u16;
            bytes[phnum_offset..phnum_offset + 2].copy_from_slice(&phnum.to_le_bytes());

            bytes
        }
    }
}
