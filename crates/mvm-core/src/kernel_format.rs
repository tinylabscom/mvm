//! Backend-neutral kernel artifact format. Backends accept a subset
//! (see `mvm_runtime::BackendCompat`); libkrun maps the ones it can
//! load to its FFI constants; unsupported variants return an error at
//! the call site rather than failing silently.
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::arch::GuestArch;
use crate::vm_backend::BackendKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelFormat {
    Raw,
    /// Uncompressed ELF `vmlinux` (Firecracker x86_64, libkrun).
    Elf,
    /// Uncompressed arm64 `Image` (Firecracker aarch64). libkrun has no
    /// FFI constant for this; use a compressed variant or the bundled kernel.
    Image,
    ImageGz,
    ImageBz2,
    ImageZstd,
    /// Uncompressed PE. libkrun has no FFI constant for this; use `pe_gz`.
    Pe,
    PeGz,
}

impl KernelFormat {
    /// How many leading bytes [`Self::sniff_magic`] reads: through the x86
    /// setup header, the deepest magic it checks.
    pub const SNIFF_LEN: usize = 0x208;

    /// The stable name, as the wire format spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Elf => "elf",
            Self::Image => "image",
            Self::ImageGz => "image_gz",
            Self::ImageBz2 => "image_bz2",
            Self::ImageZstd => "image_zstd",
            Self::Pe => "pe",
            Self::PeGz => "pe_gz",
        }
    }

    /// Classify an uncompressed kernel by its magic bytes, or `None` when
    /// `head` carries none of them. All three are stable boot ABI:
    ///
    /// - `\x7f E L F` at offset 0 is an ELF `vmlinux`;
    /// - `HdrS` at offset 0x202 is an x86 bzImage's setup header
    ///   (`Documentation/x86/boot.rst`), classified [`Self::Raw`] because no
    ///   direct-boot backend loads one;
    /// - `0x644D5241` (little-endian) at offset 56 is an arm64 `Image`
    ///   (`Documentation/arm64/booting.rst`).
    #[must_use]
    pub fn sniff_magic(head: &[u8]) -> Option<Self> {
        if head.starts_with(b"\x7fELF") {
            return Some(Self::Elf);
        }
        if head.get(0x202..0x206) == Some(b"HdrS".as_slice()) {
            return Some(Self::Raw);
        }
        if head.get(56..60) == Some(0x644D_5241u32.to_le_bytes().as_slice()) {
            return Some(Self::Image);
        }
        None
    }
}

/// The ELF note type that carries an x86 PVH entry point
/// (`XEN_ELFNOTE_PHYS32_ENTRY` in `include/xen/interface/elfnote.h`). A kernel
/// built with `CONFIG_PVH=y` emits it; QEMU's x86 loader looks it up by type.
pub const PVH_ENTRY_NOTE_TYPE: u32 = 18;

/// Upper bound on one `PT_NOTE` segment this reader will load. A vmlinux note
/// segment is a few hundred bytes; anything near this is not a kernel.
const MAX_NOTE_SEGMENT: u64 = 1 << 20;

/// A kernel the selected backend's loader cannot boot, found before the VMM
/// is started.
#[derive(Debug, thiserror::Error)]
pub enum KernelLoadError {
    #[error("reading kernel {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "kernel {path} is an uncompressed ELF vmlinux with no PVH entry note, and \
         qemu-system-x86_64 loads an ELF kernel only through its PVH entry point. \
         This is the kernel Firecracker boots; on QEMU x86_64 use a kernel built \
         with CONFIG_PVH=y or a bzImage, or run the workload on Firecracker"
    )]
    QemuElfWithoutPvhNote { path: PathBuf },
}

/// Refuse a kernel `backend` cannot load on an `arch` guest, before anything
/// is spent starting the VMM.
///
/// Format tables say which *kinds* of kernel a backend boots; this checks the
/// one property they cannot express. QEMU's x86 direct-kernel loader takes a
/// bzImage, or an uncompressed ELF only when the ELF carries a PVH entry note
/// (`Error loading uncompressed kernel without PVH ELF Note`). Firecracker's
/// x86 loader takes the same ELF without one, so "ELF" alone does not say
/// whether QEMU can boot it.
pub fn check_direct_boot_loadable(
    backend: BackendKind,
    arch: GuestArch,
    kernel: &Path,
) -> Result<(), KernelLoadError> {
    if backend != BackendKind::Qemu || arch != GuestArch::X86_64 {
        return Ok(());
    }
    let io_err = |source| KernelLoadError::Io {
        path: kernel.to_path_buf(),
        source,
    };
    let mut file = std::fs::File::open(kernel).map_err(io_err)?;
    let mut head = Vec::with_capacity(KernelFormat::SNIFF_LEN);
    (&mut file)
        .take(KernelFormat::SNIFF_LEN as u64)
        .read_to_end(&mut head)
        .map_err(io_err)?;
    if KernelFormat::sniff_magic(&head) != Some(KernelFormat::Elf) {
        return Ok(());
    }
    if elf_has_pvh_entry_note(&mut file).map_err(io_err)? {
        Ok(())
    } else {
        Err(KernelLoadError::QemuElfWithoutPvhNote {
            path: kernel.to_path_buf(),
        })
    }
}

/// Whether the ELF image in `reader` carries a PVH entry note in one of its
/// `PT_NOTE` segments.
///
/// Mirrors what QEMU's loader does: it walks the program headers, not the
/// section table, and matches the note by type alone. Both ELF classes are
/// read; only little-endian is accepted, since only an x86 image is asked.
pub fn elf_has_pvh_entry_note<R: Read + Seek>(reader: &mut R) -> io::Result<bool> {
    let header = ElfHeader::read(reader)?;
    for index in 0..header.phnum {
        let entry = header.phoff + u64::from(index) * u64::from(header.phentsize);
        let segment = header.read_program_header(reader, entry)?;
        if segment.p_type != PT_NOTE {
            continue;
        }
        if segment.filesz > MAX_NOTE_SEGMENT {
            return Err(invalid("PT_NOTE segment is implausibly large"));
        }
        let size = usize::try_from(segment.filesz)
            .map_err(|_| invalid("PT_NOTE segment does not fit in memory"))?;
        let mut notes = vec![0u8; size];
        reader.seek(SeekFrom::Start(segment.offset))?;
        reader.read_exact(&mut notes)?;
        if notes_contain_type(&notes, segment.align, PVH_ENTRY_NOTE_TYPE) {
            return Ok(true);
        }
    }
    Ok(false)
}

const PT_NOTE: u32 = 4;

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

struct ElfHeader {
    is64: bool,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

struct ProgramHeader {
    p_type: u32,
    offset: u64,
    filesz: u64,
    align: u64,
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

impl ElfHeader {
    fn read<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        let mut ident = [0u8; 64];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut ident[..52])?;
        if &ident[..4] != b"\x7fELF" {
            return Err(invalid("not an ELF image"));
        }
        if ident[5] != 1 {
            return Err(invalid("not a little-endian ELF image"));
        }
        let header = match ident[4] {
            1 => Self {
                is64: false,
                phoff: u64::from(le_u32(&ident, 0x1c)),
                phentsize: le_u16(&ident, 0x2a),
                phnum: le_u16(&ident, 0x2c),
            },
            2 => {
                reader.read_exact(&mut ident[52..64])?;
                Self {
                    is64: true,
                    phoff: le_u64(&ident, 0x20),
                    phentsize: le_u16(&ident, 0x36),
                    phnum: le_u16(&ident, 0x38),
                }
            }
            _ => return Err(invalid("unknown ELF class")),
        };
        let minimum = if header.is64 { 0x38 } else { 0x20 };
        if header.phnum > 0 && usize::from(header.phentsize) < minimum {
            return Err(invalid("ELF program header entries are too small"));
        }
        Ok(header)
    }

    fn read_program_header<R: Read + Seek>(
        &self,
        reader: &mut R,
        at: u64,
    ) -> io::Result<ProgramHeader> {
        let mut entry = [0u8; 0x38];
        let len = if self.is64 { 0x38 } else { 0x20 };
        reader.seek(SeekFrom::Start(at))?;
        reader.read_exact(&mut entry[..len])?;
        Ok(if self.is64 {
            ProgramHeader {
                p_type: le_u32(&entry, 0),
                offset: le_u64(&entry, 0x08),
                filesz: le_u64(&entry, 0x20),
                align: le_u64(&entry, 0x30),
            }
        } else {
            ProgramHeader {
                p_type: le_u32(&entry, 0),
                offset: u64::from(le_u32(&entry, 0x04)),
                filesz: u64::from(le_u32(&entry, 0x10)),
                align: u64::from(le_u32(&entry, 0x1c)),
            }
        })
    }
}

/// Walk the `Elf_Nhdr` records in one note segment the way QEMU's loader
/// does: after the 12-byte header, the name and the descriptor each occupy
/// their length rounded up to the segment alignment (8 when the segment says
/// 8, otherwise 4). A vmlinux note segment is 4-aligned.
fn notes_contain_type(notes: &[u8], align: u64, wanted: u32) -> bool {
    let pad = if align == 8 { 8 } else { 4 };
    let round = |n: usize| n.checked_add(pad - 1).map(|n| n & !(pad - 1));
    let mut at = 0usize;
    while at + 12 <= notes.len() {
        let namesz = le_u32(notes, at) as usize;
        let descsz = le_u32(notes, at + 4) as usize;
        let n_type = le_u32(notes, at + 8);
        if n_type == wanted && descsz >= 4 {
            return true;
        }
        let Some(next) = round(namesz)
            .zip(round(descsz))
            .and_then(|(name, desc)| at.checked_add(12)?.checked_add(name)?.checked_add(desc))
        else {
            return false;
        };
        at = next;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrips() {
        for (fmt, expected_json) in [
            (KernelFormat::Raw, "\"raw\""),
            (KernelFormat::Elf, "\"elf\""),
            (KernelFormat::Image, "\"image\""),
            (KernelFormat::ImageGz, "\"image_gz\""),
            (KernelFormat::ImageBz2, "\"image_bz2\""),
            (KernelFormat::ImageZstd, "\"image_zstd\""),
            (KernelFormat::Pe, "\"pe\""),
            (KernelFormat::PeGz, "\"pe_gz\""),
        ] {
            let serialized = serde_json::to_string(&fmt).unwrap();
            assert_eq!(serialized, expected_json, "serialize {fmt:?}");
            let deserialized: KernelFormat = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, fmt, "deserialize {fmt:?}");
        }
    }

    #[test]
    fn the_name_is_the_serialized_name() {
        for fmt in [
            KernelFormat::Raw,
            KernelFormat::Elf,
            KernelFormat::Image,
            KernelFormat::ImageGz,
            KernelFormat::ImageBz2,
            KernelFormat::ImageZstd,
            KernelFormat::Pe,
            KernelFormat::PeGz,
        ] {
            assert_eq!(
                serde_json::to_string(&fmt).unwrap(),
                format!("\"{}\"", fmt.name())
            );
        }
    }

    #[test]
    fn magic_bytes_classify_each_uncompressed_kernel() {
        let mut elf = vec![0u8; KernelFormat::SNIFF_LEN];
        elf[..4].copy_from_slice(b"\x7fELF");
        assert_eq!(KernelFormat::sniff_magic(&elf), Some(KernelFormat::Elf));

        let mut bzimage = vec![0u8; KernelFormat::SNIFF_LEN];
        bzimage[0x202..0x206].copy_from_slice(b"HdrS");
        assert_eq!(KernelFormat::sniff_magic(&bzimage), Some(KernelFormat::Raw));

        let mut image = vec![0u8; 64];
        image[56..60].copy_from_slice(b"ARMd");
        assert_eq!(KernelFormat::sniff_magic(&image), Some(KernelFormat::Image));

        assert_eq!(KernelFormat::sniff_magic(&[0u8; 0x300]), None);
        assert_eq!(KernelFormat::sniff_magic(b"short"), None);
    }

    #[test]
    fn new_variants_image_and_pe_are_distinct_from_compressed() {
        assert_ne!(KernelFormat::Image, KernelFormat::ImageGz);
        assert_ne!(KernelFormat::Pe, KernelFormat::PeGz);
    }

    /// One `Elf_Nhdr` record: name (NUL-terminated) and descriptor, each
    /// padded to `pad`.
    fn note(name: &[u8], n_type: u32, desc: &[u8], pad: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut name = name.to_vec();
        name.push(0);
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        out.extend_from_slice(&n_type.to_le_bytes());
        // Each field is padded by its own length, the arithmetic QEMU's walk
        // uses, rather than to an absolute offset.
        for field in [name.as_slice(), desc] {
            let start = out.len();
            out.extend_from_slice(field);
            out.resize(start + field.len().next_multiple_of(pad), 0);
        }
        out
    }

    /// A minimal little-endian ELF64 image: a header, one `PT_LOAD` that is
    /// not a note, and one `PT_NOTE` segment holding `notes`.
    fn elf64(notes: &[u8], align: u64) -> Vec<u8> {
        let phoff = 64u64;
        let notes_at = phoff + 2 * 0x38;
        let mut out = vec![0u8; notes_at as usize];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
        out[0x36..0x38].copy_from_slice(&0x38u16.to_le_bytes());
        out[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        let load = phoff as usize;
        out[load..load + 4].copy_from_slice(&1u32.to_le_bytes());
        let nh = load + 0x38;
        out[nh..nh + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        out[nh + 0x08..nh + 0x10].copy_from_slice(&notes_at.to_le_bytes());
        out[nh + 0x20..nh + 0x28].copy_from_slice(&(notes.len() as u64).to_le_bytes());
        out[nh + 0x30..nh + 0x38].copy_from_slice(&align.to_le_bytes());
        out.extend_from_slice(notes);
        out
    }

    /// The same shape as [`elf64`] in the 32-bit class.
    fn elf32(notes: &[u8]) -> Vec<u8> {
        let phoff = 52u32;
        let notes_at = phoff + 0x20;
        let mut out = vec![0u8; notes_at as usize];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 1;
        out[5] = 1;
        out[0x1c..0x20].copy_from_slice(&phoff.to_le_bytes());
        out[0x2a..0x2c].copy_from_slice(&0x20u16.to_le_bytes());
        out[0x2c..0x2e].copy_from_slice(&1u16.to_le_bytes());
        let nh = phoff as usize;
        out[nh..nh + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        out[nh + 0x04..nh + 0x08].copy_from_slice(&notes_at.to_le_bytes());
        out[nh + 0x10..nh + 0x14].copy_from_slice(&(notes.len() as u32).to_le_bytes());
        out[nh + 0x1c..nh + 0x20].copy_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(notes);
        out
    }

    fn has_pvh(image: &[u8]) -> io::Result<bool> {
        elf_has_pvh_entry_note(&mut std::io::Cursor::new(image))
    }

    const ENTRY: [u8; 4] = 0x0100_0000u32.to_le_bytes();

    #[test]
    fn a_pvh_note_is_found_after_other_notes() {
        let mut notes = note(b"GNU", 3, &[0xab; 20], 4);
        notes.extend(note(b"Xen", PVH_ENTRY_NOTE_TYPE, &ENTRY, 4));
        assert!(has_pvh(&elf64(&notes, 4)).unwrap());
        assert!(has_pvh(&elf32(&notes)).unwrap());
    }

    #[test]
    fn an_eight_byte_aligned_note_segment_is_walked_with_eight_byte_padding() {
        let mut notes = note(b"GNU", 5, &[0xcd; 12], 8);
        notes.extend(note(b"Xen", PVH_ENTRY_NOTE_TYPE, &ENTRY, 8));
        assert!(has_pvh(&elf64(&notes, 8)).unwrap());
    }

    #[test]
    fn an_elf_without_the_pvh_note_has_none() {
        let notes = note(b"GNU", 3, &[0xab; 20], 4);
        assert!(!has_pvh(&elf64(&notes, 4)).unwrap());
        assert!(!has_pvh(&elf64(&[], 4)).unwrap());
        // A Xen note of another type is not the entry point.
        let other_xen = note(b"Xen", 6, b"linux\0\0\0", 4);
        assert!(!has_pvh(&elf64(&other_xen, 4)).unwrap());
    }

    #[test]
    fn a_truncated_note_record_does_not_read_past_the_segment() {
        let mut notes = note(b"GNU", 3, &[0xab; 20], 4);
        // Claim a name far longer than the segment.
        notes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!has_pvh(&elf64(&notes, 4)).unwrap());
    }

    #[test]
    fn malformed_images_are_errors_not_answers() {
        assert!(has_pvh(b"not an elf at all, just some bytes padding to 64.....").is_err());
        let mut big_endian = elf64(&[], 4);
        big_endian[5] = 2;
        assert!(has_pvh(&big_endian).is_err());
        let mut huge = elf64(&[], 4);
        let filesz = 64 + 0x38 + 0x20;
        huge[filesz..filesz + 8].copy_from_slice(&(MAX_NOTE_SEGMENT + 1).to_le_bytes());
        assert!(has_pvh(&huge).is_err());
    }

    fn write_kernel(dir: &tempfile::TempDir, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join("vmlinux");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn qemu_x86_64_refuses_an_elf_kernel_without_a_pvh_note() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = write_kernel(&dir, &elf64(&note(b"GNU", 3, &[0; 20], 4), 4));
        let err =
            check_direct_boot_loadable(BackendKind::Qemu, GuestArch::X86_64, &kernel).unwrap_err();
        assert!(matches!(err, KernelLoadError::QemuElfWithoutPvhNote { .. }));
        let message = err.to_string();
        assert!(message.contains("CONFIG_PVH=y"), "{message}");
        assert!(message.contains(&kernel.display().to_string()), "{message}");
    }

    #[test]
    fn qemu_x86_64_admits_a_pvh_elf_and_a_bzimage() {
        let dir = tempfile::tempdir().unwrap();
        let pvh = write_kernel(&dir, &elf64(&note(b"Xen", 18, &ENTRY, 4), 4));
        check_direct_boot_loadable(BackendKind::Qemu, GuestArch::X86_64, &pvh).unwrap();

        let mut bzimage = vec![0u8; 0x400];
        bzimage[0x202..0x206].copy_from_slice(b"HdrS");
        let bz = write_kernel(&dir, &bzimage);
        check_direct_boot_loadable(BackendKind::Qemu, GuestArch::X86_64, &bz).unwrap();
    }

    #[test]
    fn the_pvh_rule_binds_only_qemu_on_x86_64() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = write_kernel(&dir, &elf64(&[], 4));
        for (backend, arch) in [
            (BackendKind::Firecracker, GuestArch::X86_64),
            (BackendKind::Libkrun, GuestArch::X86_64),
            (BackendKind::Qemu, GuestArch::Aarch64),
        ] {
            check_direct_boot_loadable(backend, arch, &kernel)
                .unwrap_or_else(|e| panic!("{backend:?}/{arch:?}: {e}"));
        }
    }

    #[test]
    fn an_unreadable_qemu_kernel_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        assert!(matches!(
            check_direct_boot_loadable(BackendKind::Qemu, GuestArch::X86_64, &missing),
            Err(KernelLoadError::Io { .. })
        ));
    }
}
