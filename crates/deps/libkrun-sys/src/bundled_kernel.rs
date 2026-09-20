use crate::{Error, KernelFormat};

const ELF64_HEADER_LEN: usize = 64;
const ELF64_HEADER_LEN_U16: u16 = 64;
const ELF64_HEADER_LEN_U64: u64 = 64;
const ELF64_PROGRAM_HEADER_LEN_U16: u16 = 56;
const ELF_PAYLOAD_OFFSET: usize = 4096;
const ELF_PAYLOAD_OFFSET_U64: u64 = 4096;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_PROGRAM_LOAD: u32 = 1;
const ELF_PROGRAM_READ_EXECUTE: u32 = 5;
const ELF_PAGE_ALIGNMENT: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BundledKernelArch {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundledKernelArtifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) format: KernelFormat,
}

#[cfg(feature = "libkrun-sys")]
pub(crate) fn artifact_for_host(
    bytes: &[u8],
    load_addr: u64,
    entry_addr: u64,
) -> Result<BundledKernelArtifact, Error> {
    let arch = if cfg!(target_arch = "x86_64") {
        BundledKernelArch::X86_64
    } else {
        BundledKernelArch::Aarch64
    };

    artifact_for_arch(arch, bytes, load_addr, entry_addr)
}

fn artifact_for_arch(
    arch: BundledKernelArch,
    bytes: &[u8],
    load_addr: u64,
    entry_addr: u64,
) -> Result<BundledKernelArtifact, Error> {
    match arch {
        BundledKernelArch::Aarch64 => Ok(BundledKernelArtifact {
            bytes: bytes.to_vec(),
            format: KernelFormat::Raw,
        }),
        BundledKernelArch::X86_64 => Ok(BundledKernelArtifact {
            bytes: x86_64_elf(bytes, load_addr, entry_addr)?,
            format: KernelFormat::Elf,
        }),
    }
}

fn x86_64_elf(bytes: &[u8], load_addr: u64, entry_addr: u64) -> Result<Vec<u8>, Error> {
    let payload_len = u64::try_from(bytes.len()).map_err(|_| Error::Io {
        context: "libkrunfw kernel is too large for an ELF64 segment".to_string(),
    })?;
    let load_end = load_addr
        .checked_add(payload_len)
        .ok_or_else(|| Error::Io {
            context: "libkrunfw kernel load range overflows the x86_64 address space".to_string(),
        })?;
    if bytes.is_empty() {
        return Err(Error::Io {
            context: "libkrunfw returned an empty x86_64 kernel".to_string(),
        });
    }
    if !load_addr.is_multiple_of(ELF_PAGE_ALIGNMENT) {
        return Err(Error::Io {
            context: format!(
                "libkrunfw x86_64 kernel load address {load_addr:#x} is not page-aligned"
            ),
        });
    }
    if !(load_addr..load_end).contains(&entry_addr) {
        return Err(Error::Io {
            context: format!(
                "libkrunfw x86_64 entry address {entry_addr:#x} is outside kernel range \
                 {load_addr:#x}..{load_end:#x}"
            ),
        });
    }

    let artifact_len = ELF_PAYLOAD_OFFSET
        .checked_add(bytes.len())
        .ok_or_else(|| Error::Io {
            context: "libkrunfw x86_64 ELF artifact length overflows usize".to_string(),
        })?;
    let mut elf = vec![0_u8; artifact_len];

    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    write_u16(&mut elf, 16, ELF_TYPE_EXECUTABLE);
    write_u16(&mut elf, 18, ELF_MACHINE_X86_64);
    write_u32(&mut elf, 20, 1);
    write_u64(&mut elf, 24, entry_addr);
    write_u64(&mut elf, 32, ELF64_HEADER_LEN_U64);
    write_u16(&mut elf, 52, ELF64_HEADER_LEN_U16);
    write_u16(&mut elf, 54, ELF64_PROGRAM_HEADER_LEN_U16);
    write_u16(&mut elf, 56, 1);

    let program = ELF64_HEADER_LEN;
    write_u32(&mut elf, program, ELF_PROGRAM_LOAD);
    write_u32(&mut elf, program + 4, ELF_PROGRAM_READ_EXECUTE);
    write_u64(&mut elf, program + 8, ELF_PAYLOAD_OFFSET_U64);
    write_u64(&mut elf, program + 16, load_addr);
    write_u64(&mut elf, program + 24, load_addr);
    write_u64(&mut elf, program + 32, payload_len);
    write_u64(&mut elf, program + 40, payload_len);
    write_u64(&mut elf, program + 48, ELF_PAGE_ALIGNMENT);
    elf[ELF_PAYLOAD_OFFSET..].copy_from_slice(bytes);

    Ok(elf)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn x86_64_artifact_preserves_firmware_load_and_entry_addresses() {
        let payload = b"firmware-kernel";
        let load_addr = 0x0100_0000;
        let entry_addr = load_addr + 3;

        let artifact =
            artifact_for_arch(BundledKernelArch::X86_64, payload, load_addr, entry_addr).unwrap();

        assert_eq!(artifact.format, KernelFormat::Elf);
        assert_eq!(&artifact.bytes[..4], b"\x7fELF");
        assert_eq!(read_u64(&artifact.bytes, 24), entry_addr);
        assert_eq!(read_u64(&artifact.bytes, 64 + 8), 4096);
        assert_eq!(read_u64(&artifact.bytes, 64 + 16), load_addr);
        assert_eq!(read_u64(&artifact.bytes, 64 + 24), load_addr);
        assert_eq!(read_u64(&artifact.bytes, 64 + 32), payload.len() as u64);
        assert_eq!(&artifact.bytes[ELF_PAYLOAD_OFFSET..], payload);
    }

    #[test]
    fn aarch64_artifact_remains_raw() {
        let payload = b"arm64-image";
        let artifact = artifact_for_arch(
            BundledKernelArch::Aarch64,
            payload,
            0x8008_0000,
            0x8008_0000,
        )
        .unwrap();

        assert_eq!(artifact.format, KernelFormat::Raw);
        assert_eq!(artifact.bytes, payload);
    }

    #[test]
    fn x86_64_artifact_rejects_an_entry_outside_the_payload() {
        let err = artifact_for_arch(
            BundledKernelArch::X86_64,
            b"kernel",
            0x0100_0000,
            0x0200_0000,
        )
        .unwrap_err();

        assert!(err.to_string().contains("outside kernel range"));
    }

    #[test]
    fn x86_64_artifact_rejects_an_unaligned_load_address() {
        let err = artifact_for_arch(
            BundledKernelArch::X86_64,
            b"kernel",
            0x0100_0001,
            0x0100_0001,
        )
        .unwrap_err();

        assert!(err.to_string().contains("not page-aligned"));
    }
}
