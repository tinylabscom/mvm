//! Hardened snapshot frame v0.
//!
//! A self-describing container for the snapshot data mvm controls (the
//! eager-CoW / raw-hypervisor path): a fixed header, then a length-prefixed
//! section table, then the sections. Parsing is fail-closed and adversary-aware:
//! every count that can drive an allocation passes through [`cap_count`] against
//! a hard ceiling *before* anything is allocated, every byte range is validated
//! against the file length with overflow-safe math via [`checked_region`], and
//! unknown/short input is rejected rather than trusted. Secrets are excluded by
//! construction — the frame carries guest RAM, device, and vCPU state plus
//! recorded artifact digests, never host keys or credential material.

use core::fmt;

use crate::arch::GuestArch;

/// 8-byte magic identifying a v0 mvm snapshot frame.
pub const FRAME_MAGIC: [u8; 8] = *b"MVMSNAP1";
/// Frame format version. A reader must reject a newer version rather than
/// guess at a layout it does not understand.
pub const FRAME_VERSION: u16 = 0;
/// Hard ceiling on the section-table entry count, so a hostile header cannot
/// drive an unbounded allocation.
pub const MAX_SECTIONS: u64 = 4096;
/// Fixed header length: magic(8) + version(2) + arch(1) + backend(1) +
/// flags(4) + section_count(2).
pub const HEADER_LEN: usize = 18;

/// Why a frame could not be parsed. Typed so the caller fails closed with a
/// specific reason instead of trusting malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Input shorter than the bytes the layout requires.
    Truncated { need: usize, have: usize },
    /// Magic did not match — not an mvm snapshot frame.
    BadMagic,
    /// Frame version newer/older than this reader supports.
    UnsupportedVersion(u16),
    /// Architecture byte not a known [`GuestArch`].
    UnknownArch(u8),
    /// A count exceeded its hard ceiling before any allocation.
    CountExceedsCap {
        name: &'static str,
        value: u64,
        max: u64,
    },
    /// A byte range overflowed or ran past the end of the input.
    RegionOutOfBounds {
        offset: u64,
        len: u64,
        file_len: u64,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Truncated { need, have } => {
                write!(
                    f,
                    "snapshot frame truncated: need {need} bytes, have {have}"
                )
            }
            FrameError::BadMagic => write!(f, "not an mvm snapshot frame (bad magic)"),
            FrameError::UnsupportedVersion(v) => {
                write!(f, "unsupported snapshot frame version {v}")
            }
            FrameError::UnknownArch(b) => write!(f, "unknown guest arch byte {b}"),
            FrameError::CountExceedsCap { name, value, max } => {
                write!(f, "snapshot frame {name} count {value} exceeds cap {max}")
            }
            FrameError::RegionOutOfBounds {
                offset,
                len,
                file_len,
            } => write!(
                f,
                "snapshot frame region [{offset}, +{len}) out of bounds (len {file_len})"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

/// Validate a count against a hard ceiling and narrow it to `usize` *before*
/// any allocation keyed on it. The one chokepoint every parse step routes
/// allocation-driving counts through.
pub fn cap_count(name: &'static str, value: u64, max: u64) -> Result<usize, FrameError> {
    if value > max {
        return Err(FrameError::CountExceedsCap { name, value, max });
    }
    usize::try_from(value).map_err(|_| FrameError::CountExceedsCap { name, value, max })
}

/// A validated byte range within the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub offset: usize,
    pub len: usize,
}

/// Validate that `[offset, offset+len)` fits within `file_len` using
/// overflow-safe math, returning a `usize` range only when it does.
pub fn checked_region(file_len: u64, offset: u64, len: u64) -> Result<Region, FrameError> {
    let oob = || FrameError::RegionOutOfBounds {
        offset,
        len,
        file_len,
    };
    let end = offset.checked_add(len).ok_or_else(oob)?;
    if end > file_len {
        return Err(oob());
    }
    Ok(Region {
        offset: usize::try_from(offset).map_err(|_| oob())?,
        len: usize::try_from(len).map_err(|_| oob())?,
    })
}

/// The fixed frame header, parsed and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub arch: GuestArch,
    /// Opaque backend-kind tag (which VMM produced the frame); validated by
    /// the restoring backend, not here.
    pub backend_kind: u8,
    pub flags: u32,
    /// Section-table entry count, already capped at [`MAX_SECTIONS`].
    pub section_count: usize,
}

/// Parse and validate the fixed header. Rejects short input, bad magic, an
/// unsupported version, an unknown arch, and an over-cap section count — in
/// that order — before any section data is touched.
pub fn parse_header(bytes: &[u8]) -> Result<FrameHeader, FrameError> {
    if bytes.len() < HEADER_LEN {
        return Err(FrameError::Truncated {
            need: HEADER_LEN,
            have: bytes.len(),
        });
    }
    if bytes[0..8] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }
    let arch = match bytes[10] {
        0 => GuestArch::X86_64,
        1 => GuestArch::Aarch64,
        other => return Err(FrameError::UnknownArch(other)),
    };
    let backend_kind = bytes[11];
    let flags = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let raw_count = u16::from_le_bytes([bytes[16], bytes[17]]);
    let section_count = cap_count("sections", u64::from(raw_count), MAX_SECTIONS)?;
    Ok(FrameHeader {
        version,
        arch,
        backend_kind,
        flags,
        section_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(magic: [u8; 8], version: u16, arch: u8, section_count: u16) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_LEN);
        b.extend_from_slice(&magic);
        b.extend_from_slice(&version.to_le_bytes());
        b.push(arch);
        b.push(7); // backend_kind
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&section_count.to_le_bytes());
        b
    }

    #[test]
    fn cap_count_rejects_value_over_ceiling() {
        assert!(cap_count("sections", 5000, 4096).is_err());
        assert_eq!(cap_count("sections", 10, 4096).unwrap(), 10);
    }

    #[test]
    fn checked_region_rejects_overflow_and_out_of_bounds() {
        assert!(checked_region(100, u64::MAX, 10).is_err()); // offset+len overflows
        assert!(checked_region(100, 90, 20).is_err()); // end 110 > 100
        assert_eq!(
            checked_region(100, 10, 20).unwrap(),
            Region {
                offset: 10,
                len: 20
            }
        );
    }

    #[test]
    fn parse_header_rejects_truncated() {
        assert_eq!(
            parse_header(&[]).unwrap_err(),
            FrameError::Truncated {
                need: HEADER_LEN,
                have: 0
            }
        );
        assert!(matches!(
            parse_header(&[0u8; 5]).unwrap_err(),
            FrameError::Truncated { .. }
        ));
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let bytes = header_bytes(*b"NOTASNAP", FRAME_VERSION, 0, 1);
        assert_eq!(parse_header(&bytes).unwrap_err(), FrameError::BadMagic);
    }

    #[test]
    fn parse_header_rejects_unsupported_version() {
        let bytes = header_bytes(FRAME_MAGIC, FRAME_VERSION + 1, 0, 1);
        assert_eq!(
            parse_header(&bytes).unwrap_err(),
            FrameError::UnsupportedVersion(FRAME_VERSION + 1)
        );
    }

    #[test]
    fn parse_header_rejects_unknown_arch() {
        let bytes = header_bytes(FRAME_MAGIC, FRAME_VERSION, 9, 1);
        assert_eq!(
            parse_header(&bytes).unwrap_err(),
            FrameError::UnknownArch(9)
        );
    }

    #[test]
    fn parse_header_caps_section_count_before_use() {
        let bytes = header_bytes(FRAME_MAGIC, FRAME_VERSION, 0, u16::MAX);
        assert!(matches!(
            parse_header(&bytes).unwrap_err(),
            FrameError::CountExceedsCap {
                name: "sections",
                ..
            }
        ));
    }

    #[test]
    fn parse_header_accepts_a_valid_header() {
        let bytes = header_bytes(FRAME_MAGIC, FRAME_VERSION, 1, 3);
        let header = parse_header(&bytes).unwrap();
        assert_eq!(header.version, FRAME_VERSION);
        assert_eq!(header.arch, GuestArch::Aarch64);
        assert_eq!(header.backend_kind, 7);
        assert_eq!(header.section_count, 3);
    }
}
