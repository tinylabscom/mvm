//! Backend-neutral kernel artifact format. Backends accept a subset
//! (see `mvm_runtime::BackendCompat`); libkrun maps the ones it can
//! load to its FFI constants; unsupported variants return an error at
//! the call site rather than failing silently.
use serde::{Deserialize, Serialize};

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
}
