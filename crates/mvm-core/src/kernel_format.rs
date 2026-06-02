//! Backend-neutral kernel artifact format. Backends accept a subset
//! (see `mvm_backend::BackendCompat`); libkrun maps the ones it can
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
    fn new_variants_image_and_pe_are_distinct_from_compressed() {
        assert_ne!(KernelFormat::Image, KernelFormat::ImageGz);
        assert_ne!(KernelFormat::Pe, KernelFormat::PeGz);
    }
}
