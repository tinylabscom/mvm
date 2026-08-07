//! arm64 Linux `Image` header parsing.
//!
//! The 64-byte header (Documentation/arm64/booting.rst) gives the load offset
//! and image size needed to place the kernel in guest RAM and set the entry PC.

/// `ARM\x64` little-endian, at byte offset 56 of an arm64 `Image`.
const IMAGE_MAGIC: u32 = 0x644d_5241;

/// The fields of the arm64 `Image` header the boot path needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64ImageHeader {
    /// Offset from the 2 MiB-aligned base where the image is loaded and entered.
    pub text_offset: u64,
    /// Effective image size (kernel + BSS) if the header records one (else 0).
    pub image_size: u64,
}

/// Parse and validate the header of an arm64 `Image`.
pub fn parse(image: &[u8]) -> Result<Arm64ImageHeader, &'static str> {
    if image.len() < 64 {
        return Err("image too small for arm64 header");
    }
    let magic = u32::from_le_bytes(image[56..60].try_into().unwrap());
    if magic != IMAGE_MAGIC {
        return Err("not an arm64 Image (bad magic at offset 56)");
    }
    let text_offset = u64::from_le_bytes(image[8..16].try_into().unwrap());
    let image_size = u64::from_le_bytes(image[16..24].try_into().unwrap());
    Ok(Arm64ImageHeader {
        text_offset,
        image_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(text_offset: u64, image_size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[8..16].copy_from_slice(&text_offset.to_le_bytes());
        b[16..24].copy_from_slice(&image_size.to_le_bytes());
        b[56..60].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        b
    }

    #[test]
    fn parses_offset_and_size() {
        let h = parse(&header_bytes(0, 0x0140_0000)).unwrap();
        assert_eq!(h.text_offset, 0);
        assert_eq!(h.image_size, 0x0140_0000);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = header_bytes(0, 0);
        b[56] = 0;
        assert!(parse(&b).is_err());
    }

    #[test]
    fn rejects_short_input() {
        assert!(parse(&[0u8; 16]).is_err());
    }
}
