//! Bounded launch-parameter metadata parsing for CUDA module images.
//!
//! CUDA cubins use ELF64 little-endian containers with one
//! `.nv.info.<entry>` section per kernel. Fatbins wrap one or more cubin or
//! PTX payloads. Neither binary format is accepted on trust: every offset and
//! length is checked against the caller-provided slice before it is used, and
//! ordinal-controlled allocation is capped by the wire contract.

use core::fmt;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const FATBIN_MAGIC: [u8; 4] = 0xba55_ed50_u32.to_le_bytes();
const ELF64_HEADER_LEN: usize = 64;
const ELF64_SECTION_HEADER_LEN: usize = 64;
const FATBIN_HEADER_LEN: usize = 16;
const FATBIN_ENTRY_HEADER_LEN: usize = 64;
const NV_INFO_PREFIX: &[u8] = b".nv.info.";
const EIATTR_KPARAM_INFO: u8 = 0x17;

/// Maximum module image inspected or copied by a guest shim.
///
/// This matches the GPU frame ceiling: a module larger than one frame can
/// never be sent to the endpoint, so reading or parsing more would only give
/// untrusted input a larger allocation surface.
pub const MAX_MODULE_IMAGE_LEN: usize = crate::wire::MAX_MESSAGE_LEN as usize;

/// A CUDA module image did not contain trustworthy launch metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelParamError {
    /// The input cannot fit in the bounded GPU wire frame.
    ImageTooLarge { len: usize, max: usize },
    /// The image is neither PTX, cubin ELF, nor a basic fatbin.
    UnsupportedImage,
    /// A fixed-format header or record ended before its required bytes.
    Truncated(&'static str),
    /// Only ELF64 cubins are supported.
    UnsupportedElfClass(u8),
    /// CUDA cubins are little-endian; another encoding is refused.
    UnsupportedEndian(u8),
    /// The fatbin container version is not the basic v1 layout.
    UnsupportedFatbinVersion(u16),
    /// Compressed fatbin payloads require a decompressor and are not guessed.
    UnsupportedCompressedFatbin,
    /// A checked file range named bytes outside the image.
    OutOfBounds(&'static str),
    /// A structurally present record violated its format invariant.
    Malformed(&'static str),
    /// The requested kernel entry was not present.
    MissingEntry,
    /// An ordinal would make the launch exceed the protocol parameter cap.
    ParameterCountExceeded { count: usize, max: usize },
    /// Two metadata records claimed the same parameter ordinal.
    DuplicateOrdinal(u16),
    /// Parameter ordinals must be dense from zero so no pointer is guessed.
    SparseOrdinals,
}

impl fmt::Display for KernelParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageTooLarge { len, max } => {
                write!(
                    f,
                    "module image is {len} bytes, exceeding the {max}-byte cap"
                )
            }
            Self::UnsupportedImage => f.write_str("unsupported CUDA module image format"),
            Self::Truncated(context) => write!(f, "truncated {context}"),
            Self::UnsupportedElfClass(class) => {
                write!(f, "unsupported cubin ELF class {class}")
            }
            Self::UnsupportedEndian(encoding) => {
                write!(f, "unsupported cubin ELF data encoding {encoding}")
            }
            Self::UnsupportedFatbinVersion(version) => {
                write!(f, "unsupported fatbin version {version}")
            }
            Self::UnsupportedCompressedFatbin => {
                f.write_str("compressed fatbin cubin metadata is not supported")
            }
            Self::OutOfBounds(context) => write!(f, "out-of-bounds {context}"),
            Self::Malformed(context) => write!(f, "malformed {context}"),
            Self::MissingEntry => f.write_str("kernel entry metadata is missing"),
            Self::ParameterCountExceeded { count, max } => {
                write!(
                    f,
                    "kernel has {count} parameters, exceeding the {max}-parameter cap"
                )
            }
            Self::DuplicateOrdinal(ordinal) => {
                write!(f, "duplicate kernel parameter ordinal {ordinal}")
            }
            Self::SparseOrdinals => f.write_str("kernel parameter ordinals are sparse"),
        }
    }
}

impl std::error::Error for KernelParamError {}

/// Recover a kernel entry's launch parameter sizes from PTX, cubin, or fatbin.
///
/// Binary metadata is authoritative only after the complete containing range
/// has passed checked arithmetic and input bounds. PTX remains the fallback
/// for text images and for PTX payloads inside a basic fatbin.
pub fn kernel_param_sizes(image: &[u8], entry: &str) -> Result<Vec<usize>, KernelParamError> {
    validate_image_len(image.len())?;
    if image.starts_with(ELF_MAGIC) {
        return cubin_param_sizes(image, entry);
    }
    if image.starts_with(&FATBIN_MAGIC) {
        return fatbin_param_sizes(image, entry);
    }
    ptx_param_sizes(image, entry)
}

/// Recover the existing PTX layout with the wire parameter cap applied while
/// parsing, before attacker-controlled input can grow the result vector.
pub(crate) fn ptx_param_sizes(image: &[u8], entry: &str) -> Result<Vec<usize>, KernelParamError> {
    let text = core::str::from_utf8(image).map_err(|_| KernelParamError::UnsupportedImage)?;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let Some(index) = trimmed.find(".entry") else {
            continue;
        };
        let rest = trimmed[index + ".entry".len()..].trim_start();
        let name = rest.split(['(', ' ', '\t']).next().unwrap_or("");
        if name != entry {
            continue;
        }
        let mut sizes = Vec::new();
        let header_has_close = rest.contains(')');
        for param_line in lines.by_ref() {
            let parameter = param_line.trim();
            if parameter.starts_with(')') {
                return Ok(sizes);
            }
            if let Some(directive) = parameter.strip_prefix(".param") {
                if sizes.len() == crate::wire::MAX_KERNEL_PARAMS {
                    return Err(KernelParamError::ParameterCountExceeded {
                        count: sizes.len() + 1,
                        max: crate::wire::MAX_KERNEL_PARAMS,
                    });
                }
                sizes.push(ptx_param_size(directive.trim_start()));
            } else if header_has_close && parameter.is_empty() {
                return Ok(sizes);
            }
        }
        return Ok(sizes);
    }
    Err(KernelParamError::MissingEntry)
}

/// Size in bytes of one `.param` directive's type (best-effort for common
/// nvcc output; unknown types conservatively size as a pointer).
fn ptx_param_size(directive: &str) -> usize {
    let mut size = 4_usize;
    let mut vector = 1_usize;
    for token in directive.split_whitespace() {
        match token {
            ".u64" | ".s64" | ".f64" | ".b64" | ".pred" if size < 8 => size = 8,
            ".u32" | ".s32" | ".f32" | ".b32" => size = size.max(4),
            ".v2" => vector = vector.max(2),
            ".v4" => vector = vector.max(4),
            _ => {}
        }
    }
    size * vector
}

/// Derive a binary module's full byte length from its fixed header.
///
/// `Ok(None)` identifies a non-binary image, which the caller may treat as
/// NUL-terminated PTX. ELF callers provide the 64-byte ELF header; fatbin
/// callers need only the 16-byte container header.
pub fn module_image_len_from_header(header: &[u8]) -> Result<Option<usize>, KernelParamError> {
    if header.starts_with(ELF_MAGIC) {
        if header.len() < ELF64_HEADER_LEN {
            return Err(KernelParamError::Truncated("ELF header"));
        }
        validate_elf_encoding(header)?;
        let section_offset =
            usize_from_u64(read_u64(header, 0x28, "ELF header")?, "ELF section table")?;
        let section_header_len = usize::from(read_u16(header, 0x3a, "ELF header")?);
        let section_count = usize::from(read_u16(header, 0x3c, "ELF header")?);
        if section_header_len < ELF64_SECTION_HEADER_LEN || section_count == 0 {
            return Err(KernelParamError::Malformed("ELF section table shape"));
        }
        let table_len = section_header_len
            .checked_mul(section_count)
            .ok_or(KernelParamError::OutOfBounds("ELF section table"))?;
        let len = section_offset
            .checked_add(table_len)
            .ok_or(KernelParamError::OutOfBounds("ELF section table"))?;
        validate_image_len(len)?;
        return Ok(Some(len));
    }
    if header.starts_with(&FATBIN_MAGIC) {
        if header.len() < FATBIN_HEADER_LEN {
            return Err(KernelParamError::Truncated("fatbin header"));
        }
        let version = read_u16(header, 4, "fatbin header")?;
        if version != 1 {
            return Err(KernelParamError::UnsupportedFatbinVersion(version));
        }
        let header_len = usize::from(read_u16(header, 6, "fatbin header")?);
        if header_len < FATBIN_HEADER_LEN {
            return Err(KernelParamError::Malformed("fatbin header size"));
        }
        let body_len = usize_from_u64(read_u64(header, 8, "fatbin header")?, "fatbin size")?;
        let len = header_len
            .checked_add(body_len)
            .ok_or(KernelParamError::OutOfBounds("fatbin size"))?;
        validate_image_len(len)?;
        return Ok(Some(len));
    }
    Ok(None)
}

fn validate_image_len(len: usize) -> Result<(), KernelParamError> {
    if len > MAX_MODULE_IMAGE_LEN {
        return Err(KernelParamError::ImageTooLarge {
            len,
            max: MAX_MODULE_IMAGE_LEN,
        });
    }
    Ok(())
}

fn cubin_param_sizes(image: &[u8], entry: &str) -> Result<Vec<usize>, KernelParamError> {
    if image.len() < ELF64_HEADER_LEN {
        return Err(KernelParamError::Truncated("ELF header"));
    }
    validate_elf_encoding(image)?;
    let section_offset = usize_from_u64(read_u64(image, 0x28, "ELF header")?, "ELF section table")?;
    let section_header_len = usize::from(read_u16(image, 0x3a, "ELF header")?);
    let section_count = usize::from(read_u16(image, 0x3c, "ELF header")?);
    let names_index = usize::from(read_u16(image, 0x3e, "ELF header")?);
    if section_header_len < ELF64_SECTION_HEADER_LEN || section_count == 0 {
        return Err(KernelParamError::Malformed("ELF section table shape"));
    }
    if names_index >= section_count {
        return Err(KernelParamError::Malformed("ELF section-name table index"));
    }
    let table_len = section_header_len
        .checked_mul(section_count)
        .ok_or(KernelParamError::OutOfBounds("ELF section table"))?;
    checked_range(image, section_offset, table_len, "ELF section table")?;

    let names_header = section_header(image, section_offset, section_header_len, names_index)?;
    let names = section_contents(image, names_header, "ELF section-name table")?;
    for index in 0..section_count {
        let header = section_header(image, section_offset, section_header_len, index)?;
        let name_offset = usize::try_from(read_u32(header, 0, "ELF section header")?)
            .map_err(|_| KernelParamError::OutOfBounds("ELF section name"))?;
        let name = nul_terminated(names, name_offset, "ELF section name")?;
        if name.strip_prefix(NV_INFO_PREFIX) == Some(entry.as_bytes()) {
            let info = section_contents(image, header, "CUDA parameter metadata section")?;
            return parse_nv_info(info);
        }
    }
    Err(KernelParamError::MissingEntry)
}

fn validate_elf_encoding(image: &[u8]) -> Result<(), KernelParamError> {
    let class = image[4];
    if class != 2 {
        return Err(KernelParamError::UnsupportedElfClass(class));
    }
    let endian = image[5];
    if endian != 1 {
        return Err(KernelParamError::UnsupportedEndian(endian));
    }
    Ok(())
}

fn section_header(
    image: &[u8],
    table_offset: usize,
    entry_len: usize,
    index: usize,
) -> Result<&[u8], KernelParamError> {
    let offset = entry_len
        .checked_mul(index)
        .and_then(|relative| table_offset.checked_add(relative))
        .ok_or(KernelParamError::OutOfBounds("ELF section header"))?;
    checked_range(
        image,
        offset,
        ELF64_SECTION_HEADER_LEN,
        "ELF section header",
    )
}

fn section_contents<'a>(
    image: &'a [u8],
    header: &[u8],
    context: &'static str,
) -> Result<&'a [u8], KernelParamError> {
    let offset = usize_from_u64(read_u64(header, 0x18, "ELF section header")?, context)?;
    let len = usize_from_u64(read_u64(header, 0x20, "ELF section header")?, context)?;
    checked_range(image, offset, len, context)
}

fn nul_terminated<'a>(
    bytes: &'a [u8],
    offset: usize,
    context: &'static str,
) -> Result<&'a [u8], KernelParamError> {
    let tail = bytes
        .get(offset..)
        .ok_or(KernelParamError::OutOfBounds(context))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(KernelParamError::Malformed(context))?;
    Ok(&tail[..end])
}

fn parse_nv_info(info: &[u8]) -> Result<Vec<usize>, KernelParamError> {
    let mut sizes = [None; crate::wire::MAX_KERNEL_PARAMS];
    let mut highest_ordinal = None;
    let mut cursor = 0_usize;
    while cursor < info.len() {
        let format = *info
            .get(cursor)
            .ok_or(KernelParamError::Truncated("CUDA metadata record"))?;
        let attribute = *info
            .get(cursor + 1)
            .ok_or(KernelParamError::Truncated("CUDA metadata record"))?;
        match format {
            1 => cursor = aligned_record_end(info, cursor, 2, 4)?,
            2 => cursor = aligned_record_end(info, cursor, 3, 2)?,
            3 => cursor = record_end(info, cursor, 4, "CUDA half-value metadata record")?,
            4 => {
                let header = checked_range(info, cursor, 4, "CUDA size-value metadata record")?;
                let payload_len = usize::from(read_u16(header, 2, "CUDA metadata record")?);
                let payload_start = cursor
                    .checked_add(4)
                    .ok_or(KernelParamError::OutOfBounds("CUDA metadata record"))?;
                let payload = checked_range(
                    info,
                    payload_start,
                    payload_len,
                    "CUDA size-value metadata record",
                )?;
                if attribute == EIATTR_KPARAM_INFO {
                    if payload_len != 12 {
                        return Err(KernelParamError::Malformed("KPARAM_INFO record length"));
                    }
                    let ordinal = read_u16(payload, 4, "KPARAM_INFO record")?;
                    let ordinal_index = usize::from(ordinal);
                    let count = ordinal_index + 1;
                    if count > crate::wire::MAX_KERNEL_PARAMS {
                        return Err(KernelParamError::ParameterCountExceeded {
                            count,
                            max: crate::wire::MAX_KERNEL_PARAMS,
                        });
                    }
                    if sizes[ordinal_index].is_some() {
                        return Err(KernelParamError::DuplicateOrdinal(ordinal));
                    }
                    let packed = read_u32(payload, 8, "KPARAM_INFO record")?;
                    let size = usize::try_from((packed >> 18) & 0x3fff)
                        .map_err(|_| KernelParamError::Malformed("KPARAM_INFO parameter size"))?;
                    if size == 0 {
                        return Err(KernelParamError::Malformed("KPARAM_INFO parameter size"));
                    }
                    let offset = usize::from(read_u16(payload, 6, "KPARAM_INFO record")?);
                    offset
                        .checked_add(size)
                        .ok_or(KernelParamError::OutOfBounds("KPARAM_INFO parameter range"))?;
                    sizes[ordinal_index] = Some(size);
                    highest_ordinal = Some(
                        highest_ordinal.map_or(ordinal_index, |old: usize| old.max(ordinal_index)),
                    );
                }
                cursor = payload_start
                    .checked_add(payload_len)
                    .ok_or(KernelParamError::OutOfBounds("CUDA metadata record"))?;
            }
            _ if attribute == EIATTR_KPARAM_INFO => {
                return Err(KernelParamError::Malformed("KPARAM_INFO record format"));
            }
            _ => return Err(KernelParamError::Malformed("CUDA metadata record format")),
        }
    }

    let Some(highest) = highest_ordinal else {
        return Ok(Vec::new());
    };
    let mut ordered = Vec::with_capacity(highest + 1);
    for size in sizes.into_iter().take(highest + 1) {
        ordered.push(size.ok_or(KernelParamError::SparseOrdinals)?);
    }
    Ok(ordered)
}

fn fatbin_param_sizes(image: &[u8], entry: &str) -> Result<Vec<usize>, KernelParamError> {
    if image.len() < FATBIN_HEADER_LEN {
        return Err(KernelParamError::Truncated("fatbin header"));
    }
    let version = read_u16(image, 4, "fatbin header")?;
    if version != 1 {
        return Err(KernelParamError::UnsupportedFatbinVersion(version));
    }
    let header_len = usize::from(read_u16(image, 6, "fatbin header")?);
    if header_len < FATBIN_HEADER_LEN {
        return Err(KernelParamError::Malformed("fatbin header size"));
    }
    let body_len = usize_from_u64(read_u64(image, 8, "fatbin header")?, "fatbin size")?;
    let end = header_len
        .checked_add(body_len)
        .ok_or(KernelParamError::OutOfBounds("fatbin size"))?;
    checked_range(image, 0, end, "fatbin body")?;

    let mut cursor = header_len;
    let mut result: Option<Vec<usize>> = None;
    let mut compressed_cubin = false;
    while cursor < end {
        let fixed = checked_range(
            image,
            cursor,
            FATBIN_ENTRY_HEADER_LEN,
            "fatbin entry header",
        )?;
        let kind = read_u16(fixed, 0, "fatbin entry header")?;
        let entry_header_len = usize::try_from(read_u32(fixed, 4, "fatbin entry header")?)
            .map_err(|_| KernelParamError::OutOfBounds("fatbin entry header"))?;
        if entry_header_len < FATBIN_ENTRY_HEADER_LEN {
            return Err(KernelParamError::Malformed("fatbin entry header size"));
        }
        let padded_len = usize_from_u64(
            read_u64(fixed, 8, "fatbin entry header")?,
            "fatbin padded payload",
        )?;
        let payload_len = usize::try_from(read_u32(fixed, 0x10, "fatbin entry header")?)
            .map_err(|_| KernelParamError::OutOfBounds("fatbin payload"))?;
        let uncompressed_len = read_u64(fixed, 0x38, "fatbin entry header")?;
        let payload_start = cursor
            .checked_add(entry_header_len)
            .ok_or(KernelParamError::OutOfBounds("fatbin entry header"))?;
        let payload_end = payload_start
            .checked_add(padded_len)
            .ok_or(KernelParamError::OutOfBounds("fatbin payload"))?;
        if payload_end > end || payload_len > padded_len {
            return Err(KernelParamError::OutOfBounds("fatbin payload"));
        }
        let actual_len = if payload_len == 0 {
            padded_len
        } else {
            payload_len
        };
        let payload = checked_range(image, payload_start, actual_len, "fatbin payload")?;
        if uncompressed_len != 0 {
            if kind == 2 {
                compressed_cubin = true;
            }
        } else if kind == 1 || kind == 2 {
            let candidate = if kind == 2 {
                cubin_param_sizes(payload, entry)
            } else {
                ptx_param_sizes(payload, entry)
            };
            match candidate {
                Ok(candidate) => {
                    if result.as_ref().is_some_and(|known| known != &candidate) {
                        return Err(KernelParamError::Malformed(
                            "fatbin parameter layouts disagree",
                        ));
                    }
                    result = Some(candidate);
                }
                Err(KernelParamError::MissingEntry) => {}
                Err(error) => return Err(error),
            }
        }
        cursor = payload_end;
    }
    if cursor != end {
        return Err(KernelParamError::OutOfBounds("fatbin body"));
    }
    if let Some(result) = result {
        return Ok(result);
    }
    if compressed_cubin {
        return Err(KernelParamError::UnsupportedCompressedFatbin);
    }
    Err(KernelParamError::MissingEntry)
}

fn aligned_record_end(
    bytes: &[u8],
    offset: usize,
    len: usize,
    alignment: usize,
) -> Result<usize, KernelParamError> {
    let end = record_end(bytes, offset, len, "CUDA metadata record")?;
    let padding = (alignment - end % alignment) % alignment;
    let aligned = end
        .checked_add(padding)
        .ok_or(KernelParamError::OutOfBounds("CUDA metadata record"))?;
    if aligned > bytes.len() {
        return Err(KernelParamError::Truncated("CUDA metadata record padding"));
    }
    Ok(aligned)
}

fn record_end(
    bytes: &[u8],
    offset: usize,
    len: usize,
    context: &'static str,
) -> Result<usize, KernelParamError> {
    checked_range(bytes, offset, len, context)?;
    offset
        .checked_add(len)
        .ok_or(KernelParamError::OutOfBounds(context))
}

fn checked_range<'a>(
    bytes: &'a [u8],
    offset: usize,
    len: usize,
    context: &'static str,
) -> Result<&'a [u8], KernelParamError> {
    let end = offset
        .checked_add(len)
        .ok_or(KernelParamError::OutOfBounds(context))?;
    bytes
        .get(offset..end)
        .ok_or(KernelParamError::OutOfBounds(context))
}

fn read_u16(bytes: &[u8], offset: usize, context: &'static str) -> Result<u16, KernelParamError> {
    let raw: [u8; 2] = checked_range(bytes, offset, 2, context)?
        .try_into()
        .map_err(|_| KernelParamError::Truncated(context))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize, context: &'static str) -> Result<u32, KernelParamError> {
    let raw: [u8; 4] = checked_range(bytes, offset, 4, context)?
        .try_into()
        .map_err(|_| KernelParamError::Truncated(context))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize, context: &'static str) -> Result<u64, KernelParamError> {
    let raw: [u8; 8] = checked_range(bytes, offset, 8, context)?
        .try_into()
        .map_err(|_| KernelParamError::Truncated(context))?;
    Ok(u64::from_le_bytes(raw))
}

fn usize_from_u64(value: u64, context: &'static str) -> Result<usize, KernelParamError> {
    usize::try_from(value).map_err(|_| KernelParamError::OutOfBounds(context))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PTX: &str = r#"
.version 8.3
.target sm_75
.address_size 64

.visible .entry vector_add(
    .param .u64 param_0,
    .param .u64 param_1,
    .param .u32 param_2
)
{
    ret;
}
"#;

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
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

    fn align(bytes: &mut Vec<u8>, alignment: usize) {
        let padding = (alignment - bytes.len() % alignment) % alignment;
        bytes.resize(bytes.len() + padding, 0);
    }

    fn kparam(ordinal: u16, offset: u16, size: u16) -> Vec<u8> {
        let mut bytes = vec![4, 0x17];
        push_u16(&mut bytes, 12);
        push_u32(&mut bytes, 0);
        push_u16(&mut bytes, ordinal);
        push_u16(&mut bytes, offset);
        push_u32(&mut bytes, u32::from(size) << 18);
        bytes
    }

    fn cubin(entry: &str, nvinfo: &[u8]) -> Vec<u8> {
        let section_name = format!(".nv.info.{entry}");
        let mut names = b"\0.shstrtab\0".to_vec();
        let nvinfo_name_offset = names.len();
        names.extend_from_slice(section_name.as_bytes());
        names.push(0);

        let mut bytes = vec![0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        let names_offset = bytes.len();
        bytes.extend_from_slice(&names);
        align(&mut bytes, 4);
        let nvinfo_offset = bytes.len();
        bytes.extend_from_slice(nvinfo);
        align(&mut bytes, 8);
        let section_table_offset = bytes.len();
        bytes.resize(section_table_offset + 3 * 64, 0);

        write_u64(&mut bytes, 0x28, section_table_offset as u64);
        write_u16(&mut bytes, 0x34, 64);
        write_u16(&mut bytes, 0x3a, 64);
        write_u16(&mut bytes, 0x3c, 3);
        write_u16(&mut bytes, 0x3e, 1);

        let shstrtab = section_table_offset + 64;
        write_u32(&mut bytes, shstrtab, 1);
        write_u32(&mut bytes, shstrtab + 4, 3);
        write_u64(&mut bytes, shstrtab + 0x18, names_offset as u64);
        write_u64(&mut bytes, shstrtab + 0x20, names.len() as u64);
        write_u64(&mut bytes, shstrtab + 0x30, 1);

        let info = section_table_offset + 2 * 64;
        write_u32(&mut bytes, info, nvinfo_name_offset as u32);
        write_u32(&mut bytes, info + 4, 0x7000_0000);
        write_u64(&mut bytes, info + 0x18, nvinfo_offset as u64);
        write_u64(&mut bytes, info + 0x20, nvinfo.len() as u64);
        write_u64(&mut bytes, info + 0x30, 4);
        bytes
    }

    fn vector_add_cubin() -> Vec<u8> {
        let mut info = kparam(2, 16, 4);
        info.extend_from_slice(&kparam(1, 8, 8));
        info.extend_from_slice(&kparam(0, 0, 8));
        cubin("vector_add", &info)
    }

    fn fatbin(payload: &[u8], kind: u16) -> Vec<u8> {
        let padded_payload_size = payload.len().div_ceil(8) * 8;
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 0xba55_ed50);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, 16);
        push_u64(&mut bytes, (64 + padded_payload_size) as u64);
        push_u16(&mut bytes, kind);
        push_u16(&mut bytes, 0x0101);
        push_u32(&mut bytes, 64);
        push_u32(&mut bytes, padded_payload_size as u32);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, payload.len() as u32);
        bytes.resize(16 + 64, 0);
        bytes.extend_from_slice(payload);
        bytes.resize(16 + 64 + padded_payload_size, 0);
        bytes
    }

    #[test]
    fn ptx_remains_the_fallback() {
        assert_eq!(
            kernel_param_sizes(PTX.as_bytes(), "vector_add"),
            Ok(vec![8, 8, 4])
        );
    }

    #[test]
    fn cubin_recovers_parameters_in_ordinal_order() {
        assert_eq!(
            kernel_param_sizes(&vector_add_cubin(), "vector_add"),
            Ok(vec![8, 8, 4])
        );
    }

    #[test]
    fn a_zero_parameter_cubin_entry_is_valid() {
        assert_eq!(
            kernel_param_sizes(&cubin("empty", &[]), "empty"),
            Ok(vec![])
        );
    }

    #[test]
    fn an_uncompressed_fatbin_exposes_its_cubin_metadata() {
        let image = fatbin(&vector_add_cubin(), 2);
        assert_eq!(kernel_param_sizes(&image, "vector_add"), Ok(vec![8, 8, 4]));
    }

    #[test]
    fn an_uncompressed_fatbin_can_fall_back_to_ptx() {
        let image = fatbin(PTX.as_bytes(), 1);
        assert_eq!(kernel_param_sizes(&image, "vector_add"), Ok(vec![8, 8, 4]));
    }

    #[test]
    fn missing_entries_are_explicit_and_never_guessed() {
        assert_eq!(
            kernel_param_sizes(&vector_add_cubin(), "absent"),
            Err(KernelParamError::MissingEntry)
        );
        assert_eq!(
            kernel_param_sizes(PTX.as_bytes(), "absent"),
            Err(KernelParamError::MissingEntry)
        );
    }

    #[test]
    fn elf_class_and_endianness_are_explicitly_refused() {
        let mut class = vector_add_cubin();
        class[4] = 1;
        assert_eq!(
            kernel_param_sizes(&class, "vector_add"),
            Err(KernelParamError::UnsupportedElfClass(1))
        );

        let mut endian = vector_add_cubin();
        endian[5] = 2;
        assert_eq!(
            kernel_param_sizes(&endian, "vector_add"),
            Err(KernelParamError::UnsupportedEndian(2))
        );
    }

    #[test]
    fn truncated_and_out_of_bounds_elf_data_is_refused() {
        assert_eq!(
            kernel_param_sizes(b"\x7fELF", "vector_add"),
            Err(KernelParamError::Truncated("ELF header"))
        );
        let mut image = vector_add_cubin();
        write_u64(&mut image, 0x28, u64::MAX);
        assert_eq!(
            kernel_param_sizes(&image, "vector_add"),
            Err(KernelParamError::OutOfBounds("ELF section table"))
        );
    }

    #[test]
    fn malformed_parameter_records_are_refused() {
        let mut short = kparam(0, 0, 8);
        write_u16(&mut short, 2, 11);
        assert_eq!(
            kernel_param_sizes(&cubin("bad", &short), "bad"),
            Err(KernelParamError::Malformed("KPARAM_INFO record length"))
        );

        let mut duplicate = kparam(0, 0, 8);
        duplicate.extend_from_slice(&kparam(0, 8, 8));
        assert_eq!(
            kernel_param_sizes(&cubin("bad", &duplicate), "bad"),
            Err(KernelParamError::DuplicateOrdinal(0))
        );

        assert_eq!(
            kernel_param_sizes(&cubin("bad", &kparam(1, 8, 8)), "bad"),
            Err(KernelParamError::SparseOrdinals)
        );
    }

    #[test]
    fn parameter_count_is_bounded_before_allocating_by_ordinal() {
        let ordinal =
            u16::try_from(crate::wire::MAX_KERNEL_PARAMS).expect("the wire parameter cap fits u16");
        assert_eq!(
            kernel_param_sizes(&cubin("wide", &kparam(ordinal, 0, 8)), "wide"),
            Err(KernelParamError::ParameterCountExceeded {
                count: crate::wire::MAX_KERNEL_PARAMS + 1,
                max: crate::wire::MAX_KERNEL_PARAMS,
            })
        );
    }

    #[test]
    fn ptx_parameter_count_is_bounded_while_parsing() {
        let mut ptx = String::from(".visible .entry too_wide(\n");
        for ordinal in 0..=crate::wire::MAX_KERNEL_PARAMS {
            ptx.push_str(&format!(".param .u32 p{ordinal},\n"));
        }
        ptx.push_str(")\n{ ret; }\n");
        assert_eq!(
            kernel_param_sizes(ptx.as_bytes(), "too_wide"),
            Err(KernelParamError::ParameterCountExceeded {
                count: crate::wire::MAX_KERNEL_PARAMS + 1,
                max: crate::wire::MAX_KERNEL_PARAMS,
            })
        );
        assert_eq!(
            crate::ptx_entry_param_sizes(ptx.as_bytes(), "too_wide"),
            None
        );
    }

    #[test]
    fn malformed_and_compressed_fatbins_fail_closed() {
        assert_eq!(
            kernel_param_sizes(&[0x50, 0xed, 0x55, 0xba], "vector_add"),
            Err(KernelParamError::Truncated("fatbin header"))
        );

        let mut compressed = fatbin(&vector_add_cubin(), 2);
        write_u64(&mut compressed, 16 + 0x38, 4096);
        assert_eq!(
            kernel_param_sizes(&compressed, "vector_add"),
            Err(KernelParamError::UnsupportedCompressedFatbin)
        );
    }

    #[test]
    fn the_input_cap_is_checked_without_allocating_from_image_fields() {
        assert_eq!(
            validate_image_len(MAX_MODULE_IMAGE_LEN + 1),
            Err(KernelParamError::ImageTooLarge {
                len: MAX_MODULE_IMAGE_LEN + 1,
                max: MAX_MODULE_IMAGE_LEN,
            })
        );
    }
}
