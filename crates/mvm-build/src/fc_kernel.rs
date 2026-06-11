//! Make a published x86_64 kernel Firecracker-loadable.
//!
//! Firecracker's x86_64 boot loader needs an **uncompressed ELF `vmlinux`**, but
//! the nixpkgs x86_64 kernel ships a **bzImage** (a self-decompressing wrapper),
//! and the default-microvm image copies that bzImage as `vmlinux` — so FC
//! rejects it with *"Invalid Elf magic number"*. We detect a non-ELF kernel and
//! extract the embedded ELF the way the kernel's own `scripts/extract-vmlinux`
//! does: locate the compressed payload and decompress it. (aarch64 ships a flat
//! `Image` that FC loads directly, so it's left untouched.)

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// An FC-loadable x86_64 `vmlinux` begins with the ELF magic.
const ELF_MAGIC: &[u8] = b"\x7fELF";
/// gzip magic + the DEFLATE method byte (`1f 8b 08`) — the payload wrapper the
/// default `CONFIG_KERNEL_GZIP` x86_64 kernel embeds in its bzImage.
const GZIP_MAGIC: &[u8] = b"\x1f\x8b\x08";

/// Whether `bytes` already begins with the ELF magic (an FC-loadable vmlinux).
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(ELF_MAGIC)
}

/// Extract the embedded ELF `vmlinux` from a bzImage by locating its gzip
/// payload and decompressing it. Already-ELF input is returned verbatim. A
/// bzImage can contain incidental `1f 8b 08` byte runs, so every gzip-magic
/// offset is tried; the first payload that decompresses to an ELF wins. Errors
/// when none does (e.g. a non-gzip kernel compression we don't yet decode —
/// named explicitly so the gap is obvious).
pub fn extract_vmlinux(image: &[u8]) -> Result<Vec<u8>> {
    if is_elf(image) {
        return Ok(image.to_vec());
    }
    for off in gzip_offsets(image) {
        if let Some(elf) = try_gunzip_to_elf(&image[off..]) {
            return Ok(elf);
        }
    }
    bail!(
        "no gzip-compressed ELF vmlinux found in the {}-byte kernel image \
         (not ELF, and no embedded gzip payload decompressed to ELF — a non-gzip \
         kernel compression such as xz/zstd/lz4 would need its decoder added)",
        image.len()
    )
}

/// Ensure the kernel file at `path` is an FC-loadable ELF `vmlinux`. Returns
/// `path` unchanged when it already is; otherwise extracts the ELF to a cached
/// sibling `<path>.elf` (once — reused on later boots) and returns that path.
/// Idempotent: a valid cached sibling short-circuits the re-extract.
pub fn ensure_fc_loadable_kernel(path: &Path) -> Result<PathBuf> {
    if file_starts_with_elf(path)? {
        return Ok(path.to_path_buf());
    }

    let elf_path = sibling_elf(path);
    if file_starts_with_elf(&elf_path).unwrap_or(false) {
        return Ok(elf_path); // already extracted on a prior boot
    }

    let image = std::fs::read(path).with_context(|| format!("read kernel {}", path.display()))?;
    let vmlinux = extract_vmlinux(&image)
        .with_context(|| format!("extract FC-loadable vmlinux from {}", path.display()))?;

    // Write atomically (tmp + rename) so a concurrent/partial boot never sees a
    // half-written kernel.
    let tmp = sibling(path, ".elf.tmp");
    std::fs::write(&tmp, &vmlinux).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &elf_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), elf_path.display()))?;
    Ok(elf_path)
}

/// Read just the first 4 bytes and test the ELF magic — avoids slurping a
/// multi-MB kernel to answer "is this already loadable?". Missing file ⇒ `false`
/// for the sibling probe, but an error for the primary path (handled by caller).
fn file_starts_with_elf(path: &Path) -> Result<bool> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("open kernel {}", path.display())),
    };
    let mut head = [0u8; 4];
    let n = f
        .read(&mut head)
        .with_context(|| format!("read kernel magic {}", path.display()))?;
    Ok(n == 4 && is_elf(&head))
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn sibling_elf(path: &Path) -> PathBuf {
    sibling(path, ".elf")
}

fn gzip_offsets(image: &[u8]) -> impl Iterator<Item = usize> + '_ {
    image
        .windows(GZIP_MAGIC.len())
        .enumerate()
        .filter(|(_, w)| *w == GZIP_MAGIC)
        .map(|(i, _)| i)
}

/// Decompress one gzip member at the start of `stream`; `Some` only when it
/// yields an ELF. `GzDecoder` reads a single member and ignores trailing bzImage
/// bytes; a bogus offset errors → `None`.
fn try_gunzip_to_elf(stream: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut dec = flate2::read::GzDecoder::new(stream);
    match dec.read_to_end(&mut out) {
        Ok(_) if out.starts_with(ELF_MAGIC) => Some(out),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    /// A stand-in "vmlinux": ELF magic + filler so it's clearly the ELF, not a
    /// coincidental match.
    fn fake_vmlinux() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(ELF_MAGIC);
        v.extend_from_slice(&[0u8; 64]);
        v.extend(b"the rest of the kernel image");
        v
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A fake bzImage: x86 boot stub bytes + the gzipped vmlinux + a trailer.
    fn fake_bzimage(vmlinux: &[u8]) -> Vec<u8> {
        let mut img = Vec::new();
        img.extend(b"MZ"); // DOS stub — definitely not ELF
        img.extend_from_slice(&[0x90u8; 512]); // padding/boot stub
        img.extend(gzip(vmlinux));
        img.extend_from_slice(&[0xABu8; 128]); // trailer after the gzip member
        img
    }

    #[test]
    fn is_elf_detects_magic() {
        assert!(is_elf(b"\x7fELF\x02\x01"));
        assert!(!is_elf(b"MZ\x90\x00"));
        assert!(!is_elf(b""));
    }

    #[test]
    fn already_elf_is_returned_verbatim() {
        let v = fake_vmlinux();
        assert_eq!(extract_vmlinux(&v).unwrap(), v);
    }

    #[test]
    fn extracts_gzip_embedded_vmlinux_from_a_bzimage() {
        let vmlinux = fake_vmlinux();
        let bzimage = fake_bzimage(&vmlinux);
        // The bzImage is not ELF...
        assert!(!is_elf(&bzimage));
        // ...but extraction recovers the exact embedded ELF.
        let got = extract_vmlinux(&bzimage).unwrap();
        assert!(is_elf(&got));
        assert_eq!(got, vmlinux);
    }

    #[test]
    fn extract_skips_incidental_gzip_magic_before_the_real_payload() {
        let vmlinux = fake_vmlinux();
        let mut bzimage = Vec::new();
        // An incidental `1f 8b 08` run that is NOT a valid gzip member.
        bzimage.extend_from_slice(b"\x1f\x8b\x08not-a-real-gzip-stream\x00\x00");
        bzimage.extend(gzip(&vmlinux));
        let got = extract_vmlinux(&bzimage).unwrap();
        assert_eq!(got, vmlinux);
    }

    #[test]
    fn non_gzip_non_elf_image_errors_clearly() {
        let junk = vec![0x42u8; 4096]; // no ELF, no gzip member
        let err = extract_vmlinux(&junk).unwrap_err();
        assert!(format!("{err}").contains("vmlinux"), "got: {err}");
    }

    #[test]
    fn ensure_fc_loadable_passes_through_an_elf_kernel() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");
        std::fs::write(&kpath, fake_vmlinux()).unwrap();
        // Already ELF → returned unchanged, no sibling created.
        let got = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(got, kpath);
        assert!(!kpath.with_extension("elf").exists() && !sibling_elf(&kpath).exists());
    }

    #[test]
    fn ensure_fc_loadable_extracts_a_bzimage_to_a_cached_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux"); // a bzImage misnamed as vmlinux
        let vmlinux = fake_vmlinux();
        std::fs::write(&kpath, fake_bzimage(&vmlinux)).unwrap();

        let got = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(got, sibling_elf(&kpath));
        assert_eq!(std::fs::read(&got).unwrap(), vmlinux);
        assert!(is_elf(&std::fs::read(&got).unwrap()));

        // Idempotent: a second call reuses the cached sibling (no .tmp left).
        let again = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(again, got);
        assert!(!sibling(&kpath, ".elf.tmp").exists());
    }
}
