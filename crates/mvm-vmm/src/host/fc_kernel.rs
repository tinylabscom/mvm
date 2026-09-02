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

/// The ARM64 Linux boot `Image` carries the ASCII magic `ARM\x64` at byte
/// offset 56 (`Documentation/arch/arm64/booting.rst`). Firecracker's aarch64
/// loader consumes this flat `Image` directly, so it needs no ELF extraction.
const ARM64_IMAGE_MAGIC: &[u8] = b"ARM\x64";
const ARM64_IMAGE_MAGIC_OFFSET: usize = 56;

/// Whether `bytes` is an ARM64 boot `Image` (magic `ARM\x64` at offset 56).
pub fn is_arm64_image(bytes: &[u8]) -> bool {
    let end = ARM64_IMAGE_MAGIC_OFFSET + ARM64_IMAGE_MAGIC.len();
    bytes.len() >= end && &bytes[ARM64_IMAGE_MAGIC_OFFSET..end] == ARM64_IMAGE_MAGIC
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
/// Idempotent: a cached sibling that still belongs to `path` short-circuits
/// the re-extract.
///
/// "Still belongs to" is the whole point. The short-circuit used to test only
/// that the sibling began with the ELF magic, which every previously extracted
/// kernel does forever. Replacing `vmlinux` — a kernel rebuild, a re-fetch —
/// therefore left the *old* `.elf` in place and every later boot silently ran
/// the superseded kernel. The caller digest-verifies `vmlinux` before calling
/// here, so that substitution also handed the guest bytes the verified-kernel
/// seam never vouched for.
pub fn ensure_fc_loadable_kernel(path: &Path) -> Result<PathBuf> {
    if file_starts_with_elf(path)? {
        return Ok(path.to_path_buf());
    }
    // aarch64 ships a flat `Image` that Firecracker loads directly — no ELF
    // extraction, so hand the path back unchanged.
    if file_is_arm64_image(path)? {
        return Ok(path.to_path_buf());
    }

    let elf_path = sibling_elf(path);
    let stamp_path = sibling(path, ".elf.src");
    let source = source_stamp(path)?;
    if file_starts_with_elf(&elf_path).unwrap_or(false)
        && std::fs::read_to_string(&stamp_path).ok().as_deref() == Some(source.as_str())
    {
        return Ok(elf_path); // extracted from *this* vmlinux on a prior boot
    }

    let image = std::fs::read(path).with_context(|| format!("read kernel {}", path.display()))?;
    let vmlinux = extract_vmlinux(&image)
        .with_context(|| format!("extract FC-loadable vmlinux from {}", path.display()))?;

    // Write atomically (tmp + rename) so a concurrent/partial boot never sees a
    // half-written kernel. The stamp is cleared first and written last: a crash
    // mid-swap then leaves no stamp, which re-extracts, rather than a stamp
    // vouching for an ELF that was never finished.
    let _ = std::fs::remove_file(&stamp_path);
    let tmp = sibling(path, ".elf.tmp");
    std::fs::write(&tmp, &vmlinux).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &elf_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), elf_path.display()))?;
    std::fs::write(&stamp_path, &source)
        .with_context(|| format!("write {}", stamp_path.display()))?;
    Ok(elf_path)
}

/// Identifies the exact `vmlinux` an extracted ELF came from.
///
/// The stamp is the kernel's content digest, so replacing `vmlinux` — a
/// rebuild, a re-fetch — never reuses an ELF extracted from the previous bytes.
/// Serving a stale kernel would cross the verified-kernel seam.
///
/// The digest is obtained through the shared size+mtime-keyed cache rather than
/// by re-reading the image. The caller that resolved this kernel just verified
/// the same bytes against their recorded pin through that same cache, so an
/// unconditional read here was hashing one multi-MB image twice per boot to
/// reach a value already computed. The two now share one entry and one hash per
/// kernel change. What that trades away is the one case a raw re-read still
/// caught: a same-sized replacement landing on a byte-identical mtime, which a
/// filesystem reporting timestamps at one-second resolution can produce. The
/// pin backing the kernel is keyed the same way, so on such a filesystem both
/// go stale together rather than one silently covering for the other.
fn source_stamp(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file_cached(path)
        .with_context(|| format!("hash kernel {} for extracted-ELF cache", path.display()))
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

/// Read the ARM64 `Image` header magic (offset 56) to detect a flat aarch64
/// kernel Firecracker loads directly. A too-short file is not an Image.
fn file_is_arm64_image(path: &Path) -> Result<bool> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("open kernel {}", path.display()))?;
    let mut head = [0u8; ARM64_IMAGE_MAGIC_OFFSET + 4];
    match f.read_exact(&mut head) {
        Ok(()) => Ok(is_arm64_image(&head)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e).with_context(|| format!("read kernel header {}", path.display())),
    }
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

    #[test]
    fn arm64_image_magic_detected_not_extracted() {
        let mut img = vec![0u8; 64];
        img[ARM64_IMAGE_MAGIC_OFFSET..ARM64_IMAGE_MAGIC_OFFSET + ARM64_IMAGE_MAGIC.len()]
            .copy_from_slice(ARM64_IMAGE_MAGIC);
        assert!(is_arm64_image(&img));
        assert!(!is_elf(&img));
        // A buffer too short to hold the offset-56 magic is not an Image.
        assert!(!is_arm64_image(&img[..40]));
        // And a flat Image is (correctly) not extractable as an x86 vmlinux.
        assert!(extract_vmlinux(&img).is_err());
    }

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

    /// Distinguishable payloads so a stale sibling is detectable by content.
    fn fake_vmlinux_tagged(tag: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(ELF_MAGIC);
        v.extend_from_slice(&[tag; 64]);
        v.extend(b"the rest of the kernel image");
        v
    }

    /// The regression this binding exists for: replacing `vmlinux` used to
    /// leave the previous `.elf` in place, and every later boot ran the
    /// superseded kernel.
    #[test]
    fn a_replaced_vmlinux_is_not_served_from_the_previous_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");

        let old = fake_vmlinux_tagged(0x11);
        std::fs::write(&kpath, fake_bzimage(&old)).unwrap();
        let first = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(std::fs::read(&first).unwrap(), old);

        // A rebuild replaces the kernel in place with different contents.
        let new = fake_vmlinux_tagged(0x22);
        std::fs::write(&kpath, fake_bzimage(&new)).unwrap();
        let second = ensure_fc_loadable_kernel(&kpath).unwrap();

        assert_eq!(
            std::fs::read(&second).unwrap(),
            new,
            "a rebuilt kernel must not boot the previously extracted ELF"
        );
    }

    /// The cache must still be a cache: an unchanged kernel does not re-extract.
    #[test]
    fn an_unchanged_vmlinux_reuses_the_cached_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");
        std::fs::write(&kpath, fake_bzimage(&fake_vmlinux_tagged(0x33))).unwrap();

        let first = ensure_fc_loadable_kernel(&kpath).unwrap();
        let stamp = std::fs::read_to_string(sibling(&kpath, ".elf.src")).unwrap();
        // Mark the extracted ELF so a re-extract would overwrite the marker.
        let marked = {
            let mut b = std::fs::read(&first).unwrap();
            b.extend(b"SENTINEL");
            b
        };
        std::fs::write(&first, &marked).unwrap();

        let second = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read(&second).unwrap(),
            marked,
            "an unchanged kernel must not pay the extraction again"
        );
        assert_eq!(
            std::fs::read_to_string(sibling(&kpath, ".elf.src")).unwrap(),
            stamp
        );
    }

    /// A sibling with no stamp is from before this binding existed, or from a
    /// crashed swap. Either way it is unattributable and must be re-derived.
    #[test]
    fn an_unstamped_sibling_is_re_extracted_rather_than_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");
        let real = fake_vmlinux_tagged(0x44);
        std::fs::write(&kpath, fake_bzimage(&real)).unwrap();

        // A leftover ELF from some other kernel, with no stamp beside it.
        std::fs::write(sibling_elf(&kpath), fake_vmlinux_tagged(0x55)).unwrap();

        let got = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(std::fs::read(&got).unwrap(), real);
    }

    /// A stamp naming a different kernel must not vouch for the sibling.
    #[test]
    fn a_stamp_that_does_not_match_the_kernel_forces_a_re_extract() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");
        let real = fake_vmlinux_tagged(0x66);
        std::fs::write(&kpath, fake_bzimage(&real)).unwrap();
        std::fs::write(sibling_elf(&kpath), fake_vmlinux_tagged(0x77)).unwrap();
        std::fs::write(sibling(&kpath, ".elf.src"), "999:1").unwrap();

        let got = ensure_fc_loadable_kernel(&kpath).unwrap();
        assert_eq!(std::fs::read(&got).unwrap(), real);
    }

    /// The stamp is the same content digest the kernel's own pin is checked
    /// against, so preparing a kernel for boot must go through the shared
    /// digest cache rather than re-reading the image. Asserted by the cache
    /// being warm afterwards: a raw re-read leaves no entry behind, so a boot
    /// path that stopped using the cache would re-read the whole image on every
    /// launch and nothing else here would notice.
    #[test]
    fn preparing_a_kernel_leaves_the_shared_digest_cache_warm() {
        use mvm_core::crypto::image_verify::{DigestSource, sha256_file_cached_with_source};

        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");
        std::fs::write(&kpath, fake_bzimage(&fake_vmlinux_tagged(0x99))).unwrap();

        ensure_fc_loadable_kernel(&kpath).unwrap();

        let (_, source) = sha256_file_cached_with_source(&kpath).unwrap();
        assert_eq!(
            source,
            DigestSource::Sidecar,
            "kernel preparation must digest through the shared cache, not a raw re-read"
        );
    }

    #[test]
    fn an_extraction_records_a_stamp_matching_the_kernel_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let kpath = dir.path().join("vmlinux");
        std::fs::write(&kpath, fake_bzimage(&fake_vmlinux_tagged(0x88))).unwrap();
        ensure_fc_loadable_kernel(&kpath).unwrap();

        assert_eq!(
            std::fs::read_to_string(sibling(&kpath, ".elf.src")).unwrap(),
            source_stamp(&kpath).unwrap()
        );
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
