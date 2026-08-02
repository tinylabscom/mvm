//! Host-side resolution of the Apple Container kernel artifact.
//!
//! The Apple Container backend boots Apple's prebuilt container kernel — a
//! fetched binary artifact mvm does not build — cached at
//! `<mvm-cache>/apple-container/vmlinux`. Everything else in the boot (the
//! universal initramfs, the guest agent, activation) is the same stack
//! every runner backend uses. Resolution is pure path probing plus digest
//! attestation: a missing kernel is a typed
//! [`AppleContainerError::ArtifactMissing`] whose hint says where to fetch
//! it, and a kernel without a matching `vmlinux.blake3` sidecar is a typed
//! [`AppleContainerError::ArtifactUntrusted`] — the same hash-sidecar
//! honesty contract the initramfs artifact already enforces, so a fetched
//! kernel is trusted only when its pinned digest matches its bytes. The
//! pin is BLAKE3: the fetched kernel is multi-hundred-MB, and BLAKE3
//! hashes it an order of magnitude faster than SHA-256.

use std::path::{Path, PathBuf};

use crate::apple_container_backend::AppleContainerError;

/// Cache subdirectory (under `mvm_cache_dir`) holding the artifact.
pub const ARTIFACT_DIR_NAME: &str = "apple-container";
/// File name of the container kernel image inside the artifact dir.
pub const KERNEL_FILE_NAME: &str = "vmlinux";
/// File name of the digest sidecar pinning the kernel bytes, beside the
/// kernel: the lowercase-hex BLAKE3 of the kernel, in either the bare
/// `<hex>` form or `b3sum`'s `<hex>  <name>` form.
pub const KERNEL_DIGEST_FILE_NAME: &str = "vmlinux.blake3";

/// Hint for a missing kernel artifact.
const KERNEL_HINT: &str = "copy an arm64 Linux Image with device-mapper + dm-verity built in \
     (CONFIG_BLK_DEV_DM=y, CONFIG_DM_VERITY=y) here — the stock Apple/Kata container kernels \
     ship no device-mapper, so the universal-initramfs verified boot needs a dm-capable kernel \
     (e.g. build github.com/apple/containerization's kernel with those options enabled)";

/// Hint for an untrusted kernel: how to record the pin after staging a
/// kernel the operator trusts.
const TRUST_HINT: &str = "after staging a trusted kernel, record its BLAKE3 digest beside it — \
     `b3sum vmlinux > vmlinux.blake3` (install b3sum via `brew install b3sum` or \
     `cargo install b3sum`) — the kernel is used only when the sidecar matches its bytes";

/// The cache directory the kernel is resolved from.
pub fn artifact_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join(ARTIFACT_DIR_NAME)
}

/// Resolve the container kernel from the cache, failing closed with a
/// typed error naming the missing file and how to fetch it, or the
/// attestation failure and how to pin a trusted kernel.
pub fn resolve() -> Result<PathBuf, AppleContainerError> {
    resolve_from(&artifact_dir())
}

/// The filesystem-probing core of [`resolve`], split out so tests point it
/// at a tempdir instead of the real cache.
fn resolve_from(dir: &Path) -> Result<PathBuf, AppleContainerError> {
    let kernel = dir.join(KERNEL_FILE_NAME);
    if !kernel.is_file() {
        return Err(AppleContainerError::ArtifactMissing {
            what: "Apple container kernel (arm64 Linux Image)",
            path: kernel.display().to_string(),
            hint: KERNEL_HINT,
        });
    }
    verify_digest_pin(&kernel)?;
    Ok(kernel)
}

/// Verify the kernel against its `vmlinux.blake3` pin: the sidecar must
/// exist, parse, and name the digest the kernel bytes actually hash to.
/// The kernel is streamed through the hasher, never read whole.
fn verify_digest_pin(kernel: &Path) -> Result<(), AppleContainerError> {
    let sidecar = kernel.with_file_name(KERNEL_DIGEST_FILE_NAME);
    let untrusted = |reason: String| AppleContainerError::ArtifactUntrusted {
        path: kernel.display().to_string(),
        reason,
        hint: TRUST_HINT,
    };
    let contents = std::fs::read_to_string(&sidecar).map_err(|_| {
        untrusted(format!(
            "no digest sidecar at {} — a fetched kernel is not trusted unpinned",
            sidecar.display()
        ))
    })?;
    let expected = parse_pinned_digest(&contents).ok_or_else(|| {
        untrusted(format!(
            "digest sidecar {} is malformed (expected `<hex>` or `<hex>  <name>`)",
            sidecar.display()
        ))
    })?;
    let actual = blake3_file(kernel)
        .map_err(|e| untrusted(format!("kernel could not be read for hashing: {e}")))?;
    if actual != expected {
        return Err(untrusted(format!(
            "kernel bytes do not match the pinned digest (pinned {expected}, hashed {actual})"
        )));
    }
    Ok(())
}

/// Stream `path` through BLAKE3 with a 64 KiB buffer and return the
/// lowercase hex digest; the file is never read whole.
fn blake3_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Parse the pinned digest out of a sidecar, accepting the bare `<hex>`
/// form and `b3sum`'s `<hex>  <name>` form. Returns the lowercase hex
/// digest, or `None` when the sidecar does not start with a well-formed
/// BLAKE3 hex token.
fn parse_pinned_digest(contents: &str) -> Option<String> {
    let hex = contents.split_whitespace().next()?;
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stage a kernel with `bytes` and a sidecar with `sidecar` contents.
    fn stage(dir: &Path, bytes: &[u8], sidecar: &str) -> PathBuf {
        let kernel = dir.join(KERNEL_FILE_NAME);
        std::fs::write(&kernel, bytes).expect("kernel");
        std::fs::write(dir.join(KERNEL_DIGEST_FILE_NAME), sidecar).expect("sidecar");
        kernel
    }

    /// The bare-hex pin for `bytes`.
    fn pin_for(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    /// Assert `err` is the `ArtifactMissing` variant and return its fields.
    fn expect_missing(err: &AppleContainerError) -> (&'static str, &str, &'static str) {
        match err {
            AppleContainerError::ArtifactMissing { what, path, hint } => (what, path, hint),
            other => panic!("expected ArtifactMissing, got {other:?}"),
        }
    }

    /// Assert `err` is the `ArtifactUntrusted` variant and return its fields.
    fn expect_untrusted(err: &AppleContainerError) -> (&str, &str, &'static str) {
        match err {
            AppleContainerError::ArtifactUntrusted { path, reason, hint } => (path, reason, hint),
            other => panic!("expected ArtifactUntrusted, got {other:?}"),
        }
    }

    #[test]
    fn missing_kernel_is_typed_with_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolve_from(dir.path()).unwrap_err();
        let (what, path, hint) = expect_missing(&err);
        assert!(what.contains("kernel"));
        assert!(path.ends_with("vmlinux"));
        assert!(hint.contains("container kernel"));
        assert_eq!(
            err.to_string(),
            format!("apple-container artifact missing: {what} at {path} — {hint}")
        );
    }

    #[test]
    fn present_kernel_with_matching_bare_hex_pin_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = stage(dir.path(), b"kernel", &pin_for(b"kernel"));
        assert_eq!(resolve_from(dir.path()).expect("resolve"), kernel);
    }

    #[test]
    fn b3sum_form_sidecar_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pin = format!("{}  vmlinux\n", pin_for(b"kernel"));
        stage(dir.path(), b"kernel", &pin);
        assert!(resolve_from(dir.path()).is_ok());
    }

    #[test]
    fn sidecar_whitespace_is_trimmed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pin = format!("  {}  \n", pin_for(b"kernel"));
        stage(dir.path(), b"kernel", &pin);
        assert!(resolve_from(dir.path()).is_ok());
    }

    #[test]
    fn missing_sidecar_is_untrusted_with_the_pin_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(KERNEL_FILE_NAME), b"kernel").expect("kernel");
        let err = resolve_from(dir.path()).unwrap_err();
        let (path, reason, hint) = expect_untrusted(&err);
        assert!(path.ends_with("vmlinux"));
        assert!(
            reason.contains("no digest sidecar"),
            "reason must say the pin is missing: {reason}"
        );
        assert!(reason.contains(KERNEL_DIGEST_FILE_NAME));
        assert!(
            hint.contains("b3sum"),
            "the hint must say how to record the digest: {hint}"
        );
    }

    #[test]
    fn garbage_sidecar_is_untrusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        stage(dir.path(), b"kernel", "not-a-digest\n");
        let err = resolve_from(dir.path()).unwrap_err();
        let (_, reason, hint) = expect_untrusted(&err);
        assert!(
            reason.contains("malformed"),
            "reason must say the sidecar is malformed: {reason}"
        );
        assert!(hint.contains("b3sum"));
    }

    #[test]
    fn mismatched_digest_names_pinned_and_actual() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wrong = pin_for(b"different-kernel-bytes");
        stage(dir.path(), b"kernel", &wrong);
        let err = resolve_from(dir.path()).unwrap_err();
        let (_, reason, _) = expect_untrusted(&err);
        let actual = pin_for(b"kernel");
        assert!(
            reason.contains(&wrong),
            "reason must name the pinned digest {wrong}: {reason}"
        );
        assert!(
            reason.contains(&actual),
            "reason must name the actual digest {actual}: {reason}"
        );
    }

    #[test]
    fn uppercase_hex_pin_resolves() {
        let dir = tempfile::tempdir().expect("tempdir");
        stage(
            dir.path(),
            b"kernel",
            &pin_for(b"kernel").to_ascii_uppercase(),
        );
        assert!(resolve_from(dir.path()).is_ok());
    }

    #[test]
    fn parse_pinned_digest_accepts_both_forms() {
        let hex = pin_for(b"x");
        assert_eq!(
            parse_pinned_digest(&hex).as_deref(),
            Some(hex.as_str()),
            "bare form"
        );
        assert_eq!(
            parse_pinned_digest(&format!("{hex}  vmlinux\n")).as_deref(),
            Some(hex.as_str()),
            "b3sum form"
        );
        assert_eq!(parse_pinned_digest(""), None);
        assert_eq!(parse_pinned_digest("zzzz"), None);
        assert_eq!(parse_pinned_digest(&hex[..63]), None, "truncated hex");
    }

    #[test]
    fn artifact_dir_lives_under_the_mvm_cache() {
        let dir = artifact_dir();
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some(ARTIFACT_DIR_NAME)
        );
    }
}
