//! Names and helpers the Stage 0 and builder-VM guests share with the host that
//! boots them.
//!
//! They live here, in the crate the guest binaries are built from, so the
//! musl build that embeds those binaries compiles only what they run. The host
//! crate re-exports each item from where it used to be defined.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// ext4 volume label on the persistent Stage 0 Nix store image.
///
/// The store used to be located by device letter, which couples it to how many
/// block devices the backend happens to attach ahead of it. Adding one drive —
/// the FlowMux identity disk — shifted every device behind it, so the guest
/// mounted a 32 KiB identity image as its Nix store, failed, and silently fell
/// back to a RAM-backed tmpfs that cannot hold a kernel source tree. The build
/// then died thousands of lines later on `No space left on device`.
pub const STAGE0_NIX_STORE_EXT4_LABEL: &str = "mvm-nix-store";

/// Scratch payload baked into the tightly packed Stage 0 ext4 root and removed
/// by PID 1 before it creates the small amount of mutable bootstrap state.
pub const ROOT_RUNTIME_RESERVE_PATH: &str = "/.mvm-stage0-root-reserve";

/// The three files an SDK-sidecar Stage 0 build hands back: the image, its
/// version stamp, and the checksum manifest covering both. Spelled out here
/// because the guest binary must not link `mvm-fs`; a test holds them equal to
/// the names that crate's resolver reads.
pub const SDK_SIDECAR_OUTPUT_FILES: [&str; 3] = ["sdk.ext4", "VERSION", "checksums-sha256.txt"];

/// Builder persistent `/nix` store auto-GC threshold (GiB of *used*
/// space). When the in-guest store exceeds this after a build, the
/// build script runs `nix-collect-garbage --delete-older-than 14d`.
/// Default 24 GiB (above doctor's 20 GiB warning, below the 64 GiB
/// sparse cap `DEFAULT_NIX_STORE_MIB`). Override with the
/// `MVM_BUILDER_STORE_GC_GIB` environment variable.
pub const DEFAULT_BUILDER_STORE_GC_GIB: u32 = 24;

/// Kernel-cmdline key carrying the builder-store GC cap into the Stage 0
/// guest.
///
/// The guest cannot read the host's environment, so without this the
/// `MVM_BUILDER_STORE_GC_GIB` override would govern the steady-state
/// store and silently not the Stage 0 one. It rides the cmdline rather than
/// `stage0-build.conf` because the ordinary builder-image bootstrap writes no
/// config at all — only the SDK-sidecar and external-kernel paths do — so a
/// config-carried cap reached the guest on exactly the paths that did not need
/// it.
pub const STAGE0_STORE_GC_KIB_CMDLINE_KEY: &str = "mvm.store_gc_kib";

/// Copy a non-empty artifact through an explicit userspace buffer.
///
/// Stage 0 copies from its ext4-backed Nix store to the output staging tree.
/// Bootstrap artifacts use ordinary reads and writes and reject an empty
/// source before it can be reported as successfully emitted.
pub fn copy_nonempty_file(src: &Path, dst: &Path) -> Result<u64> {
    let mut input = std::io::BufReader::new(
        std::fs::File::open(src).with_context(|| format!("open {} for copy", src.display()))?,
    );
    let mut output = std::io::BufWriter::new(
        std::fs::File::create(dst).with_context(|| format!("create {} for copy", dst.display()))?,
    );
    let mut buffer = [0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let read = input
            .read(&mut buffer)
            .with_context(|| format!("read {}", src.display()))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .with_context(|| format!("write {}", dst.display()))?;
        copied = copied.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    output
        .flush()
        .with_context(|| format!("flush {}", dst.display()))?;
    if copied == 0 {
        let _ = std::fs::remove_file(dst);
        bail!(
            "copy {} -> {} produced an empty artifact",
            src.display(),
            dst.display()
        );
    }
    Ok(copied)
}

/// Read the last `max_bytes` of `path` into a `String`, replacing any
/// invalid UTF-8 lossily. Returns `Err` if the file is missing or
/// unreadable. Surfaces the tail of a job's `nix-stderr.log` in the failure
/// path without loading a multi-hundred-KB log into memory.
pub fn read_last_bytes_of(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let take = max_bytes.min(len);
    // SeekFrom::End wants i64; max_bytes is bounded to a small constant
    // at every call site (4 KiB today) so the cast is safe.
    let offset = i64::try_from(take).unwrap_or(i64::MAX).saturating_neg();
    file.seek(SeekFrom::End(offset))?;
    let mut buf = Vec::with_capacity(take as usize);
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sidecar_output_names_are_the_ones_the_resolver_reads() {
        assert_eq!(
            SDK_SIDECAR_OUTPUT_FILES,
            [
                mvm_fs::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE,
                mvm_fs::sdk_sidecar::SDK_SIDECAR_VERSION_FILE,
                mvm_fs::overlay::CHECKSUM_MANIFEST_FILE,
            ]
        );
    }
}
