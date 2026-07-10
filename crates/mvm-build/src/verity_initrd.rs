use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use mvm_core::arch::GuestArch;

use crate::guest_agent_build::{self, GuestAgentBuildError};
use crate::rootfs_inject::{CpioEntry, build_newc_cpio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityInitrdLayout {
    pub dir: PathBuf,
    pub initrd: PathBuf,
    pub local_source_fingerprint_file: PathBuf,
}

impl VerityInitrdLayout {
    pub fn under(cache_root: &Path, version: &str, arch: GuestArch) -> Self {
        let dir = cache_root
            .join("verity-initrd")
            .join(version)
            .join(arch.to_string());
        Self {
            initrd: dir.join("rootfs.initrd"),
            local_source_fingerprint_file: dir.join(LOCAL_SOURCE_FINGERPRINT_FILE),
            dir,
        }
    }
}

const LOCAL_SOURCE_FINGERPRINT_FILE: &str = "SOURCE_FINGERPRINT";

pub fn resolve_or_build_verity_initrd(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<PathBuf, GuestAgentBuildError> {
    let layout = VerityInitrdLayout::under(cache_root, version, arch);
    let fingerprint =
        guest_agent_build::runtime_overlay_source_checkout_fingerprint(workspace_root)?;
    if local_source_initrd_cache_is_fresh(&layout, &fingerprint)? {
        return Ok(layout.initrd);
    }
    let bins = guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
        cache_root,
        version,
        arch,
        workspace_root,
    )?;
    install_verity_initrd_from_binary(
        &bins.verity_init,
        cache_root,
        version,
        arch,
        Some(&fingerprint),
    )
}

pub fn install_prebuilt_verity_initrd(
    verity_init_bytes: &[u8],
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<PathBuf, GuestAgentBuildError> {
    let layout = VerityInitrdLayout::under(cache_root, version, arch);
    std::fs::create_dir_all(&layout.dir)?;
    let bytes = build_verity_initrd_bytes(verity_init_bytes)?;
    std::fs::write(&layout.initrd, bytes)?;
    let _ = std::fs::remove_file(&layout.local_source_fingerprint_file);
    Ok(layout.initrd)
}

pub fn install_verity_initrd_from_binary(
    verity_init_path: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    local_source_fingerprint: Option<&str>,
) -> Result<PathBuf, GuestAgentBuildError> {
    let layout = VerityInitrdLayout::under(cache_root, version, arch);
    std::fs::create_dir_all(&layout.dir)?;
    let bytes = std::fs::read(verity_init_path)?;
    let initrd = build_verity_initrd_bytes(&bytes)?;
    std::fs::write(&layout.initrd, initrd)?;
    if let Some(fingerprint) = local_source_fingerprint {
        std::fs::write(
            &layout.local_source_fingerprint_file,
            format!("{fingerprint}\n"),
        )?;
    } else {
        let _ = std::fs::remove_file(&layout.local_source_fingerprint_file);
    }
    Ok(layout.initrd)
}

fn local_source_initrd_cache_is_fresh(
    layout: &VerityInitrdLayout,
    expected_fingerprint: &str,
) -> Result<bool, GuestAgentBuildError> {
    if !layout.initrd.is_file() || !layout.local_source_fingerprint_file.is_file() {
        return Ok(false);
    }
    let found = std::fs::read_to_string(&layout.local_source_fingerprint_file)?;
    Ok(found.trim() == expected_fingerprint)
}

pub fn build_verity_initrd_bytes(verity_init: &[u8]) -> Result<Vec<u8>, GuestAgentBuildError> {
    let cpio = build_newc_cpio(&[
        CpioEntry::file("init", 0o755, verity_init.to_vec()),
        CpioEntry::dir("dev"),
        CpioEntry::dir("proc"),
        CpioEntry::dir("sysroot"),
    ]);
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&cpio).map_err(GuestAgentBuildError::Io)?;
    enc.finish().map_err(GuestAgentBuildError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_verity_initrd_contains_expected_entries() {
        let gz = build_verity_initrd_bytes(b"verity-init").expect("build initrd");
        let mut dec = flate2::read::GzDecoder::new(gz.as_slice());
        let mut cpio = Vec::new();
        std::io::Read::read_to_end(&mut dec, &mut cpio).expect("inflate");
        let names = parse_newc_names(&cpio);
        assert_eq!(names, vec!["init", "dev", "proc", "sysroot", "TRAILER!!!"]);
    }

    #[test]
    fn install_prebuilt_verity_initrd_writes_cache_layout() {
        let cache = tempfile::tempdir().expect("temp cache");
        let path = install_prebuilt_verity_initrd(
            b"verity-init",
            cache.path(),
            "1.2.3",
            GuestArch::Aarch64,
        )
        .expect("install");
        assert!(path.is_file());
        let layout = VerityInitrdLayout::under(cache.path(), "1.2.3", GuestArch::Aarch64);
        assert_eq!(path, layout.initrd);
    }

    #[test]
    fn local_source_initrd_cache_requires_matching_fingerprint() {
        let cache = tempfile::tempdir().expect("temp cache");
        let layout = VerityInitrdLayout::under(cache.path(), "1.2.3", GuestArch::Aarch64);
        std::fs::create_dir_all(&layout.dir).expect("create initrd dir");
        std::fs::write(&layout.initrd, b"initrd").expect("write initrd");
        std::fs::write(&layout.local_source_fingerprint_file, b"abc\n").expect("write fingerprint");
        assert!(local_source_initrd_cache_is_fresh(&layout, "abc").expect("fresh cache"));
        assert!(
            !local_source_initrd_cache_is_fresh(&layout, "def").expect("stale cache"),
            "mismatched guest-source fingerprint must invalidate the cached initrd"
        );
    }

    fn parse_newc_names(buf: &[u8]) -> Vec<&str> {
        let hex = |s: &[u8]| u32::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap();
        let mut names = Vec::new();
        let mut off = 0usize;
        loop {
            assert_eq!(&buf[off..off + 6], b"070701");
            let namesize = hex(&buf[off + 94..off + 102]) as usize;
            let filesize = hex(&buf[off + 54..off + 62]) as usize;
            let name_off = off + 110;
            let name = std::str::from_utf8(&buf[name_off..name_off + namesize - 1]).unwrap();
            names.push(name);
            let mut next = name_off + namesize;
            while !next.is_multiple_of(4) {
                next += 1;
            }
            next += filesize;
            while !next.is_multiple_of(4) {
                next += 1;
            }
            if name == "TRAILER!!!" {
                break;
            }
            off = next;
        }
        names
    }
}
