//! Static `ArtifactValidator` implementation.
//!
//! `StaticValidator` runs seven checks in order against a `MicrovmArtifact`,
//! accumulating a `ValidationCheck` per step into a `ValidationReport`.
//! All checks run regardless of earlier failures — the report captures the
//! full picture so a single validate pass surfaces every problem at once.
//!
//! ## Check order (design spec §5)
//!
//! 1. Kernel + rootfs files exist on disk.
//! 2. SHA-256 of each file matches the artifact's recorded hash.
//! 3. `compat(backend).guest_arches` contains the artifact's arch.
//! 4. `kernel_format_ok(compat, arch, kernel.format)` — per-arch format table.
//! 5. `rootfs.format` is in `compat.rootfs_formats`.
//! 6. Every `compat.required_boot_args` token is present in `artifact.boot_args`.
//! 7. The rootfs ext4 image contains `/sbin/init` (via `ext4_view`).

use sha2::{Digest, Sha256};
use std::io::Read;

use crate::artifacts::artifact::{MicrovmArtifact, ValidationCheck, ValidationReport};
use crate::artifacts::traits::{ArtifactError, ArtifactValidator};
use crate::compat::{compat, kernel_format_ok};

// ── public type ───────────────────────────────────────────────────────────────

/// Stateless validator over the `BackendCompat` matrix and the filesystem.
pub struct StaticValidator;

impl ArtifactValidator for StaticValidator {
    fn validate(&self, artifact: &MicrovmArtifact) -> Result<ValidationReport, ArtifactError> {
        let mut checks: Vec<ValidationCheck> = Vec::new();

        // ── check 1: files exist ──────────────────────────────────────────────
        let kernel_exists = artifact.kernel.path.exists();
        let rootfs_exists = artifact.rootfs.path.exists();
        let files_ok = kernel_exists && rootfs_exists;
        checks.push(ValidationCheck {
            name: "files_exist".to_string(),
            ok: files_ok,
            detail: if files_ok {
                String::new()
            } else {
                let mut missing = Vec::new();
                if !kernel_exists {
                    missing.push(artifact.kernel.path.display().to_string());
                }
                if !rootfs_exists {
                    missing.push(artifact.rootfs.path.display().to_string());
                }
                format!("missing: {}", missing.join(", "))
            },
        });

        // ── check 2: SHA-256 hashes match ────────────────────────────────────
        let kernel_hash_ok = if kernel_exists {
            match hash_file(&artifact.kernel.path) {
                Ok(got) => {
                    if got == artifact.kernel.hash {
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            // File missing — already recorded above; skip hash check
            Ok(true)
        };
        let rootfs_hash_ok = if rootfs_exists {
            match hash_file(&artifact.rootfs.path) {
                Ok(got) => {
                    if got == artifact.rootfs.hash {
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(true)
        };

        let (hash_ok, hash_detail) = match (kernel_hash_ok, rootfs_hash_ok) {
            (Ok(k), Ok(r)) => {
                let ok = k && r;
                let detail = if ok {
                    String::new()
                } else {
                    let mut parts = Vec::new();
                    if !k {
                        parts.push(format!(
                            "kernel hash mismatch (expected {})",
                            artifact.kernel.hash
                        ));
                    }
                    if !r {
                        parts.push(format!(
                            "rootfs hash mismatch (expected {})",
                            artifact.rootfs.hash
                        ));
                    }
                    parts.join("; ")
                };
                (ok, detail)
            }
            (Err(e), _) | (_, Err(e)) => {
                // I/O error computing a hash — record as a failed check rather
                // than propagating; the file was present (check 1 passed for it)
                // so this is most likely a permission or corruption issue.
                (false, format!("hash I/O error: {e}"))
            }
        };
        checks.push(ValidationCheck {
            name: "hash_match".to_string(),
            ok: hash_ok,
            detail: hash_detail,
        });

        // ── check 3: backend supports the arch ───────────────────────────────
        let bc = compat(artifact.backend);
        let arch_ok = bc.guest_arches.contains(&artifact.arch);
        checks.push(ValidationCheck {
            name: "arch_supported".to_string(),
            ok: arch_ok,
            detail: if arch_ok {
                String::new()
            } else {
                format!(
                    "backend {:?} does not support arch {:?}; supported: {:?}",
                    artifact.backend, artifact.arch, bc.guest_arches
                )
            },
        });

        // ── check 4: kernel format accepted for (backend, arch) ──────────────
        let kfmt_ok = kernel_format_ok(bc, artifact.arch, artifact.kernel.format);
        checks.push(ValidationCheck {
            name: "kernel_format".to_string(),
            ok: kfmt_ok,
            detail: if kfmt_ok {
                String::new()
            } else {
                // Collect expected formats for this arch from the compat table
                let expected: Vec<_> = bc
                    .kernel_formats
                    .iter()
                    .filter(|(a, _)| *a == artifact.arch)
                    .flat_map(|(_, fmts)| fmts.iter().copied())
                    .collect();
                format!(
                    "kernel format {:?} not accepted for {:?}/{:?}; expected one of {:?}",
                    artifact.kernel.format, artifact.backend, artifact.arch, expected
                )
            },
        });

        // ── check 5: rootfs format accepted ──────────────────────────────────
        let rfmt_ok = bc.rootfs_formats.contains(&artifact.rootfs.format);
        checks.push(ValidationCheck {
            name: "rootfs_format".to_string(),
            ok: rfmt_ok,
            detail: if rfmt_ok {
                String::new()
            } else {
                format!(
                    "rootfs format {:?} not accepted for {:?}; accepted: {:?}",
                    artifact.rootfs.format, artifact.backend, bc.rootfs_formats
                )
            },
        });

        // ── check 6: required boot args present ──────────────────────────────
        let missing_args: Vec<&str> = bc
            .required_boot_args
            .iter()
            .filter(|&&required| !artifact.boot_args.iter().any(|a| a == required))
            .copied()
            .collect();
        let args_ok = missing_args.is_empty();
        checks.push(ValidationCheck {
            name: "required_boot_args".to_string(),
            ok: args_ok,
            detail: if args_ok {
                String::new()
            } else {
                format!("missing required boot args: {:?}", missing_args)
            },
        });

        // ── check 7: rootfs carries /sbin/init ───────────────────────────────
        let (init_ok, init_detail) = if rootfs_exists {
            match check_init_present(&artifact.rootfs.path) {
                Ok(true) => (true, String::new()),
                Ok(false) => (
                    false,
                    format!(
                        "rootfs {} is missing /sbin/init",
                        artifact.rootfs.path.display()
                    ),
                ),
                Err(e) => (
                    false,
                    format!(
                        "cannot open {} as ext4: {e}",
                        artifact.rootfs.path.display()
                    ),
                ),
            }
        } else {
            // Rootfs missing — already flagged in check 1; skip.
            (true, String::new())
        };
        checks.push(ValidationCheck {
            name: "init_present".to_string(),
            ok: init_ok,
            detail: init_detail,
        });

        let ok = checks.iter().all(|c| c.ok);
        Ok(ValidationReport { ok, checks })
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Stream `path` through SHA-256 and return the lowercase hex digest.
fn hash_file(path: &std::path::Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Open the rootfs as an ext4 image and assert `/sbin/init` exists.
///
/// Returns `Ok(false)` when the image is valid ext4 but the path is absent;
/// `Err` when the image can't be loaded as ext4 at all.
fn check_init_present(rootfs: &std::path::Path) -> anyhow::Result<bool> {
    let fs =
        ext4_view::Ext4::load_from_path(rootfs).map_err(|e| anyhow::anyhow!("ext4_view: {e}"))?;
    fs.exists("/sbin/init")
        .map_err(|e| anyhow::anyhow!("ext4_view lookup: {e}"))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::artifact::{KernelArtifact, RootfsArtifact};
    use crate::compat::{MicrovmBackend, RootfsFormat};
    use mvm_core::arch::GuestArch;
    use mvm_core::kernel_format::KernelFormat;
    /// Write `content` to a temp file and return the path + its SHA-256 hex.
    fn write_temp(
        dir: &std::path::Path,
        name: &str,
        content: &[u8],
    ) -> (std::path::PathBuf, String) {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = format!("{:x}", hasher.finalize());
        (path, hash)
    }

    /// Minimal valid `MicrovmArtifact` for `(Firecracker, X86_64, Elf, Ext4)`.
    ///
    /// The kernel and rootfs files are tiny stubs; this test validates checks
    /// 1–6 (file existence, hashes, arch, kernel format, rootfs format, boot
    /// args). Check 7 (init presence) is skipped here — the stub file is not
    /// a valid ext4, so we verify that a non-ext4 rootfs causes the init check
    /// to fail with an appropriate detail message rather than validating ok.
    fn stub_artifact(
        dir: &std::path::Path,
        kernel_content: &[u8],
        rootfs_content: &[u8],
        kernel_format: KernelFormat,
    ) -> MicrovmArtifact {
        let (kernel_path, kernel_hash) = write_temp(dir, "vmlinux", kernel_content);
        let (rootfs_path, rootfs_hash) = write_temp(dir, "rootfs.ext4", rootfs_content);

        MicrovmArtifact {
            id: "test-artifact-id".to_string(),
            arch: GuestArch::X86_64,
            backend: MicrovmBackend::Firecracker,
            kernel: KernelArtifact {
                path: kernel_path,
                format: kernel_format,
                hash: kernel_hash,
                version: None,
            },
            rootfs: RootfsArtifact {
                path: rootfs_path,
                format: RootfsFormat::Ext4,
                hash: rootfs_hash,
                size_bytes: rootfs_content.len() as u64,
            },
            // Firecracker's required_boot_args: ["console=ttyS0", "reboot=k", "panic=1"]
            boot_args: vec![
                "console=ttyS0".to_string(),
                "reboot=k".to_string(),
                "panic=1".to_string(),
            ],
            config_path: None,
        }
    }

    /// A non-ext4 rootfs (all zeros) causes the init check to fail with a
    /// "cannot open as ext4" message — not a silent false-negative.
    #[test]
    fn non_ext4_rootfs_fails_init_check_with_detail() {
        let tmp = tempfile::tempdir().unwrap();
        // Elf + correct hashes — checks 1-6 pass; check 7 fails on the stub rootfs.
        let artifact = stub_artifact(
            tmp.path(),
            b"ELF\x7f stub kernel",
            &[0u8; 4096],
            KernelFormat::Elf,
        );
        let report = StaticValidator.validate(&artifact).unwrap();
        // Checks 1-6 should all pass.
        for c in &report.checks[..6] {
            assert!(c.ok, "check {:?} failed unexpectedly: {}", c.name, c.detail);
        }
        // Check 7 (init_present) must fail because the rootfs isn't valid ext4.
        let init_check = &report.checks[6];
        assert_eq!(init_check.name, "init_present");
        assert!(
            !init_check.ok,
            "expected init check to fail on non-ext4 rootfs"
        );
        assert!(
            init_check.detail.contains("ext4"),
            "detail must mention ext4: {}",
            init_check.detail
        );
        assert!(!report.ok);
    }

    /// Mismatched kernel format for `(Firecracker, X86_64)`: supplying
    /// `KernelFormat::Image` (only accepted on aarch64) produces a failed check
    /// #4 with a message that names the expected set.
    #[test]
    fn wrong_kernel_format_produces_failed_check_with_expected_set() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = stub_artifact(
            tmp.path(),
            b"arm64 Image stub",
            &[0u8; 4096],
            KernelFormat::Image,
        );
        let report = StaticValidator.validate(&artifact).unwrap();
        assert!(!report.ok);
        let kfmt_check = report
            .checks
            .iter()
            .find(|c| c.name == "kernel_format")
            .unwrap();
        assert!(!kfmt_check.ok);
        // Detail must name the got format and the expected set.
        assert!(
            kfmt_check.detail.contains("Image"),
            "detail must mention the rejected format: {}",
            kfmt_check.detail
        );
        assert!(
            kfmt_check.detail.contains("Elf"),
            "detail must mention the expected format (Elf for x86_64): {}",
            kfmt_check.detail
        );
    }

    /// Missing files are reported as check #1 failure, not an `Err`.
    #[test]
    fn missing_files_fail_check_not_err() {
        let artifact = MicrovmArtifact {
            id: "no-files".to_string(),
            arch: GuestArch::X86_64,
            backend: MicrovmBackend::Firecracker,
            kernel: KernelArtifact {
                path: std::path::PathBuf::from("/nonexistent/vmlinux"),
                format: KernelFormat::Elf,
                hash: "aabbcc".to_string(),
                version: None,
            },
            rootfs: RootfsArtifact {
                path: std::path::PathBuf::from("/nonexistent/rootfs.ext4"),
                format: RootfsFormat::Ext4,
                hash: "ddeeff".to_string(),
                size_bytes: 0,
            },
            boot_args: vec![
                "console=ttyS0".to_string(),
                "reboot=k".to_string(),
                "panic=1".to_string(),
            ],
            config_path: None,
        };
        let report = StaticValidator.validate(&artifact).unwrap();
        assert!(!report.ok);
        let files_check = report
            .checks
            .iter()
            .find(|c| c.name == "files_exist")
            .unwrap();
        assert!(!files_check.ok);
        assert!(files_check.detail.contains("nonexistent"));
    }

    /// Hash mismatch is a failed check, not an `Err`.
    #[test]
    fn hash_mismatch_fails_check_not_err() {
        let tmp = tempfile::tempdir().unwrap();
        let (kernel_path, _) = write_temp(tmp.path(), "vmlinux", b"real kernel bytes");
        let (rootfs_path, _) = write_temp(tmp.path(), "rootfs.ext4", b"real rootfs bytes");
        let artifact = MicrovmArtifact {
            id: "hash-mismatch".to_string(),
            arch: GuestArch::X86_64,
            backend: MicrovmBackend::Firecracker,
            kernel: KernelArtifact {
                path: kernel_path,
                format: KernelFormat::Elf,
                hash: "wrong_hash_kernel".to_string(),
                version: None,
            },
            rootfs: RootfsArtifact {
                path: rootfs_path,
                format: RootfsFormat::Ext4,
                hash: "wrong_hash_rootfs".to_string(),
                size_bytes: 0,
            },
            boot_args: vec![
                "console=ttyS0".to_string(),
                "reboot=k".to_string(),
                "panic=1".to_string(),
            ],
            config_path: None,
        };
        let report = StaticValidator.validate(&artifact).unwrap();
        assert!(!report.ok);
        let hash_check = report
            .checks
            .iter()
            .find(|c| c.name == "hash_match")
            .unwrap();
        assert!(!hash_check.ok);
    }

    /// Missing required boot args are reported in check #6.
    #[test]
    fn missing_required_boot_args_fails_check() {
        let tmp = tempfile::tempdir().unwrap();
        let (kernel_path, kernel_hash) = write_temp(tmp.path(), "vmlinux", b"elf stub");
        let (rootfs_path, rootfs_hash) = write_temp(tmp.path(), "rootfs.ext4", b"ext4 stub");
        let artifact = MicrovmArtifact {
            id: "missing-args".to_string(),
            arch: GuestArch::X86_64,
            backend: MicrovmBackend::Firecracker,
            kernel: KernelArtifact {
                path: kernel_path,
                format: KernelFormat::Elf,
                hash: kernel_hash,
                version: None,
            },
            rootfs: RootfsArtifact {
                path: rootfs_path,
                format: RootfsFormat::Ext4,
                hash: rootfs_hash,
                size_bytes: 0,
            },
            // Missing "reboot=k" and "panic=1"
            boot_args: vec!["console=ttyS0".to_string()],
            config_path: None,
        };
        let report = StaticValidator.validate(&artifact).unwrap();
        assert!(!report.ok);
        let args_check = report
            .checks
            .iter()
            .find(|c| c.name == "required_boot_args")
            .unwrap();
        assert!(!args_check.ok);
        assert!(args_check.detail.contains("reboot=k"));
        assert!(args_check.detail.contains("panic=1"));
    }

    /// Build a tiny real ext4 from `staged_dir` at `image`, returning
    /// `false` if `mke2fs` isn't installed (skip rather than fail).
    #[cfg(target_os = "linux")]
    fn mke2fs_from_dir(staged_dir: &std::path::Path, image: &std::path::Path) -> bool {
        {
            let f = std::fs::File::create(image).expect("create image file");
            f.set_len(16 * 1024 * 1024).expect("preallocate image");
        }
        match std::process::Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-b", "4096", "-d"])
            .arg(staged_dir)
            .arg(image)
            .output()
        {
            Ok(out) if out.status.success() => true,
            Ok(out) => panic!("mke2fs failed: {}", String::from_utf8_lossy(&out.stderr)),
            Err(_) => false, // e2fsprogs absent on this host — skip.
        }
    }

    /// Real ext4 with `/sbin/init` passes check 7; without it, fails.
    #[cfg(target_os = "linux")]
    #[test]
    fn init_check_passes_with_real_ext4() {
        let tmp = tempfile::tempdir().unwrap();

        // Build rootfs with /sbin/init
        let with_dir = tmp.path().join("with");
        let sbin = with_dir.join("sbin");
        std::fs::create_dir_all(&sbin).unwrap();
        std::fs::write(sbin.join("init"), b"#!/bin/sh\nexec /bin/sh\n").unwrap();
        let with_img = tmp.path().join("with.ext4");
        if !mke2fs_from_dir(&with_dir, &with_img) {
            eprintln!("skipping: mke2fs not installed");
            return;
        }

        // Build rootfs WITHOUT /sbin/init
        let without_dir = tmp.path().join("without");
        let other_sbin = without_dir.join("sbin");
        std::fs::create_dir_all(&other_sbin).unwrap();
        std::fs::write(other_sbin.join("other-binary"), b"stub").unwrap();
        let without_img = tmp.path().join("without.ext4");
        assert!(mke2fs_from_dir(&without_dir, &without_img));

        // Kernel stub
        let (kernel_path, kernel_hash) = write_temp(tmp.path(), "vmlinux", b"elf kernel stub");

        let make_artifact = |rootfs: std::path::PathBuf| {
            let rootfs_hash = {
                let content = std::fs::read(&rootfs).unwrap();
                let mut h = Sha256::new();
                h.update(&content);
                format!("{:x}", h.finalize())
            };
            let size = std::fs::metadata(&rootfs).unwrap().len();
            MicrovmArtifact {
                id: "linux-ext4-test".to_string(),
                arch: GuestArch::X86_64,
                backend: MicrovmBackend::Firecracker,
                kernel: KernelArtifact {
                    path: kernel_path.clone(),
                    format: KernelFormat::Elf,
                    hash: kernel_hash.clone(),
                    version: None,
                },
                rootfs: RootfsArtifact {
                    path: rootfs,
                    format: RootfsFormat::Ext4,
                    hash: rootfs_hash,
                    size_bytes: size,
                },
                boot_args: vec![
                    "console=ttyS0".to_string(),
                    "reboot=k".to_string(),
                    "panic=1".to_string(),
                ],
                config_path: None,
            }
        };

        // With /sbin/init — only init check should pass; other checks pass too
        let report_with = StaticValidator.validate(&make_artifact(with_img)).unwrap();
        let init_check = report_with
            .checks
            .iter()
            .find(|c| c.name == "init_present")
            .unwrap();
        assert!(
            init_check.ok,
            "ext4 with /sbin/init must pass init check: {}",
            init_check.detail
        );

        // Without /sbin/init — init check must fail
        let report_without = StaticValidator
            .validate(&make_artifact(without_img))
            .unwrap();
        let init_check_fail = report_without
            .checks
            .iter()
            .find(|c| c.name == "init_present")
            .unwrap();
        assert!(
            !init_check_fail.ok,
            "ext4 without /sbin/init must fail init check"
        );
        assert!(
            init_check_fail.detail.contains("missing /sbin/init"),
            "detail must name the missing path: {}",
            init_check_fail.detail
        );
    }
}
