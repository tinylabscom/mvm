//! `NixMicrovmBuilder` — bridges `MicrovmBuildSpec` into a `BuilderVm` call.
//!
//! ## Flow
//!
//! 1. Translate `MicrovmBuildSpec` → `BuilderJob::Flake { flake_ref, attr_path }`.
//!    The `attr_path` is derived from `spec.arch.nix_system()` (e.g.
//!    `packages.aarch64-linux.default`).
//! 2. Call the injected `BuilderVm::run_build` with `BuilderMounts` whose
//!    `artifact_out` is the builder's configured output directory.
//! 3. From `BuilderArtifacts::Image`: SHA-256 both files, infer `KernelFormat`
//!    from magic bytes (ELF → `Elf`, arm64 Image → `Image`), set rootfs format
//!    to `Ext4` and `read_only` from the spec.
//! 4. Assemble `MicrovmArtifact`, run `StaticValidator`, embed the report in
//!    `ArtifactManifest`, and `write_to_dir` the manifest.
//!
//! ## KernelFormat sniff (keep it small)
//!
//! - Bytes 0-3 == `\x7fELF` → `KernelFormat::Elf`.
//! - Bytes 0x202-0x205 == `HdrS` (x86 bzImage setup-header magic) →
//!   `KernelFormat::Raw`. bzImage is neither ELF nor a flat Image; classifying
//!   it `Raw` makes the validator reject it on ELF/Image direct-boot backends
//!   instead of mislabeling it `Elf` and failing at boot.
//! - Bytes 56-59 (LE u32) == `0x644D5241` ("ARMd" in memory, the arm64 Image
//!   magic) → `KernelFormat::Image`. Offset 56 is the `magic` field in the
//!   arm64 `Image` header (Linux kernel docs: Documentation/arm64/booting.rst).
//! - Extension `.gz` / `.bz2` / `.zst` → compressed variants.
//! - Fallback: `KernelFormat::Elf` with a logged note.
//!
//! We read only the first 0x208 bytes — no mmap, no full-file read.

use std::io::Read;
use std::path::{Path, PathBuf};

use mvm_core::kernel_format::KernelFormat;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use mvm_build::builder_vm::{BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm};

use crate::artifacts::artifact::{KernelArtifact, MicrovmArtifact, RootfsArtifact};
use crate::artifacts::manifest::{ArtifactManifest, ManifestKernel, ManifestRootfs, Provenance};
use crate::artifacts::spec::MicrovmBuildSpec;
use crate::artifacts::traits::ArtifactValidator;
use crate::artifacts::traits::{ArtifactError, MicrovmArtifactBuilder};
use crate::artifacts::validate::StaticValidator;
use crate::compat::RootfsFormat;

// ── builder ───────────────────────────────────────────────────────────────────

/// Builds a `MicrovmArtifact` by running a Nix flake build inside an
/// injected `BuilderVm`.
///
/// Holds a reference to the `BuilderVm` and the directory into which
/// the builder VM is told to write its outputs (`artifact_out_dir`).
/// The `flake_src` is the host path of the flake to bind-mount at `/work`.
///
/// `timestamp_unix` is caller-supplied; pass `0` in tests to keep builds
/// deterministic — do not call `SystemTime::now()` here.
pub struct NixMicrovmBuilder<'a> {
    /// Injected builder backend (libkrun / HVF / mock).
    pub builder_vm: &'a dyn BuilderVm,
    /// Host path to the flake source (bind-mounted read-only at `/work`).
    pub flake_src: PathBuf,
    /// Host path where the builder VM writes kernel + rootfs.
    pub artifact_out_dir: PathBuf,
    /// Optional host Nix store for cache reuse.
    pub host_nix_store: Option<PathBuf>,
    /// Host path to the mvm host-vm binaries dir (mounted at `/mvm-bins`).
    pub host_bin_dir: PathBuf,
    /// Unix epoch seconds for the manifest's `timestamp_unix`. Pass `0` in
    /// tests; production callers supply the real wall-clock time.
    pub timestamp_unix: u64,
}

impl MicrovmArtifactBuilder for NixMicrovmBuilder<'_> {
    fn build_microvm(&self, spec: &MicrovmBuildSpec) -> Result<MicrovmArtifact, ArtifactError> {
        // ── Step 1: translate spec → BuilderJob ──────────────────────────────
        let nix_system = spec.arch.nix_system();
        let flake_ref = match &spec.kernel.source {
            crate::artifacts::spec::KernelSource::Flake { flake_ref, .. } => flake_ref.clone(),
            _ => "git+file:///work".to_string(),
        };
        // Derive attr_path from the flake_ref's attr fragment or construct
        // a default `packages.<nix_system>.default`.
        let attr_path = match &spec.kernel.source {
            crate::artifacts::spec::KernelSource::Flake { attr, .. } if !attr.is_empty() => {
                attr.clone()
            }
            _ => format!("packages.{nix_system}.default"),
        };
        let job = BuilderJob::Flake {
            // Clone so `flake_ref` is still available for Provenance below.
            flake_ref: flake_ref.clone(),
            attr_path: attr_path.clone(),
        };

        let mounts = BuilderMounts {
            flake_src: self.flake_src.clone(),
            host_nix_store: self.host_nix_store.clone(),
            artifact_out: self.artifact_out_dir.clone(),
            host_bin_dir: self.host_bin_dir.clone(),
            // Standard flake build, not the local-mvm-workspace override path.
            staged_user_flake: None,
        };

        // ── Step 2: run build ─────────────────────────────────────────────────
        let artifacts = self
            .builder_vm
            .run_build(&job, &mounts)
            .map_err(|e| ArtifactError::Io(std::io::Error::other(e.to_string())))?;

        let (rootfs_path, kernel_path, lock_hash) = match artifacts {
            BuilderArtifacts::Image {
                rootfs_path,
                kernel_path,
                lock_hash,
                ..
            } => (rootfs_path, kernel_path, lock_hash),
            BuilderArtifacts::InstallVolume { .. } => {
                return Err(ArtifactError::Io(std::io::Error::other(
                    "BuilderVm returned InstallVolume for a Flake job; expected Image",
                )));
            }
        };

        // `kernel_path` must be present — every flake build we accept must emit
        // a kernel alongside the rootfs. A `None` here means the builder returned
        // an incomplete image; reject it rather than silently boot the rootfs as
        // a kernel, which would produce a corrupt MicrovmArtifact.
        let kernel_path: PathBuf = kernel_path.ok_or_else(|| {
            ArtifactError::Io(std::io::Error::other(
                "flake produced no kernel artifact (kernel_path is None)",
            ))
        })?;

        // ── Step 3: hash + format inference ──────────────────────────────────
        let kernel_hash = hash_file(&kernel_path)?;
        let rootfs_hash = hash_file(&rootfs_path)?;

        let kernel_format = sniff_kernel_format(&kernel_path);
        let rootfs_size_bytes = std::fs::metadata(&rootfs_path)?.len();

        // ── Step 4: assemble MicrovmArtifact ─────────────────────────────────
        let artifact_id = Uuid::new_v4();

        let compat = crate::compat::compat(spec.backend);
        // Required boot args from the compat table, plus any extras from spec.
        let boot_args: Vec<String> = compat
            .required_boot_args
            .iter()
            .map(|s| s.to_string())
            .chain(spec.extra_boot_args.iter().cloned())
            .collect();

        let artifact = MicrovmArtifact {
            id: artifact_id,
            arch: spec.arch,
            backend: spec.backend,
            kernel: KernelArtifact {
                path: kernel_path.clone(),
                format: kernel_format,
                hash: kernel_hash.clone(),
                version: None,
            },
            rootfs: RootfsArtifact {
                path: rootfs_path.clone(),
                format: RootfsFormat::Ext4,
                hash: rootfs_hash.clone(),
                size_bytes: rootfs_size_bytes,
                // Nix-built artifacts are immutable; callers that need a
                // writable rootfs (e.g. dev shells) clone the image first.
                read_only: true,
            },
            boot_args,
            config_path: None,
        };

        // ── Step 5: validate + embed ValidationReport ─────────────────────────
        let report = StaticValidator
            .validate(&artifact)
            .map_err(|e| ArtifactError::Io(std::io::Error::other(e.to_string())))?;

        // ── Step 6: write ArtifactManifest ───────────────────────────────────
        let manifest = ArtifactManifest {
            artifact_id,
            build_id: spec.build_id.clone(),
            tenant_id: spec.tenant_id.clone(),
            arch: spec.arch,
            backend: spec.backend,
            kernel: ManifestKernel {
                path: kernel_path.clone(),
                format: kernel_format,
                hash: kernel_hash,
                version: None,
            },
            rootfs: ManifestRootfs {
                path: rootfs_path.clone(),
                format: RootfsFormat::Ext4,
                hash: rootfs_hash,
                size: rootfs_size_bytes,
            },
            config_path: None,
            provenance: Some(Provenance {
                flake_ref: Some(flake_ref),
                lock_hash,
            }),
            builder_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_unix: self.timestamp_unix,
            validation: Some(report),
        };

        // Write into the artifact output dir; prefer the directory containing
        // the rootfs so kernel + rootfs + manifest.json are co-located.
        let out_dir = rootfs_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        manifest.write_to_dir(&out_dir).map_err(ArtifactError::Io)?;

        Ok(artifact)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Infer `KernelFormat` by sniffing the first 0x208 bytes of the file, then
/// falling back to the file extension.
///
/// Magic byte rules (all stable ABI, safe to rely on):
/// - `\x7f E L F` at offset 0 → `KernelFormat::Elf` (ELF vmlinux).
/// - `HdrS` at offset 0x202 → `KernelFormat::Raw` (x86 bzImage; the
///   `header` field of the real-mode setup header, doc:
///   Documentation/x86/boot.rst). We have no bzImage variant and no
///   boot-protocol code — `Raw` is the honest bucket, and the validator
///   then refuses it on the ELF/Image direct-boot backends.
/// - `0x644D5241` (LE u32) at offset 56 → `KernelFormat::Image` (arm64
///   uncompressed kernel Image; the `magic` field in the arm64 image header,
///   doc: Documentation/arm64/booting.rst §"Header").
///
/// Extension fallback (for compressed variants the builder may emit):
/// - `.gz` → `ImageGz`, `.bz2` → `ImageBz2`, `.zst` → `ImageZstd`.
///
/// Any other case → `KernelFormat::Elf` (most common; logged at debug).
fn sniff_kernel_format(path: &Path) -> KernelFormat {
    // Try compressed-extension first — the magic bytes inside a gz are gzip
    // magic, not ELF, so extension wins for those.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".gz") {
            return KernelFormat::ImageGz;
        }
        if name.ends_with(".bz2") {
            return KernelFormat::ImageBz2;
        }
        if name.ends_with(".zst") || name.ends_with(".zstd") {
            return KernelFormat::ImageZstd;
        }
    }

    // Read the head for magic sniffing. The deepest magic we check is the x86
    // bzImage setup header at offset 0x202, so read through 0x208.
    let mut header = [0u8; 0x208];
    let n = match std::fs::File::open(path) {
        Ok(mut f) => f.read(&mut header).unwrap_or(0),
        Err(_) => return KernelFormat::Elf, // fallback; validator will catch missing file
    };

    if n >= 4 && header[..4] == [0x7f, b'E', b'L', b'F'] {
        return KernelFormat::Elf;
    }

    // x86 bzImage: setup-header magic "HdrS" (0x53726448 LE) at offset 0x202
    // (Documentation/x86/boot.rst, `header` field). A bzImage is neither ELF
    // nor a flat Image; classify it Raw so the validator rejects it loudly on
    // ELF/Image direct-boot backends (Firecracker, libkrun) instead of the old
    // behaviour of silently calling it Elf and panicking at boot.
    if n >= 0x206 && &header[0x202..0x206] == b"HdrS" {
        return KernelFormat::Raw;
    }

    // arm64 Image magic is at offset 56 (bytes 56-59), little-endian u32 == 0x644D5241.
    // This field was added in Linux 3.17; all kernels we'd ship carry it.
    if n >= 60 {
        let magic = u32::from_le_bytes(header[56..60].try_into().unwrap());
        if magic == 0x644D_5241 {
            return KernelFormat::Image;
        }
    }

    // Fallback — most Nix-built kernels that reach this path are ELF vmlinux.
    KernelFormat::Elf
}

/// Stream `path` through SHA-256 and return the lowercase hex digest.
fn hash_file(path: &Path) -> Result<String, ArtifactError> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).map_err(ArtifactError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::manifest::ArtifactManifest;
    use crate::artifacts::spec::{
        KernelSource, KernelSpec, MicrovmBuildSpec, RootfsSource, RootfsSpec,
    };
    use crate::compat::{MicrovmBackend, RootfsFormat};
    use mvm_build::builder_vm::{BuilderJob as BJ, BuilderMounts as BM, BuilderVmError};
    use mvm_core::arch::GuestArch;
    use mvm_core::kernel_format::KernelFormat;
    use sha2::{Digest, Sha256};

    // ── local mock BuilderVm ──────────────────────────────────────────────────
    //
    // `StubBuilderVm` always returns `NotYetImplemented`; we need a scripted
    // mock that returns a real `BuilderArtifacts::Image` pointing at temp
    // files we create in the test. Keep it local — no need for a workspace
    // fixture yet.

    struct ScriptedBuilderVm {
        rootfs_path: PathBuf,
        kernel_path: Option<PathBuf>,
        revision_hash: String,
        lock_hash: Option<String>,
    }

    impl mvm_build::builder_vm::BuilderVm for ScriptedBuilderVm {
        fn run_stage0(
            &self,
            _guest_root_dir: &std::path::Path,
            _entry_path: &str,
            _workspace_dir: &std::path::Path,
            _artifact_out: &std::path::Path,
            _host_bin_dir: &std::path::Path,
        ) -> Result<(), mvm_build::builder_vm::BuilderVmError> {
            Err(mvm_build::builder_vm::BuilderVmError::NotYetImplemented)
        }

        fn capabilities(&self) -> mvm_build::builder_vm::BuilderCapabilities {
            mvm_build::builder_vm::BuilderCapabilities::default()
        }

        fn run_build(&self, _job: &BJ, _mounts: &BM) -> Result<BuilderArtifacts, BuilderVmError> {
            Ok(BuilderArtifacts::Image {
                rootfs_path: self.rootfs_path.clone(),
                kernel_path: self.kernel_path.clone(),
                revision_hash: self.revision_hash.clone(),
                lock_hash: self.lock_hash.clone(),
                accessible: Some(true),
            })
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Write `content` to `dir/name` and return (path, sha256-hex).
    fn write_file(dir: &Path, name: &str, content: &[u8]) -> (PathBuf, String) {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        let mut h = Sha256::new();
        h.update(content);
        (p, hex::encode(h.finalize()))
    }

    // Minimal ELF magic header (first 4 bytes only matter for sniff).
    const ELF_STUB: &[u8] = &[0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
    // arm64 Image stub: offset 56-59 = 0x644D5241 (LE), rest zero.
    fn arm64_image_stub() -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[56..60].copy_from_slice(&0x644D_5241u32.to_le_bytes());
        v
    }
    // x86 bzImage stub: "MZ" at offset 0 (EFI-stub kernels) + the setup-header
    // magic "HdrS" at offset 0x202, which is what we actually key on.
    fn bzimage_stub() -> Vec<u8> {
        let mut v = vec![0u8; 0x208];
        v[0..2].copy_from_slice(b"MZ");
        v[0x202..0x206].copy_from_slice(b"HdrS");
        v
    }

    /// A minimal `MicrovmBuildSpec` targeting `(Firecracker, X86_64)`.
    fn fc_x86_spec(flake_ref: &str, attr: &str) -> MicrovmBuildSpec {
        MicrovmBuildSpec {
            arch: GuestArch::X86_64,
            backend: MicrovmBackend::Firecracker,
            kernel: KernelSpec {
                arch: GuestArch::X86_64,
                format: KernelFormat::Elf,
                source: KernelSource::Flake {
                    flake_ref: flake_ref.to_string(),
                    attr: attr.to_string(),
                },
                min_version: None,
            },
            rootfs: RootfsSpec {
                arch: GuestArch::X86_64,
                format: RootfsFormat::Ext4,
                source: RootfsSource::Flake {
                    flake_ref: flake_ref.to_string(),
                    attr: attr.to_string(),
                },
                init_path: None,
            },
            extra_boot_args: vec![],
            build_id: "test-build-001".to_string(),
            tenant_id: Some("test-tenant".to_string()),
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    /// Core mapping test: mock returns `BuilderArtifacts::Image` with an ELF
    /// kernel stub; assert the resulting `MicrovmArtifact` has the right
    /// arch/backend/format and that a `manifest.json` is written next to the
    /// rootfs. Does NOT assert `report.ok` — the stub rootfs won't pass ext4
    /// init-check on non-Linux; we assert the MAPPING, not validation pass.
    #[test]
    fn build_microvm_maps_image_to_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let (kernel_path, kernel_hash) = write_file(tmp.path(), "vmlinux", ELF_STUB);
        let (rootfs_path, rootfs_hash) = write_file(tmp.path(), "rootfs.ext4", &[0u8; 64]);

        let mock_vm = ScriptedBuilderVm {
            rootfs_path: rootfs_path.clone(),
            kernel_path: Some(kernel_path.clone()),
            revision_hash: "abc123".to_string(),
            lock_hash: Some("sha256-lock".to_string()),
        };

        let builder = NixMicrovmBuilder {
            builder_vm: &mock_vm,
            flake_src: tmp.path().to_path_buf(),
            artifact_out_dir: tmp.path().to_path_buf(),
            host_nix_store: None,
            host_bin_dir: tmp.path().to_path_buf(),
            timestamp_unix: 0,
        };

        let spec = fc_x86_spec("git+file:///work", "packages.x86_64-linux.default");
        let artifact = builder.build_microvm(&spec).unwrap();

        // Arch + backend
        assert_eq!(artifact.arch, GuestArch::X86_64);
        assert_eq!(artifact.backend, MicrovmBackend::Firecracker);

        // Kernel format sniffed from ELF magic
        assert_eq!(artifact.kernel.format, KernelFormat::Elf);

        // Hashes match the files we wrote
        assert_eq!(artifact.kernel.hash, kernel_hash);
        assert_eq!(artifact.rootfs.hash, rootfs_hash);

        // Rootfs format is always Ext4 from the Nix path
        assert_eq!(artifact.rootfs.format, RootfsFormat::Ext4);
        assert_eq!(artifact.rootfs.size_bytes, 64);

        // Firecracker required boot args are present
        let required = crate::compat::compat(MicrovmBackend::Firecracker).required_boot_args;
        for arg in required {
            assert!(
                artifact.boot_args.iter().any(|a| a == arg),
                "boot_args must contain {arg}"
            );
        }

        // manifest.json written next to the rootfs
        let manifest_path = rootfs_path.parent().unwrap().join("manifest.json");
        assert!(manifest_path.exists(), "manifest.json must be written");

        // Manifest is parseable and carries the right artifact_id
        let manifest = ArtifactManifest::read_from_dir(rootfs_path.parent().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(manifest.artifact_id, artifact.id);
        assert_eq!(manifest.arch, GuestArch::X86_64);
        assert_eq!(manifest.backend, MicrovmBackend::Firecracker);
        assert_eq!(manifest.build_id, "test-build-001");
        assert_eq!(manifest.timestamp_unix, 0);

        // ValidationReport is embedded in the manifest
        assert!(
            manifest.validation.is_some(),
            "manifest must carry a ValidationReport"
        );

        // Provenance.flake_ref must be the actual flake reference from the spec,
        // not the attr_path (regression check for the Fix-1 bug).
        let provenance = manifest.provenance.expect("manifest must have provenance");
        assert_eq!(
            provenance.flake_ref.as_deref(),
            Some("git+file:///work"),
            "flake_ref must record the flake ref, not the attr_path"
        );
    }

    /// arm64 Image magic sniff: a file with the arm64 magic at offset 56
    /// is recognized as `KernelFormat::Image`.
    #[test]
    fn kernel_format_sniff_arm64_image() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = arm64_image_stub();
        let (path, _) = write_file(tmp.path(), "Image", &stub);
        assert_eq!(sniff_kernel_format(&path), KernelFormat::Image);
    }

    /// x86 bzImage sniff: a file carrying the "HdrS" setup-header magic at
    /// offset 0x202 is classified `Raw`, NOT `Elf`. This is the regression
    /// guard for the old fall-through that silently mislabeled a bzImage as
    /// ELF — `Raw` is then refused by the validator on Firecracker/libkrun.
    #[test]
    fn kernel_format_sniff_bzimage_is_raw_not_elf() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _) = write_file(tmp.path(), "bzImage", &bzimage_stub());
        let fmt = sniff_kernel_format(&path);
        assert_eq!(fmt, KernelFormat::Raw, "bzImage must sniff as Raw");
        assert_ne!(fmt, KernelFormat::Elf, "bzImage must not be mislabeled Elf");
    }

    /// ELF magic sniff.
    #[test]
    fn kernel_format_sniff_elf() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _) = write_file(tmp.path(), "vmlinux", ELF_STUB);
        assert_eq!(sniff_kernel_format(&path), KernelFormat::Elf);
    }

    /// Extension sniff for compressed variants.
    #[test]
    fn kernel_format_sniff_compressed_by_extension() {
        let tmp = tempfile::tempdir().unwrap();
        // .gz → ImageGz (gzip header, not ELF, so extension wins)
        let (gz, _) = write_file(tmp.path(), "vmlinuz.gz", &[0x1f, 0x8b, 0, 0]);
        assert_eq!(sniff_kernel_format(&gz), KernelFormat::ImageGz);

        let (bz2, _) = write_file(tmp.path(), "vmlinuz.bz2", &[b'B', b'Z', b'h', 0]);
        assert_eq!(sniff_kernel_format(&bz2), KernelFormat::ImageBz2);

        let (zst, _) = write_file(tmp.path(), "vmlinuz.zst", &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(sniff_kernel_format(&zst), KernelFormat::ImageZstd);
    }

    /// When no kernel is returned by the builder, `build_microvm` must return
    /// `Err` — silently booting the rootfs as the kernel would produce a
    /// corrupt artifact.
    #[test]
    fn build_microvm_errors_when_no_kernel_path() {
        let tmp = tempfile::tempdir().unwrap();
        let (rootfs_path, _) = write_file(tmp.path(), "rootfs.ext4", &[0u8; 32]);

        let mock_vm = ScriptedBuilderVm {
            rootfs_path: rootfs_path.clone(),
            kernel_path: None, // builder emits no kernel
            revision_hash: "nk123".to_string(),
            lock_hash: None,
        };

        let builder = NixMicrovmBuilder {
            builder_vm: &mock_vm,
            flake_src: tmp.path().to_path_buf(),
            artifact_out_dir: tmp.path().to_path_buf(),
            host_nix_store: None,
            host_bin_dir: tmp.path().to_path_buf(),
            timestamp_unix: 1_748_000_000,
        };

        let spec = fc_x86_spec("git+file:///work", "packages.x86_64-linux.default");
        let result = builder.build_microvm(&spec);
        assert!(
            result.is_err(),
            "missing kernel must be an error, not a silent fallback"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("kernel_path is None"),
            "error message must mention kernel_path is None, got: {err_msg}"
        );
    }

    /// `id` is a UUID v4 (non-nil, non-max).
    #[test]
    fn build_microvm_id_is_uuid_v4() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = write_file(tmp.path(), "vmlinux", ELF_STUB);
        let (rootfs_path, _) = write_file(tmp.path(), "rootfs.ext4", &[0u8; 32]);

        let mock_vm = ScriptedBuilderVm {
            rootfs_path,
            kernel_path: Some(tmp.path().join("vmlinux")),
            revision_hash: "r".to_string(),
            lock_hash: None,
        };
        let builder = NixMicrovmBuilder {
            builder_vm: &mock_vm,
            flake_src: tmp.path().to_path_buf(),
            artifact_out_dir: tmp.path().to_path_buf(),
            host_nix_store: None,
            host_bin_dir: tmp.path().to_path_buf(),
            timestamp_unix: 0,
        };
        let spec = fc_x86_spec(".", "packages.x86_64-linux.default");
        let a = builder.build_microvm(&spec).unwrap();
        assert_ne!(a.id, Uuid::nil(), "id must not be nil");
        assert_ne!(a.id, Uuid::max(), "id must not be max");
    }
}
