//! Static backend capability matrix.
//!
//! `compat(backend)` returns the `BackendCompat` row for that backend.
//! Phase-C artifact validation and config writers consume this table; adding
//! a new backend is a new `static` row + a `match` arm in `compat()`.
//!
//! ## Sources used for each row
//!
//! - **Firecracker**: FC API docs + `crates/mvm-backend/src/backend.rs` cmdline.
//! - **Libkrun**: `crates/mvm-libkrun/src/sys.rs` FFI mapping;
//!   `crates/mvm-backend/src/libkrun.rs` `DEFAULT_CMDLINE`; macOS-only so
//!   `console=hvc0`; no jailer or snapshots (host process == supervisor).
//! - **HVF**: `crates/mvm-backend/src/hvf_backend.rs` capabilities; macOS-only,
//!   aarch64-only in practice (Apple Silicon + Hypervisor.framework),
//!   vsock-only egress (no guest NIC), no pause/snapshot today.
//! - **Qemu**: no implementation yet; capabilities are conventional QEMU
//!   defaults for the mvm workload shape (ELF/Image per arch, ext4 rootfs,
//!   TAP networking, snapshots, no jailer). Flagged with `// assumption`.

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};

// ── enums ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrovmBackend {
    Firecracker,
    Libkrun,
    Hvf,
    Qemu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsFormat {
    Ext4,
    InitramfsCpioGz,
    Squashfs,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkingModel {
    Tap,
    Gvproxy,
    Passt,
    UserModeVirtio,
    None,
}

// ── capability struct ─────────────────────────────────────────────────────────

pub struct BackendCompat {
    pub backend: MicrovmBackend,
    /// Guest CPU architectures this backend can boot.
    pub guest_arches: &'static [GuestArch],
    /// Per-arch accepted kernel formats. An arch absent from this slice is
    /// not supported regardless of format.
    pub kernel_formats: &'static [(GuestArch, &'static [KernelFormat])],
    pub rootfs_formats: &'static [RootfsFormat],
    /// Kernel cmdline tokens the backend requires (must appear in every
    /// boot_args string; checked by `ArtifactValidator`).
    pub required_boot_args: &'static [&'static str],
    pub supports_snapshots: bool,
    /// Whether the backend supports running under a jailer/seccomp sandbox.
    /// True only for Firecracker (the jailer path).
    pub supports_jailer: bool,
    pub networking: NetworkingModel,
}

// ── helper ────────────────────────────────────────────────────────────────────

/// Is `fmt` an accepted kernel format for `arch` on this backend?
pub fn kernel_format_ok(c: &BackendCompat, arch: GuestArch, fmt: KernelFormat) -> bool {
    c.kernel_formats
        .iter()
        .find(|(a, _)| *a == arch)
        .map(|(_, fmts)| fmts.contains(&fmt))
        .unwrap_or(false)
}

// ── local type aliases (keep the static rows readable) ───────────────────────

use GuestArch::{Aarch64, X86_64};
use KernelFormat as K;
use RootfsFormat as R;

// ── static rows ──────────────────────────────────────────────────────────────

// Firecracker: source — FC API docs + crates/mvm-backend/src/backend.rs.
// x86_64 boots ELF vmlinux; aarch64 boots uncompressed arm64 Image.
// ext4 rootfs + initramfs-cpio-gz initrd. Jailer available. TAP networking.
static FIRECRACKER: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Firecracker,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[(X86_64, &[K::Elf]), (Aarch64, &[K::Image])],
    rootfs_formats: &[R::Ext4, R::InitramfsCpioGz],
    required_boot_args: &["console=ttyS0", "reboot=k", "panic=1"],
    supports_snapshots: true,
    supports_jailer: true,
    networking: NetworkingModel::Tap,
};

// Libkrun: source — crates/mvm-libkrun/src/sys.rs to_krun_format() +
// crates/mvm-backend/src/libkrun.rs DEFAULT_CMDLINE.
// Both arches; libkrun bundles its own kernel so ELF/ImageGz/ImageBz2/ImageZstd/PeGz
// work (each maps to a KRUN_KERNEL_FORMAT_* FFI constant in to_krun_format()).
// Raw also has a constant but is undocumented for the builder path and intentionally
// excluded here. Uncompressed Image and Pe have no KRUN_KERNEL_FORMAT constant
// (to_krun_format returns Err for both) — excluded. Only the bundled kernel is
// used today, but the full accepted-format list reflects the actual FFI surface.
// gvproxy on macOS (CLAUDE.md host-deps); passt on Linux — model as Gvproxy
// (the macOS default) since mvm's libkrun path is primarily macOS today.
static LIBKRUN: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Libkrun,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[
        (
            X86_64,
            &[K::Elf, K::ImageGz, K::ImageBz2, K::ImageZstd, K::PeGz],
        ),
        (
            Aarch64,
            &[K::Elf, K::ImageGz, K::ImageBz2, K::ImageZstd, K::PeGz],
        ),
    ],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=hvc0"],
    supports_snapshots: false,
    supports_jailer: false,
    // macOS primary; Linux uses passt — Gvproxy is the default in CLAUDE.md.
    networking: NetworkingModel::Gvproxy,
};

// HVF VMM: source — crates/mvm-backend/src/hvf_backend.rs.
// macOS 26+ Apple Silicon only. The raw HVF VMM uses virtio-console/virtio-vsock,
// boots an uncompressed arm64 Image, and carries workload egress over a host-side
// vsock proxy with no guest NIC.
static HVF: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Hvf,
    guest_arches: &[Aarch64], // macOS on Apple Silicon only
    kernel_formats: &[
        // The hvf path boots an uncompressed arm64 Image.
        (Aarch64, &[K::Image]),
    ],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=hvc0"],
    supports_snapshots: false,
    supports_jailer: false,
    networking: NetworkingModel::None,
};

// Qemu: no implementation yet. Capabilities are conventional QEMU defaults
// for the mvm workload shape. All fields are marked // assumption below.
// x86_64: ELF vmlinux or bzImage (Raw accepted as generic blob);  // assumption
// aarch64: uncompressed arm64 Image or ELF vmlinux;               // assumption
// ext4 rootfs; TAP networking; snapshots; no jailer (FC-specific). // assumption
static QEMU: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Qemu,
    guest_arches: &[X86_64, Aarch64], // assumption: QEMU supports both
    kernel_formats: &[
        (X86_64, &[K::Elf, K::Raw]), // assumption: vmlinux ELF or bzImage (Raw)
        (Aarch64, &[K::Image, K::Elf]), // assumption: arm64 Image or vmlinux
    ],
    rootfs_formats: &[R::Ext4, R::Raw],     // assumption
    required_boot_args: &["console=ttyS0"], // assumption: ttyS0 for QEMU serial
    supports_snapshots: true,               // assumption: QEMU supports savevm/loadvm
    supports_jailer: false,                 // assumption: no FC jailer; QEMU has own isolation
    networking: NetworkingModel::Tap,       // assumption: QEMU standard TAP
};

// ── lookup ────────────────────────────────────────────────────────────────────

pub fn compat(b: MicrovmBackend) -> &'static BackendCompat {
    match b {
        MicrovmBackend::Firecracker => &FIRECRACKER,
        MicrovmBackend::Libkrun => &LIBKRUN,
        MicrovmBackend::Hvf => &HVF,
        MicrovmBackend::Qemu => &QEMU,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use GuestArch::{Aarch64, X86_64};

    #[test]
    fn firecracker_kernel_formats_are_arch_specific() {
        let c = compat(MicrovmBackend::Firecracker);
        assert!(kernel_format_ok(c, X86_64, KernelFormat::Elf));
        assert!(!kernel_format_ok(c, X86_64, KernelFormat::Image));
        assert!(kernel_format_ok(c, Aarch64, KernelFormat::Image));
        assert!(!kernel_format_ok(c, Aarch64, KernelFormat::Elf));
    }

    #[test]
    fn firecracker_rejects_unsupported_rootfs() {
        let c = compat(MicrovmBackend::Firecracker);
        assert!(c.rootfs_formats.contains(&RootfsFormat::Ext4));
        assert!(!c.rootfs_formats.contains(&RootfsFormat::Squashfs));
    }

    #[test]
    fn every_backend_has_a_row() {
        for b in [
            MicrovmBackend::Firecracker,
            MicrovmBackend::Libkrun,
            MicrovmBackend::Hvf,
            MicrovmBackend::Qemu,
        ] {
            assert_eq!(compat(b).backend, b);
        }
    }

    #[test]
    fn libkrun_accepts_compressed_image_on_both_arches() {
        let c = compat(MicrovmBackend::Libkrun);
        assert!(kernel_format_ok(c, X86_64, KernelFormat::ImageGz));
        assert!(kernel_format_ok(c, Aarch64, KernelFormat::ImageGz));
        assert!(kernel_format_ok(c, X86_64, KernelFormat::ImageZstd));
        assert!(kernel_format_ok(c, X86_64, KernelFormat::ImageBz2));
        assert!(kernel_format_ok(c, X86_64, KernelFormat::PeGz));
        // Uncompressed Image/Pe have no KRUN_KERNEL_FORMAT constant — rejected.
        assert!(!kernel_format_ok(c, X86_64, KernelFormat::Image));
        assert!(!kernel_format_ok(c, Aarch64, KernelFormat::Image));
    }

    #[test]
    fn hvf_is_aarch64_only() {
        let c = compat(MicrovmBackend::Hvf);
        assert!(c.guest_arches.contains(&Aarch64));
        assert!(!c.guest_arches.contains(&X86_64));
    }

    #[test]
    fn firecracker_supports_jailer_others_do_not() {
        assert!(compat(MicrovmBackend::Firecracker).supports_jailer);
        for b in [
            MicrovmBackend::Libkrun,
            MicrovmBackend::Hvf,
            MicrovmBackend::Qemu,
        ] {
            assert!(!compat(b).supports_jailer, "{b:?} should not have jailer");
        }
    }

    #[test]
    fn serde_roundtrips() {
        // Spot-check that the enums round-trip through JSON as snake_case.
        let b = MicrovmBackend::Hvf;
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(j, "\"hvf\"");
        assert_eq!(serde_json::from_str::<MicrovmBackend>(&j).unwrap(), b);

        let r = RootfsFormat::InitramfsCpioGz;
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "\"initramfs_cpio_gz\"");

        let n = NetworkingModel::UserModeVirtio;
        let j = serde_json::to_string(&n).unwrap();
        assert_eq!(j, "\"user_mode_virtio\"");
    }
}
