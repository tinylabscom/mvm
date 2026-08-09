//! Static backend capability matrix.
//!
//! `compat(backend)` returns the `BackendCompat` row for that backend.
//! Phase-C artifact validation and config writers consume this table; adding
//! a new backend is a new `static` row + a `match` arm in `compat()`.
//!
//! ## Sources used for each row
//!
//! - **Firecracker**: FC API docs + `crates/mvm-runtime/src/backend.rs` cmdline.
//! - **Libkrun**: `crates/mvm-libkrun/src/sys.rs` FFI mapping;
//!   `crates/mvm-runtime/src/libkrun.rs` `DEFAULT_CMDLINE`; macOS-only so
//!   `console=hvc0`; no jailer or snapshots (host process == supervisor).
//! - **Qemu**: the dev/test backend in `crates/mvm-runtime/src/qemu.rs` uses
//!   QEMU's unprivileged user-mode virtio network (`-netdev user`), not a host
//!   TAP device. It provides transparent guest TCP/UDP for the dev tier; it
//!   is not part of the production claim boundary.
//!
//! `MicrovmBackend` has no `Hvf` variant yet (a removed backend's row
//! was deleted rather than repurposed); the raw HVF backend
//! (`crates/mvm-runtime/src/hvf_backend.rs`) does not go through this table.

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};

// ── enums ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrovmBackend {
    Firecracker,
    Libkrun,
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
    NativeGateway,
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

// Firecracker: source — FC API docs + crates/mvm-runtime/src/backend.rs.
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
// crates/mvm-runtime/src/libkrun.rs DEFAULT_CMDLINE.
// Both arches; libkrun bundles its own kernel so ELF/ImageGz/ImageBz2/ImageZstd/PeGz
// work (each maps to a KRUN_KERNEL_FORMAT_* FFI constant in to_krun_format()).
// Raw also has a constant but is undocumented for the builder path and intentionally
// excluded here. Uncompressed Image and Pe have no KRUN_KERNEL_FORMAT constant
// (to_krun_format returns Err for both) — excluded. Only the bundled kernel is
// used today, but the full accepted-format list reflects the actual FFI surface.
// Current libkrun launches are NIC-less and route egress over vsock.
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
    networking: NetworkingModel::None,
};

// QEMU is the Linux dev/test substrate. Its user-mode virtio network gives the
// guest an ordinary NIC without requiring a host TAP, bridge, or firewall
// setup. It remains outside the production egress claim boundary.
static QEMU: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Qemu,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[(X86_64, &[K::Elf, K::Raw]), (Aarch64, &[K::Image, K::Elf])],
    rootfs_formats: &[R::Ext4, R::Raw],
    required_boot_args: &["console=ttyS0"],
    supports_snapshots: false,
    supports_jailer: false,
    networking: NetworkingModel::UserModeVirtio,
};

// ── lookup ────────────────────────────────────────────────────────────────────

pub fn compat(b: MicrovmBackend) -> &'static BackendCompat {
    match b {
        MicrovmBackend::Firecracker => &FIRECRACKER,
        MicrovmBackend::Libkrun => &LIBKRUN,
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
    fn firecracker_supports_jailer_others_do_not() {
        assert!(compat(MicrovmBackend::Firecracker).supports_jailer);
        for b in [MicrovmBackend::Libkrun, MicrovmBackend::Qemu] {
            assert!(!compat(b).supports_jailer, "{b:?} should not have jailer");
        }
    }

    #[test]
    fn qemu_uses_rootless_user_mode_virtio_networking() {
        let c = compat(MicrovmBackend::Qemu);
        assert_eq!(c.networking, NetworkingModel::UserModeVirtio);
        assert!(!c.supports_snapshots);
        assert!(!c.supports_jailer);
    }

    #[test]
    fn serde_roundtrips() {
        // Spot-check that the enums round-trip through JSON as snake_case.
        let b = MicrovmBackend::Qemu;
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(j, "\"qemu\"");
        assert_eq!(serde_json::from_str::<MicrovmBackend>(&j).unwrap(), b);

        let r = RootfsFormat::InitramfsCpioGz;
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "\"initramfs_cpio_gz\"");

        let n = NetworkingModel::UserModeVirtio;
        let j = serde_json::to_string(&n).unwrap();
        assert_eq!(j, "\"user_mode_virtio\"");
    }
}
