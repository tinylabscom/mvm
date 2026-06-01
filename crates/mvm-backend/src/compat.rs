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
//! - **Vz**: `crates/mvm-backend/src/vz.rs` `DEFAULT_CMDLINE` + capabilities;
//!   Plan 97 — macOS-only, aarch64-only in practice (Apple Silicon + HVF),
//!   gvproxy networking (Plan 102 W6.A.5), snapshot-capable on macOS 14+
//!   (capabilities() is host-probed; compat reports the nominal capability).
//! - **AppleContainer**: `crates/mvm-backend/src/apple_container.rs`; macOS
//!   26+ Apple Silicon only; vmnet networking; no snapshots or jailer.
//! - **CloudHypervisor**: `crates/mvm-backend/src/cloud_hypervisor.rs`;
//!   Linux/KVM + macOS/HVF, both arches; ELF / uncompressed Image kernel;
//!   snapshot-capable; TAP wiring incomplete (recorded as Tap intentionally —
//!   CH supports TAP, the impl note says it's a follow-up, so `networking`
//!   reflects what CH *can* do rather than what the start path does today).
//! - **Docker**: `crates/mvm-backend/src/docker.rs`; OCI image / tar.gz;
//!   no kernel (container runtime, not a VMM); ext4 rootfs or OCI layer set;
//!   no snapshots/jailer; networking via Docker's own NAT/bridge.
//! - **Qemu**: no implementation yet; capabilities are conventional QEMU
//!   defaults for the mvm workload shape (ELF/Image per arch, ext4 rootfs,
//!   TAP networking, snapshots, no jailer). Flagged with `// assumption`.
//! - **Vfkit**: no implementation yet; Apple Virtualization.framework thin
//!   wrapper (same tier as Vz), aarch64/macOS only, gvproxy networking.
//!   Flagged with `// assumption`.

use mvm_core::arch::GuestArch;
use mvm_core::kernel_format::KernelFormat;
use serde::{Deserialize, Serialize};

// ── enums ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrovmBackend {
    Firecracker,
    Libkrun,
    Vz,
    AppleContainer,
    CloudHypervisor,
    Docker,
    Qemu,
    Vfkit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsFormat {
    Ext4,
    InitramfsCpioGz,
    Squashfs,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// True only for Firecracker (ADR-002 W1.1 jailer path).
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
// Both arches; libkrun bundles its own kernel so ELF/ImageGz/ImageZstd work
// (the compressed variants map to KRUN_KERNEL_FORMAT_* FFI constants); Raw
// also has a constant but is undocumented for the builder path. Uncompressed
// Image and Pe have no KRUN_KERNEL_FORMAT constant — only the bundled kernel
// is actually used today (Plan 86 / CLAUDE.md builder-vm note), but accepting
// ImageGz/ImageZstd keeps the compat model honest about what the FFI supports.
// gvproxy on macOS (CLAUDE.md host-deps); passt on Linux — model as Gvproxy
// (the macOS default) since mvm's libkrun path is primarily macOS today.
static LIBKRUN: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Libkrun,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[
        (X86_64, &[K::Elf, K::ImageGz, K::ImageZstd]),
        (Aarch64, &[K::Elf, K::ImageGz, K::ImageZstd]),
    ],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=hvc0"],
    supports_snapshots: false,
    supports_jailer: false,
    // macOS primary; Linux uses passt — Gvproxy is the default in CLAUDE.md.
    networking: NetworkingModel::Gvproxy,
};

// Vz (Apple Virtualization.framework): source — crates/mvm-backend/src/vz.rs.
// macOS 13+ only; Apple Silicon = aarch64 only (HVF is ARM-only on Apple hardware).
// DEFAULT_CMDLINE uses console=hvc0 (virtio-console, matching libkrun shape).
// Accepts uncompressed arm64 Image — the Vz kernel API takes a raw Image or ELF;
// libkrun's bundled compressed variants are NOT needed here because Vz has its
// own VMM. Snapshot capable on macOS 14+ (capabilities() is host-probed;
// the static model reports true = backend supports it when OS meets requirement).
// Plan 102 W6.A.5 — gvproxy for networking.
static VZ: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Vz,
    guest_arches: &[Aarch64], // macOS on Apple Silicon only
    kernel_formats: &[
        // Vz loads an uncompressed ELF vmlinux or uncompressed arm64 Image.
        // Source: Apple VZ API `VZLinuxBootLoader.kernelURL` accepts both;
        // mvm's vz.rs KernelConfig accepts any path (no format validation
        // in the supervisor today). Elf is listed conservatively alongside
        // Image since Apple VZ can boot either on aarch64.
        (Aarch64, &[K::Elf, K::Image]),
    ],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=hvc0"],
    supports_snapshots: true, // macOS 14+; host-checked at runtime in VzBackend::capabilities()
    supports_jailer: false,
    networking: NetworkingModel::Gvproxy, // Plan 102 W6.A.5
};

// AppleContainer: source — crates/mvm-backend/src/apple_container.rs.
// macOS 26+ Apple Silicon only; aarch64 only.
// Apple Containerization.framework manages its own kernel internally (vminitd);
// the host-level start() receives a kernel_path but the framework controls
// the boot, so kernel format is opaque to mvm. Modelled as Image (arm64 Linux
// Image) since that is what mkGuest produces for Apple Container targets.
// vmnet networking (dedicated per-container; documented in module header).
// No jailer, no snapshots (capabilities() confirms both false).
static APPLE_CONTAINER: BackendCompat = BackendCompat {
    backend: MicrovmBackend::AppleContainer,
    guest_arches: &[Aarch64], // macOS 26+ Apple Silicon
    kernel_formats: &[
        // The Containerization.framework boots the guest; kernel format
        // is framework-internal. We model Image (the arm64 Linux Image
        // that mkGuest emits) as the accepted format.  // assumption
        (Aarch64, &[K::Image]),
    ],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=hvc0"],
    supports_snapshots: false,
    supports_jailer: false,
    networking: NetworkingModel::UserModeVirtio, // vmnet; closest model is UserModeVirtio
};

// CloudHypervisor: source — crates/mvm-backend/src/cloud_hypervisor.rs.
// Linux/KVM + macOS/HVF; both x86_64 and aarch64.
// DEFAULT_CMDLINE uses console=ttyS0 reboot=k panic=1 (matches FC shape).
// CH boots ELF vmlinux on x86_64; uncompressed arm64 Image on aarch64
// (CH API doc: `--kernel` accepts vmlinux ELF or arm64 Image; bzImage /
// compressed variants are not supported by CH's direct-boot path today).
// Snapshots supported (capabilities() reports true).
// Jailer: CH does not use Firecracker's jailer; it has its own seccomp
// profile but the mvm jailer path is FC-specific (ADR-002 §W1.1 targets FC).
// TAP: CH supports it; mvm start path defers TAP wiring (cloud_hypervisor.rs
// module docs), but the compat model reflects what CH *can* do.
static CLOUD_HYPERVISOR: BackendCompat = BackendCompat {
    backend: MicrovmBackend::CloudHypervisor,
    guest_arches: &[X86_64, Aarch64],
    kernel_formats: &[
        (X86_64, &[K::Elf]),    // vmlinux ELF; CH doesn't support bzImage
        (Aarch64, &[K::Image]), // uncompressed arm64 Image
    ],
    rootfs_formats: &[R::Ext4],
    required_boot_args: &["console=ttyS0", "reboot=k", "panic=1"],
    supports_snapshots: true,
    supports_jailer: false, // CH has its own seccomp; mvm jailer path targets FC only
    networking: NetworkingModel::Tap, // CH supports TAP; mvm start path wires it as follow-up
};

// Docker: source — crates/mvm-backend/src/docker.rs.
// Both arches (Docker is arch-agnostic; OCI image layer set handles the diff).
// No kernel (container runtime, not a VMM) — kernel_formats left empty.
// OCI images are loaded from image.tar.gz (streamLayeredImage); raw ext4
// import is a fallback on Linux. No jailer; no snapshots.
// Networking via Docker's own NAT/bridge (no TAP managed by mvm).
static DOCKER: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Docker,
    guest_arches: &[X86_64, Aarch64],
    // Docker is a container runtime, not a VMM; there is no kernel to boot.
    // The model records no accepted kernel formats — the ArtifactValidator
    // skips the kernel-format check for Docker accordingly.
    kernel_formats: &[],
    rootfs_formats: &[R::Ext4, R::Raw], // ext4 import or OCI layer (Raw = OCI tarball)
    required_boot_args: &[],
    supports_snapshots: false,
    supports_jailer: false,
    networking: NetworkingModel::None, // Docker manages its own networking; mvm doesn't wire it
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

// Vfkit: no implementation yet. Apple Virtualization.framework thin wrapper
// (same tier as Vz), aarch64/macOS only. Capabilities modelled after Vz
// since both use the same underlying Apple VZ API.                // assumption
static VFKIT: BackendCompat = BackendCompat {
    backend: MicrovmBackend::Vfkit,
    guest_arches: &[Aarch64], // assumption: Apple Silicon / macOS only
    kernel_formats: &[
        (Aarch64, &[K::Elf, K::Image]), // assumption: same as Vz (Apple VZ accepts both)
    ],
    rootfs_formats: &[R::Ext4],            // assumption
    required_boot_args: &["console=hvc0"], // assumption: matches Vz shape
    supports_snapshots: false, // assumption: conservative; Vfkit snapshot API unverified
    supports_jailer: false,    // assumption: no jailer (Apple VZ path)
    networking: NetworkingModel::Gvproxy, // assumption: mirrors Vz gvproxy path
};

// ── lookup ────────────────────────────────────────────────────────────────────

pub fn compat(b: MicrovmBackend) -> &'static BackendCompat {
    match b {
        MicrovmBackend::Firecracker => &FIRECRACKER,
        MicrovmBackend::Libkrun => &LIBKRUN,
        MicrovmBackend::Vz => &VZ,
        MicrovmBackend::AppleContainer => &APPLE_CONTAINER,
        MicrovmBackend::CloudHypervisor => &CLOUD_HYPERVISOR,
        MicrovmBackend::Docker => &DOCKER,
        MicrovmBackend::Qemu => &QEMU,
        MicrovmBackend::Vfkit => &VFKIT,
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
            MicrovmBackend::Vz,
            MicrovmBackend::AppleContainer,
            MicrovmBackend::CloudHypervisor,
            MicrovmBackend::Docker,
            MicrovmBackend::Qemu,
            MicrovmBackend::Vfkit,
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
        // Uncompressed Image has no KRUN_KERNEL_FORMAT constant — rejected.
        assert!(!kernel_format_ok(c, X86_64, KernelFormat::Image));
        assert!(!kernel_format_ok(c, Aarch64, KernelFormat::Image));
    }

    #[test]
    fn vz_is_aarch64_only() {
        let c = compat(MicrovmBackend::Vz);
        assert!(c.guest_arches.contains(&Aarch64));
        assert!(!c.guest_arches.contains(&X86_64));
    }

    #[test]
    fn apple_container_is_aarch64_only() {
        let c = compat(MicrovmBackend::AppleContainer);
        assert!(c.guest_arches.contains(&Aarch64));
        assert!(!c.guest_arches.contains(&X86_64));
    }

    #[test]
    fn cloud_hypervisor_supports_both_arches() {
        let c = compat(MicrovmBackend::CloudHypervisor);
        assert!(c.guest_arches.contains(&X86_64));
        assert!(c.guest_arches.contains(&Aarch64));
        // CH boots ELF on x86_64 and Image on aarch64 (no bzImage/compressed).
        assert!(kernel_format_ok(c, X86_64, KernelFormat::Elf));
        assert!(!kernel_format_ok(c, X86_64, KernelFormat::Image));
        assert!(kernel_format_ok(c, Aarch64, KernelFormat::Image));
        assert!(!kernel_format_ok(c, Aarch64, KernelFormat::Elf));
    }

    #[test]
    fn docker_has_no_kernel_formats() {
        let c = compat(MicrovmBackend::Docker);
        assert!(c.kernel_formats.is_empty());
        assert!(!kernel_format_ok(c, X86_64, KernelFormat::Elf));
        assert!(!kernel_format_ok(c, Aarch64, KernelFormat::Image));
    }

    #[test]
    fn firecracker_supports_jailer_others_do_not() {
        assert!(compat(MicrovmBackend::Firecracker).supports_jailer);
        for b in [
            MicrovmBackend::Libkrun,
            MicrovmBackend::Vz,
            MicrovmBackend::AppleContainer,
            MicrovmBackend::CloudHypervisor,
            MicrovmBackend::Docker,
            MicrovmBackend::Qemu,
            MicrovmBackend::Vfkit,
        ] {
            assert!(!compat(b).supports_jailer, "{b:?} should not have jailer");
        }
    }

    #[test]
    fn serde_roundtrips() {
        // Spot-check that the enums round-trip through JSON as snake_case.
        let b = MicrovmBackend::CloudHypervisor;
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(j, "\"cloud_hypervisor\"");
        assert_eq!(serde_json::from_str::<MicrovmBackend>(&j).unwrap(), b);

        let r = RootfsFormat::InitramfsCpioGz;
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "\"initramfs_cpio_gz\"");

        let n = NetworkingModel::UserModeVirtio;
        let j = serde_json::to_string(&n).unwrap();
        assert_eq!(j, "\"user_mode_virtio\"");
    }
}
