//! The canonical per-backend security profiles — the single source of truth
//! for per-backend claim coverage, layer coverage, tier, and notes.
//!
//! These used to live behind each backend's `security_profile()` impl; they
//! moved here so the matrix is declared once and every backend, plus the
//! gates that check the documentation against the code, read the same
//! values.

use super::{BackendSecurityProfile, ClaimStatus, LayerCoverage};

/// Firecracker: Tier 1 — full posture. All seven claims hold; hardware
/// isolation via KVM; verified boot via dm-verity.
pub(super) const FIRECRACKER_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [ClaimStatus::Holds; 7],
    layer_coverage: LayerCoverage::all_layers(),
    tier: "Tier 1",
    notes: &[
        "Full ADR-001 — all seven CI-enforced claims hold.",
        "Hardware isolation via KVM. Verified boot via dm-verity (W3).",
    ],
};

/// HVF: Tier 2 — the in-house VMM owns the surface and the data plane is
/// vsock-only. Claims 1-2/4-7 hold as on Firecracker; claim 3 (verified
/// boot) does not hold on the default virtiofs-root path, which cannot be
/// dm-verity-sealed.
pub(super) const HVF_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [
        ClaimStatus::Holds,       // 1 — host-fs isolation via the VMM + admitted shares
        ClaimStatus::Holds,       // 2 — uid-0 protections, guest-side (same as FC)
        ClaimStatus::DoesNotHold, // 3 — virtiofs-root has no dm-verity; block+ext4 only
        ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
        ClaimStatus::Holds,       // 5 — vsock framing fuzzed
        ClaimStatus::Holds,       // 6 — dev image hash verified
        ClaimStatus::Holds,       // 7 — cargo deps audited
    ],
    layer_coverage: LayerCoverage::all_layers(),
    tier: "Tier 2",
    notes: &[
        "In-house Hypervisor.framework VMM on macOS 26+ Apple silicon (the default tier).",
        "vsock-only data plane: no guest NIC; egress rides the host gating endpoint (auditable).",
        "Claim 3 (verified boot) does not hold on the virtiofs-root path — dm-verity targets \
         the block+ext4 backends.",
        "Pause/resume + snapshot land as they are wired onto the primitive.",
    ],
};

/// libkrun: Tier 2 — hardware isolation via KVM (Linux) or
/// Hypervisor.framework (macOS); comparable VMM TCB to Firecracker. Claim 3
/// (verified boot) does not hold because the dm-verity pipeline currently
/// targets Firecracker.
pub(super) const LIBKRUN_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [
        ClaimStatus::Holds,       // 1 — host-fs isolation via KVM/HVF
        ClaimStatus::Holds,       // 2 — uid-0 protections same as FC
        ClaimStatus::DoesNotHold, // 3 — verified boot for libkrun rootfs not yet wired
        ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
        ClaimStatus::Holds,       // 5 — vsock framing is fuzzed
        ClaimStatus::Holds,       // 6 — image hash verification
        ClaimStatus::Holds,       // 7 — cargo deps audited
    ],
    layer_coverage: LayerCoverage::all_layers(),
    tier: "Tier 2",
    notes: &[
        "Hardware isolation via KVM (Linux) or Hypervisor.framework (macOS).",
        "Comparable VMM TCB to Firecracker; passes plan 53 \"fork test\".",
        "Claim 3 (verified boot) is partial — dm-verity pipeline targets Firecracker today.",
        "Supported on Linux KVM and macOS Apple Silicon; macOS Intel is not a supported \
         local host.",
    ],
};

/// QEMU: Tier 2 best-case (KVM), same claim coverage as the other runners —
/// claim 3 (verified boot) targets Firecracker — with notes updated for the
/// converged boot path. The TCG (no-KVM) mode is a runtime Tier-3
/// degradation surfaced by the boot banner and doctor, not by this
/// compile-time tier.
pub(super) const QEMU_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [
        ClaimStatus::Holds,       // 1
        ClaimStatus::Holds,       // 2
        ClaimStatus::DoesNotHold, // 3 — verified boot targets Firecracker
        ClaimStatus::Holds,       // 4
        ClaimStatus::Holds,       // 5
        ClaimStatus::Holds,       // 6
        ClaimStatus::Holds,       // 7
    ],
    layer_coverage: LayerCoverage::all_layers(),
    tier: "Tier 2",
    notes: &[
        "QEMU workload runtime; dev/test tier only, opt-in via --hypervisor qemu, never \
         auto-selected.",
        "Boots through the unified workload runner: attaches the universal initramfs and \
         receives ActivateEnvironment over vsock, exactly like Firecracker/libkrun/HVF — \
         QEMU's vhost-vsock speaks AF_VSOCK, so the channels ride the per-VM \
         AF_VSOCK↔UNIX bridge into the same per-port UNIX-socket convention.",
        "KVM-accelerated where /dev/kvm is present; TCG software-emulation fallback \
         otherwise (runtime Tier-3, banner-flagged).",
        "Larger device model than Firecracker → higher L2 audit cost; outside the \
         CI-enforced claim set. Never a production runtime.",
    ],
};

/// Mock: in-process test infrastructure. No guest, no rootfs, no isolation
/// — none of the seven claims hold and the tier banner says test-only.
pub(super) const MOCK_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [ClaimStatus::DoesNotHold; 7],
    layer_coverage: LayerCoverage::no_layers(),
    tier: "Tier 3 (test-only)",
    notes: &[
        "MockBackend is in-process test infrastructure.",
        "No guest, no rootfs, no isolation; never use in production.",
    ],
};

/// Wasm: claim-free portability tier. Every numbered claim is
/// `DoesNotHold`, matching the mock test double's framing rather than a
/// real microVM's partial-claim profile. There is no guest, no rootfs block
/// device, and no hardware isolation boundary.
pub(super) const WASM_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [ClaimStatus::DoesNotHold; 7],
    layer_coverage: LayerCoverage::no_layers(),
    tier: "Tier 3 (portability, claim-free)",
    notes: &[
        "Runs a user-supplied WASI module under host wasmtime — no hardware virt, no guest \
         kernel, no TAP/virtio/vsock, no verified boot, no snapshot.",
        "Opt-in only; never selected by auto-detect.",
        "Carries none of the numbered security claims; never a production or untrusted-workload \
         path.",
    ],
};

/// WebLinux: claim-free browser-hosted tier (QEMU-Wasm + Nix-built Linux
/// kernel), same posture shape as the wasm tier.
pub(super) const WEB_LINUX_SECURITY_PROFILE: BackendSecurityProfile = BackendSecurityProfile {
    claims: [ClaimStatus::DoesNotHold; 7],
    layer_coverage: LayerCoverage::no_layers(),
    tier: "Tier 3 (portability, claim-free)",
    notes: &[
        "Browser-hosted WebLinux backend (QEMU-Wasm + Nix-built Linux kernel).",
        "Runs only inside a WebAssembly browser environment; the native stub is selectable \
         for catalog/help parity but cannot boot a VM.",
        "Claim-free software-emulation tier; opt-in only; never auto-selected.",
    ],
};

/// AppleContainer: the HVF runner booting Apple's prebuilt container
/// kernel — the boot, the isolation boundary, and the activation stack are
/// identical, so the claims, layer coverage, and tier are HVF's verbatim;
/// only the kernel image differs, and the notes say so honestly.
pub(super) const APPLE_CONTAINER_SECURITY_PROFILE: BackendSecurityProfile =
    BackendSecurityProfile {
        claims: HVF_SECURITY_PROFILE.claims,
        layer_coverage: HVF_SECURITY_PROFILE.layer_coverage,
        tier: HVF_SECURITY_PROFILE.tier,
        notes: &[
            "This backend is the HVF workload runner booting Apple's prebuilt container kernel: \
         the same universal initramfs, guest agent, activation flow, egress gate, and \
         isolation boundary as the HVF backend — only the kernel image differs.",
            "The kernel is a fetched binary artifact (Apple's container kernel), not an mvm-built \
         image: it is trusted only with a matching vmlinux.blake3 digest sidecar in the \
         artifact cache — resolution fails closed when the sidecar is absent, malformed, or \
         disagrees with the kernel bytes, and an unverified kernel never makes this backend \
         available.",
            "The sealed block+ext4 boot path is live-proven on macOS HVF with this kernel: \
         dm-verity-verified rootfs and runtime-overlay mounts, activation acknowledged by \
         the guest agent, and the uid-901 privilege drop all observed in the gated \
         end-to-end boot test.",
            "Opt-in only; never selected by auto-detect.",
        ],
    };
