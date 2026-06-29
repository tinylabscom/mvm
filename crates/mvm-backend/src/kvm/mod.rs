//! KVM (Linux) backend — drives [`crate::vmm`] on Linux via `kvm-ioctls`,
//! implementing the [`crate::vmm::hv`] seam (Plan 214 / ADR-099).
//!
//! [`x86_boot`] is pure logic (the x86_64 Linux boot protocol over a guest-RAM
//! slice) and compiles + unit-tests on every host. The ioctl glue ([`vm`]) is
//! Linux-only. The boot recipe is live-proven in `spikes/kvm-x86-boot/`.

pub mod serial;
pub mod x86_boot;

// The ioctl glue is x86_64-specific (x86 boot regs, segments, CPUID). aarch64
// KVM — which reuses the whole arm64 device model — is a later slice (ADR-099).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod vm;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use vm::{KvmError, KvmHandle, KvmVcpu, KvmVm};
