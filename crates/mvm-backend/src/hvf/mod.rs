//! Raw HVF (`Hypervisor.framework`) backend — spike scaffold.
//!
//! Plan 214 Phase 11 / ADR-098: a macOS backend built directly on
//! `Hypervisor.framework` instead of the higher-level Virtualization.framework
//! (`vz`), so the destination macOS path owns its device model and warm-start
//! path. This module is the spike substrate: the FFI surface ([`sys`]) and the
//! guest-RAM-mapping + minimal-boot proof ([`boot_smoke`]) that establishes the
//! primitive on real hardware. The full `VmBackend` impl (device model, vsock,
//! snapshot, console) is later work that builds on this primitive.
//!
//! Apple-silicon macOS only; every entry point needs the
//! `com.apple.security.hypervisor` entitlement (already applied by
//! [`crate::codesign`]).

mod backend;
mod boot_smoke;
mod console_smoke;
mod kernel_boot;
mod sys;
mod vcpu;

pub use backend::HvfBackend;
pub use boot_smoke::{BootProof, HvfError, MAGIC, boot_smoke, probe_available};
pub use console_smoke::{ConsoleProof, console_smoke};
pub use kernel_boot::{KernelBootResult, boot_kernel};
