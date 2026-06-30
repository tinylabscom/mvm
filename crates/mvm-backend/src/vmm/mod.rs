//! Portable, hypervisor-agnostic VMM device model.
//!
//! Guest memory access, the device tree (FDT), arm64 kernel-image loading, and
//! the virtio-mmio devices (PL011 console, block, vsock) live here with **no
//! hypervisor FFI** — so the same device model is driven by any backend's vCPU
//! run loop: HVF on macOS today, and KVM (Linux) / WHP (Windows) as they land.
//! A backend handles the platform-specific parts (create VM/vCPU, run, decode
//! the exit, raise a device's [`virtio::VirtioBlk::irq`] line its own way) and
//! delegates the MMIO/virtqueue/boot work to these types.
//!
//! This module compiles on every target; it is the "no VMM lock-in" seam.

pub mod device;
pub mod egress_gate;
pub(crate) mod egress_proxy;
pub mod fdt;
pub mod guest_mem;
pub mod hv;
pub mod kernel_image;
pub mod run;
pub mod virtio;
pub mod vsock;
