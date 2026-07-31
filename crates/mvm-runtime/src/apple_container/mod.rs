//! Apple Container guest stack on the in-house HVF VMM.
//!
//! This module boots Apple's container kernel together with the
//! `initfs.ext4` initramfs (which carries `/sbin/vminitd`) on mvm's own
//! HVF-based supervisor — no Virtualization.framework, no Swift shim. The
//! guest comes up with the initfs as the root block device and
//! `init=/sbin/vminitd` on the kernel command line, so Apple's `vminitd`
//! is PID 1 and serves its `SandboxContext` gRPC API on vsock port 1024
//! exactly as it does under Apple's own runtime.
//!
//! - [`artifacts`]: host-side resolution of the two boot artifacts mvm does
//!   not build (container kernel + vminitd initfs), failing closed with a
//!   typed error that names the build command.
//! - [`boot_spec`]: the pure mapping from a workload config to the HVF
//!   supervisor config (disk slots, cmdline, vsock port bridge).
//! - [`vminitd`]: the host-side gRPC client for that API (h2 transport
//!   over the supervisor's vsock-bridge UDS, hand-written `prost` wire
//!   types — no protoc in the build pipeline).
//!
//! The backend that composes artifact resolution, the HVF boot spec, and
//! the vminitd activation sequence lives in
//! [`crate::apple_container_backend`].

pub mod artifacts;
pub mod boot_spec;
pub mod vminitd;
