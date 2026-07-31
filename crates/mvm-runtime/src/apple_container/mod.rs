//! Apple Container support: Apple's prebuilt container kernel on the
//! in-house HVF VMM.
//!
//! The backend boots Apple's container kernel (a fetched binary artifact,
//! no toolchain) together with mvm's universal initramfs — the guest agent
//! is PID 1 and activation is the standard `ActivateEnvironment` flow every
//! runner backend uses. No Virtualization.framework, no Swift anywhere:
//! Apple's only presence is the guest-side kernel image itself.
//!
//! - [`artifacts`]: host-side resolution of the kernel artifact, failing
//!   closed with a typed error that names the fetch source.
//!
//! The backend — the HVF workload runner with the kernel image substituted
//! — lives in [`crate::apple_container_backend`].

pub mod artifacts;
