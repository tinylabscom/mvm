//! The builder boot contract: what `mvmctl` hands a builder VM at boot, and
//! what it may assume about the builder image it boots.
//!
//! mvm's own builder binaries (`mvm-host-vm-init`, `mvm-builderd`, and the
//! `mvm-setpriv` helper the guest agent is forked under) need not be part of
//! the builder image; an image at boot ABI 2 carries none of them. Every
//! builder boot carries them beside the image as a **boot payload**: a
//! deterministic initramfs the running `mvmctl` assembles from its embedded,
//! digest-verified bytes. The VMM loads it the way it loads the kernel. Its
//! `/init` is `mvm-host-vm-init` in its stage-1 role: it verifies the payload
//! against the digest on the kernel command
//! line, mounts the image read-only, checks the image's boot ABI, copies the
//! binaries to a tmpfs, pivots into the image, and re-executes itself from the
//! tmpfs as the builder's PID 1. A Rust change to `mvmctl` therefore never
//! requires a new builder image.
//!
//! The pieces of the contract, each owned by one item here:
//!
//! - the payload layout — [`PAYLOAD_DIR_IN_INITRAMFS`], [`PAYLOAD_MANIFEST_NAME`]
//!   and [`payload`]'s format;
//! - the digest on the command line — [`PAYLOAD_CMDLINE_KEY`];
//! - where the binaries live once the guest is running —
//!   [`RUNTIME_HOST_BIN_DIR`];
//! - how stage 2 knows it is stage 2 — [`STAGE_ENV`];
//! - which images the payload boots — [`abi`], against the image's
//!   [`IMAGE_ABI_MARKER`].

pub use mvm_builder_guest::builder_boot::*;

#[cfg(unix)]
pub mod stage;

#[cfg(unix)]
pub use stage::{
    BootPayloadSource, PAYLOAD_FILE_NAME, StageBootError, current_payload_digest,
    read_image_boot_abi, register_boot_payload_source, stage_builder_boot, stage_image_boot,
    supported_image_abis,
};

/// Hosts without a builder runtime cannot register a boot payload.
#[cfg(not(unix))]
pub fn supported_image_abis() -> mvm_core::image_set::BuilderBootAbiRange {
    baked_only_abis()
}
