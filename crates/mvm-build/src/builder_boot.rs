//! The builder boot contract: what `mvmctl` hands a builder VM at boot, and
//! what it may assume about the builder image it boots.
//!
//! mvm's own builder binaries (`mvm-host-vm-init`, `mvm-builderd`) are not
//! part of the builder image. Every builder boot carries them beside the image
//! as a **boot payload**: a deterministic initramfs the running `mvmctl`
//! assembles from its embedded, digest-verified bytes. The VMM loads it the
//! way it loads the kernel. Its `/init` is `mvm-host-vm-init` in its stage-1
//! role: it verifies the payload against the digest on the kernel command
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
//! - how stage 2 knows it is stage 2 — [`STAGE_ENV`].

pub mod payload;

pub use payload::{
    BootPayloadError, BuilderBootPayload, BuilderBootPayloadBuilder, PayloadDigest,
    PayloadManifest, install_payload, verify_unpacked_payload,
};

/// Where the payload's binaries and manifest sit inside the initramfs,
/// relative to its root.
pub const PAYLOAD_DIR_IN_INITRAMFS: &str = "mvm/host-bins";

/// The manifest file inside the payload directory.
pub const PAYLOAD_MANIFEST_NAME: &str = "MANIFEST";

/// The member that is also the initramfs `/init`.
pub const STAGE1_MEMBER: &str = "mvm-host-vm-init";

/// The kernel command-line key carrying the payload digest.
pub const PAYLOAD_CMDLINE_KEY: &str = "mvm.boot_payload";

/// Where the payload's binaries live in a running builder guest: a directory
/// on the `/run` tmpfs, which survives the pivot out of the initramfs.
pub const RUNTIME_HOST_BIN_DIR: &str = "/run/mvm/host-bins";

/// The environment variable stage 1 sets when it re-executes itself as the
/// builder's PID 1. The kernel command line cannot change between the two
/// stages, so this is how the second one knows the first already ran.
pub const STAGE_ENV: &str = "MVM_BUILDER_BOOT_STAGE";

/// The value of [`STAGE_ENV`] in stage 2.
pub const STAGE2: &str = "2";
