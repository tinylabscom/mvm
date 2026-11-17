//! Build-layer types, constants and pure helpers the CLI names but does not
//! own.
//!
//! Each item is re-exported from the crate that defines it, one by one, so a
//! command that only needs a type reaches it through the client rather than
//! past it. Operations are not here: they belong behind client methods.

pub use mvm_build::builder_boot::{BootPayloadError, BootPayloadSource, BuilderBootPayload};
pub use mvm_build::builder_pack::{KERNEL_FILE, ROOTFS_FILE};
pub use mvm_build::builder_vm::{GuestSidecar, SIDECAR_FILENAME, host_arch_tag};
pub use mvm_build::pipeline::BuildMode;
pub use mvm_build::run_image::RootStrategy;
pub use mvm_build::stage0_kernel::current_image_set_protocol_support;
pub use mvm_build::volume_image::VolumeImageLock;
