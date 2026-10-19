//! Image identity and production primitives, with Unix-only VM orchestration.
//!
//! Non-Unix hosts can observe repositories and produce/verify local manifests.
//! They do not expose a VM launcher or a fallback implementation of one.

pub mod artifact_acquisition;
pub mod base_image_contract;
pub mod build_cache;
pub mod builder_boot;
pub mod builder_contract;
pub mod builder_guest_paths;
pub mod builder_image_inputs;
pub mod cache_install;
pub mod embed_toolchain;
pub mod host_payload_manifest;
pub mod image_protocol;
pub mod image_source;
pub mod source_closure;
mod source_copy;
pub mod workspace_graph;

/// Portable image-contract verification; acquisition requires a Unix host.
#[cfg(not(unix))]
pub mod published_image_set {
    pub use crate::base_image_contract::verify_base_image_contract;
}

use mvm_core::env_hygiene::helper_command;

// These declarations remain at the crate root, preserving the Unix public API.
#[cfg(unix)]
include!("unix_modules.rs");
