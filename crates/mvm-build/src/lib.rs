pub mod artifacts;
pub mod backend;
pub mod cache;
pub mod firecracker;
pub mod template_reuse;

pub mod nix;
pub mod pipeline;

// Legacy re-exports — preserve `mvm_build::build::*`, `mvm_build::scripts::*`, etc.
pub use nix::manifest as nix_manifest;
pub use nix::scripts;
pub use pipeline::{build, dev_build, orchestrator, vsock_builder};
