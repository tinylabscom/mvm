#![forbid(unsafe_code)]
//! Seal built artifacts into a signed `.mvmpkg`.
//!
//! [`export_bundle_with_signer`] reads a kernel, a rootfs, and whatever else
//! the rootfs needs to boot, hashes each, builds a
//! [`BundleManifest`](mvm_core::plan::bundle::BundleManifest), signs it under
//! a caller-supplied [`BundleSigner`], and writes the archive.
//!
//! The format — manifest, signature, archive layout — belongs to
//! `mvm_core::plan::bundle`. What this crate owns is the decision about what
//! an exported bundle contains, so `mvmctl bundle export` and a library
//! caller cannot disagree about it.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use mvm_bundler::{BundleExportInputs, BundleSigner, export_bundle_with_signer};
//!
//! # fn demo(signer: &dyn BundleSigner) -> anyhow::Result<()> {
//! let inputs = BundleExportInputs::new(
//!     "/slots/abc/artifacts/vmlinux",
//!     "/slots/abc/artifacts/rootfs.ext4",
//!     "aarch64",
//!     Path::new("app.mvmpkg"),
//! )
//! .resources(2, 512)
//! .label("app");
//! let exported = export_bundle_with_signer(&inputs, signer)?;
//! println!("{} bytes under {}", exported.size_bytes, exported.key_id.0);
//! # Ok(())
//! # }
//! ```

mod debug;
mod export;
mod inputs;
mod signer;

pub use debug::{DebugFormat, DebugOutput};
pub use export::{ExportedBundle, export_bundle_with_signer, guest_sidecar_path};
pub use inputs::{BundleExportInputs, PostureInputs};
pub use signer::BundleSigner;
