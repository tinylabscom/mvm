#![forbid(unsafe_code)]
//! Filesystem + image materialization for mvm.
//!
//! - [`oci`]: OCI distribution client — registry resolution, manifest/layer
//!   fetch, digest verification, allow-listed unpack.
//! - [`ext4`]: pure-Rust deterministic ext4 image writer for read-only rootfs
//!   materialization (no mkfs, no subprocess).

pub mod ext4;
pub mod oci;
