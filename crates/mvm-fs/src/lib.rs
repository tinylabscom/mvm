#![forbid(unsafe_code)]
//! Filesystem + image materialization for mvm.
//!
//! - [`oci`]: OCI distribution client — registry resolution, manifest/layer
//!   fetch, digest verification, allow-listed unpack.
//! - [`ext4`]: pure-Rust deterministic ext4 image writer for read-only rootfs
//!   materialization (no mkfs, no subprocess).
//! - [`rootfs`]: the single directory-tree walker + pure in-process ext4
//!   materializer on top of the [`ext4`] writer.
//! - [`oci_to_rootfs`]: OCI-unpacked staging tree to a materialized,
//!   verity-sealed ext4 rootfs image.

pub mod ext4;
pub mod oci;
/// OCI layer unpack to a staging rootfs directory. Handles whiteouts,
/// symlinks, hardlinks, ownership, permissions, path traversal, the
/// `/mvm` reserved-path collision check, and per-entry + per-layer
/// size caps (decompression-bomb mitigation). ext4 generation
/// (`mke2fs -d` against the staging dir) runs inside the builder VM.
pub mod oci_to_rootfs;
pub mod rootfs;
