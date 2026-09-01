#![deny(unsafe_code)]
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
//! - [`overlay`]: runtime-overlay cache resolution — pick and validate the
//!   verity-sealed overlay artifact set for one `(version, arch)`.
//! - [`clone`]: reflink (copy-on-write) file/directory cloning primitives
//!   used by the runtime to materialize per-instance rootfs copies.
//! - [`hash`]: content-addressing helpers (file/directory SHA-256) backing
//!   [`snapshot_store`]'s content-addressed create.
//! - [`snapshot_store`]: content-addressed snapshot persistence used by the
//!   warm-parent pool.
//!
//! The crate-level lint is `deny(unsafe_code)` rather than `forbid` so that
//! the [`clone`] module can use the small, platform-specific unsafe blocks
//! required to invoke `clonefile(2)` and `FICLONE`. Everywhere else in this
//! crate remains unsafe-free.

pub mod clone;
pub mod elf;
pub mod ext4;
pub mod extension_image;
pub mod hash;
pub mod initramfs;
pub mod oci;
/// OCI layer unpack to a staging rootfs directory. Handles whiteouts,
/// symlinks, hardlinks, ownership, permissions, path traversal, the
/// `/mvm` reserved-path collision check, and per-entry + per-layer
/// size caps (decompression-bomb mitigation). ext4 generation
/// (`mke2fs -d` against the staging dir) runs inside the builder VM.
pub mod oci_to_rootfs;
pub mod overlay;
pub mod parallel;
pub mod rootfs;
pub mod sdk_sidecar;
pub mod snapshot_store;
pub mod trusted_snapshot;
