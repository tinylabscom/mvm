//! OCI layer unpack to a staging rootfs directory.
//!
//! `ImageStaging` orchestrates the unpack:
//!
//! 1. Caller creates an `ImageStaging` rooted at a directory.
//! 2. Caller calls `apply_layer` once per OCI layer, in the order
//!    the manifest lists them. The unpacker applies tar entries
//!    with security checks layered on top of the standard `tar`
//!    crate extraction (path traversal, symlink/hardlink escape,
//!    reserved-path collision, size caps, unsupported entry
//!    types).
//! 3. Caller calls `finalize` to release the staging directory and
//!    get a `StagedRootfs` descriptor pointing at it.
//! 4. Caller hands the descriptor to `materialize_to_ext4`
//!    (Linux-only at runtime; non-Linux routes through the libkrun
//!    builder VM), which produces a byte-deterministic ext4 image.
//! 5. Caller hands the `MaterializedRootfs` to
//!    `seal_with_verity` (also Linux-only) to generate the
//!    dm-verity sidecar + root hash. Two runs against byte-identical
//!    ext4 input produce
//!    byte-identical sidecars + the same root hash; this is the
//!    invariant the per-digest verity cache depends on.
//!
//! Layers are assumed to arrive *decompressed*. The CLI orchestrator
//! is responsible for piping fetched layer bytes through the right
//! decoder based on the manifest's
//! `mediaType` — gzip via `flate2::read::GzDecoder`, zstd via
//! `zstd::stream::Decoder`, plain tar passes through. Keeping the
//! decoder choice out of the unpack module means hostile-tar tests
//! don't need to compress every fixture.
//!
//! ## Whiteouts
//!
//! OCI whiteouts (`<dir>/.wh.<name>` for "delete `<name>` from
//! previous layers", `<dir>/.wh..wh..opq` for "clear this
//! directory's contents from previous layers") are processed
//! inline. The whiteout marker file itself is never written to
//! staging; its effect is to remove the corresponding path.
//!
//! ## Attack-surface coverage
//!
//! The integration tests under `mvm-build/tests/oci_unpack_*` are
//! the canonical mitigation evidence. Every variant in
//! `OciUnpackError` has at least one negative test that proves
//! the corresponding attack class is rejected without a partial
//! write landing in staging.

pub mod error;
pub mod ext4;
mod path_validation;
mod unpack;
pub mod verity;

pub use error::OciUnpackError;
pub use ext4::{MaterializedRootfs, Mke2fsOptions, estimate_image_size, materialize_to_ext4};
pub use unpack::{ImageStaging, LayerStats, StagedRootfs, StagingOptions};
pub use verity::{
    MVM_VERITY_DATA_BLOCK_SIZE, MVM_VERITY_HASH_ALGORITHM, MVM_VERITY_HASH_BLOCK_SIZE,
    MVM_VERITY_PINNED_SALT, VeritySealedRootfs, VeritysetupOptions, seal_with_verity,
};
