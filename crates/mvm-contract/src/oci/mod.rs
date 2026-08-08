//! OCI distribution types that carry no host dependency.
//!
//! The distribution client — registry calls, layer streaming, archive
//! decode, ext4 materialization — stays in `mvm-fs`, which is `std` by
//! necessity (`tokio`, `reqwest`, `rustls`, `flate2`). What lives here is
//! the half that is pure parsing and comparison over bytes already in
//! memory, so it builds for `wasm32` alongside the rest of this crate.
//!
//! That split is what lets a browser inspect and verify an image without
//! a host: a manifest is JSON, and a digest check is a hash over bytes.
//! Layer decompression is deliberately not in scope — it needs
//! `std::io::{Read, Seek}` and a deflate implementation, and a browser has
//! no block device to materialize onto regardless.

pub mod error;
pub mod manifest_types;
pub mod reference;

pub use error::OciError;
pub use reference::ImageReference;
