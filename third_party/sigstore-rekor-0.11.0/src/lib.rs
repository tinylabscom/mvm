//! Rekor transparency log client for Sigstore
//!
//! This crate provides a client for interacting with Rekor, the Sigstore
//! transparency log service.
//!
//! # Features
//!
//! - `cache` - Enable caching support for log info and public key responses.
//!   When enabled, use [`RekorClientBuilder::with_cache`] to configure a cache adapter.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_rekor::RekorClient;
//!
//! # async fn example() -> Result<(), sigstore_rekor::Error> {
//! let client = RekorClient::public();
//! let log_info = client.get_log_info().await?;
//! println!("Tree size: {}", log_info.tree_size);
//! # Ok(())
//! # }
//! ```
//!
//! With caching enabled:
//!
//! ```ignore
//! use sigstore_rekor::RekorClient;
//! use sigstore_cache::FileSystemCache;
//!
//! let cache = FileSystemCache::default_location()?;
//! let client = RekorClient::builder("https://rekor.sigstore.dev")
//!     .with_cache(cache)
//!     .build();
//! ```

pub mod body;
#[cfg(feature = "client")]
pub mod client;
pub mod entry;
pub mod error;

pub use body::RekorEntryBody;
#[cfg(feature = "client")]
pub use client::{get_public_log_info, RekorClient, RekorClientBuilder};
pub use entry::{
    DsseEntry, DsseEntryV2, HashedRekord, HashedRekordV2, LogEntry, LogInfo, RekorApiVersion,
    SearchIndex,
};
pub use error::{Error, Result};
