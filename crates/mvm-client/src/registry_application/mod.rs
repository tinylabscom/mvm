//! Shared registry discovery, not publisher or application authorization.
//!
//! Catalog entries and their advertised digests remain untrusted metadata.
//! Safe `file://` mirrors require the Unix canonical metadata reader. On
//! non-Unix platforms, use an HTTPS registry; local mirrors fail closed.

pub mod discovery;
