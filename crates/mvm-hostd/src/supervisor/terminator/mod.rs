//! Plan 129 — transparent egress terminator.
//!
//! The host nft `nat` chain REDIRECTs a guest's outbound TCP to the terminator
//! listener, which recovers the original destination, substitutes any opaque
//! secret placeholders in the payload, and forwards the request under the real
//! credential. Each sub-module is its own self-contained concern.

pub mod orig_dst;
pub mod request;
