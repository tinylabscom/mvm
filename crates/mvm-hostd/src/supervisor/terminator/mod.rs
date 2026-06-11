//! Transparent egress terminator.
//!
//! The host nft `nat` chain REDIRECTs a guest's outbound TCP to the terminator
//! listener, which recovers the original destination, substitutes any opaque
//! secret placeholders in the payload, and forwards the request under the real
//! credential. Each sub-module is its own self-contained concern.

pub mod handler;
pub mod listener;
pub mod orig_dst;
pub mod read;
pub mod request;
pub mod tls;

/// First index of `needle` in `haystack`, or `None`.
pub(super) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
