//! Host-side termination of an admitted egress flow to a credentialed host.
//!
//! When a guest opens an opaque FlowMux TCP flow to a host that carries a bound
//! secret, the endpoint serves it here instead of relaying it: `flow` terminates
//! the guest's TLS when the flow is encrypted, under a leaf minted by the per-VM
//! CA (`tls`), reads each HTTP/1.1 request (`read`), rebuilds it against the
//! authority the flow was admitted for (`request`), and drives it through the
//! substitution service.

pub mod flow;
pub mod read;
pub mod request;
pub mod tls;

/// First index of `needle` in `haystack`, or `None`.
pub(super) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
