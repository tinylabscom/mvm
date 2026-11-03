//! Host-side termination of an admitted egress flow to a credentialed host.
//!
//! When a guest opens an opaque FlowMux TCP flow to a host that carries a bound
//! secret, the endpoint serves it here instead of relaying it: `flow` terminates
//! the guest's TLS when the flow is encrypted, under a leaf minted by the per-VM
//! CA (`tls`), reads each HTTP/1.1 request (`read`) off a stream whose reads
//! report what the guest sent even once it has stopped reading (`guest_tls`),
//! rebuilds it against the authority the flow was admitted for (`request`), and
//! drives it through the substitution service.

use super::find_subslice;

pub mod flow;
mod guest_tls;
pub mod read;
pub mod request;
pub mod tls;
