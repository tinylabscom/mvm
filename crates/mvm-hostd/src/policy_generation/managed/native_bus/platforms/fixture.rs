//! Test-only ancillary disposal for bounded Unix socket fixtures.
//!
//! Darwin fixtures need room to receive and close their rights. This fixed
//! buffer is not qualified for arbitrary ancillary truncation or production use.

pub(super) const ANCILLARY_BYTES: usize = 1024;

pub(super) fn recv_flags() -> rustix::net::RecvFlags {
    rustix::net::RecvFlags::empty()
}
