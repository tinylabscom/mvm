//! Linux refuses ancillary data without installing received descriptors.

pub(super) const ANCILLARY_BYTES: usize = 0;

pub(super) fn recv_flags() -> rustix::net::RecvFlags {
    rustix::net::RecvFlags::CMSG_CLOEXEC
}
