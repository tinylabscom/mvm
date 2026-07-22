//! Vsock socket constants, raw FFI, the peer-authorization gate, and the
//! length-prefixed frame I/O that mirrors `vsock.rs`'s wire protocol.

use std::io::{Read, Write};

use mvm_agentd::vsock::{GuestRequest, GuestResponse, HOST_CID};

pub(crate) const AF_VSOCK: i32 = 40;
pub(crate) const SOCK_STREAM: i32 = 1;
pub(crate) const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
pub(crate) const MAX_FRAME_SIZE: usize = 256 * 1024;

#[repr(C)]
pub(crate) struct SockAddrVm {
    pub(crate) svm_family: u16,
    pub(crate) svm_reserved1: u16,
    pub(crate) svm_port: u32,
    pub(crate) svm_cid: u32,
    pub(crate) svm_zero: [u8; 4],
}

unsafe extern "C" {
    pub(crate) fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    pub(crate) fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
    pub(crate) fn listen(sockfd: i32, backlog: i32) -> i32;
    pub(crate) fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
    pub(crate) fn close(fd: i32) -> i32;
}

/// Whether an accepted vsock peer may drive the control port. Only the host
/// (`HOST_CID`, `VMADDR_CID_HOST` = 2) is authorized: every legitimate control
/// connection is host-initiated over the backend's vsock transport (vhost-vsock,
/// libkrun, or the in-house VMM), all of which present the host as CID 2. A
/// guest-local process connecting over loopback vsock presents `VMADDR_CID_LOCAL`
/// (1) or the guest's own CID, never 2 — so this gate rejects it before any frame
/// is read, closing the in-guest injection surface into the agent.
pub(crate) fn peer_cid_is_authorized(cid: u32) -> bool {
    cid == HOST_CID
}

pub(crate) fn read_request(file: &mut std::fs::File) -> Option<GuestRequest> {
    let mut len_buf = [0u8; 4];
    if file.read_exact(&mut len_buf).is_err() {
        return None;
    }
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_FRAME_SIZE {
        eprintln!("frame too large: {} bytes", frame_len);
        return None;
    }
    let mut buf = vec![0u8; frame_len];
    if file.read_exact(&mut buf).is_err() {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

pub(crate) fn write_response(file: &mut std::fs::File, resp: &GuestResponse) {
    let data = match serde_json::to_vec(resp) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to serialize response: {}", e);
            return;
        }
    };
    let len = (data.len() as u32).to_be_bytes();
    if let Err(e) = file.write_all(&len) {
        eprintln!("failed to write vsock response: {e}");
    }
    if let Err(e) = file.write_all(&data) {
        eprintln!("failed to write vsock response: {e}");
    }
    if let Err(e) = file.flush() {
        eprintln!("failed to flush vsock response: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the host CID (2) may drive the control port.
    #[test]
    fn peer_cid_gate_authorizes_only_host() {
        // VMADDR_CID_HOST — every backend presents the host as this CID.
        assert!(peer_cid_is_authorized(HOST_CID));
        assert!(peer_cid_is_authorized(2));
    }

    /// Guest-local and hypervisor CIDs are rejected — these are the CIDs a
    /// loopback/guest-local connection to the agent port would present.
    #[test]
    fn peer_cid_gate_rejects_non_host() {
        const VMADDR_CID_HYPERVISOR: u32 = 0;
        const VMADDR_CID_LOCAL: u32 = 1;
        const GUEST_CID: u32 = 3; // the guest's own CID under the in-house VMM
        assert!(!peer_cid_is_authorized(VMADDR_CID_HYPERVISOR));
        assert!(!peer_cid_is_authorized(VMADDR_CID_LOCAL));
        assert!(!peer_cid_is_authorized(GUEST_CID));
        assert!(!peer_cid_is_authorized(VMADDR_CID_ANY));
        for cid in [4u32, 42, 5252, u32::MAX - 1] {
            assert!(!peer_cid_is_authorized(cid), "cid {cid} must be rejected");
        }
    }
}
