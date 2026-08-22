//! Vsock socket constants, raw FFI, the peer-authorization gate, and the
//! length-prefixed frame I/O that mirrors `vsock.rs`'s wire protocol.

use std::io::Write;

use mvm_agentd::vsock::{
    AuthenticatedSession, GuestResponse, HOST_CID, MAX_FRAME_SIZE, write_frame,
};

pub(crate) const AF_VSOCK: i32 = 40;
pub(crate) const SOCK_STREAM: i32 = 1;
pub(crate) const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
#[repr(C)]
pub(crate) struct SockAddrVm {
    pub(crate) svm_family: u16,
    pub(crate) svm_reserved1: u16,
    pub(crate) svm_port: u32,
    pub(crate) svm_cid: u32,
    /// `VMADDR_FLAG_TO_HOST` and friends. Zero for every address mvm
    /// builds; carried so the mirror matches the header field-for-field.
    pub(crate) svm_flags: u8,
    pub(crate) svm_zero: [u8; 3],
}

// Layout contract with the kernel's `struct sockaddr_vm`
// (linux/vm_sockets.h). The struct is handed to bind(2)/connect(2) as a
// pointer plus an explicit length, so a size or offset mismatch binds the
// wrong port or CID instead of returning an error.
//
// Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof, not read off the
// Rust definition. Note bytes 12..16: the header gained `svm_flags` at
// offset 12 in Linux 6.0, shrinking `svm_zero` to three bytes. The total
// is 16 either way, which is why the pre-6.0 shape went unnoticed here.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<SockAddrVm>() == 16);
    assert!(align_of::<SockAddrVm>() == 4);
    assert!(offset_of!(SockAddrVm, svm_family) == 0);
    assert!(offset_of!(SockAddrVm, svm_reserved1) == 2);
    assert!(offset_of!(SockAddrVm, svm_port) == 4);
    assert!(offset_of!(SockAddrVm, svm_cid) == 8);
    assert!(offset_of!(SockAddrVm, svm_flags) == 12);
    assert!(offset_of!(SockAddrVm, svm_zero) == 13);
};

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

pub(crate) fn write_response(file: &mut (impl Write + ?Sized), resp: &GuestResponse) {
    let fallback = GuestResponse::Error {
        message: "guest response exceeded the protocol frame cap".to_string(),
    };
    let selected = match serde_json::to_vec(resp) {
        Ok(encoded) if encoded.len() <= MAX_FRAME_SIZE => resp,
        Ok(_) => &fallback,
        Err(error) => {
            eprintln!("failed to serialize vsock response: {error}");
            &fallback
        }
    };
    if let Err(error) = write_frame(file, selected) {
        // Do not append a fallback after an I/O error: the original frame may
        // already be partially written, so another prefix would corrupt it.
        //
        // Nothing is retried and the caller is not told, because there is
        // nothing useful either could do: the sealed frame already spent its
        // sequence number, so `AuthenticatedSession::write` has poisoned the
        // session and no later frame on this connection can reach the host.
        // The host learns of it as a closed connection, and this line is the
        // only place the cause is recorded.
        eprintln!("mvm-guest-agent: control response dropped, connection is finished: {error}");
    }
}

/// Adapts the existing response-writing handlers to the authenticated session
/// without allowing a raw JSON response to bypass encryption.
pub(crate) struct AuthenticatedWriter<'a> {
    file: &'a mut std::fs::File,
    session: &'a mut AuthenticatedSession,
    pending: Vec<u8>,
}

impl<'a> AuthenticatedWriter<'a> {
    pub(crate) fn new(file: &'a mut std::fs::File, session: &'a mut AuthenticatedSession) -> Self {
        Self {
            file,
            session,
            pending: Vec::new(),
        }
    }
}

impl Write for AuthenticatedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.pending.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "incomplete response frame",
            ));
        }
        let body_len = usize::try_from(u32::from_be_bytes(
            self.pending[..4]
                .try_into()
                .expect("response frame prefix is exactly four bytes"),
        ))
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid frame length")
        })?;
        if body_len > MAX_FRAME_SIZE || self.pending.len() != body_len + 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid response frame body length",
            ));
        }
        let response: GuestResponse = serde_json::from_slice(&self.pending[4..]).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid response")
        })?;
        self.session
            .write(self.file, &response)
            .map_err(std::io::Error::other)?;
        self.pending.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::read_frame;
    use std::io::Cursor;

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

    #[test]
    fn oversized_response_is_replaced_by_one_bounded_error_frame() {
        let oversized = GuestResponse::Error {
            message: "x".repeat(MAX_FRAME_SIZE),
        };
        let mut wire = Cursor::new(Vec::new());
        write_response(&mut wire, &oversized);

        assert!(wire.get_ref().len() <= MAX_FRAME_SIZE + 4);
        wire.set_position(0);
        let response: GuestResponse = read_frame(&mut wire).expect("bounded response frame");
        assert!(matches!(
            response,
            GuestResponse::Error { message }
                if message == "guest response exceeded the protocol frame cap"
        ));
        assert_eq!(
            usize::try_from(wire.position()).expect("cursor position fits usize"),
            wire.get_ref().len()
        );
    }
}
