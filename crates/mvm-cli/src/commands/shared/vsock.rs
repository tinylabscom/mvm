//! Vsock helpers for talking to the in-guest agent.
//!
//! Routes through `mvm_runtime::vsock_transport::AppleContainerTransport`
//! intentionally — these helpers serve `mvmctl up` flows that today
//! only target the Apple Container backend (Firecracker `up` uses a
//! different code path). If/when a Firecracker `up` lands, swap to
//! `vsock_transport::for_vm`.

use anyhow::Result;

use mvm_runtime::vsock_transport::{AppleContainerTransport, VsockTransport};

/// Wait for the guest agent to respond to a Ping over vsock.
/// Returns true if the agent is reachable within `timeout_secs`.
pub fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    use std::io::{Read, Write};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let ping = serde_json::to_vec(&mvm_guest::vsock::GuestRequest::Ping).unwrap_or_default();
    let len_bytes = (ping.len() as u32).to_be_bytes();
    let transport = AppleContainerTransport::new(vm_id);

    while std::time::Instant::now() < deadline {
        if let Ok(mut s) = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)
            && s.write_all(&len_bytes).is_ok()
            && s.write_all(&ping).is_ok()
            && s.flush().is_ok()
        {
            let mut resp_len = [0u8; 4];
            if s.read_exact(&mut resp_len).is_ok() {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Tell the guest agent to start a vsock→TCP forwarder for the given port.
pub fn request_port_forward(vm_id: &str, guest_port: u16) -> Result<u32> {
    let transport = AppleContainerTransport::new(vm_id);
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::start_port_forward_on(&mut stream, guest_port)
}
