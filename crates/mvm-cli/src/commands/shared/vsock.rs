//! Vsock helpers for talking to the in-guest agent.

use anyhow::Result;

/// Wait for the guest agent to respond to a Ping over vsock.
/// Returns true if the agent is reachable within `timeout_secs`.
pub fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    use std::io::{Read, Write};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let ping = serde_json::to_vec(&mvm_guest::vsock::GuestRequest::Ping).unwrap_or_default();
    let len_bytes = (ping.len() as u32).to_be_bytes();

    while std::time::Instant::now() < deadline {
        if let Ok(mut s) =
            mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
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
    let mut stream = mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    mvm_guest::vsock::start_port_forward_on(&mut stream, guest_port)
}
