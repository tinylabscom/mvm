//! Throwaway: prove a running workload microVM's guest agent answers the
//! authenticated handshake (the same one `wait_for_guest_agent` does),
//! since no CLI verb yet targets an arbitrary workload VM by name.
//!
//!   cargo run -p mvm-cli --example agent_ping -- <vm-name>

fn main() -> anyhow::Result<()> {
    let vm = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: agent_ping <vm-name>"))?;
    let transport = mvm_vmm::vsock_transport::for_vm(&vm)?;
    let mut stream = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)?;
    let (session, _) = mvm_agentd::vsock::open_peer_authenticated_session(&mut stream)?;
    println!("AGENT PING OK for '{vm}': advertised {:?}", session.offer());
    Ok(())
}
