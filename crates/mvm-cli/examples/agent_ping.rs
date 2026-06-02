//! Throwaway: prove a running workload microVM's guest agent answers the
//! ADR-053 protocol hello (the same handshake `wait_for_guest_agent` does),
//! since no CLI verb yet targets an arbitrary workload VM by name.
//!
//!   cargo run -p mvm-cli --example agent_ping -- <vm-name>

fn main() -> anyhow::Result<()> {
    let vm = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: agent_ping <vm-name>"))?;
    let transport = mvm::vsock_transport::for_vm(&vm)?;
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    let ack = mvm_guest::vsock::negotiate_protocol(
        &mut stream,
        vec![mvm_guest::vsock::GuestCapability::Ping],
    )?;
    println!("AGENT PING OK for '{vm}': negotiated {ack:?}");
    Ok(())
}
