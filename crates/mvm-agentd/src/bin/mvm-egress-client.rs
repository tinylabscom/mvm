//! `mvm-egress-client` — in-guest proxy → FlowMux egress bridge.
//!
//! Runs inside a NIC-less microVM guest. Listens on loopback for SOCKS5
//! CONNECT, ordinary HTTP-proxy requests, and UDP/TCP DNS, then relays them
//! over one authenticated, reconnecting FlowMux session to the host
//! `GuestService::NetworkFlow` vsock port. The host endpoint makes the
//! claim-10 decision and originates the external socket.
//!
//! Listen address: `MVM_EGRESS_LISTEN` (default:
//! `mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN`). Linux-only (AF_VSOCK);
//! a no-op off Linux so the workspace builds on macOS dev hosts.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
use mvm_agentd::vsock::EGRESS_PORT;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let listen = std::env::var("MVM_EGRESS_LISTEN")
        .unwrap_or_else(|_| mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN.into());
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mvm-egress-client: bad MVM_EGRESS_LISTEN '{listen}': {e}");
            return ExitCode::from(2);
        }
    };
    run(addr)
}

#[cfg(target_os = "linux")]
fn run(addr: std::net::SocketAddr) -> ExitCode {
    use mvm_agentd::flowmux::{FlowMuxError, FlowMuxReconnectClient};
    use mvm_agentd::flowmux_keys;
    use mvm_agentd::guest_vsock_session::connect_host_vsock;

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mvm-egress-client: runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let guest_signing_key = match rt.block_on(flowmux_keys::load_guest_signing_key()) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("mvm-egress-client: failed to load guest signing key: {e:#}");
            return ExitCode::from(1);
        }
    };

    let host_anchor = match flowmux_keys::load_host_signer_verifying_key(std::path::Path::new(
        flowmux_keys::DEFAULT_HOST_SIGNER_PUBKEY_PATH,
    )) {
        Ok(Some(key)) => key,
        Ok(None) => {
            eprintln!("mvm-egress-client: host-signer trust anchor not provisioned");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("mvm-egress-client: failed to load host-signer anchor: {e:#}");
            return ExitCode::from(1);
        }
    };

    let client = match rt.block_on(FlowMuxReconnectClient::connect(
        || async {
            connect_host_vsock(EGRESS_PORT)
                .await
                .map_err(FlowMuxError::Transport)
        },
        guest_signing_key,
        host_anchor,
    )) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("mvm-egress-client: FlowMux connect failed: {e}");
            return ExitCode::from(1);
        }
    };

    match rt.block_on(mvm_agentd::flowmux_egress::run(addr, client)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mvm-egress-client: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_addr: std::net::SocketAddr) -> ExitCode {
    eprintln!("mvm-egress-client: AF_VSOCK egress is only available on Linux guests");
    ExitCode::from(1)
}
