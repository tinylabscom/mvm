//! `mvm-egress-client` — in-guest proxy → vsock egress bridge.
//!
//! Runs inside a NIC-less microVM guest. Listens on loopback for SOCKS5 CONNECT
//! plus ordinary HTTP-proxy requests, then relays them over AF_VSOCK to the host
//! egress gateway, which makes the claim-10 decision and either splices raw
//! bytes or acts as the forward proxy.
//!
//! Listen address: `MVM_EGRESS_LISTEN` (default:
//! `mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN`). Linux-only (AF_VSOCK);
//! a no-op off Linux so the workspace builds on macOS dev hosts.

use std::process::ExitCode;

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
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mvm-egress-client: runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(mvm_agentd::egress_client::run(addr)) {
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
