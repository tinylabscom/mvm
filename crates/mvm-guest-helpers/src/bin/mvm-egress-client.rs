//! `mvm-egress-client` — in-guest SOCKS5 → vsock egress proxy (ADR-100).
//!
//! Runs inside a NIC-less microVM guest. Listens for SOCKS5 CONNECT on loopback
//! and forwards each connection's target over AF_VSOCK to the host egress gateway,
//! which makes the claim-10 decision and proxies the bytes. Workloads opt in with
//! `ALL_PROXY=socks5h://127.0.0.1:<port>`.
//!
//! Listen address: `MVM_EGRESS_LISTEN` (default `127.0.0.1:1080`). Linux-only
//! (AF_VSOCK); a no-op off Linux so the workspace builds on macOS dev hosts.

use std::process::ExitCode;

fn main() -> ExitCode {
    let listen = std::env::var("MVM_EGRESS_LISTEN").unwrap_or_else(|_| "127.0.0.1:1080".into());
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
    match rt.block_on(mvm_guest_helpers::egress_client::run(addr)) {
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
