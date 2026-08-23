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

/// Compiled-in host vsock port, used when no init named one.
const DEFAULT_HOST_VSOCK_PORT: u32 = mvm_agentd::vsock::EGRESS_PORT;

/// Names the host vsock port the endpoint is listening on for this boot.
///
/// The builder tiers allocate that port per build — two builds on one host must
/// not collide on a fixed number — and hand it down on the kernel cmdline,
/// which each guest init reads and re-exports here. A guest that ignores it
/// dials the compiled-in default, finds nothing, and reports a guest with no
/// network; both guest inits already set this variable and, until now, nothing
/// read it.
const HOST_VSOCK_PORT_ENV: &str = "MVM_EGRESS_VSOCK_PORT";

/// Resolve the host port to dial, falling back to the compiled-in default.
///
/// Pure over the raw value so the fallback and the refusal are testable without
/// mutating process env. An unparsable or zero port is a refusal rather than a
/// silent fallback: it means an init tried to tell us something and we could
/// not read it, and dialing the default there would reproduce exactly the
/// misdirected-connect this exists to prevent.
fn host_vsock_port_from_env(raw: Option<&str>) -> Result<u32, String> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_HOST_VSOCK_PORT);
    };
    match raw.trim().parse::<u32>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(raw.to_string()),
    }
}

#[cfg(any(target_os = "linux", test))]
fn flowmux_identity_is_complete(paths: [&std::path::Path; 3]) -> bool {
    paths.into_iter().all(std::path::Path::is_file)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let listen = std::env::var("MVM_EGRESS_LISTEN")
        .unwrap_or_else(|_| mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN.into());
    let host_port =
        match host_vsock_port_from_env(std::env::var(HOST_VSOCK_PORT_ENV).ok().as_deref()) {
            Ok(port) => port,
            Err(raw) => {
                eprintln!("mvm-egress-client: bad {HOST_VSOCK_PORT_ENV} '{raw}'");
                return ExitCode::from(2);
            }
        };
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mvm-egress-client: bad MVM_EGRESS_LISTEN '{listen}': {e}");
            return ExitCode::from(2);
        }
    };
    run(addr, host_port)
}

#[cfg(target_os = "linux")]
fn run(addr: std::net::SocketAddr, host_port: u32) -> ExitCode {
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

    // Provision this boot's identity from the host-attached drive before
    // loading it. Doing it here rather than in each guest init means one
    // implementation covers every tier -- including the Nix-built `/init`,
    // which is shell and would otherwise need a second copy of the
    // superblock-label probe. Idempotent, so an init that already provisioned
    // (Stage 0 and the builder VM do, to get a named refusal earlier) is
    // unaffected.
    if !flowmux_identity_is_complete([
        std::path::Path::new(flowmux_keys::DEFAULT_GUEST_SIGNING_KEY_PATH),
        std::path::Path::new(flowmux_keys::DEFAULT_HOST_SIGNER_PUBKEY_PATH),
        std::path::Path::new(flowmux_keys::DEFAULT_INGRESS_TARGETS_PATH),
    ]) && let Err(e) = mvm_agentd::flowmux_drive::provision_identity_from_drive()
    {
        eprintln!("mvm-egress-client: FlowMux identity not provisioned: {e}");
    }

    let guest_signing_key = match rt.block_on(flowmux_keys::load_guest_signing_key()) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("mvm-egress-client: failed to load guest signing key: {e:#}");
            return ExitCode::from(1);
        }
    };

    let ingress_targets = match rt.block_on(flowmux_keys::load_ingress_targets()) {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("mvm-egress-client: failed to load ingress targets: {e:#}");
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

    // The host endpoint is a separate process the host is still starting while
    // this guest boots, so the first dial routinely arrives before it listens
    // and is reset. That is a race, not a refusal, and waiting it out is the
    // difference between a guest with egress and a guest that powers down.
    // A refusal — bad handshake, not admitted — still fails immediately.
    let deadline = std::time::Instant::now() + mvm_agentd::flowmux::CONNECT_RETRY_BUDGET;
    let mut attempt = 0u32;
    let client = loop {
        let outcome = rt.block_on(FlowMuxReconnectClient::connect_with_ingress(
            move || async move {
                connect_host_vsock(host_port)
                    .await
                    .map_err(FlowMuxError::Transport)
            },
            guest_signing_key.clone(),
            host_anchor,
            ingress_targets.clone(),
        ));
        match outcome {
            Ok(client) => break client,
            Err(e) if e.connect_is_retryable() && std::time::Instant::now() < deadline => {
                attempt = attempt.saturating_add(1);
                std::thread::sleep(mvm_agentd::flowmux::connect_retry_delay(attempt));
            }
            Err(e) => {
                eprintln!("mvm-egress-client: FlowMux connect failed: {e}");
                return ExitCode::from(1);
            }
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
fn run(_addr: std::net::SocketAddr, _host_port: u32) -> ExitCode {
    eprintln!("mvm-egress-client: AF_VSOCK egress is only available on Linux guests");
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A guest with no init-supplied port keeps the compiled-in default, which
    /// is what the fixed-port tiers rely on.
    #[test]
    fn an_absent_env_falls_back_to_the_compiled_in_port() {
        assert_eq!(host_vsock_port_from_env(None), Ok(DEFAULT_HOST_VSOCK_PORT));
    }

    /// The regression this exists for: the builder tiers allocate the port per
    /// build and hand it down, and the client used to ignore it and dial the
    /// default — reaching nothing, every time.
    #[test]
    fn an_init_supplied_port_is_honoured() {
        assert_eq!(host_vsock_port_from_env(Some("683445")), Ok(683445));
        assert_eq!(host_vsock_port_from_env(Some(" 45253 ")), Ok(45253));
        assert_ne!(
            host_vsock_port_from_env(Some("683445")),
            Ok(DEFAULT_HOST_VSOCK_PORT),
            "an explicit port must not silently resolve to the default"
        );
    }

    /// An unreadable value means an init tried to say something we could not
    /// parse. Falling back would reproduce the misdirected dial this fixes, so
    /// it refuses instead.
    #[test]
    fn an_unparsable_or_zero_port_refuses_rather_than_falling_back() {
        for bad in ["", "0", "-1", "http", "5253x"] {
            assert!(
                host_vsock_port_from_env(Some(bad)).is_err(),
                "{bad:?} must refuse rather than fall back"
            );
        }
    }

    #[test]
    fn a_legacy_partial_identity_is_reprovisioned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signing_key = dir.path().join("flowmux-guest-signing-key");
        let host_anchor = dir.path().join("host-signer.pub");
        let ingress_targets = dir.path().join("flowmux-ingress.json");

        std::fs::write(&signing_key, [0_u8; 32]).expect("write signing key");
        std::fs::write(&host_anchor, [1_u8; 32]).expect("write host anchor");
        assert!(!flowmux_identity_is_complete([
            &signing_key,
            &host_anchor,
            &ingress_targets,
        ]));

        std::fs::write(&ingress_targets, b"[]").expect("write ingress targets");
        assert!(flowmux_identity_is_complete([
            &signing_key,
            &host_anchor,
            &ingress_targets,
        ]));
    }
}
