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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityRequirement {
    Required,
    IfPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupMode {
    Serve,
    ProvisionIdentityFor {
        uid: u32,
        requirement: IdentityRequirement,
    },
}

fn startup_mode_from_args(args: impl IntoIterator<Item = String>) -> Result<StartupMode, String> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Ok(StartupMode::Serve);
    };
    let requirement = match command.as_str() {
        "provision-identity-for" => IdentityRequirement::Required,
        "provision-identity-for-if-present" => IdentityRequirement::IfPresent,
        _ => return Err(format!("unknown command {command:?}")),
    };
    let raw_uid = args
        .next()
        .ok_or_else(|| format!("{command} requires a non-root uid"))?;
    if args.next().is_some() {
        return Err(format!("{command} accepts exactly one uid"));
    }
    match raw_uid.parse::<u32>() {
        Ok(uid) if uid > 0 => Ok(StartupMode::ProvisionIdentityFor { uid, requirement }),
        _ => Err(format!("invalid non-root egress service uid {raw_uid:?}")),
    }
}

#[cfg(any(target_os = "linux", test))]
fn provisioning_failure_is_fatal(
    requirement: IdentityRequirement,
    error: &mvm_agentd::flowmux_drive::IdentityDriveError,
) -> bool {
    requirement == IdentityRequirement::Required
        || !matches!(
            error,
            mvm_agentd::flowmux_drive::IdentityDriveError::NotAttached
        )
}

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
    let mode = match startup_mode_from_args(std::env::args().skip(1)) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("mvm-egress-client: {error}");
            return ExitCode::from(2);
        }
    };
    if let StartupMode::ProvisionIdentityFor { uid, requirement } = mode {
        return provision_identity_for(uid, requirement);
    }

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
fn provision_identity_for(uid: u32, requirement: IdentityRequirement) -> ExitCode {
    match mvm_agentd::flowmux_drive::provision_identity_from_drive_for_uid(uid) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if !provisioning_failure_is_fatal(requirement, &error) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mvm-egress-client: could not provision the FlowMux identity: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn provision_identity_for(_uid: u32, _requirement: IdentityRequirement) -> ExitCode {
    eprintln!("mvm-egress-client: FlowMux identity drives are only available on Linux guests");
    ExitCode::from(1)
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

    // Identity-drive mounting is a short privileged init action. The
    // long-lived parser reaches this point only after its init has handed the
    // root-only signing key to the dedicated service uid.
    if !flowmux_identity_is_complete([
        std::path::Path::new(flowmux_keys::DEFAULT_GUEST_SIGNING_KEY_PATH),
        std::path::Path::new(flowmux_keys::DEFAULT_HOST_SIGNER_PUBKEY_PATH),
        std::path::Path::new(flowmux_keys::DEFAULT_INGRESS_TARGETS_PATH),
    ]) {
        eprintln!("mvm-egress-client: FlowMux identity was not provisioned by guest init");
        return ExitCode::from(1);
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

    // The ICMP mediator serves `ping` for the unprivileged workload, which
    // cannot read the signing key this process just loaded. Its own blocking
    // thread rather than a task on this runtime: it opens a blocking FlowMux
    // session per client, and `block_on` inside the runtime would panic. Bound
    // here rather than on the thread, because the guest init waits only for the
    // proxy port and a workload can already be running by the time a lazily
    // bound listener is scheduled. A bind failure is not fatal — every other
    // kind of egress still works without `ping`.
    match mvm_agentd::icmp_mediator::bind_icmp_mediator() {
        Ok(listener) => {
            std::thread::spawn(move || {
                if let Err(e) = mvm_agentd::icmp_mediator::serve_icmp_mediator(&listener) {
                    eprintln!("mvm-egress-client: ICMP mediator stopped: {e:#}");
                }
            });
        }
        Err(e) => eprintln!("mvm-egress-client: ICMP mediator not serving: {e:#}"),
    }

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

    #[test]
    fn startup_mode_separates_privileged_provisioning_from_serving() {
        assert_eq!(
            startup_mode_from_args(Vec::<String>::new()),
            Ok(StartupMode::Serve)
        );
        assert_eq!(
            startup_mode_from_args(["provision-identity-for".into(), "989".into()]),
            Ok(StartupMode::ProvisionIdentityFor {
                uid: 989,
                requirement: IdentityRequirement::Required,
            })
        );
        assert_eq!(
            startup_mode_from_args(["provision-identity-for-if-present".into(), "989".into(),]),
            Ok(StartupMode::ProvisionIdentityFor {
                uid: 989,
                requirement: IdentityRequirement::IfPresent,
            })
        );
    }

    #[test]
    fn optional_provisioning_ignores_only_an_absent_drive() {
        use mvm_agentd::flowmux_drive::IdentityDriveError;

        assert!(!provisioning_failure_is_fatal(
            IdentityRequirement::IfPresent,
            &IdentityDriveError::NotAttached,
        ));
        assert!(provisioning_failure_is_fatal(
            IdentityRequirement::Required,
            &IdentityDriveError::NotAttached,
        ));
        assert!(provisioning_failure_is_fatal(
            IdentityRequirement::IfPresent,
            &IdentityDriveError::Unreadable("corrupt drive".into()),
        ));
    }

    #[test]
    fn startup_mode_rejects_root_invalid_and_ambiguous_service_uids() {
        for args in [
            vec!["provision-identity-for".into(), "0".into()],
            vec!["provision-identity-for".into(), "not-a-uid".into()],
            vec!["provision-identity-for".into()],
            vec!["serve".into()],
            vec![
                "provision-identity-for".into(),
                "989".into(),
                "extra".into(),
            ],
        ] {
            assert!(startup_mode_from_args(args).is_err());
        }
    }

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
    fn a_partial_identity_is_not_ready_for_the_deprivileged_service() {
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
