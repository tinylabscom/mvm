//! The egress and peer half of a run's launch inputs: `--net`,
//! `--network-preset`, `--allow-host` and `--peer` resolved into the one
//! `NetworkPolicy` the plan is signed over and the gate enforces.
//!
//! Shared by the CLI and the host library so the same flags produce the same
//! policy whoever launches the machine.

use anyhow::{Context, Result};

/// Resolve the transient-run egress flags (`--net` / `--allow-host`) into a
/// single `NetworkPolicy`, identical for every backend.
///
/// Precedence (one tested place so it can't drift):
/// - any `--allow-host` ⇒ allow-list (narrowest intent **wins** over `--net`);
/// - else `--net` ⇒ the `dev` preset (broad outbound + DNS, never
///   `unrestricted`, so it never trips the claim-10 unrestricted ack);
/// - else ⇒ `deny_all` (the safe default).
///
/// `HOST` with no `:PORT` defaults to `443`.
pub fn resolve_run_network_policy(
    net: bool,
    allow_host: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    resolve_run_network_policy_with_preset_and_peers(net, None, allow_host, &[])
}

pub fn parse_run_network_preset(
    value: &str,
) -> std::result::Result<mvm_core::network_policy::NetworkPreset, String> {
    use std::str::FromStr as _;

    let preset = mvm_core::network_policy::NetworkPreset::from_str(value)
        .map_err(|error| error.to_string())?;
    if preset.is_unrestricted() {
        return Err(
            "the unrestricted preset is not available here; use a narrower preset or explicit --allow-host entries"
                .to_string(),
        );
    }
    Ok(preset)
}

pub fn resolve_ai_policy(token_budget: Option<u64>) -> Option<mvm_core::network_policy::AiPolicy> {
    token_budget.map(|max_total_tokens| {
        mvm_core::network_policy::AiPolicy::metered().with_total_budget(max_total_tokens)
    })
}

pub fn persisted_run_network(
    net: bool,
    preset: Option<mvm_core::network_policy::NetworkPreset>,
    allow_host: &[String],
) -> (bool, Vec<String>) {
    match preset {
        Some(preset) => (
            false,
            preset
                .rules()
                .into_iter()
                .map(|rule| rule.to_string())
                .collect(),
        ),
        None => (net, allow_host.to_vec()),
    }
}

/// As [`resolve_run_network_policy`], plus the `--peer` routes.
///
/// Peers are orthogonal to the egress arms above: a workload may dial a peer
/// while admitting no outbound egress at all, which is the common shape for a
/// service that only talks to its own database. So the peer set is attached to
/// whichever policy the egress precedence selected rather than being an arm of
/// it.
#[cfg(test)]
fn resolve_run_network_policy_with_peers(
    net: bool,
    allow_host: &[String],
    peer: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    resolve_run_network_policy_with_preset_and_peers(net, None, allow_host, peer)
}

/// Resolve egress flags including the named preset surface.
pub fn resolve_run_network_policy_with_preset_and_peers(
    net: bool,
    preset: Option<mvm_core::network_policy::NetworkPreset>,
    allow_host: &[String],
    peer: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{NetworkPolicy, NetworkPreset};

    let base = if !allow_host.is_empty() {
        let rules = allow_host
            .iter()
            .map(|s| parse_allow_host(s))
            .collect::<Result<Vec<_>>>()?;
        NetworkPolicy::allow_list(rules)
    } else if let Some(preset) = preset {
        NetworkPolicy::preset(preset)
    } else if net {
        NetworkPolicy::preset(NetworkPreset::Dev)
    } else {
        NetworkPolicy::deny_all()
    };

    if peer.is_empty() {
        return Ok(base);
    }
    let peers = peer
        .iter()
        .map(|s| parse_peer_binding(s))
        .collect::<Result<Vec<_>>>()?;
    Ok(base.with_peers(peers))
}

/// Parse `--peer NAME:PORT=ADDR:PORT` into a validated binding.
///
/// Both halves are required and neither is inferred. The left is what the
/// guest dials; the right is the peer's admitted ingress address. Refusing
/// here rather than at the gate keeps a malformed route out of the signed
/// plan, where it would read as an admitted destination that never resolves.
pub fn parse_peer_binding(raw: &str) -> Result<mvm_contract::peer::PeerBinding> {
    let (dialed, target) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid --peer '{raw}': expected NAME:PORT=ADDR:PORT"))?;
    let (name, port) = dialed
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid --peer '{raw}': the dialed side needs a :PORT"))?;
    let (host_addr, host_port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid --peer '{raw}': the target side needs a :PORT"))?;

    let binding = mvm_contract::peer::PeerBinding {
        name: mvm_contract::peer::PeerName::parse(name)
            .map_err(|e| anyhow::anyhow!("invalid --peer '{raw}': {e}"))?,
        port: port
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid --peer '{raw}': '{port}' is not a port"))?,
        host_addr: host_addr.to_string(),
        host_port: host_port
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid --peer '{raw}': '{host_port}' is not a port"))?,
    };
    binding
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid --peer '{raw}': {e}"))?;
    Ok(binding)
}

/// Parse one `--allow-host` entry. `HOST:PORT` is parsed strictly;
/// `HOST` with no port defaults to `443` (https). Fails closed on a
/// malformed port or empty host before any VM work.
fn parse_allow_host(entry: &str) -> Result<mvm_core::network_policy::HostPort> {
    use mvm_core::network_policy::{HostPort, is_banned_ssh_port};
    let parsed = match entry.rsplit_once(':') {
        // Has an explicit `:PORT` — strict parse (rejects empty host / bad port).
        Some(_) => entry
            .parse()
            .with_context(|| format!("invalid --allow-host {entry:?}")),
        // Bare host — default to the https port.
        None if entry.is_empty() => anyhow::bail!("--allow-host cannot be empty"),
        None => Ok(HostPort::new(entry, 443)),
    }?;
    if is_banned_ssh_port(parsed.port) {
        anyhow::bail!(
            "--allow-host {entry:?} requests TCP/22, but SSH sessions are banned in microVMs"
        );
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

    #[test]
    fn run_net_default_is_deny_all() {
        assert_eq!(
            resolve_run_network_policy(false, &[]).unwrap(),
            NetworkPolicy::deny_all()
        );
    }

    #[test]
    fn run_net_flag_maps_to_dev_preset_not_unrestricted() {
        let p = resolve_run_network_policy(true, &[]).unwrap();
        assert_eq!(p, NetworkPolicy::preset(NetworkPreset::Dev));
        assert!(!p.is_unrestricted(), "--net must never be unrestricted");
    }

    #[test]
    fn allow_host_defaults_to_port_443() {
        let p = resolve_run_network_policy(false, &["api.example.com".to_string()]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)])
        );
    }

    #[test]
    fn allow_host_honors_explicit_port_and_multiple_hosts() {
        let p = resolve_run_network_policy(false, &["a.com".to_string(), "b.com:8443".to_string()])
            .unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![
                HostPort::new("a.com", 443),
                HostPort::new("b.com", 8443),
            ])
        );
    }

    #[test]
    fn allow_host_wins_over_net() {
        let p = resolve_run_network_policy(true, &["a.com".to_string()]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![HostPort::new("a.com", 443)]),
            "--allow-host must narrow, winning over --net"
        );
    }

    #[test]
    fn explicit_agent_preset_resolves_to_agent_policy() {
        let policy = resolve_run_network_policy_with_preset_and_peers(
            false,
            Some(mvm_core::network_policy::NetworkPreset::Agent),
            &[],
            &[],
        )
        .expect("agent preset resolves");
        assert_eq!(
            policy.resolve_rules(),
            Some(mvm_core::network_policy::NetworkPreset::Agent.rules())
        );
    }

    #[test]
    fn token_budget_resolves_to_a_metered_ai_policy() {
        assert!(resolve_ai_policy(None).is_none());

        let policy = resolve_ai_policy(Some(12_000)).expect("budget creates an AI policy");
        assert!(policy.metering);
        assert_eq!(
            policy.budget.expect("budget is attached").max_total_tokens,
            Some(12_000)
        );
    }

    #[test]
    fn allow_host_rejects_malformed_entries_fail_closed() {
        assert!(resolve_run_network_policy(false, &["host:0notaport".to_string()]).is_err());
        assert!(resolve_run_network_policy(false, &[":443".to_string()]).is_err());
        assert!(resolve_run_network_policy(false, &["".to_string()]).is_err());
    }

    #[test]
    fn allow_host_rejects_ssh_port() {
        let err = resolve_run_network_policy(false, &["github.com:22".to_string()])
            .expect_err("TCP/22 must be refused");
        assert!(
            err.to_string().contains("SSH sessions are banned"),
            "unexpected error: {err:#}"
        );
    }
}

#[cfg(test)]
mod peer_flag_tests {
    use super::*;

    #[test]
    fn a_well_formed_peer_parses_into_a_binding() {
        let b = parse_peer_binding("db.mvm.peer:5432=127.0.0.1:34567").expect("parses");
        assert_eq!(b.name.as_str(), "db.mvm.peer");
        assert_eq!(b.port, 5432);
        assert_eq!(b.host_addr, "127.0.0.1");
        assert_eq!(b.host_port, 34567);
    }

    /// Refused at the CLI rather than at the gate, so a malformed route never
    /// reaches the signed plan, where it would read as an admitted
    /// destination that happens never to resolve.
    #[test]
    fn a_malformed_peer_is_refused_at_the_boundary() {
        for bad in [
            "db.mvm.peer:5432",                 // no target
            "db.mvm.peer=127.0.0.1:34567",      // no dialed port
            "db.mvm.peer:5432=127.0.0.1",       // no target port
            "api.example.com:443=127.0.0.1:80", // not a peer name
            "db.mvm.peer:0=127.0.0.1:34567",    // zero port
            "db.mvm.peer:5432=db.internal:80",  // target is not a literal ip
            "db.mvm.peer:x=127.0.0.1:34567",    // port is not a number
        ] {
            assert!(
                parse_peer_binding(bad).is_err(),
                "expected `{bad}` to be refused"
            );
        }
    }

    /// Peers are orthogonal to the egress arms: the common shape is a service
    /// that talks only to its own database and admits no outbound egress.
    #[test]
    fn peers_attach_to_whichever_egress_arm_was_selected() {
        let peer = vec!["db.mvm.peer:5432=127.0.0.1:34567".to_string()];

        let denied = resolve_run_network_policy_with_peers(false, &[], &peer).expect("resolves");
        assert_eq!(denied.peers().len(), 1, "deny-all still carries its peers");

        let dev = resolve_run_network_policy_with_peers(true, &[], &peer).expect("resolves");
        assert_eq!(dev.peers().len(), 1);

        let allow = resolve_run_network_policy_with_peers(false, &["a.com".to_string()], &peer)
            .expect("resolves");
        assert_eq!(allow.peers().len(), 1);
    }

    #[test]
    fn no_peer_flag_leaves_the_policy_unchanged() {
        let p = resolve_run_network_policy_with_peers(false, &[], &[]).expect("resolves");
        assert!(p.peers().is_empty());
        assert_eq!(p, resolve_run_network_policy(false, &[]).expect("resolves"));
    }
}
