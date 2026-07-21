//! FlowPolicy hook — the mediation seam the bridge consults before
//! emitting `FlowOpened`, plus [`PlanFlowPolicy`], the per-tenant
//! deny-by-default flow gate derived from a resolved policy. This is
//! claim-10 frozen surface: flow-open drop/allow semantics must stay
//! byte-identical to the pre-decompose implementation.

use std::sync::Arc;

use crate::supervisor::audit::FlowDirection;

/// Mediation hook the bridge consults before emitting `FlowOpened`.
/// The per-tenant enforcer and future SNI / L7-URL inspectors plug in
/// here without re-architecting.
pub trait FlowPolicy: Send + Sync + 'static {
    fn evaluate(&self, ctx: &FlowDecisionCtx) -> FlowAction;
}

/// Inputs the bridge presents to [`FlowPolicy::evaluate`]. Today only
/// `direction` is filled; future SNI inspector / L7 MITM fill the
/// optional `sni_hostname` / `url_path` fields. Keeping the seam
/// forward-compat is the whole point of this struct — adding fields
/// later doesn't break callers that match-on `Allow`/`Drop`.
#[derive(Debug, Clone)]
pub struct FlowDecisionCtx {
    pub direction: FlowDirection,
    /// L3 destination IP. `None` today (no parser yet).
    pub dest_ip: Option<std::net::IpAddr>,
    /// L4 destination port. `None` today.
    pub dest_port: Option<u16>,
    /// SNI hostname extracted from TLS ClientHello. `None` until the
    /// SNI inspector lands.
    pub sni_hostname: Option<String>,
    /// Full URL path (HTTPS via TLS MITM). `None` until the L7 egress
    /// proxy populates it.
    pub url_path: Option<String>,
}

/// Outcome of [`FlowPolicy::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowAction {
    /// Permit the flow. Bridge emits `FlowOpened` and continues
    /// splicing.
    Allow,
    /// Drop the flow. Bridge emits `FlowClosed { PolicyDropped }`
    /// and tears down the bridge for that flow.
    Drop { reason: DropReason },
}

/// Why a flow was dropped. Free-form string so the enforcer / SNI / L7
/// layers can populate without coordinating enum extensions; the bridge
/// echoes this into the chain entry's `reason` label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropReason(pub String);

impl DropReason {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Per-tenant flow-open gate derived from the admitted plan's resolved
/// [`mvm_core::policy::EffectivePolicy`] (claim 10).
/// Deny-by-default: an egress flow opens only when the tenant policy
/// admits *some* egress — an explicit L4 allow rule, an egress
/// allow-list entry, or the `open` egress kill-switch. A deny-all
/// policy drops the egress flow at open. This is the libkrun analogue
/// of the Firecracker `install_default_deny` nftables drop
/// (`SupervisorEgressEnforcer`): both backends derive the same
/// default-deny posture from the same `NetworkPolicy`, through their
/// respective seams.
///
/// This is the **coarse** gate. Fine-grained per-`(proto, CIDR, port)`
/// and per-hostname admission is the packet-scan layer's job
/// (`build_egress_scan` → `L4PolicyScan` + `DnsSinkholeScan`), which
/// runs under the always-on `MandatoryDenyEgressScan` +
/// `PlaceholderLeakScan` backstops. FlowPolicy and the scan compose:
/// the flow must open **and** every packet must pass — neither widens
/// the other. So even an `open` policy still has every packet gated by
/// mandatory-deny + placeholder-leak.
///
/// Ingress always opens — an ingress frame is a reply to a guest-
/// initiated (already-gated) egress flow, and deny-by-default is an
/// *egress* control (claim 10), matching the egress-only scans.
pub struct PlanFlowPolicy {
    egress_permitted: bool,
}

impl PlanFlowPolicy {
    /// Derive the coarse flow gate from a tenant's resolved policy.
    /// Egress is permitted iff the policy is the `open` kill-switch or
    /// carries at least one allow rule (L4 or egress allow-list);
    /// otherwise it is deny-all and egress flows drop at open. The
    /// permit test deliberately mirrors what `build_egress_scan`'s
    /// packet layer would resolve to allow, so the coarse gate never
    /// drops a flow the scan would have admitted.
    pub fn from_effective(eff: &mvm_core::policy::EffectivePolicy) -> Self {
        let open = eff.egress.mode.as_deref() == Some("open");
        let has_allow = !eff.network.l4.is_empty() || !eff.egress.allow_list.is_empty();
        Self {
            egress_permitted: open || has_allow,
        }
    }

    /// Derive the coarse flow gate from a bare [`NetworkPolicy`] — the
    /// transient (no signed policy bundle) path. Mirrors `from_effective`:
    /// egress opens iff the policy is unrestricted or carries at least one
    /// allow rule; a deny-all policy (no rules) drops egress at flow-open.
    /// The fine-grained host gating is the packet scan's job
    /// (`build_egress_scan`'s `DnsSinkholeScan`), under the always-on
    /// mandatory-deny backstop — exactly as the bundle path composes.
    pub fn from_network_policy(policy: &mvm_core::network_policy::NetworkPolicy) -> Self {
        let egress_permitted = match policy.resolve_rules() {
            // `None` ⇒ unrestricted: open the flow (mandatory-deny still applies).
            None => true,
            // `Some(rules)`: allow-list/preset. Empty ⇒ deny-all ⇒ drop at open.
            Some(rules) => !rules.is_empty(),
        };
        Self { egress_permitted }
    }
}

impl FlowPolicy for PlanFlowPolicy {
    fn evaluate(&self, ctx: &FlowDecisionCtx) -> FlowAction {
        match ctx.direction {
            FlowDirection::Egress if !self.egress_permitted => FlowAction::Drop {
                reason: DropReason::new("network-policy: egress denied (deny-by-default)"),
            },
            _ => FlowAction::Allow,
        }
    }
}

/// TTL for an admission-time bare DNS pin (hours). Generous (a transient run's
/// lifetime); the pin is resolved once at bridge launch and used for the VM's
/// life, mirroring Firecracker resolving `-d <host>` once at nftables-insert.
const BARE_PIN_TTL_HOURS: i64 = 24;

/// Resolve a bare [`mvm_core::network_policy::NetworkPolicy`]'s allow-list hosts
/// to IPs on the host — the admission-time DNS pin that lets the no-bundle path
/// gate `host:port` at L4 like Firecracker (whose iptables resolves `-d <host>`
/// at insert time). Impure (does DNS); called once in `run_bridge_inner`'s sync
/// prologue, before the async bridge starts. Unrestricted ⇒ empty registry (no
/// pins needed). A literal IP needs no lookup. A host that fails to resolve is
/// pinned with an empty IP set so [`canonicalize_network_policy`] fails CLOSED
/// (deny-all) rather than silently widening reach.
pub(super) fn resolve_bare_dns_pins(
    np: &mvm_core::network_policy::NetworkPolicy,
) -> mvm_core::policy::dns_pin::DnsPinRegistry {
    use std::net::{IpAddr, ToSocketAddrs};
    let mut reg = mvm_core::policy::dns_pin::DnsPinRegistry::new();
    let Some(rules) = np.resolve_rules() else {
        return reg; // unrestricted: no L4 pin set, the gate opens wide
    };
    for hp in rules {
        let ips: Vec<IpAddr> = if let Ok(ip) = hp.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (hp.host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|sa| sa.ip()).collect())
                .unwrap_or_default()
        };
        reg.add(mvm_core::policy::dns_pin::new_pin(
            hp.host,
            ips,
            chrono::Duration::hours(BARE_PIN_TTL_HOURS),
        ));
    }
    reg
}

/// Lower a bare [`mvm_core::network_policy::NetworkPolicy`] (the no-signed-bundle
/// transient/dev path) + admission-time DNS `pins` to the bridge's
/// egress-enforcement triple `(egress_l4, dns_allow, flow_policy)` — the
/// libkrun analogue of Firecracker consuming `VmStartConfig.network_policy`.
/// Egress flows open iff the policy admits some egress (unrestricted, or a
/// non-empty allow-list / preset); a deny-all policy drops every egress flow at
/// open.
///
/// `egress_l4` now carries the resolved L4 grant set
/// ([`mvm_core::policy::projection::canonicalize_network_policy`]): a DNS
/// carve-out (UDP/53, name-gated) plus one TCP rule per (pinned IP, allow-list port), so
/// the [`L4PolicyScan`] gates `host:port` and a direct-IP dial to an unlisted
/// address is dropped — uniform with Firecracker's nftables. `dns_allow` still
/// rides the [`DnsSinkholeScan`] (the host-name gate on DNS queries); the two
/// compose under the always-on mandatory-deny + placeholder-leak scans. A
/// lowering failure (an unresolvable / expired pin) fails CLOSED to deny-all.
/// `run_bridge_inner` calls this on its no-bundle arm; the live-bridge tests
/// call it with a hand-built pin registry so they exercise the exact production
/// lowering.
pub(super) fn bare_network_policy_egress(
    np: &mvm_core::network_policy::NetworkPolicy,
    pins: &mvm_core::policy::dns_pin::DnsPinRegistry,
) -> (
    Option<mvm_core::policy::projection::CanonicalEgress>,
    Vec<String>,
    Arc<dyn FlowPolicy>,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let dns_allow: Vec<String> = np
        .resolve_rules()
        .map(|rules| rules.into_iter().map(|hp| hp.host).collect())
        .unwrap_or_default();
    let egress_l4 = mvm_core::policy::projection::canonicalize_network_policy(np, pins, &now)
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "bare egress L4 lowering failed; failing closed to deny-all"
            );
            mvm_core::policy::projection::CanonicalEgress::Rules(Vec::new())
        });
    let flow: Arc<dyn FlowPolicy> = Arc::new(PlanFlowPolicy::from_network_policy(np));
    (Some(egress_l4), dns_allow, flow)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use mvm_core::policy::L4RuleSpec;

    // -----------------------------------------------------------------
    // FlowPolicy
    // -----------------------------------------------------------------

    fn ctx() -> FlowDecisionCtx {
        FlowDecisionCtx {
            direction: FlowDirection::Egress,
            dest_ip: None,
            dest_port: None,
            sni_hostname: None,
            url_path: None,
        }
    }

    #[test]
    fn unrestricted_network_policy_lets_all_flows_through() {
        let p = unrestricted_flow_policy();
        assert_eq!(p.evaluate(&ctx()), FlowAction::Allow);
        let mut c = ctx();
        c.direction = FlowDirection::Ingress;
        assert_eq!(p.evaluate(&c), FlowAction::Allow);
    }

    struct DropAllForTest;
    impl FlowPolicy for DropAllForTest {
        fn evaluate(&self, _: &FlowDecisionCtx) -> FlowAction {
            FlowAction::Drop {
                reason: DropReason::new("test-policy-drop"),
            }
        }
    }

    #[test]
    fn drop_policy_returns_drop_with_reason() {
        let p = DropAllForTest;
        match p.evaluate(&ctx()) {
            FlowAction::Drop { reason } => {
                assert_eq!(reason.0, "test-policy-drop");
            }
            other => panic!("expected Drop, got {other:?}"),
        }
    }

    #[test]
    fn flow_decision_ctx_has_optional_sni_url_slots() {
        // Forward-compat: future SNI inspector + L7 MITM populate
        // these. The bridge passes None today; the policy seam stays
        // stable.
        let c = ctx();
        assert!(c.sni_hostname.is_none());
        assert!(c.url_path.is_none());
        assert!(c.dest_ip.is_none());
        assert!(c.dest_port.is_none());
    }

    // -----------------------------------------------------------------
    // PlanFlowPolicy — per-tenant deny-by-default flow gate
    // -----------------------------------------------------------------

    fn eff_with_l4(specs: Vec<L4RuleSpec>) -> mvm_core::policy::EffectivePolicy {
        mvm_core::policy::EffectivePolicy {
            network: mvm_core::policy::BundleNetworkPolicy {
                l4: specs,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn plan_flow_policy_deny_all_drops_egress_allows_ingress() {
        // Default resolved policy = deny-all (no L4 rules, no egress allow-list,
        // mode unset). Egress drops at open; ingress (a reply to an already-
        // gated egress flow) still opens.
        let p = PlanFlowPolicy::from_effective(&mvm_core::policy::EffectivePolicy::default());
        match p.evaluate(&ctx()) {
            FlowAction::Drop { reason } => assert!(reason.0.contains("egress denied")),
            other => panic!("expected Drop on egress, got {other:?}"),
        }
        let mut ingress = ctx();
        ingress.direction = FlowDirection::Ingress;
        assert_eq!(p.evaluate(&ingress), FlowAction::Allow);
    }

    #[test]
    fn plan_flow_policy_open_mode_allows_egress() {
        // The `open` egress kill-switch admits the flow (the packet scan still
        // gates each packet under mandatory-deny).
        let eff = mvm_core::policy::EffectivePolicy {
            egress: mvm_core::policy::EgressPolicy {
                mode: Some("open".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            PlanFlowPolicy::from_effective(&eff).evaluate(&ctx()),
            FlowAction::Allow
        );
    }

    #[test]
    fn plan_flow_policy_l4_allow_rule_permits_egress() {
        // Any L4 allow rule means the policy admits *some* egress → the coarse
        // gate opens; the L4PolicyScan does the per-(proto,CIDR,port) filtering.
        let eff = eff_with_l4(vec![L4RuleSpec {
            proto: "tcp".into(),
            dst_cidr: "1.2.3.4/32".into(),
            port_lo: 443,
            port_hi: 443,
        }]);
        assert_eq!(
            PlanFlowPolicy::from_effective(&eff).evaluate(&ctx()),
            FlowAction::Allow
        );
    }

    #[test]
    fn plan_flow_policy_from_bare_network_policy_matches_effective() {
        use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};
        // deny-all (the default) drops egress at flow-open.
        match PlanFlowPolicy::from_network_policy(&NetworkPolicy::deny_all()).evaluate(&ctx()) {
            FlowAction::Drop { reason } => assert!(reason.0.contains("egress denied")),
            other => panic!("expected Drop on deny-all egress, got {other:?}"),
        }
        // unrestricted opens (mandatory-deny still gates packets elsewhere).
        assert_eq!(
            PlanFlowPolicy::from_network_policy(&NetworkPolicy::unrestricted()).evaluate(&ctx()),
            FlowAction::Allow
        );
        // a non-empty allow-list opens the coarse gate (DnsSinkholeScan does
        // the per-host filtering).
        assert_eq!(
            PlanFlowPolicy::from_network_policy(&NetworkPolicy::allow_list(vec![HostPort::new(
                "api.example.com",
                443
            )]))
            .evaluate(&ctx()),
            FlowAction::Allow
        );
        // the dev preset carries rules → opens.
        assert_eq!(
            PlanFlowPolicy::from_network_policy(&NetworkPolicy::preset(NetworkPreset::Dev))
                .evaluate(&ctx()),
            FlowAction::Allow
        );
        // ingress always opens regardless of egress posture.
        let mut ingress = ctx();
        ingress.direction = FlowDirection::Ingress;
        assert_eq!(
            PlanFlowPolicy::from_network_policy(&NetworkPolicy::deny_all()).evaluate(&ingress),
            FlowAction::Allow
        );
    }

    #[test]
    fn plan_flow_policy_egress_allow_list_permits_egress() {
        // A hostname egress allow-list (DNS-layer gating) also counts as
        // "admits some egress" → the coarse gate opens.
        let eff = mvm_core::policy::EffectivePolicy {
            egress: mvm_core::policy::EgressPolicy {
                allow_list: vec![("api.example.com".to_string(), 443)],
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            PlanFlowPolicy::from_effective(&eff).evaluate(&ctx()),
            FlowAction::Allow
        );
    }
}
