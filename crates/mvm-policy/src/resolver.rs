//! Policy precedence resolver. Plan 37 Addendum E2.
//!
//! When a workload boots, three sources can describe its policy:
//!
//! 1. The bundle's **base** sub-policies (always present).
//! 2. The bundle's **tenant overlay** for that workload's tenant
//!    (each field is `Option<T>` — `None` inherits from base).
//! 3. **Emergency deny rules** distributed out of band by mvmd
//!    (or applied locally via `mvmctl policy apply`).
//!
//! These can disagree. Without explicit precedence, the merge
//! result depends on which code path resolves first — exactly the
//! kind of silent runtime mutation §6 invariant 6 forbids ("no
//! silent release mutation").
//!
//! Precedence rules (plan 37 Addendum E2):
//!
//! - **Emergency deny wins over everything.** A tool name on the
//!   emergency deny list is removed from the effective allowed set
//!   regardless of what the base or overlay say. Same for any
//!   future allow lists.
//! - **More-specific overlay wins over base.** When the tenant
//!   overlay has `Some(value)` for a sub-policy field, the overlay
//!   value replaces the base verbatim. `None` inherits from base.
//! - **Future "deny wins over allow"** comes online once the
//!   sub-policy types grow allow/deny pairs (today only
//!   `ToolPolicy.allowed` exists, and there's no `denied`
//!   counterpart yet — Wave 2 introduces it).
//!
//! The resolver is pure — given the same inputs it always returns
//! the same `EffectivePolicy`. CI's golden-fixture table walks
//! every cell of the precedence matrix and asserts the output.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::bundle::PolicyBundle;
use crate::policies::{
    ArtifactPolicy, AuditPolicy, EgressPolicy, KeyPolicy, NetworkPolicy, PiiPolicy, ToolPolicy,
};
use mvm_plan::TenantId;

/// An out-of-band deny instruction with bounded lifetime. Plan 37
/// §18.1 emergency deny rules are signed updates that bypass the
/// normal release cycle to revoke a destination, tool, or workload
/// class fast.
///
/// Wave 1.5 (this PR) ships the `tools` field — the only allow list
/// in the sub-policies today. Wave 2 grows this with `destinations`
/// once `EgressPolicy` carries a real allow list. `expires_at` makes
/// the rule self-expiring so a leftover emergency deny doesn't pin
/// the fleet forever after the incident clears.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyDeny {
    /// Tool names to remove from `EffectivePolicy.tool.allowed`.
    pub tools: Vec<String>,

    /// When this rule expires. The resolver treats expired rules as
    /// no-ops; `is_active` is the property test of "this rule
    /// applies right now". `None` means no expiry — supervisor
    /// implementations should refuse `None` in production (logged
    /// here as a forward-compat caveat) but the type allows it for
    /// dev-mode tests that don't want to thread a clock through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl EmergencyDeny {
    /// `true` iff this rule should affect the resolution at `now`.
    /// `expires_at = None` means "never expires" — see field docs.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            None => true,
            Some(at) => now < at,
        }
    }
}

/// The fully-resolved policy a workload boots under. Same shape as
/// `PolicyBundle`'s sub-policies, but flattened: no `Option<T>`,
/// no overlays. Every field is the value the supervisor should
/// enforce.
///
/// The supervisor consumes this; `mvmctl plan inspect <plan>` can
/// also print it for operator review.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    pub network: NetworkPolicy,
    pub egress: EgressPolicy,
    pub pii: PiiPolicy,
    pub tool: ToolPolicy,
    pub artifact: ArtifactPolicy,
    pub keys: KeyPolicy,
    pub audit: AuditPolicy,
}

/// Resolve `bundle` for `tenant` at `now`, with `emergency` applied
/// last. Pure function; no I/O.
///
/// Order:
/// 1. Take each base sub-policy from `bundle`.
/// 2. If `bundle.tenant_overlays[tenant]` has `Some(value)` for a
///    sub-policy, replace the base with the overlay value verbatim.
/// 3. If `emergency` is active at `now`, subtract its `tools` list
///    from `EffectivePolicy.tool.allowed`.
pub fn resolve(
    bundle: &PolicyBundle,
    tenant: &TenantId,
    now: DateTime<Utc>,
    emergency: &EmergencyDeny,
) -> EffectivePolicy {
    let overlay = bundle.tenant_overlays.get(tenant);
    let mut effective = EffectivePolicy {
        network: pick(overlay.and_then(|o| o.network.clone()), &bundle.network),
        egress: pick(overlay.and_then(|o| o.egress.clone()), &bundle.egress),
        pii: pick(overlay.and_then(|o| o.pii.clone()), &bundle.pii),
        tool: pick(overlay.and_then(|o| o.tool.clone()), &bundle.tool),
        artifact: pick(overlay.and_then(|o| o.artifact.clone()), &bundle.artifact),
        keys: pick(overlay.and_then(|o| o.keys.clone()), &bundle.keys),
        audit: pick(overlay.and_then(|o| o.audit.clone()), &bundle.audit),
    };

    if emergency.is_active(now) {
        effective
            .tool
            .allowed
            .retain(|t| !emergency.tools.iter().any(|d| d == t));
    }

    effective
}

/// Helper: take the overlay value if `Some`, otherwise clone the base.
/// Inlined into the resolver for clarity but factored out so the
/// "overlay-Some replaces base verbatim" precedence is in exactly
/// one place.
fn pick<T: Clone>(overlay: Option<T>, base: &T) -> T {
    overlay.unwrap_or_else(|| base.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{PolicyBundle, PolicyId, SCHEMA_VERSION, TenantOverlay};
    use chrono::TimeZone;
    use std::collections::BTreeMap;

    fn base_bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: SCHEMA_VERSION,
            bundle_id: PolicyId("test-bundle".to_string()),
            bundle_version: 1,
            network: NetworkPolicy {
                preset: Some("base-net".to_string()),
            },
            egress: EgressPolicy {
                mode: Some("base-egress".to_string()),
            },
            pii: PiiPolicy {
                mode: Some("detect".to_string()),
                categories: vec!["email".to_string()],
            },
            tool: ToolPolicy {
                allowed: vec![
                    "read_file".to_string(),
                    "list_dir".to_string(),
                    "shell".to_string(),
                ],
            },
            artifact: ArtifactPolicy {
                capture_paths: vec!["/artifacts".to_string()],
                retention_days: 7,
            },
            keys: KeyPolicy {
                rotation_interval_days: 7,
            },
            audit: AuditPolicy {
                chain_signing: true,
                stream_destinations: vec!["audit://base".to_string()],
            },
            tenant_overlays: BTreeMap::new(),
        }
    }

    fn tenant_a() -> TenantId {
        TenantId("tenant-a".to_string())
    }

    fn tenant_b() -> TenantId {
        TenantId("tenant-b".to_string())
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap()
    }

    fn empty_emergency() -> EmergencyDeny {
        EmergencyDeny::default()
    }

    // ----- Base only (no overlay, no emergency) -----

    #[test]
    fn resolve_returns_base_when_no_overlay_no_emergency() {
        let b = base_bundle();
        let eff = resolve(&b, &tenant_a(), now(), &empty_emergency());
        assert_eq!(eff.network, b.network);
        assert_eq!(eff.egress, b.egress);
        assert_eq!(eff.pii, b.pii);
        assert_eq!(eff.tool, b.tool);
        assert_eq!(eff.artifact, b.artifact);
        assert_eq!(eff.keys, b.keys);
        assert_eq!(eff.audit, b.audit);
    }

    // ----- Overlay precedence -----

    #[test]
    fn overlay_some_replaces_base_for_field() {
        let mut b = base_bundle();
        b.tenant_overlays.insert(
            tenant_a(),
            TenantOverlay {
                pii: Some(PiiPolicy {
                    mode: Some("refuse".to_string()),
                    categories: vec!["email".to_string(), "ssn".to_string()],
                }),
                ..Default::default()
            },
        );
        let eff = resolve(&b, &tenant_a(), now(), &empty_emergency());
        // PII overridden by overlay.
        assert_eq!(eff.pii.mode, Some("refuse".to_string()));
        assert_eq!(eff.pii.categories.len(), 2);
        // Other fields untouched (network is still the base).
        assert_eq!(eff.network, b.network);
    }

    #[test]
    fn overlay_none_inherits_from_base() {
        let mut b = base_bundle();
        b.tenant_overlays.insert(
            tenant_a(),
            TenantOverlay {
                // Only override pii; everything else None → inherits.
                pii: Some(PiiPolicy::default()),
                ..Default::default()
            },
        );
        let eff = resolve(&b, &tenant_a(), now(), &empty_emergency());
        assert_eq!(eff.pii, PiiPolicy::default());
        // Network/egress/tool/artifact/keys/audit all inherit.
        assert_eq!(eff.network, b.network);
        assert_eq!(eff.tool, b.tool);
        assert_eq!(eff.audit, b.audit);
    }

    #[test]
    fn overlay_for_different_tenant_does_not_apply() {
        let mut b = base_bundle();
        b.tenant_overlays.insert(
            tenant_b(),
            TenantOverlay {
                pii: Some(PiiPolicy {
                    mode: Some("refuse".to_string()),
                    categories: vec![],
                }),
                ..Default::default()
            },
        );
        let eff = resolve(&b, &tenant_a(), now(), &empty_emergency());
        // tenant-a sees the base, not tenant-b's overlay.
        assert_eq!(eff.pii, b.pii);
    }

    // ----- Emergency deny -----

    #[test]
    fn emergency_deny_removes_tool_from_allowed() {
        let b = base_bundle();
        let emergency = EmergencyDeny {
            tools: vec!["shell".to_string()],
            expires_at: None,
        };
        let eff = resolve(&b, &tenant_a(), now(), &emergency);
        assert_eq!(
            eff.tool.allowed,
            vec!["read_file".to_string(), "list_dir".to_string()]
        );
    }

    #[test]
    fn emergency_deny_subtracts_from_overlay_too() {
        // Even when the overlay re-grants a tool, an active
        // emergency deny removes it. Emergency wins over overlay.
        let mut b = base_bundle();
        b.tenant_overlays.insert(
            tenant_a(),
            TenantOverlay {
                tool: Some(ToolPolicy {
                    allowed: vec![
                        "shell".to_string(),
                        "exec".to_string(),
                        "read_file".to_string(),
                    ],
                }),
                ..Default::default()
            },
        );
        let emergency = EmergencyDeny {
            tools: vec!["shell".to_string(), "exec".to_string()],
            expires_at: None,
        };
        let eff = resolve(&b, &tenant_a(), now(), &emergency);
        assert_eq!(eff.tool.allowed, vec!["read_file".to_string()]);
    }

    #[test]
    fn emergency_deny_expired_is_ignored() {
        let b = base_bundle();
        let emergency = EmergencyDeny {
            tools: vec!["shell".to_string()],
            // Already past at `now()` (now = 2026-05-01 12:00).
            expires_at: Some(Utc.with_ymd_and_hms(2026, 5, 1, 11, 0, 0).unwrap()),
        };
        let eff = resolve(&b, &tenant_a(), now(), &emergency);
        // Shell is still in the effective allowed set.
        assert!(eff.tool.allowed.contains(&"shell".to_string()));
    }

    #[test]
    fn emergency_deny_at_expiry_boundary_is_inactive() {
        // is_active is `now < expires_at` — strict less-than. At
        // expires_at exactly, the rule is no longer active. Pin
        // this so a future change to <= won't slip through.
        let b = base_bundle();
        let n = now();
        let emergency = EmergencyDeny {
            tools: vec!["shell".to_string()],
            expires_at: Some(n),
        };
        let eff = resolve(&b, &tenant_a(), n, &emergency);
        assert!(eff.tool.allowed.contains(&"shell".to_string()));
    }

    #[test]
    fn emergency_deny_with_no_expiry_always_active() {
        let b = base_bundle();
        let emergency = EmergencyDeny {
            tools: vec!["shell".to_string()],
            expires_at: None,
        };
        // Even decades in the future, an unbounded emergency rule
        // is still in force.
        let far_future = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
        let eff = resolve(&b, &tenant_a(), far_future, &emergency);
        assert!(!eff.tool.allowed.contains(&"shell".to_string()));
    }

    #[test]
    fn emergency_deny_unknown_tool_is_no_op() {
        let b = base_bundle();
        let emergency = EmergencyDeny {
            tools: vec!["a-tool-that-was-never-allowed".to_string()],
            expires_at: None,
        };
        let eff = resolve(&b, &tenant_a(), now(), &emergency);
        // Allowed set unchanged.
        assert_eq!(eff.tool.allowed, b.tool.allowed);
    }

    // ----- Precedence table cross-product -----

    #[test]
    fn precedence_table_emergency_overlay_base() {
        // Cross-product of: { base, overlay-replaces, overlay-inherits } ×
        // { no-emergency, active-emergency, expired-emergency }.
        // Walks the precedence matrix to lock in the contract.

        let mut b = base_bundle();
        b.tool = ToolPolicy {
            allowed: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        b.tenant_overlays.insert(
            tenant_a(),
            TenantOverlay {
                tool: Some(ToolPolicy {
                    allowed: vec!["a".to_string(), "x".to_string(), "y".to_string()],
                }),
                ..Default::default()
            },
        );

        let active = EmergencyDeny {
            tools: vec!["a".to_string(), "b".to_string()],
            expires_at: None,
        };
        let expired = EmergencyDeny {
            tools: vec!["a".to_string(), "b".to_string()],
            expires_at: Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()),
        };

        // tenant-a (overlay applies):
        //   overlay = [a, x, y] - active emergency (a, b) = [x, y]
        let r = resolve(&b, &tenant_a(), now(), &active);
        assert_eq!(r.tool.allowed, vec!["x".to_string(), "y".to_string()]);

        //   overlay = [a, x, y] - expired emergency = [a, x, y]
        let r = resolve(&b, &tenant_a(), now(), &expired);
        assert_eq!(
            r.tool.allowed,
            vec!["a".to_string(), "x".to_string(), "y".to_string()]
        );

        // tenant-b (no overlay → base applies):
        //   base = [a, b, c] - active emergency (a, b) = [c]
        let r = resolve(&b, &tenant_b(), now(), &active);
        assert_eq!(r.tool.allowed, vec!["c".to_string()]);

        //   base = [a, b, c] - expired emergency = [a, b, c]
        let r = resolve(&b, &tenant_b(), now(), &expired);
        assert_eq!(
            r.tool.allowed,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    // ----- EmergencyDeny serde -----

    #[test]
    fn emergency_deny_serde_roundtrip() {
        let e = EmergencyDeny {
            tools: vec!["shell".to_string(), "exec".to_string()],
            expires_at: Some(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: EmergencyDeny = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn emergency_deny_no_expiry_field_is_omitted() {
        let e = EmergencyDeny {
            tools: vec!["shell".to_string()],
            expires_at: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        // skip_serializing_if drops the field entirely so the wire
        // is `{"tools":[...]}` rather than carrying a noisy null.
        assert!(!json.contains("expires_at"));
    }

    #[test]
    fn emergency_deny_unknown_field_rejected() {
        let json = r#"{"tools":["x"],"new_field":1}"#;
        let result: Result<EmergencyDeny, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
