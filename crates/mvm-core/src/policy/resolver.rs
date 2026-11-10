//! Resolve tenant overlays over a bundle's base policies.
//!
//! A present overlay value replaces its base sub-policy; an absent value
//! inherits it. Resolution is pure and retains network, egress, filesystem,
//! and secret-related sub-policies.

use crate::plan::TenantId;
use crate::policy::bundle::PolicyBundle;

pub use mvm_contract::policy::resolver::EffectivePolicy;

/// Resolve the bundle's base and optional tenant overlay without I/O.
pub fn resolve(bundle: &PolicyBundle, tenant: &TenantId) -> EffectivePolicy {
    let overlay = bundle.tenant_overlays.get(tenant);
    EffectivePolicy {
        network: pick(overlay.and_then(|o| o.network.clone()), &bundle.network),
        egress: pick(overlay.and_then(|o| o.egress.clone()), &bundle.egress),
        pii: pick(overlay.and_then(|o| o.pii.clone()), &bundle.pii),
        artifact: pick(overlay.and_then(|o| o.artifact.clone()), &bundle.artifact),
        keys: pick(overlay.and_then(|o| o.keys.clone()), &bundle.keys),
        audit: pick(overlay.and_then(|o| o.audit.clone()), &bundle.audit),
        wasi: pick(overlay.and_then(|o| o.wasi.clone()), &bundle.wasi),
    }
}

fn pick<T: Clone>(overlay: Option<T>, base: &T) -> T {
    overlay.unwrap_or_else(|| base.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::bundle::{PolicyId, SCHEMA_VERSION, TenantOverlay};
    use crate::policy::policies::{BundleNetworkPolicy, EgressPolicy, KeyPolicy, PiiPolicy};
    use std::collections::BTreeMap;

    fn base_bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: SCHEMA_VERSION,
            bundle_id: PolicyId("test-bundle".to_string()),
            bundle_version: 1,
            network: BundleNetworkPolicy {
                preset: Some("base-net".to_string()),
                ..Default::default()
            },
            egress: EgressPolicy {
                mode: Some("base-egress".to_string()),
                ..Default::default()
            },
            pii: PiiPolicy {
                mode: Some("detect".to_string()),
                ..Default::default()
            },
            artifact: Default::default(),
            keys: KeyPolicy {
                rotation_interval_days: 7,
            },
            audit: Default::default(),
            wasi: Default::default(),
            tenant_overlays: BTreeMap::new(),
        }
    }

    #[test]
    fn no_overlay_inherits_all_base_policies() {
        let bundle = base_bundle();
        let resolved = resolve(&bundle, &TenantId("other".to_string()));
        assert_eq!(resolved.network, bundle.network);
        assert_eq!(resolved.egress, bundle.egress);
        assert_eq!(resolved.pii, bundle.pii);
        assert_eq!(resolved.artifact, bundle.artifact);
        assert_eq!(resolved.keys, bundle.keys);
        assert_eq!(resolved.audit, bundle.audit);
        assert_eq!(resolved.wasi, bundle.wasi);
    }

    #[test]
    fn overlay_replaces_only_present_fields_for_matching_tenant() {
        let mut bundle = base_bundle();
        let tenant = TenantId("tenant-a".to_string());
        bundle.tenant_overlays.insert(
            tenant.clone(),
            TenantOverlay {
                network: Some(BundleNetworkPolicy {
                    preset: Some("tenant-net".to_string()),
                    ..Default::default()
                }),
                egress: Some(EgressPolicy {
                    mode: Some("tenant-egress".to_string()),
                    ..Default::default()
                }),
                pii: Some(PiiPolicy::default()),
                ..Default::default()
            },
        );
        let resolved = resolve(&bundle, &tenant);
        assert_eq!(resolved.network.preset.as_deref(), Some("tenant-net"));
        assert_eq!(resolved.egress.mode.as_deref(), Some("tenant-egress"));
        assert_eq!(resolved.pii, PiiPolicy::default());
        assert_eq!(resolved.keys, bundle.keys);
        assert_eq!(
            resolve(&bundle, &TenantId("other".to_string())).network,
            bundle.network
        );
    }
}
