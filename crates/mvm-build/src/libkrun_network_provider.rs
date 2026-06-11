//! `LibkrunNetworkProvider` — the mvm-build impl of
//! [`mvm_network::NetworkProvider`] for the libkrun gvproxy/passt path (macOS
//! libkrun + Linux libkrun).
//!
//! Unlike the Firecracker `BridgeTapNetworkProvider`, which owns a host bridge
//! + TAP, this provider owns **no host resource**. A libkrun guest's egress is
//! the in-process gateway bridge reached via gvproxy (macOS) or passt (Linux),
//! and that gateway's child process + unix sockets are spawned and reaped
//! *inside the supervisor process* (`mvm-libkrun-supervisor`), not here. So
//! `provision` is a pure config *selection* — which gateway — and `teardown`
//! is a no-op. The actual `krun_add_net_*` wiring happens later, when the
//! supervisor consumes the resolved [`NetworkingPreference`].
//!
//! claim-10: the provider only chooses between the two existing gvproxy/passt →
//! gateway-bridge paths; there is no no-gateway / TSI bypass to select (TSI was
//! removed). Every guest byte still transits the gateway-bridge chokepoint, so
//! routing the selection through the trait does not move the enforcement point.
//!
//! Scope: this is the additive provider only. The two live
//! selection sites still inline their own choice and **diverge** — the workload
//! path (`mvm_backend::libkrun::build_supervisor_config`) hardcodes
//! `cfg!(target_os = "macos")` (per-OS default, ignores `MVM_NETWORKING`),
//! while the builder path ([`apply_networking_mode`](crate::libkrun_builder))
//! honors `MVM_NETWORKING` via [`resolve_networking_mode`]. Re-pointing both
//! through this provider must first reconcile that divergence, so it is deferred
//! rather than silently changing the workload selection.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;
use mvm_network::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};

use crate::libkrun_builder::{NetworkingPreference, resolve_networking_mode};

/// libkrun gvproxy/passt network provider (a config producer; owns no host
/// state — see the module docs).
pub struct LibkrunNetworkProvider {
    /// The provider's advertised default — `deny_all()` (claim 10). The
    /// effective per-VM policy arrives via [`NetworkSpec`] on `provision`.
    default_policy: NetworkPolicy,
}

impl LibkrunNetworkProvider {
    pub fn new() -> Self {
        Self {
            default_policy: NetworkPolicy::deny_all(),
        }
    }

    /// Stable kind string for a resolved gateway preference — the `tag`
    /// `provision` mints and the supervisor's config build keys on.
    fn gateway_kind(pref: NetworkingPreference) -> &'static str {
        match pref {
            NetworkingPreference::Gvproxy => "gvproxy",
            NetworkingPreference::Passt => "passt",
        }
    }
}

impl Default for LibkrunNetworkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkProvider for LibkrunNetworkProvider {
    fn kind(&self) -> &str {
        "libkrun"
    }

    fn provision(&self, vm: &VmId, _spec: &NetworkSpec) -> Result<NetHandle, NetworkError> {
        // Pure selection: resolve the per-OS / MVM_NETWORKING gateway. No host
        // syscalls — the gvproxy/passt child + krun_add_net_* run later, inside
        // the supervisor process, from this preference.
        Ok(NetHandle {
            vm: vm.clone(),
            tag: Self::gateway_kind(resolve_networking_mode()).to_string(),
        })
    }

    fn policy(&self) -> &NetworkPolicy {
        &self.default_policy
    }

    fn teardown(&self, _handle: NetHandle) -> Result<(), NetworkError> {
        // No host resource to reap: the gateway child + its unix sockets live
        // inside the supervisor process and Drop on guest exit. Contrast
        // BridgeTapNetworkProvider, which must cleanup_network_policy + destroy
        // the TAP here.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::protocol::vm_backend::VmId;
    use mvm_network::{NetworkProvider, NetworkSpec};

    #[test]
    fn provision_tags_handle_with_a_known_gateway() {
        let provider = LibkrunNetworkProvider::new();
        let handle = provider
            .provision(&VmId("vm".to_string()), &NetworkSpec::default())
            .unwrap();
        // The tag is the resolved gateway kind; no host resource is provisioned,
        // so teardown is a clean no-op.
        assert!(["gvproxy", "passt"].contains(&handle.tag.as_str()));
        assert_eq!(handle.vm.0, "vm");
        assert!(provider.teardown(handle).is_ok());
    }

    #[test]
    fn gateway_kind_maps_each_preference() {
        // Deterministic mapping, independent of host OS / MVM_NETWORKING.
        assert_eq!(
            LibkrunNetworkProvider::gateway_kind(NetworkingPreference::Gvproxy),
            "gvproxy"
        );
        assert_eq!(
            LibkrunNetworkProvider::gateway_kind(NetworkingPreference::Passt),
            "passt"
        );
    }

    #[test]
    fn kind_is_libkrun_policy_is_deny_all_no_separate_enforcer() {
        let provider = LibkrunNetworkProvider::new();
        assert_eq!(provider.kind(), "libkrun");
        // claim-10: advertised default is deny-all, opening egress is opt-in.
        assert_eq!(*provider.policy(), NetworkPolicy::deny_all());
        // libkrun's chokepoint is the supervisor's in-process gateway-bridge
        // FlowPolicy, not a separate EgressEnforcer object → None (default).
        assert!(provider.egress_enforcer().is_none());
    }
}
