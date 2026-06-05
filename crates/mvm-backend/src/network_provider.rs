//! `BridgeTapNetworkProvider` — the mvm-backend impl of
//! [`mvm_network::NetworkProvider`] for the Linux bridge + TAP path
//! (Firecracker / Linux-KVM).
//!
//! It puts the existing [`crate::network`] provisioning (`bridge_ensure` +
//! `tap_create` + `apply_network_policy`) behind the seam so the Firecracker
//! start path goes through the trait instead of calling the free functions
//! directly (plan 123 Phase A, A1 step 2). The gvproxy/passt (libkrun) path
//! and the WireGuard/Tailscale mesh (mvmd) are separate `NetworkProvider`
//! impls — this one only owns the iptables-on-TAP egress mechanism.
//!
//! The per-VM `VmSlot` is reconstructed from `(vm name, spec.slot_index)`:
//! `VmSlot::new` is deterministic, so it's byte-for-byte the slot the start
//! path allocated — provisioning through this provider is the same operation,
//! same order, as the direct calls it replaces.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;
use mvm_network::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};

use crate::base::config::VmSlot;
use crate::network;

/// Bridge + TAP network provider (Firecracker / Linux-KVM).
pub struct BridgeTapNetworkProvider {
    /// The provider's advertised default — `deny_all()` (claim 10). The
    /// effective per-VM policy arrives via [`NetworkSpec`] on `provision`.
    default_policy: NetworkPolicy,
}

impl BridgeTapNetworkProvider {
    pub fn new() -> Self {
        Self {
            default_policy: NetworkPolicy::deny_all(),
        }
    }
}

impl Default for BridgeTapNetworkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkProvider for BridgeTapNetworkProvider {
    fn kind(&self) -> &str {
        "bridge"
    }

    fn provision(&self, vm: &VmId, spec: &NetworkSpec) -> Result<NetHandle, NetworkError> {
        let slot = VmSlot::new(&vm.0, spec.slot_index);
        network::bridge_ensure().map_err(|e| NetworkError::Provision(e.to_string()))?;
        network::tap_create(&slot).map_err(|e| NetworkError::Provision(e.to_string()))?;
        // Transactional, matching the old TapGuard: if the egress policy fails
        // to apply, drop the TAP we just created so we don't leak a
        // half-provisioned device. The caller re-arms a guard for the rest of
        // VM start.
        if let Err(e) = network::apply_network_policy(&slot, &spec.policy) {
            let _ = network::tap_destroy(&slot);
            return Err(NetworkError::Provision(e.to_string()));
        }
        Ok(NetHandle {
            vm: vm.clone(),
            tag: spec.slot_index.to_string(),
        })
    }

    fn policy(&self) -> &NetworkPolicy {
        &self.default_policy
    }

    fn teardown(&self, handle: NetHandle) -> Result<(), NetworkError> {
        let index: u8 = handle
            .tag
            .parse()
            .map_err(|_| NetworkError::Teardown(format!("bad slot tag {:?}", handle.tag)))?;
        let slot = VmSlot::new(&handle.vm.0, index);
        // Best-effort + symmetric with the apply path: drain the iptables
        // policy AND drop the TAP even if one fails, then report any errors
        // together (the stop path treats teardown as best-effort).
        let mut errs = Vec::new();
        if let Err(e) = network::cleanup_network_policy(&slot) {
            errs.push(format!("policy cleanup: {e}"));
        }
        if let Err(e) = network::tap_destroy(&slot) {
            errs.push(format!("tap destroy: {e}"));
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(NetworkError::Teardown(errs.join("; ")))
        }
    }
}
