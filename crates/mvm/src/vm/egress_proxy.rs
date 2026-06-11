//! Hypervisor-level L7 egress proxy supervision.
//!
//! Today (this branch): stub. The L3 tier of egress enforcement
//! (`apply_network_policy` / `cleanup_network_policy` in `vm/network.rs`)
//! is shipped via `NetworkPreset::Agent` and friends. The L7 tier
//! (HTTPS-proxy + DNS-pinning) lands in a follow-up. This module exists
//! so callers that opt into `EgressMode::L3PlusL7` get a clear "not
//! implemented yet" error from the runtime instead of a silent downgrade
//! to L3.
//!
//! The trait surface here is the integration point: when the mitmdump
//! supervisor lands, it implements `EgressProxy` and `tap_create` calls
//! `start_for_vm` after the L3 rules are installed. See
//! `EgressProxy::start_for_vm` for the contract.

use std::fmt;

use mvm_core::network_policy::{EgressMode, NetworkPolicy};

/// Per-VM proxy handle. Returned by [`EgressProxy::start_for_vm`]
/// and consumed by [`EgressProxy::stop_for_vm`]. The real implementation
/// fills in the actual fields (PID, listening port, allowlist hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHandle {
    pub vm_name: String,
    pub listen_port: u16,
}

/// Errors from the L7 supervisor. Stable across the v1 stub and the
/// real implementation so callers don't have to re-match.
#[derive(Debug)]
pub enum EgressProxyError {
    /// `EgressMode::L3PlusL7` was requested but the runtime backing
    /// the proxy isn't implemented yet. Callers should fall back to
    /// `EgressMode::L3Only` or surface the error.
    NotImplemented,
    /// Unrelated runtime failure (process spawn, port allocation,
    /// CA cert load).
    Other(anyhow::Error),
}

impl fmt::Display for EgressProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented => write!(
                f,
                "L7 egress proxy is not implemented yet (plan 34). Use EgressMode::L3Only \
                 or wait for the L7 follow-up. ADR-004 §\"L7\" documents the design."
            ),
            Self::Other(e) => write!(f, "egress proxy: {e}"),
        }
    }
}

impl std::error::Error for EgressProxyError {}

impl From<anyhow::Error> for EgressProxyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// L7 egress supervisor. The trait is the integration point with
/// `vm/network.rs`; the follow-up wires it up.
///
/// Contract:
/// - `start_for_vm`: spawn / configure the proxy for a single VM.
///   Idempotent — calling twice for the same `vm_name` returns the
///   existing handle. The L3 rules must already be in place;
///   the proxy installs additional `iptables` rules to redirect
///   HTTPS/HTTP from the VM to itself.
/// - `stop_for_vm`: stop the proxy and remove its iptables rules.
///   Idempotent — safe to call for a vm_name that was never started.
pub trait EgressProxy: Send + Sync {
    fn start_for_vm(
        &self,
        vm_name: &str,
        policy: &NetworkPolicy,
    ) -> Result<ProxyHandle, EgressProxyError>;
    fn stop_for_vm(&self, handle: &ProxyHandle) -> Result<(), EgressProxyError>;
}

/// Stub supervisor used when no real backing is configured. Returns
/// `NotImplemented` for every operation. The follow-up will replace this
/// with a `MitmdumpSupervisor` that wraps `mitmdump` from nixpkgs.
pub struct StubEgressProxy;

impl EgressProxy for StubEgressProxy {
    fn start_for_vm(
        &self,
        _vm_name: &str,
        _policy: &NetworkPolicy,
    ) -> Result<ProxyHandle, EgressProxyError> {
        Err(EgressProxyError::NotImplemented)
    }
    fn stop_for_vm(&self, _handle: &ProxyHandle) -> Result<(), EgressProxyError> {
        // stop on a stub is a no-op rather than NotImplemented — the
        // teardown path runs unconditionally and we don't want to
        // bubble errors when there's nothing to clean up.
        Ok(())
    }
}

/// Decide whether a policy + mode combination requires the L7
/// supervisor at all. Used by the network setup path so it can skip
/// proxy spawn for `L3Only` and `Open` policies.
pub fn requires_l7(mode: EgressMode) -> bool {
    matches!(mode, EgressMode::L3PlusL7)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::{HostPort, NetworkPolicy};

    #[test]
    fn stub_start_returns_not_implemented() {
        let stub = StubEgressProxy;
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.anthropic.com", 443)]);
        let err = stub.start_for_vm("vm-1", &policy).unwrap_err();
        assert!(matches!(err, EgressProxyError::NotImplemented));
    }

    #[test]
    fn stub_stop_is_noop() {
        let stub = StubEgressProxy;
        let handle = ProxyHandle {
            vm_name: "vm-1".to_string(),
            listen_port: 0,
        };
        assert!(stub.stop_for_vm(&handle).is_ok());
    }

    #[test]
    fn requires_l7_only_for_l3_plus_l7() {
        assert!(!requires_l7(EgressMode::Open));
        assert!(!requires_l7(EgressMode::L3Only));
        assert!(requires_l7(EgressMode::L3PlusL7));
    }

    #[test]
    fn error_display_mentions_plan_34() {
        let s = EgressProxyError::NotImplemented.to_string();
        assert!(
            s.contains("plan 34"),
            "error message must point at follow-up plan, got: {s}"
        );
    }
}
