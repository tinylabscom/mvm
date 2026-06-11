//! Host-side firewall enforcement.
//!
//! The firewall is **additive enforcement** beneath the proxy: even
//! if the L4/L7 proxies' allow-list is misconfigured, the firewall's
//! default-deny on the runtime-VM TAP keeps stray packets from
//! escaping to the host's other interfaces. Defense in depth.
//!
//! ## Platforms
//!
//! - **Linux** (`linux_nft`) — `nftables`-based rules. Available
//!   today.
//! - **macOS** (`macos_pf`) — `pfctl` shell-out. Deferred; pf and
//!   WFP shell-outs are fragile.
//! - **Windows** (`windows_wfp`) — WFP via `windivert`. Deferred.
//!
//! Each platform ships its own rule-formatter + apply function;
//! the operator-facing surface stays uniform — pass the per-VM
//! TAP interface name + the proxy endpoint, get a fail-closed
//! firewall.

use thiserror::Error;

#[cfg(any(target_os = "linux", test))]
pub mod linux_nft;
/// Adapts `FirewallEnforcer` to `mvm_network::EgressEnforcer`.
pub mod seam;

/// Runtime VM firewall wiring. The TAP interface is the VM-facing
/// device; the proxy interface is the only allowed egress path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallSpec {
    pub vm_id: String,
    pub tap_iface: String,
    pub proxy_iface: String,
}

impl FirewallSpec {
    pub fn new(
        vm_id: impl Into<String>,
        tap_iface: impl Into<String>,
        proxy_iface: impl Into<String>,
    ) -> Self {
        Self {
            vm_id: vm_id.into(),
            tap_iface: tap_iface.into(),
            proxy_iface: proxy_iface.into(),
        }
    }

    /// Derive firewall wiring from the Firecracker backend's runtime
    /// slot metadata. `VmSlot` owns VM identity + TAP allocation; the
    /// supervisor still supplies the proxy interface because that is
    /// owned by the L4/L7 enforcement layer, not by the backend slot.
    pub fn from_vm_slot(
        slot: &mvm_backend::base::config::VmSlot,
        proxy_iface: impl Into<String>,
    ) -> Result<Self, FirewallError> {
        let spec = Self::new(&slot.name, &slot.tap_dev, proxy_iface);
        spec.validate()?;
        Ok(spec)
    }

    /// Validate identifiers before they reach platform-specific rule
    /// formatters. This duplicates the nft-side guard intentionally:
    /// supervisor wiring rejects unsafe runtime metadata before any
    /// backend-specific script generation is attempted.
    pub fn validate(&self) -> Result<(), FirewallError> {
        validate_slug("vm_id", &self.vm_id)?;
        validate_slug("tap_iface", &self.tap_iface)?;
        validate_slug("proxy_iface", &self.proxy_iface)?;
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FirewallError {
    #[error("firewall enforcer not wired (Noop slot)")]
    NotWired,
    #[error("invalid firewall spec field {field}: {value:?} (only [A-Za-z0-9_-] permitted)")]
    InvalidSpec { field: &'static str, value: String },
    #[error("firewall backend failed: {0}")]
    Backend(String),
}

/// Host-side network enforcement boundary. Implementations install
/// default-deny rules before a runtime VM can emit packets, and remove
/// the VM-scoped rules during teardown.
pub trait FirewallEnforcer: Send + Sync {
    fn install_default_deny(&self, spec: &FirewallSpec) -> Result<(), FirewallError>;
    fn teardown(&self, vm_id: &str) -> Result<(), FirewallError>;
}

/// Fail-closed default: a supervisor that forgets to wire a platform
/// firewall fails loudly instead of booting with silent host egress.
#[derive(Debug, Default)]
pub struct NoopFirewallEnforcer;

impl FirewallEnforcer for NoopFirewallEnforcer {
    fn install_default_deny(&self, _spec: &FirewallSpec) -> Result<(), FirewallError> {
        Err(FirewallError::NotWired)
    }

    fn teardown(&self, _vm_id: &str) -> Result<(), FirewallError> {
        Err(FirewallError::NotWired)
    }
}

fn validate_slug(field: &'static str, value: &str) -> Result<(), FirewallError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(FirewallError::InvalidSpec {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_spec_keeps_vm_and_interface_names_separate() {
        let spec = FirewallSpec::new("vm1", "mvmtap0", "mvmtun0");
        assert_eq!(spec.vm_id, "vm1");
        assert_eq!(spec.tap_iface, "mvmtap0");
        assert_eq!(spec.proxy_iface, "mvmtun0");
    }

    #[test]
    fn firewall_spec_derives_from_vm_slot() {
        let slot = mvm_backend::base::config::VmSlot::new("worker-1", 7);
        let spec = FirewallSpec::from_vm_slot(&slot, "mvmtun0").expect("valid slot");

        assert_eq!(spec.vm_id, "worker-1");
        assert_eq!(spec.tap_iface, "tap7");
        assert_eq!(spec.proxy_iface, "mvmtun0");
    }

    #[test]
    fn firewall_spec_from_vm_slot_rejects_unsafe_proxy_iface() {
        let slot = mvm_backend::base::config::VmSlot::new("worker-1", 7);
        let err = FirewallSpec::from_vm_slot(&slot, "tun; rm").unwrap_err();

        assert!(matches!(
            err,
            FirewallError::InvalidSpec {
                field: "proxy_iface",
                ..
            }
        ));
    }

    #[test]
    fn firewall_spec_from_vm_slot_rejects_unsafe_vm_name() {
        let slot = mvm_backend::base::config::VmSlot::new("worker/1", 7);
        let err = FirewallSpec::from_vm_slot(&slot, "mvmtun0").unwrap_err();

        assert!(matches!(
            err,
            FirewallError::InvalidSpec { field: "vm_id", .. }
        ));
    }

    #[test]
    fn noop_firewall_fails_closed_on_install_and_teardown() {
        let firewall = NoopFirewallEnforcer;
        let spec = FirewallSpec::new("vm1", "mvmtap0", "mvmtun0");

        assert_eq!(
            firewall.install_default_deny(&spec).unwrap_err(),
            FirewallError::NotWired
        );
        assert_eq!(
            firewall.teardown("vm1").unwrap_err(),
            FirewallError::NotWired
        );
    }
}
