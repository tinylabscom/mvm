//! `SupervisorEgressEnforcer` — adapts the supervisor's [`FirewallEnforcer`]
//! to the low [`mvm_network::EgressEnforcer`] seam.
//!
//! Pure plumbing: it maps the seam's `EgressWiring` onto a [`FirewallSpec`]
//! and delegates `enforce`→`install_default_deny`, `withdraw`→`teardown`,
//! translating [`FirewallError`] into `EnforcementError` so the fail-closed
//! `NotWired` posture survives the seam. This adapter exists without
//! changing any live call path; `Supervisor::launch` is rerouted through it
//! separately.

use std::sync::Arc;

use mvm_core::network_policy::NetworkPolicy;
use mvm_network::{EgressEnforcer, EgressWiring, EnforcementError};

use super::{FirewallEnforcer, FirewallError, FirewallSpec};

/// Drives the host nftables firewall behind the `EgressEnforcer` seam.
pub struct SupervisorEgressEnforcer {
    firewall: Arc<dyn FirewallEnforcer>,
}

impl SupervisorEgressEnforcer {
    pub fn new(firewall: Arc<dyn FirewallEnforcer>) -> Self {
        Self { firewall }
    }
}

impl EgressEnforcer for SupervisorEgressEnforcer {
    fn enforce(
        &self,
        wiring: &EgressWiring,
        _policy: &NetworkPolicy,
    ) -> Result<(), EnforcementError> {
        // The firewall installs a fixed default-deny on the TAP regardless of
        // policy; the policy's allow-rules are the L4/L7 layer's job,
        // so `_policy` is reserved on the seam, not silently dropped.
        let spec = FirewallSpec::new(&wiring.vm_id, &wiring.tap_iface, &wiring.proxy_iface);
        self.firewall
            .install_default_deny(&spec)
            .map_err(firewall_to_enforcement)
    }

    fn withdraw(&self, vm_id: &str) -> Result<(), EnforcementError> {
        self.firewall
            .teardown(vm_id)
            .map_err(firewall_to_enforcement)
    }
}

fn firewall_to_enforcement(err: FirewallError) -> EnforcementError {
    match err {
        FirewallError::NotWired => EnforcementError::NotWired,
        FirewallError::InvalidSpec { field, value } => {
            EnforcementError::Rejected(format!("{field}: {value:?}"))
        }
        FirewallError::Backend(m) => EnforcementError::Backend(m),
    }
}

#[cfg(test)]
mod tests {
    use super::super::NoopFirewallEnforcer;
    use super::*;
    use std::sync::Mutex;

    fn wiring() -> EgressWiring {
        EgressWiring {
            vm_id: "vm-a".into(),
            tap_iface: "tap0".into(),
            proxy_iface: "eth0".into(),
        }
    }

    /// Records forwarded calls so we can assert the adapter passes the wiring
    /// through intact.
    #[derive(Default)]
    struct RecordingFirewall {
        installed: Mutex<Vec<FirewallSpec>>,
        torn_down: Mutex<Vec<String>>,
    }
    impl FirewallEnforcer for RecordingFirewall {
        fn install_default_deny(&self, spec: &FirewallSpec) -> Result<(), FirewallError> {
            self.installed.lock().unwrap().push(spec.clone());
            Ok(())
        }
        fn teardown(&self, vm_id: &str) -> Result<(), FirewallError> {
            self.torn_down.lock().unwrap().push(vm_id.to_string());
            Ok(())
        }
    }

    #[test]
    fn adapter_forwards_wiring_to_firewall() {
        let fw = Arc::new(RecordingFirewall::default());
        let enforcer = SupervisorEgressEnforcer::new(fw.clone());

        enforcer
            .enforce(&wiring(), &NetworkPolicy::deny_all())
            .unwrap();
        let installed = fw.installed.lock().unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0], FirewallSpec::new("vm-a", "tap0", "eth0"));
        drop(installed);

        enforcer.withdraw("vm-a").unwrap();
        assert_eq!(&*fw.torn_down.lock().unwrap(), &["vm-a".to_string()]);
    }

    #[test]
    fn adapter_preserves_fail_closed_not_wired() {
        // A Noop firewall must surface as NotWired through the seam — never a
        // silent success that would boot a VM with open host egress.
        let enforcer = SupervisorEgressEnforcer::new(Arc::new(NoopFirewallEnforcer));
        assert!(matches!(
            enforcer.enforce(&wiring(), &NetworkPolicy::deny_all()),
            Err(EnforcementError::NotWired)
        ));
        assert!(matches!(
            enforcer.withdraw("vm-a"),
            Err(EnforcementError::NotWired)
        ));
    }
}
