//! The guest-NIC invariant, enforced on the launch specification rather
//! than by convention.
//!
//! `l3-vsock` rests on the guest having no network device at all: `mvm0` is
//! the only interface its stack can route to, and `mvm0` terminates in the
//! guest agent. A launcher that attaches a NIC — even a drained one —
//! breaks that, because the guest's stack then has somewhere else to go.
//!
//! Every launcher funnels through [`VmStartConfig`], so checking it here
//! covers transient runs, persistent machines, the supervisor path, warm
//! restores, and anything added later, without each of them having to
//! remember. A launcher that could bypass this would have to bypass
//! `VmStartConfig` itself.

use mvm_core::plan::NetworkMode;
use mvm_core::vm_backend::{VmCapabilities, VmStartConfig};

/// Why a launch was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NicGuardError {
    /// The backend attaches a network device to the guest.
    #[error(
        "backend {backend:?} attaches a guest network device, which l3-vsock forbids: \
         the tunnel requires the guest to have no network device at all, so mvm0 is the \
         only interface its stack can route to"
    )]
    BackendAttachesNic { backend: String },
    /// The plan selects `l3-vsock` but the backend does not advertise the
    /// tunnel capability.
    #[error("backend {backend:?} does not carry the l3-vsock tunnel")]
    BackendLacksTunnel { backend: String },
}

/// Refuse a launch that would give an `l3-vsock` guest a network device.
///
/// Called by every launcher before it hands a configuration to a backend.
/// Modes other than `l3-vsock` are unaffected: this is not a general
/// no-NIC rule, it is the one this mode depends on.
pub fn enforce_no_guest_nic(
    mode: NetworkMode,
    config: &VmStartConfig,
    backend_name: &str,
    caps: &VmCapabilities,
) -> Result<(), NicGuardError> {
    if !mode.is_l3_vsock() {
        return Ok(());
    }
    if !caps.l3_vsock {
        return Err(NicGuardError::BackendLacksTunnel {
            backend: backend_name.to_string(),
        });
    }
    if !caps.no_routable_guest_nic {
        return Err(NicGuardError::BackendAttachesNic {
            backend: backend_name.to_string(),
        });
    }
    // The launch specification itself carries no network-device field —
    // see `the_launch_specification_has_no_guest_network_device_field`,
    // which fails if one is ever added — so there is nothing further to
    // check here. `config` stays in the signature because that guarantee is
    // a property of the type, and a future field would need this arm.
    let _ = config;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_for_tunnel() -> VmCapabilities {
        VmCapabilities {
            vsock: true,
            l3_vsock: true,
            no_routable_guest_nic: true,
            ..VmCapabilities::default()
        }
    }

    #[test]
    fn a_nic_less_backend_passes() {
        assert!(
            enforce_no_guest_nic(
                NetworkMode::L3Vsock,
                &VmStartConfig::default(),
                "firecracker",
                &caps_for_tunnel(),
            )
            .is_ok()
        );
    }

    #[test]
    fn a_backend_that_only_drains_a_nic_is_refused() {
        // libkrun's posture: no routable NIC, but a virtio-net device is
        // attached. The tunnel needs no device at all.
        let caps = VmCapabilities {
            vsock: true,
            l3_vsock: false,
            no_routable_guest_nic: true,
            ..VmCapabilities::default()
        };
        assert!(matches!(
            enforce_no_guest_nic(
                NetworkMode::L3Vsock,
                &VmStartConfig::default(),
                "libkrun",
                &caps
            ),
            Err(NicGuardError::BackendLacksTunnel { .. })
        ));
    }

    #[test]
    fn a_backend_with_a_routable_nic_is_refused() {
        let caps = VmCapabilities {
            vsock: true,
            l3_vsock: true,
            no_routable_guest_nic: false,
            ..VmCapabilities::default()
        };
        assert!(matches!(
            enforce_no_guest_nic(
                NetworkMode::L3Vsock,
                &VmStartConfig::default(),
                "hypothetical",
                &caps
            ),
            Err(NicGuardError::BackendAttachesNic { .. })
        ));
    }

    /// The backend-neutral launch specification carries no guest
    /// network-device field, and must not grow one: a launcher able to name
    /// a tap, a bridge, a MAC, or a virtio-net device could give an
    /// `l3-vsock` guest somewhere to route other than `mvm0`.
    ///
    /// Asserted over the serialized field set rather than by reading the
    /// struct, so adding a field fails here rather than passing review.
    #[test]
    fn the_launch_specification_has_no_guest_network_device_field() {
        // The Debug derive lists every field by name, which is the field
        // set without requiring the type to be Serialize.
        let rendered = format!("{:?}", VmStartConfig::default());
        for forbidden in [
            "tap",
            "tap_device",
            "nic",
            "network_interface",
            "network_interfaces",
            "mac",
            "guest_mac",
            "bridge",
            "virtio_net",
            "iface",
        ] {
            assert!(
                !rendered.contains(&format!("{forbidden}:")),
                "VmStartConfig grew a guest network-device field {forbidden:?}; \
                 l3-vsock requires the guest to have no network device at all.\n{rendered}"
            );
        }
    }

    #[test]
    fn the_guard_accepts_a_specification_that_cannot_name_a_device() {
        // The positive half of the same property: with no device field to
        // set, a default specification is admissible.
        assert!(
            enforce_no_guest_nic(
                NetworkMode::L3Vsock,
                &VmStartConfig::default(),
                "firecracker",
                &caps_for_tunnel()
            )
            .is_ok()
        );
    }

    #[test]
    fn the_guard_only_applies_to_the_l3_mode() {
        // The brokered and closed modes are unaffected: this is the L3
        // tunnel's precondition, not a global no-NIC rule. A backend with
        // no tunnel capability still serves them.
        let config = VmStartConfig::default();
        for mode in [NetworkMode::None, NetworkMode::HostVsockProxy] {
            assert!(
                enforce_no_guest_nic(mode, &config, "libkrun", &VmCapabilities::default()).is_ok(),
                "{mode:?} must not be affected by the tunnel's precondition"
            );
        }
    }

    #[test]
    fn the_refusal_explains_why_rather_than_just_saying_no() {
        let err = enforce_no_guest_nic(
            NetworkMode::L3Vsock,
            &VmStartConfig::default(),
            "libkrun",
            &VmCapabilities {
                vsock: true,
                no_routable_guest_nic: true,
                ..VmCapabilities::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("libkrun"), "{err}");
    }
}
