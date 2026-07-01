//! Host ingress-broker decision logic.
//!
//! The closed-by-default mirror of [`crate::egress_broker`]: a guest gets no
//! exposed NIC or TCP listener, so inbound access exists only where the signed
//! plan declares an ingress route. The host `mvm-ingress-broker` opens a
//! listener only for a declared route and forwards it over vsock to the guest
//! service; an inbound on any undeclared port is denied. This module is the
//! pure decision — which listeners to open, and whether an inbound is admitted.

/// A declared inbound route: a host listener port forwarded over vsock to a
/// guest service port. The only way inbound reaches a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRoute {
    pub listen_port: u16,
    pub guest_port: u16,
}

/// The workload's ingress policy: the set of declared routes. Empty = no
/// inbound at all (closed by default).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressPolicy {
    pub routes: Vec<IngressRoute>,
}

impl IngressPolicy {
    /// No inbound access.
    pub fn deny_all() -> Self {
        Self { routes: Vec::new() }
    }

    pub fn with_routes(routes: Vec<IngressRoute>) -> Self {
        Self { routes }
    }

    /// The host listener ports to open — exactly the declared routes, nothing
    /// more. The host opens no listener for which there is no route.
    pub fn listener_ports(&self) -> Vec<u16> {
        self.routes.iter().map(|r| r.listen_port).collect()
    }
}

/// Why an inbound connection was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressDenyReason {
    /// The policy declares no routes — closed by default.
    DenyAll,
    /// The policy has routes, but none for this listener port.
    NoMatchingRoute,
}

impl IngressDenyReason {
    pub const fn label(self) -> &'static str {
        match self {
            IngressDenyReason::DenyAll => "deny_all",
            IngressDenyReason::NoMatchingRoute => "no_matching_route",
        }
    }
}

/// The broker's verdict for an inbound connection on a listener port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressVerdict {
    /// Admitted; forward to the guest over vsock per this route.
    Allowed { route: IngressRoute },
    /// Denied, with the reason for the audit log.
    Denied { reason: IngressDenyReason },
}

impl IngressVerdict {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, IngressVerdict::Allowed { .. })
    }
}

/// Decide whether an inbound connection on `listen_port` is admitted. Closed by
/// default: an empty policy denies, and only a declared route admits (mapping
/// to the guest service port).
pub fn decide_ingress(policy: &IngressPolicy, listen_port: u16) -> IngressVerdict {
    if policy.routes.is_empty() {
        return IngressVerdict::Denied {
            reason: IngressDenyReason::DenyAll,
        };
    }
    match policy
        .routes
        .iter()
        .find(|route| route.listen_port == listen_port)
    {
        Some(&route) => IngressVerdict::Allowed { route },
        None => IngressVerdict::Denied {
            reason: IngressDenyReason::NoMatchingRoute,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_denies_any_inbound() {
        let verdict = decide_ingress(&IngressPolicy::deny_all(), 8080);
        assert_eq!(
            verdict,
            IngressVerdict::Denied {
                reason: IngressDenyReason::DenyAll
            }
        );
    }

    #[test]
    fn declared_route_admits_and_maps_to_guest_port() {
        let policy = IngressPolicy::with_routes(vec![IngressRoute {
            listen_port: 8080,
            guest_port: 80,
        }]);
        let verdict = decide_ingress(&policy, 8080);
        assert_eq!(
            verdict,
            IngressVerdict::Allowed {
                route: IngressRoute {
                    listen_port: 8080,
                    guest_port: 80
                }
            }
        );
        assert!(verdict.is_allowed());
    }

    #[test]
    fn undeclared_port_is_denied_even_with_other_routes() {
        let policy = IngressPolicy::with_routes(vec![IngressRoute {
            listen_port: 8080,
            guest_port: 80,
        }]);
        assert_eq!(
            decide_ingress(&policy, 9090),
            IngressVerdict::Denied {
                reason: IngressDenyReason::NoMatchingRoute
            }
        );
    }

    #[test]
    fn listener_ports_are_exactly_the_declared_routes() {
        let policy = IngressPolicy::with_routes(vec![
            IngressRoute {
                listen_port: 8080,
                guest_port: 80,
            },
            IngressRoute {
                listen_port: 8443,
                guest_port: 443,
            },
        ]);
        assert_eq!(policy.listener_ports(), vec![8080, 8443]);
        assert!(IngressPolicy::deny_all().listener_ports().is_empty());
    }
}
