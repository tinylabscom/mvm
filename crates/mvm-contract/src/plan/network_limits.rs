//! Signed per-workload networking resource ceilings.
//!
//! `NetworkLimits` is the transport-neutral, plan-admitted ceiling set every
//! networking runtime enforces: flow counts, DNS bindings, ingress listeners,
//! and the per-stream credit window. Its defaults and its upper bounds are the
//! FlowMux protocol ceilings in [`crate::protocol::network_flow`], so the plan
//! type and the wire protocol share one source of truth and a signed plan can
//! only ever narrow what the protocol permits.

use serde::{Deserialize, Serialize};

use crate::protocol::network_flow::{
    MAX_DNS_BINDINGS, MAX_INGRESS_LISTENERS, MAX_STREAM_CREDIT, MAX_TCP_FLOWS, MAX_UDP_ASSOCIATIONS,
};

/// Transport-neutral per-workload networking resource ceilings.
///
/// These limits are part of the signed execution plan. A runtime may enforce
/// a lower host ceiling, but it may never raise one of these values after
/// admission. Each default is the corresponding FlowMux protocol ceiling from
/// [`crate::protocol::network_flow`], so the plan type cannot drift from the
/// bounds the wire protocol enforces, and a plan may only ever narrow them.
/// The defaults preserve the bounds of plans authored before this type
/// existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkLimits {
    /// Aggregate concurrent TCP and typed-HTTP flows.
    #[serde(
        default = "NetworkLimits::default_max_tcp_flows",
        skip_serializing_if = "NetworkLimits::is_default_max_tcp_flows"
    )]
    pub max_tcp_flows: u32,
    /// Concurrent UDP associations.
    #[serde(
        default = "NetworkLimits::default_max_udp_associations",
        skip_serializing_if = "NetworkLimits::is_default_max_udp_associations"
    )]
    pub max_udp_associations: u32,
    /// Live host-owned DNS bindings.
    #[serde(
        default = "NetworkLimits::default_max_dns_bindings",
        skip_serializing_if = "NetworkLimits::is_default_max_dns_bindings"
    )]
    pub max_dns_bindings: u32,
    /// Declared ingress listeners.
    #[serde(
        default = "NetworkLimits::default_max_ingress_listeners",
        skip_serializing_if = "NetworkLimits::is_default_max_ingress_listeners"
    )]
    pub max_ingress_listeners: u16,
    /// Most send credit a single stream may accumulate, in bytes. The window
    /// is plan-admitted like the count ceilings so the endpoint's worst-case
    /// flow-state memory follows the signed plan rather than the protocol
    /// maximum alone.
    #[serde(
        default = "NetworkLimits::default_max_stream_credit_bytes",
        skip_serializing_if = "NetworkLimits::is_default_max_stream_credit_bytes"
    )]
    pub max_stream_credit_bytes: u32,
}

impl NetworkLimits {
    /// Start a validated limits builder from the compatibility defaults.
    #[must_use]
    pub const fn builder() -> NetworkLimitsBuilder {
        NetworkLimitsBuilder {
            limits: Self::defaults(),
        }
    }

    /// Whether every field has its compatibility default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Validate ceilings decoded from an untrusted or persisted wire value.
    /// Construction through the builder already calls this; runtime consumers
    /// call it again at their boundary so serde cannot bypass the invariant.
    ///
    /// A ceiling above the protocol maximum is refused, not clamped: the wire
    /// state machine and the endpoint cannot enforce more than the protocol
    /// permits, so silently narrowing an over-large ask would admit a plan
    /// whose signed bytes promise something the runtime never granted.
    pub fn validate(self) -> Result<Self, NetworkLimitsError> {
        if self.max_tcp_flows == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_tcp_flows",
            });
        }
        if self.max_udp_associations == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_udp_associations",
            });
        }
        if self.max_dns_bindings == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_dns_bindings",
            });
        }
        if self.max_ingress_listeners == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_ingress_listeners",
            });
        }
        if self.max_stream_credit_bytes == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_stream_credit_bytes",
            });
        }
        if self.max_tcp_flows > Self::default_max_tcp_flows() {
            return Err(NetworkLimitsError::ExceedsProtocolMax {
                field: "max_tcp_flows",
                requested: u64::from(self.max_tcp_flows),
                max: u64::from(Self::default_max_tcp_flows()),
            });
        }
        if self.max_udp_associations > Self::default_max_udp_associations() {
            return Err(NetworkLimitsError::ExceedsProtocolMax {
                field: "max_udp_associations",
                requested: u64::from(self.max_udp_associations),
                max: u64::from(Self::default_max_udp_associations()),
            });
        }
        if self.max_dns_bindings > Self::default_max_dns_bindings() {
            return Err(NetworkLimitsError::ExceedsProtocolMax {
                field: "max_dns_bindings",
                requested: u64::from(self.max_dns_bindings),
                max: u64::from(Self::default_max_dns_bindings()),
            });
        }
        if self.max_ingress_listeners > Self::default_max_ingress_listeners() {
            return Err(NetworkLimitsError::ExceedsProtocolMax {
                field: "max_ingress_listeners",
                requested: u64::from(self.max_ingress_listeners),
                max: u64::from(Self::default_max_ingress_listeners()),
            });
        }
        if self.max_stream_credit_bytes > Self::default_max_stream_credit_bytes() {
            return Err(NetworkLimitsError::ExceedsProtocolMax {
                field: "max_stream_credit_bytes",
                requested: u64::from(self.max_stream_credit_bytes),
                max: u64::from(Self::default_max_stream_credit_bytes()),
            });
        }
        Ok(self)
    }

    /// Worst-case bytes the endpoint may hold for flow state, ignoring payload
    /// buffers: every admitted stream at its admitted maximum credit window.
    ///
    /// Derived from the admitted ceilings rather than the protocol maximums so
    /// lowering a ceiling lowers the bound with it. At the defaults this
    /// reproduces the protocol-level
    /// [`crate::protocol::network_flow::MAX_FLOW_CREDIT_BYTES`]. The multiply
    /// saturates: an unvalidated value that overflowed would read as headroom,
    /// never as a wrapped small bound.
    #[must_use]
    pub const fn worst_case_flow_state_bytes(&self) -> u64 {
        (self.max_tcp_flows as u64
            + self.max_udp_associations as u64
            + self.max_ingress_listeners as u64)
            .saturating_mul(self.max_stream_credit_bytes as u64)
    }

    const fn defaults() -> Self {
        Self {
            max_tcp_flows: Self::default_max_tcp_flows(),
            max_udp_associations: Self::default_max_udp_associations(),
            max_dns_bindings: Self::default_max_dns_bindings(),
            max_ingress_listeners: Self::default_max_ingress_listeners(),
            max_stream_credit_bytes: Self::default_max_stream_credit_bytes(),
        }
    }

    const fn default_max_tcp_flows() -> u32 {
        MAX_TCP_FLOWS as u32
    }

    const fn default_max_udp_associations() -> u32 {
        MAX_UDP_ASSOCIATIONS as u32
    }

    const fn default_max_dns_bindings() -> u32 {
        MAX_DNS_BINDINGS as u32
    }

    const fn default_max_ingress_listeners() -> u16 {
        MAX_INGRESS_LISTENERS as u16
    }

    const fn default_max_stream_credit_bytes() -> u32 {
        MAX_STREAM_CREDIT
    }

    fn is_default_max_tcp_flows(value: &u32) -> bool {
        *value == Self::default_max_tcp_flows()
    }

    fn is_default_max_udp_associations(value: &u32) -> bool {
        *value == Self::default_max_udp_associations()
    }

    fn is_default_max_dns_bindings(value: &u32) -> bool {
        *value == Self::default_max_dns_bindings()
    }

    fn is_default_max_ingress_listeners(value: &u16) -> bool {
        *value == Self::default_max_ingress_listeners()
    }

    fn is_default_max_stream_credit_bytes(value: &u32) -> bool {
        *value == Self::default_max_stream_credit_bytes()
    }
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Builder for a validated [`NetworkLimits`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkLimitsBuilder {
    limits: NetworkLimits,
}

impl NetworkLimitsBuilder {
    /// Set the aggregate TCP/HTTP flow ceiling.
    #[must_use]
    pub const fn max_tcp_flows(mut self, value: u32) -> Self {
        self.limits.max_tcp_flows = value;
        self
    }

    /// Set the UDP-association ceiling.
    #[must_use]
    pub const fn max_udp_associations(mut self, value: u32) -> Self {
        self.limits.max_udp_associations = value;
        self
    }

    /// Set the DNS-binding ceiling.
    #[must_use]
    pub const fn max_dns_bindings(mut self, value: u32) -> Self {
        self.limits.max_dns_bindings = value;
        self
    }

    /// Set the ingress-listener ceiling.
    #[must_use]
    pub const fn max_ingress_listeners(mut self, value: u16) -> Self {
        self.limits.max_ingress_listeners = value;
        self
    }

    /// Set the per-stream credit window ceiling, in bytes.
    #[must_use]
    pub const fn max_stream_credit_bytes(mut self, value: u32) -> Self {
        self.limits.max_stream_credit_bytes = value;
        self
    }

    /// Validate that every resource class retains a non-zero ceiling at or
    /// below its protocol maximum.
    pub fn build(self) -> Result<NetworkLimits, NetworkLimitsError> {
        self.limits.validate()
    }
}

/// Invalid signed networking limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetworkLimitsError {
    /// A zero ceiling would make a granted networking class unusable.
    #[error("network limit {field} must be greater than zero")]
    Zero { field: &'static str },
    /// A ceiling above the protocol maximum cannot be enforced by the wire
    /// state machine or the endpoint, so the plan is refused rather than
    /// clamped.
    #[error("network limit {field} must not exceed the protocol maximum of {max}, got {requested}")]
    ExceedsProtocolMax {
        field: &'static str,
        requested: u64,
        max: u64,
    },
}

#[cfg(test)]
mod network_limits_tests {
    use super::*;
    use crate::protocol::network_flow::MAX_FLOW_CREDIT_BYTES;

    #[test]
    fn defaults_match_the_existing_endpoint_ceilings() {
        let limits = NetworkLimits::default();
        assert_eq!(limits.max_tcp_flows, 4096);
        assert_eq!(limits.max_udp_associations, 256);
        assert_eq!(limits.max_dns_bindings, 1024);
        assert_eq!(limits.max_ingress_listeners, 16);
        assert_eq!(limits.max_stream_credit_bytes, 64 * 64 * 1024);
    }

    /// The plan type must not restate the wire protocol's ceilings beside
    /// them: each default IS the protocol constant, so raising a protocol
    /// ceiling moves the plan default with it.
    #[test]
    fn defaults_are_the_protocol_ceilings() {
        let limits = NetworkLimits::default();
        assert_eq!(limits.max_tcp_flows, MAX_TCP_FLOWS as u32);
        assert_eq!(limits.max_udp_associations, MAX_UDP_ASSOCIATIONS as u32);
        assert_eq!(limits.max_dns_bindings, MAX_DNS_BINDINGS as u32);
        assert_eq!(limits.max_ingress_listeners, MAX_INGRESS_LISTENERS as u16);
        assert_eq!(limits.max_stream_credit_bytes, MAX_STREAM_CREDIT);
    }

    #[test]
    fn default_fields_are_omitted_and_roundtrip() {
        let json = serde_json::to_string(&NetworkLimits::default()).unwrap();
        assert_eq!(json, "{}");
        assert_eq!(
            serde_json::from_str::<NetworkLimits>(&json).unwrap(),
            NetworkLimits::default()
        );
    }

    /// Byte-stability for plans signed before `max_stream_credit_bytes`
    /// existed: the field defaults to the protocol ceiling when absent and is
    /// omitted again on re-serialization, so the signed bytes are unchanged.
    #[test]
    fn a_plan_without_stream_credit_deserializes_to_the_default_and_reserializes_identically() {
        let old = r#"{"max_tcp_flows":100}"#;
        let decoded: NetworkLimits = serde_json::from_str(old).unwrap();
        assert_eq!(decoded.max_tcp_flows, 100);
        assert_eq!(decoded.max_stream_credit_bytes, MAX_STREAM_CREDIT);
        assert_eq!(serde_json::to_string(&decoded).unwrap(), old);
    }

    /// A narrowed credit window is signed into the plan and round-trips.
    #[test]
    fn a_non_default_stream_credit_is_carried_on_the_wire() {
        let limits = NetworkLimits::builder()
            .max_stream_credit_bytes(1024)
            .build()
            .unwrap();
        let json = serde_json::to_string(&limits).unwrap();
        assert_eq!(json, r#"{"max_stream_credit_bytes":1024}"#);
        assert_eq!(
            serde_json::from_str::<NetworkLimits>(&json).unwrap(),
            limits
        );
    }

    #[test]
    fn builder_preserves_custom_values() {
        let limits = NetworkLimits::builder()
            .max_tcp_flows(12)
            .max_udp_associations(13)
            .max_dns_bindings(14)
            .max_ingress_listeners(15)
            .max_stream_credit_bytes(16)
            .build()
            .unwrap();
        assert_eq!(limits.max_tcp_flows, 12);
        assert_eq!(limits.max_udp_associations, 13);
        assert_eq!(limits.max_dns_bindings, 14);
        assert_eq!(limits.max_ingress_listeners, 15);
        assert_eq!(limits.max_stream_credit_bytes, 16);
    }

    #[test]
    fn builder_refuses_zero_for_every_resource_class() {
        for result in [
            NetworkLimits::builder().max_tcp_flows(0).build(),
            NetworkLimits::builder().max_udp_associations(0).build(),
            NetworkLimits::builder().max_dns_bindings(0).build(),
            NetworkLimits::builder().max_ingress_listeners(0).build(),
            NetworkLimits::builder().max_stream_credit_bytes(0).build(),
        ] {
            assert!(matches!(result, Err(NetworkLimitsError::Zero { .. })));
        }
    }

    #[test]
    fn validation_refuses_a_zero_decoded_by_serde() {
        let decoded: NetworkLimits = serde_json::from_str(r#"{"max_tcp_flows":0}"#).unwrap();
        assert_eq!(
            decoded.validate(),
            Err(NetworkLimitsError::Zero {
                field: "max_tcp_flows"
            })
        );
    }

    /// Every ceiling at exactly its protocol maximum is admitted.
    #[test]
    fn validation_admits_every_ceiling_at_its_protocol_maximum() {
        let limits = NetworkLimits::builder()
            .max_tcp_flows(MAX_TCP_FLOWS as u32)
            .max_udp_associations(MAX_UDP_ASSOCIATIONS as u32)
            .max_dns_bindings(MAX_DNS_BINDINGS as u32)
            .max_ingress_listeners(MAX_INGRESS_LISTENERS as u16)
            .max_stream_credit_bytes(MAX_STREAM_CREDIT)
            .build()
            .unwrap();
        assert_eq!(limits, NetworkLimits::default());
    }

    /// One past the protocol maximum is a refusal naming the field, the ask,
    /// and the maximum — never a silent clamp.
    #[test]
    fn validation_refuses_every_ceiling_one_past_its_protocol_maximum() {
        let cases: [(NetworkLimits, &'static str, u64, u64); 5] = [
            (
                NetworkLimits {
                    max_tcp_flows: MAX_TCP_FLOWS as u32 + 1,
                    ..NetworkLimits::default()
                },
                "max_tcp_flows",
                MAX_TCP_FLOWS as u64 + 1,
                MAX_TCP_FLOWS as u64,
            ),
            (
                NetworkLimits {
                    max_udp_associations: MAX_UDP_ASSOCIATIONS as u32 + 1,
                    ..NetworkLimits::default()
                },
                "max_udp_associations",
                MAX_UDP_ASSOCIATIONS as u64 + 1,
                MAX_UDP_ASSOCIATIONS as u64,
            ),
            (
                NetworkLimits {
                    max_dns_bindings: MAX_DNS_BINDINGS as u32 + 1,
                    ..NetworkLimits::default()
                },
                "max_dns_bindings",
                MAX_DNS_BINDINGS as u64 + 1,
                MAX_DNS_BINDINGS as u64,
            ),
            (
                NetworkLimits {
                    max_ingress_listeners: MAX_INGRESS_LISTENERS as u16 + 1,
                    ..NetworkLimits::default()
                },
                "max_ingress_listeners",
                MAX_INGRESS_LISTENERS as u64 + 1,
                MAX_INGRESS_LISTENERS as u64,
            ),
            (
                NetworkLimits {
                    max_stream_credit_bytes: MAX_STREAM_CREDIT + 1,
                    ..NetworkLimits::default()
                },
                "max_stream_credit_bytes",
                u64::from(MAX_STREAM_CREDIT) + 1,
                u64::from(MAX_STREAM_CREDIT),
            ),
        ];
        for (limits, field, requested, max) in cases {
            assert_eq!(
                limits.validate(),
                Err(NetworkLimitsError::ExceedsProtocolMax {
                    field,
                    requested,
                    max
                }),
                "{field} one past the protocol maximum must be refused"
            );
        }
    }

    /// An over-large ask arriving off the wire is refused at the same
    /// boundary the builder enforces.
    #[test]
    fn validation_refuses_an_over_max_ceiling_decoded_by_serde() {
        let decoded: NetworkLimits =
            serde_json::from_str(r#"{"max_udp_associations":257}"#).unwrap();
        let err = decoded.validate().unwrap_err();
        assert_eq!(
            err,
            NetworkLimitsError::ExceedsProtocolMax {
                field: "max_udp_associations",
                requested: 257,
                max: 256,
            }
        );
        let message = err.to_string();
        assert!(message.contains("max_udp_associations"), "{message}");
        assert!(message.contains("257"), "{message}");
        assert!(message.contains("256"), "{message}");
    }

    /// The endpoint's worst-case flow-state memory is derived from the
    /// admitted ceilings: at the defaults it is exactly the protocol-level
    /// bound, and narrowing any ceiling narrows the bound with it.
    #[test]
    fn the_worst_case_flow_state_bound_follows_the_admitted_ceilings() {
        let default = NetworkLimits::default();
        assert_eq!(default.worst_case_flow_state_bytes(), MAX_FLOW_CREDIT_BYTES);

        let fewer_flows = NetworkLimits::builder().max_tcp_flows(8).build().unwrap();
        assert!(
            fewer_flows.worst_case_flow_state_bytes() < default.worst_case_flow_state_bytes(),
            "lowering a flow ceiling must lower the bound"
        );

        let narrower_window = NetworkLimits::builder()
            .max_stream_credit_bytes(MAX_STREAM_CREDIT / 2)
            .build()
            .unwrap();
        assert_eq!(
            narrower_window.worst_case_flow_state_bytes(),
            MAX_FLOW_CREDIT_BYTES / 2,
            "halving the admitted credit window must halve the bound"
        );
    }
}
