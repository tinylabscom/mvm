//! What each side of a control session says about itself inside the
//! authenticated handshake: the guest's protocol range, build version and
//! served capability set, and the host's protocol range.
//!
//! The advertisement narrows what the host is willing to send. It never feeds
//! an authorization decision: a guest that claims more than it serves only
//! widens what the host may attempt, and the guest's own profile gate, signed
//! grants and seccomp tier still decide what runs. A guest that claims less
//! only costs itself requests.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Longest `agent_version` a peer may advertise. The field is informational,
/// so anything longer is treated as malformed rather than truncated.
pub const MAX_AGENT_VERSION_LEN: usize = 64;

/// Guest-agent control protocol capability. Closed enum so host and
/// guest fail loudly on drift instead of accepting arbitrary strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum GuestCapability {
    Ping,
    ResourceUsage,
    IntegrationStatus,
    EntrypointStatus,
    RunEntrypoint,
    /// `AgentPrompt`: one prompt to the image's resident agent.
    AgentPrompt,
    Drive,
    RunExtension,
    FilesystemRpc,
    ProcessRpc,
    /// Legacy request, always refused rather than treated as an ordinary exec.
    Console,
    /// Unix-domain socket forwarding (`StartUnixSocketForward`). Not an SSH
    /// session capability — no SSH client/server or key material crosses the
    /// guest boundary.
    UnixSocketForward,
    VolumeMount,
    UpdateIdleTimeout,
    /// `ReadinessStatus` returns
    /// `GuestResponse::ReadinessStatusReport(ReadinessReport)`.
    /// `mvmctl machine wait` / `mvmctl machine boot-report` require this capability.
    Readiness,
}

/// Required remediation for a host/guest protocol mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ProtocolUpgradeAction {
    UpgradeHost,
    RebuildGuest,
}

/// The guest's advertisement, carried in `SessionHelloAck` and therefore
/// covered by both the guest's handshake proof and the host's transcript
/// signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlOffer {
    /// Newest control protocol the guest speaks.
    pub protocol_version: u32,
    /// Oldest control protocol the guest speaks.
    pub min_supported_version: u32,
    /// Guest agent build version. Informational; never authorizes anything.
    pub agent_version: String,
    /// Capabilities the guest serves.
    pub capabilities: BTreeSet<GuestCapability>,
}

/// The host's protocol range, carried in `SessionHelloConfirm`. It is not
/// covered by the transcript signature: a forged range can only make the
/// guest refuse, never accept something the host did not offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRange {
    /// Newest control protocol the host speaks.
    pub protocol_version: u32,
    /// Oldest control protocol the host speaks.
    pub min_supported_version: u32,
}

/// A typed refusal at the handshake: the two sides share no control protocol,
/// or one side offered no advertisement at all. It names the remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlMismatch {
    /// Newest protocol the host speaks; `0` when the host sent no range.
    pub host_protocol_version: u32,
    /// Newest protocol the guest speaks; `0` when the guest sent no offer.
    pub agent_protocol_version: u32,
    /// What the operator has to change.
    pub required_action: ProtocolUpgradeAction,
    /// Operator-facing text naming the remedy.
    pub message: String,
}

impl core::fmt::Display for ControlMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({:?})", self.message, self.required_action)
    }
}

fn ranges_overlap(a_min: u32, a_max: u32, b_min: u32, b_max: u32) -> bool {
    a_min <= b_max && b_min <= a_max
}

impl ControlRange {
    /// Reject a range that contradicts itself.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_supported_version > self.protocol_version {
            return Err(format!(
                "control range minimum {} exceeds its maximum {}",
                self.min_supported_version, self.protocol_version
            ));
        }
        Ok(())
    }

    /// Whether the two ranges share a protocol; otherwise the remedy.
    ///
    /// A host whose newest protocol is below the guest's oldest has to be
    /// upgraded. A host whose oldest protocol is above the guest's newest
    /// means the guest is too old, and the remedy is rebuilding it.
    pub fn check(&self, offer: &ControlOffer) -> Result<(), ControlMismatch> {
        if ranges_overlap(
            self.min_supported_version,
            self.protocol_version,
            offer.min_supported_version,
            offer.protocol_version,
        ) {
            return Ok(());
        }
        let required_action = if self.protocol_version < offer.min_supported_version {
            ProtocolUpgradeAction::UpgradeHost
        } else {
            ProtocolUpgradeAction::RebuildGuest
        };
        Err(ControlMismatch {
            host_protocol_version: self.protocol_version,
            agent_protocol_version: offer.protocol_version,
            required_action,
            message: format!(
                "guest-agent protocol mismatch: host supports {}..={}, agent supports {}..={}",
                self.min_supported_version,
                self.protocol_version,
                offer.min_supported_version,
                offer.protocol_version
            ),
        })
    }

    /// The refusal for a guest whose ack carried no advertisement: it
    /// predates the negotiated control protocol.
    pub fn refusal_without_offer(&self) -> ControlMismatch {
        ControlMismatch {
            host_protocol_version: self.protocol_version,
            agent_protocol_version: 0,
            required_action: ProtocolUpgradeAction::RebuildGuest,
            message: format!(
                "guest agent predates control protocol {}: it advertised no protocol range or \
                 capabilities; rebuild the guest runtime (`mvmctl bootstrap`) or relaunch with a \
                 matching image",
                self.protocol_version
            ),
        }
    }
}

impl ControlOffer {
    /// Reject an advertisement that contradicts itself or carries an
    /// unbounded free-text field.
    pub fn validate(&self) -> Result<(), String> {
        self.range().validate()?;
        if self.agent_version.len() > MAX_AGENT_VERSION_LEN
            || self.agent_version.chars().any(char::is_control)
        {
            return Err(format!(
                "agent_version must be at most {MAX_AGENT_VERSION_LEN} bytes with no control characters"
            ));
        }
        Ok(())
    }

    /// The protocol range this offer covers.
    pub fn range(&self) -> ControlRange {
        ControlRange {
            protocol_version: self.protocol_version,
            min_supported_version: self.min_supported_version,
        }
    }

    /// Whether the guest says it serves `capability`.
    pub fn advertises(&self, capability: GuestCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// The refusal a guest raises when the host's confirm carried no range: the
/// host predates the negotiated control protocol.
pub fn refusal_without_host_range(guest: &ControlOffer) -> ControlMismatch {
    ControlMismatch {
        host_protocol_version: 0,
        agent_protocol_version: guest.protocol_version,
        required_action: ProtocolUpgradeAction::UpgradeHost,
        message: format!(
            "host sent no control protocol range; this guest agent speaks {}..={}: upgrade mvmctl",
            guest.min_supported_version, guest.protocol_version
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(min: u32, max: u32) -> ControlOffer {
        ControlOffer {
            protocol_version: max,
            min_supported_version: min,
            agent_version: "1.2.3".into(),
            capabilities: BTreeSet::from([GuestCapability::Ping, GuestCapability::Readiness]),
        }
    }

    const HOST: ControlRange = ControlRange {
        protocol_version: 3,
        min_supported_version: 3,
    };

    #[test]
    fn an_offer_round_trips_and_names_capabilities_in_snake_case() {
        let json = serde_json::to_string(&offer(3, 3)).unwrap();
        assert!(json.contains("\"readiness\""), "{json}");
        assert_eq!(
            serde_json::from_str::<ControlOffer>(&json).unwrap(),
            offer(3, 3)
        );
    }

    #[test]
    fn an_empty_capability_set_is_accepted() {
        let mut empty = offer(3, 3);
        empty.capabilities.clear();
        let json = serde_json::to_string(&empty).unwrap();
        assert_eq!(serde_json::from_str::<ControlOffer>(&json).unwrap(), empty);
    }

    #[test]
    fn an_unknown_capability_or_field_is_refused() {
        let unknown_capability = r#"{"protocol_version":3,"min_supported_version":3,"agent_version":"x","capabilities":["teleport"]}"#;
        assert!(serde_json::from_str::<ControlOffer>(unknown_capability).is_err());
        let unknown_field = r#"{"protocol_version":3,"min_supported_version":3,"agent_version":"x","capabilities":[],"extra":1}"#;
        assert!(serde_json::from_str::<ControlOffer>(unknown_field).is_err());
        let range_field = r#"{"protocol_version":3,"min_supported_version":3,"extra":1}"#;
        assert!(serde_json::from_str::<ControlRange>(range_field).is_err());
    }

    #[test]
    fn a_truncated_offer_is_refused() {
        let json = serde_json::to_string(&offer(3, 3)).unwrap();
        for cut in [1, json.len() / 2, json.len() - 1] {
            assert!(serde_json::from_str::<ControlOffer>(&json[..cut]).is_err());
        }
    }

    #[test]
    fn a_contradictory_or_oversized_offer_is_malformed() {
        assert!(offer(4, 3).validate().is_err());
        let mut long = offer(3, 3);
        long.agent_version = "v".repeat(MAX_AGENT_VERSION_LEN + 1);
        assert!(long.validate().is_err());
        let mut control = offer(3, 3);
        control.agent_version = "1\n2".into();
        assert!(control.validate().is_err());
        assert!(offer(3, 3).validate().is_ok());
        assert!(
            ControlRange {
                protocol_version: 2,
                min_supported_version: 3
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn overlapping_ranges_are_accepted() {
        assert!(HOST.check(&offer(3, 3)).is_ok());
        assert!(HOST.check(&offer(1, 3)).is_ok());
    }

    #[test]
    fn a_host_older_than_the_guest_must_be_upgraded() {
        let mismatch = HOST.check(&offer(4, 5)).unwrap_err();
        assert_eq!(mismatch.required_action, ProtocolUpgradeAction::UpgradeHost);
        assert_eq!(mismatch.host_protocol_version, 3);
        assert_eq!(mismatch.agent_protocol_version, 5);
    }

    #[test]
    fn a_guest_older_than_the_host_must_be_rebuilt() {
        let mismatch = HOST.check(&offer(1, 2)).unwrap_err();
        assert_eq!(
            mismatch.required_action,
            ProtocolUpgradeAction::RebuildGuest
        );
    }

    #[test]
    fn a_missing_offer_names_rebuild_and_bootstrap() {
        let mismatch = HOST.refusal_without_offer();
        assert_eq!(
            mismatch.required_action,
            ProtocolUpgradeAction::RebuildGuest
        );
        assert!(mismatch.message.contains("mvmctl bootstrap"));
    }

    #[test]
    fn a_missing_host_range_names_upgrade() {
        let mismatch = refusal_without_host_range(&offer(3, 3));
        assert_eq!(mismatch.required_action, ProtocolUpgradeAction::UpgradeHost);
    }

    #[test]
    fn the_remedy_vocabulary_has_no_downgrade() {
        assert!(serde_json::from_str::<ProtocolUpgradeAction>("\"downgrade_host\"").is_err());
    }
}
