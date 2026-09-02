//! Names one workload uses to address another.
//!
//! A workload microVM has no NIC. Egress leaves only over the `NetworkFlow`
//! channel to the per-VM network endpoint, where a single gate decides every
//! outbound connection. East-west traffic reuses that path rather than opening
//! a second one: a workload dials a *name*, the host resolves it to a peer's
//! endpoint, and the guest never learns an address.
//!
//! # Why names carry a reserved suffix
//!
//! Resolution happens in front of the existing host-name path, so a peer name
//! and a real DNS name are drawn from the same input. If the two namespaces
//! could overlap, a workload holding both a peer binding and an egress grant
//! for the same string would have two plausible destinations and no way for a
//! reader to tell which one a request took.
//!
//! The suffix removes the overlap instead of ranking it. `db.mvm.peer` cannot
//! be a public host, so a target either ends in the suffix and is a peer, or
//! does not and takes the host-name path unchanged. Neither branch has to know
//! about the other.

use alloc::string::String;
use core::fmt;

use serde::{Deserialize, Serialize};

/// The reserved suffix every peer name carries. Not a delegated TLD, so it
/// cannot collide with a name the egress path would otherwise resolve.
pub const PEER_SUFFIX: &str = ".mvm.peer";

/// Longest permitted label, matching the DNS label limit. Not because the name
/// is ever resolved through DNS, but because staying inside the familiar bound
/// keeps it printable in logs and audit entries without special-casing.
const MAX_LABEL_LEN: usize = 63;

/// A validated name for a peer workload, e.g. `db.mvm.peer`.
///
/// Construct with [`PeerName::parse`]. The stored form is canonical: lowercase,
/// suffix included.
///
/// Deserialization re-runs [`PeerName::parse`], so a plan carrying a malformed
/// name fails when it is read rather than when it is dialed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(try_from = "String", into = "String")]
pub struct PeerName(String);

/// Why a candidate string is not a peer name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerNameInvalid {
    /// No [`PEER_SUFFIX`]. The caller handed over a plain host name; it belongs
    /// on the egress path, not here.
    MissingSuffix,
    /// Nothing before the suffix.
    EmptyLabel,
    /// The label is longer than [`MAX_LABEL_LEN`].
    LabelTooLong,
    /// A character outside ASCII alphanumeric and `-`.
    IllegalCharacter,
    /// A leading or trailing `-`.
    LeadingOrTrailingHyphen,
    /// More than one label before the suffix. A peer is addressed by a flat
    /// name; permitting dots would invite a reader to expect a hierarchy that
    /// nothing implements.
    NestedLabel,
}

impl fmt::Display for PeerNameInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::MissingSuffix => "peer names end in `.mvm.peer`",
            Self::EmptyLabel => "no name before `.mvm.peer`",
            Self::LabelTooLong => "name is longer than 63 characters",
            Self::IllegalCharacter => "name allows only ASCII letters, digits, and `-`",
            Self::LeadingOrTrailingHyphen => "name may not start or end with `-`",
            Self::NestedLabel => "peer names are flat: no `.` before `.mvm.peer`",
        };
        f.write_str(msg)
    }
}

impl PeerName {
    /// Parse and validate. Input is lowercased first, so `DB.mvm.peer` and
    /// `db.mvm.peer` are one name rather than two that compare unequal in a
    /// binding lookup.
    pub fn parse(raw: &str) -> Result<Self, PeerNameInvalid> {
        let lowered = raw.to_ascii_lowercase();
        let Some(label) = lowered.strip_suffix(PEER_SUFFIX) else {
            return Err(PeerNameInvalid::MissingSuffix);
        };
        if label.is_empty() {
            return Err(PeerNameInvalid::EmptyLabel);
        }
        if label.contains('.') {
            return Err(PeerNameInvalid::NestedLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(PeerNameInvalid::LabelTooLong);
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(PeerNameInvalid::IllegalCharacter);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(PeerNameInvalid::LeadingOrTrailingHyphen);
        }
        Ok(Self(lowered))
    }

    /// Whether a target host *claims* to be a peer name, valid or not.
    ///
    /// This is the branch the egress path takes: a target ending in the suffix
    /// is routed to peer resolution and is refused there if malformed. It is
    /// deliberately not `parse(..).is_ok()` — a malformed peer name must not
    /// fall through to the host-name path and get resolved as a public host.
    pub fn is_peer_target(host: &str) -> bool {
        host.to_ascii_lowercase().ends_with(PEER_SUFFIX)
    }

    /// The canonical string form, suffix included.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The label without the suffix, e.g. `db` for `db.mvm.peer`.
    pub fn label(&self) -> &str {
        self.0
            .strip_suffix(PEER_SUFFIX)
            .expect("a parsed PeerName always carries the suffix")
    }
}

impl fmt::Display for PeerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One admitted peer route: the name a workload may dial, and where the host
/// connects when it does.
///
/// The destination is carried here rather than discovered at dial time. A peer
/// receives traffic through an admitted ingress mapping, whose `host_addr` /
/// `host_port` are already in that peer's signed plan, so binding the resolved
/// address into the *caller's* plan keeps the peer set signed instead of
/// resolved against mutable runtime state. A workload's reachable peers are
/// then fixed at admission, the same way its egress destinations are.
///
/// Liveness needs no separate check. Nothing is listening at the address until
/// the peer's endpoint binds it, so a dial to a stopped peer is refused by the
/// connect itself — fail-closed without a registry that could disagree with
/// reality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PeerBinding {
    /// The name the calling workload dials.
    pub name: PeerName,
    /// The port the calling workload dials. A dial to the right name on a port
    /// this binding does not name is refused: a binding authorizes one route,
    /// not a host.
    pub port: u16,
    /// Host address the peer's admitted ingress mapping binds.
    pub host_addr: String,
    /// Host port the peer's admitted ingress mapping binds.
    pub host_port: u16,
}

/// Why a peer binding is structurally invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerBindingInvalid {
    /// `host_addr` does not parse as an IP address. Names are not permitted:
    /// a binding that had to be resolved could resolve differently later, and
    /// the point of admitting the address is that it cannot.
    HostAddressNotAnIp,
    /// A port is zero.
    ZeroPort,
}

impl fmt::Display for PeerBindingInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::HostAddressNotAnIp => "peer host_addr must be a literal IP address",
            Self::ZeroPort => "peer ports must be in 1..=65535",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for PeerBindingInvalid {}

impl PeerBinding {
    /// Validate invariants that do not depend on host runtime state.
    pub fn validate(&self) -> Result<(), PeerBindingInvalid> {
        if self.port == 0 || self.host_port == 0 {
            return Err(PeerBindingInvalid::ZeroPort);
        }
        if self.host_addr.parse::<core::net::IpAddr>().is_err() {
            return Err(PeerBindingInvalid::HostAddressNotAnIp);
        }
        Ok(())
    }

    /// Whether this binding authorizes a dial to `name` on `port`.
    pub fn admits(&self, name: &PeerName, port: u16) -> bool {
        self.name == *name && self.port == port
    }
}

impl TryFrom<String> for PeerName {
    type Error = PeerNameInvalid;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl From<PeerName> for String {
    fn from(name: PeerName) -> Self {
        name.0
    }
}

impl core::error::Error for PeerNameInvalid {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_plain_label() {
        let name = PeerName::parse("db.mvm.peer").expect("valid");
        assert_eq!(name.as_str(), "db.mvm.peer");
        assert_eq!(name.label(), "db");
    }

    #[test]
    fn canonicalizes_case_so_a_binding_lookup_cannot_miss_on_it() {
        let upper = PeerName::parse("DB.MVM.PEER").expect("valid");
        let lower = PeerName::parse("db.mvm.peer").expect("valid");
        assert_eq!(upper, lower);
        assert_eq!(upper.as_str(), "db.mvm.peer");
    }

    #[test]
    fn rejects_a_bare_host_name() {
        assert_eq!(
            PeerName::parse("api.example.com"),
            Err(PeerNameInvalid::MissingSuffix)
        );
    }

    /// The reserved suffix is the whole reason the two namespaces cannot
    /// overlap. If a numeric target ever parsed as a peer, the egress path
    /// would have two readings of one string.
    #[test]
    fn rejects_numeric_targets() {
        assert_eq!(
            PeerName::parse("10.0.0.1"),
            Err(PeerNameInvalid::MissingSuffix)
        );
        assert_eq!(PeerName::parse("::1"), Err(PeerNameInvalid::MissingSuffix));
    }

    #[test]
    fn rejects_an_empty_or_nested_label() {
        assert_eq!(
            PeerName::parse(".mvm.peer"),
            Err(PeerNameInvalid::EmptyLabel)
        );
        assert_eq!(
            PeerName::parse("a.b.mvm.peer"),
            Err(PeerNameInvalid::NestedLabel)
        );
    }

    #[test]
    fn rejects_illegal_characters_and_edge_hyphens() {
        assert_eq!(
            PeerName::parse("d_b.mvm.peer"),
            Err(PeerNameInvalid::IllegalCharacter)
        );
        assert_eq!(
            PeerName::parse("-db.mvm.peer"),
            Err(PeerNameInvalid::LeadingOrTrailingHyphen)
        );
        assert_eq!(
            PeerName::parse("db-.mvm.peer"),
            Err(PeerNameInvalid::LeadingOrTrailingHyphen)
        );
    }

    #[test]
    fn rejects_an_overlong_label() {
        let long = "a".repeat(MAX_LABEL_LEN + 1);
        assert_eq!(
            PeerName::parse(&alloc::format!("{long}.mvm.peer")),
            Err(PeerNameInvalid::LabelTooLong)
        );
        let at_limit = "a".repeat(MAX_LABEL_LEN);
        assert!(PeerName::parse(&alloc::format!("{at_limit}.mvm.peer")).is_ok());
    }

    /// A malformed peer target must be refused at peer resolution, never
    /// handed to the host-name path — otherwise `-db.mvm.peer` would be
    /// looked up as a public host.
    #[test]
    fn a_malformed_peer_target_is_still_claimed_by_the_peer_branch() {
        assert!(PeerName::is_peer_target("-db.mvm.peer"));
        assert!(PeerName::parse("-db.mvm.peer").is_err());
        assert!(!PeerName::is_peer_target("api.example.com"));
    }

    #[test]
    fn serde_round_trips_and_revalidates() {
        let name = PeerName::parse("cache.mvm.peer").expect("valid");
        let json = serde_json::to_string(&name).expect("serialize");
        assert_eq!(json, "\"cache.mvm.peer\"");
        let back: PeerName = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, name);

        serde_json::from_str::<PeerName>("\"api.example.com\"")
            .expect_err("a bare host name is not a peer name");
    }

    #[test]
    fn invalid_reasons_render() {
        assert!(!PeerNameInvalid::MissingSuffix.to_string().is_empty());
        assert!(!PeerBindingInvalid::ZeroPort.to_string().is_empty());
    }

    fn binding(port: u16, host_addr: &str, host_port: u16) -> PeerBinding {
        PeerBinding {
            name: PeerName::parse("db.mvm.peer").expect("valid"),
            port,
            host_addr: host_addr.into(),
            host_port,
        }
    }

    #[test]
    fn a_well_formed_binding_validates() {
        assert!(binding(5432, "127.0.0.1", 34567).validate().is_ok());
        assert!(binding(5432, "::1", 34567).validate().is_ok());
    }

    /// A binding that had to be resolved could resolve differently later. The
    /// whole point of admitting the address is that it cannot.
    #[test]
    fn a_binding_host_address_must_be_a_literal_ip() {
        assert_eq!(
            binding(5432, "db.internal", 34567).validate(),
            Err(PeerBindingInvalid::HostAddressNotAnIp)
        );
    }

    #[test]
    fn zero_ports_are_refused_on_either_side() {
        assert_eq!(
            binding(0, "127.0.0.1", 34567).validate(),
            Err(PeerBindingInvalid::ZeroPort)
        );
        assert_eq!(
            binding(5432, "127.0.0.1", 0).validate(),
            Err(PeerBindingInvalid::ZeroPort)
        );
    }

    /// A binding authorizes one route, not a host: the same name on a port the
    /// binding does not name is a different destination.
    #[test]
    fn a_binding_admits_only_its_own_name_and_port() {
        let b = binding(5432, "127.0.0.1", 34567);
        let db = PeerName::parse("db.mvm.peer").expect("valid");
        let cache = PeerName::parse("cache.mvm.peer").expect("valid");
        assert!(b.admits(&db, 5432));
        assert!(
            !b.admits(&db, 5433),
            "a different port is a different route"
        );
        assert!(
            !b.admits(&cache, 5432),
            "a different name is a different peer"
        );
    }

    #[test]
    fn a_binding_round_trips_and_rejects_unknown_fields() {
        let b = binding(5432, "127.0.0.1", 34567);
        let json = serde_json::to_string(&b).expect("serialize");
        assert_eq!(
            serde_json::from_str::<PeerBinding>(&json).expect("parse"),
            b
        );

        serde_json::from_value::<PeerBinding>(serde_json::json!({
            "name": "db.mvm.peer", "port": 1, "host_addr": "127.0.0.1",
            "host_port": 2, "weight": 3
        }))
        .expect_err("unknown field must be refused");
    }
}
