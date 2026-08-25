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
    }
}
