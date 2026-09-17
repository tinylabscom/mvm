//! Content identity of one durable agent-session transition.
//!
//! A caller whose park, resume or renew was applied but whose response was lost
//! can only retry. Without an identity the store cannot tell that retry from a
//! new request: it either refuses (the session already moved) or applies the
//! transition a second time. With one, a retry whose identity equals the
//! transition the record last took is answered with that transition's original
//! result and writes nothing, and a retry that differs is refused naming what
//! differs.
//!
//! The identity covers exactly what decides a transition's outcome: its kind,
//! the session, the generation the caller observed, any further state the
//! caller observed and conditioned on, and every request input. It never covers
//! a timestamp — a retry happens later by definition, so an identity that moved
//! with the clock would make every retry look new.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tag hashed ahead of every transition identity, so the
/// digest cannot collide with a SHA-256 some other part of the system takes
/// over similarly shaped bytes.
pub const TRANSITION_IDENTITY_DOMAIN: &str = "mvm.agent-session.transition.v1";

/// Which transition an identity names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    Park,
    Resume,
    Renew,
}

impl TransitionKind {
    /// The spelling hashed into the identity and shown to an operator.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Park => "park",
            Self::Resume => "resume",
            Self::Renew => "renew",
        }
    }
}

impl std::fmt::Display for TransitionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that determines one transition's outcome, and nothing else.
///
/// Values are carried in their canonical string form rather than as typed
/// fields so one shape serves park, resume and renew, and so a conflict can
/// name the input that differs in the same spelling the operator typed. Maps
/// rather than vectors: an identity must not depend on the order a caller
/// happened to add its inputs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionIdentity {
    pub kind: TransitionKind,
    pub session_id: String,
    /// The generation the transition was evaluated against.
    pub observed_generation: u64,
    /// Further record state the transition is conditional on. Two identities
    /// that agree on kind, session, generation and this map are competing for
    /// the same step of the session's history — see
    /// [`TransitionIdentity::occupies_same_slot`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub observed: BTreeMap<String, Option<String>>,
    /// What the caller asked for.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, Option<String>>,
}

impl TransitionIdentity {
    /// Start an identity for `kind` on `session_id` at `observed_generation`.
    pub fn new(
        kind: TransitionKind,
        session_id: impl Into<String>,
        observed_generation: u64,
    ) -> Self {
        Self {
            kind,
            session_id: session_id.into(),
            observed_generation,
            observed: BTreeMap::new(),
            inputs: BTreeMap::new(),
        }
    }

    /// Record a piece of state the caller observed. `None` means the caller
    /// observed its absence, which is itself a fact the transition depends on.
    #[must_use]
    pub fn observing(mut self, name: &str, value: Option<String>) -> Self {
        self.observed.insert(name.to_string(), value);
        self
    }

    /// Record a request input that is always present.
    #[must_use]
    pub fn input(mut self, name: &str, value: impl ToString) -> Self {
        self.inputs
            .insert(name.to_string(), Some(value.to_string()));
        self
    }

    /// Record a request input that may be absent. Absent and empty hash
    /// differently, so "no approval head" is never confused with a blank one.
    #[must_use]
    pub fn optional_input(mut self, name: &str, value: Option<String>) -> Self {
        self.inputs.insert(name.to_string(), value);
        self
    }

    /// The identity's content address.
    ///
    /// Every variable-length field is length-prefixed, so no two different
    /// identities can encode to the same bytes by moving a boundary — inputs
    /// `("ab", "c")` and `("a", "bc")` hash apart.
    #[must_use]
    pub fn digest(&self) -> SessionTransitionDigest {
        SessionTransitionDigest::from_bytes(&self.digest_under(TRANSITION_IDENTITY_DOMAIN))
    }

    fn digest_under(&self, domain: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        put(&mut hasher, domain.as_bytes());
        put(&mut hasher, self.kind.as_str().as_bytes());
        put(&mut hasher, self.session_id.as_bytes());
        hasher.update(self.observed_generation.to_be_bytes());
        put_section(&mut hasher, "observed", &self.observed);
        put_section(&mut hasher, "inputs", &self.inputs);
        hasher.finalize().into()
    }

    /// Whether `other` competes for the same step of the session's history.
    ///
    /// Two identities that agree on everything the caller observed but differ
    /// in what they ask for cannot both be applied: one of them is a retry that
    /// changed its request. Two that observed different state are successive
    /// steps, and neither is a retry of the other.
    #[must_use]
    pub fn occupies_same_slot(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.session_id == other.session_id
            && self.observed_generation == other.observed_generation
            && self.observed == other.observed
    }

    /// Every way `retried` differs from this recorded identity, in a stable
    /// order: kind, session, generation, observed state, then inputs.
    #[must_use]
    pub fn differences(&self, retried: &Self) -> Vec<TransitionDifference> {
        let mut out = Vec::new();
        if self.kind != retried.kind {
            out.push(TransitionDifference::Kind {
                recorded: self.kind,
                retried: retried.kind,
            });
        }
        if self.session_id != retried.session_id {
            out.push(TransitionDifference::Session {
                recorded: self.session_id.clone(),
                retried: retried.session_id.clone(),
            });
        }
        if self.observed_generation != retried.observed_generation {
            out.push(TransitionDifference::Generation {
                recorded: self.observed_generation,
                retried: retried.observed_generation,
            });
        }
        for (name, recorded, retried) in map_differences(&self.observed, &retried.observed) {
            out.push(TransitionDifference::Observed {
                name,
                recorded,
                retried,
            });
        }
        for (name, recorded, retried) in map_differences(&self.inputs, &retried.inputs) {
            out.push(TransitionDifference::Input {
                name,
                recorded,
                retried,
            });
        }
        out
    }
}

type NamedDifference = (String, Option<String>, Option<String>);

/// Keys whose entries differ between two maps. A key missing from one side is a
/// difference even against an explicit `None` on the other, because the digest
/// counts entries and so hashes the two apart; reporting no difference for a
/// pair whose digests disagree would leave a conflict with nothing to name.
fn map_differences(
    recorded: &BTreeMap<String, Option<String>>,
    retried: &BTreeMap<String, Option<String>>,
) -> Vec<NamedDifference> {
    let mut names: Vec<&String> = recorded.keys().chain(retried.keys()).collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter(|name| recorded.get(*name) != retried.get(*name))
        .map(|name| {
            (
                name.clone(),
                recorded.get(name).cloned().flatten(),
                retried.get(name).cloned().flatten(),
            )
        })
        .collect()
}

fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn put_section(hasher: &mut Sha256, label: &str, entries: &BTreeMap<String, Option<String>>) {
    put(hasher, label.as_bytes());
    hasher.update((entries.len() as u64).to_be_bytes());
    for (name, value) in entries {
        put(hasher, name.as_bytes());
        match value {
            None => hasher.update([0u8]),
            Some(value) => {
                hasher.update([1u8]);
                put(hasher, value.as_bytes());
            }
        }
    }
}

/// One way a retried transition differs from the recorded one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionDifference {
    Kind {
        recorded: TransitionKind,
        retried: TransitionKind,
    },
    Session {
        recorded: String,
        retried: String,
    },
    Generation {
        recorded: u64,
        retried: u64,
    },
    Observed {
        name: String,
        recorded: Option<String>,
        retried: Option<String>,
    },
    Input {
        name: String,
        recorded: Option<String>,
        retried: Option<String>,
    },
}

impl std::fmt::Display for TransitionDifference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn shown(value: &Option<String>) -> &str {
            value.as_deref().unwrap_or("(none)")
        }
        match self {
            Self::Kind { recorded, retried } => {
                write!(f, "kind: recorded {recorded}, retried {retried}")
            }
            Self::Session { recorded, retried } => {
                write!(f, "session: recorded {recorded}, retried {retried}")
            }
            Self::Generation { recorded, retried } => {
                write!(f, "generation: recorded {recorded}, retried {retried}")
            }
            Self::Observed {
                name,
                recorded,
                retried,
            } => write!(
                f,
                "observed {name}: recorded {}, retried {}",
                shown(recorded),
                shown(retried)
            ),
            Self::Input {
                name,
                recorded,
                retried,
            } => write!(
                f,
                "{name}: recorded {}, retried {}",
                shown(recorded),
                shown(retried)
            ),
        }
    }
}

/// Content address of a [`TransitionIdentity`], as `sha256:<64-hex>`.
///
/// Its own type rather than a reused checkpoint digest or approval head: a
/// transition identity is not the head of either of those chains, and sharing
/// a type would let one be stored where the other is expected with nothing to
/// catch it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionTransitionDigest(String);

impl SessionTransitionDigest {
    /// The fixed hash-axis prefix every transition digest carries.
    pub const PREFIX: &'static str = "sha256:";

    /// Validate and wrap a `sha256:<64 lowercase hex>` string.
    pub fn parse(value: impl Into<String>) -> Result<Self, SessionTransitionDigestParseError> {
        use crate::digest_shape::Sha256PrefixedShape;
        let value = value.into();
        match crate::digest_shape::validate_sha256_prefixed(&value) {
            Sha256PrefixedShape::Ok => Ok(Self(value)),
            Sha256PrefixedShape::MissingPrefix => {
                Err(SessionTransitionDigestParseError::MissingPrefix(value))
            }
            Sha256PrefixedShape::WrongLength { len } => {
                Err(SessionTransitionDigestParseError::WrongLength { len })
            }
            Sha256PrefixedShape::NonHex { ch } => {
                Err(SessionTransitionDigestParseError::NonHex { ch })
            }
        }
    }

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(format!("{}{}", Self::PREFIX, hex::encode(bytes)))
    }

    /// The `sha256:<64-hex>` string view.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionTransitionDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SessionTransitionDigest {
    type Error = SessionTransitionDigestParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<SessionTransitionDigest> for String {
    fn from(digest: SessionTransitionDigest) -> Self {
        digest.0
    }
}

/// [`SessionTransitionDigest::parse`] failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionTransitionDigestParseError {
    #[error("transition digest must start with \"sha256:\", got {0:?}")]
    MissingPrefix(String),
    #[error("transition digest hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    #[error("transition digest hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn park() -> TransitionIdentity {
        TransitionIdentity::new(TransitionKind::Park, "sess-alpha", 3)
            .input("reason", "approval_wait")
            .input("journal_cursor", 42)
            .optional_input("approval_head", None)
    }

    #[test]
    fn the_digest_is_pinned_so_an_encoding_change_cannot_pass_silently() {
        // A recorded identity must still match a retry made by the next build.
        // If this value moves, every stored record stops recognising its own
        // retries, so the change has to be deliberate.
        assert_eq!(
            park().digest().as_str(),
            PINNED_PARK_DIGEST,
            "the transition identity encoding changed"
        );
    }

    const PINNED_PARK_DIGEST: &str =
        "sha256:71ebb23e0baef78411b4d4f52b6d8f2d9a6c5ba6e0e232031468bd46cfb0bd23";

    #[test]
    fn identical_identities_share_a_digest() {
        assert_eq!(park().digest(), park().digest());
    }

    #[test]
    fn input_order_does_not_move_the_digest() {
        let reordered = TransitionIdentity::new(TransitionKind::Park, "sess-alpha", 3)
            .optional_input("approval_head", None)
            .input("journal_cursor", 42)
            .input("reason", "approval_wait");
        assert_eq!(park().digest(), reordered.digest());
    }

    #[test]
    fn every_field_moves_the_digest() {
        let base = park().digest();
        let variants = [
            TransitionIdentity {
                kind: TransitionKind::Renew,
                ..park()
            },
            TransitionIdentity {
                session_id: "sess-beta".to_string(),
                ..park()
            },
            TransitionIdentity {
                observed_generation: 4,
                ..park()
            },
            park().input("reason", "idle"),
            park().input("journal_cursor", 43),
            park().optional_input("approval_head", Some(format!("sha256:{}", "ab".repeat(32)))),
            park().input("retain_for_secs", 60),
            park().observing("retain_until_unix", Some("100".to_string())),
        ];
        for variant in variants {
            assert_ne!(variant.digest(), base, "{variant:?} must hash apart");
        }
    }

    #[test]
    fn an_absent_input_and_an_empty_one_hash_apart() {
        let absent = park().optional_input("approval_head", None);
        let empty = park().optional_input("approval_head", Some(String::new()));
        assert_ne!(absent.digest(), empty.digest());
    }

    #[test]
    fn length_prefixes_stop_a_boundary_shift_from_colliding() {
        let a = TransitionIdentity::new(TransitionKind::Park, "s", 1).input("ab", "c");
        let b = TransitionIdentity::new(TransitionKind::Park, "s", 1).input("a", "bc");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn an_observed_value_and_an_input_of_the_same_name_hash_apart() {
        let observed = TransitionIdentity::new(TransitionKind::Renew, "s", 1)
            .observing("x", Some("1".to_string()));
        let input = TransitionIdentity::new(TransitionKind::Renew, "s", 1).input("x", "1");
        assert_ne!(observed.digest(), input.digest());
    }

    #[test]
    fn the_domain_tag_separates_the_digest_from_an_untagged_hash() {
        let identity = park();
        let tagged = identity.digest_under(TRANSITION_IDENTITY_DOMAIN);
        assert_ne!(tagged, identity.digest_under(""));
        assert_ne!(tagged, identity.digest_under("mvm.some-other-purpose.v1"));
    }

    #[test]
    fn same_slot_means_same_observations_whatever_was_asked() {
        let retried = park().input("reason", "operator");
        assert!(park().occupies_same_slot(&retried));
        let later = TransitionIdentity {
            observed_generation: 4,
            ..park()
        };
        assert!(!park().occupies_same_slot(&later));
        let renew_a = TransitionIdentity::new(TransitionKind::Renew, "s", 1)
            .observing("retain_until_unix", Some("100".to_string()));
        let renew_b = TransitionIdentity::new(TransitionKind::Renew, "s", 1)
            .observing("retain_until_unix", Some("200".to_string()));
        assert!(
            !renew_a.occupies_same_slot(&renew_b),
            "renews from different deadlines are successive, not competing"
        );
    }

    #[test]
    fn differences_name_the_input_that_changed() {
        let retried = park().input("reason", "operator");
        let diffs = park().differences(&retried);
        assert_eq!(
            diffs,
            vec![TransitionDifference::Input {
                name: "reason".to_string(),
                recorded: Some("approval_wait".to_string()),
                retried: Some("operator".to_string()),
            }]
        );
        assert_eq!(
            diffs[0].to_string(),
            "reason: recorded approval_wait, retried operator"
        );
    }

    #[test]
    fn differences_name_a_generation_change() {
        let retried = TransitionIdentity {
            observed_generation: 9,
            ..park()
        };
        let diffs = park().differences(&retried);
        assert_eq!(
            diffs,
            vec![TransitionDifference::Generation {
                recorded: 3,
                retried: 9
            }]
        );
    }

    #[test]
    fn an_input_present_on_one_side_only_is_a_difference() {
        let retried = park().input("boot", true);
        let diffs = park().differences(&retried);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].to_string(), "boot: recorded (none), retried true");
    }

    #[test]
    fn identity_and_digest_round_trip_through_serde() {
        let identity = park().observing("retain_until_unix", None);
        let json = serde_json::to_string(&identity).unwrap();
        assert_eq!(
            serde_json::from_str::<TransitionIdentity>(&json).unwrap(),
            identity
        );
        let digest = identity.digest();
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(
            serde_json::from_str::<SessionTransitionDigest>(&json).unwrap(),
            digest
        );
    }

    #[test]
    fn a_malformed_digest_is_refused_at_deserialize() {
        assert!(serde_json::from_str::<SessionTransitionDigest>("\"sha256:zz\"").is_err());
        assert!(
            serde_json::from_str::<TransitionIdentity>(
                r#"{"kind":"park","session_id":"s","observed_generation":1,"surprise":1}"#
            )
            .is_err()
        );
    }
}
