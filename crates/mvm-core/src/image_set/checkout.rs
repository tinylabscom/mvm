//! The identity of a local checkout, as a locally built image set records it.
//!
//! A set built from working trees rather than a release names the two trees
//! it came from — the image checkout and the mvm checkout — by commit and
//! working-tree state. The same types describe a checkout re-read at the moment
//! the set is used, so "is this manifest stale" is an equality test between
//! two values of one type rather than a comparison across two encodings.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::identity::GitCommit;
use crate::packs::Sha256Hex;

/// Whether a checkout's files match its commit.
///
/// On the wire: `{"state": "clean"}` or
/// `{"state": "dirty", "fingerprint_version": 2, "fingerprint": "<sha256>"}`.
/// Legacy clean identities remain readable. Legacy dirty identities cannot be
/// verified using the new algorithm and require rebuilding the local set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawWorktreeState", into = "RawWorktreeState")]
pub enum WorktreeState {
    Clean,
    /// Differs from its commit. The version-2 fingerprint covers HEAD, the
    /// staged entries (including conflicts), tracked working files and
    /// non-ignored untracked files using a language-neutral binary encoding.
    Dirty {
        fingerprint: Sha256Hex,
    },
}

impl WorktreeState {
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        matches!(self, Self::Dirty { .. })
    }
}

impl fmt::Display for WorktreeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::Dirty { fingerprint } => {
                write!(f, "dirty {}", &fingerprint.as_str()[..16])
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StateName {
    Clean,
    Dirty,
}

/// The wire form of [`WorktreeState`]. Serde's own tagged enums ignore unknown
/// fields on a variant that has none, so the shape is checked here instead.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorktreeState {
    state: StateName,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    fingerprint: Option<Sha256Hex>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    fingerprint_version: Option<u32>,
}

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl TryFrom<RawWorktreeState> for WorktreeState {
    type Error = &'static str;

    fn try_from(raw: RawWorktreeState) -> Result<Self, Self::Error> {
        match (raw.state, raw.fingerprint, raw.fingerprint_version) {
            (StateName::Clean, None, None) => Ok(Self::Clean),
            (StateName::Clean, _, _) => Err("a clean worktree has no fingerprint or version"),
            (StateName::Dirty, Some(fingerprint), Some(2)) => Ok(Self::Dirty { fingerprint }),
            (StateName::Dirty, _, None) => Err(
                "legacy dirty checkout identity cannot be verified; rebuild the local image set",
            ),
            (StateName::Dirty, _, Some(2)) => Err("a dirty worktree needs its fingerprint"),
            (StateName::Dirty, _, Some(_)) => {
                Err("unsupported dirty checkout fingerprint version; rebuild the local image set")
            }
        }
    }
}

impl From<WorktreeState> for RawWorktreeState {
    fn from(state: WorktreeState) -> Self {
        match state {
            WorktreeState::Clean => Self {
                state: StateName::Clean,
                fingerprint: None,
                fingerprint_version: None,
            },
            WorktreeState::Dirty { fingerprint } => Self {
                state: StateName::Dirty,
                fingerprint: Some(fingerprint),
                fingerprint_version: Some(2),
            },
        }
    }
}

/// The commit a checkout is at and whether its files match it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoIdentity {
    pub commit: GitCommit,
    pub worktree: WorktreeState,
}

impl fmt::Display for RepoIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.commit, self.worktree)
    }
}

/// The working trees a locally built set came from. Linux-only sets record
/// just the image checkout; legacy sets also record their runtime sources.
///
/// This is the whole of a local producer: it names no repository, workflow,
/// tag or signer, so nothing in it can be mistaken for the identity a release
/// is verified under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCheckouts {
    /// The image checkout whose flakes built the set.
    pub images: RepoIdentity,
    /// The mvm checkout its guest and host binaries were compiled from.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::deserialize_present"
    )]
    pub mvm: Option<RepoIdentity>,
}
