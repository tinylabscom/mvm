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
/// `{"state": "dirty", "fingerprint": "<sha256>"}`. Anything else — a clean
/// state carrying a fingerprint, a dirty one without — is refused rather than
/// read as the nearest shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawWorktreeState", into = "RawWorktreeState")]
pub enum WorktreeState {
    Clean,
    /// Differs from its commit. The fingerprint covers the tracked diff against
    /// `HEAD`, the status listing, and every untracked, non-ignored file's
    /// path and contents, so two different dirty trees on one commit do not
    /// share an identity.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<Sha256Hex>,
}

impl TryFrom<RawWorktreeState> for WorktreeState {
    type Error = &'static str;

    fn try_from(raw: RawWorktreeState) -> Result<Self, Self::Error> {
        match (raw.state, raw.fingerprint) {
            (StateName::Clean, None) => Ok(Self::Clean),
            (StateName::Dirty, Some(fingerprint)) => Ok(Self::Dirty { fingerprint }),
            (StateName::Clean, Some(_)) => Err("a clean worktree has no fingerprint"),
            (StateName::Dirty, None) => Err("a dirty worktree needs its fingerprint"),
        }
    }
}

impl From<WorktreeState> for RawWorktreeState {
    fn from(state: WorktreeState) -> Self {
        match state {
            WorktreeState::Clean => Self {
                state: StateName::Clean,
                fingerprint: None,
            },
            WorktreeState::Dirty { fingerprint } => Self {
                state: StateName::Dirty,
                fingerprint: Some(fingerprint),
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

/// The two working trees a locally built set came from.
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
    pub mvm: RepoIdentity,
}
