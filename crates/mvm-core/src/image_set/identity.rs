//! Validated identity newtypes the image set and its lock are keyed on.
//!
//! Every one of these crosses a trust boundary as a string, so each parses on
//! construction and on deserialization: a value that exists is a value that
//! was checked, and no caller re-validates or forgets to.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::release_version::{ReleaseVersion, VersionSyntax};

/// Why an identity string was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImageSetIdentityError {
    #[error("invalid semantic version {0:?}")]
    InvalidVersion(String),
    #[error("invalid git commit {0:?}: expected 40 lowercase hex characters")]
    InvalidCommit(String),
    #[error("invalid repository slug {0:?}: expected `owner/name`")]
    InvalidRepositorySlug(String),
    #[error("invalid workflow path {0:?}: expected `.github/workflows/<name>.yml`")]
    InvalidWorkflowPath(String),
    #[error("invalid release tag {0:?}: expected `[namespace/]v<semver>`")]
    InvalidReleaseTag(String),
    #[error("invalid tag ref {0:?}: expected `refs/tags/<release tag>`")]
    InvalidTagRef(String),
    #[error("invalid artifact name {0:?}: expected a single file name")]
    InvalidArtifactName(String),
    #[error("invalid revocation channel {0:?}: expected an https URL")]
    InvalidRevocationChannel(String),
    #[error(
        "invalid protocol range {min}..={max}: versions start at 1 and min must not exceed max"
    )]
    InvalidProtocolRange { min: u32, max: u32 },
}

/// Generates the string plumbing shared by the plain validated newtypes: the
/// fallible constructor, the borrowed view, `Display`, and the serde bridge
/// that routes deserialization through the same validator.
macro_rules! validated_string {
    ($(#[$meta:meta])* $name:ident, $valid:path, $error:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ImageSetIdentityError> {
                let value = value.into();
                if $valid(&value) {
                    Ok(Self(value))
                } else {
                    Err(ImageSetIdentityError::$error(value))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ImageSetIdentityError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

validated_string!(
    /// A full 40-hex git commit id. Abbreviated ids are refused because they
    /// stop being unique as a repository grows.
    GitCommit,
    is_git_commit,
    InvalidCommit
);

validated_string!(
    /// A hosted repository named as `owner/name`.
    RepositorySlug,
    is_repository_slug,
    InvalidRepositorySlug
);

validated_string!(
    /// A workflow file directly under `.github/workflows/`, which is the path a
    /// keyless signing certificate names.
    WorkflowPath,
    is_workflow_path,
    InvalidWorkflowPath
);

validated_string!(
    /// A single release-asset file name. Path separators are refused so a name
    /// can never address anything outside the directory it is placed in.
    ArtifactName,
    is_artifact_name,
    InvalidArtifactName
);

validated_string!(
    /// Where the revocation document for a set is retrieved. Plain http is
    /// refused: a revocation an on-path attacker can strip is no revocation.
    RevocationChannel,
    is_revocation_channel,
    InvalidRevocationChannel
);

fn is_git_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_repository_slug(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    let owner_ok = (1..=39).contains(&owner.len())
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !owner.starts_with('-')
        && !owner.ends_with('-');
    owner_ok && (1..=100).contains(&name.len()) && is_file_token(name)
}

fn is_workflow_path(value: &str) -> bool {
    let Some(file) = value.strip_prefix(".github/workflows/") else {
        return false;
    };
    let stem = file
        .strip_suffix(".yml")
        .or_else(|| file.strip_suffix(".yaml"));
    stem.is_some_and(|stem| !stem.is_empty() && is_file_token(file))
}

fn is_artifact_name(value: &str) -> bool {
    value.len() <= 255 && is_file_token(value)
}

fn is_revocation_channel(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    !host.is_empty() && !value.chars().any(char::is_whitespace)
}

/// A non-empty path segment made of `[A-Za-z0-9._-]` that is not `.` or `..`.
fn is_file_token(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A semantic version (strict semver 2.0.0 grammar) naming one image set.
///
/// Equality is exact, build metadata included, because the version is compared
/// against the tag a release was published under. Ordering is a separate,
/// explicit [`ImageSetVersion::cmp_precedence`], since semver precedence
/// ignores build metadata and so cannot back an `Ord` consistent with `Eq`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageSetVersion {
    raw: String,
    precedence: ReleaseVersion,
}

impl ImageSetVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, ImageSetIdentityError> {
        let raw = value.into();
        match ReleaseVersion::parse(&raw, VersionSyntax::Strict) {
            Some(precedence) => Ok(Self { raw, precedence }),
            None => Err(ImageSetIdentityError::InvalidVersion(raw)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Semver precedence, which ignores build metadata.
    pub fn cmp_precedence(&self, other: &Self) -> Ordering {
        self.precedence.cmp(&other.precedence)
    }
}

impl TryFrom<String> for ImageSetVersion {
    type Error = ImageSetIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ImageSetVersion> for String {
    fn from(value: ImageSetVersion) -> Self {
        value.raw
    }
}

impl fmt::Display for ImageSetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// An immutable release tag of the form `[namespace/]v<semver>`, carrying the
/// version it names so the set version can be compared against it without
/// re-parsing the tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReleaseTag {
    raw: String,
    version: ImageSetVersion,
}

impl ReleaseTag {
    pub fn new(value: impl Into<String>) -> Result<Self, ImageSetIdentityError> {
        let raw = value.into();
        let (namespace, leaf) = match raw.rsplit_once('/') {
            Some((namespace, leaf)) => (Some(namespace), leaf),
            None => (None, raw.as_str()),
        };
        let namespace_ok = namespace.is_none_or(|ns| ns.split('/').all(is_file_token));
        let version = leaf
            .strip_prefix('v')
            .and_then(|version| ImageSetVersion::new(version).ok());
        match version {
            Some(version) if namespace_ok => Ok(Self { raw, version }),
            _ => Err(ImageSetIdentityError::InvalidReleaseTag(raw)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn version(&self) -> &ImageSetVersion {
        &self.version
    }
}

impl TryFrom<String> for ReleaseTag {
    type Error = ImageSetIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ReleaseTag> for String {
    fn from(value: ReleaseTag) -> Self {
        value.raw
    }
}

impl fmt::Display for ReleaseTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

const TAG_REF_PREFIX: &str = "refs/tags/";

/// The `refs/tags/<tag>` git ref a signing certificate is issued under. Branch
/// refs are unrepresentable: a signature minted on a mutable branch is not a
/// release.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TagRef {
    raw: String,
    tag: ReleaseTag,
}

impl TagRef {
    pub fn new(value: impl Into<String>) -> Result<Self, ImageSetIdentityError> {
        let raw = value.into();
        match raw
            .strip_prefix(TAG_REF_PREFIX)
            .and_then(|tag| ReleaseTag::new(tag).ok())
        {
            Some(tag) => Ok(Self { raw, tag }),
            None => Err(ImageSetIdentityError::InvalidTagRef(raw)),
        }
    }

    pub fn for_tag(tag: &ReleaseTag) -> Self {
        Self {
            raw: format!("{TAG_REF_PREFIX}{tag}"),
            tag: tag.clone(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn tag(&self) -> &ReleaseTag {
        &self.tag
    }
}

impl TryFrom<String> for TagRef {
    type Error = ImageSetIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TagRef> for String {
    fn from(value: TagRef) -> Self {
        value.raw
    }
}

impl fmt::Display for TagRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// An inclusive, non-empty range of protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawProtocolRange")]
pub struct ProtocolRange {
    min: u32,
    max: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProtocolRange {
    min: u32,
    max: u32,
}

impl ProtocolRange {
    pub fn new(min: u32, max: u32) -> Result<Self, ImageSetIdentityError> {
        if min == 0 || min > max {
            Err(ImageSetIdentityError::InvalidProtocolRange { min, max })
        } else {
            Ok(Self { min, max })
        }
    }

    pub fn min(self) -> u32 {
        self.min
    }

    pub fn max(self) -> u32 {
        self.max
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

impl TryFrom<RawProtocolRange> for ProtocolRange {
    type Error = ImageSetIdentityError;

    fn try_from(raw: RawProtocolRange) -> Result<Self, Self::Error> {
        Self::new(raw.min, raw.max)
    }
}

impl fmt::Display for ProtocolRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.min, self.max)
    }
}
