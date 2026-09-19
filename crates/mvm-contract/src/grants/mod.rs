//! What a workload is permitted to consume or reach.
//!
//! Named `Grants` rather than `Capabilities` because `VmCapabilities` already
//! means "what a VMM backend supports", and `capability` additionally collides
//! with Linux `capabilities(7)`, which this project drops via bounding-set.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::num::{NonZeroU32, NonZeroU64};
use serde::{Deserialize, Deserializer, Serialize};

use crate::policy::network_policy::HostPort;

pub mod budget;
pub mod ceiling;
pub mod projection;
pub mod subset;

/// A workload's permission set. Every field is optional: absent means
/// "unspecified", which each dimension resolves differently — an absent
/// `egress` is deny-all, an absent `cpu` is uncapped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock: Option<WallClockGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<DriveGrant>,
}

/// CPU bound. The two variants are different units, not different precisions,
/// and no conversion between them is offered: a share is a fraction of host
/// wall-clock CPU, fuel is a count of executed instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "unit", rename_all = "snake_case", deny_unknown_fields)]
pub enum CpuGrant {
    /// Thousandths of one host core. 1500 = 1.5 cores. Integer because the
    /// value lands in a signed, content-addressed payload and float
    /// canonicalization is not stable across serializers.
    Share { millicores: u32 },
    /// A deterministic executed-instruction budget. Reproducible across hosts
    /// in a way no share-based bound is.
    Fuel { instructions: u64 },
}

/// Wall-clock bound.
///
/// `Unbounded` is a named variant rather than a sentinel value. The legacy
/// `TimeoutSpec::exec_secs` encodes unbounded as `0`, so a user writing `0` to
/// mean "no time allowed" would get "no limit" — the exact inversion of their
/// intent. `NonZeroU32` makes that unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WallClockGrant {
    Unbounded,
    Secs { secs: NonZeroU32 },
}

/// Outbound destinations. An empty `allow` is "no egress" and is distinct from
/// an absent `EgressGrant`, which is also deny-all — both are closed, so the
/// distinction never opens anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressGrant {
    pub allow: Vec<HostPort>,
}

/// Stable plan-authored identifier for the one program a drive session may
/// start. It is an opaque selector, never an argv or filesystem path supplied
/// by the caller opening the session.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct DriveProgramId(String);

impl DriveProgramId {
    pub fn parse(value: impl Into<String>) -> Result<Self, DriveGrantError> {
        let value = value.into();
        let mut chars = value.chars();
        let starts_with_letter = chars.next().is_some_and(|ch| ch.is_ascii_lowercase());
        let valid = value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
        if !starts_with_letter || !valid {
            return Err(DriveGrantError::InvalidProgramId(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DriveProgramId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DriveProgramId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// An absolute guest directory a drive session may read or modify.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct WorkspaceRoot(String);

impl WorkspaceRoot {
    pub fn parse(value: impl Into<String>) -> Result<Self, DriveGrantError> {
        let value = value.into();
        if !value.starts_with('/') {
            return Err(DriveGrantError::WorkspaceRootNotAbsolute(value));
        }
        if value.as_bytes().contains(&0) {
            return Err(DriveGrantError::UnsafeWorkspaceRoot(value));
        }
        let mut components = value.split('/');
        let leading = components.next();
        if leading != Some("")
            || (value != "/"
                && components
                    .any(|component| component.is_empty() || matches!(component, "." | "..")))
        {
            return Err(DriveGrantError::UnsafeWorkspaceRoot(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_within(&self, parent: &Self) -> bool {
        parent.as_str() == "/"
            || self == parent
            || self
                .as_str()
                .strip_prefix(parent.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

impl fmt::Display for WorkspaceRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for WorkspaceRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The bounded authority to drive one plan-selected program and its workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DriveGrant {
    #[serde(deserialize_with = "deserialize_workspace_roots")]
    pub workspace_roots: Vec<WorkspaceRoot>,
    pub program_id: DriveProgramId,
    pub max_bytes_in: NonZeroU64,
    pub max_bytes_out: NonZeroU64,
    /// Lifetime of one opened drive session, in seconds.
    pub ttl: NonZeroU32,
}

impl DriveGrant {
    #[must_use]
    pub fn builder() -> DriveGrantBuilder {
        DriveGrantBuilder::default()
    }
}

/// Builder for a validated [`DriveGrant`].
#[derive(Debug, Default)]
pub struct DriveGrantBuilder {
    workspace_roots: Vec<WorkspaceRoot>,
    program_id: Option<DriveProgramId>,
    max_bytes_in: Option<NonZeroU64>,
    max_bytes_out: Option<NonZeroU64>,
    ttl: Option<NonZeroU32>,
}

impl DriveGrantBuilder {
    #[must_use]
    pub fn workspace_root(mut self, root: WorkspaceRoot) -> Self {
        self.workspace_roots.push(root);
        self
    }

    #[must_use]
    pub fn program_id(mut self, program_id: DriveProgramId) -> Self {
        self.program_id = Some(program_id);
        self
    }

    #[must_use]
    pub fn max_bytes_in(mut self, max_bytes_in: NonZeroU64) -> Self {
        self.max_bytes_in = Some(max_bytes_in);
        self
    }

    #[must_use]
    pub fn max_bytes_out(mut self, max_bytes_out: NonZeroU64) -> Self {
        self.max_bytes_out = Some(max_bytes_out);
        self
    }

    #[must_use]
    pub fn ttl(mut self, ttl: NonZeroU32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn build(self) -> Result<DriveGrant, DriveGrantError> {
        if self.workspace_roots.is_empty() {
            return Err(DriveGrantError::NoWorkspaceRoots);
        }
        for (index, root) in self.workspace_roots.iter().enumerate() {
            if self.workspace_roots[..index].contains(root) {
                return Err(DriveGrantError::DuplicateWorkspaceRoot(root.clone()));
            }
        }
        Ok(DriveGrant {
            workspace_roots: self.workspace_roots,
            program_id: self.program_id.ok_or(DriveGrantError::MissingProgramId)?,
            max_bytes_in: self
                .max_bytes_in
                .ok_or(DriveGrantError::MissingBound("max_bytes_in"))?,
            max_bytes_out: self
                .max_bytes_out
                .ok_or(DriveGrantError::MissingBound("max_bytes_out"))?,
            ttl: self.ttl.ok_or(DriveGrantError::MissingBound("ttl"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DriveGrantError {
    #[error("drive program id {0:?} is not lowercase kebab-case ([a-z][a-z0-9-]*)")]
    InvalidProgramId(String),
    #[error("drive workspace root {0:?} is not absolute")]
    WorkspaceRootNotAbsolute(String),
    #[error("drive workspace root {0:?} contains an unsafe path component")]
    UnsafeWorkspaceRoot(String),
    #[error("drive grant must name at least one workspace root")]
    NoWorkspaceRoots,
    #[error("drive workspace root {0} is declared more than once")]
    DuplicateWorkspaceRoot(WorkspaceRoot),
    #[error("drive grant is missing program_id")]
    MissingProgramId,
    #[error("drive grant is missing {0}")]
    MissingBound(&'static str),
}

fn deserialize_workspace_roots<'de, D>(deserializer: D) -> Result<Vec<WorkspaceRoot>, D::Error>
where
    D: Deserializer<'de>,
{
    let roots = Vec::<WorkspaceRoot>::deserialize(deserializer)?;
    if roots.is_empty() {
        return Err(serde::de::Error::custom(DriveGrantError::NoWorkspaceRoots));
    }
    for (index, root) in roots.iter().enumerate() {
        if roots[..index].contains(root) {
            return Err(serde::de::Error::custom(
                DriveGrantError::DuplicateWorkspaceRoot(root.clone()),
            ));
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn default_grants_serialize_to_an_empty_object() {
        let g = Grants::default();
        let json = serde_json::to_string(&g).expect("serializes");
        assert_eq!(json, "{}", "absent grants must not emit null fields");
    }

    #[test]
    fn unknown_field_is_refused_not_ignored() {
        // A typo must not silently disable a cap.
        let err =
            serde_json::from_str::<Grants>(r#"{"cpu_limt":{"unit":"share","millicores":1500}}"#)
                .expect_err("unknown field must be refused");
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn wall_clock_zero_is_not_expressible() {
        // exec_secs == 0 means *unbounded* in the legacy encoding. The grant
        // must not inherit that trap: zero has to be unrepresentable, so
        // "no time allowed" can never parse as "no limit".
        let err = serde_json::from_str::<WallClockGrant>(r#"{"kind":"secs","secs":0}"#)
            .expect_err("zero seconds must not parse");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn grants_round_trip_through_json() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(600).expect("nonzero"),
            }),
            egress: Some(EgressGrant {
                allow: vec![HostPort::new("api.example.com", 443)],
            }),
            drive: Some(drive_grant()),
        };
        let json = serde_json::to_string(&g).expect("serializes");
        let back: Grants = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(g, back);
    }

    #[test]
    fn cpu_share_carries_no_floating_point() {
        let json =
            serde_json::to_string(&CpuGrant::Share { millicores: 1500 }).expect("serializes");
        assert!(
            !json.contains('.'),
            "a signed payload must not carry a float: {json}"
        );
    }

    fn drive_grant() -> DriveGrant {
        DriveGrant::builder()
            .workspace_root(WorkspaceRoot::parse("/workspace").expect("absolute root"))
            .program_id(DriveProgramId::parse("claude-code").expect("program id"))
            .max_bytes_in(NonZeroU64::new(1 << 20).expect("nonzero"))
            .max_bytes_out(NonZeroU64::new(2 << 20).expect("nonzero"))
            .ttl(NonZeroU32::new(300).expect("nonzero"))
            .build()
            .expect("complete drive grant")
    }

    #[test]
    fn drive_grant_round_trips_with_nonzero_bounds() {
        let grant = drive_grant();
        let json = serde_json::to_string(&grant).expect("serializes");
        assert_eq!(
            serde_json::from_str::<DriveGrant>(&json).expect("deserializes"),
            grant
        );
        assert!(json.contains(r#""program_id":"claude-code""#));
        assert!(json.contains(r#""workspace_roots":["/workspace"]"#));
    }

    #[test]
    fn drive_grant_rejects_empty_or_unsafe_workspace_roots() {
        for json in [
            r#"{"workspace_roots":[],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["workspace"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["/work/../etc"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["/work//src"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["/work/"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["/work","/work"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
        ] {
            assert!(serde_json::from_str::<DriveGrant>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn drive_grant_rejects_caller_shaped_programs_and_zero_bounds() {
        for json in [
            r#"{"workspace_roots":["/work"],"program_id":"/bin/sh","max_bytes_in":1,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["/work"],"program_id":"agent","max_bytes_in":0,"max_bytes_out":1,"ttl":1}"#,
            r#"{"workspace_roots":["/work"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":0,"ttl":1}"#,
            r#"{"workspace_roots":["/work"],"program_id":"agent","max_bytes_in":1,"max_bytes_out":1,"ttl":0}"#,
        ] {
            assert!(serde_json::from_str::<DriveGrant>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn drive_grant_builder_requires_every_dimension() {
        assert_eq!(
            DriveGrant::builder().build(),
            Err(DriveGrantError::NoWorkspaceRoots)
        );
        let missing_program = DriveGrant::builder()
            .workspace_root(WorkspaceRoot::parse("/workspace").expect("absolute root"))
            .max_bytes_in(NonZeroU64::new(1).expect("nonzero"))
            .max_bytes_out(NonZeroU64::new(1).expect("nonzero"))
            .ttl(NonZeroU32::new(1).expect("nonzero"))
            .build();
        assert_eq!(missing_program, Err(DriveGrantError::MissingProgramId));
    }

    #[test]
    fn workspace_root_containment_is_path_component_aware() {
        let parent = WorkspaceRoot::parse("/workspace").expect("parent root");
        assert!(
            WorkspaceRoot::parse("/workspace")
                .expect("same root")
                .is_within(&parent)
        );
        assert!(
            WorkspaceRoot::parse("/workspace/src")
                .expect("nested root")
                .is_within(&parent)
        );
        assert!(
            !WorkspaceRoot::parse("/workspace-other")
                .expect("sibling root")
                .is_within(&parent)
        );
        assert!(parent.is_within(&WorkspaceRoot::parse("/").expect("filesystem root")));
    }
}
