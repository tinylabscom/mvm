//! Optional, digest-bound task scenario for one published pack environment.
//!
//! A scenario is metadata that travels beside a runnable environment archive,
//! never inside it and never instead of it. It names the exact archive it was
//! written against by content digest, the public inputs a fresh instance starts
//! with, the outputs collected after the run, the limits the run is held to,
//! and the checks that grade it. An ordinary pack run needs no scenario.
//!
//! The document is laid out next to two asset trees:
//!
//! - `public/` holds initial files staged into each fresh workspace.
//! - `private/` holds expected answers and verifier inputs. It is never staged
//!   into the workload's instance; a command check sees it only inside a
//!   separate verifier instance started after the workload's has gone.
//!
//! Every path in the document is relative and validated with the PackSpec path
//! grammar, so no field can name a host path or climb out of its tree. Checks
//! may only read paths the scenario collects. Deserialization validates the
//! whole document; direct Rust construction must call
//! [`PackScenario::validate`].

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pack_lock::lower_hex;
use crate::pack_spec::{PackIdentity, PackTarget, relative_path, release_version, token};

/// Scenario schema version, independent of PackSpec, PackLock and bundle
/// versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PackScenarioSchema {
    #[serde(rename = "mvm.pack-scenario/v1")]
    V1,
}

/// Upper bound on a run's wall clock: one day.
pub const MAX_WALL_CLOCK_SECS: u32 = 86_400;
/// Upper bound on the bytes collected from one run: 256 MiB.
pub const MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
/// Upper bound on the files collected from one run.
pub const MAX_OUTPUT_FILES: u32 = 65_536;
/// Upper bound on the instructions text, in bytes.
pub const MAX_INSTRUCTIONS_BYTES: usize = 64 * 1024;

/// The exact environment a scenario was written against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ScenarioEnvironment {
    pub identity: PackIdentity,
    pub target: PackTarget,
    /// Lowercase hex SHA-256 of the runnable `.mvmpkg` archive, the same
    /// content address the bundle store installs it under. A scenario never
    /// runs against any other archive, including a rebuild of the same
    /// version.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 64, max = 64), regex(pattern = r"^[0-9a-f]{64}$"))
    )]
    pub bundle_sha256: String,
}

/// Bounds every run is held to. All are required and positive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ScenarioLimits {
    /// Wall clock for the workload run, and separately for each verifier run.
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 86400)))]
    pub wall_clock_secs: u32,
    /// Total bytes collected across every output of one run.
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 268435456)))]
    pub max_output_bytes: u64,
    /// Total regular files collected across every output of one run.
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 65536)))]
    pub max_output_files: u32,
}

/// Copy a `public/`-relative file or tree into the workspace before the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ScenarioInitialFile {
    /// Path under `public/`.
    pub source: String,
    /// Workspace-relative destination.
    pub destination: String,
}

/// One grading check. Paths named by `path` are workspace-relative and must
/// lie inside a collected output; paths named by `expected` are relative to
/// `private/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ScenarioCheck {
    /// The collected output contains a regular file at `path`.
    FileExists { name: String, path: String },
    /// The collected file at `path` is byte-identical to `private/<expected>`.
    FileMatches {
        name: String,
        path: String,
        expected: String,
    },
    /// The JSON value at RFC 6901 `pointer` inside the collected file at
    /// `path` equals the whole JSON document `private/<expected>`.
    JsonMatches {
        name: String,
        path: String,
        pointer: String,
        expected: String,
    },
    /// Run literal `argv` in a fresh verifier instance of the same environment
    /// that sees the collected outputs and `private/`, and require
    /// `exit_code`. The workload's instance is gone before this starts.
    Command {
        name: String,
        argv: Vec<String>,
        exit_code: i32,
    },
}

impl ScenarioCheck {
    /// The check's author-chosen name, unique within a scenario.
    pub fn name(&self) -> &str {
        match self {
            Self::FileExists { name, .. }
            | Self::FileMatches { name, .. }
            | Self::JsonMatches { name, .. }
            | Self::Command { name, .. } => name,
        }
    }

    /// The collected path the check reads, if it reads one on the host.
    pub fn output_path(&self) -> Option<&str> {
        match self {
            Self::FileExists { path, .. }
            | Self::FileMatches { path, .. }
            | Self::JsonMatches { path, .. } => Some(path),
            Self::Command { .. } => None,
        }
    }

    /// The `private/`-relative file the check compares against, if any.
    pub fn expected_path(&self) -> Option<&str> {
        match self {
            Self::FileMatches { expected, .. } | Self::JsonMatches { expected, .. } => {
                Some(expected)
            }
            Self::FileExists { .. } | Self::Command { .. } => None,
        }
    }
}

/// A complete scenario document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackScenarioWire", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PackScenario {
    pub schema: PackScenarioSchema,
    /// Scenario name: a token, distinct from the environment's pack name.
    pub name: String,
    /// SemVer 2.0 scenario version, independent of the environment version.
    pub version: String,
    pub environment: ScenarioEnvironment,
    /// Task instructions handed to the workload. Public by construction.
    pub instructions: String,
    pub initial_files: Vec<ScenarioInitialFile>,
    /// Workspace-relative files or trees collected after the run.
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub outputs: Vec<String>,
    pub limits: ScenarioLimits,
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub checks: Vec<ScenarioCheck>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackScenarioWire {
    schema: PackScenarioSchema,
    name: String,
    version: String,
    environment: ScenarioEnvironment,
    instructions: String,
    initial_files: Vec<ScenarioInitialFile>,
    outputs: Vec<String>,
    limits: ScenarioLimits,
    checks: Vec<ScenarioCheck>,
}

impl TryFrom<PackScenarioWire> for PackScenario {
    type Error = PackScenarioError;

    fn try_from(wire: PackScenarioWire) -> Result<Self, Self::Error> {
        let scenario = Self {
            schema: wire.schema,
            name: wire.name,
            version: wire.version,
            environment: wire.environment,
            instructions: wire.instructions,
            initial_files: wire.initial_files,
            outputs: wire.outputs,
            limits: wire.limits,
            checks: wire.checks,
        };
        scenario.validate()?;
        Ok(scenario)
    }
}

/// Validation errors carry no document contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackScenarioError {
    #[error("invalid scenario name or version: expected a token and a SemVer 2.0 version")]
    Identity,
    #[error(
        "invalid environment: expected a pack identity and a lowercase hex SHA-256 archive digest"
    )]
    Environment,
    #[error("instructions exceed 65536 bytes or contain NUL")]
    Instructions,
    #[error("unsafe path: expected a normalized relative path without traversal")]
    Path,
    #[error("a scenario must collect at least one output, and outputs must not overlap")]
    Outputs,
    #[error("limits must be positive and within the documented ceilings")]
    Limits,
    #[error("a scenario needs at least one uniquely named check")]
    Checks,
    #[error("a check reads a path the scenario does not collect")]
    Uncollected,
    #[error("a JSON pointer must be empty or start with '/'")]
    Pointer,
    #[error("a command check needs a nonempty executable and no NUL bytes")]
    Command,
    #[error("could not serialize PackScenario")]
    Serialization,
}

impl PackScenario {
    /// Validate both deserialized and directly constructed scenarios.
    pub fn validate(&self) -> Result<(), PackScenarioError> {
        if !token(&self.name) || !release_version(&self.version) {
            return Err(PackScenarioError::Identity);
        }
        self.environment
            .identity
            .validate()
            .map_err(|_| PackScenarioError::Environment)?;
        if !lower_hex(&self.environment.bundle_sha256, 64) {
            return Err(PackScenarioError::Environment);
        }
        if self.instructions.len() > MAX_INSTRUCTIONS_BYTES || self.instructions.contains('\0') {
            return Err(PackScenarioError::Instructions);
        }
        for file in &self.initial_files {
            path(&file.source)?;
            path(&file.destination)?;
        }
        self.validate_outputs()?;
        let limits = &self.limits;
        if !(1..=MAX_WALL_CLOCK_SECS).contains(&limits.wall_clock_secs)
            || !(1..=MAX_OUTPUT_BYTES).contains(&limits.max_output_bytes)
            || !(1..=MAX_OUTPUT_FILES).contains(&limits.max_output_files)
        {
            return Err(PackScenarioError::Limits);
        }
        self.validate_checks()
    }

    fn validate_outputs(&self) -> Result<(), PackScenarioError> {
        if self.outputs.is_empty() {
            return Err(PackScenarioError::Outputs);
        }
        for (index, output) in self.outputs.iter().enumerate() {
            path(output)?;
            if self.outputs[..index]
                .iter()
                .any(|earlier| within(output, earlier) || within(earlier, output))
            {
                return Err(PackScenarioError::Outputs);
            }
        }
        Ok(())
    }

    fn validate_checks(&self) -> Result<(), PackScenarioError> {
        if self.checks.is_empty() {
            return Err(PackScenarioError::Checks);
        }
        for (index, check) in self.checks.iter().enumerate() {
            let name = check.name();
            if !token(name) || self.checks[..index].iter().any(|c| c.name() == name) {
                return Err(PackScenarioError::Checks);
            }
            if let Some(read) = check.output_path() {
                path(read)?;
                if !self.collects(read) {
                    return Err(PackScenarioError::Uncollected);
                }
            }
            if let Some(expected) = check.expected_path() {
                path(expected)?;
            }
            match check {
                ScenarioCheck::JsonMatches { pointer, .. }
                    if !(pointer.is_empty() || pointer.starts_with('/'))
                        || pointer.contains('\0') =>
                {
                    return Err(PackScenarioError::Pointer);
                }
                ScenarioCheck::Command { argv, .. }
                    if argv.first().is_none_or(|a| a.trim().is_empty())
                        || argv.iter().any(|a| a.contains('\0')) =>
                {
                    return Err(PackScenarioError::Command);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Whether `path` lies at or below one of the collected outputs.
    pub fn collects(&self, path: &str) -> bool {
        self.outputs.iter().any(|output| within(path, output))
    }

    /// Compact UTF-8 JSON with sorted object keys and no trailing newline.
    pub fn canonical_json(&self) -> Result<Vec<u8>, PackScenarioError> {
        self.validate()?;
        let mut value = serde_json::to_value(self).map_err(|_| PackScenarioError::Serialization)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).map_err(|_| PackScenarioError::Serialization)
    }

    /// Lowercase hex SHA-256 of [`Self::canonical_json`]: the scenario's own
    /// identity, distinct from the environment digest it binds.
    pub fn sha256(&self) -> Result<String, PackScenarioError> {
        let digest = Sha256::digest(self.canonical_json()?);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            for nibble in [byte >> 4, byte & 0x0f] {
                hex.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            }
        }
        Ok(hex)
    }
}

fn path(value: &str) -> Result<(), PackScenarioError> {
    relative_path(value, false).map_err(|_| PackScenarioError::Path)
}

/// Whether `path` equals `root` or lies below it, compared by component.
fn within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}
