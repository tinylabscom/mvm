//! Versioned, evidence-oriented capture report.
//!
//! A `CaptureReportV1` records what was observed while inspecting a project
//! and its host environment. It deliberately keeps observations separate from
//! policy decisions; resolution into the canonical MVM IR happens later and
//! produces its own provenance trail.

use serde::{Deserialize, Serialize};

/// Schema version for capture reports.
pub const CAPTURE_SCHEMA_VERSION: &str = "1.0";

/// Top-level capture report.
///
/// The report is intentionally flat and serializable: every observation is
/// self-contained so third-party collectors can append observations without
/// understanding the full resolution graph.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CaptureReportV1 {
    pub schema_version: String,
    pub captured_at: String,
    pub collector: String,
    pub platform: PlatformFacts,
    pub observations: Vec<Observation>,
    pub unresolved: Vec<UnresolvedItem>,
    pub warnings: Vec<String>,
}

impl CaptureReportV1 {
    pub fn new(collector: impl Into<String>) -> Self {
        Self {
            schema_version: CAPTURE_SCHEMA_VERSION.to_owned(),
            captured_at: chrono::Utc::now().to_rfc3339(),
            collector: collector.into(),
            ..Default::default()
        }
    }
}

/// Platform facts observed from the host.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PlatformFacts {
    pub architecture: Option<String>,
    pub kernel_name: Option<String>,
    pub kernel_version: Option<String>,
    pub distribution_id: Option<String>,
    pub distribution_name: Option<String>,
    pub distribution_version: Option<String>,
    pub virtualization: Option<String>,
}

/// A single observed fact about the project or host environment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Observation {
    pub id: String,
    pub kind: ObservationKind,
    pub path: Option<String>,
    pub source: String,
    pub evidence: Evidence,
    pub confidence: Confidence,
    pub warnings: Vec<String>,
    pub provenance: Vec<String>,
}

/// Category of observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Platform,
    Distribution,
    ProjectManifest,
    Lockfile,
    Executable,
    NativePackage,
    SharedLibrary,
    Interpreter,
    ConfigurationFile,
    EnvironmentVariableName,
    NetworkEndpoint,
    Service,
    FilesystemRequirement,
    UnmanagedArtifact,
}

/// Evidence carried by an observation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Evidence {
    pub observed_path: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub package_manager: Option<String>,
    pub executable_name: Option<String>,
    pub interpreter: Option<String>,
    pub needed_libraries: Vec<String>,
    pub cpu_features: Vec<String>,
    pub build_id: Option<String>,
    pub content_hash: Option<String>,
    pub installed: bool,
    pub declared: bool,
    pub executed: bool,
    pub opened: bool,
    pub connected: bool,
    pub sensitivity: Sensitivity,
}

/// Confidence level for an observation or resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Confidence {
    #[default]
    Observed,
    Inferred,
    Heuristic,
    Unknown,
}

/// Sensitivity classification for an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Sensitivity {
    #[default]
    Public,
    Internal,
    Secret,
}

/// An item that could not be resolved into the canonical IR.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnresolvedItem {
    pub observation_id: String,
    pub reason: String,
    pub needs_review: bool,
}

/// Status of a verification attempt.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    #[default]
    Recorded,
    Built,
    Replayed,
    Failed {
        reason: String,
    },
}

/// Record of a verification attempt for a captured workload.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VerificationRecord {
    pub command: Vec<String>,
    pub status: VerificationStatus,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

/// Result of resolving a capture report into the canonical MVM IR.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolutionResult {
    pub workload: mvm_contract::ir::Workload,
    pub resolved: Vec<ResolutionRecord>,
    pub unresolved: Vec<UnresolvedItem>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub verification: Vec<VerificationRecord>,
}

/// Record of how one observation was translated into the canonical IR.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolutionRecord {
    pub observation_id: String,
    pub strategy: ResolutionStrategy,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
    pub needs_review: bool,
}

/// Strategy used to resolve an observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStrategy {
    ExistingDeclaration,
    ProjectManifest,
    NativePackage,
    NixIndex,
    ElfDependency,
    UserOverride,
    Unresolved,
}
