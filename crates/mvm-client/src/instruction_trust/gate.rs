//! The pre-boot instruction-file gate.
//!
//! Admission hands this the host paths a boot is about to copy into the guest
//! — each `--mount` source, each `--asset`, the workload's own source
//! directory — and gets back a [`ScanReport`]: every instruction file found,
//! its verdict, and what the effective enforcement mode makes of the lot.
//!
//! Every verdict becomes a chain-signed audit entry bound to the plan the boot
//! was admitted under, whatever the mode. `deny` then refuses the boot naming
//! each failing file and why; `warn` prints the same and boots; `audit` only
//! records.

use std::path::{Path, PathBuf};

use mvm_hostd::audit::emitter::InstructionTrustEvent;
use serde::Serialize;

use super::policy::{EffectivePolicy, Enforcement, InstructionTrustPolicy, PolicyError};
use super::scan::{ScanRoot, find_instruction_files};
use super::verify::{FileReport, verify_file};

/// Where the user and project policies are read from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyLocations {
    /// The user policy. `None` reads the configured location under the mvm
    /// home (`mvm_core::config::instruction_trust_policy_path`).
    pub user: Option<PathBuf>,
    /// The project root a project policy is looked for under
    /// (`<root>/.mvm/instruction-trust.toml`), if the run has one.
    pub project_root: Option<PathBuf>,
}

impl PolicyLocations {
    fn user_path(&self) -> PathBuf {
        self.user
            .clone()
            .unwrap_or_else(mvm_core::config::instruction_trust_policy_path)
    }
}

/// The publisher trust store keyed publishers named by `key_id` resolve
/// through: `~/.mvm/trusted-publishers/`, as `mvmctl trust add` writes it.
pub fn default_trust_store() -> Result<mvm_core::plan::FsTrustStore, PolicyError> {
    mvm_core::plan::FsTrustStore::default_path().map_err(|error| PolicyError::Invalid {
        path: PathBuf::from("~/.mvm/trusted-publishers"),
        reason: format!("resolving the publisher trust store: {error}"),
    })
}

/// Load and merge the user and project policies.
///
/// A broken user policy is an error: the operator wrote it to be enforced, and
/// silently falling back would run unprotected while looking protected. A
/// broken *project* policy is an error only when a user policy exists to give
/// it force; alone it is advisory, so it is reported and ignored rather than
/// letting a repository's malformed file stop the operator's boot.
pub fn load_effective_policy(
    locations: &PolicyLocations,
    trust_store: &dyn mvm_core::plan::bundle::TrustStore,
) -> Result<EffectivePolicy, PolicyError> {
    let user = InstructionTrustPolicy::load(&locations.user_path())?;
    let project_path = locations
        .project_root
        .as_deref()
        .map(mvm_core::config::project_instruction_trust_policy_path);
    let project = match project_path.as_deref().map(InstructionTrustPolicy::load) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(project))) => Some(project),
        Some(Err(error)) if user.is_some() => return Err(error),
        Some(Err(error)) => {
            let mut builtin = EffectivePolicy::builtin();
            builtin.push_note(format!("ignoring the advisory project policy: {error}"));
            return Ok(builtin);
        }
    };
    let has_user = user.is_some();
    match EffectivePolicy::merge(user, project, trust_store) {
        Err(error @ PolicyError::Invalid { .. }) if !has_user => {
            let mut builtin = EffectivePolicy::builtin();
            builtin.push_note(format!("ignoring the advisory project policy: {error}"));
            Ok(builtin)
        }
        other => other,
    }
}

/// What the gate decided for a boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing failed, or the mode is `audit`.
    Admit,
    /// Something failed under `warn`: boot, and say what.
    Warn(Vec<String>),
    /// Something failed under `deny`: do not boot.
    Refuse(String),
}

/// Every instruction file found under a set of roots, with its verdict.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub enforcement: Enforcement,
    pub origin: super::policy::PolicyOrigin,
    pub policy_sources: Vec<PathBuf>,
    pub notes: Vec<String>,
    pub files: Vec<FileReport>,
}

/// Why the scan itself could not complete.
#[derive(Debug, thiserror::Error)]
#[error("scanning {} for instruction files: {source}", root.display())]
pub struct ScanError {
    pub root: PathBuf,
    #[source]
    pub source: std::io::Error,
}

/// Find and verify every instruction file under `roots`.
///
/// A file reachable through two roots is reported once per root: each root is
/// a separate copy in the guest, and each copy is what some agent reads.
pub fn scan_roots(roots: &[ScanRoot], policy: &EffectivePolicy) -> Result<ScanReport, ScanError> {
    let mut files = Vec::new();
    for root in roots {
        let found = find_instruction_files(root, policy).map_err(|source| ScanError {
            root: root.path.clone(),
            source,
        })?;
        files.extend(found.into_iter().map(|file| verify_file(file, policy)));
    }
    Ok(ScanReport {
        enforcement: policy.enforcement(),
        origin: policy.origin(),
        policy_sources: policy.sources().to_vec(),
        notes: policy.notes().to_vec(),
        files,
    })
}

impl ScanReport {
    /// The files that did not verify.
    pub fn failures(&self) -> impl Iterator<Item = &FileReport> {
        self.files.iter().filter(|f| !f.verdict.is_verified())
    }

    /// One line per failing file: its path and why.
    #[must_use]
    pub fn failure_lines(&self) -> Vec<String> {
        self.failures()
            .map(|f| format!("{}: {}", f.file.path.display(), f.verdict.describe()))
            .collect()
    }

    /// What the effective enforcement makes of these verdicts.
    #[must_use]
    pub fn decision(&self) -> Decision {
        let lines = self.failure_lines();
        if lines.is_empty() {
            return Decision::Admit;
        }
        match self.enforcement {
            Enforcement::Audit => Decision::Admit,
            Enforcement::Warn => Decision::Warn(lines),
            Enforcement::Deny => Decision::Refuse(format!(
                "refusing to boot: {} instruction file(s) failed provenance verification under \
                 the `deny` policy ({}):\n  {}",
                lines.len(),
                self.policy_sources
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                lines.join("\n  ")
            )),
        }
    }

    /// The action the gate takes on one file, for its audit entry.
    fn action_for(&self, report: &FileReport) -> &'static str {
        if report.verdict.is_verified() {
            return "admitted";
        }
        match self.enforcement {
            Enforcement::Deny => "refused",
            Enforcement::Warn => "warned",
            Enforcement::Audit => "recorded",
        }
    }

    /// One `(event, labels)` pair per file, for the chain-signed log.
    ///
    /// Labels name the file, its digest, the verdict and its reason, the
    /// publisher when one matched, and the policy that decided — never the
    /// file's content.
    #[must_use]
    pub fn audit_records(&self) -> Vec<(InstructionTrustEvent, Vec<(String, String)>)> {
        self.files
            .iter()
            .map(|report| {
                let mut labels = vec![
                    ("path".to_string(), report.file.path.display().to_string()),
                    ("root".to_string(), report.file.root.display().to_string()),
                    (
                        "root_kind".to_string(),
                        report.file.root_kind.as_str().to_string(),
                    ),
                    (
                        "sha256".to_string(),
                        report.sha256.clone().unwrap_or_default(),
                    ),
                    (
                        "enforcement".to_string(),
                        self.enforcement.as_str().to_string(),
                    ),
                    ("policy".to_string(), self.origin.as_str().to_string()),
                    ("action".to_string(), self.action_for(report).to_string()),
                ];
                match &report.verdict {
                    super::verify::Verdict::Verified { publisher, signer } => {
                        labels.push(("publisher".to_string(), publisher.clone()));
                        labels.push(("signer".to_string(), signer.clone()));
                    }
                    super::verify::Verdict::Unsigned => {
                        labels.push(("reason".to_string(), "unsigned".to_string()));
                    }
                    super::verify::Verdict::Failed(failure) => {
                        labels.push(("reason".to_string(), failure.code().to_string()));
                        labels.push(("detail".to_string(), failure.describe()));
                    }
                }
                (report.verdict.audit_event(), labels)
            })
            .collect()
    }
}

/// The host paths a boot copies into the guest, as scan roots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootInputs {
    /// Directory shares (`--mount` sources).
    pub mounts: Vec<PathBuf>,
    /// Declared assets.
    pub assets: Vec<PathBuf>,
    /// The workload's source directory, when it has one on this host.
    pub workload_dir: Option<PathBuf>,
}

impl BootInputs {
    /// Scan roots in a stable order: workload, mounts, assets.
    #[must_use]
    pub fn roots(&self) -> Vec<ScanRoot> {
        use super::scan::RootKind;
        let mut roots: Vec<ScanRoot> = self
            .workload_dir
            .iter()
            .map(|p| ScanRoot::new(p.clone(), RootKind::Workload))
            .collect();
        roots.extend(
            self.mounts
                .iter()
                .map(|p| ScanRoot::new(p.clone(), RootKind::Mount)),
        );
        roots.extend(
            self.assets
                .iter()
                .map(|p| ScanRoot::new(p.clone(), RootKind::Asset)),
        );
        roots
    }

    /// Whether there is anything to scan.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty() && self.assets.is_empty() && self.workload_dir.is_none()
    }
}

/// Evaluate a boot's inputs: load the policy (the workload directory, when
/// present, is also where a project policy is looked for), scan, verify.
///
/// `Ok(None)` when the boot copies nothing from the host, so a run with no
/// inputs reads no policy and pays nothing.
pub fn evaluate_boot_inputs(
    inputs: &BootInputs,
    user_policy: Option<&Path>,
) -> anyhow::Result<Option<ScanReport>> {
    if inputs.is_empty() {
        return Ok(None);
    }
    let locations = PolicyLocations {
        user: user_policy.map(Path::to_path_buf),
        project_root: inputs.workload_dir.clone(),
    };
    let policy = load_effective_policy(&locations, &default_trust_store()?)?;
    Ok(Some(scan_roots(&inputs.roots(), &policy)?))
}

/// The directory a `--flake` or `--manifest` source names on this host, if
/// it names one.
///
/// A flake reference that is not a local path (`github:owner/repo`) and a
/// manifest slot name both resolve to `None`: there is no host tree to scan.
/// A manifest *file* yields its directory.
#[must_use]
pub fn local_workload_dir(flake: Option<&str>, manifest: Option<&str>) -> Option<PathBuf> {
    let candidate = flake
        .map(|f| f.strip_prefix("path:").unwrap_or(f))
        .or(manifest)?;
    let path = Path::new(candidate);
    if path.is_dir() {
        return Some(path.to_path_buf());
    }
    if path.is_file() {
        return path
            .parent()
            .map(|parent| {
                if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                }
            })
            .map(Path::to_path_buf);
    }
    None
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
