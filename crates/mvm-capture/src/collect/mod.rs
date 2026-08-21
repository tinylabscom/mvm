//! Host-side project and environment collectors.
//!
//! The public entry point is [`collect_project`], which returns a
//! [`CaptureReportV1`](crate::report::CaptureReportV1). Linux-specific
//! collectors live in `linux.rs`; other platforms get a safe stub that
//! still parses manifests and records platform facts.

use crate::CaptureError;
use crate::report::{CaptureReportV1, Evidence, Observation, ObservationKind};
use std::path::{Path, PathBuf};

mod elf;
mod platform;
mod project;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod package;
#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(target_os = "linux")]
mod trace;

/// Bounds on filesystem traversal.
#[derive(Clone, Debug)]
pub struct TraverseLimits {
    pub max_files: usize,
    pub max_depth: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_seconds: u64,
}

impl Default for TraverseLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_depth: 12,
            max_file_bytes: 1_048_576,
            max_total_bytes: 100_663_296,
            max_seconds: 60,
        }
    }
}

/// Options for project capture.
#[derive(Clone, Debug, Default)]
pub struct CollectOptions {
    pub project_path: PathBuf,
    pub explicit_commands: Vec<String>,
    pub limits: TraverseLimits,
}

/// Non-file parameters for [`inspect_executable`].
pub(crate) struct InspectMeta<'a> {
    pub source: &'a str,
    pub confidence: crate::report::Confidence,
    pub name: Option<&'a str>,
    pub warnings: Vec<String>,
    pub provenance: Vec<String>,
}

/// Collect a raw capture report for the project at `options.project_path`.
///
/// The collector is read-only: it inspects files and package databases but
/// never executes discovered scripts or installation hooks. Only commands
/// explicitly supplied by the user may be traced, and tracing is gated to
/// Linux hosts with a safe, bounded collector.
pub fn collect_project(options: &CollectOptions) -> Result<CaptureReportV1, CaptureError> {
    let mut report = CaptureReportV1::new("mvm-capture/1.0");

    report.platform = platform::collect_platform_facts();
    project::collect_manifests(&mut report, &options.project_path, &options.limits)?;

    #[cfg(target_os = "linux")]
    {
        linux::collect_packages(&mut report)?;
        linux::collect_path_executables(&mut report, &options.limits)?;
        if !options.explicit_commands.is_empty() {
            linux::trace_explicit_commands(&mut report, &options.explicit_commands)?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        stub::record_unsupported(&mut report);
    }

    redact_secrets(&mut report);
    Ok(report)
}

/// Inspect an executable file and append an observation with ELF metadata.
pub(crate) fn inspect_executable(
    report: &mut CaptureReportV1,
    path: &Path,
    display_path: &Path,
    meta: InspectMeta<'_>,
    limits: &TraverseLimits,
) -> Result<(), CaptureError> {
    let content_hash = project::hash_bytes(&read_limited(path, limits.max_file_bytes)?);
    let mut evidence = Evidence {
        observed_path: Some(display_path.display().to_string()),
        content_hash: Some(content_hash),
        executable_name: meta.name.map(str::to_owned),
        ..Default::default()
    };

    // Read a bounded prefix for ELF parsing; metadata lives in the first page.
    let prefix_len = limits.max_file_bytes.min(65_536);
    if let Ok(bytes) = read_limited(path, prefix_len) {
        if let Some(parsed) = elf::parse_elf_metadata(&bytes)? {
            evidence.interpreter = parsed.interpreter;
            evidence.needed_libraries = parsed.needed_libraries;
            evidence.build_id = parsed.build_id;
        }
    }

    report.observations.push(Observation {
        id: obs_id("exec", display_path),
        kind: ObservationKind::Executable,
        path: Some(display_path.display().to_string()),
        source: meta.source.to_owned(),
        evidence,
        confidence: meta.confidence,
        warnings: meta.warnings,
        provenance: meta.provenance,
    });
    Ok(())
}

/// Remove any accidental secret material from a report in place.
fn redact_secrets(report: &mut CaptureReportV1) {
    for obs in &mut report.observations {
        if obs.evidence.sensitivity == crate::report::Sensitivity::Secret {
            obs.evidence.content_hash = None;
            obs.evidence.build_id = None;
            obs.path = None;
        }
    }
}

/// Generate a short stable observation id.
pub(crate) fn obs_id(prefix: &str, path: impl AsRef<Path>) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    prefix.hash(&mut hasher);
    path.as_ref().as_os_str().hash(&mut hasher);
    format!("{}-{:016x}", prefix, hasher.finish())
}

/// Read a small file with bounded size.
pub(crate) fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, CaptureError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    if !metadata.is_file() {
        return Err(CaptureError::NotAFile(path.to_path_buf()));
    }
    if metadata.len() > max_bytes {
        return Err(CaptureError::FileTooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            max: max_bytes,
        });
    }
    let mut buf = Vec::with_capacity(metadata.len() as usize);
    let mut file = file;
    file.read_to_end(&mut buf)
        .map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    Ok(buf)
}
