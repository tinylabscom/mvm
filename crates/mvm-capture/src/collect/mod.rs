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
    let metadata = std::fs::metadata(path).map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    if !metadata.is_file() {
        return Err(CaptureError::NotAFile(path.to_path_buf()));
    }

    let mut warnings = meta.warnings;
    let content_hash = if metadata.len() <= limits.max_file_bytes {
        Some(project::hash_bytes(&read_limited(
            path,
            limits.max_file_bytes,
        )?))
    } else {
        warnings.push(format!(
            "content hash omitted: executable is {} bytes, above the {}-byte capture limit",
            metadata.len(),
            limits.max_file_bytes
        ));
        None
    };
    let mut evidence = Evidence {
        observed_path: Some(display_path.display().to_string()),
        content_hash,
        executable_name: meta.name.map(str::to_owned),
        ..Default::default()
    };

    // Read a bounded prefix for ELF parsing; metadata lives in the first page.
    let prefix_len = limits.max_file_bytes.min(65_536);
    if let Ok(bytes) = read_prefix(path, prefix_len) {
        if let Some(parsed) = elf::parse_elf_prefix_metadata(&bytes)? {
            evidence.interpreter = parsed.interpreter;
            evidence.needed_libraries = parsed.needed_libraries;
            evidence.build_id = parsed.build_id;
            if parsed.incomplete {
                warnings.push(format!(
                    "ELF metadata outside the bounded {}-byte prefix was omitted",
                    bytes.len()
                ));
            }
        }
    }

    report.observations.push(Observation {
        id: obs_id("exec", display_path),
        kind: ObservationKind::Executable,
        path: Some(display_path.display().to_string()),
        source: meta.source.to_owned(),
        evidence,
        confidence: meta.confidence,
        warnings,
        provenance: meta.provenance,
    });
    Ok(())
}

/// Read at most `max_bytes` from the start of a regular file.
fn read_prefix(path: &Path, max_bytes: u64) -> Result<Vec<u8>, CaptureError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    let metadata = file
        .metadata()
        .map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    if !metadata.is_file() {
        return Err(CaptureError::NotAFile(path.to_path_buf()));
    }
    let capacity = usize::try_from(metadata.len().min(max_bytes)).unwrap_or(usize::MAX);
    let mut buf = Vec::with_capacity(capacity);
    file.take(max_bytes)
        .read_to_end(&mut buf)
        .map_err(|e| CaptureError::Io(path.to_path_buf(), e))?;
    Ok(buf)
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

#[cfg(test)]
mod tests {
    use super::{InspectMeta, TraverseLimits, inspect_executable};
    use crate::report::{CaptureReportV1, Confidence};
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn oversized_executable_is_observed_without_reading_it_in_full() {
        let mut file = tempfile::NamedTempFile::new().expect("create executable fixture");
        file.write_all(b"not-an-elf").expect("write file prefix");
        file.write_all(&[0; 64]).expect("pad executable fixture");

        let limits = TraverseLimits {
            max_file_bytes: 16,
            ..Default::default()
        };
        let mut report = CaptureReportV1::new("test");
        inspect_executable(
            &mut report,
            file.path(),
            Path::new("bin/tool"),
            InspectMeta {
                source: "test",
                confidence: Confidence::Observed,
                name: Some("tool"),
                warnings: Vec::new(),
                provenance: Vec::new(),
            },
            &limits,
        )
        .expect("oversized executable should remain observable");

        let observation = report.observations.first().expect("executable observation");
        assert!(observation.evidence.content_hash.is_none());
        assert!(
            observation
                .warnings
                .iter()
                .any(|warning| warning.contains("content hash omitted"))
        );
    }
}
