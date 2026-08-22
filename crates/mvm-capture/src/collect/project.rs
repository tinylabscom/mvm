//! Project-directory inspection: manifests, lockfiles, and ignore rules.

use crate::CaptureError;
use crate::collect::{TraverseLimits, obs_id, read_limited};
use crate::report::{CaptureReportV1, Evidence, Observation, ObservationKind, Sensitivity};
use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const IGNORE_FILES: &[&str] = &[".gitignore", ".ignore"];
const SECRET_PATTERNS: &[&str] = &[
    ".env",
    ".env.",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials",
    "token",
    "secret",
    "private_key",
    "kubeconfig",
];

pub fn collect_manifests(
    report: &mut CaptureReportV1,
    root: &Path,
    limits: &TraverseLimits,
) -> Result<(), CaptureError> {
    let mut ctx = TraverseContext::new(root, limits)?;
    visit(root, root, 0, &mut ctx, report)?;
    Ok(())
}

struct TraverseContext<'a> {
    limits: &'a TraverseLimits,
    ignore_patterns: Vec<String>,
    manifest_names: HashSet<&'static str>,
    visited: usize,
    total_bytes: u64,
    start: std::time::Instant,
}

impl<'a> TraverseContext<'a> {
    fn new(root: &'a Path, limits: &'a TraverseLimits) -> Result<Self, CaptureError> {
        let ignore_patterns = load_ignore_patterns(root)?;
        let manifest_names: HashSet<&str> = [
            "Cargo.toml",
            "Cargo.lock",
            "flake.nix",
            "flake.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pyproject.toml",
            "uv.lock",
            "requirements.txt",
            "go.mod",
            "go.sum",
            "Dockerfile",
            "mvm.toml",
            "mvm.json",
            ".env",
        ]
        .iter()
        .copied()
        .collect();

        Ok(Self {
            limits,
            ignore_patterns,
            manifest_names,
            visited: 0,
            total_bytes: 0,
            start: std::time::Instant::now(),
        })
    }

    fn check_limits(&self) -> Result<(), CaptureError> {
        if self.visited >= self.limits.max_files {
            return Err(CaptureError::LimitExceeded("max_files".to_owned()));
        }
        if self.start.elapsed().as_secs() > self.limits.max_seconds {
            return Err(CaptureError::LimitExceeded("max_seconds".to_owned()));
        }
        if self.total_bytes >= self.limits.max_total_bytes {
            return Err(CaptureError::LimitExceeded("max_total_bytes".to_owned()));
        }
        Ok(())
    }
}

fn visit(
    root: &Path,
    path: &Path,
    depth: usize,
    ctx: &mut TraverseContext<'_>,
    report: &mut CaptureReportV1,
) -> Result<(), CaptureError> {
    if depth > ctx.limits.max_depth {
        return Ok(());
    }
    ctx.check_limits()?;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    if metadata.file_type().is_dir() {
        let rel = path.strip_prefix(root).unwrap_or(path);
        if is_ignored(rel, &ctx.ignore_patterns) {
            return Ok(());
        }
        let mut entries = match std::fs::read_dir(path) {
            Ok(it) => it,
            Err(_) => return Ok(()),
        };
        while let Some(Ok(entry)) = entries.next() {
            visit(root, &entry.path(), depth + 1, ctx, report)?;
        }
        return Ok(());
    }

    if !metadata.file_type().is_file() {
        return Ok(());
    }

    ctx.visited += 1;

    let rel = path.strip_prefix(root).unwrap_or(path);
    if is_ignored(rel, &ctx.ignore_patterns) {
        return Ok(());
    }

    let size = metadata.len();
    if size > ctx.limits.max_file_bytes {
        report.warnings.push(format!(
            "skipped large file {} ({} bytes)",
            rel.display(),
            size
        ));
        return Ok(());
    }
    ctx.total_bytes += size;

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if ctx.manifest_names.contains(name) {
            let kind = match name {
                "Cargo.toml" | "package.json" | "pyproject.toml" | "go.mod" | "mvm.toml"
                | "mvm.json" => ObservationKind::ProjectManifest,
                "Dockerfile" | ".env" => ObservationKind::ConfigurationFile,
                _ => ObservationKind::Lockfile,
            };
            let content_hash = hash_bytes(&read_limited(path, ctx.limits.max_file_bytes)?);
            let sensitivity = classify_sensitivity(path);
            report.observations.push(Observation {
                id: obs_id("manifest", rel),
                kind,
                path: Some(rel.display().to_string()),
                source: "project-scan".to_owned(),
                evidence: Evidence {
                    observed_path: Some(rel.display().to_string()),
                    content_hash: Some(content_hash),
                    declared: true,
                    sensitivity,
                    ..Default::default()
                },
                confidence: crate::report::Confidence::Observed,
                warnings: vec![],
                provenance: vec![format!("scanned {}", rel.display())],
            });
        }
    }

    #[cfg(unix)]
    if is_executable_mode(metadata.permissions().mode()) {
        let _ = super::inspect_executable(
            report,
            path,
            rel,
            super::InspectMeta {
                source: "project-executable-scan",
                confidence: crate::report::Confidence::Observed,
                name: rel.file_name().and_then(|n| n.to_str()),
                warnings: vec!["executable metadata only; file was not run".to_owned()],
                provenance: vec![format!("mode bits on {}", rel.display())],
            },
            ctx.limits,
        );
    }

    Ok(())
}

fn load_ignore_patterns(root: &Path) -> Result<Vec<String>, CaptureError> {
    let mut patterns = Vec::new();
    for name in IGNORE_FILES {
        let path = root.join(name);
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                patterns.push(line.to_owned());
            }
        }
    }
    patterns.extend([
        ".git".to_owned(),
        "target".to_owned(),
        "node_modules".to_owned(),
        ".venv".to_owned(),
        "__pycache__".to_owned(),
    ]);
    Ok(patterns)
}

fn is_ignored(rel: &Path, patterns: &[String]) -> bool {
    let rel_str = rel.display().to_string();
    for pattern in patterns {
        if pattern.ends_with('/') && rel_str.starts_with(pattern.trim_end_matches('/')) {
            return true;
        }
        if rel_str == *pattern || rel_str.starts_with(&format!("{}/", pattern)) {
            return true;
        }
    }
    false
}

fn classify_sensitivity(path: &Path) -> Sensitivity {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lowered = name.to_ascii_lowercase();
    if SECRET_PATTERNS.iter().any(|p| lowered.contains(p)) {
        return Sensitivity::Secret;
    }
    Sensitivity::Public
}

#[cfg(unix)]
fn is_executable_mode(mode: u32) -> bool {
    mode & 0o111 != 0
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
