//! Inspect, validate and configure locally published artifacts.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_runtime::artifacts::artifact::{KernelArtifact, MicrovmArtifact, RootfsArtifact};
use mvm_runtime::artifacts::traits::{ArtifactValidator, BackendConfigWriter};
use mvm_runtime::artifacts::{FirecrackerConfigWriter, StaticValidator};
use serde::{Deserialize, Serialize};

pub use mvm_runtime::artifacts::artifact::{BackendConfigArtifact, ValidationReport};
pub use mvm_runtime::artifacts::manifest::ArtifactManifest;

pub mod report;

/// An exact artifact ID or an unambiguous prefix, never a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ArtifactRequest {
    pub id: String,
}

/// Local artifact operations. All paths are confined to the artifact store.
#[derive(Debug, Default)]
pub struct ArtifactService;

impl ArtifactService {
    pub fn inspect(&self, request: &ArtifactRequest) -> Result<ArtifactManifest> {
        let dir = resolve(&mvm_core::config::artifacts_dir(), &request.id)?;
        read_manifest(&dir)
    }

    pub fn validate(&self, request: &ArtifactRequest) -> Result<ValidationReport> {
        let dir = resolve(&mvm_core::config::artifacts_dir(), &request.id)?;
        let artifact = reconstruct(&read_manifest(&dir)?, &dir)?;
        StaticValidator.validate(&artifact).map_err(Into::into)
    }

    pub fn configure_firecracker(
        &self,
        request: &ArtifactRequest,
    ) -> Result<BackendConfigArtifact> {
        let dir = resolve(&mvm_core::config::artifacts_dir(), &request.id)?;
        let artifact = reconstruct(&read_manifest(&dir)?, &dir)?;
        let output = artifact
            .rootfs
            .path
            .parent()
            .context("artifact rootfs has no parent")?
            .join("firecracker.json");
        relative_path(&dir, output.strip_prefix(&dir)?)?;
        FirecrackerConfigWriter
            .write_config(&artifact)
            .map_err(Into::into)
    }
}

fn resolve(root: &Path, id: &str) -> Result<PathBuf> {
    if id.is_empty() || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
        bail!("artifact id must be a nonempty ID or prefix, not a path");
    }
    let root = root.canonicalize().context("opening the artifact store")?;
    let exact = root.join(id);
    let selected = if exact.is_dir() {
        exact
    } else {
        let mut matches = Vec::new();
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(id) && entry.path().is_dir() {
                matches.push(entry.path());
            }
        }
        match matches.len() {
            0 => bail!(
                "no artifact with id or prefix {id:?} under {}",
                root.display()
            ),
            1 => matches.remove(0),
            n => bail!("prefix {id:?} matches {n} artifacts — provide a longer prefix"),
        }
    };
    let selected = selected.canonicalize()?;
    if !selected.starts_with(&root) || selected == root {
        bail!("artifact directory escapes the artifact store");
    }
    Ok(selected)
}

fn relative_path(dir: &Path, path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("artifact path must be relative and cannot escape its directory");
    }
    let joined = dir.join(path);
    // Validate existing files and the nearest existing ancestor of an output.
    let mut existing = joined.as_path();
    while std::fs::symlink_metadata(existing).is_err() {
        existing = existing
            .parent()
            .context("artifact path has no existing parent")?;
    }
    if !existing.canonicalize()?.starts_with(dir.canonicalize()?) {
        bail!("artifact path escapes its directory through a symlink");
    }
    Ok(joined)
}

fn read_manifest(dir: &Path) -> Result<ArtifactManifest> {
    relative_path(dir, Path::new("manifest.json"))?;
    ArtifactManifest::read_from_dir(dir)?
        .with_context(|| format!("no manifest.json in {}", dir.display()))
}

fn reconstruct(m: &ArtifactManifest, dir: &Path) -> Result<MicrovmArtifact> {
    Ok(MicrovmArtifact {
        id: m.artifact_id,
        arch: m.arch,
        backend: m.backend,
        kernel: KernelArtifact {
            path: relative_path(dir, &m.kernel.path)?,
            format: m.kernel.format,
            hash: m.kernel.hash.clone(),
            version: m.kernel.version.clone(),
        },
        rootfs: RootfsArtifact {
            path: relative_path(dir, &m.rootfs.path)?,
            format: m.rootfs.format,
            hash: m.rootfs.hash.clone(),
            size_bytes: m.rootfs.size,
            read_only: true,
        },
        boot_args: mvm_runtime::compat::compat(m.backend)
            .required_boot_args
            .iter()
            .map(|s| s.to_string())
            .collect(),
        config_path: m
            .config_path
            .as_ref()
            .map(|p| relative_path(dir, p))
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_requests_are_strict_and_never_accept_paths() {
        assert!(serde_json::from_str::<ArtifactRequest>(r#"{"id":"abc","path":"/tmp"}"#).is_err());
        let root = tempfile::tempdir().unwrap();
        for id in ["", "..", "../outside", "/tmp", "a/b", "a\\b"] {
            assert!(resolve(root.path(), id).is_err(), "{id}");
        }
    }

    #[test]
    fn resolves_exact_and_unique_prefix_but_refuses_ambiguity() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("abc-1")).unwrap();
        assert_eq!(
            resolve(root.path(), "abc").unwrap(),
            root.path().join("abc-1").canonicalize().unwrap()
        );
        std::fs::create_dir(root.path().join("abc-2")).unwrap();
        assert!(resolve(root.path(), "abc").is_err());
        assert!(resolve(root.path(), "abc-1").is_ok());
        assert!(resolve(root.path(), "missing").is_err());
    }

    #[test]
    fn manifest_paths_cannot_escape() {
        let root = tempfile::tempdir().unwrap();
        assert!(relative_path(root.path(), Path::new("kernel")).is_ok());
        for path in ["../kernel", "/kernel", "nested/../../kernel", ""] {
            assert!(relative_path(root.path(), Path::new(path)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_inputs_and_outputs_cannot_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        assert!(resolve(root.path(), "escape").is_err());
        assert!(relative_path(root.path(), Path::new("escape/output")).is_err());
        std::os::unix::fs::symlink(outside.path().join("missing"), root.path().join("dangling"))
            .unwrap();
        assert!(relative_path(root.path(), Path::new("dangling")).is_err());
    }
}
