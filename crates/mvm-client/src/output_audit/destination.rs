//! Host destination policy shared by output preparation and frontends.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Host trust roots and credential stores that must not receive guest outputs.
pub fn protected_host_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        mvm_core::config::mvm_keys_dir(),
        mvm_core::config::mvm_audit_dir(),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        for sub in [".ssh", ".gnupg", ".aws"] {
            roots.push(PathBuf::from(&home).join(sub));
        }
    }
    roots
}

// A protected root need not exist yet. Resolve its existing ancestor without
// creating directories or treating a dangling symlink as a missing component.
fn resolve_root(path: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::canonicalize(path)
            .with_context(|| format!("resolving protected directory '{}'", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().context("protected directory has no parent")?;
            let name = path
                .file_name()
                .context("protected directory has no name")?;
            Ok(resolve_root(parent)?.join(name))
        }
        Err(error) => Err(error.into()),
    }
}

/// Resolve an output destination through its existing parent and enforce host
/// protected roots. A nonexistent final directory is allowed; missing parents,
/// populated directories and symlink destinations are not.
pub fn resolve_output_destination(host_dir: &str) -> Result<PathBuf> {
    let raw = match (host_dir.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(host_dir),
    };
    let absolute = if raw.is_absolute() {
        raw
    } else {
        std::env::current_dir()
            .context("resolving current dir for a relative output directory")?
            .join(raw)
    };
    let name = absolute.file_name().with_context(|| {
        format!("output directory '{host_dir}' must name a directory, not a root or `..`")
    })?;
    let parent = absolute
        .parent()
        .with_context(|| format!("output directory '{host_dir}' has no parent directory"))?;
    let destination = std::fs::canonicalize(parent)
        .with_context(|| format!("output directory '{host_dir}': its parent must already exist"))?
        .join(name);
    validate_protected_destination(&destination)?;
    mvm_fs::output::check_destination_available(&destination)
        .with_context(|| format!("output directory '{host_dir}'"))?;
    Ok(destination)
}

pub(super) fn validate_protected_destination(destination: &Path) -> Result<()> {
    for root in protected_host_roots() {
        let resolved = resolve_root(&root)?;
        if destination.starts_with(&resolved) {
            anyhow::bail!(
                "refusing to collect outputs into '{}' — it is inside a protected directory '{}'",
                destination.display(),
                root.display()
            );
        }
    }
    Ok(())
}
