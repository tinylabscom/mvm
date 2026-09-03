//! Install a declared dependency set in the isolated builder environment.
//!
//! The command is the development entry point for producing a sealed
//! dependency volume from a lockfile. Cache misses run the existing builder
//! install pipeline; cache hits only verify and reuse the already sealed
//! volume. Production admission still consumes only the resulting sealed
//! volume and never performs a live package install.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use mvm_build::app_deps::{GateLevel, InstallSpec, Language};

/// Arguments for `mvmctl deps install`.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Lockfile to install. The bytes are hashed and pinned in the sealed
    /// volume manifest.
    #[arg(long, value_name = "PATH")]
    pub lockfile: PathBuf,

    /// Project directory containing the lockfile and its installer inputs.
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub source_root: PathBuf,

    /// Dependency ecosystem used to interpret the project inputs.
    #[arg(long, value_enum)]
    pub language: LanguageArg,

    /// Override the sealed dependency-volume cache root.
    #[arg(long)]
    pub cache_root: Option<PathBuf>,

    /// Emit a machine-readable JSON result on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(in crate::commands) enum LanguageArg {
    Python,
    Node,
}

impl From<LanguageArg> for Language {
    fn from(value: LanguageArg) -> Self {
        match value {
            LanguageArg::Python => Self::Python,
            LanguageArg::Node => Self::Node,
        }
    }
}

#[derive(Debug, Serialize)]
struct InstallOutcome {
    volume_hash: String,
    manifest_sha256: String,
    lockfile_sha256: String,
    volume_dir: PathBuf,
    cache_hit: bool,
    gate: GateLevel,
    language: Language,
}

pub(super) fn run(args: Args) -> Result<()> {
    let lockfile = existing_path(&args.lockfile, "lockfile")?;
    let source_root = existing_directory(&args.source_root, "source root")?;
    if !lockfile.starts_with(&source_root) {
        bail!(
            "lockfile `{}` must be inside source root `{}`",
            lockfile.display(),
            source_root.display()
        );
    }
    let cache_root = args
        .cache_root
        .as_deref()
        .map(Path::to_path_buf)
        .or_else(|| Some(mvm_build::app_deps::resolve_cache_root(None)));
    let language = Language::from(args.language);
    let spec = InstallSpec {
        lockfile,
        source_root,
        language,
        gate: GateLevel::Dev,
        cache_root_override: cache_root,
    };

    let result = install_in_builder(&spec)?;

    let outcome = InstallOutcome {
        volume_hash: result.volume_hash,
        manifest_sha256: result.manifest_sha256,
        lockfile_sha256: result.lockfile_sha256,
        volume_dir: result.volume_dir,
        cache_hit: result.cache_hit,
        gate: GateLevel::Dev,
        language,
    };
    mvm_core::audit_emit!(
        DepsAudit,
        "operation=install,volume_hash={},cache_hit={},language={},gate=dev",
        outcome.volume_hash,
        outcome.cache_hit,
        outcome.language.token(),
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        let action = if outcome.cache_hit {
            "reused"
        } else {
            "installed"
        };
        eprintln!(
            "{action} development dependency volume {} at {}",
            outcome.volume_hash,
            outcome.volume_dir.display()
        );
    }
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn install_in_builder(spec: &InstallSpec) -> Result<mvm_build::app_deps::InstallResult> {
    // The fallible resolver, deliberately. The infallible one panics when the
    // registered constructor returns an error, and on the hvf arm that error is
    // an ordinary user-facing condition — an mvmctl built without the embedded
    // Linux host binaries cannot bootstrap a builder VM. It already carries the
    // exact rebuild instruction; routed through the panicking path a reader saw
    // a Rust backtrace and "CLI thread exited unexpectedly" instead.
    let driver = mvm_build::builder_backend_select::try_resolve_builder_backend_with_override(None)
        .context("resolving the builder backend for the dependency install")?;
    let install_driver = mvm_build::app_deps::BuilderInstallDriver::new(driver.as_ref());
    mvm_build::app_deps::install_app_deps(spec, Some(&install_driver))
        .context("installing declared dependencies in the builder environment")
}

#[cfg(not(feature = "builder-vm"))]
fn install_in_builder(_spec: &InstallSpec) -> Result<mvm_build::app_deps::InstallResult> {
    bail!("mvmctl deps install requires the builder-vm feature")
}

fn existing_path(path: &Path, label: &str) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("resolving {label} `{}`", path.display()))
}

fn existing_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let resolved = existing_path(path, label)?;
    if !resolved.is_dir() {
        bail!("{label} `{}` is not a directory", path.display());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn language_arg_maps_to_install_language() {
        assert_eq!(Language::from(LanguageArg::Python), Language::Python);
        assert_eq!(Language::from(LanguageArg::Node), Language::Node);
    }

    #[test]
    fn existing_directory_rejects_a_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("not-a-directory");
        fs::write(&file, b"data").unwrap();
        let error = existing_directory(&file, "source root").unwrap_err();
        assert!(error.to_string().contains("not a directory"));
    }

    #[cfg(not(feature = "builder-vm"))]
    #[test]
    fn install_reports_missing_builder_feature() {
        let spec = InstallSpec {
            lockfile: PathBuf::from("Cargo.lock"),
            source_root: PathBuf::from("."),
            language: Language::Python,
            gate: GateLevel::Dev,
            cache_root_override: None,
        };
        let error = install_in_builder(&spec).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires the builder-vm feature")
        );
    }
}
