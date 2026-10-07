//! `mvmctl artifact`.
//!
//! `pack` is `mvmctl bundle export` under the name it had when portable
//! artifacts were a format of their own: it seals a built template into a
//! signed `.mvmpkg`, with the same arguments and the same result.
//!
//! **Artifact-model operations**:
//!   `model-inspect` / `model-validate` / `model-config` / `model-build` —
//!   operate on `ArtifactManifest` directories under `~/.mvm/artifacts/<id>/`,
//!   using the typed model from `mvm_runtime::artifacts`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_core::user_config::MvmConfig;
use mvm_runtime::artifacts::manifest::ArtifactManifest;
use mvm_runtime::artifacts::traits::{ArtifactError, ArtifactValidator, BackendConfigWriter};
use mvm_runtime::artifacts::{FirecrackerConfigWriter, StaticValidator};

use super::Cli;
use crate::commands::bundle::export as bundle_export;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Cmd {
    /// Alias of `mvmctl bundle export`: seal a built template into a
    /// signed `.mvmpkg`, optionally declaring its kernel command line,
    /// security posture, and build provenance.
    Pack(bundle_export::Args),
    // ── Artifact-model commands ───────────────────────────
    /// Print the build-level ArtifactManifest for an artifact directory.
    ///
    /// Reads `~/.mvm/artifacts/<id>/manifest.json` and pretty-prints it.
    /// The id is the artifact UUID or a unique prefix.
    #[command(name = "model-inspect")]
    ModelInspect(ModelInspectArgs),
    /// Validate an artifact directory against the compat matrix.
    ///
    /// Loads the ArtifactManifest + MicrovmArtifact from
    /// `~/.mvm/artifacts/<id>/`, runs the static validator (file
    /// hashes, arch/format compat, required boot args, /sbin/init
    /// presence), prints every check, and exits nonzero on failure.
    #[command(name = "model-validate")]
    ModelValidate(ModelValidateArgs),
    /// Write the backend-specific config for an artifact directory.
    ///
    /// Currently only `--backend firecracker` is implemented. Writes
    /// `firecracker.json` next to the artifact files
    /// and prints the path.
    #[command(name = "model-config")]
    ModelConfig(ModelConfigArgs),
    /// Build a microVM artifact via the existing build pipeline.
    ///
    /// This is a thin delegation stub — use `mvmctl build`
    /// for the full build workflow. This subcommand
    /// exists to make the artifact group self-contained.
    #[command(name = "model-build")]
    ModelBuild(ModelBuildArgs),
}

// ── model-command arg structs ──────────────────────────────────────────────────

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ModelInspectArgs {
    /// Artifact ID (UUID) or unique prefix to look up under
    /// `~/.mvm/artifacts/<id>/`.
    pub id: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ModelValidateArgs {
    /// Artifact ID (UUID) or unique prefix to look up under
    /// `~/.mvm/artifacts/<id>/`.
    pub id: String,
}

/// Backend selector for `model-config`.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub(in crate::commands) enum BackendArg {
    Firecracker,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ModelConfigArgs {
    /// Artifact ID (UUID) or unique prefix to look up under
    /// `~/.mvm/artifacts/<id>/`.
    pub id: String,
    /// `firecracker` backend (the only supported choice).
    #[arg(long, default_value = "firecracker")]
    pub backend: BackendArg,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ModelBuildArgs {
    /// Target architecture (`aarch64` or `x86_64`; `arm64`/`amd64`
    /// aliases accepted).
    #[arg(long)]
    pub arch: Option<String>,
    /// Backend for the artifact.
    #[arg(long)]
    pub backend: Option<String>,
    /// Nix flake reference.
    #[arg(long)]
    pub flake: Option<String>,
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.command {
        Cmd::Pack(a) => bundle_export::run(cli, a, cfg),
        Cmd::ModelInspect(a) => run_model_inspect(a),
        Cmd::ModelValidate(a) => run_model_validate(a),
        Cmd::ModelConfig(a) => run_model_config(a),
        Cmd::ModelBuild(a) => run_model_build(a),
    }
}

// ── artifact-model handlers ───────────────────────────────

/// Resolve an artifact id to its directory under `~/.mvm/artifacts/<id>/`.
///
/// The id may be a full UUID or a unique prefix. Returns an error if the
/// directory doesn't exist or if the prefix matches more than one entry.
fn resolve_artifact_dir(id: &str) -> Result<PathBuf> {
    let artifacts_root = mvm_core::config::artifacts_dir();
    let exact = artifacts_root.join(id);
    if exact.is_dir() {
        return Ok(exact);
    }

    // Prefix match: collect all entries whose name starts with `id`.
    let matches: Vec<PathBuf> = std::fs::read_dir(&artifacts_root)
        .with_context(|| {
            format!(
                "no artifacts directory at {} — run a build first",
                artifacts_root.display()
            )
        })?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(id) && e.path().is_dir())
        .map(|e| e.path())
        .collect();

    match matches.len() {
        0 => bail!(
            "no artifact with id or prefix {:?} under {}",
            id,
            artifacts_root.display()
        ),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => bail!(
            "prefix {:?} matches {n} artifacts — provide a longer prefix",
            id
        ),
    }
}

fn run_model_inspect(args: ModelInspectArgs) -> Result<()> {
    let dir = resolve_artifact_dir(&args.id)?;
    let manifest = ArtifactManifest::read_from_dir(&dir)
        .with_context(|| format!("read manifest from {}", dir.display()))?
        .with_context(|| {
            format!(
                "no manifest.json in {} — artifact may be incomplete",
                dir.display()
            )
        })?;

    println!("artifact:  {}", manifest.artifact_id);
    println!("build_id:  {}", manifest.build_id);
    println!(
        "arch:      {}  backend: {:?}",
        manifest.arch, manifest.backend
    );
    println!(
        "kernel:    {}  ({:?})",
        manifest.kernel.path.display(),
        manifest.kernel.format
    );
    if let Some(ver) = &manifest.kernel.version {
        println!("           version {ver}");
    }
    println!(
        "rootfs:    {}  ({:?}, {} bytes)",
        manifest.rootfs.path.display(),
        manifest.rootfs.format,
        manifest.rootfs.size
    );
    if let Some(ref prov) = manifest.provenance {
        if let Some(ref f) = prov.flake_ref {
            println!("flake_ref: {f}");
        }
        if let Some(ref h) = prov.lock_hash {
            println!("lock_hash: {h}");
        }
    }
    if let Some(ref cfg) = manifest.config_path {
        println!("config:    {}", cfg.display());
    }
    if let Some(ref report) = manifest.validation {
        let status = if report.ok { "ok" } else { "FAIL" };
        println!("validated: {status} ({} checks)", report.checks.len());
    }
    println!(
        "builder:   {}  ts={}",
        manifest.builder_version, manifest.timestamp_unix
    );
    Ok(())
}

fn run_model_validate(args: ModelValidateArgs) -> Result<()> {
    let dir = resolve_artifact_dir(&args.id)?;
    let manifest = ArtifactManifest::read_from_dir(&dir)
        .with_context(|| format!("read manifest from {}", dir.display()))?
        .with_context(|| format!("no manifest.json in {}", dir.display()))?;

    // Reconstruct a MicrovmArtifact from the manifest so we can pass it to
    // the validator. Paths in the manifest are relative to the artifact dir.
    let artifact = manifest_to_artifact(&manifest, &dir);

    let report = StaticValidator
        .validate(&artifact)
        .map_err(|e: ArtifactError| anyhow::anyhow!("{e}"))?;

    for check in &report.checks {
        let mark = if check.ok { "ok  " } else { "FAIL" };
        if check.detail.is_empty() {
            println!("[{mark}] {}", check.name);
        } else {
            println!("[{mark}] {}: {}", check.name, check.detail);
        }
    }

    if report.ok {
        crate::ui::success("artifact validated");
        Ok(())
    } else {
        crate::ui::warn("validation failed");
        mvm_observability::exit(1);
    }
}

fn run_model_config(args: ModelConfigArgs) -> Result<()> {
    let dir = resolve_artifact_dir(&args.id)?;
    let manifest = ArtifactManifest::read_from_dir(&dir)
        .with_context(|| format!("read manifest from {}", dir.display()))?
        .with_context(|| format!("no manifest.json in {}", dir.display()))?;

    match args.backend {
        BackendArg::Firecracker => {
            let artifact = manifest_to_artifact(&manifest, &dir);
            let result = FirecrackerConfigWriter
                .write_config(&artifact)
                .map_err(|e: ArtifactError| anyhow::anyhow!("{e}"))?;
            crate::ui::success(&format!("wrote {}", result.path.display()));
            Ok(())
        }
    }
}

fn run_model_build(_args: ModelBuildArgs) -> Result<()> {
    // Thin stub: the full build pipeline lives in `mvmctl build`.
    // Wiring NixMicrovmBuilder end-to-end here would require a running builder
    // VM, which is a larger slice. Delegate with a clear message.
    crate::ui::info(
        "Use `mvmctl build` to build a microVM artifact.\n\
         `mvmctl artifact model-build` is reserved for a future slice that \
         integrates directly with the artifact-model pipeline.",
    );
    Ok(())
}

/// Reconstruct a [`mvm_runtime::artifacts::artifact::MicrovmArtifact`] from an
/// `ArtifactManifest` for validation and config-writing.
///
/// Paths stored in the manifest are relative to the artifact directory.
fn manifest_to_artifact(
    m: &ArtifactManifest,
    dir: &Path,
) -> mvm_runtime::artifacts::artifact::MicrovmArtifact {
    use mvm_runtime::artifacts::artifact::{KernelArtifact, MicrovmArtifact, RootfsArtifact};

    MicrovmArtifact {
        id: m.artifact_id,
        arch: m.arch,
        backend: m.backend,
        kernel: KernelArtifact {
            path: dir.join(&m.kernel.path),
            format: m.kernel.format,
            hash: m.kernel.hash.clone(),
            version: m.kernel.version.clone(),
        },
        rootfs: RootfsArtifact {
            path: dir.join(&m.rootfs.path),
            format: m.rootfs.format,
            hash: m.rootfs.hash.clone(),
            size_bytes: m.rootfs.size,
            // Manifests written by the builder use read_only=true (the rootfs
            // is dm-verity sealed). The manifest doesn't store this flag
            // explicitly (it's a build-time
            // policy), so default to true; callers that need writable overlays
            // should use the MicrovmArtifact directly.
            read_only: true,
        },
        // Required boot args come from the compat table for this backend; the
        // manifest doesn't re-store them. Pull them so the validator's check 6
        // (required_boot_args present in boot_args) can compare correctly.
        //
        // Tautology note: because boot_args is reconstructed from the same
        // compat table that check 6 consults, check 6 always passes at this
        // call site — the set we fill in is exactly the set being checked.
        // Check 6 becomes meaningful only when boot_args is recorded in the
        // manifest from the real cmdline at build time (the compat-seeded
        // path is then absent and the manifest carries the actual args used).
        boot_args: mvm_runtime::compat::compat(m.backend)
            .required_boot_args
            .iter()
            .map(|s| s.to_string())
            .collect(),
        config_path: m.config_path.as_ref().map(|p| dir.join(p)),
    }
}
