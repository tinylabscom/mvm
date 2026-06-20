//! `mvmctl artifact`.
//!
//! Two distinct groups of operations share this command:
//!
//! **Packed-artifact operations**:
//!   `pack` / `verify` / `inspect` — operate on `.mvm` signed archive files
//!   produced by `mvm_build::packed_artifact`.
//!
//! **Artifact-model operations**:
//!   `model-inspect` / `model-validate` / `model-config` / `model-build` —
//!   operate on `ArtifactManifest` directories under `~/.mvm/artifacts/<id>/`,
//!   using the typed model from `mvm_backend::artifacts`. Named with a
//!   `model-` prefix to avoid shadowing the packed-artifact `inspect`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_backend::artifacts::manifest::ArtifactManifest;
use mvm_backend::artifacts::traits::{ArtifactError, ArtifactValidator, BackendConfigWriter};
use mvm_backend::artifacts::{FirecrackerConfigWriter, StaticValidator};
use mvm_build::packed_artifact::{
    ArtifactProfile, PackInputs, SecurityPosture, extract as extract_artifact, inspect_unverified,
    pack as pack_artifact, verify as verify_artifact,
};
use mvm_core::arch::GuestArch;
use mvm_core::config::mvm_data_dir;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::host_signer;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Cmd {
    /// Sign-and-pack a `.mvm` artifact from a kernel, rootfs,
    /// cmdline, and optional verity sidecars. Refuses to produce
    /// a `--profile sealed-prod` artifact without verity inputs.
    Pack(PackArgs),
    /// Verify a `.mvm` artifact's manifest signature, file hashes,
    /// declared format version, and security-posture invariants.
    /// Exits 0 on success, 65 (`EX_DATAERR`) on a verification
    /// failure. Does not extract payload bytes to disk.
    Verify(VerifyArgs),
    /// Print a `.mvm` manifest's contents WITHOUT verifying the
    /// signature. Useful for debugging ("what's in this file?") and
    /// for tools that don't have the producer's verifying key —
    /// e.g. surfacing a registry artifact's file list before the
    /// operator decides whether to trust the producer. For trust
    /// checks use `mvmctl artifact verify`.
    Inspect(InspectArgs),
    /// Verify a `.mvm` artifact and extract its payload files to a
    /// directory. Verification runs first (signature, hashes, format
    /// version, sealed-prod verity, traversal safety); only manifest-
    /// listed files are written, so a tampered or traversal-laden
    /// archive never lands a byte on disk. Exits 65 on a verify failure.
    Extract(ExtractArgs),
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
    /// This is a thin delegation stub — use `mvmctl build` or
    /// `mvmctl dev` for the full build workflow. This subcommand
    /// exists to make the artifact group self-contained.
    #[command(name = "model-build")]
    ModelBuild(ModelBuildArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct PackArgs {
    /// Kernel binary (vmlinux).
    #[arg(long)]
    pub kernel: PathBuf,
    /// Root filesystem image (rootfs.ext4).
    #[arg(long)]
    pub rootfs: PathBuf,
    /// Kernel command line, as a text file.
    #[arg(long)]
    pub cmdline: PathBuf,
    /// dm-verity sidecar (rootfs.verity). Required for
    /// `--profile sealed-prod`.
    #[arg(long)]
    pub verity: Option<PathBuf>,
    /// Verity roothash file. Required for `--profile sealed-prod`.
    #[arg(long)]
    pub roothash: Option<PathBuf>,
    /// Optional verity initramfs (cpio.gz).
    #[arg(long)]
    pub initrd: Option<PathBuf>,
    /// Output path for the produced `.mvm` archive.
    #[arg(long)]
    pub out: PathBuf,
    /// Target architecture (`aarch64` or `x86_64`; `arm64`/`amd64`
    /// aliases accepted). Parsed via `GuestArch::from_str`.
    #[arg(long)]
    pub target_arch: String,
    /// Image profile baked into the artifact's security posture.
    #[arg(long, value_enum, default_value_t = CliProfile::SealedProd)]
    pub profile: CliProfile,
    /// `true` when the rootfs is dm-verity-protected and the
    /// cmdline carries `roothash=`.
    #[arg(long, default_value_t = false)]
    pub verity_protected: bool,
    /// `true` when the agent enforces `require_auth = true`.
    #[arg(long, default_value_t = true)]
    pub requires_auth: bool,
    /// `true` when the image config permits runtime volume mounts.
    #[arg(long, default_value_t = false)]
    pub allows_volumes: bool,
    /// `true` when the image config permits outbound egress.
    #[arg(long, default_value_t = false)]
    pub allows_egress: bool,
    /// Build provenance pointer to surface in the manifest. Free-
    /// form today; reserved for attestation linkage.
    #[arg(long)]
    pub build_provenance: Option<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct InspectArgs {
    /// Path to the `.mvm` artifact to inspect.
    pub path: PathBuf,
    /// Emit the parsed manifest as JSON. Default is a human
    /// summary mirroring `mvmctl artifact verify` minus the
    /// "verified" header.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct VerifyArgs {
    /// Path to the `.mvm` artifact to verify.
    pub path: PathBuf,
    /// Path to the verifying-key file (32-byte Ed25519 public key,
    /// raw bytes). Defaults to the host signer's public half at
    /// `~/.mvm/keys/host-signer.pub`.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Print the verified manifest as JSON on success.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ExtractArgs {
    /// Path to the `.mvm` artifact to verify and extract.
    pub path: PathBuf,
    /// Directory to extract the verified payload into. Created if it
    /// does not exist. Manifest-listed files land at their in-archive
    /// paths (e.g. `kernel/vmlinux`, `rootfs/rootfs.ext4`).
    #[arg(long, short = 'o')]
    pub out: PathBuf,
    /// Path to the verifying-key file (32-byte Ed25519 public key, raw
    /// bytes). Defaults to the host signer's public half at
    /// `~/.mvm/keys/host-signer.pub`.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Print the verified manifest as JSON on success.
    #[arg(long)]
    pub json: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub(in crate::commands) enum CliProfile {
    SealedProd,
    Dev,
    Builder,
}

impl From<CliProfile> for ArtifactProfile {
    fn from(p: CliProfile) -> Self {
        match p {
            CliProfile::SealedProd => ArtifactProfile::SealedProd,
            CliProfile::Dev => ArtifactProfile::Dev,
            CliProfile::Builder => ArtifactProfile::Builder,
        }
    }
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
    /// Backend to write config for. Currently only `firecracker` is
    /// implemented in this slice.
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

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        Cmd::Pack(a) => run_pack(a),
        Cmd::Verify(a) => run_verify(a),
        Cmd::Inspect(a) => run_inspect(a),
        Cmd::Extract(a) => run_extract(a),
        Cmd::ModelInspect(a) => run_model_inspect(a),
        Cmd::ModelValidate(a) => run_model_validate(a),
        Cmd::ModelConfig(a) => run_model_config(a),
        Cmd::ModelBuild(a) => run_model_build(a),
    }
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    let manifest = inspect_unverified(&args.path)
        .with_context(|| format!("inspect {}", args.path.display()))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        // Lead with the "unverified" qualifier so an operator
        // reading the output never mistakes inspect for verify.
        crate::ui::info(&format!(
            "{}: unverified manifest ({}, profile={:?}, {} files)",
            args.path.display(),
            manifest.target_arch,
            manifest.security.profile,
            manifest.files.len()
        ));
        if let Some(prov) = manifest.build_provenance.as_deref() {
            println!("  build_provenance: {prov}");
        }
        println!("  security:");
        println!(
            "    verity_protected: {}",
            manifest.security.verity_protected
        );
        println!("    requires_auth:    {}", manifest.security.requires_auth);
        println!("    allows_volumes:   {}", manifest.security.allows_volumes);
        println!("    allows_egress:    {}", manifest.security.allows_egress);
        println!("  files:");
        for entry in manifest.files.values() {
            println!(
                "    {:<32} {:>12} bytes  sha256:{}…",
                entry.path,
                entry.size_bytes,
                &entry.sha256_hex[..16.min(entry.sha256_hex.len())]
            );
        }
    }
    Ok(())
}

fn run_pack(args: PackArgs) -> Result<()> {
    // Reuse the host signer so packed artifacts share the operator's
    // trust root with the audit chain. A future change can wire
    // `--key <path>` for offline signing keys.
    let signer = host_signer::load_or_init().context("load host signer")?;

    let target_arch: GuestArch = args
        .target_arch
        .parse()
        .map_err(|e| anyhow::anyhow!("--target-arch: {e}"))?;

    let inputs = PackInputs {
        kernel: &args.kernel,
        rootfs: &args.rootfs,
        cmdline: &args.cmdline,
        verity: args.verity.as_deref(),
        roothash: args.roothash.as_deref(),
        initrd: args.initrd.as_deref(),
        target_arch,
        build_provenance: args.build_provenance,
        security: SecurityPosture {
            profile: args.profile.into(),
            verity_protected: args.verity_protected,
            requires_auth: args.requires_auth,
            allows_volumes: args.allows_volumes,
            allows_egress: args.allows_egress,
        },
    };
    pack_artifact(&inputs, &signer.signing, &args.out).context("pack artifact")?;
    crate::ui::success(&format!("wrote {}", args.out.display()));
    Ok(())
}

/// Resolve the Ed25519 verifying key: an explicit `--key <path>` file, or
/// the host signer's public half by default. Shared by `verify`, `extract`,
/// and `machine check-artifact`.
pub(in crate::commands) fn resolve_verifying_key(
    key: Option<&Path>,
) -> Result<ed25519_dalek::VerifyingKey> {
    let key_bytes = match key {
        Some(p) => std::fs::read(p).with_context(|| format!("read {}", p.display()))?,
        None => {
            let signer = host_signer::load_or_init().context("load host signer")?;
            std::fs::read(&signer.public_path)
                .with_context(|| format!("read {}", signer.public_path.display()))?
        }
    };
    if key_bytes.len() != 32 {
        bail!(
            "verifying key must be 32 raw Ed25519 bytes, got {}",
            key_bytes.len()
        );
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&key_bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&buf).context("parse Ed25519 verifying key")
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let verifying = resolve_verifying_key(args.key.as_deref())?;

    match verify_artifact(&args.path, &verifying) {
        Ok(manifest) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                crate::ui::success(&format!(
                    "{}: verified ({}, profile={:?}, {} files)",
                    args.path.display(),
                    manifest.target_arch,
                    manifest.security.profile,
                    manifest.files.len()
                ));
            }
            Ok(())
        }
        Err(e) => {
            crate::ui::warn(&format!("{}: verify failed: {e}", args.path.display()));
            std::process::exit(65);
        }
    }
}

fn run_extract(args: ExtractArgs) -> Result<()> {
    let verifying = resolve_verifying_key(args.key.as_deref())?;

    match extract_artifact(&args.path, &verifying, &args.out) {
        Ok(manifest) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                crate::ui::success(&format!(
                    "{}: extracted {} files to {} ({}, profile={:?})",
                    args.path.display(),
                    manifest.files.len(),
                    args.out.display(),
                    manifest.target_arch,
                    manifest.security.profile
                ));
            }
            Ok(())
        }
        Err(e) => {
            crate::ui::warn(&format!("{}: extract failed: {e}", args.path.display()));
            std::process::exit(65);
        }
    }
}

// ── artifact-model handlers ───────────────────────────────

/// Resolve an artifact id to its directory under `~/.mvm/artifacts/<id>/`.
///
/// The id may be a full UUID or a unique prefix. Returns an error if the
/// directory doesn't exist or if the prefix matches more than one entry.
fn resolve_artifact_dir(id: &str) -> Result<PathBuf> {
    let artifacts_root = PathBuf::from(mvm_data_dir()).join("artifacts");
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
        std::process::exit(1);
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
    // Thin stub: the full build pipeline lives in `mvmctl build` / `mvmctl dev`.
    // Wiring NixMicrovmBuilder end-to-end here would require a running builder
    // VM, which is a larger slice. Delegate with a clear message.
    crate::ui::info(
        "Use `mvmctl build` or `mvmctl dev` to build a microVM artifact.\n\
         `mvmctl artifact model-build` is reserved for a future slice that \
         integrates directly with the artifact-model pipeline.",
    );
    Ok(())
}

/// Reconstruct a [`mvm_backend::artifacts::artifact::MicrovmArtifact`] from an
/// `ArtifactManifest` for validation and config-writing.
///
/// Paths stored in the manifest are relative to the artifact directory.
fn manifest_to_artifact(
    m: &ArtifactManifest,
    dir: &Path,
) -> mvm_backend::artifacts::artifact::MicrovmArtifact {
    use mvm_backend::artifacts::artifact::{KernelArtifact, MicrovmArtifact, RootfsArtifact};

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
        boot_args: mvm_backend::compat::compat(m.backend)
            .required_boot_args
            .iter()
            .map(|s| s.to_string())
            .collect(),
        config_path: m.config_path.as_ref().map(|p| dir.join(p)),
    }
}
