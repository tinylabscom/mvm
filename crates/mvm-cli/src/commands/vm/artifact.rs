//! `mvmctl artifact pack` / `verify` — plan 76 Phase 6.
//!
//! Wraps `mvm_build::packed_artifact::{pack, verify}` with the
//! host-side wiring the library can't reach: signing-key loading
//! (`host_signer.rs` from Plan 64), CLI argument shape, JSON output.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_build::packed_artifact::{
    ArtifactProfile, PackInputs, SecurityPosture, inspect_unverified, pack as pack_artifact,
    verify as verify_artifact,
};
use mvm_core::arch::GuestArch;
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
    /// form today; reserved for ADR-051 attestation linkage.
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

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        Cmd::Pack(a) => run_pack(a),
        Cmd::Verify(a) => run_verify(a),
        Cmd::Inspect(a) => run_inspect(a),
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
    // Reuse Plan 64's host signer so packed artifacts share the
    // operator's trust root with the audit chain. A future PR can
    // wire `--key <path>` for offline signing keys.
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

fn run_verify(args: VerifyArgs) -> Result<()> {
    use ed25519_dalek::VerifyingKey;
    let key_bytes = match args.key {
        Some(p) => std::fs::read(&p).with_context(|| format!("read {}", p.display()))?,
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
    let verifying = VerifyingKey::from_bytes(&buf).context("parse Ed25519 verifying key")?;

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
