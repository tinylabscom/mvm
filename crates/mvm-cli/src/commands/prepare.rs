//! Attested pack preparation and dry-run resolution.

use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_core::packs::cache::{
    PackCache, PackPrepareInput, PackPrepareInputKind, PackPrepareReason, PackPrepareReport,
    PackPrepareRequest, PackPrepareState, PackTrustState,
};
use mvm_core::packs::{PackKind, Sha256Hex};
use mvm_core::plan::bundle::FsTrustStore;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::ops::cache::{
    LocalPackRevocations, PackArchiveSource, PackBackendArg, PackPolicyArgs, build_pack_policy,
    load_pack_archive_bytes,
};
use super::shared::human_bytes;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// OCI image reference, flake reference, or local project path to prepare.
    #[arg(value_name = "IMAGE_OR_FLAKE")]
    pub input: String,
    /// Resolve and report without downloading, installing, or deriving local
    /// snapshots.
    #[arg(long)]
    pub dry_run: bool,
    /// Input kind. Defaults to a conservative inference from the input string.
    #[arg(long = "input-kind", value_enum)]
    pub input_kind: Option<PrepareInputKindArg>,
    /// Expected attested pack kind.
    #[arg(long = "pack-kind", value_enum, default_value = "image-project")]
    pub pack_kind: PreparePackKindArg,
    /// Install this local or HTTPS pack archive before resolving the input.
    #[arg(long = "pack-source", value_name = "SOURCE")]
    pub pack_source: Option<String>,
    /// Require a specific pack hash while resolving.
    #[arg(long = "pack-hash", value_name = "SHA256")]
    pub pack_hash: Option<String>,
    /// Expected local policy hash. The pack manifest must declare the same hash.
    #[arg(long, value_name = "SHA256")]
    pub policy_hash: String,
    /// Backend this host intends to use for the pack.
    #[arg(long, value_enum)]
    pub backend: PackBackendArg,
    /// Allowed artifact channel identity. Repeat to allow multiple channels.
    #[arg(long = "channel", value_name = "CHANNEL", required = true)]
    pub channels: Vec<String>,
    /// Host capability made available to this pack policy. Repeat for multiple
    /// capabilities.
    #[arg(long = "host-capability", value_name = "CAPABILITY")]
    pub host_capabilities: Vec<String>,
    /// Override the trusted publisher key directory.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Optional local revocation JSON file for offline refused pack hashes.
    #[arg(long, value_name = "FILE")]
    pub revocations: Option<PathBuf>,
    /// Allow plain-HTTP pack downloads. HTTPS or local files are preferred.
    #[arg(long)]
    pub allow_http: bool,
    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum PrepareInputKindArg {
    OciImage,
    Flake,
    LocalPath,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum PreparePackKindArg {
    Runtime,
    Builder,
    ImageProject,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let request = build_prepare_request(&args)?;
    let policy = build_pack_policy(PackPolicyArgs {
        backend: args.backend,
        policy_hash: args.policy_hash,
        channels: args.channels,
        host_capabilities: args.host_capabilities,
    })?;
    let trust = match args.trust_store {
        Some(path) => FsTrustStore::new(path),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?,
    };
    let revocations = match args.revocations {
        Some(path) => LocalPackRevocations::from_path(&path)?,
        None => LocalPackRevocations::empty(),
    };
    let cache = PackCache::default();
    if let Some(source) = args.pack_source.as_deref()
        && !args.dry_run
    {
        let source = PackArchiveSource::parse(source);
        let archive_bytes = load_pack_archive_bytes(&source, args.allow_http)?;
        let cached = cache
            .install_from_archive_reader(Cursor::new(archive_bytes), &policy, &trust, &revocations)
            .context("installing attested pack archive before prepare resolution")?;
        mvm_core::audit_emit!(
            CachePackInstall,
            "pack_hash={} kind={} channel={} source_kind=prepare cache_root={}",
            cached.verified.pack_hash.as_str(),
            pack_kind_name(&cached.manifest.kind),
            cached.manifest.trust.channel_identity,
            cached.root.display()
        );
    }

    let mut report = cache
        .prepare_report(&request, &policy, &trust, &revocations)
        .context("resolving attested pack preparation state")?;
    if args.pack_source.is_some() && args.dry_run && report.state == PackPrepareState::Missing {
        report.download_required = true;
        report.detail = Some("pack source would be downloaded and verified".to_string());
    }

    if args.json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    print_report(&report);
    Ok(())
}

fn build_prepare_request(args: &Args) -> Result<PackPrepareRequest> {
    let pack_hash = args
        .pack_hash
        .as_ref()
        .map(|hash| Sha256Hex::new(hash.clone()))
        .transpose()
        .context("invalid --pack-hash; expected lowercase SHA-256 hex")?;
    Ok(PackPrepareRequest {
        input: PackPrepareInput {
            raw: args.input.clone(),
            kind: args
                .input_kind
                .map(Into::into)
                .unwrap_or_else(|| infer_input_kind(&args.input)),
        },
        expected_kind: Some(args.pack_kind.into()),
        pack_hash,
    })
}

fn infer_input_kind(input: &str) -> PackPrepareInputKind {
    if input.starts_with("flake:")
        || input.starts_with("github:")
        || input.starts_with("git+")
        || input.contains("#")
    {
        PackPrepareInputKind::Flake
    } else if input.starts_with('.')
        || input.starts_with('/')
        || input.ends_with(".nix")
        || input.ends_with("flake.nix")
    {
        PackPrepareInputKind::LocalPath
    } else {
        PackPrepareInputKind::OciImage
    }
}

fn print_report(report: &PackPrepareReport) {
    println!("Prepare input: {}", report.input.raw);
    println!("  state: {}", state_name(report.state));
    if let Some(reason) = report.reason {
        println!("  reason: {}", reason_name(reason));
    }
    if let Some(pack_hash) = &report.pack_hash {
        println!("  pack: {}", pack_hash.as_str());
    }
    if let Some(kind) = &report.kind {
        println!("  kind: {}", pack_kind_name(kind));
    }
    if let Some(size_bytes) = report.size_bytes {
        println!("  size: {}", human_bytes(size_bytes));
    }
    println!("  trust: {}", trust_state_name(report.trust_state));
    println!("  fast path eligible: {}", report.fast_path_eligible);
    println!("  builder VM required: {}", report.builder_vm_required);
    println!("  download required: {}", report.download_required);
    if let Some(detail) = &report.detail {
        println!("  detail: {detail}");
    }
}

fn state_name(state: PackPrepareState) -> &'static str {
    match state {
        PackPrepareState::Ready => "ready",
        PackPrepareState::Missing => "missing",
        PackPrepareState::RequiresBuilder => "requires_builder",
        PackPrepareState::Refused => "refused",
    }
}

fn reason_name(reason: PackPrepareReason) -> &'static str {
    match reason {
        PackPrepareReason::MissingPack => "missing_pack",
        PackPrepareReason::MutableInput => "mutable_input",
        PackPrepareReason::PrivateInput => "private_input",
        PackPrepareReason::ExpiredSignature => "expired_signature",
        PackPrepareReason::ExpiredTrustMetadata => "expired_trust_metadata",
        PackPrepareReason::RevokedSigner => "revoked_signer",
        PackPrepareReason::UnsupportedBackend => "unsupported_backend",
        PackPrepareReason::IncompatibleHost => "incompatible_host",
        PackPrepareReason::LocalRebuildRequired => "local_rebuild_required",
        PackPrepareReason::PolicyRefusal => "policy_refusal",
        PackPrepareReason::TrustUnavailable => "trust_unavailable",
        PackPrepareReason::CacheMetadataInvalid => "cache_metadata_invalid",
        PackPrepareReason::InputMismatch => "input_mismatch",
    }
}

fn trust_state_name(state: PackTrustState) -> &'static str {
    match state {
        PackTrustState::Verified => "verified",
        PackTrustState::NotChecked => "not_checked",
        PackTrustState::Untrusted => "untrusted",
        PackTrustState::Expired => "expired",
        PackTrustState::Revoked => "revoked",
    }
}

fn pack_kind_name(kind: &PackKind) -> &'static str {
    match kind {
        PackKind::Runtime => "runtime",
        PackKind::Builder => "builder",
        PackKind::ImageProject => "image_project",
    }
}

impl From<PrepareInputKindArg> for PackPrepareInputKind {
    fn from(value: PrepareInputKindArg) -> Self {
        match value {
            PrepareInputKindArg::OciImage => PackPrepareInputKind::OciImage,
            PrepareInputKindArg::Flake => PackPrepareInputKind::Flake,
            PrepareInputKindArg::LocalPath => PackPrepareInputKind::LocalPath,
        }
    }
}

impl From<PreparePackKindArg> for PackKind {
    fn from(value: PreparePackKindArg) -> Self {
        match value {
            PreparePackKindArg::Runtime => PackKind::Runtime,
            PreparePackKindArg::Builder => PackKind::Builder,
            PreparePackKindArg::ImageProject => PackKind::ImageProject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Args {
        Args {
            input: "ghcr.io/tinylabs/mvm@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            dry_run: true,
            input_kind: None,
            pack_kind: PreparePackKindArg::ImageProject,
            pack_source: None,
            pack_hash: None,
            policy_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            backend: PackBackendArg::Libkrun,
            channels: vec!["stable".to_string()],
            host_capabilities: Vec::new(),
            trust_store: None,
            revocations: None,
            allow_http: false,
            json: false,
        }
    }

    #[test]
    fn build_prepare_request_defaults_to_oci_and_image_project() {
        let args = base_args();
        let request = build_prepare_request(&args).expect("request");
        assert_eq!(request.input.kind, PackPrepareInputKind::OciImage);
        assert_eq!(request.expected_kind, Some(PackKind::ImageProject));
        assert!(request.pack_hash.is_none());
    }

    #[test]
    fn build_prepare_request_accepts_pack_hash_and_explicit_kind() {
        let mut args = base_args();
        args.input = "github:tinylabs/mvm".to_string();
        args.input_kind = Some(PrepareInputKindArg::Flake);
        args.pack_kind = PreparePackKindArg::Runtime;
        args.pack_hash =
            Some("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string());
        let request = build_prepare_request(&args).expect("request");

        assert_eq!(request.input.kind, PackPrepareInputKind::Flake);
        assert_eq!(request.expected_kind, Some(PackKind::Runtime));
        assert_eq!(
            request.pack_hash.expect("pack hash").as_str(),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );
    }

    #[test]
    fn build_prepare_request_rejects_bad_pack_hash() {
        let mut args = base_args();
        args.pack_hash = Some("not-a-sha".to_string());
        let err = build_prepare_request(&args).expect_err("bad hash rejected");
        assert!(err.to_string().contains("invalid --pack-hash"));
    }

    #[test]
    fn infer_input_kind_distinguishes_common_inputs() {
        assert_eq!(
            infer_input_kind("github:tinylabs/mvm"),
            PackPrepareInputKind::Flake
        );
        assert_eq!(
            infer_input_kind("./flake.nix"),
            PackPrepareInputKind::LocalPath
        );
        assert_eq!(
            infer_input_kind(
                "ghcr.io/tinylabs/mvm@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            PackPrepareInputKind::OciImage
        );
    }
}
