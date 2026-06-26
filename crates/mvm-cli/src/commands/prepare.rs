//! Attested pack preparation and dry-run resolution.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_core::packs::cache::{
    PackCache, PackPrepareInput, PackPrepareInputKind, PackPrepareReason, PackPrepareReport,
    PackPrepareRequest, PackPrepareState, PackTrustState,
};
use mvm_core::packs::{PackKind, Sha256Hex};
use mvm_core::plan::bundle::FsTrustStore;
use mvm_core::user_config::MvmConfig;
use mvm_oci::{ImageReference, LinuxPlatform, OciManifestFetcher};

use super::Cli;
use super::ops::cache::{
    LocalPackRevocations, PackArchiveSource, PackBackendArg, PackPolicyArgs, PackPolicyModeArg,
    build_pack_policy, load_pack_archive_bytes,
};
use super::shared::{human_bytes, resolve_flake_ref};

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
    /// Resolve mutable OCI tags to a Linux platform digest before pack
    /// eligibility.
    #[arg(long)]
    pub resolve_oci_digest: bool,
    /// Hash a local flake.lock before pack eligibility. Remote flake lock
    /// resolution is builder-VM work and is refused here until that path is
    /// wired through builderd.
    #[arg(long)]
    pub resolve_flake_lock: bool,
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
    /// Pack policy mode. Stricter modes require pinned channel signing keys
    /// and/or mirror identity metadata.
    #[arg(long = "policy-mode", value_enum, default_value = "online-default")]
    pub policy_mode: PackPolicyModeArg,
    /// Pin a signing key to an allowed channel, formatted as
    /// `CHANNEL=KEY_ID`. Repeat to allow overlapping keys.
    #[arg(long = "channel-signing-key", value_name = "CHANNEL=KEY_ID")]
    pub channel_signing_keys: Vec<String>,
    /// Require prepared packs to declare this mirror identity.
    #[arg(long = "mirror-identity", value_name = "MIRROR")]
    pub mirror_identity: Option<String>,
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
        policy_mode: args.policy_mode,
        channel_signing_keys: args.channel_signing_keys,
        mirror_identity: args.mirror_identity,
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
    build_prepare_request_with(args, &RegistryPrepareOciDigestResolver)
}

fn build_prepare_request_with(
    args: &Args,
    resolver: &dyn PrepareOciDigestResolver,
) -> Result<PackPrepareRequest> {
    let pack_hash = args
        .pack_hash
        .as_ref()
        .map(|hash| Sha256Hex::new(hash.clone()))
        .transpose()
        .context("invalid --pack-hash; expected lowercase SHA-256 hex")?;
    Ok(PackPrepareRequest {
        input: resolve_prepare_input(args, resolver)?,
        expected_kind: Some(args.pack_kind.into()),
        pack_hash,
        required_setup_cache_layers: Vec::new(),
    })
}

trait PrepareOciDigestResolver {
    fn resolve_linux_digest(&self, image_ref: &ImageReference) -> Result<String>;
}

struct RegistryPrepareOciDigestResolver;

impl PrepareOciDigestResolver for RegistryPrepareOciDigestResolver {
    fn resolve_linux_digest(&self, image_ref: &ImageReference) -> Result<String> {
        let auth = super::image::registry_auth_for(image_ref)?.into_auth();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building Tokio runtime for OCI digest resolution")?;
        let fetcher = OciManifestFetcher::with_auth(auth);
        let fetched = runtime
            .block_on(
                fetcher
                    .fetch_linux_platform_manifest(image_ref, &LinuxPlatform::for_current_arch()),
            )
            .context("resolving OCI image digest for pack eligibility")?;
        Ok(fetched.digest)
    }
}

fn resolve_prepare_input(
    args: &Args,
    resolver: &dyn PrepareOciDigestResolver,
) -> Result<PackPrepareInput> {
    let kind = args
        .input_kind
        .map(Into::into)
        .unwrap_or_else(|| infer_input_kind(&args.input));
    if args.resolve_flake_lock && kind != PackPrepareInputKind::Flake {
        bail!("--resolve-flake-lock only applies to flake inputs");
    }
    if kind != PackPrepareInputKind::OciImage {
        if args.resolve_oci_digest {
            bail!("--resolve-oci-digest only applies to OCI image inputs");
        }
        if kind == PackPrepareInputKind::Flake {
            return resolve_flake_prepare_input(args);
        }
        return Ok(PackPrepareInput {
            raw: args.input.clone(),
            kind,
            flake_lock_hash: None,
        });
    }

    if !args.resolve_oci_digest && !args.input.contains("@sha256:") {
        return Ok(PackPrepareInput {
            raw: args.input.clone(),
            kind,
            flake_lock_hash: None,
        });
    }

    let mut image_ref: ImageReference = args
        .input
        .parse()
        .with_context(|| format!("parsing OCI image reference {:?}", args.input))?;
    if image_ref.is_digest_pinned() {
        return Ok(PackPrepareInput {
            raw: image_ref.canonical(),
            kind,
            flake_lock_hash: None,
        });
    }

    let digest = resolver.resolve_linux_digest(&image_ref)?;
    image_ref.digest = Some(digest);
    Ok(PackPrepareInput {
        raw: image_ref.canonical(),
        kind,
        flake_lock_hash: None,
    })
}

fn resolve_flake_prepare_input(args: &Args) -> Result<PackPrepareInput> {
    let raw = resolve_flake_ref(&args.input)?;
    let flake_lock_hash = if args.resolve_flake_lock {
        Some(resolve_local_flake_lock_hash(&raw)?)
    } else {
        None
    };
    Ok(PackPrepareInput {
        raw,
        kind: PackPrepareInputKind::Flake,
        flake_lock_hash,
    })
}

fn resolve_local_flake_lock_hash(resolved_flake_ref: &str) -> Result<Sha256Hex> {
    let path_text = if let Some(path) = resolved_flake_ref.strip_prefix("path:") {
        path
    } else if resolved_flake_ref.contains(':') {
        bail!("remote flake lock resolution requires the builder VM resolver path");
    } else {
        resolved_flake_ref
    };
    let flake_path = Path::new(path_text);
    let flake_dir = if flake_path
        .file_name()
        .is_some_and(|name| name == "flake.nix")
    {
        flake_path
            .parent()
            .context("flake.nix path has no parent directory")?
            .to_path_buf()
    } else {
        flake_path.to_path_buf()
    };
    let lock_path = flake_dir.join("flake.lock");
    let bytes = fs::read(&lock_path)
        .with_context(|| format!("reading flake lock file {}", lock_path.display()))?;
    Ok(Sha256Hex::from_bytes(&bytes))
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
    if let Some(lock_hash) = &report.input.flake_lock_hash {
        println!("  flake lock: {}", lock_hash.as_str());
    }
    println!("  state: {}", state_name(report.state));
    if let Some(reason) = report.reason {
        println!("  reason: {}", reason_name(reason));
        println!("  next step: {}", reason_next_step(reason));
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

pub(in crate::commands) fn reason_name(reason: PackPrepareReason) -> &'static str {
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
        PackPrepareReason::StaleRevocationMetadata => "stale_revocation_metadata",
        PackPrepareReason::CacheMetadataInvalid => "cache_metadata_invalid",
        PackPrepareReason::InputMismatch => "input_mismatch",
        PackPrepareReason::SetupCacheMiss => "setup_cache_miss",
    }
}

pub(in crate::commands) fn reason_detail(reason: PackPrepareReason) -> &'static str {
    match reason {
        PackPrepareReason::MissingPack => {
            "no verified attested pack is available for the requested input"
        }
        PackPrepareReason::MutableInput => {
            "the input can change over time and is not eligible for instant launch"
        }
        PackPrepareReason::PrivateInput => {
            "the input is local or private and must be prepared through the builder VM"
        }
        PackPrepareReason::ExpiredSignature => {
            "the pack signature is outside its accepted validity window"
        }
        PackPrepareReason::ExpiredTrustMetadata => {
            "the pack trust metadata is expired and must be refreshed"
        }
        PackPrepareReason::RevokedSigner => {
            "the signer or pack hash is revoked by the active revocation metadata"
        }
        PackPrepareReason::UnsupportedBackend => {
            "the pack does not declare compatibility with the selected backend"
        }
        PackPrepareReason::IncompatibleHost => {
            "the host does not satisfy the pack architecture or capability requirements"
        }
        PackPrepareReason::LocalRebuildRequired => {
            "local policy or source shape requires builder-VM preparation before launch"
        }
        PackPrepareReason::PolicyRefusal => {
            "local artifact policy refused the pack for this launch"
        }
        PackPrepareReason::TrustUnavailable => {
            "trusted publisher metadata is unavailable for this pack"
        }
        PackPrepareReason::StaleRevocationMetadata => {
            "active revocation metadata is older than its declared freshness window"
        }
        PackPrepareReason::CacheMetadataInvalid => {
            "cached pack metadata is missing, malformed, or inconsistent"
        }
        PackPrepareReason::InputMismatch => {
            "a cached pack was found but does not match the requested input identity"
        }
        PackPrepareReason::SetupCacheMiss => {
            "the image/project pack is verified but required setup-cache layers are missing"
        }
    }
}

pub(in crate::commands) fn reason_next_step(reason: PackPrepareReason) -> &'static str {
    match reason {
        PackPrepareReason::MissingPack => {
            "run `mvmctl prepare` with a matching pack source, or allow builder-VM preparation"
        }
        PackPrepareReason::MutableInput => {
            "pin OCI inputs by digest or resolve them with `mvmctl prepare --resolve-oci-digest`"
        }
        PackPrepareReason::PrivateInput => {
            "run `mvmctl prepare` from a trusted local checkout or let the builder VM prepare it"
        }
        PackPrepareReason::ExpiredSignature | PackPrepareReason::ExpiredTrustMetadata => {
            "refresh the pack from the release channel or rebuild it locally"
        }
        PackPrepareReason::RevokedSigner => {
            "refuse the artifact and rebuild from source with a non-revoked signer policy"
        }
        PackPrepareReason::UnsupportedBackend => {
            "select a compatible backend or prepare a pack for this backend"
        }
        PackPrepareReason::IncompatibleHost => {
            "prepare the artifact on a compatible host or choose a matching pack"
        }
        PackPrepareReason::LocalRebuildRequired => {
            "let the builder VM rebuild and cache a local pack for this input"
        }
        PackPrepareReason::PolicyRefusal => {
            "adjust local policy only if the artifact source is trusted, otherwise rebuild locally"
        }
        PackPrepareReason::TrustUnavailable => {
            "configure trusted publisher metadata or use an offline-pinned policy"
        }
        PackPrepareReason::StaleRevocationMetadata => {
            "refresh revocation metadata before using this pack, or rebuild locally"
        }
        PackPrepareReason::CacheMetadataInvalid => {
            "remove the poisoned cache entry and reinstall the pack from a trusted source"
        }
        PackPrepareReason::InputMismatch => {
            "prepare or install a pack whose manifest matches the requested input identity"
        }
        PackPrepareReason::SetupCacheMiss => {
            "run builder-VM preparation to derive the missing setup-cache layers"
        }
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
    use std::cell::Cell;

    struct FakeResolver {
        digest: Option<String>,
        calls: Cell<u32>,
    }

    impl FakeResolver {
        fn resolving_to(digest: &str) -> Self {
            Self {
                digest: Some(digest.to_string()),
                calls: Cell::new(0),
            }
        }

        fn unavailable() -> Self {
            Self {
                digest: None,
                calls: Cell::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.calls.get()
        }
    }

    impl PrepareOciDigestResolver for FakeResolver {
        fn resolve_linux_digest(&self, _image_ref: &ImageReference) -> Result<String> {
            self.calls.set(self.calls.get() + 1);
            self.digest
                .clone()
                .ok_or_else(|| anyhow::anyhow!("resolver unavailable"))
        }
    }

    fn base_args() -> Args {
        Args {
            input: "ghcr.io/tinylabs/mvm@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            dry_run: true,
            input_kind: None,
            resolve_oci_digest: false,
            resolve_flake_lock: false,
            pack_kind: PreparePackKindArg::ImageProject,
            pack_source: None,
            pack_hash: None,
            policy_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            backend: PackBackendArg::Libkrun,
            channels: vec!["stable".to_string()],
            host_capabilities: Vec::new(),
            policy_mode: PackPolicyModeArg::OnlineDefault,
            channel_signing_keys: Vec::new(),
            mirror_identity: None,
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
    fn build_prepare_request_leaves_mutable_oci_unresolved_without_flag() {
        let mut args = base_args();
        args.input = "alpine:3.19".to_string();
        let resolver = FakeResolver::unavailable();

        let request = build_prepare_request_with(&args, &resolver).expect("request");

        assert_eq!(request.input.kind, PackPrepareInputKind::OciImage);
        assert_eq!(request.input.raw, "alpine:3.19");
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn build_prepare_request_resolves_mutable_oci_when_explicit() {
        let mut args = base_args();
        args.input = "alpine:3.19".to_string();
        args.resolve_oci_digest = true;
        let resolver = FakeResolver::resolving_to(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        let request = build_prepare_request_with(&args, &resolver).expect("request");

        assert_eq!(request.input.kind, PackPrepareInputKind::OciImage);
        assert_eq!(
            request.input.raw,
            "docker.io/library/alpine:3.19@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn build_prepare_request_canonicalizes_digest_pinned_oci_without_resolver() {
        let mut args = base_args();
        args.input =
            "alpine@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string();
        let resolver = FakeResolver::unavailable();

        let request = build_prepare_request_with(&args, &resolver).expect("request");

        assert_eq!(
            request.input.raw,
            "docker.io/library/alpine@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn build_prepare_request_rejects_oci_resolution_for_non_oci_input() {
        let mut args = base_args();
        args.input = "github:tinylabs/mvm".to_string();
        args.input_kind = Some(PrepareInputKindArg::Flake);
        args.resolve_oci_digest = true;
        let resolver = FakeResolver::unavailable();

        let err = build_prepare_request_with(&args, &resolver).expect_err("non-oci rejected");

        assert!(err.to_string().contains("only applies to OCI image inputs"));
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn build_prepare_request_surfaces_oci_resolver_failures() {
        let mut args = base_args();
        args.input = "alpine:3.19".to_string();
        args.resolve_oci_digest = true;
        let resolver = FakeResolver::unavailable();

        let err = build_prepare_request_with(&args, &resolver).expect_err("resolver failed");

        assert!(err.to_string().contains("resolver unavailable"));
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn build_prepare_request_resolves_local_flake_lock_hash() {
        let temp = tempfile::tempdir().expect("tempdir");
        let flake_dir = temp.path().join("flake");
        std::fs::create_dir(&flake_dir).expect("flake dir");
        let lock_bytes = br#"{"nodes":{"root":{}},"root":"root","version":7}"#;
        std::fs::write(flake_dir.join("flake.lock"), lock_bytes).expect("flake lock");
        let mut args = base_args();
        args.input = flake_dir.display().to_string();
        args.input_kind = Some(PrepareInputKindArg::Flake);
        args.resolve_flake_lock = true;
        let resolver = FakeResolver::unavailable();
        let expected_lock_hash = Sha256Hex::from_bytes(lock_bytes);

        let request = build_prepare_request_with(&args, &resolver).expect("request");

        assert_eq!(request.input.kind, PackPrepareInputKind::Flake);
        assert_eq!(
            request
                .input
                .flake_lock_hash
                .as_ref()
                .map(Sha256Hex::as_str),
            Some(expected_lock_hash.as_str())
        );
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn build_prepare_request_refuses_remote_flake_lock_resolution() {
        let mut args = base_args();
        args.input = "github:tinylabs/mvm".to_string();
        args.input_kind = Some(PrepareInputKindArg::Flake);
        args.resolve_flake_lock = true;
        let resolver = FakeResolver::unavailable();

        let err = build_prepare_request_with(&args, &resolver).expect_err("remote refused");

        assert!(err.to_string().contains("requires the builder VM"));
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn build_prepare_request_rejects_flake_lock_resolution_for_non_flake_input() {
        let mut args = base_args();
        args.input = "alpine:3.19".to_string();
        args.resolve_flake_lock = true;
        let resolver = FakeResolver::unavailable();

        let err = build_prepare_request_with(&args, &resolver).expect_err("non-flake rejected");

        assert!(err.to_string().contains("only applies to flake inputs"));
        assert_eq!(resolver.calls(), 0);
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

    #[test]
    fn prepare_reason_help_covers_all_reasons() {
        let reasons = [
            PackPrepareReason::MissingPack,
            PackPrepareReason::MutableInput,
            PackPrepareReason::PrivateInput,
            PackPrepareReason::ExpiredSignature,
            PackPrepareReason::ExpiredTrustMetadata,
            PackPrepareReason::RevokedSigner,
            PackPrepareReason::UnsupportedBackend,
            PackPrepareReason::IncompatibleHost,
            PackPrepareReason::LocalRebuildRequired,
            PackPrepareReason::PolicyRefusal,
            PackPrepareReason::TrustUnavailable,
            PackPrepareReason::StaleRevocationMetadata,
            PackPrepareReason::CacheMetadataInvalid,
            PackPrepareReason::InputMismatch,
            PackPrepareReason::SetupCacheMiss,
        ];
        for reason in reasons {
            assert!(!reason_name(reason).is_empty());
            assert!(!reason_detail(reason).is_empty());
            assert!(!reason_next_step(reason).is_empty());
        }
    }

    #[test]
    fn prepare_reason_help_uses_stable_external_names() {
        assert_eq!(reason_name(PackPrepareReason::MissingPack), "missing_pack");
        assert_eq!(
            reason_name(PackPrepareReason::MutableInput),
            "mutable_input"
        );
        assert_eq!(
            reason_name(PackPrepareReason::PrivateInput),
            "private_input"
        );
        assert_eq!(
            reason_name(PackPrepareReason::LocalRebuildRequired),
            "local_rebuild_required"
        );
        assert_eq!(
            reason_name(PackPrepareReason::SetupCacheMiss),
            "setup_cache_miss"
        );
    }
}
