//! `mvmctl image` - pull, inspect, and prune the local OCI image cache.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufReader, Cursor, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use flate2::read::GzDecoder;
use mvm_build::rootfs::{MaterializeExt4Input, MaterializeExt4Options, materialize_ext4};
use mvm_oci::{
    ImageReference, LayerDescriptor, LayerFetchOptions, LinuxPlatform, OciLayerFetcher,
    OciManifestFetcher, RegistryAuthConfig, UnpackOptions, read_oci_archive, unpack_layer,
    verify_sha256_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use mvm_core::domain::manifest::canonical_key_for_path;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::human_bytes;

mod inspect;
mod ls;
mod pull;
mod rm;
mod source;

const INDEX_FILE: &str = "index.json";

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: ImageAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ImageAction {
    /// Pull, unpack, and materialize an OCI image into the local cache
    Pull {
        /// OCI image reference
        reference: String,
        /// Production policy: require an immutable digest-pinned reference
        #[arg(long)]
        prod: bool,
    },
    /// List cached OCI images
    Ls {
        /// Filter cached images by registry host
        #[arg(long, value_name = "HOST")]
        registry: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Inspect a cached OCI image by reference or resolved digest
    Inspect {
        /// Image reference or resolved digest
        reference: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove a cached OCI image and garbage-collect unreferenced layers
    Rm {
        /// Image reference or resolved digest
        reference: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OciCacheIndex {
    #[serde(default = "schema_version")]
    schema_version: u32,
    #[serde(default)]
    images: Vec<CachedOciImage>,
}

impl Default for OciCacheIndex {
    fn default() -> Self {
        // Hand-written, NOT derived: a derived `Default` sets `schema_version`
        // to 0 (the u32 default), which `save_index` then persists and the next
        // `load_index` rejects as unsupported. The `#[serde(default)]` only
        // fills a *missing* field on deserialize — it does not feed `Default`.
        Self {
            schema_version: schema_version(),
            images: Vec::new(),
        }
    }
}

fn schema_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::commands) struct CachedOciImage {
    reference: String,
    registry: String,
    repository: String,
    tag: Option<String>,
    resolved_digest: String,
    fetched_at: String,
    manifest_path: String,
    #[serde(default)]
    config_path: Option<String>,
    #[serde(default)]
    rootfs_path: Option<String>,
    #[serde(default)]
    claims_path: Option<String>,
    #[serde(default)]
    layers: Vec<CachedOciLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct ResolvedOciRunImage {
    pub reference: String,
    pub resolved_digest: String,
    pub rootfs_path: PathBuf,
    pub pulled: bool,
    pub provenance: OciProvenance,
    pub auth_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::commands) struct OciProvenance {
    pub schema_version: u32,
    pub source: String,
    pub supplied_reference: String,
    pub canonical_reference: String,
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub resolved_digest: String,
    pub layer_digests: Vec<String>,
    pub trust_policy: String,
    pub verification_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CachedOciLayer {
    digest: String,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default)]
    path: Option<String>,
}

impl CachedOciImage {
    pub(super) fn provenance(
        &self,
        source: &str,
        supplied_reference: &str,
        trust: &OciTrustDecision,
    ) -> OciProvenance {
        OciProvenance {
            schema_version: 1,
            source: source.to_string(),
            supplied_reference: supplied_reference.to_string(),
            canonical_reference: self.reference.clone(),
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            tag: self.tag.clone(),
            resolved_digest: self.resolved_digest.clone(),
            layer_digests: self
                .layers
                .iter()
                .map(|layer| layer.digest.clone())
                .collect(),
            trust_policy: trust.trust_policy.clone(),
            verification_status: trust.verification_status.clone(),
        }
    }
}

impl OciProvenance {
    pub(in crate::commands) fn audit_labels(&self) -> Vec<(String, String)> {
        vec![
            ("oci_source".to_string(), self.source.clone()),
            (
                "oci_supplied_reference".to_string(),
                self.supplied_reference.clone(),
            ),
            (
                "oci_canonical_reference".to_string(),
                self.canonical_reference.clone(),
            ),
            ("oci_registry".to_string(), self.registry.clone()),
            ("oci_repository".to_string(), self.repository.clone()),
            (
                "oci_resolved_digest".to_string(),
                self.resolved_digest.clone(),
            ),
            (
                "oci_layer_digests".to_string(),
                self.layer_digests.join(","),
            ),
            ("oci_trust_policy".to_string(), self.trust_policy.clone()),
            (
                "oci_verification_status".to_string(),
                self.verification_status.clone(),
            ),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OciTrustDecision {
    trust_policy: String,
    verification_status: String,
}

impl OciTrustDecision {
    fn dev_digest_only(image_ref: &ImageReference) -> Self {
        let trust_policy = if image_ref.is_digest_pinned() {
            "digest-pinned"
        } else {
            "mutable-reference-resolved-to-digest"
        };
        Self {
            trust_policy: trust_policy.to_string(),
            verification_status: "digest-verified-signature-not-required".to_string(),
        }
    }

    fn cosign_verified(identity: &CosignIdentity) -> Self {
        Self {
            trust_policy: "prod-cosign-required".to_string(),
            verification_status: format!(
                "cosign-verified identity={} issuer={}",
                identity.certificate_identity, identity.certificate_oidc_issuer
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OciRegistryPolicy {
    #[serde(default)]
    allowed_registries: Vec<String>,
    #[serde(default = "default_require_signatures")]
    require_signatures: bool,
    #[serde(default)]
    cosign: Vec<CosignIdentity>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CosignIdentity {
    certificate_identity: String,
    certificate_oidc_issuer: String,
}

fn default_require_signatures() -> bool {
    true
}

trait CosignVerifier {
    fn verify(&self, reference: &str, identity: &CosignIdentity) -> Result<(), CosignVerifyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CosignVerifyError {
    MissingSignature(String),
    InvalidSignature(String),
    ToolUnavailable(String),
}

impl std::fmt::Display for CosignVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature(msg) => write!(f, "missing signature: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {msg}"),
            Self::ToolUnavailable(msg) => write!(f, "cosign unavailable: {msg}"),
        }
    }
}

struct CosignCommandVerifier;

impl CosignVerifier for CosignCommandVerifier {
    fn verify(&self, reference: &str, identity: &CosignIdentity) -> Result<(), CosignVerifyError> {
        let cosign = which::which("cosign").map_err(|e| {
            CosignVerifyError::ToolUnavailable(format!(
                "cosign is required for production OCI policy; install cosign or run without --prod ({e})"
            ))
        })?;
        let output = std::process::Command::new(cosign)
            .args([
                "verify",
                "--certificate-identity",
                &identity.certificate_identity,
                "--certificate-oidc-issuer",
                &identity.certificate_oidc_issuer,
                reference,
            ])
            .output()
            .map_err(|e| CosignVerifyError::ToolUnavailable(e.to_string()))?;
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if detail.is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            detail
        };
        let detail = if detail.is_empty() {
            format!("cosign exited with status {}", output.status)
        } else {
            detail
        };
        if detail
            .to_ascii_lowercase()
            .contains("no matching signatures")
            || detail.to_ascii_lowercase().contains("no signatures")
        {
            Err(CosignVerifyError::MissingSignature(detail))
        } else {
            Err(CosignVerifyError::InvalidSignature(detail))
        }
    }
}

#[derive(Debug, Clone)]
struct OciRegistryAuthDecision {
    auth: RegistryAuthConfig,
    source: String,
}

fn registry_auth_for(image_ref: &ImageReference) -> Result<OciRegistryAuthDecision> {
    registry_auth_from_lookup(image_ref, |name| std::env::var(name).ok())
}

fn registry_auth_from_lookup(
    image_ref: &ImageReference,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<OciRegistryAuthDecision> {
    let registry_key = registry_env_key(&image_ref.registry)?;
    let registry_var = format!("MVM_OCI_BEARER_TOKEN_{registry_key}");
    if let Some(token) = nonempty_lookup(&registry_var, &mut lookup) {
        return Ok(OciRegistryAuthDecision {
            auth: RegistryAuthConfig::bearer(token),
            source: format!("env:{registry_var}"),
        });
    }
    if let Some(token) = nonempty_lookup("MVM_OCI_BEARER_TOKEN", &mut lookup) {
        return Ok(OciRegistryAuthDecision {
            auth: RegistryAuthConfig::bearer(token),
            source: "env:MVM_OCI_BEARER_TOKEN".to_string(),
        });
    }
    Ok(OciRegistryAuthDecision {
        auth: RegistryAuthConfig::Anonymous,
        source: "anonymous".to_string(),
    })
}

fn nonempty_lookup(name: &str, lookup: &mut impl FnMut(&str) -> Option<String>) -> Option<String> {
    lookup(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn registry_env_key(registry: &str) -> Result<String> {
    let mut key = String::with_capacity(registry.len());
    for ch in registry.chars() {
        if ch.is_ascii_alphanumeric() {
            key.push(ch.to_ascii_uppercase());
        } else if matches!(ch, '.' | '-' | ':') {
            key.push('_');
        } else {
            bail!("OCI registry host contains unsupported env-var character: {registry:?}");
        }
    }
    Ok(key)
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct ImageListRow {
    reference: String,
    registry: String,
    repository: String,
    tag: Option<String>,
    resolved_digest: String,
    fetched_at: String,
    size_bytes: u64,
    layers: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct InspectOutput {
    image: CachedOciImage,
    size_bytes: u64,
    manifest: Option<Value>,
    config: Option<Value>,
    claims: Option<Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RemoveOutcome {
    pub(super) reference: String,
    pub(super) removed_files: usize,
    pub(super) freed_bytes: u64,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let cache_root = oci_cache_root();
    match args.action {
        ImageAction::Pull { reference, prod } => pull::run(&cache_root, reference, prod),
        ImageAction::Ls { registry, json } => ls::run(&cache_root, registry.as_deref(), json),
        ImageAction::Inspect { reference, json } => inspect::run(&cache_root, &reference, json),
        ImageAction::Rm { reference } => rm::run(&cache_root, &reference),
    }
}

pub(in crate::commands) fn oci_cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join("oci")
}

pub(in crate::commands) fn resolve_or_pull_run_image(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    // Local sources route to their own ingest; a registry reference falls
    // through to the cache-or-pull path below.
    match source::ImageSource::classify(reference)? {
        source::ImageSource::OciArchive(path) => {
            return ingest_local_archive(cache_root, &path, reference, prod);
        }
        source::ImageSource::Stdin => {
            return ingest_stdin_archive(cache_root, reference, prod);
        }
        source::ImageSource::RootfsDir(path) => {
            return ingest_rootfs_dir(cache_root, &path, reference, prod);
        }
        source::ImageSource::Registry(_) => {}
    }
    let image_ref: ImageReference = reference.parse()?;
    if prod && !image_ref.is_digest_pinned() {
        bail!("mvmctl run --image --prod requires a digest-pinned reference");
    }
    let canonical = image_ref.canonical();
    let (image, pulled, trust_from_pull, auth_source_from_pull) = match load_index(cache_root)
        .ok()
        .and_then(|index| find_image(&index, &canonical).cloned())
    {
        Some(cached) if cached.rootfs_path.is_some() => (cached, false, None, None),
        _ => {
            let (cached, trust, auth_source) =
                pull_image_ref(cache_root, image_ref.clone(), reference, prod)?;
            (cached, true, Some(trust), Some(auth_source))
        }
    };
    let Some(rootfs_relative) = image.rootfs_path.as_deref() else {
        bail!(
            "cached OCI image {} has no materialized rootfs; run `mvmctl image pull {}` first",
            image.reference,
            image.reference
        );
    };
    let rootfs_path = safe_cache_path(cache_root, rootfs_relative)?;
    if !rootfs_path.is_file() {
        bail!(
            "cached OCI image {} rootfs is missing at {}",
            image.reference,
            rootfs_path.display()
        );
    }
    let trust = match trust_from_pull {
        Some(trust) => trust,
        None => trust_decision_for_cached_image(&image_ref, &image, prod, &CosignCommandVerifier)?,
    };
    Ok(ResolvedOciRunImage {
        provenance: image.provenance("run_image", reference, &trust),
        reference: image.reference,
        resolved_digest: image.resolved_digest,
        rootfs_path,
        pulled,
        auth_source: auth_source_from_pull,
    })
}

/// Inject the mvm guest runtime into `unpacked_root`, seal it into
/// `rootfs_abs` as ext4, and drop the overlay-aware sidecar beside it.
///
/// Every OCI run source funnels through here. An arbitrary OCI image has
/// no mvm agent, so without the injection `run --image` boots a guest
/// with no vsock control plane and times out at `wait_for_agent`. The
/// injected `/init` + baked agent + `/mvm/runtime` mount point make the
/// rootfs genuinely overlay-aware, so the `for_oci_run` sidecar admits
/// honestly through `admit_overlay_aware` without weakening the gate.
fn inject_runtime_and_materialize(
    cache_root: &Path,
    unpacked_root: &Path,
    rootfs_abs: &Path,
    image_label: &str,
) -> Result<()> {
    let arch = mvm_core::arch::GuestArch::host();
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot locate workspace root for guest-agent build"))?;
    let bins = mvm_build::guest_agent_build::resolve_or_build_guest_binaries(
        cache_root,
        env!("CARGO_PKG_VERSION"),
        arch,
        workspace_root,
    )
    .context("obtain guest agent binaries for OCI run")?;
    mvm_build::oci_runtime_inject::inject_mvm_runtime(unpacked_root, &bins)
        .context("inject mvm runtime into OCI rootfs")?;

    // Measure AFTER injection so the ext4 sizing covers the baked
    // agent/netinit (~1.6 MiB).
    let tree_size = unpacked_tree_size(unpacked_root)
        .with_context(|| format!("measure unpacked root {}", unpacked_root.display()))?;
    materialize_ext4(
        &MaterializeExt4Input::new(
            unpacked_root.to_path_buf(),
            rootfs_abs.to_path_buf(),
            tree_size,
        ),
        &MaterializeExt4Options::default(),
    )
    .context("materialize OCI rootfs.ext4")?;

    // The sidecar lives next to rootfs.ext4 so the backend's
    // admit_overlay_aware gate reads it at start.
    let rootfs_dir = rootfs_abs.parent().ok_or_else(|| {
        anyhow::anyhow!("rootfs path has no parent dir: {}", rootfs_abs.display())
    })?;
    mvm_build::builder_vm::GuestSidecar::for_oci_run(image_label)
        .write_to_dir(rootfs_dir)
        .with_context(|| format!("write OCI sidecar in {}", rootfs_dir.display()))?;
    Ok(())
}

/// Ingest a local OCI image-layout archive (`oci-archive:<path>`) into a
/// bootable rootfs. Mirrors the registry pull's unpack → ext4 path with no
/// network: `read_oci_archive` digest-verifies every blob, then the same
/// hardened `unpack_layer` extracts each layer. Dev-only for now — `--prod`
/// still requires a registry reference + cosign (a local archive carries no
/// registry policy or signature to check yet). Re-ingests each run rather than
/// caching by reference (the archive has no stable registry identity).
fn ingest_local_archive(
    cache_root: &Path,
    archive_path: &Path,
    supplied_reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    if prod {
        bail!(
            "`run --image --prod` requires a registry reference with cosign; \
             local OCI archives are dev-only for now"
        );
    }
    let file = fs::File::open(archive_path)
        .with_context(|| format!("open OCI archive {}", archive_path.display()))?;
    ingest_archive_from_reader(
        cache_root,
        BufReader::new(file),
        supplied_reference,
        "local_archive",
        &format!("OCI archive {}", archive_path.display()),
    )
}

/// Ingest an OCI image-layout archive streamed on stdin (`run --image -`). Same
/// digest-verified path as a file archive, for CI/agent pipelines that pipe an
/// archive in. Dev-only (see [`ingest_local_archive`]).
fn ingest_stdin_archive(
    cache_root: &Path,
    supplied_reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    if prod {
        bail!(
            "`run --image --prod` requires a registry reference with cosign; \
             stdin OCI archives are dev-only for now"
        );
    }
    let stdin = std::io::stdin();
    ingest_archive_from_reader(
        cache_root,
        stdin.lock(),
        supplied_reference,
        "stdin_archive",
        "OCI archive on stdin",
    )
}

/// Shared archive-ingest core: digest-verify the archive from `reader`, unpack
/// every layer through the hardened `unpack_layer`, materialize the ext4
/// rootfs, and build a `ResolvedOciRunImage` with local-source provenance. The
/// file and stdin callers differ only in where the bytes come from and the
/// provenance `source` label.
fn ingest_archive_from_reader<R: Read>(
    cache_root: &Path,
    reader: R,
    supplied_reference: &str,
    source_label: &str,
    source_descr: &str,
) -> Result<ResolvedOciRunImage> {
    let image = read_oci_archive(reader, &LinuxPlatform::for_current_arch())
        .with_context(|| format!("read {source_descr}"))?;

    let manifest_hex = sha256_hex(&image.manifest_digest)?;
    let unpacked_root = cache_root.join("unpacked").join(&manifest_hex);
    if unpacked_root.exists() {
        fs::remove_dir_all(&unpacked_root)
            .with_context(|| format!("remove stale unpacked root {}", unpacked_root.display()))?;
    }
    fs::create_dir_all(&unpacked_root)
        .with_context(|| format!("create {}", unpacked_root.display()))?;
    for layer in &image.layers {
        unpack_layer_bytes(&layer.descriptor, &layer.bytes, &unpacked_root)
            .with_context(|| format!("unpack layer {}", layer.descriptor.digest))?;
    }

    let rootfs_rel = format!("rootfs/{manifest_hex}/rootfs.ext4");
    let rootfs_abs = cache_root.join(&rootfs_rel);
    inject_runtime_and_materialize(
        cache_root,
        &unpacked_root,
        &rootfs_abs,
        &image.manifest_digest,
    )?;

    let provenance = OciProvenance {
        schema_version: 1,
        source: source_label.to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: image.manifest_digest.clone(),
        registry: String::new(),
        repository: String::new(),
        tag: None,
        resolved_digest: image.manifest_digest.clone(),
        layer_digests: image
            .layers
            .iter()
            .map(|l| l.descriptor.digest.clone())
            .collect(),
        trust_policy: "local-archive-digest-verified".to_string(),
        verification_status: "content-digest-verified (dev)".to_string(),
    };
    Ok(ResolvedOciRunImage {
        reference: image.manifest_digest.clone(),
        resolved_digest: image.manifest_digest,
        rootfs_path: rootfs_abs,
        pulled: true,
        provenance,
        auth_source: None,
    })
}

/// Ingest an already-unpacked rootfs directory (`run --image rootfs-dir:<path>`)
/// straight into an ext4 rootfs — no layers to unpack. A bare tree carries no
/// OCI manifest/config, so there is no digest or signature to verify; it is
/// therefore **dev-only** (`--prod` is refused) and the wrong-architecture
/// guard falls back to probing a representative ELF binary's machine type
/// against the host. `materialize_ext4` reads the directory read-only.
fn ingest_rootfs_dir(
    cache_root: &Path,
    rootfs_dir: &Path,
    supplied_reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    if prod {
        bail!(
            "`run --image --prod` requires a registry reference with cosign; an \
             unpacked rootfs directory carries no provenance to verify"
        );
    }
    if !rootfs_dir.is_dir() {
        bail!(
            "rootfs directory not found or not a directory: {}",
            rootfs_dir.display()
        );
    }
    // A bare tree has no manifest architecture, so probe a representative ELF
    // binary and reject a cross-arch tree before paying for materialization.
    if let (Some(found), Some(host)) = (probe_rootfs_elf_machine(rootfs_dir), host_elf_machine())
        && found != host
    {
        bail!(
            "rootfs directory targets a different CPU architecture \
             (ELF e_machine {found}, host expects {host})"
        );
    }

    let key = canonical_key_for_path(rootfs_dir)
        .with_context(|| format!("canonicalize rootfs dir {}", rootfs_dir.display()))?;
    let tree_size = unpacked_tree_size(rootfs_dir)
        .with_context(|| format!("measure rootfs dir {}", rootfs_dir.display()))?;
    let rootfs_rel = format!("rootfs/{key}/rootfs.ext4");
    let rootfs_abs = cache_root.join(&rootfs_rel);
    materialize_ext4(
        &MaterializeExt4Input::new(rootfs_dir.to_path_buf(), rootfs_abs.clone(), tree_size),
        &MaterializeExt4Options::default(),
    )
    .context("materialize rootfs.ext4 from directory")?;

    let provenance = OciProvenance {
        schema_version: 1,
        source: "rootfs_dir".to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: rootfs_dir.display().to_string(),
        registry: String::new(),
        repository: String::new(),
        tag: None,
        resolved_digest: String::new(),
        layer_digests: Vec::new(),
        trust_policy: "rootfs-dir-unverified".to_string(),
        verification_status: "no-provenance (dev)".to_string(),
    };
    Ok(ResolvedOciRunImage {
        reference: supplied_reference.to_string(),
        resolved_digest: String::new(),
        rootfs_path: rootfs_abs,
        pulled: true,
        provenance,
        auth_source: None,
    })
}

/// ELF `e_machine` for the host CPU, or `None` for an architecture we don't
/// map (in which case the rootfs-dir arch guard is skipped rather than
/// guessing). `EM_X86_64` = 62, `EM_AARCH64` = 183.
fn host_elf_machine() -> Option<u16> {
    if cfg!(target_arch = "x86_64") {
        Some(62)
    } else if cfg!(target_arch = "aarch64") {
        Some(183)
    } else {
        None
    }
}

/// Probe a few representative binaries in `rootfs_dir` and return the first
/// one's ELF `e_machine`. `None` when none is present/readable as ELF (a tree
/// with no probe-able binary can't be arch-checked — dev-only, so we don't
/// block on it).
fn probe_rootfs_elf_machine(rootfs_dir: &Path) -> Option<u16> {
    const CANDIDATES: &[&str] = &[
        "bin/sh",
        "bin/busybox",
        "bin/bash",
        "usr/bin/env",
        "sbin/init",
    ];
    for candidate in CANDIDATES {
        let path = rootfs_dir.join(candidate);
        if let Ok(bytes) = read_elf_header(&path)
            && let Some(machine) = elf_machine(&bytes)
        {
            return Some(machine);
        }
    }
    None
}

/// Read just enough of a file to inspect its ELF header (cheap; never slurps a
/// whole binary).
fn read_elf_header(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = [0u8; 20];
    let mut file = fs::File::open(path)?;
    let n = file.read(&mut buf)?;
    Ok(buf[..n].to_vec())
}

/// Parse the ELF `e_machine` (offset 18, endianness per `EI_DATA`) from a
/// header. `None` if the bytes aren't an ELF header.
fn elf_machine(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 20 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    let m = [bytes[18], bytes[19]];
    match bytes[5] {
        1 => Some(u16::from_le_bytes(m)),
        2 => Some(u16::from_be_bytes(m)),
        _ => None,
    }
}

pub(super) fn pull_image_with_trust(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<(CachedOciImage, OciTrustDecision, String)> {
    let image_ref: ImageReference = reference.parse()?;
    if prod && !image_ref.is_digest_pinned() {
        bail!("mvmctl image pull --prod requires a digest-pinned reference");
    }
    pull_image_ref(cache_root, image_ref, reference, prod)
}

fn trust_decision_for_cached_image(
    image_ref: &ImageReference,
    image: &CachedOciImage,
    prod: bool,
    verifier: &dyn CosignVerifier,
) -> Result<OciTrustDecision> {
    enforce_oci_trust_policy(image_ref, &image.resolved_digest, prod, verifier)
}

fn enforce_oci_trust_policy(
    image_ref: &ImageReference,
    resolved_digest: &str,
    prod: bool,
    verifier: &dyn CosignVerifier,
) -> Result<OciTrustDecision> {
    if !prod {
        return Ok(OciTrustDecision::dev_digest_only(image_ref));
    }
    let policy = load_oci_registry_policy()?;
    enforce_oci_trust_policy_with(image_ref, resolved_digest, &policy, verifier)
}

fn enforce_oci_trust_policy_with(
    image_ref: &ImageReference,
    resolved_digest: &str,
    policy: &OciRegistryPolicy,
    verifier: &dyn CosignVerifier,
) -> Result<OciTrustDecision> {
    enforce_registry_allowlist(image_ref, policy)?;
    ensure_signature_policy_is_configured(policy)?;
    let verification_ref = cosign_verification_reference(image_ref, resolved_digest);
    let mut failures = Vec::new();
    for identity in &policy.cosign {
        match verifier.verify(&verification_ref, identity) {
            Ok(()) => return Ok(OciTrustDecision::cosign_verified(identity)),
            Err(err) => failures.push(err.to_string()),
        }
    }
    bail!(
        "cosign verification failed for {} under production OCI policy: {}",
        verification_ref,
        failures.join("; ")
    );
}

fn enforce_registry_allowlist(
    image_ref: &ImageReference,
    policy: &OciRegistryPolicy,
) -> Result<()> {
    if !policy.allowed_registries.is_empty()
        && !policy
            .allowed_registries
            .iter()
            .any(|registry| registry == &image_ref.registry)
    {
        bail!(
            "OCI registry '{}' is denied by production policy",
            image_ref.registry
        );
    }
    Ok(())
}

fn ensure_signature_policy_is_configured(policy: &OciRegistryPolicy) -> Result<()> {
    if !policy.require_signatures {
        bail!("production OCI policy cannot disable cosign signatures");
    }
    if policy.cosign.is_empty() {
        bail!("production OCI policy requires signatures but has no [[cosign]] trusted identity");
    }
    Ok(())
}

fn cosign_verification_reference(image_ref: &ImageReference, resolved_digest: &str) -> String {
    format!(
        "{}/{}@{}",
        image_ref.registry, image_ref.repository, resolved_digest
    )
}

fn load_oci_registry_policy() -> Result<OciRegistryPolicy> {
    let path = match std::env::var_os("MVM_OCI_POLICY") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(mvm_core::config::mvm_data_dir()).join("oci-policy.toml"),
    };
    if !path.exists() {
        bail!(
            "mvmctl image --prod requires an OCI registry policy at {} \
             (or set MVM_OCI_POLICY to a policy file)",
            path.display()
        );
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading OCI registry policy {}", path.display()))?;
    parse_oci_registry_policy(&text)
        .with_context(|| format!("parsing OCI registry policy {}", path.display()))
}

fn parse_oci_registry_policy(text: &str) -> Result<OciRegistryPolicy> {
    let policy: OciRegistryPolicy = toml::from_str(text)?;
    validate_oci_registry_policy(&policy)?;
    Ok(policy)
}

fn validate_oci_registry_policy(policy: &OciRegistryPolicy) -> Result<()> {
    ensure_signature_policy_is_configured(policy)?;
    for registry in &policy.allowed_registries {
        if registry.is_empty()
            || registry.contains("://")
            || registry.contains('/')
            || registry.chars().any(char::is_whitespace)
        {
            bail!("invalid OCI policy registry host {registry:?}");
        }
    }
    for identity in &policy.cosign {
        if identity.certificate_identity.is_empty()
            || identity.certificate_oidc_issuer.is_empty()
            || identity.certificate_identity.chars().any(char::is_control)
            || identity
                .certificate_oidc_issuer
                .chars()
                .any(char::is_control)
        {
            bail!("invalid empty or control-character cosign identity in OCI policy");
        }
    }
    Ok(())
}

fn pull_image_ref(
    cache_root: &Path,
    image_ref: ImageReference,
    supplied_reference: &str,
    prod: bool,
) -> Result<(CachedOciImage, OciTrustDecision, String)> {
    let prod_policy = if prod {
        let policy = load_oci_registry_policy()?;
        enforce_registry_allowlist(&image_ref, &policy)?;
        ensure_signature_policy_is_configured(&policy)?;
        Some(policy)
    } else {
        None
    };
    let registry_auth = registry_auth_for(&image_ref)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime for OCI pull")?;

    let manifest_fetcher = OciManifestFetcher::with_auth(registry_auth.auth);
    let manifest = runtime
        .block_on(
            manifest_fetcher
                .fetch_linux_platform_manifest(&image_ref, &LinuxPlatform::for_current_arch()),
        )
        .context("fetch OCI image manifest")?;
    let layers = manifest.layers().context("parse OCI image layers")?;
    if layers.is_empty() {
        bail!(
            "OCI image manifest has no layers: {}",
            image_ref.canonical()
        );
    }

    let trust = match &prod_policy {
        Some(policy) => enforce_oci_trust_policy_with(
            &image_ref,
            &manifest.digest,
            policy,
            &CosignCommandVerifier,
        )?,
        None => OciTrustDecision::dev_digest_only(&image_ref),
    };

    let manifest_hex = sha256_hex(&manifest.digest)?;
    let manifest_path = format!("manifests/{manifest_hex}.json");
    write_cache_file(cache_root, &manifest_path, &manifest.bytes)?;

    let config_path = write_config_blob(
        cache_root,
        &runtime,
        &manifest_fetcher,
        &image_ref,
        &manifest.bytes,
    )?;
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    let unpacked_root = cache_root.join("unpacked").join(&manifest_hex);
    if unpacked_root.exists() {
        fs::remove_dir_all(&unpacked_root)
            .with_context(|| format!("remove stale unpacked root {}", unpacked_root.display()))?;
    }
    fs::create_dir_all(&unpacked_root)
        .with_context(|| format!("create {}", unpacked_root.display()))?;

    let mut cached_layers = Vec::with_capacity(layers.len());
    for layer in &layers {
        let compressed =
            fetch_or_read_layer(cache_root, &runtime, &layer_fetcher, &image_ref, layer)
                .with_context(|| format!("fetch layer {}", layer.digest))?;
        unpack_layer_bytes(layer, &compressed, &unpacked_root)
            .with_context(|| format!("unpack layer {}", layer.digest))?;
        cached_layers.push(CachedOciLayer {
            digest: layer.digest.clone(),
            size_bytes: layer.size,
            path: Some(layer_blob_path(&layer.digest)?),
        });
    }

    let rootfs_path = format!("rootfs/{manifest_hex}/rootfs.ext4");
    let rootfs_abs = cache_root.join(&rootfs_path);
    inject_runtime_and_materialize(
        cache_root,
        &unpacked_root,
        &rootfs_abs,
        &image_ref.canonical(),
    )?;

    let provenance = OciProvenance {
        schema_version: 1,
        source: "image_pull".to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: image_ref.canonical(),
        registry: image_ref.registry.clone(),
        repository: image_ref.repository.clone(),
        tag: image_ref.tag.clone(),
        resolved_digest: manifest.digest.clone(),
        layer_digests: cached_layers
            .iter()
            .map(|layer| layer.digest.clone())
            .collect(),
        trust_policy: trust.trust_policy.clone(),
        verification_status: trust.verification_status.clone(),
    };
    let claims_path = format!("claims/{}.provenance.json", manifest_hex);
    write_cache_file(
        cache_root,
        &claims_path,
        &serde_json::to_vec_pretty(&provenance).context("serialize OCI provenance")?,
    )?;

    let mut index = load_index(cache_root)?;
    let cached = CachedOciImage {
        reference: image_ref.canonical(),
        registry: image_ref.registry.clone(),
        repository: image_ref.repository.clone(),
        tag: image_ref.tag.clone(),
        resolved_digest: manifest.digest.clone(),
        fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        manifest_path,
        config_path,
        rootfs_path: Some(rootfs_path),
        claims_path: Some(claims_path),
        layers: cached_layers,
    };
    upsert_image(&mut index, cached.clone());
    save_index(cache_root, &index)?;
    Ok((cached, trust, registry_auth.source))
}

fn write_config_blob(
    cache_root: &Path,
    runtime: &tokio::runtime::Runtime,
    manifest_fetcher: &OciManifestFetcher,
    image_ref: &ImageReference,
    manifest_bytes: &[u8],
) -> Result<Option<String>> {
    let Some(config) = manifest_config_descriptor(manifest_bytes)? else {
        return Ok(None);
    };
    let config_path = format!("configs/{}.json", sha256_hex(&config.digest)?);
    if let Some(bytes) = read_verified_cache_file(cache_root, &config_path, &config.digest)?
        && serde_json::from_slice::<Value>(&bytes).is_ok()
    {
        return Ok(Some(config_path));
    }

    let fetcher =
        OciLayerFetcher::from_manifest_fetcher(manifest_fetcher, LayerFetchOptions::default());
    let mut bytes = Vec::new();
    runtime
        .block_on(fetcher.fetch_layer(image_ref, &config, &mut bytes))
        .context("fetch OCI image config blob")?;
    write_cache_file(cache_root, &config_path, &bytes)?;
    Ok(Some(config_path))
}

fn manifest_config_descriptor(manifest_bytes: &[u8]) -> Result<Option<LayerDescriptor>> {
    let value: Value = serde_json::from_slice(manifest_bytes).context("parse manifest JSON")?;
    let Some(config) = value.get("config").and_then(Value::as_object) else {
        return Ok(None);
    };
    let digest = config
        .get("digest")
        .and_then(Value::as_str)
        .context("manifest config missing digest")?
        .to_string();
    let media_type = config
        .get("mediaType")
        .and_then(Value::as_str)
        .unwrap_or("application/vnd.oci.image.config.v1+json")
        .to_string();
    let size = config.get("size").and_then(Value::as_u64).unwrap_or(0);
    Ok(Some(LayerDescriptor {
        digest,
        size,
        media_type,
    }))
}

fn fetch_or_read_layer(
    cache_root: &Path,
    runtime: &tokio::runtime::Runtime,
    fetcher: &OciLayerFetcher,
    image_ref: &ImageReference,
    layer: &LayerDescriptor,
) -> Result<Vec<u8>> {
    let path = layer_blob_path(&layer.digest)?;
    if let Some(bytes) = read_verified_cache_file(cache_root, &path, &layer.digest)? {
        return Ok(bytes);
    }
    let mut bytes = Vec::new();
    runtime.block_on(fetcher.fetch_layer(image_ref, layer, &mut bytes))?;
    write_cache_file(cache_root, &path, &bytes)?;
    Ok(bytes)
}

fn unpack_layer_bytes(layer: &LayerDescriptor, bytes: &[u8], unpacked_root: &Path) -> Result<()> {
    let report = if is_gzip_layer(&layer.media_type) {
        unpack_layer(
            GzDecoder::new(Cursor::new(bytes)),
            unpacked_root,
            &UnpackOptions::default(),
        )
    } else {
        unpack_layer(Cursor::new(bytes), unpacked_root, &UnpackOptions::default())
    }?;
    if !report.refused.is_empty() {
        bail!("layer unpack refused entries: {:?}", report.refused);
    }
    Ok(())
}

fn is_gzip_layer(media_type: &str) -> bool {
    media_type.ends_with("+gzip")
        || media_type.ends_with(".gzip")
        || media_type.contains("tar.gzip")
}

pub(super) fn list_rows(cache_root: &Path, registry: Option<&str>) -> Result<Vec<ImageListRow>> {
    let index = load_index(cache_root)?;
    let rows = index
        .images
        .iter()
        .filter(|image| registry.is_none_or(|want| image.registry == want))
        .map(|image| ImageListRow {
            reference: image.reference.clone(),
            registry: image.registry.clone(),
            repository: image.repository.clone(),
            tag: image.tag.clone(),
            resolved_digest: image.resolved_digest.clone(),
            fetched_at: image.fetched_at.clone(),
            size_bytes: image_size_bytes(cache_root, image),
            layers: image.layers.len(),
        })
        .collect();
    Ok(rows)
}

pub(super) fn inspect_image(cache_root: &Path, reference: &str) -> Result<InspectOutput> {
    let index = load_index(cache_root)?;
    let image = find_image(&index, reference)
        .with_context(|| format!("cached OCI image not found for '{reference}'"))?
        .clone();
    Ok(InspectOutput {
        size_bytes: image_size_bytes(cache_root, &image),
        manifest: read_json_optional(cache_root, &image.manifest_path)?,
        config: image
            .config_path
            .as_deref()
            .map(|p| read_json_optional(cache_root, p))
            .transpose()?
            .flatten(),
        claims: image
            .claims_path
            .as_deref()
            .map(|p| read_json_optional(cache_root, p))
            .transpose()?
            .flatten(),
        image,
    })
}

pub(super) fn remove_image(cache_root: &Path, reference: &str) -> Result<RemoveOutcome> {
    let mut index = load_index(cache_root)?;
    let Some(position) = index
        .images
        .iter()
        .position(|image| image_matches(image, reference))
    else {
        bail!("cached OCI image not found for '{reference}'");
    };

    let image = index.images.remove(position);
    let mut removed_files = 0usize;
    let mut freed_bytes = 0u64;
    let shared_layer_paths = remaining_layer_paths(&index);
    validate_image_paths(cache_root, &image)?;

    for path in metadata_paths(&image) {
        remove_cache_file(cache_root, &path, &mut removed_files, &mut freed_bytes)?;
    }

    for layer in &image.layers {
        let Some(path) = layer.path.as_deref() else {
            continue;
        };
        if shared_layer_paths.contains(path) {
            continue;
        }
        remove_cache_file(cache_root, path, &mut removed_files, &mut freed_bytes)?;
    }

    save_index(cache_root, &index)?;
    Ok(RemoveOutcome {
        reference: image.reference,
        removed_files,
        freed_bytes,
    })
}

fn load_index(cache_root: &Path) -> Result<OciCacheIndex> {
    let path = cache_root.join(INDEX_FILE);
    if !path.exists() {
        return Ok(OciCacheIndex::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let index: OciCacheIndex =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    if index.schema_version != 1 {
        bail!(
            "unsupported OCI cache index schema_version {} at {}",
            index.schema_version,
            path.display()
        );
    }
    Ok(index)
}

fn save_index(cache_root: &Path, index: &OciCacheIndex) -> Result<()> {
    fs::create_dir_all(cache_root).with_context(|| format!("create {}", cache_root.display()))?;
    let path = cache_root.join(INDEX_FILE);
    let bytes = serde_json::to_vec_pretty(index).context("serialize OCI cache index")?;
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

fn read_verified_cache_file(
    cache_root: &Path,
    relative: &str,
    digest: &str,
) -> Result<Option<Vec<u8>>> {
    let path = safe_cache_path(cache_root, relative)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    verify_sha256_digest(&bytes, digest)
        .with_context(|| format!("verify cached blob {}", path.display()))?;
    Ok(Some(bytes))
}

fn write_cache_file(cache_root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let path = safe_cache_path(cache_root, relative)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

fn layer_blob_path(digest: &str) -> Result<String> {
    Ok(format!("blobs/sha256/{}", sha256_hex(digest)?))
}

fn sha256_hex(digest: &str) -> Result<String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        bail!("unsupported digest algorithm in {digest:?}");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("malformed sha256 digest: {digest:?}");
    }
    Ok(hex.to_string())
}

fn unpacked_tree_size(root: &Path) -> Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("stat unpacked path {}", path.display()))?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
                stack.push(entry?.path());
            }
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn upsert_image(index: &mut OciCacheIndex, image: CachedOciImage) {
    if let Some(existing) = index
        .images
        .iter_mut()
        .find(|cached| cached.reference == image.reference)
    {
        *existing = image;
    } else {
        index.images.push(image);
    }
}

fn find_image<'a>(index: &'a OciCacheIndex, reference: &str) -> Option<&'a CachedOciImage> {
    index
        .images
        .iter()
        .find(|image| image_matches(image, reference))
}

fn image_matches(image: &CachedOciImage, reference: &str) -> bool {
    image.reference == reference
        || image.resolved_digest == reference
        || image
            .resolved_digest
            .strip_prefix("sha256:")
            .is_some_and(|digest| digest == reference)
}

fn image_size_bytes(cache_root: &Path, image: &CachedOciImage) -> u64 {
    let mut total = 0u64;
    let mut seen = BTreeSet::new();
    for path in all_image_paths(image) {
        if !seen.insert(path.clone()) {
            continue;
        }
        if let Ok(path) = safe_cache_path(cache_root, &path)
            && let Ok(meta) = path.metadata()
            && meta.is_file()
        {
            total = total.saturating_add(meta.len());
        }
    }
    if total == 0 {
        image
            .layers
            .iter()
            .map(|layer| layer.size_bytes)
            .fold(0u64, u64::saturating_add)
    } else {
        total
    }
}

fn all_image_paths(image: &CachedOciImage) -> Vec<String> {
    let mut paths = metadata_paths(image);
    paths.extend(image.layers.iter().filter_map(|layer| layer.path.clone()));
    paths
}

fn metadata_paths(image: &CachedOciImage) -> Vec<String> {
    let mut paths = vec![image.manifest_path.clone()];
    paths.extend(image.config_path.clone());
    paths.extend(image.rootfs_path.clone());
    paths.extend(image.claims_path.clone());
    paths
}

fn remaining_layer_paths(index: &OciCacheIndex) -> BTreeSet<String> {
    index
        .images
        .iter()
        .flat_map(|image| image.layers.iter())
        .filter_map(|layer| layer.path.clone())
        .collect()
}

fn validate_image_paths(cache_root: &Path, image: &CachedOciImage) -> Result<()> {
    for path in all_image_paths(image) {
        let _ = safe_cache_path(cache_root, &path)?;
    }
    Ok(())
}

fn read_json_optional(cache_root: &Path, relative: &str) -> Result<Option<Value>> {
    let path = safe_cache_path(cache_root, relative)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("parse {}", path.display()))
}

fn remove_cache_file(
    cache_root: &Path,
    relative: &str,
    removed_files: &mut usize,
    freed_bytes: &mut u64,
) -> Result<()> {
    let path = safe_cache_path(cache_root, relative)?;
    if !path.exists() {
        return Ok(());
    }
    let meta = path
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("refusing to remove non-file cache path {}", path.display());
    }
    let len = meta.len();
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    *removed_files += 1;
    *freed_bytes = freed_bytes.saturating_add(len);
    prune_empty_parents(cache_root, path.parent())?;
    Ok(())
}

fn prune_empty_parents(cache_root: &Path, mut current: Option<&Path>) -> Result<()> {
    while let Some(dir) = current {
        if dir == cache_root {
            break;
        }
        match fs::remove_dir(dir) {
            Ok(()) => current = dir.parent(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => current = dir.parent(),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
            Err(e) => return Err(e).with_context(|| format!("remove {}", dir.display())),
        }
    }
    Ok(())
}

fn safe_cache_path(cache_root: &Path, relative: &str) -> Result<PathBuf> {
    let rel = Path::new(relative);
    if rel.is_absolute() {
        bail!("OCI cache path must be relative: {relative}");
    }
    if rel.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("OCI cache path escapes cache root: {relative}");
    }
    Ok(cache_root.join(rel))
}

pub(super) fn render_list(rows: &[ImageListRow]) {
    if rows.is_empty() {
        println!("No cached OCI images.");
        return;
    }
    println!(
        "{:<38} {:<20} {:<18} {:>10}",
        "REFERENCE", "DIGEST", "FETCHED", "SIZE"
    );
    for row in rows {
        println!(
            "{:<38} {:<20} {:<18} {:>10}",
            truncate(&row.reference, 38),
            truncate(&row.resolved_digest, 20),
            truncate(&row.fetched_at, 18),
            human_bytes(row.size_bytes)
        );
    }
}

pub(super) fn render_inspect(output: &InspectOutput) {
    let image = &output.image;
    println!("Reference: {}", image.reference);
    println!("Registry: {}", image.registry);
    println!("Repository: {}", image.repository);
    if let Some(tag) = &image.tag {
        println!("Tag: {tag}");
    }
    println!("Resolved digest: {}", image.resolved_digest);
    println!("Fetched at: {}", image.fetched_at);
    println!("Size: {}", human_bytes(output.size_bytes));
    println!("Manifest: {}", image.manifest_path);
    if let Some(path) = &image.config_path {
        println!("Config: {path}");
    }
    if let Some(path) = &image.rootfs_path {
        println!("Rootfs: {path}");
    }
    println!(
        "mvm-claims.json: {}",
        if output.claims.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    println!("Layers:");
    for layer in &image.layers {
        let path = layer.path.as_deref().unwrap_or("-");
        println!(
            "  {}  {}  {}",
            layer.digest,
            human_bytes(layer.size_bytes),
            path
        );
    }
    if let Some(claims) = &output.claims
        && let Some(labels) = claims.as_object().and_then(|obj| obj.get("labels"))
    {
        let labels: BTreeMap<_, _> = labels
            .as_object()
            .into_iter()
            .flat_map(|obj| obj.iter())
            .collect();
        if !labels.is_empty() {
            println!("Claim labels:");
            for (key, value) in labels {
                println!("  {key}: {value}");
            }
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut s: String = value.chars().take(max.saturating_sub(1)).collect();
    s.push('~');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockCosignVerifier {
        results: RefCell<Vec<Result<(), CosignVerifyError>>>,
    }

    impl MockCosignVerifier {
        fn new(results: Vec<Result<(), CosignVerifyError>>) -> Self {
            Self {
                results: RefCell::new(results),
            }
        }
    }

    impl CosignVerifier for MockCosignVerifier {
        fn verify(
            &self,
            _reference: &str,
            _identity: &CosignIdentity,
        ) -> Result<(), CosignVerifyError> {
            self.results.borrow_mut().remove(0)
        }
    }

    fn sample_image(reference: &str, digest: &str, layer_path: &str) -> CachedOciImage {
        CachedOciImage {
            reference: reference.to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: Some("3.20".to_string()),
            resolved_digest: digest.to_string(),
            fetched_at: "2026-05-18T00:00:00Z".to_string(),
            manifest_path: "manifests/alpine.json".to_string(),
            config_path: Some("configs/alpine.json".to_string()),
            rootfs_path: None,
            claims_path: Some("claims/alpine.json".to_string()),
            layers: vec![CachedOciLayer {
                digest: "sha256:layer".to_string(),
                size_bytes: 4,
                path: Some(layer_path.to_string()),
            }],
        }
    }

    fn write_index(cache_root: &Path, index: &OciCacheIndex) {
        fs::create_dir_all(cache_root).expect("create cache root");
        fs::write(
            cache_root.join(INDEX_FILE),
            serde_json::to_vec_pretty(index).expect("serialize index"),
        )
        .expect("write index");
    }

    #[test]
    fn default_index_round_trips_through_save_and_load() {
        // Regression: a derived `Default` set schema_version = 0, which
        // save_index persisted and load_index then rejected — breaking
        // `image ls` / `run --image` on a freshly-created OCI cache.
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(OciCacheIndex::default().schema_version, schema_version());
        save_index(tmp.path(), &OciCacheIndex::default()).expect("save a default index");
        let loaded = load_index(tmp.path()).expect("a freshly-saved default index must load");
        assert_eq!(loaded.schema_version, schema_version());
        assert!(loaded.images.is_empty());
    }

    fn write_file(cache_root: &Path, relative: &str, body: &[u8]) {
        let path = cache_root.join(relative);
        fs::create_dir_all(path.parent().expect("relative has parent")).expect("create parent");
        fs::write(path, body).expect("write cache file");
    }

    #[test]
    fn prod_pull_requires_digest_pin_before_network() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = pull_image_with_trust(tmp.path(), "docker.io/library/alpine:3.20", true)
            .expect_err("mutable prod pull must fail before registry access");
        assert!(
            err.to_string()
                .contains("requires a digest-pinned reference"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn local_archive_prod_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_local_archive(
            tmp.path(),
            Path::new("/does/not/matter.tar"),
            "oci-archive:/does/not/matter.tar",
            true,
        )
        .expect_err("prod local archive must be refused");
        assert!(err.to_string().contains("prod"), "got {err}");
    }

    #[test]
    fn local_archive_missing_file_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("nope.tar");
        let err = ingest_local_archive(tmp.path(), &missing, "oci-archive:nope.tar", false)
            .expect_err("missing archive must error");
        assert!(err.to_string().contains("open OCI archive"), "got {err}");
    }

    #[test]
    fn local_archive_malformed_is_rejected() {
        // Fails inside read_oci_archive (no oci-layout / index) before any
        // materialize, so no builder VM is needed to exercise the reject path.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bad = tmp.path().join("bad.tar");
        std::fs::write(&bad, b"definitely not a valid tar archive").unwrap();
        let err = ingest_local_archive(tmp.path(), &bad, "oci-archive:bad.tar", false)
            .expect_err("malformed archive must be rejected");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn stdin_archive_prod_is_refused() {
        // prod bails before any stdin read.
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_stdin_archive(tmp.path(), "-", true)
            .expect_err("prod stdin archive must be refused");
        assert!(err.to_string().contains("prod"), "got {err}");
    }

    fn fake_elf(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little-endian
        b[6] = 1; // version
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b
    }

    #[test]
    fn elf_machine_parses_le_and_rejects_non_elf() {
        assert_eq!(elf_machine(&fake_elf(62)), Some(62));
        assert_eq!(elf_machine(&fake_elf(183)), Some(183));
        assert_eq!(elf_machine(b"definitely not an elf!"), None);
    }

    #[test]
    fn rootfs_dir_prod_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_rootfs_dir(tmp.path(), tmp.path(), "rootfs-dir:.", true)
            .expect_err("prod rootfs dir must be refused");
        assert!(err.to_string().contains("prod"), "got {err}");
    }

    #[test]
    fn rootfs_dir_missing_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("nope");
        let err = ingest_rootfs_dir(tmp.path(), &missing, "rootfs-dir:nope", false)
            .expect_err("missing rootfs dir must error");
        assert!(err.to_string().contains("directory"), "got {err}");
    }

    #[test]
    fn rootfs_dir_wrong_arch_is_rejected() {
        // The guard is a no-op on hosts we don't map; skip there.
        let Some(host) = host_elf_machine() else {
            return;
        };
        let wrong = if host == 62 { 183 } else { 62 };
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("sh"), fake_elf(wrong)).unwrap();
        let err = ingest_rootfs_dir(tmp.path(), tmp.path(), "rootfs-dir:.", false)
            .expect_err("cross-arch rootfs must be rejected before materialize");
        assert!(err.to_string().contains("architecture"), "got {err}");
    }

    #[test]
    fn archive_from_reader_rejects_malformed() {
        // The shared file/stdin core rejects a garbage stream inside
        // read_oci_archive, before any materialize (no builder VM needed).
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = ingest_archive_from_reader(
            tmp.path(),
            Cursor::new(b"not a valid oci archive".to_vec()),
            "-",
            "stdin_archive",
            "OCI archive on stdin",
        )
        .expect_err("malformed stdin archive must be rejected");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn prod_run_image_requires_digest_pin_before_network() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", true)
            .expect_err("mutable prod run image must fail before registry access");
        assert!(
            err.to_string()
                .contains("requires a digest-pinned reference"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_run_image_uses_cached_rootfs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(tmp.path(), "rootfs/alpine/rootfs.ext4", b"rootfs");

        let resolved =
            resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", false)
                .expect("cached rootfs resolves");

        assert_eq!(resolved.reference, "docker.io/library/alpine:3.20");
        assert_eq!(resolved.resolved_digest, digest);
        assert!(resolved.rootfs_path.ends_with("rootfs/alpine/rootfs.ext4"));
        assert!(!resolved.pulled);
        assert_eq!(resolved.provenance.source, "run_image");
        assert_eq!(
            resolved.provenance.supplied_reference,
            "docker.io/library/alpine:3.20"
        );
        assert_eq!(resolved.provenance.registry, "docker.io");
        assert_eq!(
            resolved.provenance.layer_digests,
            vec!["sha256:layer".to_string()]
        );
    }

    #[test]
    fn provenance_labels_cover_claim_10_fields() {
        let image = sample_image(
            "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "blobs/a",
        );

        let trust = OciTrustDecision {
            trust_policy: "prod-cosign-required".to_string(),
            verification_status: "cosign-verified identity=repo issuer=issuer".to_string(),
        };
        let provenance = image.provenance("image_pull", "alpine@sha256:aaa", &trust);
        let labels: BTreeMap<_, _> = provenance.audit_labels().into_iter().collect();

        assert_eq!(provenance.registry, "docker.io");
        assert_eq!(provenance.repository, "library/alpine");
        assert_eq!(
            provenance.resolved_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(provenance.layer_digests, vec!["sha256:layer"]);
        assert_eq!(provenance.trust_policy, "prod-cosign-required");
        assert_eq!(
            labels.get("oci_supplied_reference").map(String::as_str),
            Some("alpine@sha256:aaa")
        );
        assert_eq!(
            labels.get("oci_verification_status").map(String::as_str),
            Some("cosign-verified identity=repo issuer=issuer")
        );
    }

    fn policy_text() -> &'static str {
        r#"
allowed_registries = ["docker.io", "ghcr.io"]
require_signatures = true

[[cosign]]
certificate_identity = "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.14.0"
certificate_oidc_issuer = "https://token.actions.githubusercontent.com"
"#
    }

    #[test]
    fn oci_policy_parses_registry_allowlist_and_cosign_identity() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");

        assert_eq!(policy.allowed_registries, vec!["docker.io", "ghcr.io"]);
        assert!(policy.require_signatures);
        assert_eq!(policy.cosign.len(), 1);
        assert_eq!(
            policy.cosign[0].certificate_oidc_issuer,
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn production_policy_accepts_valid_cosign_signature() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Ok(())]);

        let trust = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect("valid signature accepted");

        assert_eq!(trust.trust_policy, "prod-cosign-required");
        assert!(trust.verification_status.contains("cosign-verified"));
    }

    #[test]
    fn production_policy_rejects_missing_signature() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Err(CosignVerifyError::MissingSignature(
            "no matching signatures".to_string(),
        ))]);

        let err = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect_err("missing signature rejected");

        assert!(err.to_string().contains("missing signature"));
    }

    #[test]
    fn production_policy_rejects_invalid_signature() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Err(CosignVerifyError::InvalidSignature(
            "certificate identity mismatch".to_string(),
        ))]);

        let err = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect_err("invalid signature rejected");

        assert!(err.to_string().contains("invalid signature"));
    }

    #[test]
    fn production_policy_rejects_denied_registry_before_cosign() {
        let policy = parse_oci_registry_policy(policy_text()).expect("policy parses");
        let image_ref: ImageReference = "quay.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("valid image ref");
        let verifier = MockCosignVerifier::new(vec![Ok(())]);

        let err = enforce_oci_trust_policy_with(
            &image_ref,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &policy,
            &verifier,
        )
        .expect_err("registry denial rejected");

        assert!(err.to_string().contains("denied by production policy"));
        assert!(verifier.results.borrow().len() == 1, "cosign must not run");
    }

    #[test]
    fn production_policy_requires_trusted_identity_when_signatures_required() {
        let err = parse_oci_registry_policy("allowed_registries = [\"docker.io\"]\n")
            .expect_err("missing identity rejected");

        assert!(err.to_string().contains("no [[cosign]] trusted identity"));
    }

    #[test]
    fn production_policy_rejects_signature_opt_out() {
        let err = parse_oci_registry_policy(
            r#"
allowed_registries = ["docker.io"]
require_signatures = false
"#,
        )
        .expect_err("prod policy cannot opt out of signatures");

        assert!(
            err.to_string().contains("cannot disable cosign signatures"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn registry_env_key_normalizes_registry_host() {
        assert_eq!(registry_env_key("ghcr.io").expect("key"), "GHCR_IO");
        assert_eq!(
            registry_env_key("registry.example.test:5000").expect("key"),
            "REGISTRY_EXAMPLE_TEST_5000"
        );
    }

    #[test]
    fn registry_auth_prefers_registry_specific_bearer_token() {
        let image_ref: ImageReference = "ghcr.io/acme/app:latest".parse().expect("image ref");
        let auth = registry_auth_from_lookup(&image_ref, |name| match name {
            "MVM_OCI_BEARER_TOKEN_GHCR_IO" => Some("registry-token".to_string()),
            "MVM_OCI_BEARER_TOKEN" => Some("global-token".to_string()),
            _ => None,
        })
        .expect("auth resolution");

        assert_eq!(auth.source, "env:MVM_OCI_BEARER_TOKEN_GHCR_IO");
        assert!(auth.auth.is_authenticated());
        assert_eq!(auth.auth.kind(), "bearer");
    }

    #[test]
    fn registry_auth_falls_back_to_global_bearer_token() {
        let image_ref: ImageReference = "ghcr.io/acme/app:latest".parse().expect("image ref");
        let auth = registry_auth_from_lookup(&image_ref, |name| match name {
            "MVM_OCI_BEARER_TOKEN" => Some("global-token".to_string()),
            _ => None,
        })
        .expect("auth resolution");

        assert_eq!(auth.source, "env:MVM_OCI_BEARER_TOKEN");
        assert_eq!(auth.auth.kind(), "bearer");
    }

    #[test]
    fn registry_auth_has_no_docker_config_dependency() {
        let image_ref: ImageReference = "ghcr.io/acme/app:latest".parse().expect("image ref");
        let requested = RefCell::new(Vec::new());
        let auth = registry_auth_from_lookup(&image_ref, |name| {
            requested.borrow_mut().push(name.to_string());
            None
        })
        .expect("auth resolution");

        assert_eq!(auth.source, "anonymous");
        assert!(!auth.auth.is_authenticated());
        assert_eq!(
            requested.into_inner(),
            vec![
                "MVM_OCI_BEARER_TOKEN_GHCR_IO".to_string(),
                "MVM_OCI_BEARER_TOKEN".to_string()
            ]
        );
    }

    #[test]
    fn manifest_config_descriptor_extracts_config_blob() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest,
                "size": 17,
            },
            "layers": [],
        });
        let descriptor =
            manifest_config_descriptor(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        let descriptor = descriptor.expect("config descriptor");
        assert_eq!(descriptor.digest, digest);
        assert_eq!(descriptor.size, 17);
    }

    #[test]
    fn upsert_replaces_existing_reference_entry() {
        let mut index = OciCacheIndex {
            schema_version: 1,
            images: vec![sample_image(
                "docker.io/library/alpine:3.20",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "blobs/old",
            )],
        };
        let replacement = sample_image(
            "docker.io/library/alpine:3.20",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "blobs/new",
        );

        upsert_image(&mut index, replacement);

        assert_eq!(index.images.len(), 1);
        assert_eq!(index.images[0].layers[0].path.as_deref(), Some("blobs/new"));
    }

    #[test]
    fn upsert_keeps_distinct_references_to_same_digest() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut index = OciCacheIndex {
            schema_version: 1,
            images: vec![sample_image(
                "docker.io/library/alpine:3.20",
                digest,
                "blobs/shared",
            )],
        };
        let second = sample_image(
            &format!("docker.io/library/alpine@{digest}"),
            digest,
            "blobs/shared",
        );

        upsert_image(&mut index, second);

        assert_eq!(index.images.len(), 2);
    }

    #[test]
    fn missing_index_lists_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rows = list_rows(tmp.path(), None).expect("list");
        assert!(rows.is_empty());
    }

    #[test]
    fn registry_filter_limits_list_rows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut other = sample_image("ghcr.io/acme/app:1", "sha256:app", "blobs/app");
        other.registry = "ghcr.io".to_string();
        other.repository = "acme/app".to_string();
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![
                    sample_image("docker.io/library/alpine:3.20", "sha256:alpine", "blobs/a"),
                    other,
                ],
            },
        );

        let rows = list_rows(tmp.path(), Some("ghcr.io")).expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reference, "ghcr.io/acme/app:1");
    }

    #[test]
    fn inspect_resolves_by_reference_and_digest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let image = sample_image("docker.io/library/alpine:3.20", "sha256:alpine", "blobs/a");
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(
            tmp.path(),
            "manifests/alpine.json",
            br#"{"schemaVersion":2}"#,
        );
        write_file(
            tmp.path(),
            "configs/alpine.json",
            br#"{"architecture":"arm64"}"#,
        );
        write_file(
            tmp.path(),
            "claims/alpine.json",
            br#"{"labels":{"mvm":"yes"}}"#,
        );

        let by_ref =
            inspect_image(tmp.path(), "docker.io/library/alpine:3.20").expect("inspect by ref");
        let by_digest = inspect_image(tmp.path(), "alpine").expect("inspect by short digest");
        assert_eq!(by_ref.image.reference, by_digest.image.reference);
        assert!(by_ref.manifest.is_some());
        assert!(by_ref.config.is_some());
        assert!(by_ref.claims.is_some());
    }

    #[test]
    fn remove_refuses_paths_that_escape_cache_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut image = sample_image("docker.io/library/alpine:3.20", "sha256:alpine", "../bad");
        image.manifest_path = "../manifest.json".to_string();
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );

        let err = remove_image(tmp.path(), "sha256:alpine").expect_err("unsafe path rejected");
        assert!(err.to_string().contains("escapes cache root"));
        let index = load_index(tmp.path()).expect("index still readable");
        assert_eq!(index.images.len(), 1);
    }

    #[test]
    fn remove_preserves_shared_layers_and_updates_index() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = sample_image(
            "docker.io/library/alpine:3.20",
            "sha256:first",
            "blobs/shared",
        );
        let mut second = sample_image(
            "docker.io/library/busybox:1",
            "sha256:second",
            "blobs/shared",
        );
        second.manifest_path = "manifests/busybox.json".to_string();
        second.config_path = None;
        second.claims_path = None;
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![first, second],
            },
        );
        write_file(tmp.path(), "manifests/alpine.json", b"{}");
        write_file(tmp.path(), "configs/alpine.json", b"{}");
        write_file(tmp.path(), "claims/alpine.json", b"{}");
        write_file(tmp.path(), "blobs/shared", b"layer");

        let outcome = remove_image(tmp.path(), "sha256:first").expect("remove");
        assert_eq!(outcome.removed_files, 3);
        assert!(tmp.path().join("blobs/shared").exists());
        let index = load_index(tmp.path()).expect("load index");
        assert_eq!(index.images.len(), 1);
        assert_eq!(index.images[0].reference, "docker.io/library/busybox:1");
    }
}
