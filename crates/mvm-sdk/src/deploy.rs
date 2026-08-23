//! Deploy-bundle assembly for mvmd-owned control-plane flows.
//!
//! The local side builds the archive, embeds the mvmd-side `mvmd-spec.json`,
//! and records the resulting attestation. When configured, the remote side
//! receives the archive and attestation through one authenticated, replay-safe
//! multipart request.
//!
//! ## Archive layout
//!
//! ```text
//! <bundle>.tar.gz
//! ├── flake.nix                  (mvm-side; built by the compile pipeline)
//! ├── launch.json                (mvm-side; the launch sidecar the
//! │                               generated flake reads at evaluation
//! │                               time. Will be inlined into flake.nix
//! │                               in a later phase per the plan.)
//! ├── src/                       (mvm-side; bundled source tree)
//! └── mvmd-spec.json             (mvmd-side; this module produces it)
//! ```
//!
//! Everything in `flake.nix + src/` is **byte-identical** to what
//! `mvmctl compile` would have produced on its own; `mvmd-spec.json`
//! is the additional sidecar the receiver reads to make scheduling
//! decisions without unpacking the rest.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::ir::{EnvValue, Workload};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::compile::{CompileError, archive_dir, compile};

/// Schema version of the local deploy record.
pub const DEPLOY_RECORD_SCHEMA_VERSION: u32 = 2;

/// Exact-byte identities of the sealed deploy archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigests {
    /// BLAKE3 identity used by the local content-addressed store.
    pub blake3: String,
    /// SHA-256 identity retained for external tooling and interop.
    pub sha256: String,
    /// Number of bytes hashed in the archive.
    pub size_bytes: u64,
}

/// Exact-byte identity of the filesystem image that the boot path mounts.
///
/// This is deliberately separate from [`ArtifactDigests`]: the deploy archive
/// is a transport envelope, while this identity names the boot subject. A
/// caller must never use the archive digest as a rootfs digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootArtifactIdentity {
    /// Stable artifact kind understood by the boot path.
    pub kind: String,
    /// BLAKE3 identity used by the local content-addressed store.
    pub blake3: String,
    /// SHA-256 identity used by the signed execution plan and dm-verity
    /// interoperability boundaries.
    pub sha256: String,
    /// Number of bytes in the exact boot artifact.
    pub size_bytes: u64,
}

/// The pinned runtime environment used when the workload is admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPin {
    /// Lowercase hexadecimal SHA-256 of the workload kernel.
    pub kernel_sha256: String,
}

/// The verified dependency-volume evidence carried by a deploy record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyVolumeRecord {
    /// Hash returned by `verify_sealed_volume`.
    pub volume_hash: String,
    /// SHA-256 of the sealed SBOM bytes.
    pub sbom_sha256: String,
    /// SHA-256 of the sealed CVE result bytes.
    pub cve_sha256: String,
}

/// Local attestation record for a sealed workload artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRecord {
    /// Record schema version. Readers must reject versions they do not know.
    pub schema_version: u32,
    /// Workload identifier from the IR.
    pub workload_id: String,
    /// Internal canonical IR fingerprint used by launch plans.
    pub ir_hash: String,
    /// Exact-byte identities of the sealed image archive.
    pub image: ArtifactDigests,
    /// Exact-byte identity of the filesystem image selected for boot.
    pub boot_artifact: BootArtifactIdentity,
    /// Runtime environment pin, when one was resolved before deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentPin>,
    /// Dependency-volume evidence, when the workload uses one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_volume: Option<DependencyVolumeRecord>,
}

/// The mvmd-bound payload embedded into the deploy archive as
/// `mvmd-spec.json`. Mirrors the schema fixed mvmd-side.
///
/// `#[serde(deny_unknown_fields)]` is the version gate — adding a
/// field on either side requires a coordinated `schema_version` bump
/// so older mvmd receivers can refuse with `E_SCHEMA_VERSION` rather
/// than silently dropping the new value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MvmdSpec {
    /// Schema version of `mvmd-spec.json` itself. Independent of the
    /// IR's `schema_version`. v1 is `"0.1"`.
    pub schema_version: String,
    /// Workload id. Lifted from `Workload.id`.
    pub workload_id: String,
    /// Names of env vars the workload expects to see. Values do not
    /// travel over the wire (literals are baked into `flake.nix`;
    /// secrets are resolved at admission by the supervisor's
    /// `KeystoreReleaser`). mvmd uses this for quota-side accounting
    /// and operator-facing inventory.
    pub env_keys: Vec<String>,
    /// Names of secrets the workload references via `mvm.secret(...)`.
    /// mvmd cross-references its keystore allowlist before admission.
    pub secret_refs: Vec<SecretRef>,
    /// Per-app resource budget. v1 = exactly one app per workload.
    pub resources: ResourcesSpec,
    /// Per-app network policy.
    pub network: Option<NetworkSpec>,
    /// Threat tier (consumer side). Drives mvmd's SMT-affinity matrix.
    pub threat_tier: String,
    /// Lifecycle-hook content hashes (per-phase). mvmd verifies these
    /// match the values folded into the rootfs verity hash so a
    /// tampered hook bundle fails dm-verity at boot.
    pub lifecycle: LifecycleSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesSpec {
    pub cpu_cores: u16,
    pub memory_mb: u32,
    pub rootfs_size_mb: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSpec {
    pub mode: String,
    pub ports: Vec<PortForward>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub mapping_id: u16,
    pub host_addr: String,
    pub guest: u16,
    pub host: u16,
    pub proto: String,
    pub guest_addr: String,
    pub transform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub name: String,
    /// `"env"` or `"file"`. The IR has more shape; mvmd only needs
    /// the mount kind for keystore-release accounting.
    pub mount_kind: String,
    /// Env var name or file path the secret lands at.
    pub mount_target: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSpec {
    /// Hex sha256 of the per-phase merged hook command list (after
    /// addon-merge). Empty string when the phase has no commands —
    /// keeps the field type stable so a missing phase doesn't change
    /// the schema.
    pub before_build_hash: String,
    pub before_start_hash: String,
    pub after_start_hash: String,
    pub before_stop_hash: String,
}

/// The single artifact mvmd receives for deployment. The HTTP shipping
/// client signs `sha256(<archive>)` and `POST`s the body.
#[derive(Debug, Clone)]
pub struct DeployBundle {
    pub archive_path: PathBuf,
    pub workload_id: String,
    pub schema_version: String,
    /// Identity of the exact bytes copied into the archive.
    pub boot_artifact: BootArtifactIdentity,
}

/// All deploy failure modes the caller might want to handle.
#[derive(Debug)]
pub enum DeployError {
    Compile(CompileError),
    Io(std::io::Error),
    Serialize(serde_json::Error),
    SchemaVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    BootArtifact {
        path: PathBuf,
        reason: String,
    },
    DependencyVolume {
        path: PathBuf,
        reason: String,
    },
    RemoteTransportUnavailable {
        base_url: String,
    },
    RemoteCredentialMissing {
        base_url: String,
    },
    RemoteHttp {
        base_url: String,
        status: u16,
    },
    RemoteProtocol {
        base_url: String,
        reason: String,
    },
}

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compile(e) => write!(f, "compile failed: {e}"),
            Self::Io(e) => write!(f, "deploy io: {e}"),
            Self::Serialize(e) => write!(f, "serializing mvmd-spec.json: {e}"),
            Self::SchemaVersion {
                path,
                found,
                expected,
            } => write!(
                f,
                "deploy record {} has schema version {found}, expected {expected}",
                path.display()
            ),
            Self::DependencyVolume { path, reason } => {
                write!(
                    f,
                    "dependency volume {} is not sealed: {reason}",
                    path.display()
                )
            }
            Self::BootArtifact { path, reason } => {
                write!(
                    f,
                    "boot artifact {} is not attested: {reason}",
                    path.display()
                )
            }
            Self::RemoteTransportUnavailable { base_url } => write!(
                f,
                "remote artifact transport is unavailable for {base_url}; local deployment was preserved"
            ),
            Self::RemoteCredentialMissing { base_url } => write!(
                f,
                "MVM_MVMD_API_KEY is required for authenticated remote deployment to {base_url}"
            ),
            Self::RemoteHttp { base_url, status } => write!(
                f,
                "mvmd rejected remote deployment to {base_url} with HTTP {status}"
            ),
            Self::RemoteProtocol { base_url, reason } => {
                write!(f, "invalid mvmd response from {base_url}: {reason}")
            }
        }
    }
}

impl std::error::Error for DeployError {}

impl From<CompileError> for DeployError {
    fn from(e: CompileError) -> Self {
        Self::Compile(e)
    }
}

impl From<std::io::Error> for DeployError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for DeployError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialize(e)
    }
}

/// Compile a workload, derive `mvmd-spec.json`, and pack everything
/// into a single deterministic `.tar.gz` at `out`. Returns the
/// [`DeployBundle`] for the shipping step.
pub fn build_deploy_bundle(
    workload: &Workload,
    out: &Path,
    manifest_dir: &Path,
    boot_artifact: &Path,
) -> Result<DeployBundle, DeployError> {
    let temp = tempfile::Builder::new()
        .prefix(".mvm-deploy-staging-")
        .tempdir_in(out.parent().unwrap_or_else(|| Path::new(".")))?;
    let staging = temp.path().join("artifact");
    compile(workload, &staging, manifest_dir)?;
    let spec = build_mvmd_spec(workload);
    let spec_json = serde_json::to_vec_pretty(&spec)?;
    std::fs::write(staging.join("mvmd-spec.json"), spec_json)?;
    let boot_dir = staging.join("boot");
    std::fs::create_dir_all(&boot_dir)?;
    std::fs::copy(boot_artifact, boot_dir.join("rootfs.ext4")).map_err(|error| {
        DeployError::Io(std::io::Error::new(
            error.kind(),
            format!("copying boot artifact {}: {error}", boot_artifact.display()),
        ))
    })?;
    let boot_artifact_identity = digest_boot_artifact(&boot_dir.join("rootfs.ext4"))?;
    archive_dir(&staging, out)
        .map_err(|e| DeployError::Io(std::io::Error::other(format!("archive: {e}"))))?;
    Ok(DeployBundle {
        archive_path: out.to_path_buf(),
        workload_id: workload.id.clone(),
        schema_version: workload.schema_version.clone(),
        boot_artifact: boot_artifact_identity,
    })
}

/// Compute both identity digests of a sealed archive using one streaming read.
pub fn digest_artifact(path: &Path) -> Result<ArtifactDigests, DeployError> {
    let mut file = std::fs::File::open(path)?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = sha2::Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
        size_bytes = size_bytes
            .checked_add(u64::try_from(read).expect("buffer length fits in u64"))
            .expect("artifact size must fit in u64");
    }
    Ok(ArtifactDigests {
        blake3: blake3.finalize().to_hex().to_string(),
        sha256: hex::encode(sha256.finalize()),
        size_bytes,
    })
}

/// Build the local attestation record for a previously-created bundle.
///
/// When `dependency_volume` is provided, its complete sealed layout is
/// verified before any record is returned. This prevents a deploy from
/// recording a volume whose content, SBOM, fetch log, or CVE result changed.
pub fn build_deploy_record(
    workload: &Workload,
    bundle: &DeployBundle,
    environment: Option<EnvironmentPin>,
    dependency_volume: Option<&Path>,
) -> Result<DeployRecord, DeployError> {
    let dependency_volume = dependency_volume.map(read_dependency_volume).transpose()?;
    let ir_hash = crate::ir::ir_hash(workload)?;
    Ok(DeployRecord {
        schema_version: DEPLOY_RECORD_SCHEMA_VERSION,
        workload_id: workload.id.clone(),
        ir_hash,
        image: digest_artifact(&bundle.archive_path)?,
        boot_artifact: bundle.boot_artifact.clone(),
        environment,
        dependency_volume,
    })
}

/// Hash the exact filesystem image selected for the boot path.
pub fn digest_boot_artifact(path: &Path) -> Result<BootArtifactIdentity, DeployError> {
    let digest = digest_artifact(path)?;
    Ok(BootArtifactIdentity {
        kind: "rootfs.ext4".to_string(),
        blake3: digest.blake3,
        sha256: digest.sha256,
        size_bytes: digest.size_bytes,
    })
}

/// Verify that a selected boot path still contains the bytes named by a
/// deploy record. This is intentionally a full rehash: path names and cached
/// metadata are not artifact identity.
pub fn verify_boot_artifact(
    path: &Path,
    expected: &BootArtifactIdentity,
) -> Result<(), DeployError> {
    validate_boot_artifact_identity(path, expected)?;
    let actual = digest_boot_artifact(path)?;
    if actual != *expected {
        return Err(DeployError::BootArtifact {
            path: path.to_path_buf(),
            reason: format!(
                "boot artifact identity mismatch for {}: expected {} / {}, got {} / {}",
                path.display(),
                expected.blake3,
                expected.sha256,
                actual.blake3,
                actual.sha256
            ),
        });
    }
    Ok(())
}

/// Write a deploy record as private, human-readable JSON.
pub fn write_deploy_record(record: &DeployRecord, path: &Path) -> Result<(), DeployError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(record)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Read a deploy record and reject stale or future schemas before any of its
/// fields can influence admission.
pub fn read_deploy_record(path: &Path) -> Result<DeployRecord, DeployError> {
    let record: DeployRecord = serde_json::from_slice(&std::fs::read(path)?)?;
    if record.schema_version != DEPLOY_RECORD_SCHEMA_VERSION {
        return Err(DeployError::SchemaVersion {
            path: path.to_path_buf(),
            found: record.schema_version,
            expected: DEPLOY_RECORD_SCHEMA_VERSION,
        });
    }
    validate_boot_artifact_identity(path, &record.boot_artifact)?;
    Ok(record)
}

fn validate_boot_artifact_identity(
    path: &Path,
    identity: &BootArtifactIdentity,
) -> Result<(), DeployError> {
    if identity.kind != "rootfs.ext4" {
        return Err(DeployError::BootArtifact {
            path: path.to_path_buf(),
            reason: format!("unsupported boot artifact kind {:?}", identity.kind),
        });
    }
    for (label, value) in [("BLAKE3", &identity.blake3), ("SHA-256", &identity.sha256)] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DeployError::BootArtifact {
                path: path.to_path_buf(),
                reason: format!("{label} must be 64 hexadecimal characters"),
            });
        }
    }
    Ok(())
}

fn read_dependency_volume(path: &Path) -> Result<DependencyVolumeRecord, DeployError> {
    let volume_hash = crate::compile::deps_audit::verify_sealed_volume(path).map_err(|error| {
        DeployError::DependencyVolume {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    let manifest_path = path.join(crate::compile::deps_audit::FILE_MANIFEST);
    let manifest: crate::compile::deps_audit::VolumeManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    Ok(DependencyVolumeRecord {
        volume_hash,
        sbom_sha256: manifest.sbom_sha256,
        cve_sha256: manifest.cve_sha256,
    })
}

/// Build the `MvmdSpec` JSON sidecar from a workload's mvmd-bound
/// fields. v1 picks the first (and only) app; the IR validator
/// enforces single-app workloads.
pub fn build_mvmd_spec(workload: &Workload) -> MvmdSpec {
    let app = workload
        .apps
        .first()
        .expect("validate() ensures at least one app");
    let env_keys: Vec<String> = app.env.keys().cloned().collect();
    let secret_refs: Vec<SecretRef> = app
        .env
        .values()
        .filter_map(|v| match v {
            EnvValue::SecretRef { reference } => Some(secret_ref_of(reference)),
            _ => None,
        })
        .collect();
    let resources = ResourcesSpec {
        cpu_cores: app.resources.cpu_cores,
        memory_mb: app.resources.memory_mb,
        rootfs_size_mb: app.resources.rootfs_size_mb,
    };
    let network = app.network.as_ref().map(|n| NetworkSpec {
        mode: match &n.mode {
            crate::ir::NetworkMode::None => "none".into(),
            crate::ir::NetworkMode::Bridge => "bridge".into(),
            crate::ir::NetworkMode::Host => "host".into(),
            // A custom mesh deploys under its provider's name (wireguard, …).
            crate::ir::NetworkMode::Custom { provider, .. } => provider.clone(),
        },
        ports: n
            .ports
            .iter()
            .map(|p| PortForward {
                mapping_id: p.mapping_id,
                host_addr: p.host_addr.clone(),
                guest: p.guest,
                host: p.host,
                proto: match p.proto {
                    crate::ir::PortProto::Tcp => "tcp".into(),
                    crate::ir::PortProto::Udp => "udp".into(),
                },
                guest_addr: p.guest_addr.clone(),
                transform: match p.transform {
                    crate::ir::PortTransform::Opaque => "opaque".into(),
                    crate::ir::PortTransform::Http => "http".into(),
                    crate::ir::PortTransform::Tls => "tls".into(),
                },
                tls_secret: p.tls_secret.clone(),
            })
            .collect(),
    });
    let threat_tier = match app.threat_tier {
        crate::ir::ThreatTier::Untrusted => "untrusted",
        crate::ir::ThreatTier::Trusted => "trusted",
    }
    .to_string();
    let lifecycle = LifecycleSpec {
        before_build_hash: hook_phase_hash(&app.hooks.before_build),
        before_start_hash: hook_phase_hash(&app.hooks.before_start),
        after_start_hash: hook_phase_hash(&app.hooks.after_start),
        before_stop_hash: hook_phase_hash(&app.hooks.before_stop),
    };
    MvmdSpec {
        schema_version: "0.1".to_string(),
        workload_id: workload.id.clone(),
        env_keys,
        secret_refs,
        resources,
        network,
        threat_tier,
        lifecycle,
    }
}

fn secret_ref_of(reference: &crate::ir::SecretRef) -> SecretRef {
    let (mount_kind, mount_target) = match &reference.mount {
        crate::ir::SecretMount::Env { var } => ("env".to_string(), var.clone()),
        crate::ir::SecretMount::File { path } => ("file".to_string(), path.clone()),
    };
    SecretRef {
        name: reference.name.clone(),
        mount_kind,
        mount_target,
    }
}

/// Hex SHA-256 of the JSON-serialized per-phase command list, or `""`
/// when the phase has no commands. Stable across runs because the
/// IR's `HookCmd` enum is `serde(tag = "kind")` and the serialization
/// is deterministic for a given input.
fn hook_phase_hash(cmds: &[crate::ir::HookCmd]) -> String {
    if cmds.is_empty() {
        return String::new();
    }
    let bytes = serde_json::to_vec(cmds).expect("hook serialization is infallible");
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Stable response returned by mvmd after accepting a deploy artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteArtifact {
    /// SHA-256 revision used as the replay/idempotency key.
    pub revision: String,
    /// BLAKE3 identity of the uploaded archive.
    pub blake3: String,
    /// Workload identifier from the deploy record.
    pub workload_id: String,
    /// Current remote lifecycle status.
    pub status: String,
    /// Exact archive size in bytes.
    pub size_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct RemoteResponse {
    data: RemoteArtifact,
}

/// Authenticated remote artifact client.
pub struct MvmdClient {
    /// The configured mvmd endpoint.
    pub base_url: String,
    api_key: String,
}

impl MvmdClient {
    /// Construct a new client for `base_url` with a bearer credential.
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
        }
    }

    /// Upload the bundle and its attestation as one authenticated request.
    ///
    /// Redirects are disabled so the bearer credential is never sent to a
    /// host other than the configured endpoint. The server binds ownership to
    /// the authenticated workspace and treats the archive SHA-256 as the
    /// idempotency key.
    pub fn ship(
        &self,
        bundle: &DeployBundle,
        record: &DeployRecord,
    ) -> Result<RemoteArtifact, DeployError> {
        let endpoint = remote_upload_endpoint(&self.base_url)?;
        let record_json = serde_json::to_string(record)?;
        let bundle_bytes =
            fs::read(&bundle.archive_path).map_err(|error| DeployError::RemoteProtocol {
                base_url: self.base_url.clone(),
                reason: format!("opening bundle: {error}"),
            })?;
        let (content_type, form_body) = deploy_multipart_body(&record_json, &bundle_bytes);
        // mvm-http never follows redirects, so there is no policy to set.
        let client = mvm_http::blocking::Client::builder()
            .build()
            .map_err(|error| DeployError::RemoteProtocol {
                base_url: self.base_url.clone(),
                reason: format!("building HTTP client: {error}"),
            })?;
        let response = client
            .post(endpoint)
            .bearer_auth(&self.api_key)
            .header("content-type", content_type)
            .body(form_body)
            .send()
            .map_err(|error| DeployError::RemoteTransportUnavailable {
                base_url: format!("{} ({error})", self.base_url),
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(DeployError::RemoteHttp {
                base_url: self.base_url.clone(),
                status: status.as_u16(),
            });
        }
        let payload: RemoteResponse =
            response
                .json()
                .map_err(|error| DeployError::RemoteProtocol {
                    base_url: self.base_url.clone(),
                    reason: error.to_string(),
                })?;
        Ok(payload.data)
    }
}

fn deploy_multipart_body(record_json: &str, bundle_bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = format!("mvm-deploy-{}", blake3::hash(bundle_bytes).to_hex());
    let mut body = Vec::with_capacity(record_json.len() + bundle_bytes.len() + 512);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"record\"\r\nContent-Type: application/json\r\n\r\n",
    );
    body.extend_from_slice(record_json.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"bundle\"; filename=\"image.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n",
    );
    body.extend_from_slice(bundle_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

fn remote_upload_endpoint(base_url: &str) -> Result<String, DeployError> {
    let parsed = mvm_http::Url::parse(base_url).map_err(|error| DeployError::RemoteProtocol {
        base_url: base_url.to_string(),
        reason: format!("invalid URL: {error}"),
    })?;
    let allowed =
        parsed.scheme() == "https" || (parsed.scheme() == "http" && is_loopback_url(&parsed));
    if !allowed {
        return Err(DeployError::RemoteTransportUnavailable {
            base_url: base_url.to_string(),
        });
    }
    Ok(format!(
        "{}/api/v1/deploy-artifacts",
        base_url.trim_end_matches('/')
    ))
}

fn is_loopback_url(url: &mvm_http::Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        App, Dependencies, Entrypoint, Format, Hooks, Image, NetworkMode, PortProto, Resources,
        Source,
    };
    use std::collections::BTreeMap;

    fn sample_workload() -> Workload {
        Workload {
            schema_version: "0.1".into(),
            id: "hello".into(),
            apps: vec![App {
                name: "hello".into(),
                source: Source::LocalPath {
                    path: ".".into(),
                    include: vec!["**".into()],
                    exclude: vec![],
                },
                image: Image::NixPackages {
                    packages: vec!["python312".into()],
                },
                entrypoints: vec![Entrypoint::Function {
                    language: "python".into(),
                    module: "app".into(),
                    function: "greet".into(),
                    format: Format::Json,
                    working_dir: "/app".into(),
                    env: BTreeMap::new(),
                    args_schema: None,
                    return_schema: None,
                    extra_imports: vec![],
                    primary: true,
                    concurrency: None,
                }],
                env: BTreeMap::new(),
                mounts: vec![],
                network: Some(crate::ir::Network {
                    mode: NetworkMode::Bridge,
                    ports: vec![crate::ir::PortForward {
                        mapping_id: 1,
                        host_addr: "127.0.0.1".into(),
                        guest: 8080,
                        host: 0,
                        proto: PortProto::Tcp,
                        guest_addr: "127.0.0.1".into(),
                        transform: crate::ir::PortTransform::Opaque,
                        tls_secret: None,
                    }],
                    egress: None,
                    peers: vec![],
                    dns: None,
                    ai: None,
                }),
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: Some(Dependencies::None),
                health_check: None,
                threat_tier: Default::default(),
                addons: vec![],
                hooks: Hooks::default(),
                files: vec![],
            }],
            volumes: vec![],
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn mvmd_spec_reflects_workload_fields() {
        let spec = build_mvmd_spec(&sample_workload());
        assert_eq!(spec.schema_version, "0.1");
        assert_eq!(spec.workload_id, "hello");
        assert_eq!(spec.resources.cpu_cores, 1);
        assert_eq!(spec.resources.memory_mb, 256);
        assert!(spec.env_keys.is_empty());
        assert!(spec.secret_refs.is_empty());
        let n = spec.network.expect("network present");
        assert_eq!(n.mode, "bridge");
        assert_eq!(n.ports.len(), 1);
        assert_eq!(n.ports[0].guest, 8080);
        assert_eq!(n.ports[0].proto, "tcp");
        assert_eq!(spec.threat_tier, "untrusted");
        assert_eq!(spec.lifecycle, LifecycleSpec::default());
    }

    #[test]
    fn mvmd_spec_serializes_round_trip() {
        let spec = build_mvmd_spec(&sample_workload());
        let json = serde_json::to_vec(&spec).expect("serialize");
        let back: MvmdSpec = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    #[test]
    fn mvmd_spec_rejects_unknown_fields() {
        let mut value = serde_json::to_value(build_mvmd_spec(&sample_workload())).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("bogus".into(), serde_json::json!(true));
        let err = serde_json::from_value::<MvmdSpec>(value).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }

    #[test]
    fn hook_phase_hash_is_empty_for_no_commands() {
        let h = hook_phase_hash(&[]);
        assert!(h.is_empty());
    }

    #[test]
    fn hook_phase_hash_is_deterministic_and_nonempty_for_one_command() {
        let cmds = vec![crate::ir::HookCmd::Shell {
            line: "echo hi".into(),
        }];
        let a = hook_phase_hash(&cmds);
        let b = hook_phase_hash(&cmds);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn deploy_bundle_round_trips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join("src");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(manifest_dir.join("hello.py"), b"x = 1\n").unwrap();

        // Source path is relative to manifest_dir, so set it to "."
        let mut workload = sample_workload();
        workload.apps[0].source = Source::LocalPath {
            path: ".".into(),
            include: vec!["**".into()],
            exclude: vec![],
        };

        let archive = tmp.path().join("hello.tar.gz");
        let boot_artifact = tmp.path().join("rootfs.ext4");
        std::fs::write(&boot_artifact, b"rootfs bytes").unwrap();
        let bundle =
            build_deploy_bundle(&workload, &archive, &manifest_dir, &boot_artifact).expect("build");
        assert_eq!(bundle.archive_path, archive);
        assert_eq!(bundle.workload_id, "hello");
        assert!(archive.is_file());
        // Confirm the archive contains mvmd-spec.json.
        let f = std::fs::File::open(&archive).unwrap();
        let gz = flate2::read::GzDecoder::new(f);
        let mut a = tar::Archive::new(gz);
        let entries: Vec<String> = a
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.path().ok().map(|p| p.display().to_string()))
            .collect();
        assert!(
            entries.iter().any(|p| p == "mvmd-spec.json"),
            "archive missing mvmd-spec.json; entries: {entries:?}"
        );
        assert!(
            entries.iter().any(|p| p == "flake.nix"),
            "archive missing flake.nix; entries: {entries:?}"
        );
        assert!(
            entries.iter().any(|p| p == "boot/rootfs.ext4"),
            "archive missing exact boot artifact; entries: {entries:?}"
        );
    }

    #[test]
    fn deploy_record_contains_both_archive_digests() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest_dir = tmp.path().join("src");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(manifest_dir.join("hello.py"), b"x = 1\n").unwrap();
        let archive = tmp.path().join("hello.tar.gz");
        let boot_artifact = tmp.path().join("rootfs.ext4");
        std::fs::write(&boot_artifact, b"rootfs bytes").unwrap();
        let workload = sample_workload();
        let bundle =
            build_deploy_bundle(&workload, &archive, &manifest_dir, &boot_artifact).unwrap();
        let record = build_deploy_record(
            &workload,
            &bundle,
            Some(EnvironmentPin {
                kernel_sha256: "a".repeat(64),
            }),
            None,
        )
        .unwrap();
        assert_eq!(record.schema_version, DEPLOY_RECORD_SCHEMA_VERSION);
        assert_eq!(record.workload_id, "hello");
        assert_eq!(
            record.image.size_bytes,
            std::fs::metadata(&archive).unwrap().len()
        );
        assert_eq!(record.image.blake3.len(), 64);
        assert_eq!(record.image.sha256.len(), 64);
        assert_eq!(record.boot_artifact.kind, "rootfs.ext4");
        assert_eq!(record.boot_artifact.size_bytes, 12);
        assert!(record.environment.is_some());

        let record_path = tmp.path().join("deploy.json");
        write_deploy_record(&record, &record_path).unwrap();
        let round_trip: DeployRecord =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        assert_eq!(round_trip, record);
        assert_eq!(read_deploy_record(&record_path).unwrap(), record);

        let stale_path = tmp.path().join("stale-deploy.json");
        let mut stale = serde_json::to_value(&record).unwrap();
        stale["schema_version"] = serde_json::json!(1);
        std::fs::write(&stale_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        assert!(matches!(
            read_deploy_record(&stale_path),
            Err(DeployError::SchemaVersion { .. })
        ));

        let mut unknown = serde_json::to_value(record).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DeployRecord>(unknown).is_err());
    }

    #[test]
    fn boot_artifact_verification_refuses_tamper_and_wrong_kind() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"attested rootfs").unwrap();
        let identity = digest_boot_artifact(&rootfs).unwrap();
        verify_boot_artifact(&rootfs, &identity).unwrap();

        std::fs::write(&rootfs, b"tampered rootfs").unwrap();
        let error = verify_boot_artifact(&rootfs, &identity).unwrap_err();
        assert!(matches!(error, DeployError::BootArtifact { .. }));

        let mut wrong_kind = identity;
        wrong_kind.kind = "image.tar.gz".to_string();
        let error = verify_boot_artifact(&rootfs, &wrong_kind).unwrap_err();
        assert!(matches!(error, DeployError::BootArtifact { .. }));
    }

    #[test]
    fn deploy_record_refuses_tampered_dependency_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let volume = tmp.path().join("volume");
        let content = volume.join(crate::compile::deps_audit::FILE_CONTENT_DIR);
        std::fs::create_dir_all(&content).unwrap();
        let sbom = volume.join(crate::compile::deps_audit::FILE_SBOM);
        let fetch_log = volume.join(crate::compile::deps_audit::FILE_FETCH_LOG);
        let cve = volume.join(crate::compile::deps_audit::FILE_CVE);
        std::fs::write(content.join("site.py"), b"print('ok')").unwrap();
        std::fs::write(&sbom, br#"{"bomFormat":"CycloneDX"}"#).unwrap();
        std::fs::write(&fetch_log, b"https://example.test\n").unwrap();
        std::fs::write(&cve, br#"{"vulnerabilities":[]}"#).unwrap();
        let seal = crate::compile::deps_audit::seal_volume(
            &content,
            &sbom,
            &fetch_log,
            &cve,
            "2026-01-01T00:00:00Z",
            Default::default(),
        )
        .unwrap();
        std::fs::write(
            volume.join(crate::compile::deps_audit::FILE_MANIFEST),
            seal.manifest_bytes,
        )
        .unwrap();
        std::fs::write(&cve, br#"{"vulnerabilities":["tampered"]}"#).unwrap();

        let archive = tmp.path().join("image.tar.gz");
        std::fs::write(&archive, b"image").unwrap();
        let boot_artifact = tmp.path().join("rootfs.ext4");
        std::fs::write(&boot_artifact, b"rootfs").unwrap();
        let bundle = DeployBundle {
            archive_path: archive,
            workload_id: "hello".into(),
            schema_version: "0.1".into(),
            boot_artifact: digest_boot_artifact(&boot_artifact).unwrap(),
        };
        let err =
            build_deploy_record(&sample_workload(), &bundle, None, Some(&volume)).unwrap_err();
        assert!(matches!(err, DeployError::DependencyVolume { .. }));
    }

    #[test]
    fn remote_client_fails_closed_for_unreachable_transport() {
        let client = MvmdClient::new("http://127.0.0.1:1", "test-token");
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("hello.tar.gz");
        std::fs::write(&archive, b"fake-bytes").unwrap();
        let boot_artifact = tmp.path().join("rootfs.ext4");
        std::fs::write(&boot_artifact, b"rootfs").unwrap();
        let bundle = DeployBundle {
            archive_path: archive,
            workload_id: "hello".into(),
            schema_version: "0.1".into(),
            boot_artifact: digest_boot_artifact(&boot_artifact).unwrap(),
        };
        let record = DeployRecord {
            schema_version: DEPLOY_RECORD_SCHEMA_VERSION,
            workload_id: "hello".into(),
            ir_hash: "ir-hash".into(),
            image: ArtifactDigests {
                blake3: "b".repeat(64),
                sha256: "a".repeat(64),
                size_bytes: 10,
            },
            boot_artifact: BootArtifactIdentity {
                kind: "rootfs.ext4".into(),
                blake3: "b".repeat(64),
                sha256: "a".repeat(64),
                size_bytes: 6,
            },
            environment: None,
            dependency_volume: None,
        };
        let error = client
            .ship(&bundle, &record)
            .expect_err("remote shipping must not report a false success");
        assert!(matches!(
            error,
            DeployError::RemoteTransportUnavailable { .. }
        ));
    }

    #[test]
    fn remote_endpoint_rejects_cleartext_non_loopback() {
        let error = remote_upload_endpoint("http://mvmd.example").unwrap_err();
        assert!(matches!(
            error,
            DeployError::RemoteTransportUnavailable { .. }
        ));
    }

    #[test]
    fn deploy_multipart_body_contains_record_and_bundle_parts() {
        let (content_type, body) = deploy_multipart_body(r#"{"workload_id":"demo"}"#, b"bundle");
        let body = String::from_utf8(body).expect("multipart test body is UTF-8");
        assert!(content_type.starts_with("multipart/form-data; boundary=mvm-deploy-"));
        assert!(body.contains("name=\"record\""));
        assert!(body.contains("{\"workload_id\":\"demo\"}"));
        assert!(body.contains("name=\"bundle\"; filename=\"image.tar.gz\""));
        assert!(body.ends_with("\r\n"));
    }
}
