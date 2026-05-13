//! `mvmctl deploy` — compile a Workload into a single signed archive
//! and ship it to mvmd.
//!
//! v1 ships the stub end of the contract: build the archive, embed
//! `mvmd-spec.json` per ADR-0020 (mvmd-side, see
//! `../../../mvmd/specs/adrs/0020-mvmctl-deploy-bundle-contract.md`),
//! and call `MvmdClient::ship(bundle)` which currently logs the bundle
//! and exits 0. The real HTTP transport (with Ed25519 signature scope
//! over the whole archive bytes, idempotency by `sha256(body)`,
//! tenant scoping, and the rejection taxonomy) lands once mvmd's
//! `POST /v1/workloads` endpoint is implemented per Plan 48.
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

use std::path::{Path, PathBuf};

use mvm_ir::{EnvValue, Workload};
use serde::{Deserialize, Serialize};

use crate::compile::{CompileError, archive_dir, compile};

/// The mvmd-bound payload embedded into the deploy archive as
/// `mvmd-spec.json`. Mirrors the schema fixed in mvmd ADR-0020.
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
    pub guest: u16,
    pub host: u16,
    pub proto: String,
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

/// The single artifact `mvmctl deploy` produces. The HTTP shipping
/// stub takes this verbatim; the real client signs `sha256(<archive>)`
/// and `POST`s the body.
#[derive(Debug, Clone)]
pub struct DeployBundle {
    pub archive_path: PathBuf,
    pub workload_id: String,
    pub schema_version: String,
}

/// All deploy failure modes the caller might want to handle. v1 only
/// surfaces compile + io errors; the HTTP shipping stub will grow
/// signature / quota / tenant rejection arms once the real client
/// lands.
#[derive(Debug)]
pub enum DeployError {
    Compile(CompileError),
    Io(std::io::Error),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compile(e) => write!(f, "compile failed: {e}"),
            Self::Io(e) => write!(f, "deploy io: {e}"),
            Self::Serialize(e) => write!(f, "serializing mvmd-spec.json: {e}"),
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
) -> Result<DeployBundle, DeployError> {
    let temp = tempfile::Builder::new()
        .prefix(".mvm-deploy-staging-")
        .tempdir_in(out.parent().unwrap_or_else(|| Path::new(".")))?;
    let staging = temp.path().join("artifact");
    compile(workload, &staging, manifest_dir)?;
    let spec = build_mvmd_spec(workload);
    let spec_json = serde_json::to_vec_pretty(&spec)?;
    std::fs::write(staging.join("mvmd-spec.json"), spec_json)?;
    archive_dir(&staging, out)
        .map_err(|e| DeployError::Io(std::io::Error::other(format!("archive: {e}"))))?;
    Ok(DeployBundle {
        archive_path: out.to_path_buf(),
        workload_id: workload.id.clone(),
        schema_version: workload.schema_version.clone(),
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
        mode: match n.mode {
            mvm_ir::NetworkMode::None => "none".into(),
            mvm_ir::NetworkMode::Bridge => "bridge".into(),
            mvm_ir::NetworkMode::Host => "host".into(),
        },
        ports: n
            .ports
            .iter()
            .map(|p| PortForward {
                guest: p.guest,
                host: p.host,
                proto: match p.proto {
                    mvm_ir::PortProto::Tcp => "tcp".into(),
                    mvm_ir::PortProto::Udp => "udp".into(),
                },
            })
            .collect(),
    });
    let threat_tier = match app.threat_tier {
        mvm_ir::ThreatTier::Untrusted => "untrusted",
        mvm_ir::ThreatTier::Trusted => "trusted",
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

fn secret_ref_of(reference: &mvm_ir::SecretRef) -> SecretRef {
    let (mount_kind, mount_target) = match &reference.mount {
        mvm_ir::SecretMount::Env { var } => ("env".to_string(), var.clone()),
        mvm_ir::SecretMount::File { path } => ("file".to_string(), path.clone()),
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
fn hook_phase_hash(cmds: &[mvm_ir::HookCmd]) -> String {
    if cmds.is_empty() {
        return String::new();
    }
    let bytes = serde_json::to_vec(cmds).expect("hook serialization is infallible");
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

/// Stub shipping transport. Today it logs the bundle path and the
/// mvmd-side fields and returns Ok. The real client lands once
/// mvmd's `POST /v1/workloads` endpoint is implemented (Plan 48
/// Phase 1090).
pub struct MvmdClient {
    /// Reserved for the real client — `tinylabscom://mvmd` URL or a
    /// per-tenant override. Stub ignores the value.
    pub base_url: String,
}

impl MvmdClient {
    /// Construct a new client for `base_url`. v1 stub ignores the
    /// argument; the real client uses it as the HTTP target.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Ship the bundle. v1 stub: log the archive path + the embedded
    /// mvmd-spec to stderr; exits Ok. The real client (Plan 48
    /// Phase 1090+) will sign the archive bytes with the host signer,
    /// `POST /v1/workloads`, and surface mvmd's rejection codes.
    pub fn ship(&self, bundle: &DeployBundle) -> Result<(), DeployError> {
        let archive_size = std::fs::metadata(&bundle.archive_path)
            .map(|m| m.len())
            .unwrap_or(0);
        eprintln!(
            "would ship: {} ({} bytes, workload {}, schema_version {}) → {}",
            bundle.archive_path.display(),
            archive_size,
            bundle.workload_id,
            bundle.schema_version,
            self.base_url
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_ir::{
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
                network: Some(mvm_ir::Network {
                    mode: NetworkMode::Bridge,
                    ports: vec![mvm_ir::PortForward {
                        guest: 8080,
                        host: 0,
                        proto: PortProto::Tcp,
                    }],
                    egress: None,
                    peers: vec![],
                    dns: None,
                }),
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: Some(Dependencies::None),
                threat_tier: Default::default(),
                addons: vec![],
                hooks: Hooks::default(),
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
        let cmds = vec![mvm_ir::HookCmd::Shell {
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
        let bundle = build_deploy_bundle(&workload, &archive, &manifest_dir).expect("build");
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
    }

    #[test]
    fn stub_client_logs_without_failing() {
        let client = MvmdClient::new("https://mvmd.test/v1");
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("hello.tar.gz");
        std::fs::write(&archive, b"fake-bytes").unwrap();
        let bundle = DeployBundle {
            archive_path: archive,
            workload_id: "hello".into(),
            schema_version: "0.1".into(),
        };
        client.ship(&bundle).expect("stub never errors");
    }
}
