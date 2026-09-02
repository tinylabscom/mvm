//! Runtime SDK — record mode for `Sandbox`-style imperative scripts.
//! SDK port Phase 7.
//!
//! The decorator path (`@mvm.app(...)`) is static: the user's script
//! is read but never executed; tree-sitter pulls the kwargs out of
//! the AST and they lower into a `Workload`. The runtime path
//! (`Sandbox.create(...)` + `sb.commands.start(...)`) is imperative:
//! the user expects to compose calls with regular Python/TS control
//! flow. The two surfaces compile to the same target — a Nix
//! template + `Workload` IR — but the lowering differs.
//!
//! **Record mode** runs the user's script on the host with the SDK
//! reconfigured so every `Sandbox` operation appends to a
//! [`RuntimeRecording`] instead of dialing a real microVM. After the
//! script returns, [`compile_recording`] walks the recording and
//! synthesizes a `Workload` whose:
//!
//! - `image` is resolved from `Sandbox.create(template, ...)` via
//!   [`resolve_base_image`].
//! - `env`, `include`, `resources`, `network` flow through from the
//!   `Sandbox.create` kwargs as-is.
//! - `entrypoint` is the **final** [`RecordedOp::CommandStart`]
//!   argv. Earlier `CommandStart` ops become `before_start` hooks so
//!   they fire in declaration order before the entrypoint.
//! - [`RecordedOp::FilesWrite`] ops lower to `App::files` entries
//!   baked into the rootfs at build time — never into a shell hook.
//! - [`RecordedOp::Kill`] ops are dropped — the workload VM lives
//!   for its declared TTL, not until a kill in the recording.
//!
//! **The host runs user code in this path.** Per the SDK plan's S2
//! security note: this is a deliberate departure from the decorator
//! path's "never executes user code on the host" rule, documented
//! prominently in the SDK guide. The literal-only AST check
//! (Decision I) is enforced by the language SDKs before the script
//! runs; this Rust core trusts the recording was already vetted.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::ir::{
    App, Entrypoint, EnvValue, HookCmd, Hooks, Image, MaterializedFile, Network, Resources, Source,
    Workload,
};

const SCHEMA_VERSION: &str = "0.1";

/// Hard cap on ops per recording. A hand-authored script never
/// approaches this; a runaway loop or adversarial trace does.
pub const MAX_RECORDED_OPS: usize = 1024;

/// Hard cap on one `FilesWrite`'s decoded payload. Larger assets
/// belong in the source bundle or a dependency volume, not inlined
/// in the trace.
pub const MAX_FILES_WRITE_DECODED_BYTES: usize = 8 * 1024 * 1024;

/// Canonical terminal result for a live process operation. The language SDKs
/// expose the byte fields using their native byte container while preserving
/// this shared shape at the contract boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RuntimeProcessResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Canonical stream event emitted while a live process is awaited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RuntimeProcessEvent {
    pub stream: String,
    pub data: Vec<u8>,
}

/// Canonical filesystem directory-entry shape exposed by the live SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RuntimeFsEntry {
    pub name: String,
    pub kind: String,
    pub size: u64,
}

/// Canonical filesystem metadata shape exposed by the live SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RuntimeFsStat {
    pub canonical_path: String,
    pub kind: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: Option<String>,
}

// ────────────────────────────────────────────────────────────────────
// Recording — what the language-SDK side appends to.
// ────────────────────────────────────────────────────────────────────

/// One full record from a `Sandbox`-style script run.
///
/// The language SDK constructs this incrementally: `Sandbox.create`
/// fills [`Self::create`], and each subsequent method call pushes
/// onto [`Self::ops`]. After the user's script returns, the SDK
/// serializes the recording to JSON and hands it to the Rust core's
/// [`compile_recording`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRecording {
    /// User-supplied workload id. Mirrors `@mvm.app("name")` — the
    /// Python SDK reads `__name__` or accepts an override; v1 falls
    /// back to a stable hash of the source file path if neither is
    /// supplied.
    pub workload_id: String,
    /// The single `Sandbox.create(...)` call. Per the SDK plan's
    /// "v1 scope: one app per workload" decision, a script that
    /// constructs multiple sandboxes raises an error at the SDK
    /// boundary before the recording is built.
    pub create: SandboxCreate,
    /// Subsequent operations in declaration order.
    pub ops: Vec<RecordedOp>,
}

/// The `Sandbox.create(source, ...)` kwargs as recorded.
///
/// Every field maps directly to an `App` field in the lowered
/// `Workload`. Exactly one of `template` or `image` must be present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCreate {
    /// Well-known base image template id (`python-3.12`, `node-22`,
    /// `minimal`, …). See [`resolve_base_image`] for the v1 list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Digest-pinned OCI image reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, EnvValue>,
    /// Source directories to bundle into the rootfs at `/app/<dir>`.
    /// Mirrors `@mvm.app(include=[...])`. Empty list = bundle the
    /// script's parent dir only.
    #[serde(default)]
    pub include: Vec<String>,
    /// Best-effort metadata (e.g. `tags={"job":"etl"}`). Currently
    /// unused by the lowering but preserved through the recording so
    /// tooling can surface it.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// Lifetime hint propagated from `Sandbox.create(ttl=...)`. v1
    /// does not lower this into the IR (the orchestrator owns TTL);
    /// kept here for parity with the language SDK surface and the
    /// "orphan microVM cleanup" mitigation in the plan's
    /// considerations section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Declared resource budget. Defaults to a 1-CPU / 256-MiB /
    /// 512-MiB-rootfs frame if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
}

/// One recorded `Sandbox` method call.
///
/// `kind` is the internal tag — matches every other internally-tagged
/// enum in the IR (`Image`, `Source`, `HookCmd`, …) so the JSON wire
/// shape is uniform across the recording and the IR.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordedOp {
    /// `sb.commands.start(argv, env=...)` — argv is literal-checked
    /// at the language-SDK boundary. The *final* `CommandStart` in
    /// the recording becomes the workload's entrypoint; earlier ones
    /// become `before_start` hooks.
    CommandStart {
        argv: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, EnvValue>,
    },
    /// `sb.files.write(path, bytes)` — bytes are base64-encoded so
    /// the recording is plain JSON-safe and binary-safe at the same
    /// time. Lowered into an `App.files` entry baked into the rootfs
    /// at build time; the path and payload are pure data, never
    /// interpolated into a shell line.
    FilesWrite {
        path: String,
        /// Base64 (standard alphabet, with `=` padding) of the
        /// literal bytes the script wrote.
        bytes_b64: String,
    },
    /// `sb.kill()` — dropped at lower time. The microVM's TTL is the
    /// orchestrator's job, not the recording's.
    Kill,
}

// ────────────────────────────────────────────────────────────────────
// Base image registry.
// ────────────────────────────────────────────────────────────────────

/// Resolve a base image template name to an [`Image`]. v1 ships with
/// the small closed list called out in the plan's
/// "Well-known base-image trust" consideration. Unknown names fail
/// closed (`LowerError::UnknownBaseImage`); user-defined bases via
/// `mvmctl image push <template>` are explicitly out of scope for v1.
///
/// Update [`KNOWN_BASE_IMAGES`] when adding entries — both the array
/// and the match below need to stay in sync.
pub fn resolve_base_image(template: &str) -> Result<Image, LowerError> {
    let packages: &[&str] = match template {
        "python-3.12" => &["python312"],
        "python-3.13" => &["python313"],
        "node-22" => &["nodejs_22"],
        "node-lts" => &["nodejs"],
        "minimal" => &["bash", "coreutils"],
        _ => return Err(LowerError::UnknownBaseImage(template.to_string())),
    };
    Ok(Image::NixPackages {
        packages: packages.iter().map(|s| (*s).to_string()).collect(),
    })
}

/// Closed, hand-curated list of known base-image templates. Exposed
/// so `mvmctl doctor` / SDK error messages can render an actionable
/// list when a user mistypes a template name.
pub const KNOWN_BASE_IMAGES: &[&str] = &[
    "python-3.12",
    "python-3.13",
    "node-22",
    "node-lts",
    "minimal",
];

// ────────────────────────────────────────────────────────────────────
// Lowering — recording → Workload.
// ────────────────────────────────────────────────────────────────────

/// Errors surfaced by [`compile_recording`].
#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    #[error(
        "runtime recording must contain exactly one non-empty boot source: `template` or `image`"
    )]
    InvalidBootSource,
    #[error("OCI image source `{0}` must be pinned as <reference>@sha256:<64 lowercase hex>")]
    InvalidImageSource(String),
    #[error(
        "unknown base image template `{0}` — known templates: python-3.12, python-3.13, node-22, node-lts, minimal"
    )]
    UnknownBaseImage(String),
    #[error(
        "runtime recording has no `Sandbox.commands.start(...)` call — at least one is required so the workload has an entrypoint"
    )]
    NoEntrypoint,
    #[error("FilesWrite recording carries malformed base64 for path `{path}`: {error}")]
    InvalidFilesWriteB64 {
        path: String,
        error: base64::DecodeError,
    },
    #[error("recording has {count} ops, max {max} — a runaway or adversarial trace, not a script")]
    TooManyOps { count: usize, max: usize },
    #[error(
        "FilesWrite for `{path}` decodes to {decoded} bytes, max {max} — ship large assets via the source bundle, not the trace"
    )]
    FilesWriteTooLarge {
        path: String,
        decoded: usize,
        max: usize,
    },
    #[error(
        "recording writes `{path}` more than once — ambiguous in a declarative scaffold; make the script write each file once"
    )]
    DuplicateFilesWritePath { path: String },
    #[error(
        "recording digest mismatch: expected {expected}, got {actual} — the bytes changed between capture and use"
    )]
    DigestMismatch { expected: String, actual: String },
}

fn resolve_recorded_image(create: &SandboxCreate) -> Result<Image, LowerError> {
    match (&create.template, &create.image) {
        (Some(template), None) if !template.is_empty() => resolve_base_image(template),
        (None, Some(image)) if !image.is_empty() => {
            let Some((reference, hex_digest)) = image.rsplit_once("@sha256:") else {
                return Err(LowerError::InvalidImageSource(image.clone()));
            };
            if reference.is_empty()
                || hex_digest.len() != 64
                || !hex_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(LowerError::InvalidImageSource(image.clone()));
            }
            Ok(Image::OciBase {
                reference: reference.to_string(),
                digest: format!("sha256:{hex_digest}"),
            })
        }
        _ => Err(LowerError::InvalidBootSource),
    }
}

/// One place the trace replay knowingly differs from what the
/// recorded script actually did. Findings do not block lowering —
/// they block *admission* unless explicitly acknowledged, because
/// a preview that ran one way and a ship that behaves another is
/// exactly the dishonesty the promotion gate exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// A `sb.kill()` was recorded and dropped: the replayed
    /// workload's lifetime is the orchestrator's TTL, not the
    /// script's explicit kill point.
    KillDropped { op_index: usize },
    /// The script wrote this file after starting the entrypoint;
    /// the replay writes it before boot. Anything the entrypoint
    /// did before the write existed will behave differently.
    FilesWriteAfterEntrypoint { op_index: usize, path: String },
}

impl Divergence {
    /// Stable slug used by `--ack-divergence` to acknowledge a
    /// finding class. Kept kebab-case to read naturally on a CLI.
    pub fn kind_slug(&self) -> &'static str {
        match self {
            Self::KillDropped { .. } => "kill-dropped",
            Self::FilesWriteAfterEntrypoint { .. } => "files-write-after-entrypoint",
        }
    }
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillDropped { op_index } => write!(
                f,
                "[kill-dropped] op #{op_index}: sb.kill() is dropped — replay lifetime is the orchestrator's TTL"
            ),
            Self::FilesWriteAfterEntrypoint { op_index, path } => write!(
                f,
                "[files-write-after-entrypoint] op #{op_index}: `{path}` was written after start; replay writes it before boot"
            ),
        }
    }
}

/// SHA-256 of the raw recording bytes, lowercase hex. Captured the
/// moment the recording is read; verified again wherever the bytes
/// cross a tamperable boundary (a file at rest between record and
/// ship is exactly that boundary).
pub fn recording_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Refuse recording bytes whose digest does not match the expected
/// hex (case-insensitive). Fail-closed: a mismatch means the bytes
/// changed between capture and use.
pub fn verify_recording_digest(bytes: &[u8], expected_hex: &str) -> Result<(), LowerError> {
    let actual = recording_sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected_hex) {
        return Err(LowerError::DigestMismatch {
            expected: expected_hex.to_ascii_lowercase(),
            actual,
        });
    }
    Ok(())
}

/// Lower a [`RuntimeRecording`] into a `Workload`, collecting
/// divergence findings in the process.
///
/// The exact shape is documented at the top of the module. In one
/// line: the *final* `CommandStart` is the entrypoint, every prior
/// `CommandStart` becomes a `before_start` hook in declaration order,
/// `FilesWrite` ops populate `App.files` (baked at build time, never
/// a shell hook), and `Kill` ops are dropped (emitting a
/// [`Divergence::KillDropped`] finding). `FilesWrite` ops after the
/// final `CommandStart` emit [`Divergence::FilesWriteAfterEntrypoint`].
pub fn compile_recording_with_findings(
    rec: &RuntimeRecording,
) -> Result<(Workload, Vec<Divergence>), LowerError> {
    if rec.ops.len() > MAX_RECORDED_OPS {
        return Err(LowerError::TooManyOps {
            count: rec.ops.len(),
            max: MAX_RECORDED_OPS,
        });
    }
    let mut seen_paths = std::collections::BTreeSet::new();
    for op in &rec.ops {
        // nested rather than a let-chain: let-chains need Rust 1.88, MSRV is 1.85
        #[allow(clippy::collapsible_if)]
        if let RecordedOp::FilesWrite { path, .. } = op {
            if !seen_paths.insert(path.clone()) {
                return Err(LowerError::DuplicateFilesWritePath { path: path.clone() });
            }
        }
    }

    let image = resolve_recorded_image(&rec.create)?;
    let resources = rec.create.resources.clone().unwrap_or(Resources {
        cpu_cores: 1,
        memory_mb: 256,
        rootfs_size_mb: 512,
    });

    let final_cmd_pos = rec
        .ops
        .iter()
        .rposition(|op| matches!(op, RecordedOp::CommandStart { .. }))
        .ok_or(LowerError::NoEntrypoint)?;

    // Walk every op: earlier CommandStart ops become before_start hooks;
    // FilesWrite ops go into materialized_files (baked at build time);
    // Kill ops are dropped. The final CommandStart is the entrypoint.
    let mut before_start: Vec<HookCmd> = Vec::new();
    let mut materialized_files: Vec<MaterializedFile> = Vec::new();
    let mut entrypoint: Option<Entrypoint> = None;
    let mut findings: Vec<Divergence> = Vec::new();

    for (idx, op) in rec.ops.iter().enumerate() {
        match op {
            RecordedOp::CommandStart { argv, env } => {
                if idx == final_cmd_pos {
                    entrypoint = Some(Entrypoint::Command {
                        command: argv.clone(),
                        working_dir: "/app".to_string(),
                        env: env.clone(),
                    });
                } else {
                    // Earlier commands fire as hooks. `Argv` keeps
                    // shell metacharacters from being interpreted —
                    // the recording is the argv exactly as the user
                    // typed it.
                    before_start.push(HookCmd::Argv { argv: argv.clone() });
                }
            }
            RecordedOp::FilesWrite { path, bytes_b64 } => {
                // Decode to validate the payload is well-formed STANDARD
                // base64 and within the size cap — fail closed at lower
                // time rather than baking a broken entry into the IR.
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(bytes_b64)
                    .map_err(|error| LowerError::InvalidFilesWriteB64 {
                        path: path.clone(),
                        error,
                    })?;
                if decoded.len() > MAX_FILES_WRITE_DECODED_BYTES {
                    return Err(LowerError::FilesWriteTooLarge {
                        path: path.clone(),
                        decoded: decoded.len(),
                        max: MAX_FILES_WRITE_DECODED_BYTES,
                    });
                }
                if idx > final_cmd_pos {
                    findings.push(Divergence::FilesWriteAfterEntrypoint {
                        op_index: idx,
                        path: path.clone(),
                    });
                }
                // Carry as a declarative IR entry — path and payload are
                // pure data, decoded by the Nix factory at build time.
                // No shell line is generated; no user-controlled bytes
                // reach a shell context at any point.
                materialized_files.push(MaterializedFile {
                    path: path.clone(),
                    bytes_b64: bytes_b64.clone(),
                    mode: None,
                });
            }
            RecordedOp::Kill => {
                // Dropped — the workload's lifetime is the orchestrator's
                // TTL, not the recording's kill point. Emit a finding so
                // the admission path can refuse unless acknowledged.
                findings.push(Divergence::KillDropped { op_index: idx });
            }
        }
    }

    let entrypoint = entrypoint.expect("final_cmd_pos guarantees one CommandStart maps here");

    let app = App {
        name: rec.workload_id.clone(),
        source: Source::LocalPath {
            path: ".".to_string(),
            include: if rec.create.include.is_empty() {
                vec!["**".to_string()]
            } else {
                rec.create.include.clone()
            },
            exclude: Vec::new(),
        },
        image,
        entrypoints: vec![entrypoint],
        env: rec.create.env.clone(),
        mounts: Vec::new(),
        network: rec.create.network.clone(),
        resources,
        dependencies: None,
        health_check: None,
        threat_tier: Default::default(),
        addons: Vec::new(),
        hooks: Hooks {
            before_build: Vec::new(),
            before_start,
            after_start: Vec::new(),
            before_stop: Vec::new(),
        },
        files: materialized_files,
    };

    Ok((
        Workload {
            schema_version: SCHEMA_VERSION.to_string(),
            id: rec.workload_id.clone(),
            apps: vec![app],
            volumes: Vec::new(),
            extensions: BTreeMap::new(),
        },
        findings,
    ))
}

/// Findings-agnostic wrapper kept for callers that only need the
/// Workload (tests, tooling). Admission paths use
/// [`compile_recording_with_findings`] and gate on the findings.
pub fn compile_recording(rec: &RuntimeRecording) -> Result<Workload, LowerError> {
    compile_recording_with_findings(rec).map(|(wl, _)| wl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    fn minimal_create(template: &str) -> SandboxCreate {
        SandboxCreate {
            template: Some(template.into()),
            image: None,
            env: BTreeMap::new(),
            include: Vec::new(),
            tags: BTreeMap::new(),
            ttl_seconds: None,
            resources: None,
            network: None,
        }
    }

    #[test]
    fn known_templates_resolve() {
        for tmpl in KNOWN_BASE_IMAGES {
            resolve_base_image(tmpl).unwrap_or_else(|e| panic!("{tmpl}: {e}"));
        }
    }

    #[test]
    fn unknown_template_fails_closed() {
        let err = resolve_base_image("python-2.7").unwrap_err();
        match err {
            LowerError::UnknownBaseImage(t) => assert_eq!(t, "python-2.7"),
            other => panic!("expected UnknownBaseImage, got {other:?}"),
        }
    }

    #[test]
    fn digest_pinned_oci_source_lowers() {
        let mut create = minimal_create("minimal");
        create.template = None;
        create.image = Some(format!(
            "docker.io/example/browser@sha256:{}",
            "a".repeat(64)
        ));
        let rec = RuntimeRecording {
            workload_id: "browser".into(),
            create,
            ops: vec![RecordedOp::CommandStart {
                argv: vec!["/browser".into()],
                env: BTreeMap::new(),
            }],
        };
        let workload = compile_recording(&rec).expect("pinned OCI image must lower");
        assert_eq!(
            workload.apps[0].image,
            Image::OciBase {
                reference: "docker.io/example/browser".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
            }
        );
    }

    #[test]
    fn mutable_oci_source_fails_closed() {
        let mut create = minimal_create("minimal");
        create.template = None;
        create.image = Some("docker.io/example/browser:latest".into());
        let rec = RuntimeRecording {
            workload_id: "browser".into(),
            create,
            ops: vec![RecordedOp::CommandStart {
                argv: vec!["/browser".into()],
                env: BTreeMap::new(),
            }],
        };
        assert!(matches!(
            compile_recording(&rec),
            Err(LowerError::InvalidImageSource(_))
        ));
    }

    #[test]
    fn missing_or_conflicting_boot_sources_fail_closed() {
        let mut missing = minimal_create("minimal");
        missing.template = None;
        let mut conflicting = minimal_create("minimal");
        conflicting.image = Some(format!(
            "docker.io/example/browser@sha256:{}",
            "a".repeat(64)
        ));
        for create in [missing, conflicting] {
            let rec = RuntimeRecording {
                workload_id: "browser".into(),
                create,
                ops: vec![RecordedOp::CommandStart {
                    argv: vec!["/browser".into()],
                    env: BTreeMap::new(),
                }],
            };
            assert!(matches!(
                compile_recording(&rec),
                Err(LowerError::InvalidBootSource)
            ));
        }
    }

    #[test]
    fn no_entrypoint_recording_fails_closed() {
        let rec = RuntimeRecording {
            workload_id: "no-cmd".into(),
            create: minimal_create("python-3.12"),
            ops: vec![RecordedOp::Kill],
        };
        let err = compile_recording(&rec).unwrap_err();
        assert!(matches!(err, LowerError::NoEntrypoint));
    }

    #[test]
    fn final_command_becomes_entrypoint() {
        let rec = RuntimeRecording {
            workload_id: "etl".into(),
            create: minimal_create("python-3.12"),
            ops: vec![
                RecordedOp::CommandStart {
                    argv: vec!["python".into(), "setup.py".into()],
                    env: BTreeMap::new(),
                },
                RecordedOp::CommandStart {
                    argv: vec!["python".into(), "process.py".into()],
                    env: BTreeMap::new(),
                },
            ],
        };
        let wl = compile_recording(&rec).unwrap();
        let app = &wl.apps[0];
        match &app.entrypoints[0] {
            Entrypoint::Command { command, .. } => {
                assert_eq!(command, &vec!["python".to_string(), "process.py".into()]);
            }
            _ => panic!("expected Command entrypoint"),
        }
        // The earlier setup.py becomes a before_start argv hook.
        assert_eq!(app.hooks.before_start.len(), 1);
        match &app.hooks.before_start[0] {
            HookCmd::Argv { argv } => {
                assert_eq!(argv, &vec!["python".to_string(), "setup.py".into()]);
            }
            other => panic!("expected Argv hook, got {other:?}"),
        }
    }

    #[test]
    fn files_write_lowers_to_materialized_file_not_a_hook() {
        let ops = vec![write_op("/app/conf.toml", b"a=1"), start_op(&["/bin/true"])];
        let wl = compile_recording(&rec_with_ops(ops)).expect("must lower");
        let app = &wl.apps[0];
        // No before_start hook is emitted for FilesWrite anymore.
        assert!(
            app.hooks.before_start.is_empty(),
            "FilesWrite must not produce a hook"
        );
        assert_eq!(app.files.len(), 1);
        assert_eq!(app.files[0].path, "/app/conf.toml");
        assert_eq!(
            app.files[0].bytes_b64,
            base64::engine::general_purpose::STANDARD.encode(b"a=1")
        );
    }

    #[test]
    fn files_write_hostile_path_is_carried_as_data_never_a_shell_line() {
        // The old hostile-path concern is gone: the path is a plain
        // data field, never interpolated into a shell command.
        let hostile = "/app/x'; rm -rf /tmp/pwn; echo '";
        let ops = vec![write_op(hostile, b"x"), start_op(&["/bin/true"])];
        let wl = compile_recording(&rec_with_ops(ops)).expect("must lower");
        assert!(wl.apps[0].hooks.before_start.is_empty());
        assert_eq!(wl.apps[0].files[0].path, hostile);
    }

    #[test]
    fn files_write_rejects_malformed_b64() {
        let rec = RuntimeRecording {
            workload_id: "bad".into(),
            create: minimal_create("python-3.12"),
            ops: vec![
                RecordedOp::FilesWrite {
                    path: "/etc/passwd".into(),
                    // `!` is not a valid base64 standard-alphabet char.
                    bytes_b64: "!!!!".into(),
                },
                RecordedOp::CommandStart {
                    argv: vec!["true".into()],
                    env: BTreeMap::new(),
                },
            ],
        };
        let err = compile_recording(&rec).unwrap_err();
        assert!(matches!(err, LowerError::InvalidFilesWriteB64 { .. }));
    }

    #[test]
    fn kill_ops_are_dropped() {
        let rec = RuntimeRecording {
            workload_id: "killing".into(),
            create: minimal_create("python-3.12"),
            ops: vec![
                RecordedOp::CommandStart {
                    argv: vec!["python".into(), "run.py".into()],
                    env: BTreeMap::new(),
                },
                RecordedOp::Kill,
                RecordedOp::Kill,
            ],
        };
        let wl = compile_recording(&rec).unwrap();
        let app = &wl.apps[0];
        assert!(app.hooks.before_start.is_empty());
        assert!(
            matches!(app.entrypoints[0], Entrypoint::Command { .. }),
            "kill ops shouldn't perturb entrypoint detection"
        );
    }

    #[test]
    fn create_kwargs_flow_through() {
        let mut env = BTreeMap::new();
        env.insert(
            "MODEL".to_string(),
            EnvValue::Literal {
                value: "/data/m.pt".into(),
            },
        );
        let rec = RuntimeRecording {
            workload_id: "etl".into(),
            create: SandboxCreate {
                template: Some("python-3.12".into()),
                image: None,
                env: env.clone(),
                include: vec!["src".into(), "lib".into()],
                tags: BTreeMap::new(),
                ttl_seconds: Some(1800),
                resources: Some(Resources {
                    cpu_cores: 2,
                    memory_mb: 512,
                    rootfs_size_mb: 1024,
                }),
                network: None,
            },
            ops: vec![RecordedOp::CommandStart {
                argv: vec!["python".into(), "run.py".into()],
                env: BTreeMap::new(),
            }],
        };
        let wl = compile_recording(&rec).unwrap();
        let app = &wl.apps[0];
        assert_eq!(app.env, env);
        match &app.source {
            Source::LocalPath { path, include, .. } => {
                assert_eq!(path, ".");
                assert_eq!(include, &vec!["src".to_string(), "lib".into()]);
            }
            other => panic!("expected LocalPath source, got {other:?}"),
        }
        assert_eq!(app.resources.cpu_cores, 2);
        assert_eq!(app.resources.memory_mb, 512);
    }

    #[test]
    fn default_resources_when_unspecified() {
        let rec = RuntimeRecording {
            workload_id: "etl".into(),
            create: minimal_create("python-3.12"),
            ops: vec![RecordedOp::CommandStart {
                argv: vec!["python".into(), "run.py".into()],
                env: BTreeMap::new(),
            }],
        };
        let wl = compile_recording(&rec).unwrap();
        let app = &wl.apps[0];
        assert_eq!(app.resources.cpu_cores, 1);
        assert_eq!(app.resources.memory_mb, 256);
        assert_eq!(app.resources.rootfs_size_mb, 512);
    }

    #[test]
    fn empty_include_defaults_to_glob_all() {
        let rec = RuntimeRecording {
            workload_id: "etl".into(),
            create: minimal_create("python-3.12"),
            ops: vec![RecordedOp::CommandStart {
                argv: vec!["python".into(), "run.py".into()],
                env: BTreeMap::new(),
            }],
        };
        let wl = compile_recording(&rec).unwrap();
        match &wl.apps[0].source {
            Source::LocalPath { include, .. } => assert_eq!(include, &vec!["**".to_string()]),
            other => panic!("expected LocalPath, got {other:?}"),
        }
    }

    fn start_op(argv: &[&str]) -> RecordedOp {
        RecordedOp::CommandStart {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
        }
    }

    fn write_op(path: &str, bytes: &[u8]) -> RecordedOp {
        RecordedOp::FilesWrite {
            path: path.to_string(),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    fn rec_with_ops(ops: Vec<RecordedOp>) -> RuntimeRecording {
        RuntimeRecording {
            workload_id: "wl-limits".to_string(),
            create: minimal_create("minimal"),
            ops,
        }
    }

    #[test]
    fn too_many_ops_refuses() {
        let mut ops: Vec<RecordedOp> = (0..MAX_RECORDED_OPS).map(|_| RecordedOp::Kill).collect();
        ops.push(start_op(&["/bin/true"]));
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(matches!(err, LowerError::TooManyOps { .. }), "got {err:?}");
    }

    #[test]
    fn op_count_at_limit_is_accepted() {
        let mut ops: Vec<RecordedOp> = (0..MAX_RECORDED_OPS - 1)
            .map(|_| RecordedOp::Kill)
            .collect();
        ops.push(start_op(&["/bin/true"]));
        assert_eq!(ops.len(), MAX_RECORDED_OPS);
        compile_recording(&rec_with_ops(ops)).expect("at-limit recording must lower");
    }

    #[test]
    fn files_write_oversize_refuses() {
        let big = vec![0u8; MAX_FILES_WRITE_DECODED_BYTES + 1];
        let ops = vec![write_op("/app/big.bin", &big), start_op(&["/bin/true"])];
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(
            matches!(err, LowerError::FilesWriteTooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn duplicate_files_write_path_refuses() {
        let ops = vec![
            write_op("/app/conf.toml", b"a = 1"),
            write_op("/app/conf.toml", b"a = 2"),
            start_op(&["/bin/true"]),
        ];
        let err = compile_recording(&rec_with_ops(ops)).unwrap_err();
        assert!(
            matches!(err, LowerError::DuplicateFilesWritePath { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn kill_op_yields_divergence_finding() {
        let ops = vec![start_op(&["/bin/true"]), RecordedOp::Kill];
        let (_, findings) =
            compile_recording_with_findings(&rec_with_ops(ops)).expect("must lower");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0],
            Divergence::KillDropped { op_index: 1 }
        ));
    }

    #[test]
    fn files_write_after_entrypoint_yields_divergence_finding() {
        // The script wrote this file AFTER starting the workload;
        // the replay materializes it BEFORE start. That reordering
        // is a real preview-vs-ship behavior difference.
        let ops = vec![
            start_op(&["/bin/server"]),
            write_op("/app/late.txt", b"late"),
        ];
        let (wl, findings) =
            compile_recording_with_findings(&rec_with_ops(ops)).expect("must lower");
        assert!(matches!(
            &findings[0],
            Divergence::FilesWriteAfterEntrypoint { op_index: 1, path } if path == "/app/late.txt"
        ));
        // The file is carried in app.files even when written after the entrypoint.
        assert_eq!(wl.apps[0].files.len(), 1);
        assert_eq!(wl.apps[0].files[0].path, "/app/late.txt");
        // No shell hook is produced.
        assert!(wl.apps[0].hooks.before_start.is_empty());
    }

    #[test]
    fn clean_recording_yields_no_findings() {
        let ops = vec![write_op("/app/a.txt", b"a"), start_op(&["/bin/true"])];
        let (_, findings) =
            compile_recording_with_findings(&rec_with_ops(ops)).expect("must lower");
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn compile_recording_is_findings_agnostic_back_compat() {
        let ops = vec![start_op(&["/bin/true"]), RecordedOp::Kill];
        let rec = rec_with_ops(ops);
        let plain = compile_recording(&rec).expect("plain must lower");
        let (with, _) = compile_recording_with_findings(&rec).expect("must lower");
        assert_eq!(
            plain, with,
            "the two entry points must produce identical Workloads"
        );
    }

    #[test]
    fn workload_round_trips_through_serde() {
        let rec = RuntimeRecording {
            workload_id: "etl".into(),
            create: minimal_create("python-3.12"),
            ops: vec![
                RecordedOp::FilesWrite {
                    path: "/app/payload.txt".into(),
                    bytes_b64: b64(b"hi"),
                },
                RecordedOp::CommandStart {
                    argv: vec!["python".into(), "run.py".into()],
                    env: BTreeMap::new(),
                },
            ],
        };
        let wl = compile_recording(&rec).unwrap();
        let json = serde_json::to_string(&wl).unwrap();
        let back: Workload = serde_json::from_str(&json).unwrap();
        assert_eq!(wl, back);
    }

    #[test]
    fn recording_rejects_unknown_op_kind() {
        // The wire format uses `kind` tagging; an unknown variant
        // must fail closed so a future SDK that emits a new op
        // can't silently bypass an older lower.
        let bad = serde_json::json!({"kind": "stat", "path": "/app/x"});
        let err = serde_json::from_value::<RecordedOp>(bad).unwrap_err();
        assert!(
            err.to_string().contains("stat") || err.to_string().contains("unknown"),
            "got: {err}"
        );
    }

    #[test]
    fn recording_digest_is_stable_64_hex() {
        let d = recording_sha256_hex(b"{}");
        assert_eq!(d.len(), 64);
        assert_eq!(d, recording_sha256_hex(b"{}"));
        assert_ne!(d, recording_sha256_hex(b"{} "));
    }

    #[test]
    fn digest_verify_match_passes_mismatch_refuses() {
        let bytes = b"some recording bytes";
        let good = recording_sha256_hex(bytes);
        verify_recording_digest(bytes, &good).expect("matching digest must pass");
        let err = verify_recording_digest(bytes, &recording_sha256_hex(b"other")).unwrap_err();
        assert!(
            matches!(err, LowerError::DigestMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn digest_verify_is_case_insensitive_on_expected() {
        let bytes = b"case test";
        let upper = recording_sha256_hex(bytes).to_uppercase();
        verify_recording_digest(bytes, &upper).expect("hex case must not matter");
    }
}
