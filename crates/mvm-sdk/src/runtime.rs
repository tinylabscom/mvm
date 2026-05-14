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
//! - [`RecordedOp::FilesWrite`] ops become `before_start` hooks
//!   that base64-decode the recorded bytes into the declared path.
//!   Binary-safe.
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

use mvm_ir::{
    App, Entrypoint, EnvValue, HookCmd, Hooks, Image, Network, Resources, Source, Workload,
};

const SCHEMA_VERSION: &str = "0.1";

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

/// The `Sandbox.create(template, ...)` kwargs as recorded.
///
/// Every field maps directly to an `App` field in the lowered
/// `Workload`. `template` resolves to an `Image` via
/// [`resolve_base_image`]; the rest are passed through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxCreate {
    /// Well-known base image template id (`python-3.12`, `node-22`,
    /// `minimal`, …). See [`resolve_base_image`] for the v1 list.
    pub template: String,
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
    /// time. Lowered into a `before_start` hook that re-emits the
    /// file with `base64 -d`.
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
pub const KNOWN_BASE_IMAGES: &[&str] =
    &["python-3.12", "python-3.13", "node-22", "node-lts", "minimal"];

// ────────────────────────────────────────────────────────────────────
// Lowering — recording → Workload.
// ────────────────────────────────────────────────────────────────────

/// Errors surfaced by [`compile_recording`].
#[derive(Debug, thiserror::Error)]
pub enum LowerError {
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
}

/// Lower a [`RuntimeRecording`] into a `Workload`.
///
/// The exact shape is documented at the top of the module. In one
/// line: the *final* `CommandStart` is the entrypoint, every prior
/// `CommandStart` and `FilesWrite` becomes a `before_start` hook in
/// declaration order, and `Kill` ops are dropped.
pub fn compile_recording(rec: &RuntimeRecording) -> Result<Workload, LowerError> {
    let image = resolve_base_image(&rec.create.template)?;
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

    // Walk every op, building `before_start` hooks for everything
    // *except* the final CommandStart (which becomes the entrypoint)
    // and any Kill ops. Earlier CommandStart ops become hooks in
    // declaration order so they fire before the entrypoint at boot.
    let mut before_start: Vec<HookCmd> = Vec::new();
    let mut entrypoint: Option<Entrypoint> = None;

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
                // Sanity-check the encoding now so a malformed
                // recording fails closed at lower time rather than
                // baking a broken hook into the rootfs.
                base64::engine::general_purpose::STANDARD
                    .decode(bytes_b64)
                    .map_err(|error| LowerError::InvalidFilesWriteB64 {
                        path: path.clone(),
                        error,
                    })?;
                // Emit a shell hook that pipes the base64 string
                // through `base64 -d` into the destination. Single
                // quotes around the b64 token are safe — the
                // standard alphabet contains no `'` characters.
                let line = format!(
                    "mkdir -p \"$(dirname {path})\" && printf '%s' '{b64}' | base64 -d > {path}",
                    path = shell_single_quote(path),
                    b64 = bytes_b64,
                );
                before_start.push(HookCmd::Shell { line });
            }
            RecordedOp::Kill => {
                // Dropped — see lower-error doc + module doc for the
                // TTL/orchestrator rationale.
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
        threat_tier: Default::default(),
        addons: Vec::new(),
        hooks: Hooks {
            before_build: Vec::new(),
            before_start,
            after_start: Vec::new(),
            before_stop: Vec::new(),
        },
    };

    Ok(Workload {
        schema_version: SCHEMA_VERSION.to_string(),
        id: rec.workload_id.clone(),
        apps: vec![app],
        volumes: Vec::new(),
        extensions: BTreeMap::new(),
    })
}

/// Wrap `s` in single quotes for shell-safe interpolation, escaping
/// any single quotes inside. Use only when emitting shell lines for
/// `HookCmd::Shell` — argv hooks don't need it.
fn shell_single_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
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
            template: template.into(),
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
    fn files_write_becomes_base64_shell_hook() {
        let rec = RuntimeRecording {
            workload_id: "files".into(),
            create: minimal_create("python-3.12"),
            ops: vec![
                RecordedOp::FilesWrite {
                    path: "/app/config.json".into(),
                    bytes_b64: b64(b"{\"hello\":\"world\"}\n"),
                },
                RecordedOp::CommandStart {
                    argv: vec!["python".into(), "run.py".into()],
                    env: BTreeMap::new(),
                },
            ],
        };
        let wl = compile_recording(&rec).unwrap();
        let app = &wl.apps[0];
        assert_eq!(app.hooks.before_start.len(), 1);
        match &app.hooks.before_start[0] {
            HookCmd::Shell { line } => {
                assert!(line.contains("base64 -d"), "got: {line}");
                assert!(line.contains("/app/config.json"), "got: {line}");
                assert!(line.contains(&b64(b"{\"hello\":\"world\"}\n")), "got: {line}");
                assert!(line.contains("mkdir -p"), "got: {line}");
            }
            other => panic!("expected Shell hook, got {other:?}"),
        }
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
                template: "python-3.12".into(),
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

    #[test]
    fn shell_single_quote_escapes_apostrophes() {
        assert_eq!(shell_single_quote("hello"), "'hello'");
        assert_eq!(shell_single_quote(""), "''");
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
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
}
