//! `mvmctl build compile` — Workload IR to staged build artifacts.
//!
//! Renders `flake.nix`, `launch.json`, and the bundled source tree
//! into `--out <dir>` (or a deterministic `.tar.gz`/`.tgz` archive when
//! the output path ends that way) from one of three sources:
//!
//! - A `.py` / `.ts` script carrying an `@mvm.app(...)` decorator: the
//!   parser walks the AST statically to derive the IR. The host never
//!   imports or runs the script.
//! - A pre-rendered IR JSON (`--from-ir <path>`, or `-` for stdin).
//! - A runtime recording (`--from-recording <path>`).
//!
//! A `.py`/`.ts`/`.js` script with no decorator is treated as a
//! `Sandbox`-shaped record-mode script and auto-executed to capture its
//! recording (see `auto_exec_record_script`).
//!
//! Flags:
//!
//! - `<entry>` — positional. A `.json` IR path, `-` for stdin, or a
//!   `.py` / `.ts` / `.js` script.
//! - `--from-ir <path>` — explicit IR-JSON path (alternative to the
//!   positional).
//! - `--out <path>` — output directory (or `.tar.gz`/`.tgz` archive).
//! - `--mode {live|plan|record}` — explicit mode form.
//! - `--dev` / `--prod` — verb-default aliases. For `compile`, `--prod`
//!   resolves to `--mode record` (the default); `--dev` is refused
//!   (use `mvmctl run` for the live transport).
//! - `MVM_SDK_MODE` — env-var override that supersedes flags.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};

use mvm_contract::ir::{Entrypoint, Workload};
use mvm_core::user_config::MvmConfig;
use mvm_sdk::compile::{compile, compile_archive, is_archive_output};
use mvm_sdk::decorator::{ParseError, parse_python, parse_typescript};

use super::Cli;
use super::ir_input::{IrJsonSource, read_ir_json_workload};
use super::sandbox_record::{
    LoadedRecording, ScriptLanguage, auto_exec_record_script, load_recording,
    script_language_from_path,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Entry — IR JSON path, `-` for stdin, or a `.py`/`.ts` script.
    /// When omitted, requires `--from-ir <path>`.
    #[arg(value_name = "ENTRY")]
    pub entry: Option<String>,

    /// Read the Workload IR from this JSON file (alternative to the
    /// positional entry).
    #[arg(long = "from-ir", value_name = "PATH")]
    pub from_ir: Option<PathBuf>,

    /// Read a runtime recording JSON (the wire shape emitted by the
    /// Python / TypeScript SDK's `mvm.emitRecordingJson()` /
    /// `mvm.emit_recording_json()`) from this path and lower it into
    /// a Workload before compile. Mutually exclusive with `--from-ir`
    /// and the positional entry.
    #[arg(
        long = "from-recording",
        value_name = "PATH",
        conflicts_with = "from_ir"
    )]
    pub from_recording: Option<PathBuf>,

    /// Expected SHA-256 (hex) of the recording file. Refuses a
    /// recording whose bytes changed since capture. Only meaningful
    /// with --from-recording.
    #[arg(long, value_name = "HEX64", requires = "from_recording")]
    pub recording_sha256: Option<String>,

    /// Output path. Directory by default; ending in `.tar.gz`/`.tgz`
    /// produces a deterministic archive.
    #[arg(
        short = 'o',
        long = "out",
        value_name = "PATH",
        default_value = "./out"
    )]
    pub out: PathBuf,

    /// Explicit mode. `record` is the default for `mvmctl build compile`.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<Mode>,

    /// Friendly alias — resolves to `--mode record` on `mvmctl build compile`.
    #[arg(long = "prod", conflicts_with_all = ["dev", "mode"])]
    pub prod: bool,

    /// Refused on `mvmctl build compile` — use `mvmctl run` for the live
    /// transport. Accepted only to surface the rejection clearly.
    #[arg(long = "dev", conflicts_with_all = ["prod", "mode"])]
    pub dev: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(in crate::commands) enum Mode {
    /// Live transport — `Sandbox` calls shell out to existing mvmctl
    /// verbs. Refused by `compile` (use `mvmctl run`).
    Live,
    /// Plan transport — synthesize one ExecutionPlan per `Sandbox`
    /// call. Not yet supported by `compile`.
    Plan,
    /// Record transport (default for `compile`) — capture `Sandbox`
    /// operations into a `RuntimeRecording` and lower to a Workload.
    Record,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let resolved_mode = resolve_mode(&args)?;
    if !matches!(resolved_mode, Mode::Record) {
        bail!(
            "mvmctl build compile only supports --mode record (alias --prod) in v1; \
             received {resolved_mode:?}. Use `mvmctl run` for live/plan modes \
             (lands in SDK-port Phase 7)."
        );
    }

    let loaded = load_workload(&args)?;
    let workload = loaded.workload;
    for finding in &loaded.findings {
        eprintln!("divergence: {finding}");
    }
    for sf in &loaded.secret_findings {
        eprintln!(
            "warning: embedded secret at {} [{}]",
            sf.location,
            sf.rules.join(", ")
        );
    }
    let manifest_dir = resolve_manifest_dir(&args)?;

    if is_archive_output(&args.out) {
        compile_archive(&workload, &args.out, &manifest_dir)
            .with_context(|| format!("compile to archive {}", args.out.display()))?;
        eprintln!("compiled archive: {}", args.out.display());
    } else {
        compile(&workload, &args.out, &manifest_dir)
            .with_context(|| format!("compile to directory {}", args.out.display()))?;
        eprintln!("compiled directory: {}", args.out.display());
    }
    warn_node_deps(&workload, &manifest_dir);
    Ok(())
}

/// Warn at compile time when a Node workload ships a `package.json` whose
/// dependencies the build won't install. The build-time bake is npm-only
/// (nixpkgs `importNpmLock`, which reads `package-lock.json` integrity
/// hashes — the only hash-free path); pnpm/yarn need a precomputed FOD hash
/// the host-side compile can't produce, so they route through the
/// sealed-volume builder path (not yet wired). Either gap is
/// silent today — the bundle just copies the source with no `node_modules` —
/// so a missing dep only surfaces as a runtime import failure. Make it loud.
fn warn_node_deps(workload: &Workload, manifest_dir: &Path) {
    let is_node = workload.apps.iter().any(|app| {
        app.entrypoints
            .iter()
            .any(|ep| matches!(ep, Entrypoint::Function { language, .. } if language == "node"))
    });
    if !is_node || !manifest_dir.join("package.json").is_file() {
        return;
    }
    // npm lockfile → the nix-native bake handles it; nothing to warn.
    if manifest_dir.join("package-lock.json").is_file() {
        return;
    }
    if let Some(lock) = ["pnpm-lock.yaml", "yarn.lock"]
        .into_iter()
        .find(|f| manifest_dir.join(f).is_file())
    {
        eprintln!(
            "[mvm] warning: {lock} detected, but the build-time bake is npm-only \
             (nixpkgs importNpmLock). pnpm/yarn dependencies are NOT baked into the image \
             — install them via the sealed-volume builder path (Plan 145 WS-A, not yet \
             wired). For a build-time bake today, use npm + package-lock.json."
        );
        return;
    }
    eprintln!(
        "[mvm] warning: package.json has no lockfile — dependencies will NOT be installed \
         and `node_modules` will be absent at runtime. Run `npm install` to generate \
         package-lock.json so the build bakes the dependency tree into the image."
    );
}

fn resolve_mode(args: &Args) -> Result<Mode> {
    if let Ok(env_mode) = std::env::var(mvm_sdk::env::MVM_SDK_MODE_ENV) {
        return parse_env_mode(&env_mode);
    }
    if args.dev {
        bail!(
            "--dev is refused on `mvmctl build compile` (it boots a live microVM, which is the \
             `mvmctl run` verb). Drop the flag, or run `mvmctl run --dev <script>` instead."
        );
    }
    if let Some(mode) = args.mode {
        return Ok(mode);
    }
    // `--prod` (or no flag at all) → default for compile.
    Ok(Mode::Record)
}

fn parse_env_mode(raw: &str) -> Result<Mode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "live" => Ok(Mode::Live),
        "plan" => Ok(Mode::Plan),
        "record" => Ok(Mode::Record),
        other => {
            bail!("MVM_SDK_MODE={other:?} is not recognized; expected one of: live, plan, record")
        }
    }
}

fn load_workload(args: &Args) -> Result<LoadedRecording> {
    let source = workload_source(args)?;
    match source {
        WorkloadSource::IrJsonPath(path) => {
            let workload = read_ir_json_workload(&IrJsonSource::Path(path))?;
            Ok(LoadedRecording {
                workload,
                findings: Vec::new(),
                digest_hex: String::new(),
                secret_findings: Vec::new(),
            })
        }
        WorkloadSource::IrJsonStdin => {
            let workload = read_ir_json_workload(&IrJsonSource::Stdin)?;
            Ok(LoadedRecording {
                workload,
                findings: Vec::new(),
                digest_hex: String::new(),
                secret_findings: Vec::new(),
            })
        }
        WorkloadSource::RecordingPath(path) => {
            load_recording(&path, args.recording_sha256.as_deref())
        }
        WorkloadSource::DecoratorScript(path) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading decorator script {}", path.display()))?;
            match parse_python(&bytes, &path) {
                Ok((workload, _manifest)) => Ok(LoadedRecording {
                    workload,
                    findings: Vec::new(),
                    digest_hex: String::new(),
                    secret_findings: Vec::new(),
                }),
                Err(ParseError::NoDecoratedFunction { .. }) => {
                    // No `@mvm.app`, so the script is record-mode.
                    // Auto-exec it on the host with
                    // `MVM_SDK_MODE=record` + `MVM_SDK_OUT_PATH`
                    // pointed at a tempfile; the SDK's atexit hook
                    // writes the recording there before the process
                    // exits, and we lower it the same way
                    // `--from-recording` does.
                    auto_exec_record_script(&path, ScriptLanguage::Python)
                }
                Err(e) => Err(anyhow::anyhow!("{e}"))
                    .with_context(|| format!("parsing @mvm.app decorator in {}", path.display())),
            }
        }
        WorkloadSource::RuntimeScript(path) => {
            // .ts / .tsx / .mts / .cts → first try the decorator parser
            // (mvm.app({...})(fn)); on NoDecoratedFunction, auto-exec
            // via tsx / bun / deno.
            // .js / .mjs / .cjs → Sandbox-shaped only; auto-exec via node.
            match script_language_from_path(&path) {
                Some(ScriptLanguage::TypeScript) => {
                    let bytes = std::fs::read(&path)
                        .with_context(|| format!("reading decorator script {}", path.display()))?;
                    match parse_typescript(&bytes, &path) {
                        Ok((workload, _manifest)) => Ok(LoadedRecording {
                            workload,
                            findings: Vec::new(),
                            digest_hex: String::new(),
                            secret_findings: Vec::new(),
                        }),
                        Err(ParseError::NoDecoratedFunction { .. }) => {
                            auto_exec_record_script(&path, ScriptLanguage::TypeScript)
                        }
                        Err(e) => Err(anyhow::anyhow!("{e}")).with_context(|| {
                            format!(
                                "parsing mvm.app({{...}})(fn) decorator in {}",
                                path.display()
                            )
                        }),
                    }
                }
                Some(ScriptLanguage::Node) => auto_exec_record_script(&path, ScriptLanguage::Node),
                Some(ScriptLanguage::Python) | None => {
                    bail!(no_decorator_runtime_message(&path))
                }
            }
        }
    }
}

/// Diagnostic the runtime-script + decorator-without-app paths share:
/// they both bottom out in "auto-execution of Sandbox-shaped scripts
/// is not yet wired; for now, emit the recording manually and pass
/// `--from-recording`."
fn no_decorator_runtime_message(path: &Path) -> String {
    format!(
        "no `@mvm.app(...)` decorator found in {script}, and automatic execution of \
         Sandbox-shaped record-mode scripts on the host is not yet wired (lands in \
         SDK-port Phase 7e after Plan 72 unblocks live transport). For now: \
         run the script with `MVM_SDK_MODE=record` yourself, capture the JSON output \
         of `mvm.emit_recording_json()` (Python) / `mvm.emitRecordingJson()` \
         (TypeScript), and pass it via `--from-recording <path>`.",
        script = path.display()
    )
}

enum WorkloadSource {
    IrJsonPath(PathBuf),
    IrJsonStdin,
    RecordingPath(PathBuf),
    DecoratorScript(PathBuf),
    RuntimeScript(PathBuf),
}

fn workload_source(args: &Args) -> Result<WorkloadSource> {
    if let Some(p) = &args.from_recording {
        if args.entry.as_deref().is_some_and(|s| !s.is_empty()) {
            bail!(
                "--from-recording and the positional entry are mutually exclusive — pass one or the other."
            );
        }
        return Ok(WorkloadSource::RecordingPath(p.clone()));
    }
    if let Some(p) = &args.from_ir {
        if args.entry.as_deref().is_some_and(|s| !s.is_empty()) {
            bail!(
                "--from-ir and the positional entry are mutually exclusive — pass one or the other."
            );
        }
        return Ok(WorkloadSource::IrJsonPath(p.clone()));
    }
    match args.entry.as_deref() {
        None => bail!(
            "missing entry: pass a script path, an IR JSON path, `-` for stdin, or use `--from-ir <path>` / `--from-recording <path>`."
        ),
        Some("-") => Ok(WorkloadSource::IrJsonStdin),
        Some(s) => {
            let p = PathBuf::from(s);
            match p.extension().and_then(|e| e.to_str()) {
                Some("json") => Ok(WorkloadSource::IrJsonPath(p)),
                Some("py") => Ok(WorkloadSource::DecoratorScript(p)),
                Some("ts") | Some("tsx") | Some("mts") | Some("cts") | Some("js") | Some("mjs")
                | Some("cjs") => Ok(WorkloadSource::RuntimeScript(p)),
                _ => bail!(
                    "could not infer entry kind from extension on {}; pass `--from-ir <path>` \
                     for IR JSON, `--from-recording <path>` for a runtime recording, \
                     or use a known script extension (`.py`, `.ts`, ...).",
                    p.display()
                ),
            }
        }
    }
}

fn resolve_manifest_dir(args: &Args) -> Result<PathBuf> {
    // `manifest_dir` is the base for resolving `app.source.path`. For an
    // IR-JSON / recording path, default to the file's containing
    // directory. For stdin, default to cwd. Decorator/runtime scripts
    // (when wired) resolve relative to the script's directory.
    let from_path = args.from_ir.as_ref().or(args.from_recording.as_ref());
    let basis: PathBuf = if let Some(p) = from_path {
        p.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        match args.entry.as_deref() {
            Some("-") | None => std::env::current_dir().context("getting cwd")?,
            Some(s) => PathBuf::from(s)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        }
    };
    Ok(basis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Args {
        Args {
            entry: Some("./foo.json".to_string()),
            from_ir: None,
            from_recording: None,
            recording_sha256: None,
            out: PathBuf::from("./out"),
            mode: None,
            prod: false,
            dev: false,
        }
    }

    #[test]
    fn resolve_mode_default_is_record() {
        let args = base_args();
        let mode = resolve_mode(&args).expect("default mode resolves");
        assert!(matches!(mode, Mode::Record));
    }

    #[test]
    fn resolve_mode_prod_resolves_to_record() {
        let mut args = base_args();
        args.prod = true;
        let mode = resolve_mode(&args).expect("--prod resolves to record");
        assert!(matches!(mode, Mode::Record));
    }

    #[test]
    fn resolve_mode_dev_is_refused_on_compile() {
        let mut args = base_args();
        args.dev = true;
        let err = resolve_mode(&args).expect_err("--dev must be refused on compile");
        let msg = err.to_string();
        assert!(msg.contains("--dev"));
        assert!(msg.contains("mvmctl run"));
    }
}
