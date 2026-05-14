//! `mvmctl compile` — Workload IR to staged build artifacts.
//!
//! v1 surface accepts a pre-rendered IR JSON (via `--from-ir <path>`
//! or `-` for stdin) and renders `flake.nix`, `launch.json`, and the
//! bundled source tree into `--out <dir>`. Output ending in `.tar.gz`
//! or `.tgz` is written as a deterministic archive instead.
//!
//! Decorator-script entry (parse `app.py` / `app.ts` to derive the
//! IR) lands with Phase 4 of the SDK port; runtime record-mode (parse
//! a `Sandbox`-shaped script) lands with Phase 7. v1 only handles the
//! IR-JSON path so the compile pipeline has an end-to-end smoke test
//! independent of the parser.
//!
//! Flag shapes follow the approved plan:
//!
//! - `<entry>` — positional. A `.json` path, `-` for stdin, or a
//!   `.py` / `.ts` script (rejected with a `not-yet-implemented`
//!   pointer to Phase 4/7 until those land).
//! - `--from-ir <path>` — explicit IR-JSON path (alternative to the
//!   positional).
//! - `--out <path>` — output directory (or `.tar.gz`/`.tgz` archive).
//! - `--mode {live|plan|record}` — explicit mode form.
//! - `--dev` / `--prod` — verb-default aliases. For `compile`, `--prod`
//!   resolves to `--mode record` (the default); `--dev` is refused
//!   (use `mvmctl run` for the live transport).
//! - `MVM_SDK_MODE` — env-var override that supersedes flags.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};

use mvm_core::user_config::MvmConfig;
use mvm_ir::Workload;
use mvm_sdk::compile::{compile, compile_archive, is_archive_output};
use mvm_sdk::decorator::{ParseError, parse_python, parse_typescript};
use mvm_sdk::runtime::{RuntimeRecording, compile_recording};

use super::Cli;

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
    #[arg(long = "from-recording", value_name = "PATH", conflicts_with = "from_ir")]
    pub from_recording: Option<PathBuf>,

    /// Output path. Directory by default; ending in `.tar.gz`/`.tgz`
    /// produces a deterministic archive.
    #[arg(
        short = 'o',
        long = "out",
        value_name = "PATH",
        default_value = "./out"
    )]
    pub out: PathBuf,

    /// Explicit mode. `record` is the default for `mvmctl compile`.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<Mode>,

    /// Friendly alias — resolves to `--mode record` on `mvmctl compile`.
    #[arg(long = "prod", conflicts_with_all = ["dev", "mode"])]
    pub prod: bool,

    /// Refused on `mvmctl compile` — use `mvmctl run` for the live
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
    /// call. Refused by `compile` until Phase 7.
    Plan,
    /// Record transport (default for `compile`) — capture `Sandbox`
    /// operations into a `RuntimeRecording` and lower to a Workload.
    Record,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let resolved_mode = resolve_mode(&args)?;
    if !matches!(resolved_mode, Mode::Record) {
        bail!(
            "mvmctl compile only supports --mode record (alias --prod) in v1; \
             received {resolved_mode:?}. Use `mvmctl run` for live/plan modes \
             (lands in SDK-port Phase 7)."
        );
    }

    let workload = load_workload(&args)?;
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
    Ok(())
}

fn resolve_mode(args: &Args) -> Result<Mode> {
    if let Ok(env_mode) = std::env::var("MVM_SDK_MODE") {
        return parse_env_mode(&env_mode);
    }
    if args.dev {
        bail!(
            "--dev is refused on `mvmctl compile` (it boots a live microVM, which is the \
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

fn load_workload(args: &Args) -> Result<Workload> {
    let source = workload_source(args)?;
    match source {
        WorkloadSource::IrJsonPath(path) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading IR JSON from {}", path.display()))?;
            let workload: Workload = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing IR JSON from {}", path.display()))?;
            Ok(workload)
        }
        WorkloadSource::IrJsonStdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading IR JSON from stdin")?;
            let workload: Workload =
                serde_json::from_slice(&buf).context("parsing IR JSON from stdin")?;
            Ok(workload)
        }
        WorkloadSource::RecordingPath(path) => load_recording(&path),
        WorkloadSource::DecoratorScript(path) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading decorator script {}", path.display()))?;
            match parse_python(&bytes, &path) {
                Ok((workload, _manifest)) => Ok(workload),
                Err(ParseError::NoDecoratedFunction { .. }) => {
                    // Phase 7e — no `@mvm.app`, so the script is
                    // record-mode. Auto-exec it on the host with
                    // `MVM_SDK_MODE=record` + `MVM_SDK_OUT_PATH`
                    // pointed at a tempfile; the SDK's atexit hook
                    // writes the recording there before the process
                    // exits, and we lower it the same way
                    // `--from-recording` does.
                    auto_exec_record_script(&path, ScriptLanguage::Python)
                }
                Err(e) => Err(anyhow::anyhow!("{e}")).with_context(|| {
                    format!("parsing @mvm.app decorator in {}", path.display())
                }),
            }
        }
        WorkloadSource::RuntimeScript(path) => {
            // .ts / .tsx / .mts / .cts → first try the decorator parser
            // (mvm.app({...})(fn)); on NoDecoratedFunction, auto-exec
            // via tsx / bun / deno.
            // .js / .mjs / .cjs → Sandbox-shaped only; auto-exec via node.
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "ts" | "tsx" | "mts" | "cts") {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("reading decorator script {}", path.display()))?;
                match parse_typescript(&bytes, &path) {
                    Ok((workload, _manifest)) => Ok(workload),
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
            } else if matches!(ext, "js" | "mjs" | "cjs") {
                auto_exec_record_script(&path, ScriptLanguage::Node)
            } else {
                bail!(no_decorator_runtime_message(&path))
            }
        }
    }
}

fn load_recording(path: &Path) -> Result<Workload> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading runtime recording from {}", path.display()))?;
    let recording: RuntimeRecording = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing runtime recording JSON from {}", path.display()))?;
    compile_recording(&recording)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("lowering runtime recording from {}", path.display()))
}

/// Languages the auto-exec path supports.
#[derive(Debug, Clone, Copy)]
enum ScriptLanguage {
    /// Python via `python3` (or `python`); Phase 7e.
    Python,
    /// Plain JavaScript via `node`; Phase 7f.
    Node,
    /// TypeScript via `tsx`, `bun`, or `deno`. The `node` binary
    /// alone can't run `.ts` files in mvm's supported Node range,
    /// so the CLI insists on a TS-aware runner. Phase 7f.
    TypeScript,
}

/// Phase 7e — run `<interpreter> <script>` on the host with
/// `MVM_SDK_MODE=record` and `MVM_SDK_OUT_PATH=<tempfile>`, then
/// load the recording the SDK's atexit hook wrote and lower it
/// to a Workload.
///
/// **Security**: this *runs the user's script on the host*. Per
/// S2 in the SDK plan, this is a deliberate departure from the
/// decorator path's "never executes user code on the host" rule;
/// `mvmctl compile <Sandbox-script>` is opt-in for that posture.
/// Users who don't want it can use the `@mvm.app` decorator path
/// instead (which the decorator parser handles statically).
fn auto_exec_record_script(script: &Path, lang: ScriptLanguage) -> Result<Workload> {
    let interpreter = resolve_interpreter(lang)?;
    let tmp = tempfile::Builder::new()
        .prefix("mvm-recording-")
        .suffix(".json")
        .tempfile()
        .context("creating tempfile for runtime recording capture")?;
    let out_path = tmp.path().to_path_buf();

    eprintln!(
        "running {} on the host with MVM_SDK_MODE=record (Phase 7e/7f auto-exec)",
        script.display()
    );

    let mut cmd = Command::new(&interpreter);
    // Deno's default sandbox refuses fs writes; the SDK's atexit
    // hook needs to write the recording, so opt out explicitly.
    let basename = interpreter
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if basename.starts_with("deno") {
        cmd.arg("run").arg("--allow-all");
    }
    let status = cmd
        .arg(script)
        .env("MVM_SDK_MODE", "record")
        .env("MVM_SDK_OUT_PATH", &out_path)
        .status()
        .with_context(|| {
            format!(
                "spawning {} to run record-mode script {}",
                interpreter.display(),
                script.display()
            )
        })?;
    if !status.success() {
        bail!(
            "record-mode script {} exited with {:?} (no Workload emitted). \
             Re-run it under {} with MVM_SDK_MODE=record to see the error.",
            script.display(),
            status.code(),
            interpreter.display()
        );
    }
    if !out_path.exists() {
        bail!(
            "record-mode script {} did not emit a recording. Confirm the \
             script imports `mvm` and calls `Sandbox.create(...)`; the SDK's \
             atexit hook writes the recording to MVM_SDK_OUT_PATH on process \
             exit, which only fires when a Sandbox was constructed.",
            script.display()
        );
    }
    load_recording(&out_path)
}

/// Resolve which interpreter to spawn for a given language. Each
/// language has a discrete env-var override (`MVM_PYTHON`, `MVM_NODE`,
/// `MVM_TSX`) so users with non-standard layouts can pin a binary
/// explicitly. The fallback search order is best-effort but explicit
/// in the error message when nothing is found.
fn resolve_interpreter(lang: ScriptLanguage) -> Result<PathBuf> {
    match lang {
        ScriptLanguage::Python => {
            if let Some(p) = env_override("MVM_PYTHON") {
                return Ok(p);
            }
            for candidate in ["python3", "python"] {
                if let Ok(found) = which::which(candidate) {
                    return Ok(found);
                }
            }
            bail!(
                "no Python interpreter found on PATH (tried `python3`, `python`). \
                 Install Python 3.10+ or set `MVM_PYTHON=<path>` and re-run."
            )
        }
        ScriptLanguage::Node => {
            if let Some(p) = env_override("MVM_NODE") {
                return Ok(p);
            }
            if let Ok(found) = which::which("node") {
                return Ok(found);
            }
            bail!(
                "no Node.js interpreter found on PATH (tried `node`). \
                 Install Node 20+ or set `MVM_NODE=<path>` and re-run."
            )
        }
        ScriptLanguage::TypeScript => {
            if let Some(p) = env_override("MVM_TSX") {
                return Ok(p);
            }
            for candidate in ["tsx", "bun", "deno"] {
                if let Ok(found) = which::which(candidate) {
                    return Ok(found);
                }
            }
            bail!(
                "no TypeScript runner found on PATH (tried `tsx`, `bun`, `deno`). \
                 Install one (e.g. `npm install -g tsx`) or set `MVM_TSX=<path>` \
                 and re-run."
            )
        }
    }
}

fn env_override(name: &str) -> Option<PathBuf> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// Diagnostic the runtime-script + decorator-without-app paths share:
/// they both bottom out in "auto-execution of Sandbox-shaped scripts
/// is Phase 7e; for now, emit the recording manually and pass
/// `--from-recording`."
fn no_decorator_runtime_message(path: &Path) -> String {
    format!(
        "no `@mvm.app(...)` decorator found in {script}, and automatic execution of \
         Sandbox-shaped record-mode scripts on the host is not yet wired (lands in \
         SDK-port Phase 7e after Plan 71 unblocks live transport). For now: \
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
