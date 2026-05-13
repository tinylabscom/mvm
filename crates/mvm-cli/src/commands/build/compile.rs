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

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, ValueEnum};

use mvm_core::user_config::MvmConfig;
use mvm_ir::Workload;
use mvm_sdk::compile::{compile, compile_archive, is_archive_output};
use mvm_sdk::decorator::parse_python;

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
        WorkloadSource::DecoratorScript(path) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading decorator script {}", path.display()))?;
            let (workload, _manifest) = parse_python(&bytes, &path)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("parsing @mvm.app decorator in {}", path.display()))?;
            Ok(workload)
        }
        WorkloadSource::RuntimeScript(path) => bail!(
            "runtime-script entry not yet supported (script = {}). \
             Lands in SDK-port Phase 7 (record-mode lowering). \
             For now, emit the IR JSON yourself and pass it via --from-ir.",
            path.display()
        ),
    }
}

enum WorkloadSource {
    IrJsonPath(PathBuf),
    IrJsonStdin,
    DecoratorScript(PathBuf),
    RuntimeScript(PathBuf),
}

fn workload_source(args: &Args) -> Result<WorkloadSource> {
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
            "missing entry: pass a script path, an IR JSON path, `-` for stdin, or use `--from-ir <path>`."
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
                     for IR JSON, or use a known script extension (`.py`, `.ts`, ...).",
                    p.display()
                ),
            }
        }
    }
}

fn resolve_manifest_dir(args: &Args) -> Result<PathBuf> {
    // `manifest_dir` is the base for resolving `app.source.path`. For an
    // IR-JSON path, default to the file's containing directory. For
    // stdin, default to cwd. Decorator/runtime scripts (when wired)
    // resolve relative to the script's directory.
    let basis: PathBuf = if let Some(p) = &args.from_ir {
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
