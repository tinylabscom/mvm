//! `mvmctl deploy` — compile a workload and ship it to mvmd.
//!
//! v1 stub end: takes the same `<entry>` shapes as `mvmctl compile`
//! (Python `.py` / TypeScript `.ts*` decorator script, IR JSON path,
//! or stdin), builds the single signed archive (compile output +
//! embedded `mvmd-spec.json` per mvmd ADR-0020), and calls
//! `MvmdClient::ship`. The stub logs the archive and exits 0; the
//! real HTTP client lands with mvmd Plan 48 Phase 1090.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;
use mvm_ir::Workload;
use mvm_sdk::decorator::{parse_python, parse_typescript};
use mvm_sdk::deploy::{MvmdClient, build_deploy_bundle};

use super::Cli;

/// Default mvmd endpoint when `--target` is not given. The stub
/// client ignores the value but echoes it back so users can see what
/// the real client would hit.
const DEFAULT_TARGET: &str = "https://mvmd.local/v1";

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

    /// Output archive path. Defaults to `./out/<workload>.tar.gz`.
    /// Must end in `.tar.gz` or `.tgz` — deploy always produces a
    /// single signable archive.
    #[arg(short = 'o', long = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// mvmd endpoint URL. v1 stub ignores this and only logs.
    #[arg(long = "target", value_name = "URL", default_value = DEFAULT_TARGET)]
    pub target: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let workload = load_workload(&args)?;
    let manifest_dir = resolve_manifest_dir(&args)?;
    let archive = resolve_archive_path(&args, &workload);
    if !is_archive_suffix(&archive) {
        bail!(
            "deploy --out must end in .tar.gz or .tgz (got {}). mvmd \
             receives one signed archive; a directory output would \
             break the body-hash idempotency contract (mvmd ADR-0020).",
            archive.display()
        );
    }

    if let Some(parent) = archive.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating archive parent dir {}", parent.display()))?;
    }

    let bundle = build_deploy_bundle(&workload, &archive, &manifest_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("building deploy bundle for {}", workload.id))?;

    let client = MvmdClient::new(args.target);
    client
        .ship(&bundle)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("shipping deploy bundle to mvmd")?;
    Ok(())
}

fn load_workload(args: &Args) -> Result<Workload> {
    let source = workload_source(args)?;
    match source {
        WorkloadSource::IrJsonPath(p) => {
            let bytes = std::fs::read(&p)
                .with_context(|| format!("reading IR JSON from {}", p.display()))?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing IR JSON from {}", p.display()))
        }
        WorkloadSource::IrJsonStdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading IR JSON from stdin")?;
            serde_json::from_slice(&buf).context("parsing IR JSON from stdin")
        }
        WorkloadSource::PythonScript(p) => {
            let bytes = std::fs::read(&p)
                .with_context(|| format!("reading decorator script {}", p.display()))?;
            parse_python(&bytes, &p)
                .map(|(w, _)| w)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| format!("parsing @mvm.app decorator in {}", p.display()))
        }
        WorkloadSource::TypeScriptScript(p) => {
            let bytes = std::fs::read(&p)
                .with_context(|| format!("reading decorator script {}", p.display()))?;
            parse_typescript(&bytes, &p)
                .map(|(w, _)| w)
                .map_err(|e| anyhow::anyhow!("{e}"))
                .with_context(|| {
                    format!("parsing mvm.app({{...}})(fn) decorator in {}", p.display())
                })
        }
        WorkloadSource::UnknownScript(p) => bail!(
            "unknown entry extension on {}; pass `--from-ir <path>` for IR JSON, \
             or use a known script extension (`.py`, `.ts`, `.tsx`, `.mts`, `.cts`).",
            p.display()
        ),
    }
}

enum WorkloadSource {
    IrJsonPath(PathBuf),
    IrJsonStdin,
    PythonScript(PathBuf),
    TypeScriptScript(PathBuf),
    UnknownScript(PathBuf),
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
                Some("py") => Ok(WorkloadSource::PythonScript(p)),
                Some("ts") | Some("tsx") | Some("mts") | Some("cts") => {
                    Ok(WorkloadSource::TypeScriptScript(p))
                }
                _ => Ok(WorkloadSource::UnknownScript(p)),
            }
        }
    }
}

fn resolve_manifest_dir(args: &Args) -> Result<PathBuf> {
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

fn resolve_archive_path(args: &Args, workload: &Workload) -> PathBuf {
    if let Some(p) = &args.out {
        return p.clone();
    }
    PathBuf::from("./out").join(format!("{}.tar.gz", workload.id))
}

fn is_archive_suffix(p: &Path) -> bool {
    let s = p.to_string_lossy().to_ascii_lowercase();
    s.ends_with(".tar.gz") || s.ends_with(".tgz")
}
