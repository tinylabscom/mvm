//! `mvmctl watch` — rebuild a Workload IR when its inputs change.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use blake3::Hasher;
use clap::Args as ClapArgs;
use mvm_core::user_config::MvmConfig;
use mvm_protocol::ir::{Source, Workload, ir_hash};
use mvm_sdk::compile::compile;

use super::Cli;
use super::load_ir_json_workload;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Workload IR JSON path. `--from-ir` is accepted as an alternative.
    #[arg(value_name = "ENTRY")]
    pub entry: Option<String>,

    /// Read Workload IR from this JSON file.
    #[arg(long = "from-ir", value_name = "PATH")]
    pub from_ir: Option<PathBuf>,

    /// Output directory for the rebuilt compile artifact.
    #[arg(short = 'o', long = "out", value_name = "DIR", default_value = "./out")]
    pub out: PathBuf,

    /// Directory containing local source paths referenced by the workload.
    #[arg(long = "manifest-dir", value_name = "DIR")]
    pub manifest_dir: Option<PathBuf>,

    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 500, value_name = "MILLISECONDS")]
    pub interval_ms: u64,

    /// Build once and exit after the initial rebuild.
    #[arg(long)]
    pub once: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    validate_interval(args.interval_ms)?;
    let input = resolve_input(&args)?;
    let manifest_dir = args.manifest_dir.unwrap_or(resolve_manifest_dir(&input)?);
    let mut previous = None;

    loop {
        let workload = match load_workload(&input) {
            Ok(workload) => workload,
            Err(error) => {
                handle_watch_error(error, args.once, "watch input unavailable")?;
                std::thread::sleep(Duration::from_millis(args.interval_ms));
                continue;
            }
        };
        let state = match input_state(&workload, &manifest_dir, &args.out) {
            Ok(state) => state,
            Err(error) => {
                handle_watch_error(error, args.once, "watched input unavailable")?;
                std::thread::sleep(Duration::from_millis(args.interval_ms));
                continue;
            }
        };
        if previous.as_ref() != Some(&state) {
            let change = previous.as_ref().map_or("initial", |old| {
                match (
                    old.ir_hash != state.ir_hash,
                    old.inputs_blake3 != state.inputs_blake3,
                ) {
                    (true, true) => "ir+inputs",
                    (true, false) => "ir",
                    (false, true) => "inputs",
                    (false, false) => "unknown",
                }
            });
            let started = Instant::now();
            let compile_result = compile(&workload, &args.out, &manifest_dir)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("compiling watched workload to {}", args.out.display()));
            if let Err(error) = compile_result {
                handle_watch_error(error, args.once, "rebuild failed")?;
            } else {
                let compile_ms = started.elapsed().as_millis();
                eprintln!(
                    "rebuilt workload {} (change={change}, ir_hash {}, compile_ms={compile_ms})",
                    workload.id, state.ir_hash,
                );
            }
            previous = Some(state);
        } else {
            eprintln!(
                "unchanged workload {} (ir_hash {})",
                workload.id, state.ir_hash
            );
        }

        if args.once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(args.interval_ms));
    }
}

fn handle_watch_error(error: anyhow::Error, once: bool, context: &str) -> Result<()> {
    if once {
        return Err(error);
    }
    eprintln!("{context}: {error}; waiting for the next change");
    Ok(())
}

fn validate_interval(interval_ms: u64) -> Result<()> {
    if interval_ms == 0 {
        bail!("--interval-ms must be greater than zero");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InputState {
    ir_hash: String,
    inputs_blake3: String,
}

enum Input {
    Path(PathBuf),
}

fn resolve_input(args: &Args) -> Result<Input> {
    match (
        args.from_ir.as_ref(),
        args.entry
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        (Some(_), Some(_)) => bail!("--from-ir and the positional entry are mutually exclusive"),
        (Some(path), None) => Ok(Input::Path(path.clone())),
        (None, Some("-")) => {
            bail!("mvmctl watch requires a file-backed IR; stdin cannot be watched")
        }
        (None, Some(path)) => Ok(Input::Path(PathBuf::from(path))),
        (None, None) => bail!("missing entry: pass an IR JSON path or --from-ir <path>"),
    }
}

fn load_workload(input: &Input) -> Result<Workload> {
    match input {
        Input::Path(path) => load_ir_json_workload(Some(path), None),
    }
}

fn resolve_manifest_dir(input: &Input) -> Result<PathBuf> {
    match input {
        Input::Path(path) => Ok(path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))),
    }
}

fn input_state(workload: &Workload, manifest_dir: &Path, output: &Path) -> Result<InputState> {
    let ir_hash = ir_hash(workload).context("computing watched workload ir_hash")?;
    let roots = local_source_roots(workload, manifest_dir)?;
    let excluded = absolute_path(output)?;
    let inputs_blake3 = hash_inputs(&roots, &excluded)?;
    Ok(InputState {
        ir_hash,
        inputs_blake3,
    })
}

fn local_source_roots(workload: &Workload, manifest_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = BTreeSet::new();
    for app in &workload.apps {
        if let Source::LocalPath { path, .. } = &app.source {
            roots.insert(manifest_dir.join(path));
        } else {
            bail!(
                "mvmctl watch requires local_path sources; app {:?} is not file-backed",
                app.name
            );
        }
    }
    Ok(roots.into_iter().collect())
}

fn hash_inputs(roots: &[PathBuf], excluded: &Path) -> Result<String> {
    let mut hasher = Hasher::new();
    let mut files = Vec::new();
    for root in roots {
        collect_files(root, excluded, &mut files)?;
    }
    files.sort();
    for path in files {
        let relative = path.to_string_lossy();
        hasher.update(relative.as_bytes());
        hasher.update(&[0]);
        let mut file = fs::File::open(&path)
            .with_context(|| format!("opening watched input {}", path.display()))?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn collect_files(path: &Path, excluded: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let absolute = absolute_path(path)?;
    if absolute == excluded || absolute.starts_with(excluded) {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&absolute)
        .with_context(|| format!("reading watched input {}", absolute.display()))?;
    if metadata.is_file() {
        files.push(absolute);
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    let mut children = fs::read_dir(&absolute)
        .with_context(|| format!("reading watched input directory {}", absolute.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort();
    for child in children {
        if child.file_name().is_some_and(|name| name == ".git") {
            continue;
        }
        collect_files(&child, excluded, files)?;
    }
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Commands;
    use clap::Parser;
    use mvm_protocol::ir::{App, Entrypoint, Image, Resources};

    fn sample_workload() -> Workload {
        Workload {
            schema_version: "0.1".into(),
            id: "watch-test".into(),
            apps: vec![App {
                name: "app".into(),
                source: Source::LocalPath {
                    path: ".".into(),
                    include: vec!["**".into()],
                    exclude: vec![],
                },
                image: Image::NixPackages { packages: vec![] },
                entrypoints: vec![Entrypoint::Command {
                    command: vec!["/bin/true".into()],
                    working_dir: "/app".into(),
                    env: Default::default(),
                }],
                env: Default::default(),
                mounts: vec![],
                network: None,
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: None,
                threat_tier: Default::default(),
                addons: vec![],
                hooks: Default::default(),
                files: vec![],
                health_check: None,
            }],
            volumes: vec![],
            extensions: Default::default(),
        }
    }

    #[test]
    fn same_ir_and_inputs_are_a_noop_state() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("main.py"), b"print('hello')").unwrap();
        let mut workload = sample_workload();
        workload.apps[0].source = Source::LocalPath {
            path: "src".into(),
            include: vec!["**".into()],
            exclude: vec![],
        };
        let a = input_state(&workload, tmp.path(), &tmp.path().join("out")).unwrap();
        let b = input_state(&workload, tmp.path(), &tmp.path().join("out")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn source_change_changes_input_state_without_changing_ir_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        fs::create_dir_all(&source).unwrap();
        let path = source.join("main.py");
        fs::write(&path, b"print('hello')").unwrap();
        let mut workload = sample_workload();
        workload.apps[0].source = Source::LocalPath {
            path: "src".into(),
            include: vec!["**".into()],
            exclude: vec![],
        };
        let before = input_state(&workload, tmp.path(), &tmp.path().join("out")).unwrap();
        fs::write(path, b"print('changed')").unwrap();
        let after = input_state(&workload, tmp.path(), &tmp.path().join("out")).unwrap();
        assert_eq!(before.ir_hash, after.ir_hash);
        assert_ne!(before.inputs_blake3, after.inputs_blake3);
    }

    #[test]
    fn non_local_sources_are_rejected_instead_of_being_treated_as_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let mut workload = sample_workload();
        workload.apps[0].source = Source::OciImage {
            reference: "example/app".into(),
            digest: "sha256:deadbeef".into(),
        };
        assert!(input_state(&workload, tmp.path(), &tmp.path().join("out")).is_err());
    }

    #[test]
    fn one_shot_watch_writes_a_compile_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("main.py"), b"print('hello')").unwrap();
        let ir_path = tmp.path().join("workload.json");
        fs::write(
            &ir_path,
            serde_json::to_vec(&sample_workload()).expect("sample workload serializes"),
        )
        .unwrap();
        let output = tmp.path().join("out");
        let cli = Cli::try_parse_from([
            "mvmctl",
            "watch",
            "--from-ir",
            ir_path.to_str().expect("temporary path is UTF-8"),
            "--out",
            output.to_str().expect("temporary path is UTF-8"),
            "--manifest-dir",
            tmp.path().to_str().expect("temporary path is UTF-8"),
            "--once",
        ])
        .expect("watch CLI parses");
        let Commands::Watch(args) = cli.command.clone() else {
            panic!("expected watch command")
        };
        run(&cli, args, &MvmConfig::default()).expect("one-shot watch compiles");
        assert!(output.join("launch.json").is_file());
        assert!(output.join("workload.json").is_file());
    }

    #[test]
    fn stdin_is_rejected_because_it_cannot_be_watched() {
        let args = Args {
            entry: Some("-".into()),
            from_ir: None,
            out: PathBuf::from("out"),
            manifest_dir: None,
            interval_ms: 500,
            once: true,
        };
        assert!(resolve_input(&args).is_err());
    }

    #[test]
    fn zero_poll_interval_is_rejected() {
        assert!(validate_interval(0).is_err());
        assert!(validate_interval(1).is_ok());
    }

    #[test]
    fn long_running_watch_recovers_from_transient_errors() {
        assert!(handle_watch_error(anyhow::anyhow!("broken input"), false, "watch").is_ok());
        assert!(handle_watch_error(anyhow::anyhow!("broken input"), true, "watch").is_err());
    }
}
