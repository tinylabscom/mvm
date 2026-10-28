//! `mvmctl pack lock` and `mvmctl pack compile` — resolve an authored pack
//! spec into a frozen lock, and compile only what a lock still describes.
//!
//! The spec is read as data: nothing here evaluates the author's Python or
//! TypeScript. Lowering and rendering go through the shared workload compiler.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;
use mvm_compiler::PinnedMvmRevision;
use mvm_contract::pack_lock::PackLock;
use mvm_contract::pack_spec::PackSpec;
use mvm_sdk::pack::{PackInput, compile_frozen, lock_pack};

/// File name a lock is written to beside its spec when no path is given.
pub(super) use mvm_sdk::pack::LOCK_FILE as DEFAULT_LOCK_FILE;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct LockArgs {
    /// The authored `mvm.pack-spec/v1` JSON document
    #[arg(value_name = "SPEC.json")]
    pub spec: PathBuf,
    /// Full 40-character mvm commit the generated flake will pin; it also
    /// pins the package set the pack's packages come from
    #[arg(long, value_name = "COMMIT")]
    pub mvm_revision: String,
    /// Where to write the lock (default: pack.lock.json beside the spec)
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Print the lock to stdout instead of writing it
    #[arg(long, conflicts_with = "out")]
    pub stdout: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct CompileArgs {
    /// The authored `mvm.pack-spec/v1` JSON document
    #[arg(value_name = "SPEC.json")]
    pub spec: PathBuf,
    /// The lock the build must match (default: pack.lock.json beside the spec)
    #[arg(long, value_name = "FILE")]
    pub lock: Option<PathBuf>,
    /// Directory the compiled flake artifact is written to
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
}

/// A spec read as data, with the directory its source path resolves against.
pub(super) struct LoadedSpec {
    pub spec: PackSpec,
    pub dir: PathBuf,
}

impl LoadedSpec {
    pub(super) fn read(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("reading pack spec {}", path.display()))?;
        let spec: PackSpec = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing pack spec {}", path.display()))?;
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok(Self { spec, dir })
    }

    pub(super) fn input<'a>(&'a self, revision: &'a PinnedMvmRevision) -> PackInput<'a> {
        PackInput {
            spec: &self.spec,
            spec_dir: &self.dir,
            revision,
        }
    }

    pub(super) fn default_lock_path(&self) -> PathBuf {
        self.dir.join(DEFAULT_LOCK_FILE)
    }
}

pub(super) fn read_lock(path: &Path) -> Result<PackLock> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "reading pack lock {} (create it with `mvmctl pack lock`)",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing pack lock {}", path.display()))
}

/// Pretty JSON with a trailing newline: a lock is meant to be committed and
/// reviewed beside the spec.
pub(super) fn render_lock(lock: &PackLock) -> Result<String> {
    let mut text = serde_json::to_string_pretty(lock).context("serializing pack lock")?;
    text.push('\n');
    Ok(text)
}

pub(super) fn parse_revision(value: &str) -> Result<PinnedMvmRevision> {
    PinnedMvmRevision::parse(value).map_err(|error| anyhow!(error))
}

/// The revision a lock pins, so a frozen compile renders against exactly it.
pub(super) fn locked_revision(lock: &PackLock) -> Result<PinnedMvmRevision> {
    parse_revision(&lock.compiler.mvm_revision)
}

pub(super) fn run_lock(args: LockArgs) -> Result<()> {
    let loaded = LoadedSpec::read(&args.spec)?;
    let revision = parse_revision(&args.mvm_revision)?;
    let lock = lock_pack(&loaded.input(&revision))
        .with_context(|| format!("locking pack spec {}", args.spec.display()))?;
    let text = render_lock(&lock)?;
    if args.stdout {
        print!("{text}");
        return Ok(());
    }
    let out = args.out.unwrap_or_else(|| loaded.default_lock_path());
    fs::write(&out, text).with_context(|| format!("writing pack lock {}", out.display()))?;
    eprintln!(
        "locked {}@{} -> {}",
        lock.identity.name,
        lock.identity.version,
        out.display()
    );
    Ok(())
}

pub(super) fn run_compile(args: CompileArgs) -> Result<()> {
    let loaded = LoadedSpec::read(&args.spec)?;
    let lock_path = args.lock.unwrap_or_else(|| loaded.default_lock_path());
    let lock = read_lock(&lock_path)?;
    let revision = locked_revision(&lock)?;
    compile_frozen(&loaded.input(&revision), &lock, &args.out).with_context(|| {
        format!(
            "compiling pack spec {} against {}",
            args.spec.display(),
            lock_path.display()
        )
    })?;
    eprintln!("compiled {} -> {}", args.spec.display(), args.out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const REVISION: &str = "4e65b221744885e536ec91a3f2948cdc508dcb49";

    fn write_pack(dir: &Path) -> PathBuf {
        fs::write(dir.join("hello.txt"), "hi\n").unwrap();
        let spec = serde_json::json!({
            "schema": "mvm.pack-spec/v1",
            "identity": { "name": "acme/hello", "version": "1.0.0" },
            "target": "aarch64-linux",
            "source": { "kind": "local", "path": "." },
            "packages": [{ "name": "busybox", "scope": "runtime" }],
            "dependencies": [],
            "copy": [{ "source": "hello.txt", "destination": "/app/hello.txt" }],
            "entrypoint": ["cat", "/app/hello.txt"],
            "resources": { "cpu_cores": 1, "memory_mb": 128 }
        });
        let path = dir.join("pack.json");
        fs::write(&path, serde_json::to_vec(&spec).unwrap()).unwrap();
        path
    }

    #[test]
    fn lock_then_compile_round_trips_through_the_default_lock_path() {
        let dir = TempDir::new().unwrap();
        let spec = write_pack(dir.path());
        run_lock(LockArgs {
            spec: spec.clone(),
            mvm_revision: REVISION.into(),
            out: None,
            stdout: false,
        })
        .unwrap();
        let written = fs::read_to_string(dir.path().join(DEFAULT_LOCK_FILE)).unwrap();
        assert!(written.ends_with('\n'));
        let lock: PackLock = serde_json::from_str(&written).unwrap();
        assert_eq!(lock.compiler.mvm_revision, REVISION);

        let out = dir.path().join("artifact");
        run_compile(CompileArgs {
            spec,
            lock: None,
            out: out.clone(),
        })
        .unwrap();
        assert!(out.join("flake.nix").is_file());
        assert_eq!(
            fs::read_to_string(out.join("src/hello.txt")).unwrap(),
            "hi\n"
        );
    }

    #[test]
    fn compile_without_a_lock_is_refused_and_names_the_fix() {
        let dir = TempDir::new().unwrap();
        let spec = write_pack(dir.path());
        let error = run_compile(CompileArgs {
            spec,
            lock: None,
            out: dir.path().join("artifact"),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("mvmctl pack lock"));
        assert!(!dir.path().join("artifact").exists());
    }

    #[test]
    fn compile_against_a_stale_lock_is_refused() {
        let dir = TempDir::new().unwrap();
        let spec = write_pack(dir.path());
        run_lock(LockArgs {
            spec: spec.clone(),
            mvm_revision: REVISION.into(),
            out: None,
            stdout: false,
        })
        .unwrap();
        fs::write(dir.path().join("hello.txt"), "changed\n").unwrap();
        let error = run_compile(CompileArgs {
            spec,
            lock: None,
            out: dir.path().join("artifact"),
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("source_tree_sha256"));
        assert!(!dir.path().join("artifact").exists());
    }

    #[test]
    fn a_short_revision_is_refused() {
        let dir = TempDir::new().unwrap();
        let spec = write_pack(dir.path());
        assert!(
            run_lock(LockArgs {
                spec,
                mvm_revision: "main".into(),
                out: None,
                stdout: false,
            })
            .is_err()
        );
    }
}
