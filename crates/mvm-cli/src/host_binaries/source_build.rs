use std::path::{Path, PathBuf};

use crate::host_binaries::embedded::EMBEDDED;
use crate::host_binaries::manifest::{HOST_BINARIES, SEED_BINARIES};

const SOURCE_BUILD_SEGMENT: &str = "source-checkout";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostBinaryBuildLayout {
    pub dir: PathBuf,
    pub target_dir: PathBuf,
}

impl HostBinaryBuildLayout {
    fn under(cache_root: &Path, version: &str, arch: &str) -> Self {
        let dir = cache_root
            .join(SOURCE_BUILD_SEGMENT)
            .join(version)
            .join(arch);
        let target_dir = cache_root
            .join(format!("{SOURCE_BUILD_SEGMENT}-target"))
            .join(version)
            .join(arch);
        Self { dir, target_dir }
    }

    fn path_for(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn is_complete(&self) -> bool {
        all_host_binary_names()
            .into_iter()
            .all(|name| self.path_for(name).is_file())
    }
}

#[derive(Debug)]
pub(crate) enum HostBinaryBuildError {
    NoSourceCheckout,

    BuildFailed { reason: String },

    OutputMissing(PathBuf),

    Io(std::io::Error),
}

impl std::fmt::Display for HostBinaryBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSourceCheckout => {
                write!(f, "this mvmctl was not built from a source checkout")
            }
            Self::BuildFailed { reason } => write!(f, "cargo-zigbuild failed: {reason}"),
            Self::OutputMissing(path) => {
                write!(
                    f,
                    "built host binary missing after zigbuild: {}",
                    path.display()
                )
            }
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for HostBinaryBuildError {}

impl From<std::io::Error> for HostBinaryBuildError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostBinaryBuildSpec {
    workspace_root: PathBuf,
    target_dir: PathBuf,
    target_triple: String,
    cargo: Option<PathBuf>,
}

impl HostBinaryBuildSpec {
    fn new(workspace_root: PathBuf, target_dir: PathBuf, target_triple: String) -> Self {
        Self {
            workspace_root,
            target_dir,
            target_triple,
            cargo: None,
        }
    }

    fn argv(&self) -> Vec<String> {
        let cargo = self
            .cargo
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "cargo".to_string());
        let mut argv = vec![
            cargo,
            "zigbuild".to_string(),
            "--release".to_string(),
            "--target".to_string(),
            self.target_triple.clone(),
            "-p".to_string(),
            "mvm-build".to_string(),
        ];
        for name in all_host_binary_names() {
            argv.push("--bin".to_string());
            argv.push(name.to_string());
        }
        argv
    }

    fn output_dir(&self) -> PathBuf {
        self.target_dir.join(&self.target_triple).join("release")
    }
}

pub(crate) fn has_source_checkout() -> bool {
    source_checkout_root().is_some()
}

pub(crate) fn resolve_or_build_host_binaries(
    cache_root: &Path,
) -> Result<PathBuf, HostBinaryBuildError> {
    let version = env!("CARGO_PKG_VERSION");
    let arch = host_arch();
    let layout = HostBinaryBuildLayout::under(cache_root, version, arch);
    if layout.is_complete() {
        return Ok(layout.dir);
    }

    let workspace_root = source_checkout_root().ok_or(HostBinaryBuildError::NoSourceCheckout)?;
    let spec = HostBinaryBuildSpec::new(
        workspace_root,
        layout.target_dir.clone(),
        musl_target_triple(arch).to_string(),
    );
    let output_dir = build_host_binaries(&spec)?;

    std::fs::create_dir_all(&layout.dir)?;
    for name in all_host_binary_names() {
        install_one(&output_dir.join(name), &layout.path_for(name))?;
    }
    Ok(layout.dir)
}

pub(crate) fn load_stage0_init_bytes(cache_root: &Path) -> Result<Vec<u8>, HostBinaryBuildError> {
    let stage0_init = EMBEDDED
        .iter()
        .find(|bin| bin.name == "stage0-init")
        .ok_or_else(|| HostBinaryBuildError::OutputMissing(PathBuf::from("stage0-init")))?;
    if !stage0_init.bytes.is_empty() {
        return Ok(stage0_init.bytes.to_vec());
    }
    let dir = resolve_or_build_host_binaries(cache_root)?;
    Ok(std::fs::read(dir.join("stage0-init"))?)
}

fn build_host_binaries(spec: &HostBinaryBuildSpec) -> Result<PathBuf, HostBinaryBuildError> {
    let argv = spec.argv();
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&spec.workspace_root)
        .env("CARGO_TARGET_DIR", &spec.target_dir);
    if let Some(rustc) = rustup_rustc() {
        cmd.env("RUSTC", rustc);
    }
    let out = cmd
        .output()
        .map_err(|e| HostBinaryBuildError::BuildFailed {
            reason: format!("spawn `{}`: {e}", argv[0]),
        })?;
    if !out.status.success() {
        return Err(HostBinaryBuildError::BuildFailed {
            reason: format!(
                "exit {:?}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ),
        });
    }
    let dir = spec.output_dir();
    for name in all_host_binary_names() {
        let path = dir.join(name);
        if !path.is_file() {
            return Err(HostBinaryBuildError::OutputMissing(path));
        }
    }
    Ok(dir)
}

fn source_checkout_root() -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?.to_path_buf();
    workspace_root
        .join("crates")
        .join("mvm-build")
        .is_dir()
        .then_some(workspace_root)
}

fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

fn musl_target_triple(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "aarch64-unknown-linux-musl",
        "x86_64" => "x86_64-unknown-linux-musl",
        _ => panic!("unsupported host arch for host binary source build: {arch}"),
    }
}

fn all_host_binary_names() -> Vec<&'static str> {
    HOST_BINARIES
        .iter()
        .map(|bin| bin.name)
        .chain(SEED_BINARIES.iter().copied())
        .collect()
}

fn rustup_rustc() -> Option<PathBuf> {
    let out = std::process::Command::new("rustup")
        .args(["which", "rustc"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn install_one(src: &Path, dst: &Path) -> Result<(), HostBinaryBuildError> {
    if !src.is_file() {
        return Err(HostBinaryBuildError::OutputMissing(src.to_path_buf()));
    }
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)?;
    set_exec(dst)?;
    Ok(())
}

#[cfg(unix)]
fn set_exec(path: &Path) -> Result<(), HostBinaryBuildError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_exec(_path: &Path) -> Result<(), HostBinaryBuildError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_versioned_and_arch_scoped() {
        let layout = HostBinaryBuildLayout::under(Path::new("/cache"), "0.17.0", "aarch64");
        assert_eq!(
            layout.dir,
            PathBuf::from("/cache/source-checkout/0.17.0/aarch64")
        );
        assert_eq!(
            layout.target_dir,
            PathBuf::from("/cache/source-checkout-target/0.17.0/aarch64")
        );
        assert_eq!(
            layout.path_for("stage0-init"),
            PathBuf::from("/cache/source-checkout/0.17.0/aarch64/stage0-init")
        );
    }

    #[test]
    fn build_argv_targets_musl_and_lists_each_binary() {
        let spec = HostBinaryBuildSpec::new(
            PathBuf::from("/ws"),
            PathBuf::from("/cache/target"),
            "aarch64-unknown-linux-musl".to_string(),
        );
        let argv = spec.argv();
        assert_eq!(argv[0], "cargo");
        assert_eq!(argv[1], "zigbuild");
        assert!(argv.contains(&"aarch64-unknown-linux-musl".to_string()));
        assert!(argv.contains(&"mvm-build".to_string()));
        for name in all_host_binary_names() {
            assert!(
                argv.contains(&name.to_string()),
                "expected {name} in argv: {argv:?}"
            );
        }
        assert_eq!(
            spec.output_dir(),
            PathBuf::from("/cache/target/aarch64-unknown-linux-musl/release")
        );
    }
}
