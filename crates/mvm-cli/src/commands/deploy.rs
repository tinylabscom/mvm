//! `mvmctl deploy` — build, seal, and record a local workload artifact.
//!
//! Local recording is written before any remote operation. A configured mvmd
//! endpoint requires `MVM_MVMD_API_KEY`; the local record remains available if
//! remote transport or admission fails.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_contract::ir::ir_hash;
use mvm_core::user_config::MvmConfig;
use mvm_sdk::deploy::{
    EnvironmentPin, MvmdClient, build_deploy_bundle, build_deploy_record, write_deploy_record,
};

use super::Cli;
use super::build::ir_input::load_ir_json_workload;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Workload IR JSON path, or `-` for stdin. Omit to use --from-ir.
    #[arg(value_name = "ENTRY")]
    pub entry: Option<String>,

    /// Read Workload IR from this JSON file.
    #[arg(long = "from-ir", value_name = "PATH")]
    pub from_ir: Option<PathBuf>,

    /// Local deployment directory. It contains image.tar.gz, rootfs.ext4,
    /// and deploy.json.
    /// Defaults to ~/.mvm/deployments/<ir-hash>.
    #[arg(short = 'o', long = "out", value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// Directory containing the source tree referenced by the workload.
    /// Defaults to the IR file's parent directory, or the current directory
    /// for stdin.
    #[arg(long = "manifest-dir", value_name = "DIR")]
    pub manifest_dir: Option<PathBuf>,

    /// Exact rootfs.ext4 that the selected boot path will mount. The file is
    /// copied into the deployment directory and shipped inside the archive.
    #[arg(long = "boot-artifact", value_name = "PATH")]
    pub boot_artifact: PathBuf,

    /// Verify this sealed dependency volume and include its audit hashes.
    #[arg(long = "dep-volume", value_name = "DIR")]
    pub dependency_volume: Option<PathBuf>,

    /// SHA-256 of the kernel/environment selected for admission.
    #[arg(long = "kernel-sha256", value_name = "HEX64")]
    pub kernel_sha256: Option<String>,

    /// mvmd endpoint. The local artifact is written before the authenticated
    /// remote-upload attempt; unavailable transport fails closed.
    #[arg(long = "mvmd-url", value_name = "URL")]
    pub mvmd_url: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let Args {
        entry,
        from_ir,
        out,
        manifest_dir,
        boot_artifact,
        dependency_volume,
        kernel_sha256,
        mvmd_url,
    } = args;
    let workload = load_ir_json_workload(from_ir.as_deref(), entry.as_deref())?;
    let ir_hash = ir_hash(&workload).context("computing workload ir_hash")?;
    let deployment_dir = out.unwrap_or_else(|| mvm_core::config::deployments_dir().join(&ir_hash));
    std::fs::create_dir_all(&deployment_dir)
        .with_context(|| format!("creating deployment directory {}", deployment_dir.display()))?;

    let artifact_path = deployment_dir.join("image.tar.gz");
    let local_boot_artifact = deployment_dir.join("rootfs.ext4");
    let record_path = deployment_dir.join("deploy.json");
    let manifest_dir = manifest_dir.unwrap_or(resolve_default_manifest_dir(
        from_ir.as_deref(),
        entry.as_deref(),
    )?);

    install_boot_artifact(&boot_artifact, &local_boot_artifact)?;
    let bundle = build_deploy_bundle(
        &workload,
        &artifact_path,
        &manifest_dir,
        &local_boot_artifact,
    )
    .map_err(anyhow::Error::from)
    .with_context(|| format!("building sealed artifact {}", artifact_path.display()))?;
    let environment = kernel_sha256
        .map(|kernel_sha256| {
            validate_sha256(&kernel_sha256).map(|_| EnvironmentPin { kernel_sha256 })
        })
        .transpose()?;
    let record = build_deploy_record(
        &workload,
        &bundle,
        environment,
        dependency_volume.as_deref(),
    )
    .map_err(anyhow::Error::from)
    .context("attesting local deploy")?;
    write_deploy_record(&record, &record_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("writing deploy record {}", record_path.display()))?;

    println!("local deployment: {}", deployment_dir.display());
    println!("  artifact: {}", artifact_path.display());
    println!("  boot artifact: {}", local_boot_artifact.display());
    println!("  record: {}", record_path.display());
    println!("  image blake3: {}", record.image.blake3);
    println!("  image sha256: {}", record.image.sha256);

    if let Some(base_url) = resolve_mvmd_url(mvmd_url.as_deref(), cfg) {
        let api_key = std::env::var("MVM_MVMD_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("MVM_MVMD_API_KEY is required when mvmd is configured")
            })?;
        let client = MvmdClient::new(&base_url, api_key);
        client
            .ship(&bundle, &record)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("shipping deployment to {base_url}"))?;
        println!("remote deployment requested: {base_url}");
    }
    Ok(())
}

fn install_boot_artifact(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_file() {
        bail!(
            "--boot-artifact is not a regular file: {}",
            source.display()
        );
    }
    if source == destination {
        return Ok(());
    }
    let temporary = destination.with_extension("ext4.tmp");
    fs::copy(source, &temporary).with_context(|| {
        format!(
            "copying boot artifact {} into {}",
            source.display(),
            destination.display()
        )
    })?;
    fs::rename(&temporary, destination)
        .with_context(|| format!("publishing local boot artifact {}", destination.display()))?;
    Ok(())
}

fn resolve_mvmd_url(cli_url: Option<&str>, cfg: &MvmConfig) -> Option<String> {
    cli_url
        .map(str::to_owned)
        .or_else(|| std::env::var("MVM_MVMD_URL").ok())
        .or_else(|| cfg.mvmd_url.clone())
        .filter(|url| !url.trim().is_empty())
}

fn resolve_default_manifest_dir(from_ir: Option<&Path>, entry: Option<&str>) -> Result<PathBuf> {
    if let Some(path) = from_ir {
        return Ok(path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")));
    }
    match entry {
        Some("-") | None => std::env::current_dir().context("getting current directory"),
        Some(path) => Ok(PathBuf::from(path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))),
    }
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("--kernel-sha256 must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_manifest_dir_uses_ir_parent() {
        let dir =
            resolve_default_manifest_dir(Some(Path::new("fixtures/workload.json")), None).unwrap();
        assert_eq!(dir, Path::new("fixtures"));
    }

    #[test]
    fn kernel_digest_requires_64_hex_chars() {
        assert!(validate_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_sha256(&"A".repeat(64)).is_err());
        assert!(validate_sha256("not-a-digest").is_err());
    }
}
