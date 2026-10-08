//! Offline creation of unsigned application filesystem assets.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{ffi::CString, os::unix::ffi::OsStrExt};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use mvm_build::rootfs::MaterializeExt4Input;

const ASSETS: [&str; 3] = ["rootfs.ext4", "rootfs.verity", "rootfs.roothash"];

#[derive(Debug, PartialEq, Eq, Serialize)]
struct AssetReport {
    path: &'static str,
    sha256: String,
    size: u64,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct BuildReport {
    assets: Vec<AssetReport>,
}

pub(super) fn run(source: &Path, output: &Path) -> Result<()> {
    let report = build(source, output)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn build(source: &Path, output: &Path) -> Result<BuildReport> {
    let source_meta = fs::symlink_metadata(source)
        .with_context(|| format!("inspect staged application tree {}", source.display()))?;
    if !source_meta.is_dir() {
        bail!(
            "staged application tree must be a directory: {}",
            source.display()
        );
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("resolve staged application tree {}", source.display()))?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("output parent must exist: {}", parent.display()))?;
    if parent.starts_with(&source) {
        bail!("output directory must be outside the staged application tree");
    }
    if output.file_name().is_none() || output.file_name().is_some_and(|n| n == "." || n == "..") {
        bail!("output must name a new directory");
    }
    let output = parent.join(output.file_name().expect("output name checked above"));
    if fs::symlink_metadata(&output).is_ok() {
        bail!("output already exists: {}", output.display());
    }

    let staging = tempfile::Builder::new()
        .prefix(".mvm-layer-")
        .tempdir_in(&parent)
        .with_context(|| format!("create private staging directory in {}", parent.display()))?;
    let image = staging.path().join(ASSETS[0]);
    let input = MaterializeExt4Input::new(source, image, 0).with_verity();
    mvm_build::rootfs::materialize_ext4_rejecting_unsupported(&input).with_context(|| {
        format!(
            "build offline application layer in {}",
            staging.path().display()
        )
    })?;

    let assets = ASSETS
        .iter()
        .map(|name| report_asset(&staging.path().join(name), name))
        .collect::<Result<Vec<_>>>()?;
    let report = BuildReport { assets };
    fs::write(
        staging.path().join("asset-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )
    .with_context(|| format!("write asset report in {}", staging.path().display()))?;
    if fs::symlink_metadata(&output).is_ok() {
        bail!("output appeared during build: {}", output.display());
    }
    publish_directory_noclobber(staging.path(), &output).with_context(|| {
        format!(
            "publish completed application layer to {}",
            output.display()
        )
    })?;
    Ok(report)
}

/// Publish a complete directory in one filesystem operation, refusing a
/// destination created by another process after the preflight check.
fn publish_directory_noclobber(source: &Path, output: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let source = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let output = CString::new(output.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        #[cfg(target_os = "linux")]
        // SAFETY: both paths are valid, nul-terminated C strings and the
        // kernel only reads them for this rename operation.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                output.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: both paths are valid, nul-terminated C strings and the
        // kernel only reads them for this rename operation.
        let result = unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                output.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, output);
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

fn report_asset(path: &Path, name: &'static str) -> Result<AssetReport> {
    let mut file =
        BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
        size = size
            .checked_add(u64::try_from(n).context("asset read size overflow")?)
            .context("asset size overflow")?;
    }
    Ok(AssetReport {
        path: name,
        sha256: hex::encode(digest.finalize()),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_requires_explicit_source_and_output() {
        let cli = crate::commands::Cli::try_parse_from([
            "mvmctl",
            "image",
            "build-layer",
            "--source",
            "staged",
            "--output",
            "assets",
        ])
        .unwrap();
        let crate::commands::Commands::Image(args) = cli.command else {
            panic!("expected image command");
        };
        let super::super::ImageAction::BuildLayer { source, output } = args.action else {
            panic!("expected build-layer action");
        };
        assert_eq!(source, Path::new("staged"));
        assert_eq!(output, Path::new("assets"));
        assert!(crate::commands::Cli::try_parse_from(["mvmctl", "image", "build-layer"]).is_err());
    }

    #[test]
    fn independent_builds_have_identical_assets_and_report() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("staged");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("app"), b"offline application\n").unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        let one = build(&source, &first).unwrap();
        let two = build(&source, &second).unwrap();
        assert_eq!(one, two);
        for name in ASSETS.into_iter().chain(["asset-report.json"]) {
            assert_eq!(
                fs::read(first.join(name)).unwrap(),
                fs::read(second.join(name)).unwrap()
            );
        }
    }

    #[test]
    fn rejects_bad_source_and_output_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("staged");
        let missing = tmp.path().join("missing");
        assert!(build(&missing, &tmp.path().join("out")).is_err());
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"data").unwrap();
        assert!(build(&source, &source.join("nested")).is_err());
        assert!(!source.join("nested").exists());
        assert!(build(&source, &source).is_err());
        assert!(build(&source, &tmp.path().join("file")).is_ok());
        assert!(build(&source, &tmp.path().join("file")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_input_leaves_no_published_output() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("staged");
        fs::create_dir(&source).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(source.join("socket")).unwrap();
        let output = tmp.path().join("assets");
        let err = build(&source, &output).unwrap_err();
        assert!(format!("{err:#}").contains("cannot represent"), "{err:#}");
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn source_root_symlink_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("staged");
        fs::create_dir(&source).unwrap();
        let link = tmp.path().join("staged-link");
        std::os::unix::fs::symlink(&source, &link).unwrap();

        let output = tmp.path().join("assets");
        assert!(build(&link, &output).is_err());
        assert!(!output.exists());
    }

    #[test]
    fn publication_never_replaces_an_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let output = tmp.path().join("output");
        fs::create_dir(&staging).unwrap();
        fs::create_dir(&output).unwrap();
        assert!(publish_directory_noclobber(&staging, &output).is_err());
        assert!(staging.is_dir());
        assert!(output.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn publication_never_replaces_an_existing_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        let output = tmp.path().join("output");
        let target = tmp.path().join("target");
        fs::create_dir(&staging).unwrap();
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &output).unwrap();
        assert!(publish_directory_noclobber(&staging, &output).is_err());
        assert!(staging.is_dir());
        assert_eq!(fs::read_link(output).unwrap(), target);
    }
}
