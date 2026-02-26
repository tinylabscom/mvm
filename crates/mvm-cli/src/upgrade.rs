use anyhow::{Context, Result};
use std::path::Path;

use crate::http;
use crate::ui;
use mvm_runtime::shell::run_host;

const GITHUB_REPO: &str = "auser/mvm";

/// Current version compiled into the binary (from Cargo.toml).
fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Detect the target triple for the current platform at compile time.
/// Returns strings matching the release artifact naming from release.yml.
fn detect_target() -> Result<&'static str> {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return Ok("aarch64-apple-darwin");

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return Ok("x86_64-apple-darwin");

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    return Ok("x86_64-unknown-linux-gnu");

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    return Ok("aarch64-unknown-linux-gnu");

    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
    )))]
    anyhow::bail!(
        "Unsupported platform: {} / {}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
}

/// Query the GitHub releases API for the latest release tag name.
fn fetch_latest_version() -> Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );

    let json = http::fetch_json(&url)
        .context("Failed to query GitHub releases API. Check your network connection.")?;

    let tag = json["tag_name"]
        .as_str()
        .context("GitHub API response missing 'tag_name' field")?;

    Ok(tag.to_string())
}

/// Strip the "v" prefix from a version tag.
fn strip_v_prefix(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Download the release archive into the given temp directory.
fn download_release(version: &str, target: &str, tmp_dir: &Path) -> Result<()> {
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let download_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, version, archive_name
    );
    let dest = tmp_dir.join(&archive_name);

    let sp = ui::spinner(&format!("Downloading {}...", download_url));

    http::download_file(&download_url, &dest).with_context(|| {
        format!(
            "Download failed. Check that {} has a release for {}.",
            version, target
        )
    })?;

    sp.finish_and_clear();
    ui::success("Download complete.");
    Ok(())
}

/// Check if a directory is writable by the current user.
fn is_writable(path: &Path) -> bool {
    tempfile::Builder::new()
        .prefix(".mvm-write-test-")
        .tempfile_in(path)
        .is_ok()
}

/// Extract the archive and install the binary + resources, replacing the current installation.
fn extract_and_install(target: &str, tmp_dir: &Path, current_exe: &Path) -> Result<()> {
    let archive_name = format!("mvmctl-{}.tar.gz", target);
    let archive_path = tmp_dir.join(&archive_name);

    let output = run_host(
        "tar",
        &[
            "xzf",
            archive_path.to_str().unwrap(),
            "-C",
            tmp_dir.to_str().unwrap(),
        ],
    )?;

    if !output.status.success() {
        anyhow::bail!("Failed to extract archive");
    }

    let extracted_dir = tmp_dir.join(format!("mvmctl-{}", target));
    let new_binary = extracted_dir.join("mvmctl");
    if !new_binary.exists() {
        anyhow::bail!(
            "Binary not found in archive at expected path: mvmctl-{}/mvmctl",
            target
        );
    }

    let install_dir = current_exe
        .parent()
        .context("Cannot determine install directory")?;

    let needs_sudo = !is_writable(install_dir);

    ui::info(&format!("Installing to {}...", install_dir.display()));
    if needs_sudo {
        ui::warn("Requires elevated permissions.");
    }

    // --- Replace binary ---
    let backup_path = current_exe.with_extension("old");

    if needs_sudo {
        run_sudo_mv(current_exe, &backup_path)?;
        if let Err(e) = run_sudo_cp(&new_binary, current_exe) {
            let _ = run_sudo_mv(&backup_path, current_exe);
            return Err(e);
        }
        let _ = run_host("sudo", &["chmod", "+x", current_exe.to_str().unwrap()]);
        let _ = run_host("sudo", &["rm", "-f", backup_path.to_str().unwrap()]);
    } else {
        std::fs::rename(current_exe, &backup_path).context("Failed to back up current binary")?;
        if let Err(e) = std::fs::copy(&new_binary, current_exe) {
            let _ = std::fs::rename(&backup_path, current_exe);
            return Err(anyhow::anyhow!(e).context("Failed to install new binary"));
        }
        set_executable(current_exe)?;
        let _ = std::fs::remove_file(&backup_path);
    }

    // --- Replace resources ---
    let new_resources = extracted_dir.join("resources");
    if new_resources.exists() {
        let dest_resources = install_dir.join("resources");
        ui::info("Updating resources...");

        if needs_sudo {
            let _ = run_host("sudo", &["rm", "-rf", dest_resources.to_str().unwrap()]);
            let output = run_host(
                "sudo",
                &[
                    "cp",
                    "-r",
                    new_resources.to_str().unwrap(),
                    dest_resources.to_str().unwrap(),
                ],
            )?;
            if !output.status.success() {
                ui::warn("Failed to update resources directory");
            }
        } else {
            let _ = std::fs::remove_dir_all(&dest_resources);
            copy_dir_recursive(&new_resources, &dest_resources)
                .context("Failed to update resources directory")?;
        }
    }

    Ok(())
}

fn run_sudo_mv(from: &Path, to: &Path) -> Result<()> {
    let output = run_host(
        "sudo",
        &["mv", from.to_str().unwrap(), to.to_str().unwrap()],
    )?;
    if !output.status.success() {
        anyhow::bail!("sudo mv failed");
    }
    Ok(())
}

fn run_sudo_cp(from: &Path, to: &Path) -> Result<()> {
    let output = run_host(
        "sudo",
        &["cp", from.to_str().unwrap(), to.to_str().unwrap()],
    )?;
    if !output.status.success() {
        anyhow::bail!("sudo cp failed");
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

/// Main entry point: check for updates and optionally install.
pub fn upgrade(check_only: bool, force: bool) -> Result<()> {
    let current = current_version();
    ui::info(&format!("Current version: {}", current));

    let sp = ui::spinner("Checking for updates...");
    let latest_tag = fetch_latest_version()?;
    let latest_version = strip_v_prefix(&latest_tag);
    sp.finish_and_clear();

    if latest_version == current && !force {
        ui::success(&format!("Already up to date ({}).", current));
        return Ok(());
    }

    if latest_version == current {
        ui::info(&format!(
            "Already at {} but --force specified, reinstalling.",
            current
        ));
    } else {
        ui::info(&format!(
            "New version available: {} -> {}",
            current, latest_version
        ));
    }

    if check_only {
        return Ok(());
    }

    let target = detect_target()?;
    ui::info(&format!("Platform: {}", target));

    let current_exe =
        std::env::current_exe().context("Failed to determine path of current executable")?;
    let current_exe = current_exe.canonicalize().unwrap_or(current_exe);

    let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    download_release(&latest_tag, target, tmp_dir.path())?;
    extract_and_install(target, tmp_dir.path(), &current_exe)?;

    ui::success(&format!("\nSuccessfully upgraded to {}!", latest_tag));

    // Verify the new binary works
    let output = run_host(current_exe.to_str().unwrap(), &["--version"])?;
    if output.status.success() {
        let version_output = String::from_utf8_lossy(&output.stdout);
        ui::success(&format!("Verified: {}", version_output.trim()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version_non_empty() {
        let v = current_version();
        assert!(!v.is_empty());
        assert!(v.contains('.'), "Version should contain dots: {}", v);
    }

    #[test]
    fn test_strip_v_prefix() {
        assert_eq!(strip_v_prefix("v0.1.0"), "0.1.0");
        assert_eq!(strip_v_prefix("0.1.0"), "0.1.0");
        assert_eq!(strip_v_prefix("v1.2.3-beta"), "1.2.3-beta");
    }

    #[test]
    fn test_detect_target_succeeds() {
        let target = detect_target().unwrap();
        let valid_targets = [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        ];
        assert!(
            valid_targets.contains(&target),
            "Unexpected target: {}",
            target
        );
    }
}
