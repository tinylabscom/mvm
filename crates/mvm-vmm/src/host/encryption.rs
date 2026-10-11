//! Fail-closed detection of encryption on the filesystem backing a host path.

use anyhow::Result;
use mvm_core::platform::{self, Platform};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFdeStatus {
    pub enabled: bool,
    pub info: String,
}

impl HostFdeStatus {
    pub fn enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: true,
            info: info.into(),
        }
    }

    pub fn not_enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: false,
            info: info.into(),
        }
    }
}

pub fn require_host_path_encrypted(path: &Path) -> Result<()> {
    let status = detect_host_path_encryption_status(path);
    if status.enabled {
        return Ok(());
    }
    anyhow::bail!(
        "LocalBackend volume mounts require the mounted host directory to live \
         on encrypted backing storage. {}",
        status.info
    )
}

#[cfg(target_os = "macos")]
fn macos_containing_device(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c_path` is NUL-terminated and `buf` is a correctly-sized
    // statfs structure which the kernel initializes on success.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut buf) } != 0 {
        return None;
    }
    // SAFETY: on success the kernel leaves f_mntfromname NUL-terminated.
    let device = unsafe { std::ffi::CStr::from_ptr(buf.f_mntfromname.as_ptr()) };
    device
        .to_str()
        .ok()
        .map(str::to_string)
        .filter(|d| !d.is_empty())
}

#[cfg(not(target_os = "macos"))]
fn macos_containing_device(_path: &Path) -> Option<String> {
    None
}

pub fn detect_host_path_encryption_status(path: &Path) -> HostFdeStatus {
    let plat = platform::current();
    if matches!(plat, Platform::MacOS) {
        let target = macos_containing_device(path).unwrap_or_else(|| path.display().to_string());
        match mvm_core::env_hygiene::helper_command("diskutil")
            .arg("info")
            .arg(&target)
            .output()
        {
            Ok(out) if out.status.success() => {
                parse_macos_diskutil_encryption_status(path, &String::from_utf8_lossy(&out.stdout))
            }
            Ok(out) => HostFdeStatus::not_enabled(format!(
                "diskutil could not report on {target} (for {}): {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr).trim(),
            )),
            Err(e) => HostFdeStatus::not_enabled(format!(
                "could not run diskutil to check {}: {e}",
                path.display()
            )),
        }
    } else if matches!(plat, Platform::LinuxNative | Platform::LinuxNoKvm) {
        match mvm_core::env_hygiene::helper_command("findmnt")
            .args(["-no", "SOURCE", "-T"])
            .arg(path)
            .output()
        {
            Ok(out) if out.status.success() => {
                let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
                match mvm_core::env_hygiene::helper_command("lsblk")
                    .args(["-no", "TYPE", &dev])
                    .output()
                {
                    Ok(types) if types.status.success() => parse_linux_volume_backing_types(
                        path,
                        &dev,
                        &String::from_utf8_lossy(&types.stdout),
                    ),
                    _ => HostFdeStatus::not_enabled(format!(
                        "could not inspect block-device type chain for {} ({dev})",
                        path.display()
                    )),
                }
            }
            _ => HostFdeStatus::not_enabled(format!(
                "could not determine backing device for {} (findmnt unavailable)",
                path.display()
            )),
        }
    } else {
        HostFdeStatus::not_enabled("unsupported platform for encrypted-volume detection")
    }
}

pub fn parse_linux_volume_backing_types(path: &Path, dev: &str, types: &str) -> HostFdeStatus {
    if types.lines().any(|l| l.trim() == "crypt") {
        HostFdeStatus::enabled(format!(
            "{} is backed by {dev}, which sits on a dm-crypt/LUKS mapping",
            path.display()
        ))
    } else {
        HostFdeStatus::not_enabled(format!(
            "{} is backed by {dev}, which does NOT appear to sit on a \
             dm-crypt/LUKS mapping",
            path.display()
        ))
    }
}

pub fn parse_macos_diskutil_encryption_status(path: &Path, output: &str) -> HostFdeStatus {
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().to_ascii_lowercase();
        let encrypted = value.starts_with("yes") || value.starts_with("encrypted");
        if matches!(key, "FileVault" | "Encrypted") && encrypted {
            return HostFdeStatus::enabled(format!(
                "{} is on a macOS volume reported as encrypted ({key}: {})",
                path.display(),
                value
            ));
        }
    }
    HostFdeStatus::not_enabled(format!(
        "{} is not on a macOS volume reported as encrypted by diskutil",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_resolves_to_its_containing_device() {
        let device = macos_containing_device(Path::new("/System/Volumes/Data"))
            .expect("a real directory resolves to a device");
        assert!(device.starts_with("/dev/"), "{device}");
        assert_eq!(
            macos_containing_device(Path::new("/no/such/path/anywhere")),
            None
        );
    }

    #[test]
    fn volume_encryption_parsers_fail_closed() {
        let path = Path::new("/work");
        assert!(parse_linux_volume_backing_types(path, "/dev/test", "disk\ncrypt\n").enabled);
        assert!(!parse_linux_volume_backing_types(path, "/dev/test", "disk\npart\n").enabled);
        assert!(parse_macos_diskutil_encryption_status(path, "FileVault: Yes").enabled);
        assert!(!parse_macos_diskutil_encryption_status(path, "FileVault: No").enabled);
        assert!(!parse_macos_diskutil_encryption_status(path, "").enabled);
    }
}
