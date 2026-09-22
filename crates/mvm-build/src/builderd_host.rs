//! Host-only helpers used around the resident builder daemon.

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
fn e2fsck_repair_exit_code_is_success(code: i32) -> bool {
    matches!(code, 0..=2)
}

/// Repair a writable ext4 rootfs copy before it reaches a read-only guest.
#[cfg(target_os = "linux")]
pub fn repair_ext4_filesystem(path: &Path) -> Result<(), String> {
    let status = std::process::Command::new("/sbin/e2fsck")
        .args(["-f", "-y"])
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("spawn e2fsck on {}: {e}", path.display()))?;
    match status.code() {
        Some(code) if e2fsck_repair_exit_code_is_success(code) => Ok(()),
        Some(code) => Err(format!(
            "e2fsck on {} exited with status {code}; the rootfs journal may still be dirty",
            path.display()
        )),
        None => Err(format!(
            "e2fsck on {} was terminated by a signal; the rootfs journal may still be dirty",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext4_repair_accepts_clean_and_corrected_e2fsck_exit_codes_only() {
        for code in [0, 1, 2] {
            assert!(e2fsck_repair_exit_code_is_success(code));
        }
        for code in [3, 4, 8, 16, 32, 128] {
            assert!(!e2fsck_repair_exit_code_is_success(code));
        }
    }
}
