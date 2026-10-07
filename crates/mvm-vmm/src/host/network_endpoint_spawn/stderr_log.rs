use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Where a VM's endpoint stderr is captured. Per VM and truncated on each
/// spawn, so the tail always belongs to the endpoint the launch is reporting.
pub(super) fn endpoint_stderr_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("network-endpoint.stderr.log")
}

pub(super) fn open_endpoint_stderr_log(state_dir: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let path = endpoint_stderr_log_path(state_dir);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("open substitution endpoint stderr log {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| {
            format!(
                "protect substitution endpoint stderr log {}",
                path.display()
            )
        })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_stderr_log_is_private_and_confined_to_vm_state() {
        use std::os::unix::fs::PermissionsExt as _;

        let state = tempfile::tempdir().unwrap();
        let path = endpoint_stderr_log_path(state.path());
        let _log = open_endpoint_stderr_log(state.path()).unwrap();
        assert_eq!(path.parent(), Some(state.path()));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn endpoint_stderr_log_refuses_symlink_target() {
        let state = tempfile::tempdir().unwrap();
        let target = state.path().join("unrelated");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, endpoint_stderr_log_path(state.path())).unwrap();

        assert!(open_endpoint_stderr_log(state.path()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn endpoint_stderr_log_restricts_existing_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let state = tempfile::tempdir().unwrap();
        let path = endpoint_stderr_log_path(state.path());
        std::fs::write(&path, b"old log").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _log = open_endpoint_stderr_log(state.path()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"");
    }
}
