use super::*;

pub(super) fn resident_parent_rootfs_dir(
    parent_vm_name: &str,
) -> std::result::Result<PathBuf, StandbyError> {
    let metadata = crate::base::runtime_meta::read(parent_vm_name)
        .map_err(|e| StandbyError::ClaimFailed(format!("read resident parent metadata: {e}")))?
        .ok_or_else(|| {
            StandbyError::ClaimFailed(format!(
                "resident parent '{parent_vm_name}' has no runtime metadata"
            ))
        })?;
    let rootfs = metadata
        .rootfs_path
        .ok_or_else(|| StandbyError::ClaimFailed("resident parent has no rootfs path".into()))?;
    let rootfs = PathBuf::from(rootfs);
    if !rootfs.is_file() {
        return Err(StandbyError::ClaimFailed(format!(
            "resident parent rootfs {} is not a regular file",
            rootfs.display()
        )));
    }
    rootfs.parent().map(Path::to_path_buf).ok_or_else(|| {
        StandbyError::ClaimFailed(format!(
            "resident parent rootfs {} has no containing directory",
            rootfs.display()
        ))
    })
}
