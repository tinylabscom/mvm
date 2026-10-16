//! Which host files a full-VM capture copies for the devices its snapshot
//! names.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::checkpoint::DeviceAnchors;

/// The host file backing each device the snapshot names, for the capture to
/// copy.
///
/// A fork restores each embedded device from the file the capture copied for
/// it, so a device the snapshot names with no file here refuses the capture
/// instead of producing a checkpoint whose forks cannot load. A file the
/// snapshot does not name is left out: no fork would open it.
pub(super) fn embedded_device_files<'a>(
    anchors: &DeviceAnchors,
    files: &'a DeviceAnchors,
) -> Result<Vec<&'a Path>> {
    let mut out = Vec::new();
    for (device, embedded, file) in [
        (
            "rootfs.verity",
            &anchors.rootfs_verity,
            &files.rootfs_verity,
        ),
        ("config", &anchors.config, &files.config),
        ("secrets", &anchors.secrets, &files.secrets),
        ("identity", &anchors.identity, &files.identity),
    ] {
        if embedded.is_none() {
            continue;
        }
        let file = file.as_deref().with_context(|| {
            format!("the snapshot names a {device} device but this host has no file for it")
        })?;
        out.push(file);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn anchors(config: Option<&str>, secrets: Option<&str>) -> DeviceAnchors {
        DeviceAnchors {
            rootfs: "/vm/rootfs.ext4".into(),
            rootfs_verity: None,
            config: config.map(PathBuf::from),
            secrets: secrets.map(PathBuf::from),
            identity: None,
            vsock: "/vm/runtime/v.sock".into(),
        }
    }

    /// Each device the snapshot names is copied from this host's own file for
    /// it, which for a restored VM is not the path the snapshot names.
    #[test]
    fn each_embedded_device_is_copied_from_its_host_file() {
        let embedded = anchors(Some("/parent/vm/config.ext4"), None);
        let files = anchors(
            Some("/child/vm/config.ext4"),
            Some("/child/vm/secrets.ext4"),
        );
        let copied = embedded_device_files(&embedded, &files).unwrap();
        assert_eq!(copied, vec![Path::new("/child/vm/config.ext4")]);
    }

    /// A device the snapshot names with no file here would make every fork of
    /// the checkpoint unloadable, so the capture refuses.
    #[test]
    fn an_embedded_device_without_a_host_file_refuses_the_capture() {
        let embedded = anchors(Some("/parent/vm/config.ext4"), None);
        let files = anchors(None, None);
        let err = embedded_device_files(&embedded, &files).unwrap_err();
        assert!(err.to_string().contains("config"), "{err}");
    }
}
