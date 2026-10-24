//! Pointing a forked child's Firecracker at its own devices.
//!
//! A Firecracker snapshot names every block device and the vsock socket by the
//! host path the parent opened it from. A child restored from that snapshot
//! must use its own copies instead. Firecracker supports both moves through its
//! API, with no privilege and no mount namespace:
//!
//! - the vsock socket is overridden on `PUT /snapshot/load` itself
//!   (`vsock_override`), so the child binds its own socket and never touches
//!   the parent's;
//! - each drive is reopened from the child's path with `PATCH /drives/{id}`
//!   after the load and before anything resumes. The load leaves the vCPUs
//!   paused, so no guest I/O reaches the parent's file in between.
//!
//! The load still opens every recorded drive path once, so each must exist;
//! [`ForkDevices::ensure_recorded_drives_exist`] creates an empty placeholder
//! for one whose parent has since been removed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Where a forked child's devices live, in place of the paths its parent's
/// snapshot recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkDevices {
    /// Drives the parent opened outside its state dir, each with the child's
    /// copy: the rootfs and its verity sidecar.
    files: Vec<(PathBuf, PathBuf)>,
    /// Every drive path the snapshot recorded, so a load can find it.
    recorded_drives: Vec<PathBuf>,
    parent_state_dir: PathBuf,
    child_state_dir: PathBuf,
    child_vsock_uds: PathBuf,
}

/// One drive as Firecracker reports it in `GET /vm/config`.
#[derive(Debug, Deserialize)]
struct RestoredDrive {
    drive_id: String,
    #[serde(default)]
    path_on_host: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct RestoredDrives {
    #[serde(default)]
    drives: Vec<RestoredDrive>,
}

impl ForkDevices {
    /// The child's devices for a parent captured with `anchors`.
    ///
    /// `child_dir` holds the child's copies of the parent's rootfs and verity
    /// sidecar; `child_state_dir` is the child's VM state dir, which mirrors
    /// the parent's file for file and holds its vsock socket.
    pub fn from_anchors(
        anchors: &mvm_core::checkpoint::DeviceAnchors,
        child_dir: &Path,
        child_state_dir: &Path,
    ) -> Result<Self> {
        let parent_state_dir = anchors
            .vsock
            .parent()
            .and_then(Path::parent)
            .context("the parent's recorded vsock socket has no VM state dir above it")?
            .to_path_buf();
        let mut files = vec![(anchors.rootfs.clone(), child_dir.join("rootfs.ext4"))];
        if let Some(verity) = &anchors.rootfs_verity {
            files.push((verity.clone(), child_dir.join("rootfs.verity")));
        }
        let recorded_drives = std::iter::once(&anchors.rootfs)
            .chain(&anchors.rootfs_verity)
            .chain(&anchors.config)
            .chain(&anchors.secrets)
            .chain(&anchors.identity)
            .cloned()
            .collect();
        let child_vsock_uds = PathBuf::from(super::firecracker_vsock_uds_path(
            &child_state_dir.to_string_lossy(),
        ));
        Ok(Self {
            files,
            recorded_drives,
            parent_state_dir,
            child_state_dir: child_state_dir.to_path_buf(),
            child_vsock_uds,
        })
    }

    /// The vsock socket the child's Firecracker binds instead of the parent's.
    pub fn child_vsock_uds(&self) -> &Path {
        &self.child_vsock_uds
    }

    /// The child's file for a drive the snapshot recorded at `recorded`, or
    /// `None` for one the child shares with its parent as-is: a read-only
    /// artifact outside any VM's state, such as the runtime overlay.
    pub fn child_path_for(&self, recorded: &Path) -> Option<PathBuf> {
        if let Some((_, child)) = self.files.iter().find(|(parent, _)| parent == recorded) {
            return Some(child.clone());
        }
        recorded
            .strip_prefix(&self.parent_state_dir)
            .ok()
            .map(|relative| self.child_state_dir.join(relative))
    }

    /// A capture of the parent's runtime, with every drive path the child
    /// repoints to its own file rewritten to that file. What the restored VMM
    /// reports after the retarget is compared against this, not against the
    /// parent's recorded paths.
    pub fn as_child_capture(
        &self,
        mut capture: mvm_vmm::runtime_artifacts::RuntimeArtifacts,
    ) -> mvm_vmm::runtime_artifacts::RuntimeArtifacts {
        let remap = |path: &mut PathBuf| {
            if let Some(child) = self.child_path_for(path) {
                *path = child;
            }
        };
        for drive in capture.firecracker_drives.iter_mut().flatten() {
            remap(&mut drive.path);
        }
        for disk in &mut capture.disks {
            remap(&mut disk.path);
        }
        capture
    }

    /// Make sure every drive path the snapshot recorded exists, so the load
    /// can open it before the drive is pointed at the child's copy.
    ///
    /// A parent's state can be gone by the time its standby child is loaded.
    /// Its recorded paths then get an empty placeholder, which the load opens
    /// and the retarget replaces before the child runs.
    pub fn ensure_recorded_drives_exist(&self) -> Result<()> {
        for recorded in &self.recorded_drives {
            if recorded.exists() {
                continue;
            }
            if let Some(dir) = recorded.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(recorded)
                .with_context(|| format!("creating placeholder {}", recorded.display()))?;
        }
        Ok(())
    }

    /// The fields `PUT /snapshot/load` carries for a fork, beyond the
    /// snapshot and memory paths.
    pub fn load_overrides(&self) -> serde_json::Value {
        serde_json::json!({
            "vsock_override": { "uds_path": self.child_vsock_uds },
        })
    }

    /// The `PATCH /drives/{id}` each restored drive needs, from Firecracker's
    /// `GET /vm/config` answer after the load.
    ///
    /// Refuses a drive whose recorded path names the parent's own state but
    /// has no counterpart in the child: leaving it would hand the child its
    /// parent's file.
    pub fn drive_patches(&self, vm_config: &str) -> Result<Vec<(String, String)>> {
        let restored: RestoredDrives = serde_json::from_str(vm_config)
            .context("parsing the restored drives from GET /vm/config")?;
        let mut patches = Vec::new();
        for drive in restored.drives {
            let Some(recorded) = drive.path_on_host else {
                continue;
            };
            let Some(child) = self.child_path_for(&recorded) else {
                continue;
            };
            anyhow::ensure!(
                child.exists(),
                "the child has no copy of drive '{}' (recorded at {}): expected {}",
                drive.drive_id,
                recorded.display(),
                child.display()
            );
            let body = serde_json::json!({
                "drive_id": drive.drive_id,
                "path_on_host": child,
            })
            .to_string();
            patches.push((drive.drive_id, body));
        }
        Ok(patches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::DeviceAnchors;

    struct Fixture {
        _root: tempfile::TempDir,
        parent_dir: PathBuf,
        image: PathBuf,
        child_dir: PathBuf,
        devices: ForkDevices,
    }

    fn fixture() -> Fixture {
        // The default temp dir can be deep enough that the VM's sockets fall
        // back to the short namespace; from_anchors then derives the parent's
        // state dir from the relocated socket path and drive remapping breaks.
        // Production refuses that layout, so the fixture keeps sockets inside
        // the state dir by rooting at a short path.
        let root = crate::driver::socket_tempdir();
        let image_dir = root.path().join("cache/image");
        let parent_dir = root.path().join("vms/parent");
        let child_dir = root.path().join("vms/child");
        for dir in [&image_dir, &parent_dir, &child_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let image = image_dir.join("rootfs.ext4");
        std::fs::write(&image, b"image").unwrap();
        std::fs::write(image_dir.join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(parent_dir.join("config.ext4"), b"parent config").unwrap();
        for name in ["rootfs.ext4", "rootfs.verity", "config.ext4"] {
            std::fs::write(child_dir.join(name), b"child").unwrap();
        }
        let anchors = DeviceAnchors {
            rootfs: image.clone(),
            rootfs_verity: Some(image_dir.join("rootfs.verity")),
            config: Some(parent_dir.join("config.ext4")),
            secrets: None,
            identity: None,
            vsock: PathBuf::from(super::super::firecracker_vsock_uds_path(
                &parent_dir.to_string_lossy(),
            )),
        };
        let devices = ForkDevices::from_anchors(&anchors, &child_dir, &child_dir).unwrap();
        Fixture {
            _root: root,
            parent_dir,
            image,
            child_dir,
            devices,
        }
    }

    fn vm_config(drives: &[(&str, &Path)]) -> String {
        serde_json::json!({
            "drives": drives
                .iter()
                .map(|(id, path)| serde_json::json!({"drive_id": id, "path_on_host": path}))
                .collect::<Vec<_>>(),
        })
        .to_string()
    }

    #[test]
    fn every_parent_owned_drive_is_pointed_at_the_childs_copy() {
        let f = fixture();
        let overlay = f.image.with_file_name("runtime-overlay.ext4");
        let config = vm_config(&[
            ("rootfs", &f.image),
            ("rootfs-verity", &f.image.with_file_name("rootfs.verity")),
            ("config", &f.parent_dir.join("config.ext4")),
            ("runtime", &overlay),
        ]);
        let patches = f.devices.drive_patches(&config).unwrap();
        let targets: Vec<(String, PathBuf)> = patches
            .iter()
            .map(|(id, body)| {
                let body: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(body["drive_id"], id.as_str());
                (
                    id.clone(),
                    PathBuf::from(body["path_on_host"].as_str().unwrap()),
                )
            })
            .collect();
        assert_eq!(
            targets,
            vec![
                ("rootfs".into(), f.child_dir.join("rootfs.ext4")),
                ("rootfs-verity".into(), f.child_dir.join("rootfs.verity")),
                ("config".into(), f.child_dir.join("config.ext4")),
            ],
            "a shared artifact outside the parent's state keeps its path"
        );
    }

    #[test]
    fn a_parent_capture_is_read_at_the_childs_drive_paths() {
        use mvm_vmm::runtime_artifacts::{FirecrackerDrive, RuntimeArtifact, RuntimeArtifacts};
        let f = fixture();
        let overlay = f.image.with_file_name("runtime-overlay.ext4");
        let config = f.parent_dir.join("config.ext4");
        let drive = |id: &str, path: &Path, read_only| FirecrackerDrive {
            drive_id: id.into(),
            path: path.to_path_buf(),
            is_root_device: false,
            is_read_only: read_only,
        };
        let disk = |path: &Path| RuntimeArtifact {
            path: path.to_path_buf(),
            sha256: "ab".repeat(32),
        };
        let capture = RuntimeArtifacts {
            kernel: None,
            initramfs: None,
            disks: vec![disk(&overlay), disk(&config)],
            kernel_cmdline: String::new(),
            firecracker_drives: Some(vec![
                drive("blk0", &f.image, false),
                drive("blk1", &overlay, true),
                drive("blk2", &config, true),
            ]),
        };
        let child = f.devices.as_child_capture(capture);
        let paths: Vec<_> = child
            .firecracker_drives
            .unwrap()
            .into_iter()
            .map(|d| d.path)
            .collect();
        assert_eq!(
            paths,
            vec![
                f.child_dir.join("rootfs.ext4"),
                overlay.clone(),
                f.child_dir.join("config.ext4")
            ]
        );
        let disks: Vec<_> = child.disks.into_iter().map(|d| d.path).collect();
        assert_eq!(disks, vec![overlay, f.child_dir.join("config.ext4")]);
    }

    #[test]
    fn a_parent_owned_drive_the_child_has_no_copy_of_is_refused() {
        let f = fixture();
        let config = vm_config(&[("secrets", &f.parent_dir.join("secrets.ext4"))]);
        let error = f.devices.drive_patches(&config).unwrap_err();
        assert!(format!("{error:#}").contains("no copy of drive 'secrets'"));
    }

    #[test]
    fn the_load_binds_the_childs_vsock_socket_not_the_parents() {
        let f = fixture();
        let overrides = f.devices.load_overrides();
        let uds = PathBuf::from(overrides["vsock_override"]["uds_path"].as_str().unwrap());
        assert!(uds.starts_with(&f.child_dir), "{}", uds.display());
        assert_eq!(uds, f.devices.child_vsock_uds());
    }

    #[test]
    fn a_removed_parents_drives_get_placeholders_and_existing_files_are_untouched() {
        let f = fixture();
        std::fs::remove_dir_all(&f.parent_dir).unwrap();
        f.devices.ensure_recorded_drives_exist().unwrap();
        assert!(f.parent_dir.join("config.ext4").exists());
        assert_eq!(std::fs::read(&f.image).unwrap(), b"image");
    }
}
