//! Process-local fixture observations, not an image trust or launch cache.

use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) fn preparation_key(home: &Path, image: &str) -> io::Result<String> {
    Ok(format!("{:?}\0{image}", home.canonicalize()?))
}

/// Observe one `image inspect --json` response. Metadata is an availability
/// and identity heuristic, never a substitute for runtime trust verification.
pub(crate) fn inspect_snapshot(cache: &Path, output: &serde_json::Value) -> io::Result<Snapshot> {
    let entry = &output["image"];
    for key in ["reference", "resolved_digest"] {
        if entry[key].as_str().is_none_or(str::is_empty) {
            return Err(io::Error::other(format!(
                "image inspection is missing {key}"
            )));
        }
    }
    let mut paths = Vec::new();
    for key in ["manifest_path", "config_path", "rootfs_path", "claims_path"] {
        let relative = entry[key]
            .as_str()
            .ok_or_else(|| io::Error::other(format!("image inspection is missing {key}")))?;
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(io::Error::other("image artifact path escapes cache"));
        }
        let path = cache.join(relative);
        if key == "rootfs_path" && path.extension().is_some_and(|ext| ext == "ext4") {
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other("rootfs artifact has no parent"))?;
            paths.push(parent.join("rootfs.verity"));
            paths.push(parent.join("rootfs.roothash"));
        }
        paths.push(path);
    }
    Snapshot::capture(
        serde_json::to_string(entry).map_err(io::Error::other)?,
        &paths,
    )
}

#[derive(Debug, PartialEq, Eq)]
struct FileStamp {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    identity: String,
    files: Vec<FileStamp>,
}

impl Snapshot {
    fn capture(identity: String, paths: &[PathBuf]) -> io::Result<Self> {
        let files = paths
            .iter()
            .map(|path| {
                let metadata = path.metadata()?;
                if !metadata.is_file() || metadata.len() == 0 {
                    return Err(io::Error::other(format!(
                        "image fixture artifact is not a nonempty file: {}",
                        path.display()
                    )));
                }
                Ok(FileStamp {
                    path: path.canonicalize()?,
                    len: metadata.len(),
                    modified: metadata.modified()?,
                    #[cfg(unix)]
                    inode: {
                        use std::os::unix::fs::MetadataExt;
                        metadata.ino()
                    },
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { identity, files })
    }
}
