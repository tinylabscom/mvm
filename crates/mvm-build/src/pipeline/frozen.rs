//! Owned, checked inputs for builds that must not substitute contributor sources.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// A private source snapshot. Its owner must outlive every consumer of its path.
#[derive(Debug)]
pub struct FrozenInputs {
    staging: tempfile::TempDir,
    digest: String,
}

impl FrozenInputs {
    /// Copy through the builder's actual disk-input staging filter, then verify
    /// that neither concurrent mutation nor filtering changed the compiled tree.
    pub fn stage(source: &Path, expected: &str) -> Result<Self> {
        if tree_digest(source)? != expected {
            bail!("compiled artifact changed before frozen staging");
        }
        let staging = crate::builder_vm_runtime::stage_filtered_work_input(source)
            .map_err(anyhow::Error::new)?;
        let inputs = Self {
            staging,
            digest: expected.to_string(),
        };
        inputs.verify()?;
        Ok(inputs)
    }

    pub fn path(&self) -> &Path {
        self.staging.path()
    }

    pub fn verify(&self) -> Result<()> {
        if tree_digest(self.path())? != self.digest {
            bail!("frozen build input changed at the builder staging boundary");
        }
        Ok(())
    }
}

/// Digest regular files' relative paths, modes and bytes in sorted order.
/// Symlinks contribute their target rather than the target's contents.
pub fn tree_digest(root: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort();
    let mut hasher = Sha256::new();
    for relative in entries {
        let path = root.join(&relative);
        let metadata = std::fs::symlink_metadata(&path)?;
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        if metadata.file_type().is_symlink() {
            hasher.update(b"link:");
            hasher.update(std::fs::read_link(&path)?.to_string_lossy().as_bytes());
        } else {
            hasher.update(format!("{:o}:", metadata.permissions().mode() & 0o777).as_bytes());
            hasher.update(std::fs::read(&path)?);
        }
        hasher.update([0]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        let kind = std::fs::symlink_metadata(&path)?.file_type();
        if kind.is_dir() {
            collect(root, &path, out)?;
        } else {
            out.push(path.strip_prefix(root)?.to_path_buf());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_native_staging_owns_exact_bytes_and_rejects_mutation() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("flake.nix"),
            "github:tinylabscom/mvm/rev-a",
        )
        .unwrap();
        let expected = tree_digest(source.path()).unwrap();
        let frozen = FrozenInputs::stage(source.path(), &expected).unwrap();
        assert_ne!(source.path(), frozen.path());
        std::fs::write(
            source.path().join("flake.nix"),
            "github:tinylabscom/mvm/rev-b",
        )
        .unwrap();
        frozen.verify().unwrap();
        assert!(FrozenInputs::stage(source.path(), &expected).is_err());
        std::fs::write(frozen.path().join("flake.nix"), "changed").unwrap();
        assert!(frozen.verify().is_err());
    }

    #[test]
    fn non_native_staging_refuses_any_filtering_of_locked_bytes() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir(source.path().join("target")).unwrap();
        std::fs::write(source.path().join("target/input"), "locked").unwrap();
        let digest = tree_digest(source.path()).unwrap();
        assert!(FrozenInputs::stage(source.path(), &digest).is_err());
    }

    #[test]
    fn non_native_concurrent_sources_and_pins_have_disjoint_owned_staging() {
        let handles: Vec<_> = ["rev-a", "rev-b"]
            .into_iter()
            .map(|pin| {
                std::thread::spawn(move || {
                    let source = tempfile::tempdir().unwrap();
                    std::fs::write(
                        source.path().join("flake.nix"),
                        format!("github:tinylabscom/mvm/{pin}"),
                    )
                    .unwrap();
                    std::fs::write(source.path().join("workload.json"), "same-workload").unwrap();
                    std::fs::write(source.path().join("source"), pin).unwrap();
                    FrozenInputs::stage(source.path(), &tree_digest(source.path()).unwrap())
                        .unwrap()
                })
            })
            .collect();
        let frozen: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_ne!(frozen[0].path(), frozen[1].path());
        assert_ne!(
            tree_digest(frozen[0].path()).unwrap(),
            tree_digest(frozen[1].path()).unwrap()
        );
        let first = frozen[0].path().to_path_buf();
        let second = frozen[1].path().to_path_buf();
        drop(frozen);
        assert!(!first.exists());
        assert!(!second.exists());
    }
}
