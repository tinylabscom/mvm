//! Offline image-set revocation administration through the canonical store.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, ensure};
pub use mvm_core::image_set_revocation::{
    ImageSetRevocationCheckpoint, VerifiedImageSetRevocations,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

/// Bound both operator inputs before handing their bytes to the canonical
/// signature, freshness and monotonic-checkpoint verifier. No acquisition.
/// The canonical store may initialize its private directory and lock even when
/// verification refuses the update; refusal does not establish an applied list.
pub fn update(document: &Path, bundle: &Path) -> Result<ImageSetRevocationCheckpoint> {
    let document = read_input(document)?;
    let bundle = read_input(bundle)?;
    Ok(mvm_core::image_set_revocation::update_image_set_revocations(&document, &bundle)?)
}

/// Reauthenticate the host's applied list under the current trust policy.
/// Missing state may initialize store infrastructure, not an applied list.
pub fn status() -> Result<VerifiedImageSetRevocations> {
    Ok(mvm_core::image_set_revocation::load_image_set_revocations()?)
}

fn read_input(path: &Path) -> Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("checking signed input {}", path.display()))?;
    ensure!(
        before.is_file() && before.len() <= MAX_INPUT_BYTES,
        "signed input {} must be a regular file no larger than 1 MiB",
        path.display()
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening signed input {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_INPUT_BYTES,
        "signed input {} must be a regular file no larger than 1 MiB",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            before.dev() == metadata.dev() && before.ino() == metadata.ino(),
            "signed input {} changed while opening",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading signed input {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_INPUT_BYTES,
        "signed input {} exceeds 1 MiB",
        path.display()
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_directory_and_oversized_inputs_are_refused() {
        let root = tempfile::tempdir().unwrap();
        assert!(read_input(&root.path().join("missing")).is_err());
        assert!(read_input(root.path()).is_err());
        let path = root.path().join("input");
        std::fs::write(&path, vec![7; MAX_INPUT_BYTES as usize]).unwrap();
        assert_eq!(read_input(&path).unwrap().len(), MAX_INPUT_BYTES as usize);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_INPUT_BYTES + 1)
            .unwrap();
        assert!(read_input(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_fifos_are_refused_without_reading() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("document");
        std::fs::write(&target, b"{}").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_input(&link).is_err());
        let fifo = root.path().join("fifo");
        let status = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(read_input(&fifo).is_err());
    }

    #[test]
    fn absent_status_and_unsigned_update_do_not_create_an_applied_list() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        let error = status().unwrap_err();
        assert!(format!("{error:#}").contains("mvmctl image revocations update"));
        let document = root.path().join("document");
        let bundle = root.path().join("bundle");
        std::fs::write(&document, b"{}").unwrap();
        std::fs::write(&bundle, b"not a bundle").unwrap();
        assert!(update(&document, &bundle).is_err());
        let store = mvm_core::config::image_set_revocation_store_dir();
        assert!(!store.join("checkpoint.json").exists());
        assert!(!store.join("feed.json").exists());
    }
}
