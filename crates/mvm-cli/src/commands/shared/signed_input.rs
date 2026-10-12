//! Bounded, no-follow reads of a signed document or its signature bundle
//! named on the command line.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};

const MAX_BYTES: u64 = 1024 * 1024;

/// Read a regular file of at most 1 MiB. A symlink, a directory, or a larger
/// file is refused before its contents are read.
pub(in crate::commands) fn read_signed_input(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("checking signed input {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_BYTES {
        bail!(
            "signed input {} must be a regular file no larger than 1 MiB",
            path.display()
        );
    }
    let file =
        File::open(path).with_context(|| format!("opening signed input {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading signed input {}", path.display()))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("signed input {} exceeds 1 MiB", path.display());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_oversized_inputs_are_refused() {
        let home = tempfile::tempdir().expect("tempdir");
        assert!(read_signed_input(&home.path().join("missing")).is_err());
        let oversized = home.path().join("oversized");
        std::fs::write(&oversized, vec![0; 1024 * 1024 + 1]).expect("write input");
        assert!(read_signed_input(&oversized).is_err());
        let exact = home.path().join("exact");
        std::fs::write(&exact, vec![7; 1024 * 1024]).expect("write input");
        assert_eq!(read_signed_input(&exact).expect("read").len(), 1024 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_input_is_refused() {
        let home = tempfile::tempdir().expect("tempdir");
        let document = home.path().join("document");
        std::fs::write(&document, b"{}").expect("write document");
        let link = home.path().join("link");
        std::os::unix::fs::symlink(&document, &link).expect("link");
        assert!(read_signed_input(&link).is_err());
    }
}
