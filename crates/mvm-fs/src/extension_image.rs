//! Deterministic guest filesystem images for publisher-owned extensions.

use std::path::Path;

use thiserror::Error;

use crate::rootfs::{
    MaterializeError, MaterializeOptions, MaterializedImage, UnsupportedNodePolicy,
    materialize_ext4_pure,
};

/// Build a read-only extension filesystem after proving the declared
/// entrypoint is a fixed, non-writable regular file.
pub fn materialize_extension_image(
    source: &Path,
    entrypoint: &Path,
    output: &Path,
) -> Result<MaterializedImage, ExtensionImageError> {
    validate_entrypoint(source, entrypoint)?;
    if output.starts_with(source) {
        return Err(ExtensionImageError::OutputInsideSource);
    }
    let options = MaterializeOptions::default()
        .with_unsupported_node_policy(UnsupportedNodePolicy::Reject)
        .with_volume_label(b"mvm-extension-v1");
    materialize_ext4_pure(source, output, &options).map_err(ExtensionImageError::Materialize)
}

fn validate_entrypoint(source: &Path, entrypoint: &Path) -> Result<(), ExtensionImageError> {
    if entrypoint.is_absolute()
        || entrypoint
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ExtensionImageError::UnsafeEntrypoint);
    }
    let path = source.join(entrypoint);
    let metadata = std::fs::symlink_metadata(&path).map_err(|source| {
        ExtensionImageError::EntrypointMetadata {
            path: path.display().to_string(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ExtensionImageError::EntrypointNotFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o555 {
            return Err(ExtensionImageError::EntrypointMode);
        }
    }
    Ok(())
}

/// Why an extension filesystem was not produced.
#[derive(Debug, Error)]
pub enum ExtensionImageError {
    #[error("extension entrypoint must be a safe relative path")]
    UnsafeEntrypoint,
    #[error("reading extension entrypoint {path}: {source}")]
    EntrypointMetadata {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("extension entrypoint must be a regular file")]
    EntrypointNotFile,
    #[error("extension entrypoint must have exact mode 0555")]
    EntrypointMode,
    #[error("extension output must be outside the source tree")]
    OutputInsideSource,
    #[error(transparent)]
    Materialize(#[from] MaterializeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("source root");
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).expect("bin directory");
        let executable = bin.join("extension");
        std::fs::write(&executable, b"extension-binary").expect("entrypoint");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o555))
            .expect("entrypoint mode");
        let output = root.path().with_extension("ext4");
        (root, output)
    }

    #[cfg(unix)]
    #[test]
    fn a_fixed_executable_becomes_a_guest_mountable_ext4() {
        let (root, output) = fixture();
        materialize_extension_image(root.path(), Path::new("bin/extension"), &output)
            .expect("materialize extension");
        let image = ext4_view::Ext4::load_from_path(&output).expect("read ext4");
        assert!(
            image.exists("/bin/extension").expect("lookup entrypoint"),
            "entrypoint must exist inside the image"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_writable_entrypoint_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, output) = fixture();
        std::fs::set_permissions(
            root.path().join("bin/extension"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("change mode");
        assert!(matches!(
            materialize_extension_image(root.path(), Path::new("bin/extension"), &output),
            Err(ExtensionImageError::EntrypointMode)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_entrypoint_escape_is_refused() {
        let (root, output) = fixture();
        assert!(matches!(
            materialize_extension_image(root.path(), Path::new("../bin/extension"), &output),
            Err(ExtensionImageError::UnsafeEntrypoint)
        ));
    }
}
