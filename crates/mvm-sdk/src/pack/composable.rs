//! Smolfile-sized TOML front end to the neutral, versioned composition spec.
//!
//! Parsing is authoring only: it never resolves a runtime, builds an image,
//! signs a bundle or interprets a production request as permission to publish.

#[cfg(feature = "compiler")]
pub use mvm_compiler::pack::{
    ComposableStageError, StagedComposableApplication, stage_composable_application,
};
pub use mvm_contract::pack_spec_v2::{
    BuildMode, ComposablePackError, ComposablePackSchema, ComposablePackSpec, Production,
};

/// A private source snapshot and its deterministic, digest-bound application tar.
#[cfg(feature = "compiler")]
pub struct PreparedComposableApplication {
    stage: StagedComposableApplication,
    archive: crate::addon::archive::AddonArchive,
}

#[cfg(feature = "compiler")]
impl std::fmt::Debug for PreparedComposableApplication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedComposableApplication")
            .field("source_sha256", &self.stage.source_sha256())
            .field("archive_sha256", &self.archive.sha256)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "compiler")]
impl PreparedComposableApplication {
    /// Compressed tar containing only the authored application files.
    pub fn archive_bytes(&self) -> &[u8] {
        &self.archive.bytes
    }

    /// SHA-256 of the exact compressed tar bytes.
    pub fn archive_sha256(&self) -> &str {
        &self.archive.sha256
    }

    /// SHA-256 of the selected source snapshot, excluding unrelated files.
    pub fn source_sha256(&self) -> &str {
        self.stage.source_sha256()
    }

    /// Refuse changed staged files or archive bytes before composition or signing.
    ///
    /// # Errors
    ///
    /// A changed snapshot or archive cannot supply frozen production input.
    pub fn reverify(&self) -> Result<(), PrepareComposableError> {
        self.stage.reverify()?;
        if crate::addon::archive::sha256_hex(&self.archive.bytes) != self.archive.sha256 {
            return Err(PrepareComposableError::ChangedArchive);
        }
        Ok(())
    }
}

/// Prepare one Nix-free application archive from the closed v2 spec.
///
/// This is not a signed `.mvmpkg` or a production grant. The caller must bind
/// the returned digest into its frozen plan and verify it again before export.
///
/// # Errors
///
/// Refuses an invalid source, unsafe copy, changed snapshot or oversized archive.
#[cfg(feature = "compiler")]
pub fn prepare_composable_application(
    spec: &ComposablePackSpec,
    spec_dir: &std::path::Path,
) -> Result<PreparedComposableApplication, PrepareComposableError> {
    let stage = stage_composable_application(spec, spec_dir)?;
    stage.reverify()?;
    let archive = crate::addon::archive::pack_addon_dir(stage.root())?;
    if archive.bytes.len() > 2 * 1024 * 1024 * 1024 {
        return Err(PrepareComposableError::OversizedArchive);
    }
    let prepared = PreparedComposableApplication { stage, archive };
    prepared.reverify()?;
    Ok(prepared)
}

/// Refusal before a composable application becomes authenticated build input.
#[cfg(feature = "compiler")]
#[derive(Debug, thiserror::Error)]
pub enum PrepareComposableError {
    #[error(transparent)]
    Stage(#[from] ComposableStageError),
    #[error("could not archive the staged application: {0}")]
    Archive(#[from] std::io::Error),
    #[error("application archive exceeds 2 GiB")]
    OversizedArchive,
    #[error("application archive bytes changed after staging")]
    ChangedArchive,
}

/// Parse the same closed contract the language SDKs can emit as JSON.
///
/// # Errors
///
/// Refuses unknown fields, unsafe paths, unversioned schema and invalid
/// runtime requests. Errors never include the authored file's contents.
pub fn parse_toml(input: &str) -> Result<ComposablePackSpec, ComposableTomlError> {
    if input.len() > 64 * 1024 {
        return Err(ComposableTomlError::Oversized);
    }
    toml::from_str(input).map_err(|_| ComposableTomlError::Invalid)
}

/// Public parser errors avoid echoing author-supplied source or secret names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComposableTomlError {
    #[error("composable pack TOML exceeds 64 KiB")]
    Oversized,
    #[error("invalid or unsupported composable pack TOML")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PYTHON: &str = r#"
schema = "mvm.pack-spec/v2"
target = "x86_64-linux"
runtimes = ["runtime/python"]
entrypoint = ["/usr/bin/python3", "/srv/app/main.py"]

[identity]
name = "agent/example"
version = "1.0.0"

[source]
kind = "local"
path = "."

[[copy]]
source = "main.py"
destination = "/srv/app/main.py"

[resources]
cpu_cores = 1
memory_mb = 256
"#;

    #[test]
    fn dev_is_the_default_and_prod_requires_a_separate_table() {
        let spec = parse_toml(PYTHON).unwrap();
        spec.check_mode_request(BuildMode::Development).unwrap();
        assert_eq!(
            spec.check_mode_request(BuildMode::Production),
            Err(ComposablePackError::ProductionNotSelected)
        );
        let prod = parse_toml(&format!("{PYTHON}\n[production]\n")).unwrap();
        prod.check_mode_request(BuildMode::Production).unwrap();
        assert_eq!(prod.runtimes, ["runtime/python"]);
        assert!(prod.canonical_json().unwrap().starts_with(b"{"));
    }

    #[test]
    fn author_cannot_enable_nic_or_sneak_prod_settings() {
        for addition in ["net = true", "ssh = true", "[production]\nnet = true"] {
            assert_eq!(
                parse_toml(&format!("{PYTHON}\n{addition}\n")),
                Err(ComposableTomlError::Invalid),
                "{addition}"
            );
        }
        assert_eq!(
            parse_toml(&"x".repeat(64 * 1024 + 1)),
            Err(ComposableTomlError::Oversized)
        );
    }

    #[cfg(feature = "compiler")]
    #[test]
    fn v2_application_snapshots_into_a_deterministic_guest_layer() {
        use std::io::Read as _;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/main.py"), b"print('hello')\n").unwrap();
        let spec = parse_toml(&PYTHON.replace("path = \".\"", "path = \"src\"")).unwrap();
        let prepared = prepare_composable_application(&spec, project.path()).unwrap();
        prepared.reverify().unwrap();
        assert_eq!(
            prepared.archive_sha256(),
            prepare_composable_application(&spec, project.path())
                .unwrap()
                .archive_sha256()
        );
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(prepared.archive_bytes()));
        let mut found = false;
        for entry in tar.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap().as_ref() == std::path::Path::new("srv/app/main.py") {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"print('hello')\n");
                found = true;
            }
        }
        assert!(found, "application tar omitted the declared guest path");
    }

    #[cfg(feature = "compiler")]
    #[test]
    fn prepared_archive_refuses_staged_or_archive_mutation() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/main.py"), b"print('hello')\n").unwrap();
        let spec = parse_toml(&PYTHON.replace("path = \".\"", "path = \"src\"")).unwrap();
        let prepared = prepare_composable_application(&spec, project.path()).unwrap();
        std::fs::write(prepared.stage.root().join("srv/app/main.py"), b"tampered").unwrap();
        assert!(matches!(
            prepared.reverify(),
            Err(PrepareComposableError::Stage(
                ComposableStageError::StagedApplicationChanged
            ))
        ));

        let mut prepared = prepare_composable_application(&spec, project.path()).unwrap();
        prepared.archive.bytes[0] ^= 1;
        assert!(matches!(
            prepared.reverify(),
            Err(PrepareComposableError::ChangedArchive)
        ));
    }
}
