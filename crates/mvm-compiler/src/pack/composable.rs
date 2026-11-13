//! Snapshot an authored application without invoking Nix or reading a runtime.

use std::path::{Path, PathBuf};

use mvm_contract::pack_spec::PackSource;
use mvm_contract::pack_spec_v2::{ComposablePackError, ComposablePackSpec};

use super::PackError;

/// Errors from staging the versioned, composable application input.
#[derive(Debug, thiserror::Error)]
pub enum ComposableStageError {
    #[error("invalid composable pack spec: {0}")]
    Spec(#[from] ComposablePackError),
    #[error("application snapshot failed: {0}")]
    Pack(#[from] PackError),
    #[error("staged application bytes changed after the source snapshot")]
    StagedApplicationChanged,
}

/// Private application tree with source and output digests for later locking.
#[derive(Debug)]
pub struct StagedComposableApplication {
    _directory: tempfile::TempDir,
    snapshot: PathBuf,
    root: PathBuf,
    source_sha256: String,
    output_sha256: String,
}

impl StagedComposableApplication {
    /// Guest-rooted tree; only the author's `/srv/app` files are present.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Source snapshot digest, including file modes and in-tree symlink targets.
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// Staged application tree digest, to compare before and after health boot.
    pub fn output_sha256(&self) -> &str {
        &self.output_sha256
    }

    /// Rehash held bytes before another producer copies or signs them.
    ///
    /// # Errors
    ///
    /// Refuses any changed source snapshot or composed application output.
    pub fn reverify(&self) -> Result<(), ComposableStageError> {
        let source = crate::source::rehash(&self.snapshot).map_err(PackError::Source)?;
        let output = crate::source::rehash(&self.root).map_err(PackError::Source)?;
        if source.tree_hash != self.source_sha256 || output.tree_hash != self.output_sha256 {
            return Err(ComposableStageError::StagedApplicationChanged);
        }
        Ok(())
    }
}

/// Freeze a v2 local source once, then copy only declared application paths.
///
/// This is candidate input only. A production build still requires a separate
/// exact resolved lock, authenticated layers, health boot and final signer.
///
/// # Errors
///
/// Refuses unsafe paths, escaping symlinks, missing files and changed snapshots.
pub fn stage_composable_application(
    spec: &ComposablePackSpec,
    spec_dir: &Path,
) -> Result<StagedComposableApplication, ComposableStageError> {
    spec.validate()?;
    let PackSource::Local { path } = &spec.source else {
        return Err(PackError::YoctoSourceNotNix.into());
    };
    let spec_root = spec_dir
        .canonicalize()
        .map_err(|source| PackError::SourceRoot {
            path: spec_dir.to_path_buf(),
            source,
        })?;
    let source = spec_root.join(path);
    let resolved = source
        .canonicalize()
        .map_err(|source| PackError::SourceRoot {
            path: spec_root.clone(),
            source,
        })?;
    if !resolved.starts_with(&spec_root) || (path != "." && resolved != source) {
        return Err(PackError::SourceEscape { path: path.clone() }.into());
    }
    let directory = tempfile::tempdir().map_err(PackError::Staging)?;
    let snapshot = directory.path().join("snapshot");
    let selected: Vec<String> = spec.copy.iter().map(|copy| copy.source.clone()).collect();
    let source_plan = crate::source::copy_selected_source(&resolved, &snapshot, &selected)
        .map_err(PackError::Source)?;
    let root = directory.path().join("application");
    super::app_tree::assemble_v2(spec, &snapshot, &root)?;
    let output_plan = crate::source::rehash(&root).map_err(PackError::Source)?;
    let staged = StagedComposableApplication {
        _directory: directory,
        snapshot,
        root,
        source_sha256: source_plan.tree_hash,
        output_sha256: output_plan.tree_hash,
    };
    staged.reverify()?;
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ComposablePackSpec {
        serde_json::from_value(serde_json::json!({
            "schema": "mvm.pack-spec/v2",
            "identity": {"name": "agent/example", "version": "1.0.0"},
            "target": "aarch64-linux",
            "source": {"kind": "local", "path": "src"},
            "runtimes": ["runtime/python"],
            "copy": [{"source": "main.py", "destination": "/srv/app/main.py"}],
            "entrypoint": ["/usr/bin/python3", "/srv/app/main.py"],
            "resources": {"cpu_cores": 1, "memory_mb": 256}
        }))
        .unwrap()
    }

    #[test]
    fn app_is_a_private_nix_free_snapshot_and_mutation_refuses() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/main.py"), b"print('hello')\n").unwrap();
        let staged = stage_composable_application(&spec(), project.path()).unwrap();
        assert_eq!(
            std::fs::read(staged.root().join("srv/app/main.py")).unwrap(),
            b"print('hello')\n"
        );
        staged.reverify().unwrap();
        std::fs::write(project.path().join("src/main.py"), b"changed").unwrap();
        staged.reverify().unwrap();
        std::fs::write(staged.root().join("srv/app/main.py"), b"changed").unwrap();
        assert!(matches!(
            staged.reverify(),
            Err(ComposableStageError::StagedApplicationChanged)
        ));
    }

    #[test]
    fn invalid_spec_and_changed_snapshot_have_distinct_refusals() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/main.py"), b"print('hello')\n").unwrap();
        let mut invalid = spec();
        invalid.entrypoint[0] = "python3".into();
        assert!(matches!(
            stage_composable_application(&invalid, project.path()),
            Err(ComposableStageError::Spec(ComposablePackError::Entrypoint))
        ));

        let staged = stage_composable_application(&spec(), project.path()).unwrap();
        std::fs::write(staged.snapshot.join("main.py"), b"changed").unwrap();
        assert!(matches!(
            staged.reverify(),
            Err(ComposableStageError::StagedApplicationChanged)
        ));
    }

    #[test]
    fn unrelated_files_do_not_enter_the_v2_snapshot_or_invalidate_its_digest() {
        let project = tempfile::tempdir().unwrap();
        let src = project.path().join("src");
        std::fs::create_dir_all(src.join("module")).unwrap();
        std::fs::write(src.join("main.py"), b"print('hello')\n").unwrap();
        std::fs::write(src.join("module/answer.py"), b"answer = 42\n").unwrap();
        std::fs::write(src.join("unused.txt"), b"not a build input").unwrap();
        let mut spec = spec();
        spec.copy.push(mvm_contract::pack_spec::CopyOperation {
            source: "module".into(),
            destination: "/srv/app/module".into(),
        });
        let first = stage_composable_application(&spec, project.path()).unwrap();
        assert!(!first.snapshot.join("unused.txt").exists());
        assert_eq!(
            std::fs::read(first.root().join("srv/app/module/answer.py")).unwrap(),
            b"answer = 42\n"
        );
        std::fs::write(src.join("unused.txt"), b"edited unrelated file").unwrap();
        let unchanged = stage_composable_application(&spec, project.path()).unwrap();
        assert_eq!(first.source_sha256(), unchanged.source_sha256());
        std::fs::write(src.join("module/answer.py"), b"answer = 43\n").unwrap();
        let changed = stage_composable_application(&spec, project.path()).unwrap();
        assert_ne!(first.source_sha256(), changed.source_sha256());
    }

    #[test]
    fn copy_path_glob_characters_are_literal() {
        let project = tempfile::tempdir().unwrap();
        let src = project.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("file[1].py"), b"literal").unwrap();
        std::fs::write(src.join("file1.py"), b"not selected").unwrap();
        let mut spec = spec();
        spec.copy[0].source = "file[1].py".into();
        let staged = stage_composable_application(&spec, project.path()).unwrap();
        assert_eq!(
            std::fs::read(staged.root().join("srv/app/main.py")).unwrap(),
            b"literal"
        );
        assert!(!staged.snapshot.join("file1.py").exists());
    }

    #[test]
    fn no_copies_stage_no_source_files_and_symlinked_parents_are_refused() {
        let project = tempfile::tempdir().unwrap();
        let src = project.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("unused.py"), b"unused").unwrap();
        let mut spec = spec();
        spec.copy.clear();
        let staged = stage_composable_application(&spec, project.path()).unwrap();
        assert_eq!(std::fs::read_dir(&staged.snapshot).unwrap().count(), 0);

        std::fs::create_dir(src.join("actual")).unwrap();
        std::fs::write(src.join("actual/main.py"), b"print('ok')").unwrap();
        std::os::unix::fs::symlink("actual", src.join("link")).unwrap();
        spec.copy.push(mvm_contract::pack_spec::CopyOperation {
            source: "link/main.py".into(),
            destination: "/srv/app/main.py".into(),
        });
        assert!(matches!(
            stage_composable_application(&spec, project.path()),
            Err(ComposableStageError::Pack(PackError::Source(_)))
        ));
    }

    #[test]
    fn source_path_cannot_escape_through_a_symlink() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("src")).unwrap();
        assert!(matches!(
            stage_composable_application(&spec(), project.path()),
            Err(ComposableStageError::Pack(PackError::SourceEscape { .. }))
        ));
    }
}
