//! Assembling the application tree from a verified source snapshot.
//!
//! Copy operations run in authored order against the snapshot, never the live
//! source, so what lands in the image is exactly what the lock describes. A
//! later copy may replace a file an earlier one wrote or merge into a directory
//! it created; replacing a file with a directory, or the reverse, is refused
//! rather than resolved. Symlinks are refused anywhere a copy reads: following
//! one would let the tree's shape depend on where it points.

use super::PackError;
use super::lower::{NPM_LOCKFILE, NPM_MANIFEST, app_relative};
use super::python::{UV_LOCKFILE, UV_MANIFEST};
use mvm_contract::ir::Dependencies;
use mvm_contract::pack_spec::PackSpec;
use std::fs;
use std::path::{Path, PathBuf};

/// Write the application tree for `spec` into `out`, reading only `snapshot`.
/// `dependencies` is the lowered declaration; its manifest and lockfile are
/// placed at the tree root. The factory installs npm dependencies from there,
/// and the uv pair keeps the application tree's own lockfile check, and the
/// project metadata the application may read, consistent with what was
/// resolved.
pub(super) fn assemble(
    spec: &PackSpec,
    dependencies: Option<&Dependencies>,
    snapshot: &Path,
    out: &Path,
) -> Result<(), PackError> {
    let root = canonical(snapshot)?;
    create_dir(out)?;
    for copy in &spec.copy {
        let source = contained_source(&root, &copy.source)?;
        let destination = out.join(app_relative(&copy.destination)?);
        copy_entry(&source, &destination, &copy.source, &copy.destination)?;
    }
    let files = match dependencies {
        Some(Dependencies::Node { .. }) => [NPM_MANIFEST, NPM_LOCKFILE],
        Some(Dependencies::Python { .. }) => [UV_MANIFEST, UV_LOCKFILE],
        Some(Dependencies::None) | None => return Ok(()),
    };
    for name in files {
        place_dependency_file(&root, out, name)?;
    }
    Ok(())
}

/// The snapshot path a copy source names, refused when it is missing, is a
/// symlink, or reaches outside the snapshot through a symlinked component.
fn contained_source(root: &Path, source: &str) -> Result<PathBuf, PackError> {
    let joined = if source == "." {
        root.to_path_buf()
    } else {
        root.join(source)
    };
    let metadata =
        fs::symlink_metadata(&joined).map_err(|_| copy_source(source, "does not exist"))?;
    if metadata.file_type().is_symlink() {
        return Err(copy_source(source, "is a symlink"));
    }
    let resolved = joined
        .canonicalize()
        .map_err(|_| copy_source(source, "cannot be resolved"))?;
    if resolved != joined {
        return Err(copy_source(source, "passes through a symlink"));
    }
    Ok(resolved)
}

fn copy_entry(
    source: &Path,
    destination: &Path,
    source_name: &str,
    destination_name: &str,
) -> Result<(), PackError> {
    let metadata = fs::symlink_metadata(source).map_err(|e| assemble_error(source, e))?;
    let kind = metadata.file_type();
    if kind.is_symlink() {
        return Err(copy_source(source_name, "contains a symlink"));
    }
    if kind.is_dir() {
        return copy_dir(source, destination, source_name, destination_name);
    }
    if !kind.is_file() {
        return Err(copy_source(
            source_name,
            "is not a regular file or directory",
        ));
    }
    copy_file(source, destination, destination_name)
}

fn copy_dir(
    source: &Path,
    destination: &Path,
    source_name: &str,
    destination_name: &str,
) -> Result<(), PackError> {
    match fs::symlink_metadata(destination) {
        Ok(existing) if !existing.is_dir() => {
            return Err(conflict(destination_name, "a file is already there"));
        }
        Ok(_) => {}
        Err(_) => create_dir(destination)?,
    }
    let mut entries = fs::read_dir(source)
        .map_err(|e| assemble_error(source, e))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| assemble_error(source, e))?;
    entries.sort();
    for name in entries {
        copy_entry(
            &source.join(&name),
            &destination.join(&name),
            source_name,
            destination_name,
        )?;
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path, destination_name: &str) -> Result<(), PackError> {
    if fs::symlink_metadata(destination).is_ok_and(|existing| existing.is_dir()) {
        return Err(conflict(destination_name, "a directory is already there"));
    }
    if let Some(parent) = destination.parent() {
        if fs::symlink_metadata(parent).is_ok_and(|existing| !existing.is_dir()) {
            return Err(conflict(destination_name, "a parent is a file"));
        }
        create_dir(parent)?;
    }
    // `fs::copy` carries the permission bits, so an executable stays one.
    fs::copy(source, destination).map_err(|e| assemble_error(destination, e))?;
    Ok(())
}

/// Place a dependency manifest or lockfile at the tree root. A copy that already put
/// different bytes there would install something other than what is locked.
fn place_dependency_file(root: &Path, out: &Path, name: &str) -> Result<(), PackError> {
    let source = contained_source(root, name)?;
    if !source.is_file() {
        return Err(copy_source(name, "is not a regular file"));
    }
    let destination = out.join(name);
    if destination.exists() {
        let same = fs::read(&source).map_err(|e| assemble_error(&source, e))?
            == fs::read(&destination).map_err(|e| assemble_error(&destination, e))?;
        return if same {
            Ok(())
        } else {
            Err(conflict(
                name,
                "a copy placed a different dependency file there",
            ))
        };
    }
    copy_file(&source, &destination, name)
}

fn canonical(path: &Path) -> Result<PathBuf, PackError> {
    path.canonicalize().map_err(|e| assemble_error(path, e))
}

fn create_dir(path: &Path) -> Result<(), PackError> {
    fs::create_dir_all(path).map_err(|e| assemble_error(path, e))
}

fn assemble_error(path: &Path, source: std::io::Error) -> PackError {
    PackError::Assemble {
        path: path.to_path_buf(),
        source,
    }
}

fn copy_source(source: &str, reason: &'static str) -> PackError {
    PackError::CopySource {
        source_path: source.to_string(),
        reason,
    }
}

fn conflict(destination: &str, reason: &'static str) -> PackError {
    PackError::CopyConflict {
        destination: destination.to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::test_support::spec;
    use mvm_contract::ir::NodeTool;
    use mvm_contract::pack_spec::CopyOperation;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn snapshot() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("hello.txt"), "hi\n").unwrap();
        fs::create_dir_all(dir.path().join("bin/sub")).unwrap();
        fs::write(dir.path().join("bin/run"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(
            dir.path().join("bin/run"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(dir.path().join("bin/sub/data"), "d").unwrap();
        dir
    }

    fn with_copies(copies: &[(&str, &str)]) -> PackSpec {
        let mut spec = spec();
        spec.copy = copies
            .iter()
            .map(|(source, destination)| CopyOperation {
                source: (*source).into(),
                destination: (*destination).into(),
            })
            .collect();
        spec
    }

    fn assemble_into(
        spec: &PackSpec,
        deps: Option<&Dependencies>,
        snap: &Path,
    ) -> Result<TempDir, PackError> {
        let out = TempDir::new().unwrap();
        assemble(spec, deps, snap, &out.path().join("app"))?;
        Ok(out)
    }

    #[test]
    fn copies_files_and_trees_to_their_destinations() {
        let snap = snapshot();
        let spec = with_copies(&[("hello.txt", "/app/greeting.txt"), ("bin", "/app/tools")]);
        let out = assemble_into(&spec, None, snap.path()).unwrap();
        let app = out.path().join("app");
        assert_eq!(
            fs::read_to_string(app.join("greeting.txt")).unwrap(),
            "hi\n"
        );
        assert_eq!(fs::read_to_string(app.join("tools/sub/data")).unwrap(), "d");
        let mode = fs::metadata(app.join("tools/run"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111, "executable bit survives");
        assert!(!app.join("hello.txt").exists(), "uncopied files stay out");
    }

    #[test]
    fn later_copies_replace_files_and_merge_directories() {
        let snap = snapshot();
        let spec = with_copies(&[("hello.txt", "/app/bin/run"), ("bin", "/app/bin")]);
        let out = assemble_into(&spec, None, snap.path()).unwrap();
        let app = out.path().join("app");
        assert_eq!(
            fs::read_to_string(app.join("bin/run")).unwrap(),
            "#!/bin/sh\n"
        );
        assert!(app.join("bin/sub/data").exists());
    }

    #[test]
    fn a_file_over_a_directory_is_a_conflict() {
        let snap = snapshot();
        let spec = with_copies(&[("bin", "/app/x"), ("hello.txt", "/app/x")]);
        assert!(matches!(
            assemble_into(&spec, None, snap.path()),
            Err(PackError::CopyConflict { .. })
        ));
        let spec = with_copies(&[("hello.txt", "/app/x"), ("bin", "/app/x")]);
        assert!(matches!(
            assemble_into(&spec, None, snap.path()),
            Err(PackError::CopyConflict { .. })
        ));
    }

    #[test]
    fn symlinks_are_refused_wherever_a_copy_reads() {
        let snap = snapshot();
        symlink("hello.txt", snap.path().join("alias")).unwrap();
        let spec = with_copies(&[("alias", "/app/alias")]);
        assert!(matches!(
            assemble_into(&spec, None, snap.path()),
            Err(PackError::CopySource {
                reason: "is a symlink",
                ..
            })
        ));

        symlink("bin", snap.path().join("bindir")).unwrap();
        let spec = with_copies(&[("bindir/run", "/app/run")]);
        assert!(matches!(
            assemble_into(&spec, None, snap.path()),
            Err(PackError::CopySource {
                reason: "passes through a symlink",
                ..
            })
        ));

        symlink("../hello.txt", snap.path().join("bin/sub/link")).unwrap();
        let spec = with_copies(&[("bin", "/app/bin")]);
        assert!(matches!(
            assemble_into(&spec, None, snap.path()),
            Err(PackError::CopySource {
                reason: "contains a symlink",
                ..
            })
        ));
    }

    #[test]
    fn a_missing_source_is_refused() {
        let snap = snapshot();
        let spec = with_copies(&[("nope.txt", "/app/nope.txt")]);
        assert!(matches!(
            assemble_into(&spec, None, snap.path()),
            Err(PackError::CopySource {
                reason: "does not exist",
                ..
            })
        ));
    }

    #[test]
    fn npm_files_land_at_the_tree_root() {
        let snap = snapshot();
        fs::write(snap.path().join(NPM_MANIFEST), "{}").unwrap();
        fs::write(snap.path().join(NPM_LOCKFILE), "{\"lockfileVersion\":3}").unwrap();
        let deps = Dependencies::Node {
            lockfile: NPM_LOCKFILE.into(),
            tool: NodeTool::Npm,
        };
        let spec = with_copies(&[("hello.txt", "/app/hello.txt")]);
        let out = assemble_into(&spec, Some(&deps), snap.path()).unwrap();
        assert!(out.path().join("app").join(NPM_MANIFEST).is_file());
        assert!(out.path().join("app").join(NPM_LOCKFILE).is_file());

        let spec = with_copies(&[("hello.txt", "/app/package.json")]);
        assert!(matches!(
            assemble_into(&spec, Some(&deps), snap.path()),
            Err(PackError::CopyConflict { .. })
        ));
    }

    #[test]
    fn uv_files_land_at_the_tree_root() {
        let snap = snapshot();
        fs::write(snap.path().join(UV_MANIFEST), "[project]\n").unwrap();
        fs::write(snap.path().join(UV_LOCKFILE), "version = 1\n").unwrap();
        let deps = Dependencies::Python {
            lockfile: UV_LOCKFILE.into(),
            tool: mvm_contract::ir::PythonTool::Uv,
        };
        let spec = with_copies(&[("hello.txt", "/app/hello.txt")]);
        let out = assemble_into(&spec, Some(&deps), snap.path()).unwrap();
        assert!(out.path().join("app").join(UV_MANIFEST).is_file());
        assert!(out.path().join("app").join(UV_LOCKFILE).is_file());
        assert!(!out.path().join("app").join(NPM_MANIFEST).exists());
    }
}
