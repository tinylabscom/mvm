//! Filtered source staging shared by producers and Unix builder runtimes.

use std::path::Path;

/// Build artifacts and local state which never enter a staged source tree.
const WORKSPACE_SNAPSHOT_SKIP: &[&str] = &[
    "target",
    ".build",
    "node_modules",
    ".direnv",
    ".cargo",
    "dist",
    ".astro",
    "dev-prebuilt",
    ".mvm-ci",
    ".mvm-test",
    "graphify-out",
    ".ur-seed-result",
    "nixos.qcow2",
    ".git",
    ".claude",
    ".worktrees",
    ".playwright-mcp",
    "keys",
    "result",
    "__pycache__",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
];

/// Copy a source tree, pruning local state at every depth.
///
/// The active mvm home is pruned too, wherever it sits. A home kept inside the
/// checkout (a worktree-local or per-run one) holds every cached image and the
/// running builder's own disks, and staging it would pack gigabytes into the
/// guest's input disk before the build starts.
///
/// Links are preserved on Unix, never dereferenced. Other hosts refuse links
/// rather than requiring link-creation privileges or reading host targets.
pub(crate) fn copy_dir_filtered(src: &Path, dst: &Path) -> std::io::Result<()> {
    let home = std::fs::canonicalize(mvm_core::config::mvm_home()).ok();
    copy_pruned(src, dst, home.as_deref())
}

fn copy_pruned(src: &Path, dst: &Path, home: Option<&Path>) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let raw = entry.file_name();
        let name = raw.to_string_lossy();
        if WORKSPACE_SNAPSHOT_SKIP.contains(&name.as_ref()) || name.starts_with("result-") {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&raw);
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            copy_link(&from, &to)?;
        } else if file_type.is_dir() {
            if home.is_some_and(|home| std::fs::canonicalize(&from).is_ok_and(|dir| dir == home)) {
                continue;
            }
            copy_pruned(&from, &to, home)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_link(from: &Path, to: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(std::fs::read_link(from)?, to)
}

#[cfg(not(unix))]
fn copy_link(from: &Path, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "source staging cannot preserve symbolic link {}",
            from.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_files_and_prunes_local_state_at_every_depth() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        for file in [
            "nested/source",
            "nested/target/object",
            ".git/config",
            "result-build",
        ] {
            let path = source.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"source").unwrap();
        }
        copy_dir_filtered(source.path(), destination.path()).unwrap();
        assert_eq!(
            std::fs::read(destination.path().join("nested/source")).unwrap(),
            b"source"
        );
        for path in ["nested/target", ".git", "result-build"] {
            assert!(!destination.path().join(path).exists());
        }
    }

    #[test]
    fn the_active_mvm_home_inside_the_tree_is_not_staged() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let home = source.path().join(".mvm-e2e-1-1-0");
        std::fs::create_dir_all(home.join("vms")).unwrap();
        std::fs::write(home.join("vms/disk.img"), b"gigabytes").unwrap();
        std::fs::write(source.path().join("flake.nix"), b"source").unwrap();
        env.set("MVM_HOME", &home);

        copy_dir_filtered(source.path(), destination.path()).unwrap();

        assert!(destination.path().join("flake.nix").exists());
        assert!(!destination.path().join(".mvm-e2e-1-1-0").exists());
    }

    #[test]
    fn missing_source_and_file_destination_return_errors() {
        let root = tempfile::tempdir().unwrap();
        assert!(copy_dir_filtered(&root.path().join("missing"), &root.path().join("out")).is_err());
        let file = root.path().join("file");
        std::fs::write(&file, b"untouched").unwrap();
        assert!(copy_dir_filtered(root.path(), &file).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_dangling_and_external_links_without_copying_targets() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, b"not source").unwrap();
        for (name, target) in [
            ("external", secret.as_path()),
            ("dangling", Path::new("absent")),
        ] {
            std::os::unix::fs::symlink(target, source.path().join(name)).unwrap();
        }
        copy_dir_filtered(source.path(), destination.path()).unwrap();
        assert_eq!(
            std::fs::read_link(destination.path().join("external")).unwrap(),
            secret
        );
        assert_eq!(
            std::fs::read_link(destination.path().join("dangling")).unwrap(),
            Path::new("absent")
        );
        drop(destination);
        assert_eq!(std::fs::read(secret).unwrap(), b"not source");
    }

    #[cfg(not(unix))]
    #[test]
    fn link_copy_refuses_before_reading_a_target() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("out");
        let error = copy_link(&root.path().join("absent"), &destination).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(!destination.exists());
    }
}
