//! Side-effect-free host destination policy, not a reservation or permission
//! to publish. A future writer must recheck its own ownership and file policy.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

fn protected_host_roots() -> Result<Vec<PathBuf>> {
    let home = mvm_core::config::user_home_dir_strict()
        .context("user home is required to locate protected credential roots")?;
    let mut roots = vec![
        mvm_core::config::mvm_keys_dir(),
        mvm_core::config::mvm_audit_dir(),
    ];
    for name in [".ssh", ".gnupg", ".aws"] {
        roots.push(home.join(name));
    }
    Ok(roots)
}

// Resolve existing ancestors without creating storage. In particular a dangling
// symlink is an error, not an absent directory to create later.
fn resolve_root(path: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::canonicalize(path).context("resolving destination policy directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .context("destination policy directory has no parent")?;
            let name = path
                .file_name()
                .context("destination policy directory has no name")?;
            Ok(resolve_root(parent)?.join(name))
        }
        Err(error) => Err(error).context("inspecting destination policy directory"),
    }
}

fn validate_protected_destination(destination: &Path) -> Result<()> {
    for root in protected_host_roots()? {
        anyhow::ensure!(
            !destination.starts_with(resolve_root(&root)?),
            "destination is inside a protected directory"
        );
    }
    Ok(())
}

/// Validate a potential host-local receipt destination without creating,
/// opening for write, repairing, signing, or loading keys.
///
/// Missing parents may be represented in the returned path, but are not
/// created. This is only path policy preflight: it neither pins the namespace
/// nor guarantees that a later publication can or should succeed.
pub fn validate_destination(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving current directory")?
            .join(path)
    };
    let parent = absolute.parent().context("destination has no parent")?;
    let name = absolute
        .file_name()
        .context("destination must name a file")?;
    let destination = resolve_root(parent)?.join(name);
    validate_protected_destination(&destination)?;
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "destination must be a regular file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspecting destination"),
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn missing_parents_are_only_path_intent_and_never_initialize_storage() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let destination = home.path().join("missing/parents/receipt.json");
        assert!(
            validate_destination(&destination)
                .unwrap()
                .ends_with("missing/parents/receipt.json")
        );
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn absent_user_home_refuses_instead_of_substituting_the_state_root() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.remove("HOME");
        assert!(validate_destination(&home.path().join("receipt.json")).is_err());
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn protected_roots_refuse_before_creating_or_loading_any_keys() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let roots = protected_host_roots().unwrap();
        for root in roots {
            assert!(validate_destination(&root.join("receipt.json")).is_err());
        }
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn existing_regular_file_is_checked_without_reading_or_changing_its_bytes() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let path = home.path().join("existing");
        std::fs::write(&path, b"unchanged").unwrap();
        let before = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            validate_destination(&path).unwrap(),
            std::fs::canonicalize(&path).unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions(), before);
        assert!(validate_destination(&path.join("receipt")).is_err());
        assert!(validate_destination(home.path()).is_err());
        assert!(!mvm_core::config::mvm_keys_dir().exists());
    }

    #[cfg(unix)]
    #[test]
    fn aliases_and_dangling_links_do_not_bypass_protected_roots_or_create_parents() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir(&keys).unwrap();
        let alias = home.path().join("alias");
        symlink(&keys, &alias).unwrap();
        assert!(validate_destination(&alias.join("receipt")).is_err());
        assert_eq!(std::fs::read_dir(&keys).unwrap().count(), 0);
        let dangling = home.path().join("dangling");
        symlink(home.path().join("absent"), &dangling).unwrap();
        assert!(validate_destination(&dangling.join("receipt")).is_err());
        assert!(validate_destination(&dangling).is_err());
        assert!(!home.path().join("absent").exists());
        let file = home.path().join("file");
        std::fs::write(&file, b"original").unwrap();
        let link = home.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(validate_destination(&link).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_destination_refuses_without_opening_it() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let path = home.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(validate_destination(&path).is_err());
        assert!(!mvm_core::config::mvm_keys_dir().exists());
    }
}
