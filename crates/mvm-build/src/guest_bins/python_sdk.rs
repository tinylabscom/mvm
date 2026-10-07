//! The in-guest Python SDK package, as archive members.
//!
//! The runtime overlay carries `crates/mvm-sdk/sdks/python/mvm` at
//! `/sdk-py/mvm`. It is pure Python, so the archive carries the source files
//! themselves, once, for every architecture. Interpreter and tool caches are
//! left out by the same basename list the workspace build fingerprint and the
//! Nix workspace filter apply, so `__pycache__` written by a local test run
//! never reaches an image.

use std::path::{Path, PathBuf};

use super::GuestBinsError;
use super::member::GuestBinsMember;

/// The package directory, relative to the workspace root.
pub const PYTHON_SDK_SOURCE_DIR: &str = "crates/mvm-sdk/sdks/python/mvm";

/// Every shipped file under the package at `workspace_root`, as
/// `(member, source path)` in sorted order.
///
/// A symlink or other non-regular entry is refused rather than followed or
/// skipped: the archive carries regular files only, and a link here would
/// either smuggle bytes from outside the package or silently drop a module.
pub fn python_sdk_members(
    workspace_root: &Path,
) -> Result<Vec<(GuestBinsMember, PathBuf)>, GuestBinsError> {
    let root = workspace_root.join(PYTHON_SDK_SOURCE_DIR);
    let mut members = Vec::new();
    collect(&root, "", &mut members)?;
    if members.is_empty() {
        return Err(GuestBinsError::EmptyPythonSdk(root));
    }
    Ok(members)
}

fn collect(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(GuestBinsMember, PathBuf)>,
) -> Result<(), GuestBinsError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| GuestBinsError::NonRegularSource(entry.path()))?;
        if crate::pipeline::build_cache::EXCLUDED_BASENAMES.contains(&name) {
            continue;
        }
        let relative = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect(&entry.path(), &relative, out)?;
        } else if file_type.is_file() {
            let member = GuestBinsMember::python_sdk(&relative)?;
            out.push((member, entry.path()));
        } else {
            return Err(GuestBinsError::NonRegularSource(entry.path()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(root: &Path) -> PathBuf {
        let dir = root.join(PYTHON_SDK_SOURCE_DIR);
        std::fs::create_dir_all(dir.join("_broker/__pycache__")).unwrap();
        std::fs::write(dir.join("__init__.py"), "").unwrap();
        std::fs::write(dir.join("_broker/services.py"), "x = 1\n").unwrap();
        std::fs::write(
            dir.join("_broker/__pycache__/services.cpython-312.pyc"),
            "c",
        )
        .unwrap();
        dir
    }

    fn paths(members: &[(GuestBinsMember, PathBuf)]) -> Vec<String> {
        members.iter().map(|(m, _)| m.path()).collect()
    }

    #[test]
    fn the_package_files_are_members_and_interpreter_caches_are_not() {
        let tmp = tempfile::tempdir().unwrap();
        package(tmp.path());
        let members = python_sdk_members(tmp.path()).unwrap();
        assert_eq!(
            paths(&members),
            ["sdk-py/mvm/__init__.py", "sdk-py/mvm/_broker/services.py"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_package_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = package(tmp.path());
        std::os::unix::fs::symlink("/etc/passwd", dir.join("passwd.py")).unwrap();
        assert!(matches!(
            python_sdk_members(tmp.path()),
            Err(GuestBinsError::NonRegularSource(path)) if path.ends_with("passwd.py")
        ));
    }

    #[test]
    fn an_empty_package_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(PYTHON_SDK_SOURCE_DIR)).unwrap();
        assert!(matches!(
            python_sdk_members(tmp.path()),
            Err(GuestBinsError::EmptyPythonSdk(_))
        ));
    }

    /// The real package: every tracked module is shipped, and nothing but
    /// Python source is.
    #[test]
    fn the_workspace_package_ships_its_python_modules() {
        let workspace =
            crate::guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .expect("the test runs inside the mvm workspace");
        let members = python_sdk_members(&workspace).unwrap();
        let paths = paths(&members);
        assert!(paths.contains(&"sdk-py/mvm/__init__.py".to_string()));
        assert!(paths.iter().all(|p| p.ends_with(".py")), "{paths:?}");
    }
}
