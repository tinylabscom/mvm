//! Find a program the way a shell would, without starting one.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// The first executable file `name` resolves to, or `None`.
///
/// A bare name is looked up in each `PATH` entry in order. An empty or
/// relative entry is taken relative to the working directory, as `execvp`
/// takes it, and a leading `~` in an entry is `$HOME`. A name
/// with a path separator is never searched for: it is that path, relative
/// to the working directory.
pub fn which(name: impl AsRef<OsStr>) -> Option<PathBuf> {
    search(
        Path::new(name.as_ref()),
        std::env::var_os("PATH").as_deref(),
        crate::config::user_home_dir_strict().ok().as_deref(),
    )
}

fn search(name: &Path, path_var: Option<&OsStr>, home: Option<&Path>) -> Option<PathBuf> {
    if name.components().count() > 1 {
        let candidate = std::path::absolute(name).ok()?;
        return is_executable(&candidate).then_some(candidate);
    }
    std::env::split_paths(path_var?)
        .flat_map(|dir| candidates(expand_tilde(dir, home).join(name)))
        .find(|candidate| is_executable(candidate))
}

fn expand_tilde(dir: PathBuf, home: Option<&Path>) -> PathBuf {
    let mut components = dir.components();
    match (components.next(), home) {
        (Some(Component::Normal(first)), Some(home)) if first == "~" => {
            home.join(components.as_path())
        }
        _ => dir,
    }
}

#[cfg(not(windows))]
fn candidates(path: PathBuf) -> impl Iterator<Item = PathBuf> {
    std::iter::once(path)
}

/// The path itself, then the path with each `PATHEXT` extension appended.
#[cfg(windows)]
fn candidates(path: PathBuf) -> impl Iterator<Item = PathBuf> {
    let extensions = std::env::var("PATHEXT").unwrap_or_default();
    let with_extension: Vec<PathBuf> = extensions
        .split(';')
        .filter(|extension| extension.starts_with('.'))
        .map(|extension| {
            let mut extended = path.clone().into_os_string();
            extended.push(extension);
            PathBuf::from(extended)
        })
        .collect();
    std::iter::once(path).chain(with_extension)
}

// shortcut: any execute bit counts, not whether this user may execute the
// file; ask the kernel (`access(2)`) if a caller ever needs that distinction.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tool(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\n").expect("write tool");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    fn joined(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs).expect("join PATH")
    }

    /// `dir` spelled relative to the working directory.
    fn relative_to_cwd(dir: &Path) -> PathBuf {
        let cwd = std::env::current_dir().expect("cwd");
        let up: PathBuf = cwd.components().skip(1).map(|_| "..").collect();
        up.join(dir.strip_prefix("/").expect("absolute temp dir"))
    }

    #[test]
    fn finds_the_first_executable_in_path_order() {
        let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        tool(second.path(), "mvm-tool", 0o755);
        let path = joined(&[first.path(), second.path()]);
        assert_eq!(
            search(Path::new("mvm-tool"), Some(&path), None),
            Some(second.path().join("mvm-tool"))
        );

        let earlier = tool(first.path(), "mvm-tool", 0o700);
        assert_eq!(
            search(Path::new("mvm-tool"), Some(&path), None),
            Some(earlier)
        );
    }

    #[test]
    fn a_missing_name_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = joined(&[dir.path()]);
        assert_eq!(search(Path::new("mvm-tool"), Some(&path), None), None);
    }

    #[test]
    fn a_file_without_an_execute_bit_is_skipped_for_a_later_executable() {
        let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        tool(first.path(), "mvm-tool", 0o644);
        let path = joined(&[first.path(), second.path()]);
        assert_eq!(search(Path::new("mvm-tool"), Some(&path), None), None);

        let executable = tool(second.path(), "mvm-tool", 0o755);
        assert_eq!(
            search(Path::new("mvm-tool"), Some(&path), None),
            Some(executable)
        );
    }

    #[test]
    fn a_directory_named_like_the_tool_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("mvm-tool")).unwrap();
        let path = joined(&[dir.path()]);
        assert_eq!(search(Path::new("mvm-tool"), Some(&path), None), None);
    }

    #[test]
    fn an_unset_or_empty_path_finds_nothing_outside_the_working_directory() {
        let name = Path::new("mvm-tool-that-is-not-in-the-working-directory");
        assert_eq!(search(name, None, None), None);
        assert_eq!(search(name, Some(OsStr::new("")), None), None);
    }

    #[test]
    fn a_relative_entry_is_taken_from_the_working_directory() {
        let dir = tempfile::tempdir().unwrap();
        tool(dir.path(), "mvm-tool", 0o755);
        let entry = relative_to_cwd(&dir.path().canonicalize().unwrap());
        assert!(entry.is_relative());
        assert_eq!(
            search(Path::new("mvm-tool"), Some(entry.as_os_str()), None),
            Some(entry.join("mvm-tool"))
        );
    }

    #[test]
    fn a_tilde_entry_is_the_home_directory() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("bin")).unwrap();
        let expected = tool(&home.path().join("bin"), "mvm-tool", 0o755);
        let path = OsStr::new("~/bin");
        assert_eq!(
            search(Path::new("mvm-tool"), Some(path), Some(home.path())),
            Some(expected)
        );
        assert_eq!(search(Path::new("mvm-tool"), Some(path), None), None);
    }

    #[test]
    fn a_name_with_a_separator_is_a_path_and_is_never_searched_for() {
        let dir = tempfile::tempdir().unwrap();
        let executable = tool(dir.path(), "mvm-tool", 0o755);
        let plain = tool(dir.path(), "mvm-data", 0o644);
        let path = joined(&[dir.path()]);
        assert_eq!(search(&executable, None, None), Some(executable));
        assert_eq!(search(&plain, Some(&path), None), None);
        assert_eq!(search(Path::new("bin/mvm-tool"), Some(&path), None), None);
    }
}
