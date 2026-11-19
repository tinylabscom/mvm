//! Directory policy for caller-selected output files.

use std::io;
use std::path::{Component, Path, PathBuf};

struct Step {
    directory: PathBuf,
    missing: bool,
}

struct Directories {
    target: PathBuf,
    steps: Vec<Step>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Destination {
    CallerOutput,
    PrivateDirectory,
}

/// Resolve existing directories without discarding missing directories traversed
/// before `..`. Those directories must exist for the original spelling to work.
fn directories(path: &Path) -> io::Result<Directories> {
    // Path::parent returns "" for a bare relative filename. Directory creation
    // historically treats that parent as the current directory.
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    let absolute = std::path::absolute(path)?;
    let mut target = PathBuf::new();
    let mut steps = Vec::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => target.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                target.pop();
            }
            Component::Normal(name) => {
                target.push(name);
                let missing = match std::fs::symlink_metadata(&target) {
                    Ok(_) => {
                        // Resolve symlinks before processing subsequent '..'.
                        // A dangling symlink is an error, not a missing directory.
                        target = std::fs::canonicalize(&target)?;
                        if !std::fs::metadata(&target)?.is_dir() {
                            return Err(io::Error::new(
                                io::ErrorKind::NotADirectory,
                                format!("{} is not a directory", target.display()),
                            ));
                        }
                        false
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                    Err(error) => return Err(error),
                };
                steps.push(Step {
                    directory: target.clone(),
                    missing,
                });
            }
        }
    }
    Ok(Directories { target, steps })
}

/// Create a caller-selected output parent without chmodding external directories.
///
/// Existing directories outside the resolved MVM home retain their permissions.
/// Within that home, repair the complete home-to-parent chain to private mode.
/// Relative paths and directory symlinks are resolved before classifying ownership;
/// missing components traversed before `..` are still created.
///
/// This follows directory symlinks like [`super::create_private_dir`]. It is a
/// trusted-host permission policy, not containment against concurrent path
/// replacement. It does not change the mode of the output file itself.
///
/// # Errors
///
/// Refuses unresolvable home/destination paths, dangling links, nondirectories,
/// permission errors and failed creation. Classification errors never fall back
/// to external creation.
pub fn create_output_parent(dir: impl AsRef<Path>) -> io::Result<()> {
    prepare_directory(dir.as_ref(), Destination::CallerOutput)
}

/// Create a dedicated private directory using resolved namespace ownership.
///
/// Unlike a caller-selected output parent, the target is private even outside
/// MVM home. Missing external traversal directories are created privately, but
/// existing external ancestors retain their modes. Relative paths, directory
/// symlinks and `..` retain filesystem meaning without chmodding escaped ancestors.
///
/// This shares the trusted-host, non-containment boundary of
/// [`create_output_parent`]; it does not change [`super::create_private_dir`].
///
/// # Errors
///
/// Returns classification, traversal, creation or permission-repair failures.
pub fn create_private_dir_resolved(dir: impl AsRef<Path>) -> io::Result<()> {
    prepare_directory(dir.as_ref(), Destination::PrivateDirectory)
}

fn prepare_directory(dir: &Path, destination: Destination) -> io::Result<()> {
    let home = directories(Path::new(&super::mvm_home()))?;
    let output = directories(dir)?;
    let touches_home = output.target.starts_with(&home.target)
        || output
            .steps
            .iter()
            .any(|step| step.directory.starts_with(&home.target));
    if touches_home {
        // Preserve even the configured home's missing-before-.. spelling.
        // Only missing external ancestors are created; existing ones retain modes.
        for step in &home.steps {
            if step.missing {
                crate::private_fs::ensure_private_dir(&step.directory)?;
            }
        }
        super::create_private_dir_under(&home.target, &home.target)?;
    }
    for step in output.steps {
        if step.directory.starts_with(&home.target) {
            super::create_private_dir_under(&home.target, &step.directory)?;
        } else if destination == Destination::PrivateDirectory
            && (step.missing || step.directory == output.target)
        {
            crate::private_fs::ensure_private_dir(&step.directory)?;
        } else if step.missing {
            // This path is resolved outside the owned namespace. The caller,
            // not MVM, owns its existing parents and their permission policy.
            std::fs::create_dir_all(&step.directory)?;
        }
    }
    if destination == Destination::PrivateDirectory {
        crate::private_fs::ensure_private_dir(&output.target)?;
    }
    // Recheck the original traversal, including directories before '..'. A
    // restrictive umask on an external intermediate can make that spelling
    // unsearchable even when the resolved final directory exists.
    let spelling = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    if !std::fs::metadata(spelling)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "output parent is not a directory",
        ));
    }
    if std::fs::canonicalize(spelling)? != output.target {
        return Err(io::Error::other("output parent changed during creation"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
