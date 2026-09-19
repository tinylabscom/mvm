//! What this library tells the runtime about the process it was loaded into.
//!
//! Loaded into `python3` or `node`, the running executable is the interpreter.
//! Left alone, helper resolution would search the interpreter's directory for
//! the per-VM supervisors and endpoints, and any path that falls back to
//! running `mvmctl` would run the interpreter instead. So before the first
//! call reaches the runtime, the library declares that the process is a
//! library embedder, which makes every `mvmctl` spawn refuse, and declares its
//! own directory as the one holding the helper binaries. The release ships
//! them side by side.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Why the library could not describe the process to the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmbedderError {
    /// The dynamic loader could not say which file this library was loaded
    /// from.
    UnknownLibraryPath,
    /// The loader's path has no parent directory to hold the helpers.
    NoParentDirectory(PathBuf),
    /// The runtime refused the directory (for instance, another was declared
    /// first).
    Refused(String),
}

impl std::fmt::Display for EmbedderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownLibraryPath => {
                f.write_str("the dynamic loader did not report this library's path")
            }
            Self::NoParentDirectory(path) => write!(
                f,
                "the library path {} has no parent directory",
                path.display()
            ),
            Self::Refused(reason) => f.write_str(reason),
        }
    }
}

/// Make the declarations once per process, and report the same result to
/// every later call.
pub(crate) fn ensure_declared() -> Result<(), EmbedderError> {
    static DECLARED: OnceLock<Result<(), EmbedderError>> = OnceLock::new();
    DECLARED
        .get_or_init(|| {
            mvm_vmm::host::aux_bin::declare_library_embedder();
            let library = loaded_library_path().ok_or(EmbedderError::UnknownLibraryPath)?;
            let dir = helper_dir_for(&library)?;
            mvm_vmm::host::aux_bin::declare_host_binary_dir(dir)
                .map_err(|e| EmbedderError::Refused(e.to_string()))
        })
        .clone()
}

/// The directory holding the helper binaries for a library at `library`: the
/// library's own directory, made absolute against the working directory as it
/// is now, because the runtime refuses a relative one.
pub(crate) fn helper_dir_for(library: &Path) -> Result<PathBuf, EmbedderError> {
    let absolute = if library.is_absolute() {
        library.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| EmbedderError::Refused(format!("no working directory: {e}")))?
            .join(library)
    };
    absolute
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or(EmbedderError::NoParentDirectory(absolute.clone()))
}

/// The file the dynamic loader mapped this library from.
fn loaded_library_path() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    // Any address inside this library identifies it to the loader; the entry
    // point is one that is certain to be there.
    let address = crate::mvm_hostlib_call as *const () as *const libc::c_void;
    // SAFETY: `Dl_info` is a plain C struct of pointers and integers, for which
    // all-zero is a valid value, and `dladdr` only writes it.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: `address` points into this loaded object's text, and `info` is a
    // valid, writable `Dl_info` that outlives the call.
    let found = unsafe { libc::dladdr(address, &mut info) };
    if found == 0 || info.dli_fname.is_null() {
        return None;
    }
    // SAFETY: on success `dli_fname` is a NUL-terminated path owned by the
    // loader, valid for as long as the object stays loaded, and this library
    // is loaded while its own code runs.
    let name = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_helper_dir_is_the_library_s_own_directory() {
        assert_eq!(
            helper_dir_for(Path::new("/opt/mvm/lib/libmvm_hostlib.so")),
            Ok(PathBuf::from("/opt/mvm/lib"))
        );
    }

    /// A loader can report the path it was given, relative to the working
    /// directory at load time. The runtime refuses a relative directory.
    #[test]
    fn a_relative_library_path_resolves_against_the_working_directory() {
        let dir = helper_dir_for(Path::new("lib/libmvm_hostlib.so")).unwrap();
        assert!(dir.is_absolute(), "{}", dir.display());
        assert!(dir.ends_with("lib"), "{}", dir.display());
    }

    #[test]
    fn a_path_with_no_parent_is_refused() {
        assert!(matches!(
            helper_dir_for(Path::new("/")),
            Err(EmbedderError::NoParentDirectory(_))
        ));
    }

    /// The loader answers for code in this object, whatever file that is.
    #[test]
    fn the_loader_reports_where_this_code_was_loaded_from() {
        let path = loaded_library_path().expect("dladdr answers for our own symbol");
        assert!(path.exists(), "{}", path.display());
    }
}
