//! Errors returned by this crate, plus host-side libkrun install probing.
//!
//! [`is_available`], [`install_hint`], and [`install_paths`] answer "is
//! libkrun installed on this host, and if not, what should the user do
//! about it" — the precondition every entry point in this crate checks
//! before touching the FFI.

use std::path::Path;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// libkrun is not installed on the host (no shared library found at
    /// any of the standard locations checked by [`is_available`]).
    NotInstalled {
        /// Suggested install command for the user.
        install_hint: &'static str,
    },
    /// Built without the `libkrun-sys` feature — the FFI bindings are
    /// compiled out so [`start`](crate::start) / [`stop`](crate::stop)
    /// cannot dispatch. Rebuild with `--features libkrun-sys` on a host
    /// where libkrun is installed.
    NotYetWired {
        /// Tracking issue / plan reference.
        tracking: &'static str,
    },
    /// libkrun returned a negative errno from one of its C functions.
    /// The value is the raw return code (which libkrun documents as
    /// `-EINVAL`, `-ENOMEM`, etc. for most calls).
    Krun(i32),
    /// A path or string argument contained an interior NUL byte or
    /// was not representable as UTF-8 / a C string.
    InvalidCString,
    /// Filesystem I/O failure while setting up the supervisor's per-VM
    /// state directory or PID file. Carries a free-form context
    /// string rather than the raw `io::Error` so the `PartialEq`/`Eq`
    /// derives on `Error` keep working.
    Io {
        /// Operation + path + underlying message, formatted by the
        /// caller. E.g. `create_dir_all /Users/x/.mvm/vms/foo: permission denied`.
        context: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled { install_hint } => {
                write!(f, "libkrun is not installed on this host. {install_hint}")
            }
            Self::NotYetWired { tracking } => write!(
                f,
                "libkrun FFI is not compiled into this build (tracking: {tracking}). \
                 Rebuild with `--features libkrun-sys` on a host with libkrun installed."
            ),
            Self::Krun(rc) => write!(f, "libkrun call failed with rc {rc}"),
            Self::InvalidCString => write!(
                f,
                "argument contained an interior NUL byte or non-UTF-8 path"
            ),
            Self::Io { context } => write!(f, "supervisor I/O error: {context}"),
        }
    }
}

impl std::error::Error for Error {}

/// Detect whether libkrun is installed on the host by probing for the
/// shared library at the standard install locations.
///
/// **Not the same as "is functional"** — even if `is_available()`
/// returns `true`, a build without the `libkrun-sys` feature will still
/// return [`Error::NotYetWired`] from [`start`](crate::start). Treat
/// this as a precondition probe: if it returns `false`, point the user
/// at [`install_hint`].
pub fn is_available() -> bool {
    install_paths().iter().any(|p| Path::new(p).exists())
}

/// Human-readable install hint used in error messages and `mvmctl
/// doctor` output. Caller-platform-aware so users see the right
/// command for their OS.
pub const fn install_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Install via Homebrew: `brew install libkrun`."
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "Install via your distro package manager (e.g. `apt install libkrun-dev` \
         on Debian/Ubuntu, `dnf install libkrun-devel` on Fedora) or build from \
         source: https://github.com/containers/libkrun"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "Install via your distro package manager or build from source: \
         https://github.com/containers/libkrun"
    }
    #[cfg(target_os = "windows")]
    {
        "libkrun is not supported on Windows. Use --hypervisor docker \
         or install WSL2 and run mvm inside a Linux distro."
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "libkrun is not supported on this platform."
    }
}

/// Standard filesystem locations checked by [`is_available`]. Order is
/// "most likely first" so the predicate short-circuits on the typical
/// developer install.
///
/// Derived from `mvm_core::platform::LIBKRUN_LIB_PATHS` — the canonical
/// source of truth. Both sides are structurally identical; use the const
/// directly when a slice suffices, this function when a `Vec` is needed.
pub fn install_paths() -> Vec<&'static str> {
    mvm_core::platform::LIBKRUN_LIB_PATHS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_paths_are_platform_specific() {
        let paths = install_paths();
        #[cfg(target_os = "macos")]
        assert!(paths.iter().any(|p| p.ends_with(".dylib")));
        #[cfg(target_os = "linux")]
        assert!(paths.iter().any(|p| p.ends_with(".so")));
        #[cfg(target_os = "windows")]
        assert!(paths.is_empty());
    }

    #[test]
    fn install_hint_is_non_empty() {
        // All platforms produce *some* hint, even Windows ("not supported").
        assert!(!install_hint().is_empty());
    }

    #[test]
    fn error_display_messages_are_actionable() {
        let not_installed = Error::NotInstalled {
            install_hint: "brew install libkrun",
        };
        let not_wired = Error::NotYetWired {
            tracking: "plan 57",
        };
        let krun_err = Error::Krun(-22);
        let invalid = Error::InvalidCString;
        // Each variant produces a non-empty, distinct message that
        // names what to do next.
        assert!(format!("{not_installed}").contains("brew install"));
        assert!(format!("{not_wired}").contains("plan 57"));
        assert!(format!("{krun_err}").contains("-22"));
        assert!(format!("{invalid}").contains("NUL"));
    }

    /// Assert that `install_paths()` is correctly wired to
    /// `mvm_core::platform::LIBKRUN_LIB_PATHS` — same entry count and
    /// matching first entry. Catches any future refactor that breaks the
    /// delegation without altering the public function signature.
    #[test]
    fn install_paths_matches_core_const() {
        let paths = install_paths();
        let canonical = mvm_core::platform::LIBKRUN_LIB_PATHS;
        assert_eq!(
            paths.len(),
            canonical.len(),
            "install_paths() entry count differs from LIBKRUN_LIB_PATHS"
        );
        if !canonical.is_empty() {
            assert_eq!(
                paths[0], canonical[0],
                "install_paths()[0] differs from LIBKRUN_LIB_PATHS[0]"
            );
        }
    }
}
