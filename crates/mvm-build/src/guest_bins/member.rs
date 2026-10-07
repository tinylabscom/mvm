//! What each archive member is, where it lives, and how it is checked.
//!
//! The member path spells its kind, so a consumer can install the archive by
//! layout alone:
//!
//! ```text
//!   <arch>/bin/<name>                 static guest executable
//!   <arch>/initramfs/mvm-guest-agent  the initramfs's static agent (PID 1)
//!   <arch>/lib/<libc>/<soname>        guest shared object, per libc
//!   sdk-py/mvm/<path>                 the in-guest Python SDK package
//! ```

use std::path::Path;

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;

/// The single binary the initramfs carries.
pub const INITRAMFS_AGENT_NAME: &str = "mvm-guest-agent";

/// Where the Python SDK package sits in the archive.
pub const PYTHON_SDK_PREFIX: &str = "sdk-py/mvm";

/// One archive member, by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestBinsMember {
    /// A static musl executable.
    Executable { arch: GuestArch, name: String },
    /// The size-tuned static agent the universal initramfs runs as `/init`.
    /// A different build from the overlay's agent, so a separate member.
    InitramfsAgent { arch: GuestArch },
    /// A shared object built against `libc`, named by the soname it installs as.
    SharedObject {
        arch: GuestArch,
        libc: GuestLibc,
        soname: String,
    },
    /// One file of the Python SDK, by its `/`-separated path inside the package.
    PythonSdk { relative: String },
}

/// Why a member could not be added or a member path not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MemberError {
    #[error("{0:?} is not a plain file name")]
    InvalidName(String),
    #[error("{0:?} is not a guest-bins member path")]
    UnknownLayout(String),
    #[error("{0} names no libc a shared object can be built for")]
    UnsupportedLibc(GuestLibc),
}

/// A plain file name: non-empty, no separator, not a dot entry.
pub(crate) fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\'])
}

impl GuestBinsMember {
    /// A static executable named `name`.
    pub fn executable(arch: GuestArch, name: &str) -> Result<Self, MemberError> {
        plain(name)?;
        Ok(Self::Executable {
            arch,
            name: name.to_string(),
        })
    }

    /// A `libc` shared object installed as `soname`.
    pub fn shared_object(
        arch: GuestArch,
        libc: GuestLibc,
        soname: &str,
    ) -> Result<Self, MemberError> {
        plain(soname)?;
        if libc.libc_soname().is_none() {
            return Err(MemberError::UnsupportedLibc(libc));
        }
        Ok(Self::SharedObject {
            arch,
            libc,
            soname: soname.to_string(),
        })
    }

    /// A Python SDK file at `relative` (`/`-separated) inside the package.
    pub fn python_sdk(relative: &str) -> Result<Self, MemberError> {
        if relative.is_empty() || !relative.split('/').all(is_plain_name) {
            return Err(MemberError::InvalidName(relative.to_string()));
        }
        Ok(Self::PythonSdk {
            relative: relative.to_string(),
        })
    }

    /// The archive-relative path.
    pub fn path(&self) -> String {
        match self {
            Self::Executable { arch, name } => format!("{arch}/bin/{name}"),
            Self::InitramfsAgent { arch } => format!("{arch}/initramfs/{INITRAMFS_AGENT_NAME}"),
            Self::SharedObject { arch, libc, soname } => format!("{arch}/lib/{libc}/{soname}"),
            Self::PythonSdk { relative } => format!("{PYTHON_SDK_PREFIX}/{relative}"),
        }
    }

    /// Read a member path back into its kind, refusing anything outside the
    /// layout — including any path a careless extractor could follow out of
    /// its destination.
    pub fn parse(path: &str) -> Result<Self, MemberError> {
        let unknown = || MemberError::UnknownLayout(path.to_string());
        if let Some(relative) = path
            .strip_prefix(PYTHON_SDK_PREFIX)
            .and_then(|rest| rest.strip_prefix('/'))
        {
            return Self::python_sdk(relative).map_err(|_| unknown());
        }
        let parts: Vec<&str> = path.split('/').collect();
        let arch = parts.first().and_then(|segment| canonical_arch(segment));
        let member = match (arch, parts.as_slice()) {
            (Some(arch), [_, "bin", name]) => Self::executable(arch, name),
            (Some(arch), [_, "initramfs", INITRAMFS_AGENT_NAME]) => {
                Ok(Self::InitramfsAgent { arch })
            }
            (Some(arch), [_, "lib", libc, soname]) => {
                let libc = canonical_libc(libc).ok_or_else(unknown)?;
                Self::shared_object(arch, libc, soname)
            }
            _ => Err(unknown()),
        };
        member.map_err(|_| unknown())
    }

    /// The tar mode the member is archived with.
    pub fn mode(&self) -> u32 {
        match self {
            Self::Executable { .. } | Self::InitramfsAgent { .. } => 0o755,
            Self::SharedObject { .. } | Self::PythonSdk { .. } => 0o644,
        }
    }

    /// Check `bytes` are what this kind of member must be. `source` names the
    /// file they were read from, for the error.
    pub fn validate(&self, bytes: &[u8], source: &Path) -> Result<(), String> {
        let result = match self {
            Self::Executable { arch, .. } | Self::InitramfsAgent { arch } => {
                crate::guest_elf::validate_static_guest_elf(bytes, source, *arch)
            }
            Self::SharedObject { arch, libc, .. } => {
                crate::guest_elf::validate_guest_shared_object(bytes, source, *arch, *libc)
            }
            // Pure Python source: nothing about its bytes is guest-specific.
            Self::PythonSdk { .. } => Ok(()),
        };
        result.map_err(|e| e.to_string())
    }
}

fn plain(name: &str) -> Result<(), MemberError> {
    if is_plain_name(name) {
        Ok(())
    } else {
        Err(MemberError::InvalidName(name.to_string()))
    }
}

/// `segment` as an architecture, only in the spelling the archive writes —
/// an alias such as `amd64` would read back as a different path.
fn canonical_arch(segment: &str) -> Option<GuestArch> {
    segment
        .parse::<GuestArch>()
        .ok()
        .filter(|arch| arch.to_string() == segment)
}

fn canonical_libc(segment: &str) -> Option<GuestLibc> {
    [GuestLibc::Glibc, GuestLibc::Musl]
        .into_iter()
        .find(|libc| libc.as_str() == segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_lives_under_its_own_prefix_and_reads_back() {
        let members = [
            (
                GuestBinsMember::executable(GuestArch::Aarch64, "mvm-setpriv").unwrap(),
                "aarch64/bin/mvm-setpriv",
            ),
            (
                GuestBinsMember::InitramfsAgent {
                    arch: GuestArch::X86_64,
                },
                "x86_64/initramfs/mvm-guest-agent",
            ),
            (
                GuestBinsMember::shared_object(GuestArch::X86_64, GuestLibc::Musl, "libcuda.so.1")
                    .unwrap(),
                "x86_64/lib/musl/libcuda.so.1",
            ),
            (
                GuestBinsMember::shared_object(
                    GuestArch::Aarch64,
                    GuestLibc::Glibc,
                    "libmvm_host_services.so",
                )
                .unwrap(),
                "aarch64/lib/glibc/libmvm_host_services.so",
            ),
            (
                GuestBinsMember::python_sdk("_broker/services.py").unwrap(),
                "sdk-py/mvm/_broker/services.py",
            ),
        ];
        for (member, path) in members {
            assert_eq!(member.path(), path);
            assert_eq!(GuestBinsMember::parse(path).unwrap(), member, "{path}");
        }
    }

    #[test]
    fn executables_are_archived_executable_and_the_rest_are_not() {
        let exe = GuestBinsMember::executable(GuestArch::X86_64, "mvm-ping").unwrap();
        let agent = GuestBinsMember::InitramfsAgent {
            arch: GuestArch::X86_64,
        };
        let lib =
            GuestBinsMember::shared_object(GuestArch::X86_64, GuestLibc::Glibc, "libcudart.so")
                .unwrap();
        let py = GuestBinsMember::python_sdk("host.py").unwrap();
        assert_eq!(exe.mode(), 0o755);
        assert_eq!(agent.mode(), 0o755);
        assert_eq!(lib.mode(), 0o644);
        assert_eq!(py.mode(), 0o644);
    }

    #[test]
    fn paths_outside_the_layout_are_refused() {
        for path in [
            "aarch64/mvm-guest-agent",
            "aarch64/bin/nested/mvm-ping",
            "aarch64/bin/..",
            "amd64/bin/mvm-ping",
            "riscv64/bin/mvm-ping",
            "x86_64/initramfs/mvm-ping",
            "x86_64/lib/unknown/libc.so",
            "x86_64/lib/bionic/libc.so",
            "x86_64/lib/glibc",
            "sdk-py/mvm",
            "sdk-py/mvm/../escape.py",
            "sdk-py/mvm//double.py",
            "sdk-py/other/x.py",
            "/aarch64/bin/mvm-ping",
            "",
        ] {
            assert!(
                matches!(
                    GuestBinsMember::parse(path),
                    Err(MemberError::UnknownLayout(_))
                ),
                "{path:?} must be refused"
            );
        }
    }

    #[test]
    fn constructors_refuse_names_that_would_escape_their_directory() {
        assert!(GuestBinsMember::executable(GuestArch::X86_64, "../escape").is_err());
        assert!(GuestBinsMember::executable(GuestArch::X86_64, "").is_err());
        assert!(
            GuestBinsMember::shared_object(GuestArch::X86_64, GuestLibc::Musl, "a/b.so").is_err()
        );
        assert!(GuestBinsMember::python_sdk("../x.py").is_err());
        assert!(GuestBinsMember::python_sdk("").is_err());
    }

    #[test]
    fn a_shared_object_needs_a_known_libc() {
        assert_eq!(
            GuestBinsMember::shared_object(GuestArch::X86_64, GuestLibc::Unknown, "libx.so"),
            Err(MemberError::UnsupportedLibc(GuestLibc::Unknown))
        );
    }
}
