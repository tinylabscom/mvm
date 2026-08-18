//! Canonical guest CPU architecture. `arm64` canonicalizes to
//! `aarch64`; `amd64` to `x86_64`. This is the single arch type; its
//! `Display` form (`"aarch64"` / `"x86_64"`) is the canonical cache
//! directory-name segment that string-typed layers (e.g. the fs-layer
//! runtime-overlay cache in `mvm_fs::overlay`) consume.
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestArch {
    X86_64,
    Aarch64,
}

impl GuestArch {
    /// The Nix `system` string (`<arch>-linux`) used for flake attrs.
    pub fn nix_system(self) -> &'static str {
        match self {
            GuestArch::X86_64 => "x86_64-linux",
            GuestArch::Aarch64 => "aarch64-linux",
        }
    }
    /// The host's arch at compile time. Replaces `host_system_linux()`.
    ///
    /// Assumption: mvm only supports `x86_64` and `aarch64` hosts. A
    /// non-`x86_64` host is treated as `aarch64` *by design* — if a
    /// third arch (RISC-V, s390x, …) is ever supported, add a variant
    /// and a matching `cfg` arm here, or this silently returns the
    /// wrong answer.
    pub const fn host() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            GuestArch::X86_64
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            GuestArch::Aarch64
        }
    }

    /// Parse a manifest-declared architecture and require it to match this
    /// host.
    ///
    /// Fails closed on both a mismatch and an architecture this build has no
    /// variant for, so a bundle that declares something unrecognised is refused
    /// rather than admitted on the strength of `host()`'s non-x86_64 fallback.
    ///
    /// The message is deliberately subject-free — callers prepend whatever they
    /// are refusing, since the same comparison guards an admitted plan's pinned
    /// bundle and a registry bundle resolved at boot.
    pub fn require_host(declared: &str) -> Result<Self, HostArchMismatch> {
        let declared_arch = declared.parse::<Self>()?;
        let host = Self::host();
        if declared_arch == host {
            Ok(declared_arch)
        } else {
            Err(HostArchMismatch::Mismatch {
                declared: declared_arch,
                host,
            })
        }
    }
}

/// Why a declared architecture is not runnable on this host.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostArchMismatch {
    #[error("declares architecture {declared} but this host is {host}")]
    Mismatch {
        declared: GuestArch,
        host: GuestArch,
    },
    #[error("declares an architecture this build cannot run: {0}")]
    Unknown(#[from] UnknownArch),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unsupported guest architecture: {0:?} (expected one of: x86_64/amd64, aarch64/arm64)")]
pub struct UnknownArch(pub String);

impl FromStr for GuestArch {
    type Err = UnknownArch;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Trim the whole input first, then take the arch token before
        // any `-` (so `<arch>-linux` Nix systems parse too).
        let base = s.trim().split('-').next().unwrap_or(s).to_ascii_lowercase();
        match base.as_str() {
            // `x64` is the shorthand some Docker/Windows toolchains emit.
            "x86_64" | "amd64" | "x64" => Ok(GuestArch::X86_64),
            "aarch64" | "arm64" => Ok(GuestArch::Aarch64),
            _ => Err(UnknownArch(s.to_string())),
        }
    }
}

impl std::fmt::Display for GuestArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            GuestArch::X86_64 => "x86_64",
            GuestArch::Aarch64 => "aarch64",
        })
    }
}

#[cfg(test)]
mod tests {
    /// The host arch, and the other one, so these tests read the same on an
    /// x86_64 CI runner and an aarch64 dev machine.
    fn other_than_host() -> GuestArch {
        match GuestArch::host() {
            GuestArch::X86_64 => GuestArch::Aarch64,
            GuestArch::Aarch64 => GuestArch::X86_64,
        }
    }

    #[test]
    fn require_host_accepts_the_host_arch_and_its_aliases() {
        let host = GuestArch::host();
        assert_eq!(GuestArch::require_host(&host.to_string()), Ok(host));
        let alias = match host {
            GuestArch::X86_64 => "amd64",
            GuestArch::Aarch64 => "arm64",
        };
        assert_eq!(GuestArch::require_host(alias), Ok(host));
        // `<arch>-linux` Nix systems parse too.
        assert_eq!(GuestArch::require_host(host.nix_system()), Ok(host));
    }

    #[test]
    fn require_host_refuses_the_other_arch() {
        let other = other_than_host();
        assert_eq!(
            GuestArch::require_host(&other.to_string()),
            Err(HostArchMismatch::Mismatch {
                declared: other,
                host: GuestArch::host(),
            })
        );
    }

    /// Fails closed rather than falling through to `host()`, whose non-x86_64
    /// arm would otherwise read an unsupported arch as aarch64.
    #[test]
    fn require_host_refuses_an_architecture_this_build_does_not_know() {
        for declared in ["riscv64", "s390x", "", "aarch64_be"] {
            assert!(
                matches!(
                    GuestArch::require_host(declared),
                    Err(HostArchMismatch::Unknown(_))
                ),
                "{declared} should be refused as unknown"
            );
        }
    }

    #[test]
    fn the_mismatch_message_names_both_sides() {
        let msg = GuestArch::require_host(&other_than_host().to_string())
            .unwrap_err()
            .to_string();
        assert!(msg.contains("but this host is"), "{msg}");
        assert!(msg.contains(&GuestArch::host().to_string()), "{msg}");
    }

    use super::*;
    #[test]
    fn aliases_normalize() {
        assert_eq!("x86_64".parse::<GuestArch>().unwrap(), GuestArch::X86_64);
        assert_eq!("amd64".parse::<GuestArch>().unwrap(), GuestArch::X86_64);
        assert_eq!("aarch64".parse::<GuestArch>().unwrap(), GuestArch::Aarch64);
        assert_eq!("arm64".parse::<GuestArch>().unwrap(), GuestArch::Aarch64);
        assert!("riscv64".parse::<GuestArch>().is_err());
    }
    #[test]
    fn nix_system_suffixed_inputs_parse() {
        assert_eq!(
            "x86_64-linux".parse::<GuestArch>().unwrap(),
            GuestArch::X86_64
        );
        assert_eq!(
            "aarch64-linux".parse::<GuestArch>().unwrap(),
            GuestArch::Aarch64
        );
    }
    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(
            "  aarch64 ".parse::<GuestArch>().unwrap(),
            GuestArch::Aarch64
        );
        assert_eq!(
            " x86_64-linux\n".parse::<GuestArch>().unwrap(),
            GuestArch::X86_64
        );
    }
    #[test]
    fn nix_system_strings() {
        assert_eq!(GuestArch::X86_64.nix_system(), "x86_64-linux");
        assert_eq!(GuestArch::Aarch64.nix_system(), "aarch64-linux");
    }
    #[test]
    fn serde_roundtrips_lowercase() {
        let j = serde_json::to_string(&GuestArch::Aarch64).unwrap();
        assert_eq!(j, "\"aarch64\"");
        assert_eq!(
            serde_json::from_str::<GuestArch>(&j).unwrap(),
            GuestArch::Aarch64
        );
    }
}
