//! Canonical guest CPU architecture. `arm64` canonicalizes to
//! `aarch64`; `amd64` to `x86_64`. This is the single arch type —
//! it replaces `mvm-build`'s `runtime_overlay::Arch` and the stringly
//! `target_arch` fields (migrated in a later task).
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
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unsupported guest architecture: {0:?} (expected one of: x86_64/amd64, aarch64/arm64)")]
pub struct UnknownArch(pub String);

impl FromStr for GuestArch {
    type Err = UnknownArch;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept bare arch or `<arch>-linux`.
        let base = s.split('-').next().unwrap_or(s).trim().to_ascii_lowercase();
        match base.as_str() {
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
