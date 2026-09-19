//! What a locally built image is keyed on.
//!
//! One key per build output: the two checkouts it was built from, the output
//! itself (role and flake attribute), the guest architecture, the toolchain
//! pinned for the host binaries, and the flake locks the role evaluates.
//!
//! Every input the key names is also covered by one of the two checkout
//! identities, since the toolchain pins and the locks are tracked files. They
//! are named separately anyway, so that an entry's recorded key says which
//! inputs it was built from rather than leaving a reader to reconstruct them
//! from two commits.
//!
//! Paths are deliberately not part of the key. Two worktree pairs at the same
//! commits and the same working-tree state build the same bytes, so they share
//! the entry.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use mvm_core::arch::GuestArch;
use mvm_core::image_set::LocalCheckouts;
use mvm_core::packs::Sha256Hex;
use serde::{Deserialize, Serialize};

use super::LocalImageCacheError;
use crate::embed_toolchain::try_read_pinned_toolchain;
use crate::image_source::LocalImageCheckout;
use crate::image_source::local_set::open_mvm_checkout;

/// Prefixed to the serialized key before hashing, so a key digest cannot equal
/// the digest of anything else the cache root holds, whatever its bytes.
const KEY_DOMAIN: &[u8] = b"mvm local-dev image cache key v1\n";

/// The toolchain file every mvm checkout pins its compiler with.
const RUST_TOOLCHAIN_FILE: &str = "rust-toolchain.toml";

/// A buildable output family of an image checkout: one of its image
/// directories, or the kernel flake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageBuildRole {
    BuilderVm,
    DefaultTenant,
    RuntimeOverlay,
    Initramfs,
    Kernel,
}

impl ImageBuildRole {
    pub const ALL: [Self; 5] = [
        Self::BuilderVm,
        Self::DefaultTenant,
        Self::RuntimeOverlay,
        Self::Initramfs,
        Self::Kernel,
    ];

    /// The name the image checkout uses for the role: its directory under
    /// `images/`, or `kernel`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BuilderVm => "builder-vm",
            Self::DefaultTenant => "default-tenant",
            Self::RuntimeOverlay => "runtime-overlay",
            Self::Initramfs => "initramfs",
            Self::Kernel => "kernel",
        }
    }

    /// The flake locks, relative to the image checkout's root, that the role's
    /// evaluation reads. The kernel is a flake of its own; every image role
    /// evaluates through the root flake.
    #[must_use]
    pub const fn flake_locks(self) -> &'static [&'static str] {
        match self {
            Self::Kernel => &["kernel/flake.lock"],
            _ => &["flake.lock"],
        }
    }
}

impl fmt::Display for ImageBuildRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ImageBuildRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.name() == s)
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|role| role.name()).collect();
                format!("unknown image role `{s}` (one of {})", names.join(", "))
            })
    }
}

/// A flake attribute name under a role: one segment, so it can never select
/// something outside the role it is paired with.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FlakeAttr(String);

impl FlakeAttr {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let well_formed = !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            && !value.contains("..");
        if well_formed {
            Ok(Self(value))
        } else {
            Err(format!(
                "`{value}` is not a flake attribute name (one segment of letters, digits, \
                 `-`, `_` and `.`)"
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FlakeAttr {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FlakeAttr> for String {
    fn from(attr: FlakeAttr) -> Self {
        attr.0
    }
}

impl fmt::Display for FlakeAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One output of an image checkout: a role and the attribute under it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageBuildTarget {
    pub role: ImageBuildRole,
    pub attr: FlakeAttr,
}

impl fmt::Display for ImageBuildTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.role, self.attr)
    }
}

/// The toolchain an mvm checkout pins for the binaries built outside Nix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainPins {
    pub rust_toolchain_sha256: Sha256Hex,
    pub rust: String,
    pub zig: String,
    pub cargo_zigbuild: String,
    /// The Rust target the host binaries are built for on this architecture.
    pub target: String,
}

/// The digest of one flake lock the role evaluates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlakeLockDigest {
    /// Relative to the image checkout's root.
    pub path: String,
    pub sha256: Sha256Hex,
}

/// Everything one locally built output depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalImageCacheKey {
    pub checkouts: LocalCheckouts,
    pub target: ImageBuildTarget,
    pub arch: GuestArch,
    pub toolchain: ToolchainPins,
    pub flake_locks: Vec<FlakeLockDigest>,
}

/// What a key is derived from.
#[derive(Debug, Clone, Copy)]
pub struct KeyInputs<'a> {
    pub images: &'a LocalImageCheckout,
    pub mvm_checkout: &'a Path,
    pub target: &'a ImageBuildTarget,
    pub arch: GuestArch,
}

impl LocalImageCacheKey {
    /// Read every input of `inputs.target` as it is now.
    ///
    /// The image selection is re-verified first, so a key is never derived
    /// from a checkout that moved since it was selected.
    pub fn derive(inputs: &KeyInputs<'_>) -> Result<Self, LocalImageCacheError> {
        inputs.images.reverify()?;
        let (mvm_root, mvm) = open_mvm_checkout(inputs.mvm_checkout)?;
        let toolchain = toolchain_pins(&mvm_root, inputs.arch)?;
        let flake_locks = inputs
            .target
            .role
            .flake_locks()
            .iter()
            .map(|lock| {
                Ok(FlakeLockDigest {
                    path: (*lock).to_string(),
                    sha256: digest_regular_file(inputs.images.root(), lock)?,
                })
            })
            .collect::<Result<Vec<_>, LocalImageCacheError>>()?;
        Ok(Self {
            checkouts: LocalCheckouts {
                images: inputs.images.identity().clone(),
                mvm,
            },
            target: inputs.target.clone(),
            arch: inputs.arch,
            toolchain,
            flake_locks,
        })
    }

    /// The key's digest, which names its cache entry.
    #[must_use]
    pub fn digest(&self) -> Sha256Hex {
        let mut bytes = KEY_DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(self).expect("a cache key always serializes"));
        Sha256Hex::from_bytes(&bytes)
    }
}

fn toolchain_pins(mvm_root: &Path, arch: GuestArch) -> Result<ToolchainPins, LocalImageCacheError> {
    let rust_toolchain_sha256 = digest_regular_file(mvm_root, RUST_TOOLCHAIN_FILE)?;
    let pin = try_read_pinned_toolchain(mvm_root, &arch.to_string()).map_err(|detail| {
        LocalImageCacheError::Input {
            path: mvm_root.join("Cargo.toml"),
            detail,
        }
    })?;
    Ok(ToolchainPins {
        rust_toolchain_sha256,
        rust: pin.rust,
        zig: pin.zig,
        cargo_zigbuild: pin.cargo_zigbuild,
        target: pin.target,
    })
}

/// The digest of `relative` under `root`, which must be a regular file there:
/// a link would key the entry on bytes the checkout's identity does not cover.
fn digest_regular_file(root: &Path, relative: &str) -> Result<Sha256Hex, LocalImageCacheError> {
    let path = root.join(relative);
    let failed = |detail: String| LocalImageCacheError::Input {
        path: path.clone(),
        detail,
    };
    let meta = std::fs::symlink_metadata(&path).map_err(|e| failed(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(failed("not a regular file".to_string()));
    }
    let bytes = std::fs::read(&path).map_err(|e| failed(e.to_string()))?;
    Ok(Sha256Hex::from_bytes(&bytes))
}
