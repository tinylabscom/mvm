//! Author-side machinery for composable attested addons (SDK port Phase 1b).
//!
//! Everything an addon **author** needs:
//!
//! - [`manifest`] — `addon.toml` types deriving `JsonSchema`. The
//!   committed schema (`schema/addon-manifest-v0.json`) is regenerated
//!   from these types by the `emit_addon_schema` binary that ships
//!   alongside this crate.
//! - [`lockfile`] — `mvm.lock` types and TOML round-trip. Lockfile
//!   integrity comes from per-entry sigstore-keyless signatures over
//!   the canonical artifact bytes, plus the git-commit signature on
//!   the lockfile blob as the file-level authenticity proof.
//! - [`validator`] — tree-sitter-nix-backed validator for hand-authored
//!   Nix bodies bundled with addons. v1 is parse-only (rejects malformed
//!   Nix); AST-level merging arrives with the in-VM addon tier.
//! - [`registry`] — registry client surface plus a directory-backed
//!   `LocalRegistry` (test / offline) and an `HttpRegistry` skeleton
//!   (real sigstore-keyless verification lands in a follow-up).
//! - [`archive`] — deterministic `.tar.gz` packaging of an addon
//!   directory: sorted entries, mtime = 0, normalized mode bits,
//!   gzip with no filename header.
//! - [`sbom`] — minimal SPDX 2.3 SBOM emission. Real dep-tree walking
//!   lands in a follow-up.
//! - [`verify`] — `mvm addon verify <ref>` reproducible-build check.
//!
//! The consumer-side IR shape (`AddonUse`, `AddonRef`, `AddonTier`,
//! `ThreatTier`) lives in `mvm-ir` and is re-exported through
//! `mvm_sdk::addon` for convenience.

pub mod archive;
pub mod lockfile;
pub mod manifest;
pub mod registry;
pub mod sbom;
pub mod validator;
pub mod verify;

pub use lockfile::{LocalLockfileEntry, Lockfile, LockfileEntry, RegistryLockfileEntry};
pub use manifest::{
    AddonExport, AddonManifest, AddonParam, AddonParamType, AddonSection, CredentialsKind,
    SeccompProfile, SecuritySection, TrustTier,
};

// Re-export the consumer-side IR shapes so authors can write
// `use mvm_sdk::addon::{AddonUse, AddonRef, ...}` rather than reaching
// across two crates.
pub use mvm_ir::{AddonRef, AddonTier, AddonUse, ThreatTier};
