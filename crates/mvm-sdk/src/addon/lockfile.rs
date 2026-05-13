//! `mvm.lock` — mvm-authored lockfile capturing resolved
//! addon-uses + their per-entry registry signatures.
//!
//! Distinct from the host-toolchain heuristic scanner over user-managed
//! lockfiles (`uv.lock`, `pnpm-lock.yaml`) — `mvm.lock` is structured
//! TOML the lockfile-author writes via `mvm addon lock`.
//!
//! Integrity model:
//! - **Per-entry**: registry-issued sigstore-keyless signatures over
//!   the canonical artifact bytes. Verified at lock time and at
//!   compile time.
//! - **Whole-file**: the git-commit signature on the lockfile blob is
//!   the file-level authenticity proof. Project policy enforces
//!   branch-protection + signed commits; mvm does not re-sign on
//!   update. CI checks: every entry's signature is valid; the commit
//!   touching the lockfile is signed by an allowed identity.

use serde::{Deserialize, Serialize};

/// Top-level lockfile structure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    /// Lockfile schema version. Independent of workload IR's
    /// `schema_version`. v1 is `"1"`.
    pub schema_version: String,
    /// One entry per addon-use (registry or local). Order is stable
    /// (alphabetical by `name`); rewriting the lockfile preserves
    /// order to keep git-diffs minimal.
    #[serde(rename = "addon", default)]
    pub addons: Vec<LockfileEntry>,
}

impl Default for Lockfile {
    fn default() -> Self {
        Self {
            schema_version: "1".to_string(),
            addons: vec![],
        }
    }
}

/// One lockfile entry — registry-resolved or local-path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LockfileEntry {
    Registry(RegistryLockfileEntry),
    Local(LocalLockfileEntry),
}

/// Entry for a registry-resolved addon. Carries the resolved version,
/// canonical-form sha256, signature bundle, and Rekor inclusion proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryLockfileEntry {
    /// Bare addon name (matches `[addon].name` in the manifest).
    pub name: String,
    /// Composition tier — `"separate"` at v1.
    pub tier: String,
    /// What the user originally wrote (a SemVer constraint or pinned
    /// version). Preserved so `mvm addon update` can re-resolve
    /// against the original intent.
    pub requested: String,
    /// What the registry returned (a concrete SemVer version).
    pub resolved: String,
    /// Canonical registry ref (e.g. `addons.mvm.io/postgres@16.1.0`).
    pub r#ref: String,
    /// sha256 over the canonical-form addon tarball bytes.
    pub sha256: String,
    /// sha256 over the canonical manifest bytes (subset of the
    /// signature payload). Lets consumers detect manifest-only drift
    /// independently of the tarball.
    pub exports_sha256: String,
    /// sha256 over the SPDX SBOM bytes.
    pub sbom_sha256: String,
    /// Rekor transparency-log entry index. Required for registry
    /// addons; blocks lock if missing or non-includable.
    pub rekor_log_index: u64,
    /// Sigstore-keyless signature bundle (cert + signature) over
    /// `sha256(canonical_manifest) || sha256(tarball) || sha256(sbom)`.
    /// Encoded as a single base64 blob; future versions may decompose
    /// into separate `cert` / `sig` fields. Verified against the
    /// registry's trust root at lock time and compile time.
    pub signature: String,
}

/// Entry for a local-path addon (development / unsafe). No signature;
/// content_sha256 is the only integrity check. `mvm addon publish`
/// rejects any workload that contains local-path entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalLockfileEntry {
    /// Bare addon name (must match the local manifest's `[addon].name`).
    pub name: String,
    /// Path relative to the workload manifest.
    pub path: String,
    /// sha256 over the canonical-form deterministic-archive bytes of
    /// the local addon directory. Re-hashed at compile time; mismatch
    /// → `E_ADDON_LOCAL_PATH_DRIFT`.
    pub content_sha256: String,
    /// Always empty for local entries. Present in the schema only so
    /// `LockfileEntry` round-trips uniformly.
    #[serde(default)]
    pub signature: String,
}

/// Header banner written by `mvm addon lock`. Reminds editors that the
/// lockfile is managed.
pub const LOCKFILE_HEADER: &str = "# mvm.lock — managed by mvm addon lock; do not hand-edit.\n";

/// Parse a `mvm.lock` from a string. The header banner is ignored (it's
/// a TOML comment).
pub fn parse(s: &str) -> Result<Lockfile, ParseError> {
    toml::from_str(s).map_err(ParseError::Toml)
}

/// Serialize a lockfile back to TOML, prefixed with the standard
/// banner. Output is deterministic given equal inputs.
pub fn to_toml(lockfile: &Lockfile) -> Result<String, ParseError> {
    let body = toml::to_string_pretty(lockfile).map_err(ParseError::Serialize)?;
    Ok(format!("{LOCKFILE_HEADER}{body}"))
}

#[derive(Debug)]
pub enum ParseError {
    Toml(toml::de::Error),
    Serialize(toml::ser::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml(e) => write!(f, "mvm.lock parse error: {e}"),
            Self::Serialize(e) => write!(f, "mvm.lock serialize error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lockfile() -> &'static str {
        r#"
schema_version = "1"

[[addon]]
kind = "registry"
name = "postgres"
tier = "separate"
requested = "16"
resolved = "16.1.0"
ref = "addons.mvm.io/postgres@16.1.0"
sha256 = "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
exports_sha256 = "789abc4567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
sbom_sha256 = "def9876543210fedcba0987654321fedcba0987654321fedcba0987654321fedc"
rekor_log_index = 12345678
signature = "MEUCIQDexample..."

[[addon]]
kind = "local"
name = "my-db"
path = "./addons/my-db"
content_sha256 = "fed0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
"#
    }

    #[test]
    fn parses_registry_and_local_entries() {
        let lock = parse(sample_lockfile()).expect("parse");
        assert_eq!(lock.schema_version, "1");
        assert_eq!(lock.addons.len(), 2);
        match &lock.addons[0] {
            LockfileEntry::Registry(reg) => {
                assert_eq!(reg.name, "postgres");
                assert_eq!(reg.resolved, "16.1.0");
                assert_eq!(reg.tier, "separate");
                assert_eq!(reg.rekor_log_index, 12345678);
            }
            other => panic!("expected Registry, got {other:?}"),
        }
        match &lock.addons[1] {
            LockfileEntry::Local(loc) => {
                assert_eq!(loc.name, "my-db");
                assert_eq!(loc.path, "./addons/my-db");
                assert!(loc.signature.is_empty());
            }
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let parsed = parse(sample_lockfile()).expect("parse");
        let emitted = to_toml(&parsed).expect("serialize");
        assert!(emitted.starts_with(LOCKFILE_HEADER));
        let reparsed = parse(&emitted).expect("re-parse");
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let bad = format!("{}\nbogus = true\n", sample_lockfile());
        let err = parse(&bad).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }
}
