//! Signed-bundle DTOs — the pure, wire-shape half of the portable image
//! bundle (`.mvmpkg`) contract.
//!
//! `KeyId`, `ArtifactRole`, `BundleArtifact`, `BundleResources`,
//! `VerityInfo`, `BundleManifest`, `PlanArtifact`, the schema/filename
//! consts, and the base64 signature helpers live here. The crypto (Ed25519,
//! SHA-256), filesystem, tar-archive, resolver, registry, and trust-store
//! logic — everything that reads or writes a real `.mvmpkg` archive — stays
//! in `mvm_core::plan::bundle`, which re-exports every type in this module
//! at its existing path. `KeyId::from_pubkey`/`from_identity` and
//! `BundleManifest::canonical_bytes` moved to `mvm-core` as free functions
//! (`key_id_from_pubkey`/`key_id_from_identity`/`canonical_manifest_bytes`)
//! because deriving a key_id or canonicalising a manifest needs `sha2`/`hex`,
//! which this `no_std` crate doesn't carry.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

/// Highest bundle-manifest schema version this build understands.
/// Verifiers fail closed on a future bump rather than silently
/// dropping fields they don't know about.
///
/// Bumped 1 → 2 when `BundleManifest` gained the optional
/// `resources: Option<BundleResources>` field. Older verifiers
/// `#[serde(deny_unknown_fields)]` would
/// refuse v2 bundles on the field alone, but the version sniff
/// runs first and surfaces a clear `UnsupportedSchema` error.
/// Newer verifiers reading a v1 bundle accept the missing field
/// via `#[serde(default)]` and fall back to operator-config
/// defaults at launch time.
pub const BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Filename inside the archive for the canonical-JSON manifest.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Filename inside the archive for the detached Ed25519 signature.
/// 64 raw bytes — no header, no encoding.
pub const SIGNATURE_FILENAME: &str = "manifest.sig";

/// Directory inside the archive that holds the actual artifact
/// bytes (kernel, rootfs, verity sidecar, ...).
pub const ARTIFACTS_DIR: &str = "artifacts";

/// Content-derived identifier for a publisher's Ed25519 key. Equals
/// `sha256(pubkey_bytes)` truncated to 32 hex characters.
///
/// `key_id` is the lookup token a consumer uses to find the matching
/// pubkey in its trust store. It is **not a substitute for the
/// pubkey itself**: verification always uses the full key loaded
/// from `~/.mvm/trusted-publishers/<key_id>.pub`. Truncation is for
/// filesystem readability, not cryptographic strength.
///
/// Derived from a pubkey or an identity string via
/// `mvm_core::plan::bundle::key_id_from_pubkey`/`key_id_from_identity` —
/// those need `sha2`/`hex`, which live in `mvm-core`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(pub String);

impl KeyId {
    /// Validation: 32 lowercase hex characters. Anything else
    /// indicates a tampered or malformed manifest.
    pub fn is_well_formed(&self) -> bool {
        self.0.len() == 32
            && self
                .0
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }
}

/// Role of an artifact inside a bundle. Verifiers + launchers use
/// this to find the kernel, rootfs, verity sidecar, etc. without
/// pinning to specific filenames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    /// Linux kernel image (`vmlinux`).
    Kernel,
    /// Root filesystem block image (ext4 or squashfs).
    Rootfs,
    /// dm-verity Merkle-hash sidecar paired with `Rootfs`.
    VerityHashSidecar,
    /// Firecracker base VM config JSON.
    FirecrackerBaseConfig,
    /// Initial ramdisk (NixOS stage-1 or similar).
    Initrd,
    /// Catch-all for backend-specific extras. The role consumer
    /// must inspect `name` to know what it's looking at.
    Other,
}

/// One file inside the bundle. The `path` is relative to the
/// archive root (e.g. `artifacts/vmlinux`). `sha256` is the
/// lowercase-hex digest of the file bytes — verifiers re-hash at
/// extract time and reject on mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleArtifact {
    pub name: String,
    pub role: ArtifactRole,
    /// Archive-relative path, forward-slash separated. The verifier
    /// rejects absolute paths, `..` traversal, and `\` separators.
    pub path: String,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    pub size_bytes: u64,
}

/// Resource expectations the bundle publisher recorded at build
/// time. Optional on the wire (`#[serde(default)]` via the parent
/// struct's `Option<BundleResources>`), present in v2+ bundles.
/// Old (`schema_version = 1`) bundles deserialise with `None` and
/// the template loader defaults to operator config.
///
/// Both fields are advisory: `mvmctl up --cpus / --memory`
/// overrides them. The point is to let a bundle ship with sensible
/// resource expectations baked in so dev-laptop users don't have
/// to remember the right values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleResources {
    /// vCPU count the workload was sized for at build time.
    pub vcpus: u32,
    /// Memory cap in MiB the workload was sized for at build time.
    pub mem_mib: u32,
}

/// dm-verity binding for the rootfs. Present when the workload was
/// built with `verifiedBoot = true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerityInfo {
    /// 64-char lowercase-hex Merkle-tree root hash. Baked into the
    /// kernel cmdline as `dm-mod.create=`.
    pub roothash: String,
    /// `name` of the `VerityHashSidecar` artifact inside this
    /// bundle. Verifier matches on `name`, not `path`, so a later
    /// re-layout of the archive doesn't break the binding.
    pub sidecar_artifact: String,
}

/// Top-level signed bundle manifest. Serialised as canonical JSON
/// (via `serde_json::to_vec`); the signed bytes are exactly those.
///
/// `deny_unknown_fields` keeps the wire format strict: a future
/// field added in v2 will fail to parse in a v1 verifier. The
/// `schema_version` sniff happens *after* signature check (same
/// pattern as `ExecutionPlan`), so an attacker who flips
/// `schema_version` doesn't slip in a v2 plan past a v1 build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u32,
    /// Human-readable name for the publisher (not authoritative —
    /// trust derives from `key_id` lookup, not from this string).
    pub publisher: String,
    /// Lookup token for the publisher's Ed25519 pubkey. The full
    /// pubkey lives at `~/.mvm/trusted-publishers/<key_id>.pub` on
    /// the consumer side.
    pub key_id: KeyId,
    /// Target architecture (`x86_64`, `aarch64`). Verifiers refuse
    /// to launch a bundle whose arch doesn't match the host.
    pub arch: String,
    /// Optional kernel version string, e.g. `6.6.39`. Surfaced in
    /// `mvmctl bundle inspect` and `mvmctl doctor`; not authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Optional flake profile name the bundle was built for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Optional human-readable workload label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_label: Option<String>,
    /// ISO-8601 timestamp the bundle was sealed at.
    pub created_at: String,
    /// Free-form metadata key/value pairs. Reserved for publisher
    /// annotations; verifiers must not interpret these.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Every artifact inside the archive. Order is preserved in the
    /// JSON for determinism; consumers find artifacts by `role` or
    /// `name`, not by index.
    pub artifacts: Vec<BundleArtifact>,
    /// dm-verity binding, when the rootfs was built verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verity: Option<VerityInfo>,
    /// Advisory resource expectations recorded by the publisher at
    /// build time. `Some(...)` in v2+ bundles; `None` for v1
    /// bundles (handled via `#[serde(default)]`). The template
    /// loader uses these to set defaults when `mvmctl up` doesn't
    /// pass `--cpus` / `--memory` explicitly. The claim-9 re-verify
    /// still re-hashes the field as part of the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<BundleResources>,
}

impl BundleManifest {
    /// Find an artifact by role. Returns the first match — manifests
    /// shouldn't carry two artifacts with the same role, but the
    /// schema doesn't enforce uniqueness so consumers should treat
    /// duplicates as undefined.
    pub fn find_by_role(&self, role: &ArtifactRole) -> Option<&BundleArtifact> {
        self.artifacts.iter().find(|a| &a.role == role)
    }

    /// Find an artifact by exact name.
    pub fn find_by_name(&self, name: &str) -> Option<&BundleArtifact> {
        self.artifacts.iter().find(|a| a.name == name)
    }
}

/// Pin from an `ExecutionPlan` to a specific signed bundle. Captures
/// the three quantities the supervisor needs to re-verify on admit:
///
/// 1. **`bundle_sha256`** — SHA-256 of the entire archive bytes. The
///    plan's pin is "I authorise launching this exact byte string."
/// 2. **`manifest_sig_base64`** — the publisher's signature over the
///    bundle's manifest. Held in the plan so the verifier can refuse
///    the launch without trusting whatever copy of the manifest the
///    archive on disk contains.
/// 3. **`key_id`** — the publisher's key_id. Lets admission reject
///    plans whose pinning publisher isn't in the local trust store
///    *before* opening the archive.
///
/// `serde(deny_unknown_fields)` keeps the wire format strict — a
/// future field added in v2 fails closed in older builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanArtifact {
    /// Lowercase-hex SHA-256 of the entire `.mvmpkg` archive.
    pub bundle_sha256: String,
    /// Base64-encoded 64-byte Ed25519 signature over the bundle's
    /// `manifest.json` bytes. Use [`signature_from_base64`] to decode.
    pub manifest_sig_base64: String,
    /// Publisher key_id the bundle was signed under.
    pub key_id: KeyId,
}

impl PlanArtifact {
    /// Construct from raw signature bytes + bundle hash + key_id.
    pub fn new(bundle_sha256: String, sig: &[u8; 64], key_id: KeyId) -> Self {
        Self {
            bundle_sha256,
            manifest_sig_base64: signature_to_base64(sig),
            key_id,
        }
    }

    /// Decode the base64-encoded signature back to raw bytes.
    /// Returns `None` when the field is malformed.
    pub fn signature_bytes(&self) -> Option<[u8; 64]> {
        signature_from_base64(&self.manifest_sig_base64)
    }
}

/// Base64-encode a signature for transport on a JSON wire (e.g.
/// inside an `ExecutionPlan`). Round-trips via [`signature_from_base64`].
pub fn signature_to_base64(sig: &[u8; 64]) -> String {
    B64.encode(sig)
}

/// Inverse of [`signature_to_base64`]. Returns `None` for malformed
/// input; the verifier surfaces this as `MalformedSignature`.
pub fn signature_from_base64(s: &str) -> Option<[u8; 64]> {
    let bytes = B64.decode(s).ok()?;
    bytes.as_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn well_formed_rejects_wrong_length_and_case() {
        assert!(!KeyId("abc".to_string()).is_well_formed());
        assert!(!KeyId("X".repeat(32)).is_well_formed());
        assert!(!KeyId("g".repeat(32)).is_well_formed());
    }

    #[test]
    fn signature_base64_round_trips() {
        let sig_bytes: [u8; 64] = core::array::from_fn(|i| i as u8);
        let s = signature_to_base64(&sig_bytes);
        let recovered = signature_from_base64(&s).unwrap();
        assert_eq!(recovered, sig_bytes);
    }

    #[test]
    fn plan_artifact_rejects_bad_base64_signature() {
        let pin = PlanArtifact {
            bundle_sha256: "0".repeat(64),
            manifest_sig_base64: "not-base64-!!".to_string(),
            key_id: KeyId("0".repeat(32)),
        };
        assert!(pin.signature_bytes().is_none());
    }

    #[test]
    fn bundle_schema_version_is_two() {
        // Pin the current version constant — bumps are deliberate;
        // a silent rev should trip this test.
        assert_eq!(BUNDLE_SCHEMA_VERSION, 2);
    }

    #[test]
    fn plan_artifact_deny_unknown_fields() {
        // Defence in depth: an attacker bumping the schema must
        // fail closed in older verifiers.
        let json = serde_json::json!({
            "bundle_sha256": "0".repeat(64),
            "manifest_sig_base64": "AA==",
            "key_id": "0".repeat(32),
            "extra_future_field": 42,
        });
        let result: Result<PlanArtifact, _> = serde_json::from_value(json);
        assert!(result.is_err(), "deny_unknown_fields must reject");
    }
}
