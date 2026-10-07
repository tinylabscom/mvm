//! Signed-bundle DTOs — the pure, wire-shape half of the portable image
//! bundle (`.mvmpkg`) contract.
//!
//! `KeyId`, `ArtifactRole`, `BundleArtifact`, `BundleMember`,
//! `BundleSecurityPosture`, `BundleResources`, `VerityInfo`,
//! `BundleManifest`, `PlanArtifact`, the schema/filename consts, the size
//! caps, and the base64 signature helpers live here. The crypto (Ed25519,
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

use crate::plan::types::BuildProvenance;
use crate::policy::security::AgentProfile;

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
/// Bumped 2 → 3 when `BundleManifest` gained backend-neutral member
/// classes. The first class embeds one complete image-set manifest and binds
/// its member artifacts to ordinary bundle artifacts. Older bundles remain
/// readable because `members` defaults to an empty list.
pub const BUNDLE_SCHEMA_VERSION: u32 = 3;

/// Filename inside the archive for the canonical-JSON manifest.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Filename inside the archive for the detached Ed25519 signature.
/// 64 raw bytes — no header, no encoding.
pub const SIGNATURE_FILENAME: &str = "manifest.sig";

/// Directory inside the archive that holds the actual artifact
/// bytes (kernel, rootfs, verity sidecar, ...).
pub const ARTIFACTS_DIR: &str = "artifacts";

/// `artifactType` of an image-registry manifest that carries one signed
/// bundle. The manifest's config is the empty descriptor and its only layer
/// is the `.mvmpkg` archive, which already holds the signature.
pub const BUNDLE_ARTIFACT_TYPE: &str = "application/vnd.mvm.bundle.v1";

/// Media type of that layer: the `.mvmpkg` archive byte for byte, plain tar.
pub const BUNDLE_LAYER_MEDIA_TYPE: &str = "application/vnd.mvm.bundle.v1.tar";

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

/// Largest single artifact a bundle may carry (2 GiB). Verification refuses a
/// manifest that declares more, and an archive entry whose header claims more,
/// before reading its bytes.
pub const MAX_BUNDLE_ENTRY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Largest total payload a bundle may carry (4 GiB), summed over every archive
/// entry. Any workload image fits well inside it; an archive past it is
/// refused before it can exhaust the host's memory or disk.
pub const MAX_BUNDLE_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Longest kernel command line a [`BundleMember::KernelCmdline`] may carry.
/// Matches the arm64 kernel's `COMMAND_LINE_SIZE`, the larger of the two
/// supported guest architectures.
pub const MAX_KERNEL_CMDLINE_BYTES: usize = 2048;

/// A typed, backend-neutral member carried by a portable bundle.
///
/// Member classes describe how a group of ordinary [`BundleArtifact`] files
/// is interpreted, or carry a small signed declaration about the workload.
/// They never name a host backend. A future sealed-checkpoint class can
/// therefore evolve independently without changing the image-set contract or
/// duplicating its artifact bytes.
///
/// A bundle carries at most one member of each declaration class
/// (`kernel_cmdline`, `security_posture`, `build_provenance`); verification
/// refuses a second one rather than picking between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleMember {
    /// A complete `mvm_core::image_set::ImageSetManifest`. The named bundle
    /// artifact contains the JSON manifest; every artifact named by that
    /// manifest must also appear as an ordinary bundle artifact with the same
    /// name, size, and SHA-256.
    EmbeddedImageSet { manifest_artifact: String },
    /// The kernel command line the publisher built and tested the workload
    /// with. Advisory: the launcher derives the command line it boots with,
    /// so a bundle cannot use this to switch off dm-verity or redirect init.
    /// Bounded by [`MAX_KERNEL_CMDLINE_BYTES`], printable ASCII only.
    KernelCmdline { cmdline: String },
    /// What the publisher allows the workload to do. A launch may only
    /// narrow it: admission refuses a run that asks for more than the
    /// posture permits.
    SecurityPosture(BundleSecurityPosture),
    /// What the workload was built from and what the build produced. The
    /// artifact digests it records must match the bundle's own artifacts.
    BuildProvenance(BuildProvenance),
}

/// The publisher's declared security posture for a bundled workload.
///
/// Every flag is a ceiling, never a grant: `allows_egress = true` does not
/// open the network, it only stops admission from refusing a run whose
/// policy does. A bundle without this member places no ceiling of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSecurityPosture {
    /// Guest-agent profile baked into the image.
    pub profile: AgentProfile,
    /// The rootfs is dm-verity protected. Must agree with the manifest's
    /// [`VerityInfo`]: claiming verity without a binding is malformed.
    pub verity_protected: bool,
    /// The guest agent requires authenticated vsock frames.
    pub requires_auth: bool,
    /// The workload may be launched with host shares or volumes attached.
    pub allows_volumes: bool,
    /// The workload may be launched with a network policy other than
    /// deny-all.
    pub allows_egress: bool,
}

/// Resource expectations the bundle publisher recorded at build
/// time. Optional on the wire (`#[serde(default)]` via the parent
/// struct's `Option<BundleResources>`), present in v2+ bundles.
/// Old (`schema_version = 1`) bundles deserialise with `None` and
/// the template loader defaults to operator config.
///
/// Both fields are advisory. Nothing reads them back at boot today:
/// the boot's own `--cpus` / `--memory` (or their defaults) decide.
/// They record what the publisher expected the workload to need.
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
/// field added in a newer schema will fail to parse in an older verifier. The
/// `schema_version` sniff happens *after* signature check (same
/// pattern as `ExecutionPlan`), so an attacker who flips
/// `schema_version` doesn't slip a newer bundle past an older build.
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
    /// Typed groups of artifacts with their own validation contracts. Empty
    /// for schema-v1/v2 workload-only bundles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<BundleMember>,
    /// dm-verity binding, when the rootfs was built verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verity: Option<VerityInfo>,
    /// Advisory resource expectations recorded by the publisher at
    /// build time. `Some(...)` in v2+ bundles; `None` for v1
    /// bundles (handled via `#[serde(default)]`). No boot path reads
    /// them as defaults today. The claim-9 re-verify
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

    /// The declared kernel command line, when the bundle carries one.
    pub fn kernel_cmdline(&self) -> Option<&str> {
        self.members.iter().find_map(|member| match member {
            BundleMember::KernelCmdline { cmdline } => Some(cmdline.as_str()),
            _ => None,
        })
    }

    /// The publisher's security posture, when the bundle declares one.
    pub fn security_posture(&self) -> Option<&BundleSecurityPosture> {
        self.members.iter().find_map(|member| match member {
            BundleMember::SecurityPosture(posture) => Some(posture),
            _ => None,
        })
    }

    /// The recorded build provenance, when the bundle carries it.
    pub fn build_provenance(&self) -> Option<&BuildProvenance> {
        self.members.iter().find_map(|member| match member {
            BundleMember::BuildProvenance(provenance) => Some(provenance),
            _ => None,
        })
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
    fn bundle_schema_version_is_three() {
        // Pin the current version constant — bumps are deliberate;
        // a silent rev should trip this test.
        assert_eq!(BUNDLE_SCHEMA_VERSION, 3);
    }

    #[test]
    fn embedded_image_set_member_round_trips() {
        let member = BundleMember::EmbeddedImageSet {
            manifest_artifact: "image-set.json".to_string(),
        };
        let value = serde_json::to_value(&member).expect("serialize member");
        assert_eq!(value["class"], "embedded_image_set");
        assert_eq!(value["manifest_artifact"], "image-set.json");
        assert_eq!(
            serde_json::from_value::<BundleMember>(value).expect("deserialize member"),
            member
        );
    }

    fn posture() -> BundleSecurityPosture {
        BundleSecurityPosture {
            profile: AgentProfile::SealedProd,
            verity_protected: true,
            requires_auth: true,
            allows_volumes: false,
            allows_egress: true,
        }
    }

    #[test]
    fn declaration_members_round_trip_with_their_class_tag() {
        let provenance: BuildProvenance = serde_json::from_value(serde_json::json!({
            "input_kind": "nix_flake",
            "input_ref": ".#app",
            "artifacts": { "kernel": "ab" },
        }))
        .expect("provenance fixture");
        let cases = [
            (
                BundleMember::KernelCmdline {
                    cmdline: "console=ttyS0 quiet".to_string(),
                },
                "kernel_cmdline",
            ),
            (BundleMember::SecurityPosture(posture()), "security_posture"),
            (
                BundleMember::BuildProvenance(provenance),
                "build_provenance",
            ),
        ];
        for (member, class) in cases {
            let value = serde_json::to_value(&member).expect("serialize member");
            assert_eq!(value["class"], class);
            assert_eq!(
                serde_json::from_value::<BundleMember>(value).expect("deserialize member"),
                member
            );
        }
    }

    #[test]
    fn posture_member_serializes_its_fields_flat_and_kebab_case() {
        let value = serde_json::to_value(BundleMember::SecurityPosture(posture())).unwrap();
        assert_eq!(value["profile"], "sealed-prod");
        assert_eq!(value["allows_egress"], true);
    }

    #[test]
    fn posture_member_refuses_unknown_and_missing_fields() {
        let mut value = serde_json::to_value(BundleMember::SecurityPosture(posture())).unwrap();
        value["allows_everything"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BundleMember>(value).is_err());

        let mut value = serde_json::to_value(BundleMember::SecurityPosture(posture())).unwrap();
        value.as_object_mut().unwrap().remove("allows_egress");
        assert!(
            serde_json::from_value::<BundleMember>(value).is_err(),
            "a posture missing a ceiling must not default it open"
        );
    }

    #[test]
    fn manifest_accessors_find_each_declaration() {
        let mut manifest: BundleManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 3,
            "publisher": "p",
            "key_id": "0".repeat(32),
            "arch": "x86_64",
            "created_at": "2026-01-01T00:00:00Z",
            "artifacts": [],
        }))
        .unwrap();
        assert!(manifest.security_posture().is_none());
        assert!(manifest.kernel_cmdline().is_none());
        assert!(manifest.build_provenance().is_none());

        manifest.members = alloc::vec![
            BundleMember::KernelCmdline {
                cmdline: "quiet".to_string()
            },
            BundleMember::SecurityPosture(posture()),
        ];
        assert_eq!(manifest.kernel_cmdline(), Some("quiet"));
        assert_eq!(manifest.security_posture(), Some(&posture()));
    }

    #[test]
    fn size_caps_are_two_and_four_gib() {
        assert_eq!(MAX_BUNDLE_ENTRY_BYTES, 1 << 31);
        assert_eq!(MAX_BUNDLE_TOTAL_BYTES, 1 << 32);
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
