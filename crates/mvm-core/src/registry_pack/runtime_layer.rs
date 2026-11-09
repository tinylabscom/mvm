//! Closed, unauthenticated descriptor for a composable runtime filesystem layer.
//!
//! Parsing alone never authorizes extraction or execution. The registry
//! signature, exact manifest pin, payload bytes and current revocation feed
//! must be verified before a layer is used as build input.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use mvm_contract::pack_spec::PackTarget;
use mvm_contract::pack_spec_v2::ComposablePackSpec;

use super::application::{deserialize_object, validate_application_source};
use super::{
    AuthenticatedRegistryManifest, MAX_REGISTRY_DESCRIPTOR_BYTES, PackPin, PackReference,
    RegistryPackFile, RegistryPackVerificationError, VerifiedRegistryRuntimeLayer,
};
use crate::plan::bundle::HashingWriter;

/// A runtime layer is not an application or a legacy policy-only pack.
pub const RUNTIME_LAYER_MANIFEST_SCHEMA_VERSION: u32 = 3;
const RUNTIME_LAYER_SCHEMA_VERSION: u32 = 1;
const MAX_RUNTIME_LAYER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RUNTIME_LAYER_DEPENDENCIES: usize = 16;
const GROUP_FILE: &str = "pack/group.toml";
const PROFILE_FILE: &str = "pack/profile.toml";

/// Exact kind discriminator; unknown kinds never fall back to application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLayerKind {
    RuntimeLayer,
}

/// Metadata for one architecture's layer and its pinned runtime dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLayer {
    pub schema_version: u32,
    pub guest_arch: String,
    /// Authenticated manifests in composition order, not arbitrary names.
    pub dependencies: Vec<PackPin>,
    #[serde(deserialize_with = "deserialize_object")]
    pub archive: RuntimeLayerArchive,
}

/// External source bound by the publisher-signed runtime-layer descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLayerArchive {
    /// Canonical HTTPS or digest-only OCI locator, never trusted by itself.
    pub source: String,
    pub archive_sha256: crate::packs::Sha256Hex,
    pub archive_size: u64,
}

/// Registry-signed metadata for one nonbootable, non-executable layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRuntimeLayerManifest {
    pub schema_version: u32,
    pub kind: RuntimeLayerKind,
    pub reference: PackReference,
    pub description: String,
    #[serde(deserialize_with = "deserialize_object")]
    pub runtime_layer: RuntimeLayer,
    /// Repository payload contains policy only; large layer bytes live outside Git.
    pub files: Vec<RegistryPackFile>,
}

/// Parse original bytes, refusing hybrid, unpinned and oversized descriptors.
///
/// # Errors
///
/// Returns a manifest-parse error when the closed wire shape or a required
/// immutable layer invariant is violated. This does not verify a signature.
pub fn parse_runtime_layer_manifest(
    bytes: &[u8],
) -> Result<RegistryRuntimeLayerManifest, RegistryPackVerificationError> {
    let invalid = |reason: &str| RegistryPackVerificationError::ManifestParse(reason.to_string());
    if bytes.len() > MAX_REGISTRY_DESCRIPTOR_BYTES {
        return Err(invalid("runtime layer descriptor exceeds its size bound"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest: RegistryRuntimeLayerManifest = deserialize_object(&mut deserializer)
        .map_err(|_| invalid("runtime layer descriptor has invalid JSON or a non-closed shape"))?;
    deserializer
        .end()
        .map_err(|_| invalid("runtime layer descriptor has trailing data"))?;
    if manifest.schema_version != RUNTIME_LAYER_MANIFEST_SCHEMA_VERSION
        || manifest.runtime_layer.schema_version != RUNTIME_LAYER_SCHEMA_VERSION
    {
        return Err(invalid(
            "runtime layer requires manifest schema 3 and layer schema 1",
        ));
    }
    if manifest.reference.namespace() != "runtime"
        || manifest
            .reference
            .version()
            .is_none_or(|version| version.as_str().contains('+'))
        || manifest.description.trim().is_empty()
    {
        return Err(invalid(
            "runtime layer requires a versioned runtime/* identity and description",
        ));
    }
    if !matches!(
        manifest.runtime_layer.guest_arch.as_str(),
        "x86_64" | "aarch64"
    ) {
        return Err(invalid("runtime layer guest architecture is not canonical"));
    }
    let archive = &manifest.runtime_layer.archive;
    if archive.archive_size == 0 || archive.archive_size > MAX_RUNTIME_LAYER_BYTES {
        return Err(invalid(
            "runtime layer archive size is missing or exceeds its bound",
        ));
    }
    validate_application_source(&archive.source)?;
    if manifest.runtime_layer.dependencies.len() > MAX_RUNTIME_LAYER_DEPENDENCIES {
        return Err(invalid("runtime layer declares too many dependencies"));
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &manifest.runtime_layer.dependencies {
        if dependency.reference().namespace() != "runtime"
            || dependency
                .reference()
                .version()
                .is_some_and(|v| v.as_str().contains('+'))
            || dependency.reference().coordinate_string() == manifest.reference.coordinate_string()
            || !dependencies.insert(dependency.reference().coordinate_string())
        {
            return Err(invalid(
                "runtime layer has a duplicate, self, or non-runtime dependency",
            ));
        }
    }
    let mut paths = BTreeSet::new();
    for file in &manifest.files {
        if !matches!(file.path.as_str(), GROUP_FILE | PROFILE_FILE)
            || !paths.insert(file.path.as_str())
            || file.size == 0
            || file.size > MAX_REGISTRY_DESCRIPTOR_BYTES as u64
        {
            return Err(invalid(
                "runtime layer declares an unsafe, duplicate or oversized file",
            ));
        }
    }
    if paths.is_empty() {
        return Err(invalid("runtime layer requires a declared policy document"));
    }
    Ok(manifest)
}

const MAX_RESOLVED_LAYERS: usize = 64;

/// A refused dependency graph; no candidate becomes an executable pack.
#[derive(Debug, Error)]
pub enum RuntimeLayerResolveError {
    #[error("runtime layer graph exceeds its bound or contains duplicate names")]
    InvalidGraph,
    #[error("runtime layer dependency is missing: {0}")]
    Missing(String),
    #[error("runtime layer dependency pin or architecture differs: {0}")]
    Drift(String),
    #[error("runtime layer dependency cycle at {0}")]
    Cycle(String),
    #[error(transparent)]
    Revocation(#[from] crate::registry_pack_store::RegistryPackStoreError),
}

/// Resolve exact authenticated runtime pins into dependency-first build order.
///
/// Candidates are publisher-authenticated metadata, not archives. The caller
/// still needs to verify and stage each archive, enforce policy, and bind the
/// resolved pins into the final signed application. No registry lookup or Nix
/// evaluation occurs here.
///
/// # Errors
///
/// Refuses missing, drifted, duplicate, cyclic, wrong-architecture or revoked
/// layers; an unused candidate cannot mask a missing exact dependency.
pub fn resolve_runtime_layers<'a>(
    roots: &[PackPin],
    candidates: &'a [VerifiedRegistryRuntimeLayer],
    arch: &str,
) -> Result<Vec<&'a VerifiedRegistryRuntimeLayer>, RuntimeLayerResolveError> {
    let ordered = resolve_graph(roots, candidates, arch)?;
    for layer in &ordered {
        layer.check_current_revocations()?;
    }
    Ok(ordered)
}

/// Bind authored runtime requests to exactly the authenticated dependency closure.
///
/// Unversioned requests resolve to an authenticated candidate's exact version;
/// the returned descriptors are in dependency-first order, ready to enter a
/// separate frozen build plan. A spec alone never pins or signs a release.
///
/// # Errors
///
/// Refuses unrequested candidates, wrong architecture/version, missing
/// dependencies, publisher revocations and unsigned metadata.
pub fn resolve_requested_runtime_layers<'a>(
    spec: &ComposablePackSpec,
    candidates: &'a [VerifiedRegistryRuntimeLayer],
) -> Result<Vec<&'a VerifiedRegistryRuntimeLayer>, RuntimeLayerResolveError> {
    let ordered = requested_graph(spec, candidates)?;
    for layer in &ordered {
        layer.check_current_revocations()?;
    }
    Ok(ordered)
}

fn requested_graph<'a>(
    spec: &ComposablePackSpec,
    candidates: &'a [VerifiedRegistryRuntimeLayer],
) -> Result<Vec<&'a VerifiedRegistryRuntimeLayer>, RuntimeLayerResolveError> {
    spec.validate()
        .map_err(|_| RuntimeLayerResolveError::InvalidGraph)?;
    let arch = match spec.target {
        PackTarget::X86_64Linux => "x86_64",
        PackTarget::Aarch64Linux => "aarch64",
    };
    let mut roots = Vec::with_capacity(spec.runtimes.len());
    for request in &spec.runtimes {
        let reference: PackReference = request
            .parse()
            .map_err(|_| RuntimeLayerResolveError::InvalidGraph)?;
        let candidate = candidates
            .iter()
            .find(|layer| layer.reference().coordinate_string() == reference.coordinate_string())
            .ok_or_else(|| RuntimeLayerResolveError::Missing(request.clone()))?;
        if reference.version().is_some() && reference.version() != candidate.reference().version() {
            return Err(RuntimeLayerResolveError::Drift(request.clone()));
        }
        roots.push(
            PackPin::new(
                candidate.reference().clone(),
                candidate.manifest_sha256().clone(),
            )
            .map_err(|_| RuntimeLayerResolveError::InvalidGraph)?,
        );
    }
    let ordered = resolve_graph(&roots, candidates, arch)?;
    if ordered.len() != candidates.len() {
        return Err(RuntimeLayerResolveError::InvalidGraph);
    }
    Ok(ordered)
}

fn resolve_graph<'a>(
    roots: &[PackPin],
    candidates: &'a [VerifiedRegistryRuntimeLayer],
    arch: &str,
) -> Result<Vec<&'a VerifiedRegistryRuntimeLayer>, RuntimeLayerResolveError> {
    if !matches!(arch, "x86_64" | "aarch64")
        || roots.len() > MAX_RESOLVED_LAYERS
        || candidates.len() > MAX_RESOLVED_LAYERS
    {
        return Err(RuntimeLayerResolveError::InvalidGraph);
    }
    let mut by_name = BTreeMap::new();
    for layer in candidates {
        if by_name
            .insert(layer.reference().coordinate_string(), layer)
            .is_some()
        {
            // A build cannot contain two versions of the same runtime name.
            return Err(RuntimeLayerResolveError::InvalidGraph);
        }
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut ordered = Vec::new();
    for root in roots {
        visit(
            root,
            arch,
            &by_name,
            &mut visiting,
            &mut visited,
            &mut ordered,
        )?;
    }
    Ok(ordered)
}

fn visit<'a>(
    pin: &PackPin,
    arch: &str,
    by_name: &BTreeMap<String, &'a VerifiedRegistryRuntimeLayer>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    ordered: &mut Vec<&'a VerifiedRegistryRuntimeLayer>,
) -> Result<(), RuntimeLayerResolveError> {
    let name = pin.reference().coordinate_string();
    let layer = by_name
        .get(&name)
        .ok_or_else(|| RuntimeLayerResolveError::Missing(pin.reference().to_string()))?;
    if layer.reference() != pin.reference()
        || layer.manifest_sha256() != pin.manifest_sha256()
        || layer.manifest().runtime_layer.guest_arch != arch
    {
        return Err(RuntimeLayerResolveError::Drift(pin.reference().to_string()));
    }
    if visiting.contains(&name) {
        return Err(RuntimeLayerResolveError::Cycle(name));
    }
    if visited.contains(&name) {
        return Ok(());
    }
    visiting.insert(name.clone());
    for dependency in &layer.manifest().runtime_layer.dependencies {
        visit(dependency, arch, by_name, visiting, visited, ordered)?;
    }
    visiting.remove(&name);
    visited.insert(name);
    ordered.push(layer);
    Ok(())
}

/// A private copy of descriptor-pinned bytes, not an extracted or runnable layer.
#[derive(Debug)]
pub struct VerifiedRuntimeLayerArchive {
    descriptor: VerifiedRegistryRuntimeLayer,
    snapshot: tempfile::NamedTempFile,
}

impl VerifiedRuntimeLayerArchive {
    /// Publisher-authenticated metadata that names the bytes held in the snapshot.
    pub fn descriptor(&self) -> &VerifiedRegistryRuntimeLayer {
        &self.descriptor
    }

    /// Open the retained snapshot read-only after checking its exact byte identity.
    ///
    /// A caller that interprets the stream must call [`Self::reverify`] again
    /// before making any resulting artifacts visible.
    ///
    /// # Errors
    ///
    /// Refuses changed or unreadable snapshots.
    pub fn open_verified(&self) -> Result<std::fs::File, RuntimeLayerArchiveError> {
        self.reverify()?;
        Ok(std::fs::File::open(self.snapshot.path())?)
    }

    /// Recheck the held bytes before a later consumer interprets the tar.
    ///
    /// # Errors
    ///
    /// Refuses a snapshot that has changed after its original verification.
    pub fn reverify(&self) -> Result<(), RuntimeLayerArchiveError> {
        let expected = &self.descriptor.manifest().runtime_layer.archive;
        let reader = self.snapshot.reopen()?;
        if reader.metadata()?.len() != expected.archive_size {
            return Err(RuntimeLayerArchiveError::Size);
        }
        let mut writer = HashingWriter::new(std::io::sink());
        std::io::copy(&mut reader.take(expected.archive_size + 1), &mut writer)?;
        let (size, digest) = writer.finish();
        if size != expected.archive_size {
            return Err(RuntimeLayerArchiveError::Size);
        }
        if digest != expected.archive_sha256.as_str() {
            return Err(RuntimeLayerArchiveError::Digest);
        }
        Ok(())
    }
}

/// Why a declared runtime tar was refused before any extraction.
#[derive(Debug, Error)]
pub enum RuntimeLayerArchiveError {
    #[error("runtime layer archive I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime layer archive is not a regular file matching its signed size")]
    Size,
    #[error("runtime layer archive digest differs from its signed descriptor")]
    Digest,
}

/// Snapshot and hash an authenticated descriptor's external archive.
///
/// # Errors
///
/// Refuses special, linked, truncated, oversized or digest-mismatched inputs.
/// This does not verify the tar's entries or grant permission to install it.
pub fn verify_runtime_layer_archive(
    descriptor: &VerifiedRegistryRuntimeLayer,
    archive: &Path,
) -> Result<VerifiedRuntimeLayerArchive, RuntimeLayerArchiveError> {
    let expected = &descriptor.manifest().runtime_layer.archive;
    if expected.archive_size == 0 || expected.archive_size > MAX_RUNTIME_LAYER_BYTES {
        return Err(RuntimeLayerArchiveError::Size);
    }
    let input = super::local_input::open_sized_regular(archive, expected.archive_size).map_err(
        |error| {
            if error.kind() == std::io::ErrorKind::Other {
                RuntimeLayerArchiveError::Size
            } else {
                RuntimeLayerArchiveError::Io(error)
            }
        },
    )?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    let mut writer = HashingWriter::new(snapshot.as_file_mut());
    std::io::copy(&mut input.take(expected.archive_size + 1), &mut writer)?;
    let (size, digest) = writer.finish();
    if size != expected.archive_size {
        return Err(RuntimeLayerArchiveError::Size);
    }
    if digest != expected.archive_sha256.as_str() {
        return Err(RuntimeLayerArchiveError::Digest);
    }
    snapshot.as_file().sync_all()?;
    Ok(VerifiedRuntimeLayerArchive {
        descriptor: descriptor.clone(),
        snapshot,
    })
}

/// Bounded copies of the descriptor's exact signed policy documents.
///
/// These are policy inputs, not authority to grant their requests. A later
/// composer must parse and intersect them with host-authorized policy.
#[derive(Debug, Clone)]
pub struct VerifiedRuntimeLayerPolicies {
    descriptor: VerifiedRegistryRuntimeLayer,
    group: Option<Vec<u8>>,
    profile: Option<Vec<u8>>,
}

impl VerifiedRuntimeLayerPolicies {
    /// Original authenticated descriptor, including publisher and manifest pin.
    pub fn descriptor(&self) -> &VerifiedRegistryRuntimeLayer {
        &self.descriptor
    }

    /// The exact group document, when the signed descriptor declared one.
    pub fn group(&self) -> Option<&[u8]> {
        self.group.as_deref()
    }

    /// The exact profile document, when the signed descriptor declared one.
    pub fn profile(&self) -> Option<&[u8]> {
        self.profile.as_deref()
    }

    /// Recheck held policy bytes and the current publisher revocation feed.
    ///
    /// # Errors
    ///
    /// Refuses altered policy bytes or withdrawn or stale publisher trust.
    pub fn reverify(&self) -> Result<(), RuntimeLayerPolicyError> {
        self.reverify_with(VerifiedRegistryRuntimeLayer::check_current_revocations)
    }

    fn reverify_with(
        &self,
        check_revocations: impl FnOnce(
            &VerifiedRegistryRuntimeLayer,
        )
            -> Result<(), crate::registry_pack_store::RegistryPackStoreError>,
    ) -> Result<(), RuntimeLayerPolicyError> {
        check_revocations(&self.descriptor)?;
        for file in &self.descriptor.manifest().files {
            let held = match file.path.as_str() {
                GROUP_FILE => self.group(),
                PROFILE_FILE => self.profile(),
                _ => None,
            }
            .ok_or(RuntimeLayerPolicyError::Digest)?;
            if held.len() as u64 != file.size
                || crate::packs::Sha256Hex::from_bytes(held) != file.sha256
            {
                return Err(RuntimeLayerPolicyError::Digest);
            }
        }
        Ok(())
    }
}

/// Why a signed runtime-layer policy document cannot be used as build input.
#[derive(Debug, Error)]
pub enum RuntimeLayerPolicyError {
    #[error("runtime layer policy read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime layer policy differs from the signed descriptor")]
    Digest,
    #[error(transparent)]
    Revocation(#[from] crate::registry_pack_store::RegistryPackStoreError),
}

/// Snapshot every declared policy document from a private staging directory.
///
/// Only the descriptor's closed `pack/group.toml` and `pack/profile.toml` paths
/// are read. The original directory is not held or exposed to the composer.
///
/// # Errors
///
/// Refuses missing, special, linked, changed, oversized or digest-mismatched
/// policy files; no partial policy is returned.
pub fn verify_runtime_layer_policies(
    descriptor: &VerifiedRegistryRuntimeLayer,
    files_root: &Path,
) -> Result<VerifiedRuntimeLayerPolicies, RuntimeLayerPolicyError> {
    let mut group = None;
    let mut profile = None;
    for file in &descriptor.manifest().files {
        let mut source = super::local_input::open_payload(files_root, &file.path, file.size)?;
        let before = source.metadata()?;
        let mut bytes = Vec::new();
        source
            .by_ref()
            .take(file.size + 1)
            .read_to_end(&mut bytes)?;
        super::local_input::ensure_unchanged(&source, &before, files_root, &file.path, file.size)?;
        if bytes.len() as u64 != file.size
            || crate::packs::Sha256Hex::from_bytes(&bytes) != file.sha256
        {
            return Err(RuntimeLayerPolicyError::Digest);
        }
        match file.path.as_str() {
            GROUP_FILE => group = Some(bytes),
            PROFILE_FILE => profile = Some(bytes),
            _ => return Err(RuntimeLayerPolicyError::Digest),
        }
    }
    Ok(VerifiedRuntimeLayerPolicies {
        descriptor: descriptor.clone(),
        group,
        profile,
    })
}

/// Authenticated layer bytes and policy documents retained as one build input.
#[derive(Debug)]
pub struct VerifiedRuntimeLayerInputs {
    archive: VerifiedRuntimeLayerArchive,
    policies: VerifiedRuntimeLayerPolicies,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfflineGroup {
    #[serde(default, rename = "description")]
    _description: Option<String>,
    required: bool,
    network: OfflineNetwork,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfflineNetwork {
    block: bool,
}

/// The first composable slice admits only a non-excludable, deny-all signed group.
///
/// # Errors
///
/// Refuses changed inputs, stale revocations, profiles, or any other policy request.
pub fn require_offline_runtime_policy(
    inputs: &VerifiedRuntimeLayerInputs,
) -> Result<(), OfflineRuntimePolicyError> {
    inputs.reverify()?;
    require_offline_policy_shape(inputs.policies())
}

/// Recheck a retained signed policy independently of its original acquisition.
///
/// # Errors
///
/// Refuses changed policy bytes, stale revocations, or non-offline requests.
pub fn require_offline_runtime_policies(
    policies: &VerifiedRuntimeLayerPolicies,
) -> Result<(), OfflineRuntimePolicyError> {
    policies.reverify()?;
    require_offline_policy_shape(policies)
}

fn require_offline_policy_shape(
    policies: &VerifiedRuntimeLayerPolicies,
) -> Result<(), OfflineRuntimePolicyError> {
    if policies.profile().is_some() {
        return Err(OfflineRuntimePolicyError::Unsupported);
    }
    let group = policies
        .group()
        .ok_or(OfflineRuntimePolicyError::Unsupported)?;
    require_offline_group(group)
}

fn require_offline_group(bytes: &[u8]) -> Result<(), OfflineRuntimePolicyError> {
    if bytes.len() > MAX_REGISTRY_DESCRIPTOR_BYTES {
        return Err(OfflineRuntimePolicyError::Unsupported);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| OfflineRuntimePolicyError::Unsupported)?;
    let group: OfflineGroup =
        toml::from_str(text).map_err(|_| OfflineRuntimePolicyError::Unsupported)?;
    if !group.required || !group.network.block {
        return Err(OfflineRuntimePolicyError::Unsupported);
    }
    Ok(())
}

/// Why a verified runtime layer cannot enter the first offline composition.
#[derive(Debug, Error)]
pub enum OfflineRuntimePolicyError {
    #[error(transparent)]
    Input(#[from] RuntimeLayerInputError),
    #[error(transparent)]
    Policy(#[from] RuntimeLayerPolicyError),
    #[error(
        "the first composable runtime requires a signed, required deny-all group with no other policy requests"
    )]
    Unsupported,
}

impl VerifiedRuntimeLayerInputs {
    /// The held archive, not a live publisher URL or mutable cache file.
    pub fn archive(&self) -> &VerifiedRuntimeLayerArchive {
        &self.archive
    }

    /// Exact policy documents pinned by the same signed descriptor.
    pub fn policies(&self) -> &VerifiedRuntimeLayerPolicies {
        &self.policies
    }

    /// Check exact held bytes and current revocations before and after use.
    ///
    /// # Errors
    ///
    /// Refuses a withdrawn publisher or a changed archive/policy snapshot.
    pub fn reverify(&self) -> Result<(), RuntimeLayerInputError> {
        self.archive.descriptor().check_current_revocations()?;
        self.archive.reverify()?;
        self.policies.reverify()?;
        Ok(())
    }
}

/// Failure to retain a complete signed runtime and policy input.
#[derive(Debug, Error)]
pub enum RuntimeLayerInputError {
    #[error(transparent)]
    Archive(#[from] RuntimeLayerArchiveError),
    #[error(transparent)]
    Policy(#[from] RuntimeLayerPolicyError),
    #[error(transparent)]
    Revocation(#[from] crate::registry_pack_store::RegistryPackStoreError),
}

/// Snapshot both the external tar and all declared policy documents.
///
/// Publisher authentication must precede this call. The returned value is
/// still build input, not permission to compose policy or launch a workload.
///
/// # Errors
///
/// Refuses missing, altered or revoked bytes before returning a complete input.
pub fn verify_runtime_layer_inputs(
    descriptor: &VerifiedRegistryRuntimeLayer,
    archive_path: &Path,
    files_root: &Path,
) -> Result<VerifiedRuntimeLayerInputs, RuntimeLayerInputError> {
    descriptor.check_current_revocations()?;
    let archive = verify_runtime_layer_archive(descriptor, archive_path)?;
    let policies = verify_runtime_layer_policies(descriptor, files_root)?;
    let held = VerifiedRuntimeLayerInputs { archive, policies };
    held.reverify()?;
    Ok(held)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn document() -> Value {
        json!({
            "schema_version": 3,
            "kind": "runtime_layer",
            "reference": "runtime/python@1.2.0",
            "description": "Python runtime",
            "runtime_layer": {
                "schema_version": 1,
                "guest_arch": "x86_64",
                "dependencies": [],
                "archive": {
                    "source": "https://example.test/runtime/python/1.2.0/layer.tar",
                    "archive_sha256": "a".repeat(64),
                    "archive_size": 1024
                }
            },
            "files": [
                { "path": "pack/group.toml", "sha256": "b".repeat(64), "size": 28 }
            ]
        })
    }

    fn parse(value: &Value) -> Result<RegistryRuntimeLayerManifest, RegistryPackVerificationError> {
        parse_runtime_layer_manifest(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn a_runtime_layer_is_not_a_bootable_application() {
        let layer = parse(&document()).unwrap();
        assert_eq!(layer.reference.to_string(), "runtime/python@1.2.0");
        let bytes = serde_json::to_vec(&document()).unwrap();
        assert!(super::super::application::parse_application_manifest(&bytes).is_err());
        for field in ["application", "entrypoint", "kernel", "image", "secret"] {
            let mut invalid = document();
            invalid[field] = json!("not allowed");
            assert!(parse(&invalid).is_err(), "{field} must not be accepted");
        }
    }

    fn authenticated(value: &Value) -> VerifiedRegistryRuntimeLayer {
        use super::super::{
            PackAdoption,
            dispatch::adopt_with,
            tests::{accept_signature, publisher_policy, reference},
        };

        let bytes = serde_json::to_vec(value).unwrap();
        let requested = reference(value["reference"].as_str().unwrap());
        let policy = publisher_policy();
        let request = PackAdoption {
            requested: &requested,
            manifest_bytes: &bytes,
            signature_bundle: b"test bundle",
            publisher_policy: &policy,
        };
        let verified = adopt_with(&request, accept_signature).unwrap();
        let super::super::VerifiedRegistryManifest::RuntimeLayer(layer) = verified else {
            panic!("authenticated runtime layer must retain its distinct kind");
        };
        assert_eq!(layer.manifest_bytes(), bytes);
        layer
    }

    fn authenticated_layer() -> VerifiedRegistryRuntimeLayer {
        let mut signed = document();
        signed["runtime_layer"]["archive"]["archive_sha256"] =
            json!(crate::packs::Sha256Hex::from_bytes(b"test tar").as_str());
        signed["runtime_layer"]["archive"]["archive_size"] = json!(b"test tar".len());
        authenticated(&signed)
    }

    #[test]
    fn policy_files_are_held_only_when_the_signed_inventory_matches() {
        const GROUP: &[u8] = b"description = 'python runtime'\n";
        const PROFILE: &[u8] = b"description = 'python profile'\n";
        let mut signed = document();
        signed["files"] = json!([
            {
                "path": "pack/group.toml",
                "sha256": crate::packs::Sha256Hex::from_bytes(GROUP),
                "size": GROUP.len()
            },
            {
                "path": "pack/profile.toml",
                "sha256": crate::packs::Sha256Hex::from_bytes(PROFILE),
                "size": PROFILE.len()
            }
        ]);
        let layer = authenticated(&signed);
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("pack")).unwrap();
        let group = root.path().join("pack/group.toml");
        let profile = root.path().join("pack/profile.toml");
        std::fs::write(&group, GROUP).unwrap();
        std::fs::write(&profile, PROFILE).unwrap();
        let mut held = verify_runtime_layer_policies(&layer, root.path()).unwrap();
        assert_eq!(held.descriptor().manifest_sha256(), layer.manifest_sha256());
        assert_eq!(held.group(), Some(GROUP));
        assert_eq!(held.profile(), Some(PROFILE));
        held.reverify_with(|_| Ok(())).unwrap();

        std::fs::write(&group, b"changed source file").unwrap();
        assert_eq!(held.group(), Some(GROUP), "the private copy is held");
        assert!(matches!(
            verify_runtime_layer_policies(&layer, root.path()),
            Err(RuntimeLayerPolicyError::Io(_) | RuntimeLayerPolicyError::Digest)
        ));
        held.group = Some(b"changed held file".to_vec());
        assert!(matches!(
            held.reverify_with(|_| Ok(())),
            Err(RuntimeLayerPolicyError::Digest)
        ));
        #[cfg(unix)]
        {
            std::fs::remove_file(&group).unwrap();
            std::os::unix::fs::symlink(&profile, &group).unwrap();
            assert!(matches!(
                verify_runtime_layer_policies(&layer, root.path()),
                Err(RuntimeLayerPolicyError::Io(_))
            ));
        }
    }

    #[test]
    fn signed_offline_group_refuses_optional_and_granting_policy() {
        require_offline_group(
            b"description = 'Offline Python runtime'\nrequired = true\n[network]\nblock = true\n",
        )
        .unwrap();
        for document in [
            b"[network]\nblock = true\n".as_slice(),
            b"required = false\n[network]\nblock = true\n".as_slice(),
            b"required = true\n[network]\nblock = false\n".as_slice(),
            b"required = true\n[network]\nblock = true\nallow = ['pypi.org:443']\n".as_slice(),
            b"required = true\n[[secrets.bind]]\nname = 'token'\n[network]\nblock = true\n".as_slice(),
            b"required = true\n[[shares.mount]]\nhost = '.'\nguest = '/work'\n[network]\nblock = true\n".as_slice(),
            b"required = true\n[network]\nblock = true\n[resources]\nmax_cpus = 2\n".as_slice(),
            b"required = true\n[network]\nblock = true\nnet = true\n".as_slice(),
            b"required = true\n[network]\nblock = true\n[network]\nblock = true\n".as_slice(),
        ] {
            assert!(require_offline_group(document).is_err(), "{document:?}");
        }
    }

    #[test]
    fn authenticated_policy_bytes_cannot_bypass_offline_shape_check() {
        for (group_bytes, allowed) in [
            (
                b"required = true\n[network]\nblock = true\n".as_slice(),
                true,
            ),
            (
                b"required = false\n[network]\nblock = true\n".as_slice(),
                false,
            ),
            (
                b"required = true\n[network]\nblock = true\nallow = ['pypi.org:443']\n".as_slice(),
                false,
            ),
        ] {
            let mut signed = document();
            signed["files"] = json!([{
                "path": GROUP_FILE,
                "sha256": crate::packs::Sha256Hex::from_bytes(group_bytes),
                "size": group_bytes.len()
            }]);
            let descriptor = authenticated(&signed);
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("pack")).unwrap();
            std::fs::write(root.path().join(GROUP_FILE), group_bytes).unwrap();
            let held = verify_runtime_layer_policies(&descriptor, root.path()).unwrap();
            held.reverify_with(|_| Ok(())).unwrap();
            assert_eq!(require_offline_policy_shape(&held).is_ok(), allowed);
        }
    }

    fn pin(layer: &VerifiedRegistryRuntimeLayer) -> PackPin {
        PackPin::new(layer.reference().clone(), layer.manifest_sha256().clone()).unwrap()
    }

    #[test]
    fn runtime_dependencies_resolve_once_in_declared_postorder() {
        let base = authenticated_layer();
        let mut alternate = document();
        alternate["reference"] = json!("runtime/stdlib@1.0.0");
        let stdlib = authenticated(&alternate);
        let mut parent = document();
        parent["reference"] = json!("runtime/appdeps@1.0.0");
        parent["runtime_layer"]["dependencies"] = json!([pin(&base), pin(&stdlib)]);
        let appdeps = authenticated(&parent);
        let mut top = document();
        top["reference"] = json!("runtime/cli@1.0.0");
        top["runtime_layer"]["dependencies"] = json!([pin(&base), pin(&appdeps)]);
        let cli = authenticated(&top);
        let candidates = [cli.clone(), stdlib, base, appdeps];
        let roots = [pin(&cli), pin(&cli)];
        let resolved = resolve_graph(&roots, &candidates, "x86_64").unwrap();
        let names: Vec<_> = resolved
            .iter()
            .map(|layer| layer.reference().name())
            .collect();
        assert_eq!(names, ["python", "stdlib", "appdeps", "cli"]);
    }

    #[test]
    fn authored_v2_requests_bind_only_the_exact_authenticated_closure() {
        fn authored(request: &str) -> ComposablePackSpec {
            serde_json::from_value(json!({
                "schema": "mvm.pack-spec/v2",
                "identity": {"name": "agent/example", "version": "1.0.0"},
                "target": "x86_64-linux",
                "source": {"kind": "local", "path": "."},
                "runtimes": [request],
                "copy": [],
                "entrypoint": ["/usr/bin/python3"],
                "resources": {"cpu_cores": 1, "memory_mb": 256}
            }))
            .unwrap()
        }
        let base = authenticated_layer();
        let mut parent = document();
        parent["reference"] = json!("runtime/appdeps@1.0.0");
        parent["runtime_layer"]["dependencies"] = json!([pin(&base)]);
        let appdeps = authenticated(&parent);
        let selected = [appdeps.clone(), base.clone()];
        let ordered = requested_graph(&authored("runtime/appdeps"), &selected).unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|layer| layer.reference().name())
                .collect::<Vec<_>>(),
            ["python", "appdeps"]
        );
        assert!(matches!(
            requested_graph(&authored("runtime/appdeps@2.0.0"), &selected),
            Err(RuntimeLayerResolveError::Drift(_))
        ));
        assert!(matches!(
            requested_graph(&authored("runtime/missing"), &selected),
            Err(RuntimeLayerResolveError::Missing(_))
        ));
        let mut wrong_arch = authored("runtime/appdeps");
        wrong_arch.target = PackTarget::Aarch64Linux;
        assert!(matches!(
            requested_graph(&wrong_arch, &selected),
            Err(RuntimeLayerResolveError::Drift(_))
        ));
        let mut extra = document();
        extra["reference"] = json!("runtime/node@1.0.0");
        assert!(matches!(
            requested_graph(
                &authored("runtime/appdeps"),
                &[appdeps, base, authenticated(&extra)]
            ),
            Err(RuntimeLayerResolveError::InvalidGraph)
        ));
    }

    #[test]
    fn runtime_resolution_refuses_missing_or_drifted_inputs() {
        let base = authenticated_layer();
        let mut parent = document();
        parent["reference"] = json!("runtime/appdeps@1.0.0");
        parent["runtime_layer"]["dependencies"] = json!([pin(&base)]);
        let appdeps = authenticated(&parent);
        let root = pin(&appdeps);
        assert!(matches!(
            resolve_graph(
                std::slice::from_ref(&root),
                std::slice::from_ref(&appdeps),
                "x86_64"
            ),
            Err(RuntimeLayerResolveError::Missing(_))
        ));
        let mut changed = document();
        changed["reference"] = json!("runtime/python@1.2.1");
        let changed = authenticated(&changed);
        assert!(matches!(
            resolve_graph(
                std::slice::from_ref(&root),
                &[appdeps.clone(), changed],
                "x86_64"
            ),
            Err(RuntimeLayerResolveError::Drift(_))
        ));
        assert!(matches!(
            resolve_graph(&[root], &[appdeps, base], "aarch64"),
            Err(RuntimeLayerResolveError::Drift(_))
        ));
    }

    #[test]
    fn runtime_resolution_refuses_ambiguous_versions_and_unbounded_graphs() {
        let base = authenticated_layer();
        let mut version = document();
        version["reference"] = json!("runtime/python@2.0.0");
        let version = authenticated(&version);
        assert!(matches!(
            resolve_graph(&[pin(&base)], &[base.clone(), version], "x86_64"),
            Err(RuntimeLayerResolveError::InvalidGraph)
        ));
        let too_many = vec![base; MAX_RESOLVED_LAYERS + 1];
        assert!(matches!(
            resolve_graph(&[], &too_many, "x86_64"),
            Err(RuntimeLayerResolveError::InvalidGraph)
        ));
    }

    #[test]
    fn authenticated_layer_keeps_registry_kind_distinct() {
        let layer = authenticated_layer();
        assert_eq!(
            layer.manifest().reference.to_string(),
            "runtime/python@1.2.0"
        );
    }

    #[test]
    fn runtime_dispatch_refuses_another_reference_or_unauthenticated_bytes() {
        use super::super::{
            PackAdoption,
            dispatch::adopt_with,
            tests::{accept_signature, publisher_policy, reference, reject_signature},
        };

        let bytes = serde_json::to_vec(&document()).unwrap();
        let policy = publisher_policy();
        let wrong = reference("runtime/node@1.2.0");
        let request = PackAdoption {
            requested: &wrong,
            manifest_bytes: &bytes,
            signature_bundle: b"test bundle",
            publisher_policy: &policy,
        };
        assert!(matches!(
            adopt_with(&request, accept_signature),
            Err(RegistryPackVerificationError::ManifestReferenceMismatch { .. })
        ));
        assert!(matches!(
            adopt_with(&request, reject_signature),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn verified_snapshot_refuses_tamper_and_nonregular_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let layer = authenticated_layer();
        let source = dir.path().join("layer.tar");
        std::fs::write(&source, b"test tar").unwrap();
        let held = verify_runtime_layer_archive(&layer, &source).unwrap();
        held.reverify().unwrap();
        assert_eq!(std::fs::read(held.snapshot.path()).unwrap(), b"test tar");

        std::fs::write(&source, b"mutated!").unwrap();
        assert_eq!(std::fs::read(held.snapshot.path()).unwrap(), b"test tar");
        assert!(matches!(
            verify_runtime_layer_archive(&layer, &source),
            Err(RuntimeLayerArchiveError::Digest)
        ));
        std::fs::write(held.snapshot.path(), b"mutated!").unwrap();
        assert!(matches!(
            held.reverify(),
            Err(RuntimeLayerArchiveError::Digest)
        ));
        std::fs::write(&source, b"short").unwrap();
        assert!(verify_runtime_layer_archive(&layer, &source).is_err());
        assert!(verify_runtime_layer_archive(&layer, dir.path()).is_err());
        #[cfg(unix)]
        {
            let symlink = dir.path().join("linked.tar");
            std::os::unix::fs::symlink(held.snapshot.path(), &symlink).unwrap();
            assert!(verify_runtime_layer_archive(&layer, &symlink).is_err());
            let hardlink = dir.path().join("hardlink.tar");
            std::fs::hard_link(held.snapshot.path(), &hardlink).unwrap();
            assert!(verify_runtime_layer_archive(&layer, held.snapshot.path()).is_err());
        }
    }

    #[test]
    fn strict_schema_and_file_inventory_refuse_incomplete_layers() {
        for (field, value) in [
            ("schema_version", json!(2)),
            ("kind", json!("application")),
            ("reference", json!("runtime/python")),
            ("reference", json!("agent/claude@2.0.0")),
            ("reference", json!("runtime/python@1.2.0+other")),
            ("description", json!(" ")),
        ] {
            let mut invalid = document();
            invalid[field] = value;
            assert!(parse(&invalid).is_err(), "{field}: {invalid}");
        }
        for path in ["vmlinux", "../layer.tar", "pack/other.toml", "layer.tar"] {
            let mut invalid = document();
            invalid["files"][0]["path"] = json!(path);
            assert!(parse(&invalid).is_err(), "{path} must be refused");
        }
        let mut missing = document();
        missing["files"] = json!([]);
        assert!(parse(&missing).is_err());
        let mut wrong_arch = document();
        wrong_arch["runtime_layer"]["guest_arch"] = json!("linux/x86_64");
        assert!(parse(&wrong_arch).is_err());
        let mut zero_size = document();
        zero_size["runtime_layer"]["archive"]["archive_size"] = json!(0);
        assert!(parse(&zero_size).is_err());
        let mut oversized = document();
        oversized["runtime_layer"]["archive"]["archive_size"] = json!(MAX_RUNTIME_LAYER_BYTES + 1);
        assert!(parse(&oversized).is_err());
        let mut bad_digest = document();
        bad_digest["runtime_layer"]["archive"]["archive_sha256"] = json!("not-a-digest");
        assert!(parse(&bad_digest).is_err());
        let mut pinned_oci = document();
        pinned_oci["runtime_layer"]["archive"]["source"] = json!(format!(
            "oci://registry.example/runtime/python@sha256:{}",
            "c".repeat(64)
        ));
        assert!(parse(&pinned_oci).is_ok());
        let mut mutable_source = document();
        mutable_source["runtime_layer"]["archive"]["source"] =
            json!("oci://registry.example/runtime/python:latest");
        assert!(parse(&mutable_source).is_err());
        let mut credential_source = document();
        credential_source["runtime_layer"]["archive"]["source"] =
            json!("https://user:pass@example.test/layer.tar");
        assert!(parse(&credential_source).is_err());
        let mut missing_archive = document();
        missing_archive["runtime_layer"]
            .as_object_mut()
            .unwrap()
            .remove("archive");
        assert!(parse(&missing_archive).is_err());
        let mut untrusted_key = document();
        untrusted_key["runtime_layer"]["archive"]["key_id"] = json!("a".repeat(32));
        assert!(parse(&untrusted_key).is_err());
    }

    #[test]
    fn runtime_dependencies_are_exact_distinct_pins_not_entrypoints() {
        let pin = json!({
            "reference": "runtime/node@2.0.0",
            "manifest_sha256": "c".repeat(64)
        });
        let mut document = document();
        document["runtime_layer"]["dependencies"] = json!([pin]);
        assert_eq!(
            parse(&document).unwrap().runtime_layer.dependencies.len(),
            1
        );
        for references in [
            vec!["runtime/node"],
            vec!["agent/claude@2.0.0"],
            vec!["runtime/python@1.2.0"],
            vec!["runtime/node@2.0.0", "runtime/node@2.1.0"],
        ] {
            document["runtime_layer"]["dependencies"] = Value::Array(
                references
                    .iter()
                    .map(|reference| {
                        json!({
                            "reference": reference,
                            "manifest_sha256": "c".repeat(64)
                        })
                    })
                    .collect(),
            );
            assert!(parse(&document).is_err(), "{references:?} must be refused");
        }
        document["runtime_layer"]["dependencies"] = Value::Array(
            (0..=MAX_RUNTIME_LAYER_DEPENDENCIES)
                .map(|i| {
                    json!({
                        "reference": format!("runtime/dep{i}@1.0.0"),
                        "manifest_sha256": "c".repeat(64)
                    })
                })
                .collect(),
        );
        assert!(
            parse(&document).is_err(),
            "dependency count must be bounded"
        );
    }

    #[test]
    fn duplicate_keys_and_trailing_data_are_refused() {
        let bytes = serde_json::to_vec(&document()).unwrap();
        assert!(parse_runtime_layer_manifest(&[bytes.as_slice(), b"{}"].concat()).is_err());
        assert!(
            parse_runtime_layer_manifest(&vec![b' '; MAX_REGISTRY_DESCRIPTOR_BYTES + 1]).is_err()
        );
        let valid = String::from_utf8(bytes).unwrap();
        let duplicate = valid.replacen(
            "\"schema_version\":3",
            "\"schema_version\":3,\"schema_version\":3",
            1,
        );
        assert!(parse_runtime_layer_manifest(duplicate.as_bytes()).is_err());
        let duplicate_nested = valid.replacen(
            "\"guest_arch\":\"x86_64\"",
            "\"guest_arch\":\"x86_64\",\"guest_arch\":\"x86_64\"",
            1,
        );
        assert!(parse_runtime_layer_manifest(duplicate_nested.as_bytes()).is_err());
    }
}
