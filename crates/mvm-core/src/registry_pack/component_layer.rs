//! Strict signed runtime and tool components, without legacy-layer fallback.
//!
//! A descriptor authenticates immutable bytes and compatibility requirements.
//! It does not prove a selected base satisfies those requirements or grant
//! permission to extract an archive or apply policy.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::application::{deserialize_object, validate_application_source};
use super::application_component::{
    ComponentArchive, ComponentRequirements, validate_component_requirements,
};
use super::{
    MAX_REGISTRY_DESCRIPTOR_BYTES, PackAdoption, PackLockfile, PackPin, PackReference,
    RegistryPackFile, RegistryPackPublisherPolicy, RegistryPackSignatureChecker,
    RegistryPackVerification, RegistryPackVerificationError,
};
use crate::crypto::image_verify::VerifiedSigner;
use crate::packs::Sha256Hex;
use crate::plan::bundle::HashingWriter;
use crate::registry_pack_store::RegistryPackStoreError;

/// Outer schema for strictly versioned, nonbootable runtime and tool components.
pub const COMPONENT_LAYER_MANIFEST_SCHEMA_VERSION: u32 = 4;
const MAX_COMPONENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DEPENDENCIES: usize = 16;
const MAX_RESOLVED_COMPONENTS: usize = 64;
const GROUP_FILE: &str = "pack/group.toml";
const PROFILE_FILE: &str = "pack/profile.toml";

/// The only two component-layer roles. A schema 3 runtime layer is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentLayerKind {
    Runtime,
    Tool,
}

/// One architecture's signed compatibility requirements and immutable inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentLayer {
    pub schema_version: u32,
    pub guest_arch: String,
    #[serde(deserialize_with = "deserialize_object")]
    pub requirements: ComponentRequirements,
    pub dependencies: Vec<PackPin>,
    #[serde(deserialize_with = "deserialize_object")]
    pub archive: ComponentArchive,
}

/// Closed signed wire shape; the kind determines the sole permitted nested field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistryComponentLayerManifest {
    RuntimeComponent {
        schema_version: u32,
        reference: PackReference,
        description: String,
        #[serde(deserialize_with = "deserialize_object")]
        runtime_component: ComponentLayer,
        files: Vec<RegistryPackFile>,
    },
    ToolComponent {
        schema_version: u32,
        reference: PackReference,
        description: String,
        #[serde(deserialize_with = "deserialize_object")]
        tool_component: ComponentLayer,
        files: Vec<RegistryPackFile>,
    },
}

impl RegistryComponentLayerManifest {
    /// Runtime or tool role selected by the exact signed kind.
    pub fn kind(&self) -> ComponentLayerKind {
        match self {
            Self::RuntimeComponent { .. } => ComponentLayerKind::Runtime,
            Self::ToolComponent { .. } => ComponentLayerKind::Tool,
        }
    }

    /// Exact versioned pack identity.
    pub fn reference(&self) -> &PackReference {
        match self {
            Self::RuntimeComponent { reference, .. } | Self::ToolComponent { reference, .. } => {
                reference
            }
        }
    }

    /// Signed requirements, ordered dependencies and archive bytes.
    pub fn component(&self) -> &ComponentLayer {
        match self {
            Self::RuntimeComponent {
                runtime_component, ..
            } => runtime_component,
            Self::ToolComponent { tool_component, .. } => tool_component,
        }
    }

    /// Signed policy inventory, not authorization to apply its contents.
    pub fn files(&self) -> &[RegistryPackFile] {
        match self {
            Self::RuntimeComponent { files, .. } | Self::ToolComponent { files, .. } => files,
        }
    }
}

fn invalid(reason: &str) -> RegistryPackVerificationError {
    RegistryPackVerificationError::ManifestParse(reason.to_string())
}

/// Parse only schema 4 runtime/tool component descriptors with closed shapes.
///
/// # Errors
///
/// Refuses oversized, unknown, duplicate, hybrid, unversioned or noncanonical data.
/// No publisher, external archive or policy bytes are authenticated by parsing.
pub fn parse_component_layer_manifest(
    bytes: &[u8],
) -> Result<RegistryComponentLayerManifest, RegistryPackVerificationError> {
    if bytes.len() > MAX_REGISTRY_DESCRIPTOR_BYTES {
        return Err(invalid("component layer descriptor exceeds 1 MiB"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest: RegistryComponentLayerManifest = deserialize_object(&mut deserializer)
        .map_err(|_| invalid("component layer descriptor has invalid or non-closed JSON"))?;
    deserializer
        .end()
        .map_err(|_| invalid("component layer descriptor has trailing data"))?;
    let (schema_version, description) = match &manifest {
        RegistryComponentLayerManifest::RuntimeComponent {
            schema_version,
            description,
            ..
        }
        | RegistryComponentLayerManifest::ToolComponent {
            schema_version,
            description,
            ..
        } => (*schema_version, description),
    };
    let component = manifest.component();
    let reference = manifest.reference();
    if schema_version != COMPONENT_LAYER_MANIFEST_SCHEMA_VERSION || component.schema_version != 1 {
        return Err(invalid(
            "component layer requires outer schema 4 and nested schema 1",
        ));
    }
    let namespace = match manifest.kind() {
        ComponentLayerKind::Runtime => "runtime",
        ComponentLayerKind::Tool => "tool",
    };
    if reference.namespace() != namespace
        || reference
            .version()
            .is_none_or(|version| version.as_str().contains('+'))
        || description.trim().is_empty()
    {
        return Err(invalid(
            "component layer requires a matching, versioned identity and description",
        ));
    }
    if !matches!(component.guest_arch.as_str(), "aarch64" | "x86_64") {
        return Err(invalid(
            "component layer guest architecture is not canonical",
        ));
    }
    validate_component_requirements(&component.requirements, &component.guest_arch)?;
    if component.archive.archive_size == 0 || component.archive.archive_size > MAX_COMPONENT_BYTES {
        return Err(invalid("component layer archive size is out of bounds"));
    }
    validate_application_source(&component.archive.source)?;
    if component.dependencies.len() > MAX_DEPENDENCIES {
        return Err(invalid("component layer declares too many dependencies"));
    }
    let mut dependencies = BTreeSet::new();
    for dependency in &component.dependencies {
        let reference = dependency.reference();
        if !matches!(reference.namespace(), "runtime" | "tool")
            || reference
                .version()
                .is_none_or(|version| version.as_str().contains('+'))
            || reference.coordinate_string() == manifest.reference().coordinate_string()
            || !dependencies.insert(reference.coordinate_string())
        {
            return Err(invalid(
                "component layer has a duplicate, self or non-component dependency",
            ));
        }
    }
    let mut paths = BTreeSet::new();
    if manifest.files().is_empty()
        || manifest.files().len() > 2
        || manifest.files().iter().any(|file| {
            !matches!(file.path.as_str(), GROUP_FILE | PROFILE_FILE)
                || !paths.insert(file.path.as_str())
                || file.size == 0
                || file.size > MAX_REGISTRY_DESCRIPTOR_BYTES as u64
        })
    {
        return Err(invalid(
            "component layer requires one or two pinned policy documents",
        ));
    }
    Ok(manifest)
}

/// Publisher-authenticated component metadata, not an installed or executable pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryComponentLayer {
    manifest: RegistryComponentLayerManifest,
    manifest_bytes: Vec<u8>,
    signature_bundle: Vec<u8>,
    manifest_sha256: Sha256Hex,
    signer: VerifiedSigner,
}

impl VerifiedRegistryComponentLayer {
    /// Strictly parsed signed descriptor.
    pub fn manifest(&self) -> &RegistryComponentLayerManifest {
        &self.manifest
    }

    /// Exact publisher-signed bytes, without reserialization.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Detached signature evidence.
    pub fn signature_bundle(&self) -> &[u8] {
        &self.signature_bundle
    }

    /// Digest of the exact original signed descriptor bytes.
    pub fn manifest_sha256(&self) -> &Sha256Hex {
        &self.manifest_sha256
    }

    /// Publisher identity verified under the namespace's enrolled authority.
    pub fn signer(&self) -> &VerifiedSigner {
        &self.signer
    }

    /// Require a current authenticated feed, with no legacy absent-feed fallback.
    ///
    /// # Errors
    ///
    /// Refuses revoked identities or manifests, expired feeds or missing trust.
    pub fn check_current_revocations(&self) -> Result<(), RegistryPackStoreError> {
        crate::registry_pack_store::check_application_revocations(self)
    }

    /// Recheck signed evidence against the current publisher enrollment.
    ///
    /// # Errors
    ///
    /// Refuses withdrawn or changed publisher authority.
    pub fn reverify_publisher(&self) -> Result<(), ComponentLayerInputError> {
        let loaded = crate::registry_pack_store::load_publisher_policy_or_official_default(
            &crate::config::registry_pack_publisher_policy_path(),
        )?;
        self.reverify_publisher_with(&loaded.policy, super::check_registry_pack_signature)
    }

    fn reverify_publisher_with(
        &self,
        policy: &RegistryPackPublisherPolicy,
        check: RegistryPackSignatureChecker,
    ) -> Result<(), ComponentLayerInputError> {
        let pin = PackPin::new(
            self.manifest.reference().clone(),
            self.manifest_sha256.clone(),
        )?;
        let lock = PackLockfile::new(vec![pin])?;
        let request = RegistryPackVerification::new(
            self.manifest.reference(),
            &self.manifest_bytes,
            &self.signature_bundle,
            &lock,
            policy,
        );
        if verify_component_layer_with(&request, check)? != *self {
            return Err(invalid("retained component layer publisher identity changed").into());
        }
        Ok(())
    }
}

/// Verify the exact lock pin, enrolled namespace signer and current revocations.
///
/// # Errors
///
/// Refuses drifted pins, untrusted signatures, invalid descriptors or revoked
/// metadata. No archive is acquired and no base compatibility is asserted.
pub fn verify_component_layer_manifest(
    request: &RegistryPackVerification<'_>,
) -> Result<VerifiedRegistryComponentLayer, ComponentLayerInputError> {
    let verified = verify_component_layer_with(request, super::check_registry_pack_signature)?;
    verified.check_current_revocations()?;
    Ok(verified)
}

fn verify_component_layer_with(
    request: &RegistryPackVerification<'_>,
    check: RegistryPackSignatureChecker,
) -> Result<VerifiedRegistryComponentLayer, RegistryPackVerificationError> {
    match super::dispatch::verify_with(request, check)? {
        super::VerifiedRegistryManifest::ComponentLayer(component) => Ok(component),
        _ => Err(invalid("pinned pack is not a runtime or tool component")),
    }
}

/// Complete the typed component branch after dispatch verifies the publisher.
pub(super) fn finish_component_layer(
    request: &PackAdoption<'_>,
    signer: VerifiedSigner,
) -> Result<VerifiedRegistryComponentLayer, RegistryPackVerificationError> {
    let manifest = parse_component_layer_manifest(request.manifest_bytes)?;
    let reference = manifest.reference();
    if reference.coordinate != request.requested.coordinate
        || request
            .requested
            .version
            .as_ref()
            .is_some_and(|version| Some(version) != reference.version.as_ref())
    {
        return Err(RegistryPackVerificationError::ManifestReferenceMismatch {
            manifest: reference.to_string(),
            locked: request.requested.to_string(),
        });
    }
    let manifest_sha256 = Sha256Hex::from_bytes(request.manifest_bytes);
    super::historical::check_legacy_manifest_policy(
        request.publisher_policy,
        &signer.identity,
        reference,
        &manifest_sha256,
    )?;
    Ok(VerifiedRegistryComponentLayer {
        manifest,
        manifest_sha256,
        signer,
        manifest_bytes: request.manifest_bytes.to_vec(),
        signature_bundle: request.signature_bundle.to_vec(),
    })
}

/// Failure to resolve exact signed runtime/tool dependencies.
#[derive(Debug, Error)]
pub enum ComponentLayerResolveError {
    #[error("component graph exceeds its bound or contains duplicate names")]
    InvalidGraph,
    #[error("component dependency is missing: {0}")]
    Missing(String),
    #[error("component dependency pin or architecture differs: {0}")]
    Drift(String),
    #[error("component dependency cycle at {0}")]
    Cycle(String),
    #[error(transparent)]
    Revocation(#[from] RegistryPackStoreError),
}

/// Resolve exact signed pins into dependency-first order, checking revocations.
///
/// This accepts only schema 4 component metadata and cannot silently upgrade
/// schema 3 runtime layers. The returned metadata is not base compatibility or
/// permission to unpack an archive or apply policy.
///
/// # Errors
///
/// Refuses absent, drifted, duplicate, cyclic, wrong-architecture or revoked
/// components. Every selected manifest needs a current signed revocation feed.
pub fn resolve_component_layers<'a>(
    roots: &[PackPin],
    candidates: &'a [VerifiedRegistryComponentLayer],
    arch: &str,
) -> Result<Vec<&'a VerifiedRegistryComponentLayer>, ComponentLayerResolveError> {
    let ordered = resolve_graph(roots, candidates, arch)?;
    for component in &ordered {
        component.check_current_revocations()?;
    }
    Ok(ordered)
}

fn resolve_graph<'a>(
    roots: &[PackPin],
    candidates: &'a [VerifiedRegistryComponentLayer],
    arch: &str,
) -> Result<Vec<&'a VerifiedRegistryComponentLayer>, ComponentLayerResolveError> {
    if !matches!(arch, "x86_64" | "aarch64")
        || roots.len() > MAX_RESOLVED_COMPONENTS
        || candidates.len() > MAX_RESOLVED_COMPONENTS
    {
        return Err(ComponentLayerResolveError::InvalidGraph);
    }
    let mut by_name = BTreeMap::new();
    for component in candidates {
        if by_name
            .insert(
                component.manifest().reference().coordinate_string(),
                component,
            )
            .is_some()
        {
            return Err(ComponentLayerResolveError::InvalidGraph);
        }
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut root_names = BTreeSet::new();
    let mut ordered = Vec::new();
    for root in roots {
        if !root_names.insert(root.reference().coordinate_string()) {
            return Err(ComponentLayerResolveError::InvalidGraph);
        }
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
    by_name: &BTreeMap<String, &'a VerifiedRegistryComponentLayer>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    ordered: &mut Vec<&'a VerifiedRegistryComponentLayer>,
) -> Result<(), ComponentLayerResolveError> {
    let name = pin.reference().coordinate_string();
    let component = by_name
        .get(&name)
        .ok_or_else(|| ComponentLayerResolveError::Missing(pin.reference().to_string()))?;
    if component.manifest().reference() != pin.reference()
        || component.manifest_sha256() != pin.manifest_sha256()
        || component.manifest().component().guest_arch != arch
    {
        return Err(ComponentLayerResolveError::Drift(
            pin.reference().to_string(),
        ));
    }
    if visiting.contains(&name) {
        return Err(ComponentLayerResolveError::Cycle(name));
    }
    if visited.contains(&name) {
        return Ok(());
    }
    visiting.insert(name.clone());
    for dependency in &component.manifest().component().dependencies {
        visit(dependency, arch, by_name, visiting, visited, ordered)?;
    }
    visiting.remove(&name);
    visited.insert(name);
    ordered.push(component);
    Ok(())
}

/// Failure to authenticate or hold a complete component input.
#[derive(Debug, Error)]
pub enum ComponentLayerInputError {
    #[error(transparent)]
    Verification(#[from] RegistryPackVerificationError),
    #[error(transparent)]
    Trust(#[from] RegistryPackStoreError),
    #[error(transparent)]
    Lock(#[from] super::RegistryPackError),
    #[error("component layer input I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("component layer archive is not a regular file matching its signed size")]
    Size,
    #[error("component layer bytes differ from their signed descriptor")]
    Digest,
}

/// A private snapshot and signed policies, not an extracted or admitted layer.
#[derive(Debug)]
pub struct VerifiedComponentLayerInputs {
    descriptor: VerifiedRegistryComponentLayer,
    snapshot: tempfile::NamedTempFile,
    group: Option<Vec<u8>>,
    profile: Option<Vec<u8>>,
}

impl VerifiedComponentLayerInputs {
    /// Authenticated typed metadata, including requirements and ordered pins.
    pub fn descriptor(&self) -> &VerifiedRegistryComponentLayer {
        &self.descriptor
    }

    /// Exact signed group policy bytes, if declared.
    pub fn group(&self) -> Option<&[u8]> {
        self.group.as_deref()
    }

    /// Exact signed profile policy bytes, if declared.
    pub fn profile(&self) -> Option<&[u8]> {
        self.profile.as_deref()
    }

    /// Recheck publisher, revocations, archive and held policy bytes.
    ///
    /// # Errors
    ///
    /// Refuses withdrawn trust or changed held bytes.
    pub fn reverify(&self) -> Result<(), ComponentLayerInputError> {
        self.descriptor.reverify_publisher()?;
        self.descriptor.check_current_revocations()?;
        self.reverify_bytes()
    }

    fn reverify_bytes(&self) -> Result<(), ComponentLayerInputError> {
        let expected = &self.descriptor.manifest.component().archive;
        let reader = self.snapshot.reopen()?;
        if reader.metadata()?.len() != expected.archive_size {
            return Err(ComponentLayerInputError::Size);
        }
        let mut writer = HashingWriter::new(std::io::sink());
        std::io::copy(&mut reader.take(expected.archive_size + 1), &mut writer)?;
        let (size, digest) = writer.finish();
        if size != expected.archive_size || digest != expected.archive_sha256.as_str() {
            return Err(ComponentLayerInputError::Digest);
        }
        for file in self.descriptor.manifest.files() {
            let bytes = match file.path.as_str() {
                GROUP_FILE => self.group(),
                PROFILE_FILE => self.profile(),
                _ => None,
            }
            .ok_or(ComponentLayerInputError::Digest)?;
            if bytes.len() as u64 != file.size || Sha256Hex::from_bytes(bytes) != file.sha256 {
                return Err(ComponentLayerInputError::Digest);
            }
        }
        Ok(())
    }

    /// Open the private archive after rechecking trust and exact byte identity.
    ///
    /// # Errors
    ///
    /// Refuses changed bytes, publisher policy or revocation feed.
    pub fn open_verified_archive(&self) -> Result<std::fs::File, ComponentLayerInputError> {
        self.reverify()?;
        Ok(std::fs::File::open(self.snapshot.path())?)
    }
}

/// Snapshot exact external archive bytes and every signed policy document.
///
/// # Errors
///
/// Refuses missing, linked, special, changed, oversized or mismatched inputs.
/// This does not verify archive entries or prove selected-base compatibility.
pub fn verify_component_layer_inputs(
    descriptor: &VerifiedRegistryComponentLayer,
    archive: &Path,
    files_root: &Path,
) -> Result<VerifiedComponentLayerInputs, ComponentLayerInputError> {
    verify_inputs_with(
        descriptor,
        archive,
        files_root,
        VerifiedRegistryComponentLayer::reverify_publisher,
        |descriptor| descriptor.check_current_revocations().map_err(Into::into),
    )
}

fn verify_inputs_with(
    descriptor: &VerifiedRegistryComponentLayer,
    archive: &Path,
    files_root: &Path,
    publisher: impl FnOnce(&VerifiedRegistryComponentLayer) -> Result<(), ComponentLayerInputError>,
    revocations: impl FnOnce(&VerifiedRegistryComponentLayer) -> Result<(), ComponentLayerInputError>,
) -> Result<VerifiedComponentLayerInputs, ComponentLayerInputError> {
    publisher(descriptor)?;
    revocations(descriptor)?;
    let expected = &descriptor.manifest.component().archive;
    let input = super::local_input::open_sized_regular(archive, expected.archive_size).map_err(
        |error| {
            if error.kind() == std::io::ErrorKind::Other {
                ComponentLayerInputError::Size
            } else {
                ComponentLayerInputError::Io(error)
            }
        },
    )?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    let mut writer = HashingWriter::new(snapshot.as_file_mut());
    std::io::copy(&mut input.take(expected.archive_size + 1), &mut writer)?;
    let (size, digest) = writer.finish();
    if size != expected.archive_size {
        return Err(ComponentLayerInputError::Size);
    }
    if digest != expected.archive_sha256.as_str() {
        return Err(ComponentLayerInputError::Digest);
    }
    snapshot.as_file().sync_all()?;
    let mut group = None;
    let mut profile = None;
    for file in descriptor.manifest.files() {
        let mut source = super::local_input::open_payload(files_root, &file.path, file.size)?;
        let before = source.metadata()?;
        let mut bytes = Vec::new();
        source
            .by_ref()
            .take(file.size + 1)
            .read_to_end(&mut bytes)?;
        super::local_input::ensure_unchanged(&source, &before, files_root, &file.path, file.size)?;
        if bytes.len() as u64 != file.size || Sha256Hex::from_bytes(&bytes) != file.sha256 {
            return Err(ComponentLayerInputError::Digest);
        }
        match file.path.as_str() {
            GROUP_FILE => group = Some(bytes),
            PROFILE_FILE => profile = Some(bytes),
            _ => return Err(ComponentLayerInputError::Digest),
        }
    }
    let held = VerifiedComponentLayerInputs {
        descriptor: descriptor.clone(),
        snapshot,
        group,
        profile,
    };
    held.reverify_bytes()?;
    Ok(held)
}

#[cfg(test)]
mod tests;
