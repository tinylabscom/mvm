//! Strict, nonbootable application-component inputs from signed registry metadata.
//!
//! The descriptor authenticates requirements and byte pins, not base suitability
//! or execution authority. Callers must separately admit the selected base and
//! interpret the archive and policy within that admission boundary.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::application::{deserialize_object, validate_application_source};
use super::{
    AuthenticatedRegistryManifest, MAX_REGISTRY_DESCRIPTOR_BYTES, PackPin, PackReference,
    RegistryPackFile, RegistryPackPublisherPolicy, RegistryPackSignatureChecker,
    RegistryPackVerification, RegistryPackVerificationError, VerifiedRegistryApplicationComponent,
};
use crate::packs::Sha256Hex;
use crate::plan::bundle::HashingWriter;
use crate::registry_pack_store::RegistryPackStoreError;

/// The application-component outer manifest version.
pub const APPLICATION_COMPONENT_MANIFEST_SCHEMA_VERSION: u32 = 3;
const MAX_COMPONENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const GROUP_FILE: &str = "pack/group.toml";
const PROFILE_FILE: &str = "pack/profile.toml";

/// Exact kind discriminator; never a legacy or complete application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationComponentKind {
    ApplicationComponent,
}

/// Signed, closed outer descriptor with policy files kept separate from the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryApplicationComponentManifest {
    pub schema_version: u32,
    pub kind: ApplicationComponentKind,
    pub reference: PackReference,
    pub description: String,
    #[serde(deserialize_with = "deserialize_object")]
    pub application_component: ApplicationComponent,
    pub files: Vec<RegistryPackFile>,
}

/// One architecture's application archive, requirements and named literal commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationComponent {
    pub schema_version: u32,
    pub guest_arch: String,
    #[serde(deserialize_with = "deserialize_object")]
    pub requirements: ComponentRequirements,
    #[serde(deserialize_with = "deserialize_object")]
    pub archive: ComponentArchive,
    pub entrypoints: Vec<ComponentEntrypoint>,
}

/// Requirements to compare with a selected signed base, not capabilities granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRequirements {
    pub filesystem_abi: u32,
    pub libc: String,
    #[serde(
        default,
        deserialize_with = "present_loader",
        skip_serializing_if = "Option::is_none"
    )]
    pub loader: Option<String>,
    pub minimum_kernel: String,
    pub required_capabilities: Vec<String>,
}

fn present_loader<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// External, canonical locator and exact bytes authenticated by the descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentArchive {
    pub source: String,
    pub archive_sha256: Sha256Hex,
    pub archive_size: u64,
}

/// Named literal argv; only `default` is a candidate for implicit selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentEntrypoint {
    pub name: String,
    pub argv: Vec<String>,
}

fn invalid(reason: &str) -> RegistryPackVerificationError {
    RegistryPackVerificationError::ManifestParse(reason.to_string())
}

fn canonical_name(name: &str) -> bool {
    name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path[1..]
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
        && !path.chars().any(|c| c.is_ascii_control() || c == '\\')
}

fn kernel_version(version: &str) -> bool {
    version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Parse only outer schema 3 / `application_component`, nested schema 1.
///
/// # Errors
///
/// Rejects oversized, duplicate, unknown or noncanonical descriptor data.
/// Parsing alone does not authenticate the publisher or any external bytes.
pub fn parse_application_component_manifest(
    bytes: &[u8],
) -> Result<RegistryApplicationComponentManifest, RegistryPackVerificationError> {
    if bytes.len() > MAX_REGISTRY_DESCRIPTOR_BYTES {
        return Err(invalid("application component descriptor exceeds 1 MiB"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest: RegistryApplicationComponentManifest = deserialize_object(&mut deserializer)
        .map_err(|_| invalid("application component descriptor has invalid or non-closed JSON"))?;
    deserializer
        .end()
        .map_err(|_| invalid("application component descriptor has trailing data"))?;
    let component = &manifest.application_component;
    if manifest.schema_version != APPLICATION_COMPONENT_MANIFEST_SCHEMA_VERSION
        || component.schema_version != 1
    {
        return Err(invalid(
            "application component requires outer schema 3 and nested schema 1",
        ));
    }
    let version = manifest.reference.version().map(|v| v.as_str());
    if version.is_none_or(|v| !kernel_version(v)) || manifest.description.trim().is_empty() {
        return Err(invalid(
            "application component requires an exact numeric version and description",
        ));
    }
    if !matches!(component.guest_arch.as_str(), "aarch64" | "x86_64") {
        return Err(invalid(
            "application component guest architecture is not canonical",
        ));
    }
    let archive = &component.archive;
    if archive.archive_size == 0 || archive.archive_size > MAX_COMPONENT_BYTES {
        return Err(invalid(
            "application component archive size is out of bounds",
        ));
    }
    validate_application_source(&archive.source)?;
    validate_component_requirements(&component.requirements)?;
    let mut names = BTreeSet::new();
    if component.entrypoints.len() > 16
        || component.entrypoints.iter().any(|entry| {
            !canonical_name(&entry.name)
                || !names.insert(&entry.name)
                || entry.argv.is_empty()
                || entry.argv.len() > 64
                || !absolute_path(&entry.argv[0])
                || entry
                    .argv
                    .iter()
                    .any(|arg| arg.is_empty() || arg.chars().count() > 4096 || arg.contains('\0'))
        })
    {
        return Err(invalid(
            "application component entrypoints are invalid or duplicated",
        ));
    }
    let mut paths = BTreeSet::new();
    if manifest.files.is_empty()
        || manifest.files.len() > 2
        || manifest.files.iter().any(|file| {
            !matches!(file.path.as_str(), GROUP_FILE | PROFILE_FILE)
                || !paths.insert(&file.path)
                || file.size == 0
                || file.size > MAX_REGISTRY_DESCRIPTOR_BYTES as u64
        })
    {
        return Err(invalid(
            "application component requires one or two pinned policy files",
        ));
    }
    Ok(manifest)
}

pub(super) fn validate_component_requirements(
    requirements: &ComponentRequirements,
) -> Result<(), RegistryPackVerificationError> {
    if requirements.filesystem_abi != 1
        || !kernel_version(&requirements.minimum_kernel)
        || match requirements.libc.as_str() {
            "static" => requirements.loader.is_some(),
            "musl" | "glibc" => requirements
                .loader
                .as_deref()
                .is_none_or(|p| !absolute_path(p)),
            _ => true,
        }
    {
        return Err(invalid(
            "application component requirements are not canonical",
        ));
    }
    let mut capabilities = BTreeSet::new();
    if requirements.required_capabilities.len() > 16
        || requirements
            .required_capabilities
            .iter()
            .any(|name| !canonical_name(name) || !capabilities.insert(name))
    {
        return Err(invalid(
            "application component capabilities are invalid or duplicated",
        ));
    }
    Ok(())
}

/// Verify the exact lock pin, namespace publisher and current signed revocations.
///
/// # Errors
///
/// Refuses missing or drifted pins, untrusted signatures, invalid wire shapes,
/// or a stale, absent or revoking feed. No archive is fetched.
pub fn verify_application_component_manifest(
    request: &RegistryPackVerification<'_>,
) -> Result<VerifiedRegistryApplicationComponent, ApplicationComponentInputError> {
    let verified =
        super::dispatch::verify_component_with(request, super::check_registry_pack_signature)?;
    verified.check_current_revocations()?;
    Ok(verified)
}

impl VerifiedRegistryApplicationComponent {
    /// Recheck retained signed bytes against today's publisher enrollment and lock pin.
    ///
    /// # Errors
    ///
    /// Refuses withdrawn identities or altered descriptor/signature bytes.
    pub fn reverify_publisher(&self) -> Result<(), ApplicationComponentInputError> {
        let loaded = crate::registry_pack_store::load_publisher_policy_or_official_default(
            &crate::config::registry_pack_publisher_policy_path(),
        )?;
        self.reverify_publisher_with(&loaded.policy, super::check_registry_pack_signature)
    }

    fn reverify_publisher_with(
        &self,
        policy: &RegistryPackPublisherPolicy,
        check: RegistryPackSignatureChecker,
    ) -> Result<(), ApplicationComponentInputError> {
        let pin = PackPin::new(self.reference().clone(), self.manifest_sha256().clone())?;
        let lock = super::PackLockfile::new(vec![pin])?;
        let request = RegistryPackVerification::new(
            self.reference(),
            self.manifest_bytes(),
            self.signature_bundle(),
            &lock,
            policy,
        );
        if super::dispatch::verify_component_with(&request, check)? != *self {
            return Err(invalid("retained component publisher identity changed").into());
        }
        Ok(())
    }
}

/// Local verified bytes, not a tar extraction or a launch grant.
#[derive(Debug)]
pub struct VerifiedApplicationComponentInputs {
    descriptor: VerifiedRegistryApplicationComponent,
    snapshot: tempfile::NamedTempFile,
    group: Option<Vec<u8>>,
    profile: Option<Vec<u8>>,
}

impl VerifiedApplicationComponentInputs {
    /// Signed component requirements and archive pin.
    pub fn descriptor(&self) -> &VerifiedRegistryApplicationComponent {
        &self.descriptor
    }

    /// Exact signed group policy bytes, when declared.
    pub fn group(&self) -> Option<&[u8]> {
        self.group.as_deref()
    }

    /// Exact signed profile policy bytes, when declared.
    pub fn profile(&self) -> Option<&[u8]> {
        self.profile.as_deref()
    }

    /// Recheck publisher enrollment, revocations, snapshot and policy bytes.
    ///
    /// # Errors
    ///
    /// Refuses changed evidence or payload and stale or withdrawn trust.
    pub fn reverify(&self) -> Result<(), ApplicationComponentInputError> {
        self.descriptor.reverify_publisher()?;
        self.descriptor.check_current_revocations()?;
        self.reverify_bytes()
    }

    fn reverify_bytes(&self) -> Result<(), ApplicationComponentInputError> {
        let expected = &self.descriptor.manifest().application_component.archive;
        let mut reader = self.snapshot.reopen()?;
        if reader.metadata()?.len() != expected.archive_size {
            return Err(ApplicationComponentInputError::Size);
        }
        let mut hasher = HashingWriter::new(std::io::sink());
        std::io::copy(
            &mut reader.by_ref().take(expected.archive_size + 1),
            &mut hasher,
        )?;
        let (size, digest) = hasher.finish();
        if size != expected.archive_size || digest != expected.archive_sha256.as_str() {
            return Err(ApplicationComponentInputError::Digest);
        }
        for file in &self.descriptor.manifest().files {
            let bytes = match file.path.as_str() {
                GROUP_FILE => self.group(),
                PROFILE_FILE => self.profile(),
                _ => None,
            }
            .ok_or(ApplicationComponentInputError::Digest)?;
            if bytes.len() as u64 != file.size || Sha256Hex::from_bytes(bytes) != file.sha256 {
                return Err(ApplicationComponentInputError::Digest);
            }
        }
        Ok(())
    }

    /// Recheck trust and return a private archive stream; no extraction occurs.
    ///
    /// # Errors
    ///
    /// Refuses altered bytes or withdrawn trust.
    pub fn open_verified_archive(&self) -> Result<std::fs::File, ApplicationComponentInputError> {
        self.reverify()?;
        Ok(std::fs::File::open(self.snapshot.path())?)
    }
}

/// Failure to authenticate a component's descriptor or locally supplied bytes.
#[derive(Debug, Error)]
pub enum ApplicationComponentInputError {
    #[error(transparent)]
    Verification(#[from] RegistryPackVerificationError),
    #[error(transparent)]
    Trust(#[from] RegistryPackStoreError),
    #[error(transparent)]
    Lock(#[from] super::RegistryPackError),
    #[error("application component input I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("application component archive is not a regular file matching its signed size")]
    Size,
    #[error("application component bytes differ from their signed descriptor")]
    Digest,
}

/// Snapshot and hash an external archive and all signed policy files.
///
/// # Errors
///
/// Refuses missing, linked, special, changed, oversized or mismatched bytes,
/// and checks current publisher trust and revocation before returning custody.
pub fn verify_application_component_inputs(
    descriptor: &VerifiedRegistryApplicationComponent,
    archive: &Path,
    files_root: &Path,
) -> Result<VerifiedApplicationComponentInputs, ApplicationComponentInputError> {
    verify_inputs_with(
        descriptor,
        archive,
        files_root,
        VerifiedRegistryApplicationComponent::reverify_publisher,
        |descriptor| descriptor.check_current_revocations().map_err(Into::into),
    )
}

fn verify_inputs_with(
    descriptor: &VerifiedRegistryApplicationComponent,
    archive: &Path,
    files_root: &Path,
    publisher: impl FnOnce(
        &VerifiedRegistryApplicationComponent,
    ) -> Result<(), ApplicationComponentInputError>,
    revocations: impl FnOnce(
        &VerifiedRegistryApplicationComponent,
    ) -> Result<(), ApplicationComponentInputError>,
) -> Result<VerifiedApplicationComponentInputs, ApplicationComponentInputError> {
    publisher(descriptor)?;
    revocations(descriptor)?;
    let expected = &descriptor.manifest().application_component.archive;
    let input = super::local_input::open_sized_regular(archive, expected.archive_size).map_err(
        |error| {
            if error.kind() == std::io::ErrorKind::Other {
                ApplicationComponentInputError::Size
            } else {
                ApplicationComponentInputError::Io(error)
            }
        },
    )?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    let mut hasher = HashingWriter::new(snapshot.as_file_mut());
    std::io::copy(&mut input.take(expected.archive_size + 1), &mut hasher)?;
    let (size, digest) = hasher.finish();
    if size != expected.archive_size {
        return Err(ApplicationComponentInputError::Size);
    }
    if digest != expected.archive_sha256.as_str() {
        return Err(ApplicationComponentInputError::Digest);
    }
    snapshot.as_file().sync_all()?;
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
        if bytes.len() as u64 != file.size || Sha256Hex::from_bytes(&bytes) != file.sha256 {
            return Err(ApplicationComponentInputError::Digest);
        }
        match file.path.as_str() {
            GROUP_FILE => group = Some(bytes),
            PROFILE_FILE => profile = Some(bytes),
            _ => return Err(ApplicationComponentInputError::Digest),
        }
    }
    let held = VerifiedApplicationComponentInputs {
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
