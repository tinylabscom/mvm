//! Signed declarations binding registry policy to installed workload archives.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use mvm_core::arch::GuestArch;
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::bundle::{
    ArtifactRole, BundleRegistry, FsTrustStore, MAX_BUNDLE_TOTAL_BYTES, TrustStore,
    VerifiedBundleFile, verify_bundle_file,
};
use mvm_core::registry_pack::{
    MAX_APPLICATION_POLICY_BYTES, PackReference, REGISTRY_APPLICATION_FILE as DECLARATION_FILE,
    REGISTRY_APPLICATION_POLICY_ARTIFACT, VerifiedRegistryPack,
};

const PROFILE_FILE: &str = "pack/profile.toml";
const ARCHIVE_PROFILE: &str = "artifacts/policy/profile.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    schema_version: u32,
    #[serde(deserialize_with = "unique_archives")]
    archives: BTreeMap<GuestArch, Archive>,
}

fn unique_archives<'de, D>(deserializer: D) -> Result<BTreeMap<GuestArch, Archive>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ArchivesVisitor;
    impl<'de> serde::de::Visitor<'de> for ArchivesVisitor {
        type Value = BTreeMap<GuestArch, Archive>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object with unique supported architecture keys")
        }

        fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut archives = BTreeMap::new();
            while let Some((arch, archive)) = entries.next_entry::<GuestArch, Archive>()? {
                if archives.insert(arch, archive).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate application architecture",
                    ));
                }
            }
            Ok(archives)
        }
    }
    deserializer.deserialize_map(ArchivesVisitor)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    url: String,
    sha256: Sha256Hex,
    size_bytes: u64,
    key_id: String,
}

impl Declaration {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let declaration: Self = serde_json::from_slice(bytes)?;
        if declaration.schema_version != 1 || declaration.archives.is_empty() {
            bail!("unsupported or empty application declaration");
        }
        for archive in declaration.archives.values() {
            let url = mvm_http::Url::parse(&archive.url)?;
            let segments = url
                .path_segments()
                .context("archive URL has no release path")?
                .collect::<Vec<_>>();
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.host_str() != Some("github.com")
                || segments.len() != 6
                || segments[2] != "releases"
                || segments[3] != "download"
                || segments.iter().any(|s| s.is_empty())
                || segments[4].eq_ignore_ascii_case("latest")
            {
                bail!("application archive must name an immutable HTTPS release asset");
            }
            if archive.size_bytes == 0
                || archive.size_bytes > MAX_BUNDLE_TOTAL_BYTES
                || archive.key_id.len() != 32
                || !archive
                    .key_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                bail!("invalid application archive size or signing key identifier");
            }
        }
        Ok(declaration)
    }

    fn selected(&self) -> Result<&Archive> {
        self.archives
            .get(&GuestArch::host())
            .context("application has no archive for this host architecture")
    }
}

/// A fully verified installed application selected by an exact registry pin.
#[derive(Debug)]
pub struct InstalledApplication {
    pub bundle_sha256: String,
    pub reference: PackReference,
    pub policy_path: PathBuf,
}

fn declaration(
    payload_root: &Path,
    verified: &VerifiedRegistryPack,
) -> Result<Option<Declaration>> {
    let files = verified.payload_files();
    let Some(metadata) = files.iter().find(|file| file.path == DECLARATION_FILE) else {
        return Ok(None);
    };
    anyhow::ensure!(
        metadata.size > 0 && metadata.size <= 64 * 1024,
        "application declaration must contain between 1 and 65536 bytes"
    );
    if !files.iter().any(|file| {
        file.path == PROFILE_FILE
            && file.size > 0
            && file.size <= MAX_APPLICATION_POLICY_BYTES as u64
    }) {
        bail!("runnable application requires a signed pack/profile.toml");
    }
    Declaration::parse(&std::fs::read(payload_root.join(DECLARATION_FILE))?).map(Some)
}

fn check_archive(
    path: &Path,
    archive: &Archive,
    reference: &PackReference,
    profile: &[u8],
    trust: &dyn TrustStore,
) -> Result<VerifiedBundleFile> {
    if std::fs::metadata(path)?.len() != archive.size_bytes {
        bail!("application archive size differs from signed declaration");
    }
    let verified = verify_bundle_file(path, trust)?;
    if verified.bundle_sha256 != archive.sha256.as_str() || verified.key_id.0 != archive.key_id {
        bail!("application archive digest or signing key differs from signed declaration");
    }
    let manifest = &verified.manifest;
    if manifest.arch != GuestArch::host().to_string()
        || manifest.find_by_role(&ArtifactRole::Initrd).is_none()
        || verified
            .boot_assets
            .as_ref()
            .is_none_or(|assets| assets.arch != GuestArch::host())
    {
        bail!("application archive lacks the complete host boot closure");
    }
    mvm_core::image_set::check_protocol_compatibility(
        &verified
            .boot_assets
            .as_ref()
            .context("application boot assets are missing")?
            .image_set
            .manifest,
        &mvm_build::stage0_kernel::current_image_set_protocol_support(),
    )
    .context("application boot protocols are incompatible")?;
    let environment = manifest
        .environment()
        .context("application archive has no environment")?;
    let identity = environment
        .pack
        .as_ref()
        .context("application environment has no pack identity")?;
    if format!("{}@{}", identity.name, identity.version) != reference.to_string() {
        bail!("application archive pack identity differs from registry reference");
    }
    let posture = manifest
        .security_posture()
        .context("application archive has no security posture")?;
    if !matches!(
        posture.profile,
        mvm_core::security::AgentProfile::Dev | mvm_core::security::AgentProfile::SealedProd
    ) || !posture.verity_protected
        || !posture.requires_auth
        || manifest.verity.is_none()
        || manifest.find_by_role(&ArtifactRole::Kernel).is_none()
        || manifest.find_by_role(&ArtifactRole::Rootfs).is_none()
    {
        bail!("application archive requires authenticated verified boot");
    }
    let sidecar = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == mvm_core::guest_sidecar::SIDECAR_FILENAME)
        .context("application archive lacks its runtime compatibility sidecar")?;
    anyhow::ensure!(
        sidecar.role == ArtifactRole::Other
            && sidecar.path == format!("artifacts/{}", mvm_core::guest_sidecar::SIDECAR_FILENAME)
            && sidecar.size_bytes > 0,
        "application archive has an invalid runtime compatibility sidecar"
    );
    let policy = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.name == REGISTRY_APPLICATION_POLICY_ARTIFACT)
        .context("application archive lacks policy/profile.toml")?;
    if policy.path != ARCHIVE_PROFILE
        || policy.role != ArtifactRole::Other
        || policy.size_bytes != u64::try_from(profile.len())?
        || policy.sha256 != Sha256Hex::from_bytes(profile).as_str()
    {
        bail!("application archive policy differs from signed registry policy");
    }
    Ok(verified)
}

pub(crate) fn install_declared(payload_root: &Path, verified: &VerifiedRegistryPack) -> Result<()> {
    if !verified
        .manifest()
        .files
        .iter()
        .any(|file| file.path == DECLARATION_FILE)
    {
        return Ok(());
    }
    mvm_core::registry_pack::verify_registry_pack_contents(verified, payload_root)?;
    let declaration = declaration(payload_root, verified)?
        .context("signed application declaration is missing")?;
    let archive = declaration.selected()?;
    let staging = tempfile::tempdir_in("/tmp")?;
    let path = staging.path().join("application.mvmpkg");
    crate::pack_registry::download_payload_file(&archive.url, &path, archive.size_bytes, true)?;
    let profile = std::fs::read(payload_root.join(PROFILE_FILE))?;
    let checked = check_archive(
        &path,
        archive,
        &verified.manifest().reference,
        &profile,
        &FsTrustStore::default_path()?,
    )?;
    let registry = BundleRegistry::default_path()?;
    // Replacement repairs any stale extracted bytes through the existing verifier.
    registry.install_file_with_preflight(
        &path,
        &FsTrustStore::default_path()?,
        true,
        |root, manifest, sha| {
            anyhow::ensure!(
                manifest == &checked.manifest && sha == checked.bundle_sha256.as_str(),
                "application archive changed before installation"
            );
            mvm_client::launch::bundle_runtime::validate_payloads(root, &checked)
                .context("application boot runtime is incompatible")?;
            // Downloads and validation may outlive the feed checked before
            // acquisition. Recheck freshness at the installation boundary.
            mvm_core::registry_pack_store::check_registry_pack_revocations_if_configured(verified)?;
            Ok(())
        },
    )?;
    Ok(())
}

/// Resolve only a pinned pack coordinate. Never downloads or builds.
pub fn resolve_installed(reference: &str) -> Result<Option<InstalledApplication>> {
    use mvm_core::registry_pack_store::{
        load_pack_lockfile, load_publisher_policy_or_official_default, open_installed_registry_pack,
    };
    let Ok(reference) = reference.parse::<PackReference>() else {
        return Ok(None);
    };
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let Some(reference) = locked_reference(&lock, &reference) else {
        return Ok(None);
    };
    let publisher = load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?;
    let (installed, verified) = open_installed_registry_pack(
        &mvm_core::config::registry_pack_cache_dir(),
        &lock,
        &publisher.policy,
        &reference,
    )?;
    let declaration = declaration(&installed.payload_root(), &verified)?
        .context("pinned pack is policy-only; it declares no runnable application")?;
    let archive = declaration.selected()?;
    let registry = BundleRegistry::default_path()?;
    let path = registry.archive_path(archive.sha256.as_str());
    if !path.is_file() {
        bail!("application archive is missing; pull {reference} before running it");
    }
    let policy_path = installed.payload_root().join(PROFILE_FILE);
    let profile = std::fs::read(&policy_path)?;
    let checked = check_archive(
        &path,
        archive,
        &reference,
        &profile,
        &FsTrustStore::default_path()?,
    )?;
    let root = check_installed(&registry, &checked, &profile)
        .with_context(|| format!("application install is missing or changed; pull {reference}"))?;
    mvm_client::launch::bundle_runtime::validate_payloads(&root, &checked)
        .context("installed application boot runtime is incompatible")?;
    Ok(Some(InstalledApplication {
        bundle_sha256: checked.bundle_sha256,
        reference,
        policy_path,
    }))
}

fn locked_reference(
    lock: &mvm_core::registry_pack::PackLockfile,
    requested: &PackReference,
) -> Option<PackReference> {
    lock.pins()
        .iter()
        .find(|pin| {
            pin.reference().coordinate_string() == requested.coordinate_string()
                && (requested.version().is_none() || pin.reference() == requested)
        })
        .map(|pin| pin.reference().clone())
}

fn check_installed(
    registry: &BundleRegistry,
    checked: &VerifiedBundleFile,
    profile: &[u8],
) -> Result<PathBuf> {
    let bundle = registry
        .find(&checked.bundle_sha256)?
        .context("application is not installed")?;
    if bundle.manifest != checked.manifest {
        bail!("installed application manifest differs from verified archive");
    }
    for artifact in &checked.manifest.artifacts {
        let artifact_path = bundle.root.join(&artifact.path);
        let file = std::fs::File::open(&artifact_path)?;
        if file.metadata()?.len() != artifact.size_bytes
            || mvm_core::crypto::image_verify::sha256_reader(file)? != artifact.sha256
        {
            bail!("installed application artifact differs from verified archive");
        }
    }
    if std::fs::read(bundle.root.join(ARCHIVE_PROFILE))? != profile {
        bail!("installed application policy differs from signed registry policy");
    }
    Ok(bundle.root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_core::plan::bundle::{
        BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, KeyId, key_id_from_pubkey,
        write_bundle,
    };
    use serde_json::{Value, json};

    fn metadata() -> Value {
        json!({
            "schema_version": 1,
            "archives": {
                "aarch64": {
                    "url": "https://github.com/owner/repository/releases/download/1.0.0/application.mvmpkg",
                    "sha256": "a".repeat(64),
                    "size_bytes": 42,
                    "key_id": "b".repeat(32)
                },
                "x86_64": {
                    "url": "https://github.com/owner/repository/releases/download/1.0.0/application-x86_64.mvmpkg",
                    "sha256": "c".repeat(64),
                    "size_bytes": 43,
                    "key_id": "d".repeat(32)
                }
            }
        })
    }

    fn parse(value: &Value) -> Result<Declaration> {
        Declaration::parse(&serde_json::to_vec(value)?)
    }

    #[test]
    fn strict_metadata_selects_only_host_architecture() {
        let declaration = parse(&metadata()).unwrap();
        let size = match GuestArch::host() {
            GuestArch::Aarch64 => 42,
            GuestArch::X86_64 => 43,
        };
        assert_eq!(declaration.selected().unwrap().size_bytes, size);
        let mut value = metadata();
        value["archives"]
            .as_object_mut()
            .unwrap()
            .remove(&GuestArch::host().to_string());
        assert!(parse(&value).unwrap().selected().is_err());
    }

    #[test]
    fn strict_metadata_rejects_unknown_fields_versions_sizes_keys_and_architectures() {
        for (field, replacement) in [
            ("schema_version", json!(2)),
            ("extra", json!(true)),
            ("archives", json!({})),
            (
                "archives",
                json!({"arm64": metadata()["archives"]["aarch64"].clone()}),
            ),
        ] {
            let mut value = metadata();
            value[field] = replacement;
            assert!(parse(&value).is_err(), "{value}");
        }
        for (field, replacement) in [
            ("size_bytes", json!(0)),
            ("size_bytes", json!(MAX_BUNDLE_TOTAL_BYTES + 1)),
            ("size_bytes", json!(-1)),
            ("sha256", json!("short")),
            ("key_id", json!("B".repeat(32))),
            ("extra", json!(false)),
        ] {
            let mut value = metadata();
            value["archives"]["aarch64"][field] = replacement;
            assert!(parse(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn duplicate_architecture_keys_are_refused() {
        let archive = serde_json::to_string(&metadata()["archives"]["aarch64"]).unwrap();
        let bytes = format!(
            r#"{{"schema_version":1,"archives":{{"aarch64":{archive},"aarch64":{archive}}}}}"#
        );
        assert!(
            Declaration::parse(bytes.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("duplicate application architecture")
        );
    }

    #[test]
    fn the_default_https_port_matches_the_producer_contract() {
        let mut value = metadata();
        value["archives"]["aarch64"]["url"] = json!(
            "https://github.com:443/owner/repository/releases/download/1.0.0/application.mvmpkg"
        );
        parse(&value).unwrap();
    }

    #[test]
    fn release_urls_refuse_mutable_or_unauthenticated_locations() {
        for url in [
            "http://github.com/owner/repository/releases/download/1.0.0/application.mvmpkg",
            "file:///tmp/application.mvmpkg",
            "https://github.com/owner/repository/releases/latest/download/application.mvmpkg",
            "https://github.com/owner/repository/releases/download/latest/application.mvmpkg",
            "https://github.com/owner/repository/releases/download/Latest/application.mvmpkg",
            "https://github.com/owner/repository/releases/download/1.0.0/application.mvmpkg?token=none",
            "https://user@github.com/owner/repository/releases/download/1.0.0/application.mvmpkg",
        ] {
            let mut value = metadata();
            value["archives"]["aarch64"]["url"] = json!(url);
            assert!(parse(&value).is_err(), "{url}");
        }
    }

    struct EphemeralTrust(VerifyingKey);
    impl TrustStore for EphemeralTrust {
        fn lookup(&self, id: &KeyId) -> Option<VerifyingKey> {
            (id == &key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        archive: Archive,
        trust: EphemeralTrust,
        profile: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir_in("/tmp").unwrap();
            let key = SigningKey::from_bytes(&[83; 32]);
            let profile = b"schema_version = 1\n".to_vec();
            let manifest = BundleManifest {
                schema_version: BUNDLE_SCHEMA_VERSION,
                publisher: "ephemeral-test".into(),
                key_id: key_id_from_pubkey(&key.verifying_key()),
                arch: GuestArch::host().to_string(),
                kernel_version: None,
                profile: None,
                workload_label: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                labels: BTreeMap::new(),
                artifacts: vec![BundleArtifact {
                    name: "policy/profile.toml".into(),
                    path: ARCHIVE_PROFILE.into(),
                    role: ArtifactRole::Other,
                    sha256: Sha256Hex::from_bytes(&profile).as_str().into(),
                    size_bytes: u64::try_from(profile.len()).unwrap(),
                }],
                members: Vec::new(),
                verity: None,
                resources: None,
            };
            let bytes = write_bundle(
                &manifest,
                &key,
                vec![(ARCHIVE_PROFILE.into(), profile.clone())],
            )
            .unwrap();
            std::fs::write(directory.path().join("application.mvmpkg"), &bytes).unwrap();
            let archive = Archive {
                url: String::new(),
                sha256: Sha256Hex::from_bytes(&bytes),
                size_bytes: u64::try_from(bytes.len()).unwrap(),
                key_id: manifest.key_id.0,
            };
            Self {
                directory,
                archive,
                trust: EphemeralTrust(key.verifying_key()),
                profile,
            }
        }

        fn path(&self) -> PathBuf {
            self.directory.path().join("application.mvmpkg")
        }

        fn check(&self) -> Result<VerifiedBundleFile> {
            check_archive(
                &self.path(),
                &self.archive,
                &"runtime/example@1.0.0".parse().unwrap(),
                &self.profile,
                &self.trust,
            )
        }
    }

    #[test]
    fn genuine_signed_archive_rejects_key_digest_size_and_incomplete_closure() {
        let mut fixture = Fixture::new();
        assert!(
            fixture
                .check()
                .unwrap_err()
                .to_string()
                .contains("boot closure")
        );
        fixture.archive.key_id = "0".repeat(32);
        assert!(
            fixture
                .check()
                .unwrap_err()
                .to_string()
                .contains("signing key")
        );
        fixture.archive.key_id = key_id_from_pubkey(&fixture.trust.0).0;
        fixture.archive.sha256 = Sha256Hex::from_bytes(b"other");
        assert!(fixture.check().unwrap_err().to_string().contains("digest"));
        fixture.archive.size_bytes += 1;
        assert!(fixture.check().unwrap_err().to_string().contains("size"));
    }

    #[test]
    fn genuine_archive_and_installed_artifacts_are_reverified_after_tamper() {
        let fixture = Fixture::new();
        let checked = verify_bundle_file(&fixture.path(), &fixture.trust).unwrap();
        let registry = BundleRegistry::new(fixture.directory.path().join("registry"));
        assert!(check_installed(&registry, &checked, &fixture.profile).is_err());
        let installed = registry
            .install_file(&fixture.path(), &fixture.trust, false)
            .unwrap();
        check_installed(&registry, &checked, &fixture.profile).unwrap();
        std::fs::write(installed.root.join(ARCHIVE_PROFILE), b"changed").unwrap();
        assert!(check_installed(&registry, &checked, &fixture.profile).is_err());
        let mut bytes = std::fs::read(fixture.path()).unwrap();
        let offset = bytes
            .windows(fixture.profile.len())
            .position(|part| part == fixture.profile)
            .unwrap();
        bytes[offset] ^= 1;
        std::fs::write(fixture.path(), bytes).unwrap();
        assert!(verify_bundle_file(&fixture.path(), &fixture.trust).is_err());
    }

    #[test]
    fn package_names_resolve_the_exact_installed_version() {
        use mvm_core::registry_pack::{PackLockfile, PackPin};
        let installed: PackReference = "agent/environment@1.2.3".parse().unwrap();
        let lock = PackLockfile::new(vec![
            PackPin::new(installed.clone(), Sha256Hex::from_bytes(b"manifest")).unwrap(),
        ])
        .unwrap();
        for name in ["agent/environment", "agent/environment@1.2.3"] {
            assert_eq!(
                locked_reference(&lock, &name.parse().unwrap()),
                Some(installed.clone())
            );
        }
        for name in ["agent/environment@1.2.4", "agent/other"] {
            assert_eq!(locked_reference(&lock, &name.parse().unwrap()), None);
        }
    }

    #[test]
    fn installed_lookup_preserves_non_pack_and_unversioned_sources() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        for reference in [
            "oci://registry.example/application:1",
            "/tmp/application.mvmpkg",
            "runtime/example",
        ] {
            assert!(resolve_installed(reference).unwrap().is_none());
        }
    }
}
