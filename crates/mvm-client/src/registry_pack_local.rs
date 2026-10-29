//! Offline acquisition of an explicitly pinned, authenticated local candidate.
//! No registry lookup, recursive fetch, trust override, or runtime launch.

use anyhow::{Context, Result, bail, ensure};
use mvm_core::registry_pack::{
    InstalledRegistryPack, PackLockfile, PackPin, PackReference, RegistryPackVerification,
    VerifiedRegistryPack, local_input,
};
use mvm_core::registry_pack_store as store;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::policy_profiles::{PolicyRef, ProfileFile, builtin};

/// Explicit bounded paths to small sidecars and the exact ready payload root.
#[derive(Clone, Debug)]
pub struct LocalRegistryPackPaths {
    manifest: PathBuf,
    bundle: PathBuf,
    files: PathBuf,
}

impl LocalRegistryPackPaths {
    pub fn new(manifest: PathBuf, bundle: PathBuf, files: PathBuf) -> Result<Self> {
        for path in [&manifest, &bundle, &files] {
            ensure!(
                !path.as_os_str().is_empty() && path.as_os_str().len() <= 4096,
                "local candidate paths must contain 1..4096 bytes"
            );
            ensure!(
                path.components().count() <= 64,
                "local candidate paths must contain at most 64 components"
            );
        }
        Ok(Self {
            manifest,
            bundle,
            files,
        })
    }
}

/// Authenticate small metadata first, freeze the complete signed inventory,
/// verify installed locked dependencies, and install without replacing state.
pub fn install_local_registry_pack(
    expected: &PackPin,
    paths: &LocalRegistryPackPaths,
) -> Result<InstalledRegistryPack> {
    let manifest = local_input::read_metadata(&paths.manifest).context("reading local manifest")?;
    let bundle =
        local_input::read_metadata(&paths.bundle).context("reading local Sigstore bundle")?;
    let policy = store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?
    .policy;
    let expected_lock = PackLockfile::new(vec![expected.clone()])?;
    let verified = mvm_core::registry_pack::verify_registry_pack(&RegistryPackVerification::new(
        expected.reference(),
        &manifest,
        &bundle,
        &expected_lock,
        &policy,
    ))?;
    store::check_registry_pack_revocations_if_configured(&verified)?;
    mvm_core::registry_pack::preflight_registry_pack_payload(&verified, &paths.files)?;
    let lock_path = mvm_core::config::pack_lockfile_path();
    let cache = mvm_core::config::registry_pack_cache_dir();
    let lease = store::lock_registry_pack_store(&lock_path)?;
    let lock = store::load_pack_lockfile(&lock_path)?;
    store::check_local_expected_pin(&lock, expected, &verified)?;
    let snapshot =
        mvm_core::registry_pack::snapshot_registry_pack_payload(&paths.files, &verified)?;
    let payload = snapshot.path().join("payload");
    let mut seen = BTreeSet::new();
    let mut active = BTreeSet::new();
    active.insert(expected.reference().coordinate_string());
    check_dependencies(
        &payload,
        &verified,
        &cache,
        &lock,
        &policy,
        &mut seen,
        &mut active,
    )?;
    Ok(lease.install_local_and_pin(&cache, &payload, expected, &verified)?)
}

fn check_dependencies(
    payload: &Path,
    verified: &VerifiedRegistryPack,
    cache: &Path,
    lock: &PackLockfile,
    policy: &mvm_core::registry_pack::RegistryPackPublisherPolicy,
    seen: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
) -> Result<()> {
    let name = store::PackPolicyDocument::Profile.file_name();
    if !verified
        .manifest()
        .files
        .iter()
        .any(|file| file.path == name)
    {
        return Ok(());
    }
    let bytes = local_input::read_metadata(&payload.join(name))?;
    for requested in profile_pack_dependencies(std::str::from_utf8(&bytes)?)? {
        let coordinate = requested.coordinate_string();
        ensure!(
            !active.contains(&coordinate),
            "local candidate dependency cycle at {requested}"
        );
        let pin = lock.pins().iter().find(|pin| pin.reference().coordinate_string() == coordinate)
            .with_context(|| format!("local candidate dependency {requested} requires a trusted installed lock pin; no fetch is performed"))?;
        ensure!(
            requested.version().is_none() || requested.version() == pin.reference().version(),
            "local candidate dependency version conflicts with locked {requested}"
        );
        if seen.contains(&pin.reference().to_string()) {
            continue;
        }
        ensure!(
            seen.len() < 128,
            "local candidate dependency graph exceeds 128 packs"
        );
        seen.insert(pin.reference().to_string());
        let (installed, dependency) =
            store::open_installed_registry_pack(cache, lock, policy, &requested)
                .with_context(|| format!("verifying local locked dependency {requested}"))?;
        active.insert(coordinate.clone());
        check_dependencies(
            &installed.payload_root(),
            &dependency,
            cache,
            lock,
            policy,
            seen,
            active,
        )?;
        active.remove(&coordinate);
    }
    Ok(())
}

/// Signed profiles may depend only on registry packs or shipped built-ins.
/// Shared with remote pull so both acquisition transports use the same rule.
pub fn profile_pack_dependencies(text: &str) -> Result<Vec<PackReference>> {
    let profile: ProfileFile = toml::from_str(text).context("parsing signed pack profile")?;
    let mut dependencies = Vec::new();
    for name in profile.extends.to_vec() {
        add_policy_dependency(&name, true, &mut dependencies)?;
    }
    for name in profile.groups.include {
        add_policy_dependency(&name, false, &mut dependencies)?;
    }
    for block in profile.when {
        for name in block.include {
            add_policy_dependency(&name, false, &mut dependencies)?;
        }
    }
    Ok(dependencies)
}

fn add_policy_dependency(
    name: &str,
    profile: bool,
    dependencies: &mut Vec<PackReference>,
) -> Result<()> {
    match PolicyRef::parse(name).map_err(|reason| {
        anyhow::anyhow!("invalid signed pack policy reference {name:?}: {reason}")
    })? {
        PolicyRef::Pack { .. } => {
            let pack = name
                .parse()
                .with_context(|| format!("invalid pack reference {name:?}"))?;
            if !dependencies.contains(&pack) {
                dependencies.push(pack);
            }
        }
        PolicyRef::Name(local) => {
            let exists = if profile {
                builtin::profile(&local).is_some()
            } else {
                builtin::group(&local).is_some()
            };
            if !exists {
                bail!(
                    "{local:?} is not a built-in {}; signed packs cannot import local policy",
                    if profile { "profile" } else { "group" }
                );
            }
        }
        PolicyRef::Path(_) => {
            bail!("signed pack profile cannot follow a filesystem policy path: {name:?}")
        }
    }
    Ok(())
}
