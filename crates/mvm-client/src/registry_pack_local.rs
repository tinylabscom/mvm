//! Offline acquisition of an explicitly pinned, authenticated local candidate.
//! No registry lookup, recursive fetch, trust override, or runtime launch.

use anyhow::{Context, Result, bail, ensure};
use mvm_core::registry_pack::runtime_layer::{
    VerifiedRuntimeLayerInputs, verify_runtime_layer_inputs,
};
use mvm_core::registry_pack::{
    InstalledRegistryPack, PackLockfile, PackPin, PackReference, RegistryPackVerification,
    VerifiedRegistryManifest, VerifiedRegistryPack, local_input, verify_registry_manifest,
};
use mvm_core::registry_pack_store as store;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::policy_profiles::model::NetworkSection;
use crate::policy_profiles::{GroupFile, PolicyRef, ProfileFile, builtin};

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

/// Retain an exact pinned layer and signed policy documents as build inputs.
///
/// This never installs a layer as a runnable image or updates a user's pack
/// lock. A later composer must resolve the complete pinned dependency graph
/// and enforce policy before using these bytes.
///
/// # Errors
///
/// Refuses a wrong manifest kind or pin, untrusted signer, absent/stale
/// revocation feed, changed archive, or missing/changed policy document.
pub fn acquire_local_runtime_layer(
    expected: &PackPin,
    paths: &LocalRegistryPackPaths,
    archive: &Path,
) -> Result<VerifiedRuntimeLayerInputs> {
    let manifest =
        local_input::read_metadata(&paths.manifest).context("reading local runtime manifest")?;
    let bundle = local_input::read_metadata(&paths.bundle)
        .context("reading local runtime Sigstore bundle")?;
    let policy = store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?
    .policy;
    let lock = PackLockfile::new(vec![expected.clone()])?;
    let verified = verify_registry_manifest(&RegistryPackVerification::new(
        expected.reference(),
        &manifest,
        &bundle,
        &lock,
        &policy,
    ))?;
    let VerifiedRegistryManifest::RuntimeLayer(layer) = verified else {
        bail!("the pinned manifest is not a build-only runtime layer");
    };
    layer.check_current_revocations()?;
    let held = verify_runtime_layer_inputs(&layer, archive, &paths.files)?;
    require_offline_runtime_policy(&held)?;
    Ok(held)
}

/// Admit only a signed, deny-all group for the first composable Python slice.
///
/// The full policy intersection is a separate contract. Until it is signed
/// and enforced at both build and launch, unsupported requests cannot become
/// implicit host grants or silently disappear from a production package.
///
/// # Errors
///
/// Refuses stale proof, a profile, malformed TOML or any other policy shape.
pub fn require_offline_runtime_policy(inputs: &VerifiedRuntimeLayerInputs) -> Result<()> {
    inputs.reverify()?;
    ensure!(
        inputs.policies().profile().is_none(),
        "the first composable runtime cannot inherit a policy profile"
    );
    let group = inputs
        .policies()
        .group()
        .context("the first composable runtime requires a signed policy group")?;
    require_offline_group(group)
}

fn require_offline_group(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("signed runtime group is not UTF-8")?;
    let group: GroupFile =
        toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid signed runtime group"))?;
    ensure!(
        !group.required
            && group.network
                == NetworkSection {
                    block: Some(true),
                    ..NetworkSection::default()
                }
            && group.secrets.is_empty()
            && group.shares.is_empty()
            && group.env.is_empty()
            && group.tools.is_empty()
            && group.resources.is_empty(),
        "the first composable runtime requires a deny-all group with no other policy requests"
    );
    Ok(())
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

#[cfg(test)]
mod runtime_layer_tests {
    use super::*;
    use mvm_core::packs::Sha256Hex;

    #[test]
    fn offline_layer_requires_a_manifest_before_any_payload() {
        let temp = tempfile::tempdir().unwrap();
        let paths = LocalRegistryPackPaths::new(
            temp.path().join("missing.json"),
            temp.path().join("manifest.sigstore.json"),
            temp.path().join("files"),
        )
        .unwrap();
        let pin = PackPin::new(
            "runtime/python@1.1.0".parse().unwrap(),
            Sha256Hex::from_bytes(b"expected manifest"),
        )
        .unwrap();
        assert!(
            acquire_local_runtime_layer(&pin, &paths, &temp.path().join("layer.tar"))
                .unwrap_err()
                .to_string()
                .contains("reading local runtime manifest")
        );
    }

    #[test]
    fn first_runtime_policy_is_closed_and_does_not_drop_requests() {
        require_offline_group(
            b"description = 'Offline Python runtime'\nrequired = false\n[network]\nblock = true\n",
        )
        .unwrap();
        for document in [
            b"[network]\nallow = ['pypi.org:443']\n".as_slice(),
            b"[network]\nblock = false\n".as_slice(),
            b"[network]\nblock = true\nallow = ['pypi.org:443']\n".as_slice(),
            b"[[secrets.bind]]\nname = 'token'\n[network]\nblock = true\n".as_slice(),
            b"[[shares.mount]]\nhost = '.'\nguest = '/work'\n[network]\nblock = true\n".as_slice(),
            b"[network]\nblock = true\n[resources]\nmax_cpus = 2\n".as_slice(),
            b"[network]\nblock = true\nnet = true\n".as_slice(),
        ] {
            assert!(require_offline_group(document).is_err(), "{document:?}");
        }
    }
}
