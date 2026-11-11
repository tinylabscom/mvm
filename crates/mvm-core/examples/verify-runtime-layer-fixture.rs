//! Verify a throwaway keyless-signed runtime layer with an independently signed feed.
//!
//! This does not install the layer or qualify a final application archive.

use std::path::{Path, PathBuf};

use mvm_core::registry_pack::runtime_layer::{
    verify_runtime_layer_archive, verify_runtime_layer_policies,
};
use mvm_core::registry_pack::{
    PackAdoption, RegistryPackPublisher, RegistryPackPublisherPolicy, VerifiedRegistryManifest,
    adopt_registry_manifest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let [
        _,
        manifest,
        signature,
        archive,
        files,
        identity,
        feed,
        feed_bundle,
    ] = args.as_slice()
    else {
        return Err("usage: verify-runtime-layer-fixture MANIFEST BUNDLE LAYER_TAR FILES_ROOT OIDC_IDENTITY FEED_JSON FEED_BUNDLE".into());
    };
    let home = PathBuf::from(std::env::var_os("MVM_HOME").ok_or("explicit MVM_HOME required")?);
    if !home.is_absolute()
        || identity == mvm_core::registry_pack_store::OFFICIAL_REGISTRY_PACK_REVOCATION_IDENTITY
    {
        return Err(
            "the fixture requires a private absolute home and independent publisher identities"
                .into(),
        );
    }
    std::fs::create_dir(&home)?;
    let trust_path = mvm_core::config::registry_pack_revocation_trust_path();
    std::fs::create_dir_all(
        trust_path
            .parent()
            .ok_or("revocation trust has no parent")?,
    )?;
    std::fs::write(
        trust_path,
        format!(
            "schema_version = 1\nissuer = 'https://token.actions.githubusercontent.com'\naccepted_identities = ['{}']\n",
            mvm_core::registry_pack_store::OFFICIAL_REGISTRY_PACK_REVOCATION_IDENTITY
        ),
    )?;
    let manifest = std::fs::read(manifest)?;
    let signature = std::fs::read(signature)?;
    let reference = "runtime/python@1.1.0".parse()?;
    let policy = RegistryPackPublisherPolicy::new(vec![RegistryPackPublisher::new(
        "runtime",
        "https://token.actions.githubusercontent.com",
        vec![identity.clone()],
    )?])?;
    mvm_core::registry_pack_store::save_publisher_policy(
        &mvm_core::config::registry_pack_publisher_policy_path(),
        &policy,
    )?;
    mvm_core::registry_pack_store::update_registry_pack_revocations(
        &std::fs::read(feed)?,
        &std::fs::read(feed_bundle)?,
    )?;
    let VerifiedRegistryManifest::RuntimeLayer(layer) = adopt_registry_manifest(&PackAdoption {
        requested: &reference,
        manifest_bytes: &manifest,
        signature_bundle: &signature,
        publisher_policy: &policy,
    })?
    else {
        return Err("fixture must be a signed runtime layer".into());
    };
    verify_runtime_layer_archive(&layer, Path::new(archive))?;
    verify_runtime_layer_policies(&layer, Path::new(files))?;
    layer.check_current_revocations()?;
    println!("signed runtime layer, independent current feed and declared bytes verified");
    Ok(())
}
