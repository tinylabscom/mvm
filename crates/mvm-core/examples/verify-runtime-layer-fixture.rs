//! Verify a throwaway keyless-signed runtime-layer descriptor and its pinned bytes.
//!
//! This does not install the layer or bypass fresh revocation checks at build time.

use std::path::Path;

use mvm_core::registry_pack::runtime_layer::{
    verify_runtime_layer_archive, verify_runtime_layer_policies,
};
use mvm_core::registry_pack::{
    PackAdoption, RegistryPackPublisher, RegistryPackPublisherPolicy, VerifiedRegistryManifest,
    adopt_registry_manifest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let [_, manifest, signature, archive, files, identity] = args.as_slice() else {
        return Err("usage: verify-runtime-layer-fixture MANIFEST BUNDLE LAYER_TAR FILES_ROOT OIDC_IDENTITY".into());
    };
    let manifest = std::fs::read(manifest)?;
    let signature = std::fs::read(signature)?;
    let reference = "runtime/python@1.1.0".parse()?;
    let policy = RegistryPackPublisherPolicy::new(vec![RegistryPackPublisher::new(
        "runtime",
        "https://token.actions.githubusercontent.com",
        vec![identity.clone()],
    )?])?;
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
    println!("signed runtime layer and all declared input bytes verified");
    Ok(())
}
