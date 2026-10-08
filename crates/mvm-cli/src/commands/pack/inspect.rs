//! Inspect an installed workload pack only after re-verifying its lock pin,
//! publisher signature, and complete payload.

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::PackReference;
use mvm_core::registry_pack_store::{
    load_pack_lockfile, load_publisher_policy_or_official_default, open_installed_registry_pack,
};

#[derive(Serialize)]
struct VerifiedPackInfo {
    reference: String,
    description: String,
    manifest_sha256: String,
    signer_identity: String,
    signer_issuer: String,
    official_status: &'static str,
    revocation_scope: &'static str,
    publisher_issuer: String,
    accepted_signing_identities: Vec<String>,
    policy_files: Vec<String>,
    policy_documents: Vec<VerifiedPolicy>,
    image_manifest: Option<String>,
    files: Vec<VerifiedFile>,
}

#[derive(Serialize)]
struct VerifiedPolicy {
    path: String,
    text: String,
}

#[derive(Serialize)]
struct VerifiedFile {
    path: String,
    sha256: String,
    size: u64,
}

pub(super) fn run(reference_arg: &str, json: bool, verify_only: bool) -> Result<()> {
    let reference: PackReference = reference_arg
        .parse()
        .with_context(|| format!("invalid pack reference {reference_arg:?}"))?;
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let publisher = load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?;
    let (installed, verified) = open_installed_registry_pack(
        &mvm_core::config::registry_pack_cache_dir(),
        &lock,
        &publisher.policy,
        &reference,
    )?;
    let manifest = verified.manifest();
    let trust = publisher
        .policy
        .trust_for_namespace(manifest.reference.namespace())?;
    let mut policy_documents = Vec::new();
    for file in manifest
        .files
        .iter()
        .filter(|file| matches!(file.path.as_str(), "pack/group.toml" | "pack/profile.toml"))
    {
        let path = installed.payload_root().join(&file.path);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading signed pack policy {}", file.path))?;
        ensure!(
            u64::try_from(bytes.len()).context("pack policy exceeds supported file size")?
                == file.size,
            "pack policy size changed: {}",
            file.path
        );
        ensure!(
            Sha256Hex::from_bytes(&bytes) == file.sha256,
            "pack policy digest changed: {}",
            file.path
        );
        let text = String::from_utf8(bytes)
            .with_context(|| format!("pack policy is not UTF-8: {}", file.path))?;
        policy_documents.push(VerifiedPolicy {
            path: file.path.clone(),
            text,
        });
    }
    let info = VerifiedPackInfo {
        reference: manifest.reference.to_string(),
        description: manifest.description.clone(),
        manifest_sha256: verified.manifest_sha256().as_str().to_string(),
        signer_identity: verified.signer().identity.clone(),
        signer_issuer: verified.signer().issuer.clone(),
        official_status: "not_established",
        revocation_scope: "operator_configured_only",
        publisher_issuer: trust.issuer,
        accepted_signing_identities: trust.accepted_identities,
        policy_files: policy_documents
            .iter()
            .map(|policy| policy.path.clone())
            .collect(),
        policy_documents,
        image_manifest: manifest.image.as_ref().map(|image| image.manifest.clone()),
        files: manifest
            .files
            .iter()
            .map(|file| VerifiedFile {
                path: file.path.clone(),
                sha256: file.sha256.as_str().to_string(),
                size: file.size,
            })
            .collect(),
    };

    if json {
        return crate::json_out::emit_json(&info);
    }
    if verify_only {
        println!("Verified {} ({})", info.reference, info.manifest_sha256);
        println!("Signer identity: {}", info.signer_identity);
        println!("Signer issuer: {}", info.signer_issuer);
        println!("Official status: not established by this verification");
        println!("Revocation scope: operator-configured signed feed only; no feed is required");
        println!("Signature proves publisher identity and integrity, not safety.");
        return Ok(());
    }
    println!("Pack: {}", info.reference);
    println!("Description: {}", info.description);
    println!("Manifest SHA-256: {}", info.manifest_sha256);
    println!("Signer identity: {}", info.signer_identity);
    println!("Signer issuer: {}", info.signer_issuer);
    println!("Official status: not established by this verification");
    println!("Revocation scope: operator-configured signed feed only; no feed is required");
    println!("Publisher issuer: {}", info.publisher_issuer);
    println!(
        "Accepted signing identities: {}",
        info.accepted_signing_identities.join(", ")
    );
    println!("Policy files: {}", info.policy_files.join(", "));
    for policy in &info.policy_documents {
        println!(
            "Policy {}: {}",
            policy.path,
            serde_json::to_string(&policy.text)?
        );
    }
    if let Some(image) = &info.image_manifest {
        println!("Image source manifest: {image}");
    }
    println!("Payload files: {}", info.files.len());
    for file in &info.files {
        println!("  {}  {}  {} bytes", file.sha256, file.path, file.size);
    }
    println!("Signature proves publisher identity and integrity, not safety.");
    Ok(())
}
