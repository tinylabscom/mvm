//! Standalone verification gate for a locally staged optional-extension pack.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use mvm_core::pack_trust::load_pack_trust_config;
use mvm_core::packs::{
    HostCapability, LocalPackPolicy, PackBackend, PackKind, PackManifest, Sha256Hex, verify_pack_at,
};

fn main() -> ExitCode {
    match parse_args().and_then(verify) {
        Ok(result) => {
            println!("{result}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("mvm-extension-pack-verify: {error}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug)]
struct Args {
    root: PathBuf,
    trust: PathBuf,
    backend: PackBackend,
    policy_hash: Sha256Hex,
    now: DateTime<Utc>,
    host_capabilities: BTreeSet<HostCapability>,
}

fn verify(args: Args) -> Result<String, String> {
    let manifest_path = args.root.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let manifest: PackManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    if manifest.kind != PackKind::Extension {
        return Err("staged pack is not an extension pack".to_string());
    }
    let trust = load_pack_trust_config(&args.trust)
        .map_err(|error| format!("load trust config: {error}"))?
        .ok_or_else(|| "trust config does not exist".to_string())?;
    let policy = LocalPackPolicy {
        host_arch: manifest.target_arch,
        backend: args.backend,
        host_capabilities: args.host_capabilities,
        policy_hash: args.policy_hash,
        allowed_channels: trust.allowed_channels(),
        now: args.now,
    };
    let verified = verify_pack_at(&manifest, &args.root, &policy, &trust, &trust)
        .map_err(|error| format!("pack refused: {error}"))?;
    serde_json::to_string(&serde_json::json!({
        "pack_hash": verified.pack_hash.as_str(),
        "signing_key_id": verified.signer_key_id.0,
        "file_count": verified.file_count,
        "extension_id": manifest.extension.as_ref().map(|extension| extension.extension_id.as_str()),
        "artifact_sha256": manifest.extension.as_ref().and_then(|extension| {
            manifest.outputs.files.iter().find(|file| file.path == extension.artifact)
        }).map(|file| file.sha256.as_str()),
    }))
    .map_err(|error| format!("encode verification result: {error}"))
}

fn parse_args() -> Result<Args, String> {
    let mut root = None;
    let mut trust = None;
    let mut backend = None;
    let mut policy_hash = None;
    let mut now = None;
    let mut host_capabilities = BTreeSet::new();
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {}", argument.to_string_lossy()))?;
        match argument.to_str() {
            Some("--root") if root.is_none() => root = Some(PathBuf::from(value)),
            Some("--trust") if trust.is_none() => trust = Some(PathBuf::from(value)),
            Some("--backend") if backend.is_none() => {
                backend = Some(parse_backend(&value.to_string_lossy())?)
            }
            Some("--policy-hash") if policy_hash.is_none() => {
                policy_hash = Some(
                    Sha256Hex::new(value.to_string_lossy().into_owned())
                        .map_err(|error| error.to_string())?,
                )
            }
            Some("--now") if now.is_none() => {
                now = Some(
                    DateTime::parse_from_rfc3339(&value.to_string_lossy())
                        .map_err(|error| format!("invalid --now: {error}"))?
                        .with_timezone(&Utc),
                )
            }
            Some("--host-capability") => {
                host_capabilities.insert(HostCapability(value.to_string_lossy().into_owned()));
            }
            _ => {
                return Err(format!(
                    "unknown or repeated argument {}",
                    argument.to_string_lossy()
                ));
            }
        }
    }
    Ok(Args {
        root: root.ok_or_else(|| "missing --root".to_string())?,
        trust: trust.ok_or_else(|| "missing --trust".to_string())?,
        backend: backend.ok_or_else(|| "missing --backend".to_string())?,
        policy_hash: policy_hash.ok_or_else(|| "missing --policy-hash".to_string())?,
        now: now.ok_or_else(|| "missing --now".to_string())?,
        host_capabilities,
    })
}

fn parse_backend(value: &str) -> Result<PackBackend, String> {
    match value {
        "firecracker" => Ok(PackBackend::Firecracker),
        "libkrun" => Ok(PackBackend::Libkrun),
        "qemu" => Ok(PackBackend::Qemu),
        "hvf" => Ok(PackBackend::Hvf),
        _ => Err(format!("unsupported backend {value:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parser_is_closed() {
        assert_eq!(parse_backend("firecracker"), Ok(PackBackend::Firecracker));
        assert!(parse_backend("docker").is_err());
    }
}
