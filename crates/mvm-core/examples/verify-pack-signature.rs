//! Standalone verifier for a keyless-signed pack manifest.
//!
//! Given a pack manifest file and its detached cosign bundle, this checks
//! the bundle against the manifest's signature payload using the exact same
//! primitive the real pack verifier (`packs::verify_pack_keyless_at`) calls.
//! It exists so a CI smoke job can prove a real `cosign sign-blob` bundle
//! round-trips through the Rust sigstore-verify stack without depending on
//! the full pack-cache machinery.
//!
//! ```text
//! verify-pack-signature \
//!   --manifest <path> --bundle <path> \
//!   --identity <SAN> --issuer <url>
//! ```
//!
//! Exits `0` and prints "pack signature verified" on success; exits nonzero
//! and prints the error to stderr on any failure (bad JSON, bad bundle,
//! identity/issuer mismatch, tampered payload).

use std::fs;
use std::process::ExitCode;

use mvm_core::crypto::image_verify::verify_signed_payload;
use mvm_core::packs::PackManifest;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 || matches!(argv[1].as_str(), "-h" | "--help" | "help") {
        usage();
        return if argv.len() < 2 {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }
    match run(&argv[1..]) {
        Ok(()) => {
            println!("pack signature verified");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "usage: verify-pack-signature \\\n\
         \x20 --manifest <path> --bundle <path> \\\n\
         \x20 --identity <SAN> --issuer <url>"
    );
}

fn run(rest: &[String]) -> Result<(), String> {
    let manifest_path = required(rest, "manifest")?;
    let bundle_path = required(rest, "bundle")?;
    let identity = required(rest, "identity")?;
    let issuer = required(rest, "issuer")?;

    let manifest_bytes =
        fs::read(manifest_path).map_err(|e| format!("read {manifest_path}: {e}"))?;
    let manifest: PackManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("parse manifest {manifest_path}: {e}"))?;
    let payload = manifest
        .signature_payload_bytes()
        .map_err(|e| format!("build signature payload: {e}"))?;
    let bundle = fs::read(bundle_path).map_err(|e| format!("read {bundle_path}: {e}"))?;

    verify_signed_payload(&payload, &bundle, identity, issuer)
        .map_err(|e| format!("signature verification failed: {e}"))
}

fn required<'a>(rest: &'a [String], key: &str) -> Result<&'a str, String> {
    optional(rest, key).ok_or_else(|| format!("missing required arg: --{key}"))
}

/// Return the value following `--key`, or `None` if the flag is absent.
fn optional<'a>(rest: &'a [String], key: &str) -> Option<&'a str> {
    let needle = format!("--{key}");
    rest.iter()
        .position(|arg| arg == &needle)
        .and_then(|i| rest.get(i + 1))
        .map(String::as_str)
}
