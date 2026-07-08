//! Standalone verifier for a keyless-signed image manifest.
//!
//! Given a `SignedManifest` JSON file and its detached cosign bundle, this
//! calls the exact entrypoint the dev-image download path uses
//! (`image_verify::verify_manifest`): it checks the bundle against the raw
//! manifest bytes through the Rust sigstore-verify stack, then parses the
//! manifest. It exists so a CI smoke job can prove a real `cosign sign-blob`
//! bundle over an image manifest round-trips through that verifier.
//!
//! ```text
//! verify-signed-manifest \
//!   --manifest <path> --bundle <path> \
//!   --identity <SAN> --issuer <url>
//! ```
//!
//! Exits `0` and prints "image manifest signature verified" on success; exits
//! nonzero and prints the error to stderr on any failure (bad JSON, bad bundle,
//! identity/issuer mismatch, tampered payload).

use std::fs;
use std::process::ExitCode;

use mvm_core::crypto::image_verify::verify_manifest;

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
            println!("image manifest signature verified");
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
        "usage: verify-signed-manifest \\\n\
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
    let bundle = fs::read(bundle_path).map_err(|e| format!("read {bundle_path}: {e}"))?;

    verify_manifest(&manifest_bytes, &bundle, identity, issuer)
        .map(|_| ())
        .map_err(|e| format!("signature verification failed: {e}"))
}

fn required<'a>(rest: &'a [String], key: &str) -> Result<&'a str, String> {
    let needle = format!("--{key}");
    rest.iter()
        .position(|arg| arg == &needle)
        .and_then(|i| rest.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing required arg: --{key}"))
}
