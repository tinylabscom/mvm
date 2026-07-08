//! Standalone verifier for a signed pack revocation list.
//!
//! Given a `PackRevocationList` JSON file and its detached cosign bundle, this
//! calls the exact entrypoint the fetch path uses
//! (`pack_revocation::verify_pack_revocation_list`): it checks the bundle over
//! the raw list bytes through the Rust sigstore-verify stack, then parses and
//! validates schema + freshness. It exists so a CI smoke job can prove a real
//! `cosign sign-blob` bundle over a revocation list round-trips through that
//! verifier.
//!
//! ```text
//! verify-pack-revocation-list \
//!   --list <path> --bundle <path> \
//!   --identity <SAN> --issuer <url>
//! ```
//!
//! Exits `0` and prints "pack revocation list signature verified" on success;
//! exits nonzero and prints the error to stderr on any failure.

use std::fs;
use std::process::ExitCode;

use mvm_core::pack_revocation::verify_pack_revocation_list;
use mvm_core::packs::KeylessTrust;

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
            println!("pack revocation list signature verified");
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
        "usage: verify-pack-revocation-list \\\n\
         \x20 --list <path> --bundle <path> \\\n\
         \x20 --identity <SAN> --issuer <url>"
    );
}

fn run(rest: &[String]) -> Result<(), String> {
    let list_path = required(rest, "list")?;
    let bundle_path = required(rest, "bundle")?;
    let identity = required(rest, "identity")?;
    let issuer = required(rest, "issuer")?;

    let list_bytes = fs::read(list_path).map_err(|e| format!("read {list_path}: {e}"))?;
    let bundle = fs::read(bundle_path).map_err(|e| format!("read {bundle_path}: {e}"))?;
    let trust = KeylessTrust {
        accepted_identities: vec![identity.to_string()],
        issuer: issuer.to_string(),
    };

    verify_pack_revocation_list(&list_bytes, &bundle, &trust, chrono::Utc::now())
        .map(|_| ())
        .map_err(|e| format!("revocation list verification failed: {e}"))
}

fn required<'a>(rest: &'a [String], key: &str) -> Result<&'a str, String> {
    let needle = format!("--{key}");
    rest.iter()
        .position(|arg| arg == &needle)
        .and_then(|i| rest.get(i + 1))
        .map(String::as_str)
        .ok_or_else(|| format!("missing required arg: --{key}"))
}
