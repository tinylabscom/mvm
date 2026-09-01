//! Drive the real end-user acquisition path against a staged release.
//!
//! Runs the production `download_runtime_overlay` / `download_sdk_sidecar`
//! unchanged — the whole ladder: fetch the checksum, fetch the archive, verify
//! its digest, verify its cosign signature against the tagged release identity,
//! safe-extract, re-check the archive's own manifest, install atomically, and
//! re-resolve the installed entry.
//!
//! `release.yml` points this at its own about-to-be-published artifacts over a
//! `file://` URL before `gh release create` runs. That is the one context where
//! the signing identity genuinely is the tagged release workflow's, so no trust
//! override is needed or offered — a release that cannot be consumed by the
//! consumer path fails here instead of stranding every download after publish.
//!
//! ```text
//! download-release-artifact --kind sidecar --base-url file:///abs/staging \
//!   --version 0.18.0 --arch x86_64 --cache /tmp/verify-cache
//! ```
//!
//! Exits 0 only when the artifact installs *and* resolves.

use std::path::PathBuf;
use std::process::ExitCode;

use mvm_core::arch::GuestArch;

enum Kind {
    Overlay,
    Sidecar,
}

struct Args {
    kind: Kind,
    base_url: String,
    version: String,
    arch: GuestArch,
    cache: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let (mut kind, mut base_url, mut version, mut arch, mut cache) = (None, None, None, None, None);
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--kind" => {
                kind = Some(match value()?.as_str() {
                    "overlay" => Kind::Overlay,
                    "sidecar" => Kind::Sidecar,
                    other => return Err(format!("--kind must be overlay|sidecar, got {other}")),
                })
            }
            "--base-url" => base_url = Some(value()?),
            "--version" => version = Some(value()?),
            "--arch" => {
                let raw = value()?;
                arch = Some(match raw.as_str() {
                    "aarch64" => GuestArch::Aarch64,
                    "x86_64" => GuestArch::X86_64,
                    other => return Err(format!("--arch must be aarch64|x86_64, got {other}")),
                })
            }
            "--cache" => cache = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        kind: kind.ok_or("--kind is required")?,
        base_url: base_url.ok_or("--base-url is required")?,
        version: version.ok_or("--version is required")?,
        arch: arch.ok_or("--arch is required")?,
        cache: cache.ok_or("--cache is required")?,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(reason) => {
            eprintln!("error: {reason}");
            return ExitCode::FAILURE;
        }
    };

    // `release_base_url` appends `/v<version>` itself, so the caller supplies
    // the prefix — exactly as an operator pointing at a private mirror would.
    // SAFETY: single-threaded example, set before any download runs.
    unsafe { std::env::set_var("MVM_OVERLAY_BASE_URL", &args.base_url) };

    // The two downloaders return different error types. Render each at its own
    // call site rather than coercing one into the other — a wrong-variant
    // coercion would print a reason that misnames what actually failed.
    let outcome: Result<String, String> = match args.kind {
        Kind::Overlay => mvm_build::runtime_overlay::download_runtime_overlay(
            &args.version,
            args.arch,
            &args.cache,
        )
        .map(|a| format!("runtime overlay {} roothash {}", a.version, a.roothash))
        .map_err(|e| e.to_string()),
        Kind::Sidecar => {
            mvm_build::sdk_sidecar::download_sdk_sidecar(
                &args.version,
                args.arch,
                // The published release carries one variant; asking for the
                // other is refused rather than mislabelled, so this example
                // exercises the arm that actually has an asset behind it.
                mvm_contract::guest_libc::GuestLibc::Glibc,
                &args.cache,
            )
            .map(|a| format!("sdk sidecar {} sha256 {}", a.version, a.image_sha256))
            .map_err(|e| e.to_string())
        }
    };

    match outcome {
        Ok(summary) => {
            println!("ok: installed and resolved {summary} ({})", args.arch);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "error: {} {} did not survive the consumer path: {e}",
                args.arch, args.version
            );
            ExitCode::FAILURE
        }
    }
}
