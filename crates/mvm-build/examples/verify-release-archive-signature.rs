//! Verify a release archive against a real cosign bundle, under an explicit
//! signing identity.
//!
//! Exists so a CI lane can prove the *format* contract end to end: sign a real
//! tarball with the exact `cosign sign-blob` invocation `release.yml` uses, then
//! feed the resulting bundle through the same primitive the downloader calls.
//! Offline unit fixtures cannot cover this — a valid Sigstore signature needs
//! Fulcio and Rekor — so a bundle-format regression in the release workflow
//! would otherwise stay invisible until a real release stranded every download.
//!
//! Identity is a parameter because the smoke lane signs under its own workflow's
//! OIDC identity, not the tagged release workflow's.
//!
//! ```text
//! verify-release-archive-signature \
//!   --archive sdk-sidecar-x86_64.tar.gz \
//!   --bundle  sdk-sidecar-x86_64.tar.gz.bundle \
//!   --identity "https://github.com/<repo>/.github/workflows/<wf>@<ref>" \
//!   --issuer   "https://token.actions.githubusercontent.com"
//! ```
//!
//! Exits 0 when the signature verifies, nonzero with a reason otherwise.

use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    archive: PathBuf,
    bundle: PathBuf,
    identity: String,
    issuer: String,
}

fn parse_args() -> Result<Args, String> {
    let (mut archive, mut bundle, mut identity, mut issuer) = (None, None, None, None);
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--archive" => archive = Some(PathBuf::from(value()?)),
            "--bundle" => bundle = Some(PathBuf::from(value()?)),
            "--identity" => identity = Some(value()?),
            "--issuer" => issuer = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        archive: archive.ok_or("--archive is required")?,
        bundle: bundle.ok_or("--bundle is required")?,
        identity: identity.ok_or("--identity is required")?,
        issuer: issuer.ok_or("--issuer is required")?,
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

    let archive = match std::fs::read(&args.archive) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.archive.display());
            return ExitCode::FAILURE;
        }
    };
    let bundle = match std::fs::read(&args.bundle) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.bundle.display());
            return ExitCode::FAILURE;
        }
    };

    let asset = args
        .archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| args.archive.display().to_string());

    match mvm_build::release_signature::verify_release_archive_bytes(
        &archive,
        &bundle,
        &asset,
        std::slice::from_ref(&args.identity),
        &args.issuer,
    ) {
        Ok(()) => {
            println!("ok: {asset} verified under {}", args.identity);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
