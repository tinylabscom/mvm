//! Drive the CLI-release acquisition path against a staged release.
//!
//! Installed clients acquire the runtime overlay and SDK sidecar as members of
//! the signed image set. The CLI release still publishes both per version for
//! clients that predate the image set, and this proves those archives survive
//! the ladder such a client runs: fetch the checksum, fetch the archive, verify
//! its digest, verify its cosign signature against the tagged release identity,
//! then the production install half unchanged — safe-extract, re-check the
//! archive's own manifest, install atomically, and re-resolve the installed
//! entry.
//!
//! `release.yml` points this at its own about-to-be-published artifacts over a
//! `file://` URL before `gh release create` runs. That is the one context where
//! the signing identity genuinely is the tagged release workflow's, so no trust
//! override is needed or offered — a release that cannot be consumed by the
//! consumer path fails here instead of stranding every download after publish.
//!
//! ```text
//! download-release-artifact --kind sidecar --base-url file:///abs/staging \
//!   --version 0.18.0 --arch x86_64 --libc musl --cache /tmp/verify-cache
//! ```
//!
//! Exits 0 only when the artifact installs *and* resolves.

use std::path::PathBuf;
use std::process::ExitCode;

use mvm_contract::guest_libc::GuestLibc;
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
    libc: Option<GuestLibc>,
    cache: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let (mut kind, mut base_url, mut version, mut arch, mut libc, mut cache) =
        (None, None, None, None, None, None);
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
            "--libc" => {
                let raw = value()?;
                libc = Some(match raw.as_str() {
                    "glibc" => GuestLibc::Glibc,
                    "musl" => GuestLibc::Musl,
                    other => return Err(format!("--libc must be glibc|musl, got {other}")),
                })
            }
            "--cache" => cache = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let kind = kind.ok_or("--kind is required")?;
    if matches!(&kind, Kind::Sidecar) && libc.is_none() {
        return Err("--libc is required for --kind sidecar".to_string());
    }
    Ok(Args {
        kind,
        base_url: base_url.ok_or("--base-url is required")?,
        version: version.ok_or("--version is required")?,
        arch: arch.ok_or("--arch is required")?,
        libc,
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

    // The caller supplies the release prefix, as an operator pointing at a
    // private mirror would; the per-version directory is `v<version>` under it.
    let release_url = format!("{}/v{}", args.base_url.trim_end_matches('/'), args.version);
    let stage = match tempfile::tempdir() {
        Ok(stage) => stage,
        Err(e) => {
            eprintln!("error: create a staging directory: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The two install halves return different error types. Render each at its
    // own call site rather than coercing one into the other — a wrong-variant
    // coercion would print a reason that misnames what actually failed.
    let outcome: Result<String, String> = match args.kind {
        Kind::Overlay => {
            let asset = mvm_build::runtime_overlay::RuntimeOverlayArtifactNames::for_arch(
                &args.arch.to_string(),
            )
            .archive;
            let archive = stage.path().join(&asset);
            mvm_build::runtime_overlay::fetch_cli_release_archive(
                &release_url,
                &args.version,
                &asset,
                &archive,
            )
            .and_then(|()| {
                mvm_build::runtime_overlay::install_runtime_overlay_archive(
                    &archive,
                    &args.version,
                    args.arch,
                    &args.cache,
                )
            })
            .map(|a| format!("runtime overlay {} roothash {}", a.version, a.roothash))
            .map_err(|e| e.to_string())
        }
        Kind::Sidecar => {
            let Some(libc) = args.libc else {
                eprintln!("error: --libc is required for --kind sidecar");
                return ExitCode::FAILURE;
            };
            let asset = mvm_build::sdk_sidecar::SdkSidecarArtifactNames::for_target(
                &args.arch.to_string(),
                libc,
            )
            .archive;
            let archive = stage.path().join(&asset);
            mvm_build::runtime_overlay::fetch_cli_release_archive(
                &release_url,
                &args.version,
                &asset,
                &archive,
            )
            .map_err(mvm_build::sdk_sidecar::SdkSidecarBuildError::from)
            .and_then(|()| {
                mvm_build::sdk_sidecar::install_sdk_sidecar_archive(
                    &archive,
                    &args.version,
                    args.arch,
                    libc,
                    &args.cache,
                )
            })
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
