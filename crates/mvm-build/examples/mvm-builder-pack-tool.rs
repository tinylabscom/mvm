//! Thin CLI wrapper around `mvm_build::builder_pack::build_builder_pack`.
//!
//! Release CI or a maintainer invokes this to turn a freshly built `vmlinux` +
//! `rootfs.ext4` into a signed, cache-promotable Builder pack. All inputs are
//! explicit on the command line so the tool never reaches into a real cache or
//! key store by accident; the producer it calls is pure, so this wrapper owns
//! the only wall-clock read (`--valid-days` from now).
//!
//! Usage:
//!
//! ```text
//! mvm-builder-pack-tool \
//!   --vmlinux <path> --rootfs <path> --arch <x86_64|aarch64> \
//!   --channel <name> --signing-key <hex-file> --out-dir <dir> \
//!   --sbom <path> --revocation-channel <url> \
//!   [--builder-identity <s>] [--build-env <s>] \
//!   [--valid-days <n>] [--mirror-identity <s>]
//! ```
//!
//! `--signing-key` names a file holding the 32-byte Ed25519 secret key as 64
//! lowercase hex characters (surrounding whitespace trimmed). `--sbom` names the
//! SBOM file enumerating the pack's contents; its bytes are hashed into the
//! manifest's SBOM reference.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use mvm_build::builder_pack::{BuildBuilderPackParams, build_builder_pack};
use mvm_core::arch::GuestArch;
use mvm_core::packs::{
    ReproducibilityStatus, SbomReference, Sha256Hex, SignatureValidity, TransparencyLogReference,
};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 || matches!(argv[1].as_str(), "-h" | "--help" | "help") {
        usage();
        return if argv.len() < 2 {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    match run(&argv[1..]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!(
        "usage: mvm-builder-pack-tool \\\n\
         \x20 --vmlinux <path> --rootfs <path> --arch <x86_64|aarch64> \\\n\
         \x20 --channel <name> --signing-key <hex-file> --out-dir <dir> \\\n\
         \x20 --sbom <path> --revocation-channel <url> \\\n\
         \x20 [--builder-identity <s>] [--build-env <s>] \\\n\
         \x20 [--valid-days <n>] [--mirror-identity <s>]"
    );
}

fn run(rest: &[String]) -> Result<(), String> {
    let parsed = parse_args(rest)?;
    let signing_key = load_signing_key(&parsed.signing_key)?;
    let sbom = sbom_reference(&parsed.sbom)?;

    // The producer is pure; this wrapper owns the single wall-clock read.
    let now = Utc::now();
    let expires_at = now + Duration::days(parsed.valid_days);
    let params = BuildBuilderPackParams {
        vmlinux: parsed.vmlinux,
        rootfs: parsed.rootfs,
        target_arch: parsed.arch,
        channel: parsed.channel,
        builder_identity: parsed.builder_identity,
        build_environment_identity: parsed.build_environment_identity,
        build_timestamp: now,
        // This tool does not perform a reproduction check.
        reproducibility: ReproducibilityStatus::NotChecked,
        sbom,
        expires_at,
        revocation_channel: parsed.revocation_channel,
        mirror_identity: parsed.mirror_identity,
        transparency_log: None::<TransparencyLogReference>,
        signature: SignatureValidity {
            signed_at: now,
            expires_at,
        },
    };

    let manifest =
        build_builder_pack(&params, &signing_key, &parsed.out_dir).map_err(|e| e.to_string())?;
    println!(
        "wrote builder pack {} to {}",
        manifest.outputs.pack_hash.as_str(),
        parsed.out_dir.display()
    );
    Ok(())
}

/// Parsed, validated command line — pure and unit-testable, with no wall-clock
/// or filesystem reads.
#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    vmlinux: PathBuf,
    rootfs: PathBuf,
    arch: GuestArch,
    channel: String,
    signing_key: PathBuf,
    out_dir: PathBuf,
    sbom: PathBuf,
    revocation_channel: String,
    builder_identity: String,
    build_environment_identity: String,
    valid_days: i64,
    mirror_identity: Option<String>,
}

fn parse_args(rest: &[String]) -> Result<ParsedArgs, String> {
    Ok(ParsedArgs {
        vmlinux: PathBuf::from(required(rest, "vmlinux")?),
        rootfs: PathBuf::from(required(rest, "rootfs")?),
        arch: required(rest, "arch")?
            .parse::<GuestArch>()
            .map_err(|e| e.to_string())?,
        channel: required(rest, "channel")?.to_string(),
        signing_key: PathBuf::from(required(rest, "signing-key")?),
        out_dir: PathBuf::from(required(rest, "out-dir")?),
        sbom: PathBuf::from(required(rest, "sbom")?),
        revocation_channel: required(rest, "revocation-channel")?.to_string(),
        builder_identity: optional(rest, "builder-identity")
            .unwrap_or("mvm-builder-pack-tool")
            .to_string(),
        build_environment_identity: optional(rest, "build-env")
            .map(str::to_string)
            .unwrap_or_else(default_build_env),
        valid_days: match optional(rest, "valid-days") {
            Some(v) => v
                .parse::<i64>()
                .map_err(|_| format!("--valid-days must be an integer, got {v:?}"))?,
            None => 365,
        },
        mirror_identity: optional(rest, "mirror-identity").map(str::to_string),
    })
}

/// Honest description of the host running the tool — no placeholder.
fn default_build_env() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
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

/// Read a 64-hex-char (32-byte) Ed25519 secret key from `path`.
fn load_signing_key(path: &Path) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let bytes =
        hex::decode(raw.trim()).map_err(|e| format!("signing key is not valid hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("signing key must be 32 bytes, got {}", b.len()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Build the manifest's SBOM reference from the SBOM file: hash its bytes and
/// point the uri at the file.
fn sbom_reference(path: &Path) -> Result<SbomReference, String> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).map_err(|e| format!("read sbom {}: {e}", path.display()))?;
    let hex = format!("{:x}", Sha256::digest(&bytes));
    Ok(SbomReference {
        uri: format!("file://{}", path.display()),
        sha256: Sha256Hex::new(hex).map_err(|e| e.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Vec<String> {
        pairs
            .iter()
            .flat_map(|(k, v)| [format!("--{k}"), v.to_string()])
            .collect()
    }

    fn full_args() -> Vec<String> {
        args(&[
            ("vmlinux", "/tmp/vmlinux"),
            ("rootfs", "/tmp/rootfs.ext4"),
            ("arch", "aarch64"),
            ("channel", "stable"),
            ("signing-key", "/tmp/key.hex"),
            ("out-dir", "/tmp/out"),
            ("sbom", "/tmp/sbom.json"),
            (
                "revocation-channel",
                "https://example.test/revocations.json",
            ),
        ])
    }

    #[test]
    fn parses_required_args_with_defaults() {
        let parsed = parse_args(&full_args()).expect("parse");
        assert_eq!(parsed.vmlinux, PathBuf::from("/tmp/vmlinux"));
        assert_eq!(parsed.rootfs, PathBuf::from("/tmp/rootfs.ext4"));
        assert_eq!(parsed.arch, GuestArch::Aarch64);
        assert_eq!(parsed.channel, "stable");
        assert_eq!(parsed.sbom, PathBuf::from("/tmp/sbom.json"));
        // Defaults applied when optional flags are absent.
        assert_eq!(parsed.builder_identity, "mvm-builder-pack-tool");
        assert_eq!(parsed.valid_days, 365);
        assert_eq!(parsed.mirror_identity, None);
    }

    #[test]
    fn optional_flags_override_defaults() {
        let mut a = full_args();
        a.extend(args(&[
            ("builder-identity", "release-ci"),
            ("valid-days", "30"),
            ("mirror-identity", "origin"),
        ]));
        let parsed = parse_args(&a).expect("parse");
        assert_eq!(parsed.builder_identity, "release-ci");
        assert_eq!(parsed.valid_days, 30);
        assert_eq!(parsed.mirror_identity, Some("origin".to_string()));
    }

    #[test]
    fn missing_required_arg_is_error() {
        let mut a = full_args();
        // Drop the --channel flag and its value.
        let idx = a.iter().position(|x| x == "--channel").unwrap();
        a.drain(idx..idx + 2);
        let err = parse_args(&a).expect_err("missing channel");
        assert!(err.contains("channel"), "got: {err}");
    }

    #[test]
    fn unknown_arch_is_error() {
        let mut a = full_args();
        let idx = a.iter().position(|x| x == "--arch").unwrap();
        a[idx + 1] = "riscv64".to_string();
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn non_integer_valid_days_is_error() {
        let mut a = full_args();
        a.extend(args(&[("valid-days", "soon")]));
        let err = parse_args(&a).expect_err("bad valid-days");
        assert!(err.contains("valid-days"), "got: {err}");
    }
}
