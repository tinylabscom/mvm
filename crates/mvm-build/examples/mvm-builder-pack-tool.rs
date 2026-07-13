//! Thin CLI wrapper around `mvm_build::builder_pack::build_builder_pack` /
//! `build_keyless_builder_pack`.
//!
//! Release CI or a maintainer invokes this to turn a freshly built `vmlinux` +
//! `rootfs.ext4` into a Builder pack. All inputs are explicit on the command
//! line so the tool never reaches into a real cache or key store by accident;
//! the producers it calls are pure, so this wrapper owns the only wall-clock
//! read (`--valid-days` from now).
//!
//! Two authority modes:
//!
//! ```text
//! # ed25519: signs the manifest with a local key.
//! mvm-builder-pack-tool \
//!   --vmlinux <path> --rootfs <path> --arch <x86_64|aarch64> \
//!   --channel <name> --signing-key <hex-file> --out-dir <dir> \
//!   --sbom <path> --revocation-channel <url> \
//!   [--closure <nar-path>] \
//!   [--builder-identity <s>] [--build-env <s>] \
//!   [--valid-days <n>] [--mirror-identity <s>] [--sbom-uri <url>]
//!
//! # keyless: writes an unsigned Sigstore-authority manifest; a release
//! # pipeline signs it out of band with `cosign sign-blob`.
//! mvm-builder-pack-tool \
//!   --vmlinux <path> --rootfs <path> --arch <x86_64|aarch64> \
//!   --channel <name> --keyless --identity <SAN> --out-dir <dir> \
//!   --sbom <path> --revocation-channel <url> \
//!   [--closure <nar-path>] \
//!   [--builder-identity <s>] [--build-env <s>] \
//!   [--valid-days <n>] [--mirror-identity <s>] [--sbom-uri <url>]
//! ```
//!
//! `--signing-key` names a file holding the 32-byte Ed25519 secret key as 64
//! lowercase hex characters (surrounding whitespace trimmed); required unless
//! `--keyless` is given. `--identity` names the OIDC subject the keyless
//! manifest's `trust.signing_key_id` is derived from; required with
//! `--keyless`, otherwise ignored. `--sbom` names the SBOM file enumerating
//! the pack's contents; its bytes are hashed into the manifest's SBOM
//! reference. `--sbom-uri` optionally overrides the SBOM reference's `uri`
//! field with a real published location (e.g. a release download URL); the
//! sha256 is always computed from the local `--sbom` file regardless. Without
//! it, the `uri` falls back to a `file://` path of the local SBOM file, which
//! is only meaningful on the machine that produced the pack. `--closure`
//! optionally bundles a seeded Nix store closure NAR (a `nix-store --export`
//! of the dev-shell toolchain) into a builder pack; omitting it produces a
//! pack exactly as before this flag existed, and is only accepted with the
//! default builder kind (a runtime pack never carries one).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use mvm_build::builder_pack::{
    BuildBuilderPackParams, BuildRuntimePackParams, build_builder_pack, build_keyless_builder_pack,
    build_keyless_runtime_pack,
};
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
         \x20 [--kind runtime --verity <path> --roothash <path>] \\\n\
         \x20 --channel <name> --out-dir <dir> \\\n\
         \x20 --sbom <path> --revocation-channel <url> \\\n\
         \x20 (--signing-key <hex-file> | --keyless --identity <SAN>) \\\n\
         \x20 [--closure <nar-path>] \\\n\
         \x20 [--builder-identity <s>] [--build-env <s>] \\\n\
         \x20 [--valid-days <n>] [--mirror-identity <s>] [--sbom-uri <url>]\n\
         \n\
         --kind defaults to builder; --kind runtime additionally needs \
         --verity and --roothash (the workload rootfs's dm-verity tree + root \
         hash) and is keyless-only (--keyless --identity).\n\
         --closure optionally bundles a seeded Nix store closure NAR into a \
         builder pack (default kind only); omitting it is unchanged behavior.\n\
         --sbom-uri overrides the manifest's SBOM reference uri with a \
         published location (e.g. a release download URL) instead of the \
         default file:// path of the local --sbom file; the sha256 is \
         always computed from the local file."
    );
}

fn run(rest: &[String]) -> Result<(), String> {
    let parsed = parse_args(rest)?;
    let sbom = sbom_reference(&parsed.sbom, parsed.sbom_uri.as_deref())?;

    // The producers are pure; this wrapper owns the single wall-clock read.
    let now = Utc::now();
    let expires_at = now + Duration::days(parsed.valid_days);

    if parsed.runtime {
        // Runtime packs are keyless-only; `parse_args` guarantees --keyless
        // --identity, --rootfs, --verity, and --roothash when --kind runtime.
        let identity = parsed
            .identity
            .expect("parse_args guarantees --identity for --kind runtime");
        let verity = parsed
            .verity
            .expect("parse_args guarantees --verity for --kind runtime");
        let roothash = parsed
            .roothash
            .expect("parse_args guarantees --roothash for --kind runtime");
        let params = BuildRuntimePackParams {
            vmlinux: parsed.vmlinux,
            rootfs: parsed.rootfs,
            verity,
            roothash,
            target_arch: parsed.arch,
            channel: parsed.channel,
            builder_identity: parsed.builder_identity,
            build_environment_identity: parsed.build_environment_identity,
            build_timestamp: now,
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
        let produced = build_keyless_runtime_pack(&params, &identity, &parsed.out_dir)
            .map_err(|e| e.to_string())?;
        println!(
            "wrote unsigned keyless runtime pack manifest {} to {} (sign {} with cosign)",
            produced.manifest.outputs.pack_hash.as_str(),
            parsed.out_dir.display(),
            produced.manifest_path.display()
        );
        return Ok(());
    }

    let params = BuildBuilderPackParams {
        vmlinux: parsed.vmlinux,
        rootfs: parsed.rootfs,
        closure: parsed.closure,
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

    if let Some(identity) = parsed.identity {
        // `parse_args` already refused `--keyless` without `--identity`, so
        // this branch never signs — it only stamps the Sigstore authority and
        // writes the bytes a release pipeline will hand to `cosign sign-blob`.
        let produced = build_keyless_builder_pack(&params, &identity, &parsed.out_dir)
            .map_err(|e| e.to_string())?;
        println!(
            "wrote unsigned keyless builder pack manifest {} to {} (sign {} with cosign)",
            produced.manifest.outputs.pack_hash.as_str(),
            parsed.out_dir.display(),
            produced.manifest_path.display()
        );
    } else {
        let signing_key_path = parsed
            .signing_key
            .expect("parse_args guarantees --signing-key when --identity is absent");
        let signing_key = load_signing_key(&signing_key_path)?;
        let manifest = build_builder_pack(&params, &signing_key, &parsed.out_dir)
            .map_err(|e| e.to_string())?;
        println!(
            "wrote builder pack {} to {}",
            manifest.outputs.pack_hash.as_str(),
            parsed.out_dir.display()
        );
    }
    Ok(())
}

/// Parsed, validated command line — pure and unit-testable, with no wall-clock
/// or filesystem reads. Exactly one authority is set: `identity` (keyless) or
/// `signing_key` (ed25519).
#[derive(Debug, PartialEq, Eq)]
struct ParsedArgs {
    vmlinux: PathBuf,
    /// Root filesystem: the builder VM disk for a builder pack, or the
    /// verity-sealed workload rootfs for a runtime pack. Required for both.
    rootfs: PathBuf,
    /// Runtime pack dm-verity hash tree (`--verity`). `Some` iff `--kind runtime`.
    verity: Option<PathBuf>,
    /// Runtime pack dm-verity root-hash file (`--roothash`). `Some` iff runtime.
    roothash: Option<PathBuf>,
    /// `--kind runtime`. A runtime pack is keyless-only (no ed25519 producer).
    runtime: bool,
    /// Optional seeded Nix store closure NAR (`--closure`). Only accepted for
    /// the default builder kind; `None` when the flag is absent.
    closure: Option<PathBuf>,
    arch: GuestArch,
    channel: String,
    signing_key: Option<PathBuf>,
    identity: Option<String>,
    out_dir: PathBuf,
    sbom: PathBuf,
    sbom_uri: Option<String>,
    revocation_channel: String,
    builder_identity: String,
    build_environment_identity: String,
    valid_days: i64,
    mirror_identity: Option<String>,
}

fn parse_args(rest: &[String]) -> Result<ParsedArgs, String> {
    let keyless = flag_present(rest, "keyless");
    let signing_key = optional(rest, "signing-key").map(PathBuf::from);
    let identity = optional(rest, "identity").map(str::to_string);
    if keyless && identity.is_none() {
        return Err("missing required arg: --identity (required with --keyless)".to_string());
    }
    if !keyless && signing_key.is_none() {
        return Err(
            "missing required arg: --signing-key (or pass --keyless --identity)".to_string(),
        );
    }
    let runtime = matches!(optional(rest, "kind"), Some("runtime"));
    if runtime && !keyless {
        return Err(
            "--kind runtime requires --keyless --identity (no ed25519 runtime producer)"
                .to_string(),
        );
    }
    let closure = optional(rest, "closure").map(PathBuf::from);
    if runtime && closure.is_some() {
        return Err("--closure is only accepted for the default builder kind".to_string());
    }
    // Both kinds carry a rootfs; a runtime pack additionally carries the
    // dm-verity hash tree + root hash so the launch can boot it verity-sealed.
    let rootfs = PathBuf::from(required(rest, "rootfs")?);
    let (verity, roothash) = if runtime {
        (
            Some(PathBuf::from(required(rest, "verity")?)),
            Some(PathBuf::from(required(rest, "roothash")?)),
        )
    } else {
        (None, None)
    };
    Ok(ParsedArgs {
        vmlinux: PathBuf::from(required(rest, "vmlinux")?),
        rootfs,
        verity,
        roothash,
        runtime,
        closure,
        arch: required(rest, "arch")?
            .parse::<GuestArch>()
            .map_err(|e| e.to_string())?,
        channel: required(rest, "channel")?.to_string(),
        // `identity` is `Some` iff the keyless path runs; `run` branches on it.
        signing_key: if keyless { None } else { signing_key },
        identity,
        out_dir: PathBuf::from(required(rest, "out-dir")?),
        sbom: PathBuf::from(required(rest, "sbom")?),
        sbom_uri: optional(rest, "sbom-uri").map(str::to_string),
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

/// Whether a value-less flag like `--keyless` was passed.
fn flag_present(rest: &[String], key: &str) -> bool {
    let needle = format!("--{key}");
    rest.iter().any(|arg| arg == &needle)
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
/// point the uri at `uri_override` when given, or at the local file otherwise.
/// The sha256 always comes from hashing `path`, regardless of `uri_override`.
fn sbom_reference(path: &Path, uri_override: Option<&str>) -> Result<SbomReference, String> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(path).map_err(|e| format!("read sbom {}: {e}", path.display()))?;
    let hex = hex::encode(Sha256::digest(&bytes));
    let uri = match uri_override {
        Some(uri) => uri.to_string(),
        None => format!("file://{}", path.display()),
    };
    Ok(SbomReference {
        uri,
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

    /// A runtime pack: `--kind runtime` with `--rootfs --verity --roothash` and
    /// keyless (`--keyless --identity ...`).
    fn runtime_args() -> Vec<String> {
        let mut a = args(&[
            ("vmlinux", "/tmp/vmlinux"),
            ("kind", "runtime"),
            ("rootfs", "/tmp/rootfs.ext4"),
            ("verity", "/tmp/rootfs.verity"),
            ("roothash", "/tmp/rootfs.roothash"),
            ("arch", "aarch64"),
            ("channel", "stable"),
            ("out-dir", "/tmp/out"),
            ("sbom", "/tmp/sbom.json"),
            (
                "revocation-channel",
                "https://example.test/revocations.json",
            ),
            ("identity", "https://example.test/wf.yml@refs/tags/v1"),
        ]);
        a.push("--keyless".to_string());
        a
    }

    #[test]
    fn parses_runtime_kind_with_rootfs_verity_roothash_and_keyless() {
        let parsed = parse_args(&runtime_args()).expect("parse runtime");
        assert!(parsed.runtime);
        assert_eq!(parsed.rootfs, PathBuf::from("/tmp/rootfs.ext4"));
        assert_eq!(parsed.verity, Some(PathBuf::from("/tmp/rootfs.verity")));
        assert_eq!(parsed.roothash, Some(PathBuf::from("/tmp/rootfs.roothash")));
        assert_eq!(
            parsed.identity.as_deref(),
            Some("https://example.test/wf.yml@refs/tags/v1")
        );
    }

    #[test]
    fn runtime_kind_requires_verity_and_roothash() {
        // A runtime pack must carry the dm-verity tree + root hash.
        let mut a = runtime_args();
        let idx = a.iter().position(|x| x == "--verity").unwrap();
        a.drain(idx..idx + 2);
        let err = parse_args(&a).expect_err("runtime requires verity");
        assert!(err.contains("verity"), "got: {err}");
    }

    #[test]
    fn runtime_kind_without_keyless_is_rejected() {
        // Runtime is keyless-only: swap the keyless flag for an ed25519 key.
        let a = args(&[
            ("vmlinux", "/tmp/vmlinux"),
            ("kind", "runtime"),
            ("rootfs", "/tmp/rootfs.ext4"),
            ("verity", "/tmp/rootfs.verity"),
            ("roothash", "/tmp/rootfs.roothash"),
            ("arch", "aarch64"),
            ("channel", "stable"),
            ("out-dir", "/tmp/out"),
            ("sbom", "/tmp/sbom.json"),
            (
                "revocation-channel",
                "https://example.test/revocations.json",
            ),
            ("signing-key", "/tmp/key.hex"),
        ]);
        let err = parse_args(&a).expect_err("runtime requires keyless");
        assert!(err.contains("keyless"), "got: {err}");
    }

    #[test]
    fn parses_required_args_with_defaults() {
        let parsed = parse_args(&full_args()).expect("parse");
        assert_eq!(parsed.vmlinux, PathBuf::from("/tmp/vmlinux"));
        assert_eq!(parsed.rootfs, PathBuf::from("/tmp/rootfs.ext4"));
        assert!(!parsed.runtime);
        assert_eq!(parsed.verity, None);
        assert_eq!(parsed.arch, GuestArch::Aarch64);
        assert_eq!(parsed.channel, "stable");
        assert_eq!(parsed.sbom, PathBuf::from("/tmp/sbom.json"));
        // Ed25519 authority: signing_key set, no identity.
        assert_eq!(parsed.signing_key, Some(PathBuf::from("/tmp/key.hex")));
        assert_eq!(parsed.identity, None);
        // Defaults applied when optional flags are absent.
        assert_eq!(parsed.builder_identity, "mvm-builder-pack-tool");
        assert_eq!(parsed.valid_days, 365);
        assert_eq!(parsed.mirror_identity, None);
        // --closure is absent by default.
        assert_eq!(parsed.closure, None);
    }

    #[test]
    fn closure_flag_is_parsed_when_given() {
        let mut a = full_args();
        a.extend(args(&[("closure", "/tmp/nix-closure.nar")]));
        let parsed = parse_args(&a).expect("parse");
        assert_eq!(parsed.closure, Some(PathBuf::from("/tmp/nix-closure.nar")));
    }

    #[test]
    fn closure_flag_on_runtime_kind_is_error() {
        let mut a = runtime_args();
        a.extend(args(&[("closure", "/tmp/nix-closure.nar")]));
        let err = parse_args(&a).expect_err("closure rejected on runtime kind");
        assert!(err.contains("closure"), "got: {err}");
    }

    /// `full_args()` minus `--signing-key`, plus `--keyless --identity <SAN>`.
    fn keyless_args() -> Vec<String> {
        let mut a = full_args();
        let idx = a.iter().position(|x| x == "--signing-key").unwrap();
        a.drain(idx..idx + 2);
        a.push("--keyless".to_string());
        a.extend(args(&[("identity", "https://issuer.example/subject")]));
        a
    }

    #[test]
    fn keyless_parses_without_signing_key() {
        let parsed = parse_args(&keyless_args()).expect("parse keyless");
        assert_eq!(parsed.signing_key, None);
        assert_eq!(
            parsed.identity,
            Some("https://issuer.example/subject".to_string())
        );
    }

    #[test]
    fn keyless_without_identity_is_error() {
        let mut a = full_args();
        let idx = a.iter().position(|x| x == "--signing-key").unwrap();
        a.drain(idx..idx + 2);
        a.push("--keyless".to_string());
        let err = parse_args(&a).expect_err("missing identity");
        assert!(err.contains("identity"), "got: {err}");
    }

    #[test]
    fn neither_signing_key_nor_keyless_is_error() {
        let mut a = full_args();
        let idx = a.iter().position(|x| x == "--signing-key").unwrap();
        a.drain(idx..idx + 2);
        let err = parse_args(&a).expect_err("no authority given");
        assert!(err.contains("signing-key"), "got: {err}");
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

    #[test]
    fn sbom_uri_flag_is_absent_by_default() {
        let parsed = parse_args(&full_args()).expect("parse");
        assert_eq!(parsed.sbom_uri, None);
    }

    #[test]
    fn sbom_uri_flag_is_parsed_when_given() {
        let mut a = full_args();
        a.extend(args(&[("sbom-uri", "https://example.test/s.txt")]));
        let parsed = parse_args(&a).expect("parse");
        assert_eq!(
            parsed.sbom_uri,
            Some("https://example.test/s.txt".to_string())
        );
    }

    #[test]
    fn sbom_reference_uses_override_uri_when_given() {
        use sha2::Digest as _;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("sbom.json");
        fs::write(&path, b"sbom bytes").expect("write sbom");
        let reference =
            sbom_reference(&path, Some("https://example.test/s.txt")).expect("sbom reference");
        assert_eq!(reference.uri, "https://example.test/s.txt");
        assert_eq!(
            reference.sha256.as_str(),
            hex::encode(sha2::Sha256::digest(b"sbom bytes"))
        );
    }

    #[test]
    fn sbom_reference_defaults_to_file_uri_when_no_override() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("sbom.json");
        fs::write(&path, b"sbom bytes").expect("write sbom");
        let reference = sbom_reference(&path, None).expect("sbom reference");
        assert_eq!(reference.uri, format!("file://{}", path.display()));
    }
}
