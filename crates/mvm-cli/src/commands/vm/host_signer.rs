//! Plan 64 W2 — host-local Ed25519 signer for `ExecutionPlan` envelopes.
//!
//! Stores keypair under `~/.mvm/keys/host-signer.{ed25519,pub}`:
//!
//! - `host-signer.ed25519` — 32-byte Ed25519 secret key, mode `0600`
//! - `host-signer.pub`     — 32-byte Ed25519 public key, mode `0644`
//!
//! Generated on first use with `OsRng`. Idempotent on repeat calls:
//! re-reads the existing files, verifies the mode is tight enough,
//! and refuses to use a secret key that's world- or group-readable.
//! The supervisor only trusts plans signed by this key when the
//! signer_id matches `host:{hostname}`.
//!
//! ## Why files instead of OS keychain
//!
//! `keyring` integration is plan 63 W3's job (cross-platform secret
//! storage). For plan 64's wiring, the host signer is local-only and
//! "the host trusts itself" is the established model (CLAUDE.md
//! security model §non-goals — "Defending against a malicious *host*.
//! mvmctl trusts the host with the hypervisor, GC roots, and private
//! build keys."). A flat file at `~/.mvm/keys/` matches the
//! `snapshot.key` precedent and keeps the wiring shipping today.
//!
//! ## Refusal posture
//!
//! Loose perms (mode > 0o600 on the secret half) trip a hard refusal
//! rather than self-healing — the snapshot_hmac module self-heals
//! because its key is a fresh-each-run advisory; the host signer is
//! a long-lived identity tied to every audit chain entry, so
//! tightening it under the user's nose is the wrong default. The
//! refusal message names the file + the expected mode; the user
//! either chmod-fixes it or rotates.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Filename of the Ed25519 secret key under `~/.mvm/keys/`.
pub const SECRET_FILENAME: &str = "host-signer.ed25519";

/// Filename of the Ed25519 public key under `~/.mvm/keys/`.
pub const PUBLIC_FILENAME: &str = "host-signer.pub";

/// Required mode for the secret-half file.
pub const SECRET_MODE: u32 = 0o600;

/// Required mode for the public-half file.
pub const PUBLIC_MODE: u32 = 0o644;

/// Length of an Ed25519 key, in bytes (both halves).
pub const KEY_BYTES: usize = 32;

/// Resolve `~/.mvm/keys/` from the calling user's `$HOME`.
pub fn default_keys_dir() -> Result<PathBuf> {
    Ok(mvm_core::config::mvm_data_dir_strict()?.join("keys"))
}

/// Compose the host-signer identifier used as `signer_id` in the
/// `SignedExecutionPlan` envelope. Currently `host:{hostname}`; a
/// future workstream may make this configurable.
pub fn host_signer_id() -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    format!("host:{hostname}")
}

/// Load the host signer, creating both halves on first use.
///
/// Idempotent: a subsequent call reloads from disk. Refuses if the
/// secret-half file has perms looser than `SECRET_MODE`. Caller is
/// responsible for ensuring `~/.mvm/` itself is mode `0700` (the
/// `mvm_core::config::ensure_data_dir` helper handles that already
/// for the parent).
pub fn load_or_init() -> Result<HostSigner> {
    load_or_init_at(&default_keys_dir()?)
}

/// Same as [`load_or_init`] but accepts an explicit keys directory.
/// Test seam.
pub fn load_or_init_at(keys_dir: &Path) -> Result<HostSigner> {
    std::fs::create_dir_all(keys_dir)
        .with_context(|| format!("creating {}", keys_dir.display()))?;

    let secret_path = keys_dir.join(SECRET_FILENAME);
    let public_path = keys_dir.join(PUBLIC_FILENAME);

    if secret_path.exists() {
        return load_existing(&secret_path, &public_path);
    }
    generate_new(&secret_path, &public_path)
}

/// The loaded signer + its derived public half. Carries the path
/// so error messages have somewhere to point.
///
/// `Debug` is hand-written rather than derived — the `signing` field
/// holds Ed25519 secret bytes, and we don't want the default derived
/// Debug to forward to the underlying SigningKey's Debug (whose
/// redaction behaviour varies across `ed25519_dalek` versions). The
/// custom impl is explicit: prints paths + public-key prefix only,
/// never the secret bytes.
pub struct HostSigner {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    pub secret_path: PathBuf,
    pub public_path: PathBuf,
}

// allow(secret-debug): hand-written Debug below redacts the SigningKey
// half; reports paths + 8-byte public-key prefix only.
impl std::fmt::Debug for HostSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pk_bytes = self.verifying.to_bytes();
        let prefix = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
        );
        f.debug_struct("HostSigner")
            .field("signing", &"<redacted>")
            .field("verifying_pubkey_prefix", &prefix)
            .field("secret_path", &self.secret_path)
            .field("public_path", &self.public_path)
            .finish()
    }
}

impl HostSigner {
    /// Verbatim copy of the public key for trusted-keys-list use.
    /// Consumed by W4's audit chain (`FileAuditSigner` is built around
    /// the host signer's keypair); kept on the surface in W3 so the
    /// `pub` API is stable across the staged commits.
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying
    }
}

fn generate_new(secret_path: &Path, public_path: &Path) -> Result<HostSigner> {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();

    // Write secret half mode 0600 atomically — create_new refuses if
    // a concurrent caller raced us into existence.
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_MODE)
            .open(secret_path)
            .with_context(|| format!("creating {}", secret_path.display()))?;
        f.write_all(signing.to_bytes().as_ref())
            .with_context(|| format!("writing {}", secret_path.display()))?;
        f.sync_all().ok();
    }

    // Write public half mode 0644.
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PUBLIC_MODE)
            .open(public_path)
            .with_context(|| format!("creating {}", public_path.display()))?;
        f.write_all(verifying.to_bytes().as_ref())
            .with_context(|| format!("writing {}", public_path.display()))?;
        f.sync_all().ok();
    }

    Ok(HostSigner {
        signing,
        verifying,
        secret_path: secret_path.to_path_buf(),
        public_path: public_path.to_path_buf(),
    })
}

fn load_existing(secret_path: &Path, public_path: &Path) -> Result<HostSigner> {
    // Refuse to use a secret key the kernel says is world- or
    // group-readable. The user fixes this with `chmod 0600 <file>`
    // and re-runs, or rotates the key.
    let meta = std::fs::metadata(secret_path)
        .with_context(|| format!("stat {}", secret_path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != SECRET_MODE {
        bail!(
            "{} has mode {:04o}; expected {:04o}. Tighten with `chmod 0600 {}` or rotate.",
            secret_path.display(),
            mode,
            SECRET_MODE,
            secret_path.display(),
        );
    }

    let secret_bytes = read_exact_n(secret_path, KEY_BYTES)?;
    let signing = SigningKey::from_bytes(
        &secret_bytes
            .as_slice()
            .try_into()
            .expect("read_exact_n returned wrong length"),
    );

    // Read + verify the public half matches what the secret derives.
    // This protects against a tampered public-half file pointing the
    // supervisor at a different identity from the one signing.
    let public_bytes = read_exact_n(public_path, KEY_BYTES)?;
    let public_array: [u8; KEY_BYTES] = public_bytes
        .as_slice()
        .try_into()
        .expect("read_exact_n returned wrong length");
    let public_from_disk = VerifyingKey::from_bytes(&public_array)
        .with_context(|| format!("parsing {}", public_path.display()))?;
    let derived = signing.verifying_key();
    if public_from_disk.to_bytes() != derived.to_bytes() {
        bail!(
            "{} does not match the public key derived from {}. Rotate via `rm` + re-run.",
            public_path.display(),
            secret_path.display(),
        );
    }

    Ok(HostSigner {
        signing,
        verifying: derived,
        secret_path: secret_path.to_path_buf(),
        public_path: public_path.to_path_buf(),
    })
}

fn read_exact_n(path: &Path, n: usize) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.len() != n as u64 {
        bail!(
            "{} is {} bytes, expected {}. Rotate via `rm` + re-run.",
            path.display(),
            meta.len(),
            n
        );
    }
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{sign_plan, verify_plan};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn fresh_keys_dir() -> TempDir {
        tempfile::tempdir().expect("tmpdir")
    }

    #[test]
    fn init_creates_both_halves_with_correct_modes() {
        let dir = fresh_keys_dir();
        let _signer = load_or_init_at(dir.path()).expect("init");

        let secret = dir.path().join(SECRET_FILENAME);
        let public = dir.path().join(PUBLIC_FILENAME);
        assert!(secret.exists());
        assert!(public.exists());

        let smode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        let pmode = std::fs::metadata(&public).unwrap().permissions().mode() & 0o777;
        assert_eq!(smode, SECRET_MODE, "secret-half must be 0600");
        assert_eq!(pmode, PUBLIC_MODE, "public-half must be 0644");
    }

    #[test]
    fn init_is_idempotent_on_second_call() {
        let dir = fresh_keys_dir();
        let s1 = load_or_init_at(dir.path()).expect("init");
        let s2 = load_or_init_at(dir.path()).expect("reload");
        assert_eq!(
            s1.verifying.to_bytes(),
            s2.verifying.to_bytes(),
            "second call must reload the same key, not generate a new one"
        );
    }

    #[test]
    fn refuses_loose_perms_above_0600() {
        let dir = fresh_keys_dir();
        load_or_init_at(dir.path()).expect("init");

        // Loosen the secret-half perms to 0644 (world-readable).
        let secret = dir.path().join(SECRET_FILENAME);
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&secret, perms).unwrap();

        let err = load_or_init_at(dir.path()).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("0644"), "error names the actual mode: {msg}");
        assert!(msg.contains("0600"), "error names the required mode: {msg}");
    }

    #[test]
    fn refuses_secret_file_with_wrong_length() {
        let dir = fresh_keys_dir();
        load_or_init_at(dir.path()).expect("init");

        // Truncate the secret-half file. Mode is still 0600 so the
        // perms check passes, but the byte-length check should refuse.
        let secret = dir.path().join(SECRET_FILENAME);
        std::fs::write(&secret, [0u8; 16]).unwrap();
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&secret, perms).unwrap();

        let err = load_or_init_at(dir.path()).expect_err("must refuse");
        assert!(
            err.to_string().contains("16 bytes"),
            "error names the actual length: {err}"
        );
    }

    #[test]
    fn refuses_public_half_mismatch_with_secret_half() {
        let dir = fresh_keys_dir();
        load_or_init_at(dir.path()).expect("init");

        // Swap the public-half bytes for a fresh unrelated key's bytes.
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        let public = dir.path().join(PUBLIC_FILENAME);
        std::fs::write(&public, other.to_bytes()).unwrap();

        let err = load_or_init_at(dir.path()).expect_err("must refuse");
        assert!(
            err.to_string().contains("does not match"),
            "error names the mismatch: {err}"
        );
    }

    #[test]
    fn signs_plan_envelope_verifiable_via_pubkey() {
        use super::super::plan_builder::{SynthesisInput, synthesize_plan};

        let dir = fresh_keys_dir();
        let signer = load_or_init_at(dir.path()).expect("init");
        let plan = synthesize_plan(&SynthesisInput {
            vm_name: "test-vm",
            tenant: None,
            backend_name: "firecracker",
            image_name: "img",
            image_sha256: &"a".repeat(64),
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            audit_event_prefix: None,
            cpus: 1,
            mem_mib: 256,
            disk_mib: 0,
            boot_timeout_secs: 30,
            exec_timeout_secs: 0,
            destroy_on_exit: true,
            bundle_pin: None,
            deps_volume: None,
        })
        .expect("synth");

        let signer_id = "host:test";
        let signed = sign_plan(&plan, &signer.signing, signer_id);
        let trusted = [(signer_id, &signer.verifying)];
        let recovered = verify_plan(&signed, &trusted).expect("verify");
        assert_eq!(recovered, plan);
    }

    #[test]
    fn host_signer_id_uses_format_prefix() {
        let id = host_signer_id();
        assert!(id.starts_with("host:"), "id must be host-namespaced: {id}");
    }
}
