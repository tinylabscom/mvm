//! Plan 60 Phase 6 — host attestation identity key.
//!
//! Stores an Ed25519 keypair under
//! `~/.mvm/attestation/identity.{ed25519,pub}`:
//!
//! - `identity.ed25519` — 32-byte Ed25519 secret key, mode `0600`
//! - `identity.pub`     — 32-byte Ed25519 public key, mode `0644`
//!
//! This is the *runtime* identity layer (plan 60 §"Attestation
//! everywhere" tier 4): every attestation report the host emits is
//! signed by this key, so verifiers can prove which host produced
//! the boot/runtime measurements. The host signer at
//! `~/.mvm/keys/host-signer.*` (plan 64 W2) is a *separate* identity
//! used for signing `ExecutionPlan` envelopes — same crypto, different
//! roles. Keeping them separate means a compromised plan-signer key
//! does not implicitly reauthenticate previously emitted attestation
//! reports, and vice versa.
//!
//! The lifecycle mirrors `mvm_cli::commands::vm::host_signer`
//! verbatim — generate-on-first-use with `OsRng`, refuse to load if
//! the secret-half's permissions are looser than `0600`, refuse if
//! the public-half doesn't match what the secret derives. The
//! divergence is the directory + filenames so the two identities
//! never collide on disk and a sloppy operator can't accidentally
//! confuse "rotate my plan signer" with "rotate my attestation
//! identity."
//!
//! ## Refusal posture
//!
//! Loose perms on the secret half are a hard refusal, not a self-heal
//! (same rationale as plan 64 W2 — the identity key is long-lived and
//! every attestation chain trusts it; silently tightening perms hides
//! a real misconfiguration). The error message names both the actual
//! mode and the expected mode so the operator can `chmod 0600 <file>`
//! and re-run, or rotate the keypair via `rm` + next CLI call.

use anyhow::{Context, Result, bail};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Filename of the Ed25519 secret half under
/// `~/.mvm/attestation/`.
pub const SECRET_FILENAME: &str = "identity.ed25519";

/// Filename of the Ed25519 public half under
/// `~/.mvm/attestation/`.
pub const PUBLIC_FILENAME: &str = "identity.pub";

/// Required mode for the secret half file.
pub const SECRET_MODE: u32 = 0o600;

/// Required mode for the public half file.
pub const PUBLIC_MODE: u32 = 0o644;

/// Length of an Ed25519 key, in bytes (both halves).
pub const KEY_BYTES: usize = 32;

/// Resolve `~/.mvm/attestation/` from the calling user's `$HOME`.
pub fn default_identity_dir() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").context("$HOME unset; cannot locate ~/.mvm/attestation/")?;
    Ok(PathBuf::from(home).join(".mvm").join("attestation"))
}

/// Compose the identity identifier used as `signer_id` in attestation
/// reports. Format: `attest:{hostname}`.
pub fn identity_signer_id() -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    format!("attest:{hostname}")
}

/// Load the identity key, creating both halves on first use.
///
/// Idempotent — a subsequent call reloads the same keypair from
/// disk. Refuses if the secret half's perms are looser than
/// `SECRET_MODE`. The caller is responsible for ensuring `~/.mvm/`
/// itself is mode `0700`.
pub fn load_or_init() -> Result<IdentityKey> {
    load_or_init_at(&default_identity_dir()?)
}

/// Same as [`load_or_init`] but accepts an explicit directory.
/// Test seam — every unit test points this at a fresh `tempdir`.
pub fn load_or_init_at(dir: &Path) -> Result<IdentityKey> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let secret_path = dir.join(SECRET_FILENAME);
    let public_path = dir.join(PUBLIC_FILENAME);

    if secret_path.exists() {
        return load_existing(&secret_path, &public_path);
    }
    generate_new(&secret_path, &public_path)
}

/// The loaded identity key + its derived public half. Carries the
/// path so error messages have somewhere concrete to point.
///
/// `Debug` is hand-written rather than derived — the `signing`
/// field holds Ed25519 secret bytes. The custom impl prints the
/// paths + a public-key prefix and explicitly redacts the secret
/// bytes. The struct name contains "Key" but does not match the
/// `xtask check-no-display-on-secret-types` heuristic
/// (no leading `Root`/`Wrapped`, no `Secret`/`Master` prefix, no
/// `password`/`token`/`credential` fragment), so no
/// `// allow(secret-debug)` directive is needed.
pub struct IdentityKey {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
    pub secret_path: PathBuf,
    pub public_path: PathBuf,
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pk = self.verifying.to_bytes();
        let prefix = format!("{:02x}{:02x}{:02x}{:02x}", pk[0], pk[1], pk[2], pk[3]);
        f.debug_struct("IdentityKey")
            .field("signing", &"<redacted>")
            .field("verifying_pubkey_prefix", &prefix)
            .field("secret_path", &self.secret_path)
            .field("public_path", &self.public_path)
            .finish()
    }
}

impl IdentityKey {
    /// Verbatim copy of the public key for trusted-keys-list use.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying
    }
}

fn generate_new(secret_path: &Path, public_path: &Path) -> Result<IdentityKey> {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();

    // Write secret half mode 0600. `create_new` refuses if a
    // concurrent caller raced us into existence.
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

    Ok(IdentityKey {
        signing,
        verifying,
        secret_path: secret_path.to_path_buf(),
        public_path: public_path.to_path_buf(),
    })
}

fn load_existing(secret_path: &Path, public_path: &Path) -> Result<IdentityKey> {
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

    Ok(IdentityKey {
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
    use tempfile::TempDir;

    fn fresh_dir() -> TempDir {
        tempfile::tempdir().expect("tmpdir")
    }

    #[test]
    fn init_creates_both_halves_with_correct_modes() {
        let dir = fresh_dir();
        let _id = load_or_init_at(dir.path()).expect("init");

        let secret = dir.path().join(SECRET_FILENAME);
        let public = dir.path().join(PUBLIC_FILENAME);
        assert!(secret.exists());
        assert!(public.exists());

        let smode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        let pmode = std::fs::metadata(&public).unwrap().permissions().mode() & 0o777;
        assert_eq!(smode, SECRET_MODE, "secret half must be 0600");
        assert_eq!(pmode, PUBLIC_MODE, "public half must be 0644");
    }

    #[test]
    fn init_is_idempotent_on_second_call() {
        let dir = fresh_dir();
        let a = load_or_init_at(dir.path()).expect("init");
        let b = load_or_init_at(dir.path()).expect("reload");
        assert_eq!(
            a.verifying.to_bytes(),
            b.verifying.to_bytes(),
            "second call must reload the same key, not generate a new one"
        );
    }

    #[test]
    fn refuses_loose_perms_above_0600() {
        let dir = fresh_dir();
        load_or_init_at(dir.path()).expect("init");

        let secret = dir.path().join(SECRET_FILENAME);
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&secret, perms).unwrap();

        let err = load_or_init_at(dir.path()).expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("0644"), "error names the actual mode: {msg}");
        assert!(msg.contains("0600"), "error names the required mode: {msg}");
    }

    #[test]
    fn refuses_secret_with_wrong_length() {
        let dir = fresh_dir();
        load_or_init_at(dir.path()).expect("init");

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
        let dir = fresh_dir();
        load_or_init_at(dir.path()).expect("init");

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
    fn identity_signer_id_uses_attest_prefix() {
        let id = identity_signer_id();
        assert!(
            id.starts_with("attest:"),
            "id must be attest-namespaced: {id}"
        );
    }

    #[test]
    fn debug_redacts_secret_bytes() {
        let dir = fresh_dir();
        let id = load_or_init_at(dir.path()).expect("init");
        let dbg = format!("{id:?}");
        assert!(dbg.contains("<redacted>"), "Debug must redact: {dbg}");
        assert!(
            !dbg.contains(&hex(&id.signing.to_bytes())),
            "Debug must not contain secret bytes"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}
