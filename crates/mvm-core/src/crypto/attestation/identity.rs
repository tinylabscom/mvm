//! Host attestation identity key.
//!
//! Stores an Ed25519 keypair under
//! `~/.mvm/attestation/identity.{ed25519,pub}`:
//!
//! - `identity.ed25519` — 32-byte Ed25519 secret key, mode `0600`
//! - `identity.pub`     — 32-byte Ed25519 public key, mode `0644`
//!
//! This is the *runtime* identity layer: every attestation report the
//! host emits is signed by this key, so verifiers can prove which host
//! produced the boot/runtime measurements. The host signer at
//! `~/.mvm/keys/host-signer.*` is a *separate* identity used for
//! signing `ExecutionPlan` envelopes — same crypto, different roles.
//! Keeping them separate means a compromised plan-signer key does not
//! implicitly reauthenticate previously emitted attestation reports,
//! and vice versa.
//!
//! The lifecycle is the host plan signer's, from the same
//! [`crate::crypto::ed25519_keypair`] — generate on first use (safely
//! when several processes race to it), refuse to load if the
//! secret-half's permissions are looser than `0600`, refuse if the
//! public-half doesn't match what the secret derives. The
//! divergence is the directory + filenames so the two identities
//! never collide on disk and a sloppy operator can't accidentally
//! confuse "rotate my plan signer" with "rotate my attestation
//! identity."
//!
//! ## Refusal posture
//!
//! Loose perms on the secret half are a hard refusal, not a self-heal
//! — the identity key is long-lived and every attestation chain trusts
//! it; silently tightening perms hides a real misconfiguration. The
//! error message names both the actual
//! mode and the expected mode so the operator can `chmod 0600 <file>`
//! and re-run, or rotate the keypair via `rm` + next CLI call.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

use crate::crypto::ed25519_keypair;

/// Filename of the Ed25519 secret half under
/// `~/.mvm/attestation/`.
pub const SECRET_FILENAME: &str = "identity.ed25519";

/// Filename of the Ed25519 public half under
/// `~/.mvm/attestation/`.
pub const PUBLIC_FILENAME: &str = "identity.pub";

/// Required mode for the secret half file.
pub const SECRET_MODE: u32 = ed25519_keypair::SECRET_MODE;

/// Required mode for the public half file.
pub const PUBLIC_MODE: u32 = ed25519_keypair::PUBLIC_MODE;

/// Length of an Ed25519 key, in bytes (both halves).
pub const KEY_BYTES: usize = ed25519_keypair::KEY_BYTES;

/// Resolve the attestation key directory: `<mvm_home>/attestation/`.
pub fn default_identity_dir() -> Result<PathBuf> {
    let home = crate::config::mvm_home_strict()
        .context("no home root (MVM_HOME/$HOME unset); cannot locate the attestation dir")?;
    Ok(home.join("attestation"))
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
/// `SECRET_MODE`. The attestation directory and every component above
/// it inside the mvm home are created or tightened to `0700`.
pub fn load_or_init() -> Result<IdentityKey> {
    load_or_init_at(&default_identity_dir()?)
}

/// Same as [`load_or_init`] but accepts an explicit directory.
/// Test seam — every unit test points this at a fresh `tempdir`.
pub fn load_or_init_at(dir: &Path) -> Result<IdentityKey> {
    crate::config::create_private_dir(dir)
        .with_context(|| format!("creating {} privately", dir.display()))?;

    let secret_path = dir.join(SECRET_FILENAME);
    let public_path = dir.join(PUBLIC_FILENAME);
    let (signing, verifying) = ed25519_keypair::load_or_init(&secret_path, &public_path)?;
    Ok(IdentityKey {
        signing,
        verifying,
        secret_path,
        public_path,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng as _;
    use std::os::unix::fs::PermissionsExt as _;
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

        let dmode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        let smode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        let pmode = std::fs::metadata(&public).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "identity directory must be 0700");
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

        let mut __ed_seed2 = [0u8; 32];
        rand::rng().fill_bytes(&mut __ed_seed2);
        let other = SigningKey::from_bytes(&__ed_seed2).verifying_key();
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
