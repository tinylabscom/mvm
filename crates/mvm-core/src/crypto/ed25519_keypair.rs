//! An Ed25519 keypair kept on disk as two files: a 32-byte secret half at
//! mode `0600` and the 32-byte public half it derives at mode `0644`.
//!
//! The host plan signer (`~/.mvm/keys/host-signer.*`) and the attestation
//! identity (`~/.mvm/attestation/identity.*`) are both stored this way and
//! both create theirs on first use, so the create-or-load protocol lives here
//! once.
//!
//! First use has to be safe when several processes get there together. The
//! secret half is published with a no-clobber link of a fully written file
//! (`atomic_io::load_or_create_private`), so exactly one minted seed becomes
//! the key and every caller, including the ones whose seed lost, loads that
//! one. The public half follows the same way. It is a pure function of the
//! secret, so every racer would write the same bytes, and a reader that finds
//! the secret but not yet the public half writes it rather than failing.
//!
//! What is refused is unchanged from the hand-written loaders this replaced:
//! a secret half whose mode is not exactly `0600`, either half at the wrong
//! length, and a public half that is present but does not match the secret.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::Rng as _;
use zeroize::Zeroizing;

use crate::atomic_io;
use crate::private_fs::mode_bits;

/// Required mode for the secret-half file.
pub const SECRET_MODE: u32 = 0o600;

/// Required mode for the public-half file.
pub const PUBLIC_MODE: u32 = 0o644;

/// Length of an Ed25519 key, in bytes (both halves).
pub const KEY_BYTES: usize = 32;

/// Load the keypair at `secret_path` / `public_path`, generating it on first
/// use.
///
/// The directory holding both files must already exist; create it with
/// `config::create_private_dir` so it is `0700`.
pub fn load_or_init(secret_path: &Path, public_path: &Path) -> Result<(SigningKey, VerifyingKey)> {
    let signing = atomic_io::load_or_create_private(secret_path, mint_seed, load_secret_half)?;
    let derived = signing.verifying_key();
    ensure_public_half(public_path, &derived)?;
    check_public_half(secret_path, public_path, &derived)?;
    Ok((signing, derived))
}

/// Load an existing identity without creating, replacing, or repairing either
/// half. Evidence maintenance must not mint a new signer when custody is lost.
pub fn load_existing(secret_path: &Path, public_path: &Path) -> Result<(SigningKey, VerifyingKey)> {
    let signing = load_secret_half(secret_path)?;
    let derived = signing.verifying_key();
    check_public_half(secret_path, public_path, &derived)?;
    Ok((signing, derived))
}

fn mint_seed() -> Zeroizing<Vec<u8>> {
    let mut seed = Zeroizing::new(vec![0u8; KEY_BYTES]);
    rand::rng().fill_bytes(&mut seed);
    seed
}

/// Read the secret half, refusing a file anyone but the owner can read.
///
/// Loose perms trip a hard refusal rather than a silent chmod: both keys
/// that use this are long-lived identities, and tightening one under the
/// operator hides a real misconfiguration.
fn load_secret_half(secret_path: &Path) -> Result<SigningKey> {
    let meta = std::fs::metadata(secret_path)
        .with_context(|| format!("stat {}", secret_path.display()))?;
    let mode = mode_bits(secret_path, &meta)?;
    if mode != SECRET_MODE {
        bail!(
            "{} has mode {:04o}; expected {:04o}. Tighten with `chmod 0600 {}` or rotate.",
            secret_path.display(),
            mode,
            SECRET_MODE,
            secret_path.display(),
        );
    }
    let seed = read_exact_key(secret_path)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Write the public half if it is absent. A concurrent writer can only be
/// writing these same bytes, so losing that race is success.
fn ensure_public_half(public_path: &Path, derived: &VerifyingKey) -> Result<()> {
    match std::fs::symlink_metadata(public_path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            atomic_io::write_new_with_mode(public_path, derived.as_bytes(), PUBLIC_MODE)
                .with_context(|| format!("creating {}", public_path.display()))?;
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("stat {}", public_path.display())),
    }
}

/// Refuse a public half that is not the one the secret derives, so a
/// tampered file cannot point a verifier at a different identity from the one
/// signing.
fn check_public_half(secret_path: &Path, public_path: &Path, derived: &VerifyingKey) -> Result<()> {
    let public_bytes = read_exact_key(public_path)?;
    let public_from_disk = VerifyingKey::from_bytes(&public_bytes)
        .with_context(|| format!("parsing {}", public_path.display()))?;
    if public_from_disk.to_bytes() != derived.to_bytes() {
        bail!(
            "{} does not match the public key derived from {}. Rotate via `rm` + re-run.",
            public_path.display(),
            secret_path.display(),
        );
    }
    Ok(())
}

fn read_exact_key(path: &Path) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.len() != KEY_BYTES as u64 {
        bail!(
            "{} is {} bytes, expected {}. Rotate via `rm` + re-run.",
            path.display(),
            meta.len(),
            KEY_BYTES
        );
    }
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut buf = Zeroizing::new([0u8; KEY_BYTES]);
    file.read_exact(buf.as_mut_slice())
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Barrier};

    fn paths(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        (dir.join("k.ed25519"), dir.join("k.pub"))
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn first_use_writes_both_halves_at_their_modes() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, public) = paths(dir.path());
        let (_, verifying) = load_or_init(&secret, &public).unwrap();
        assert_eq!(mode_of(&secret), SECRET_MODE);
        assert_eq!(mode_of(&public), PUBLIC_MODE);
        assert_eq!(std::fs::read(&public).unwrap(), verifying.to_bytes());
    }

    #[test]
    fn an_existing_keypair_is_loaded_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, public) = paths(dir.path());
        let (_, first) = load_or_init(&secret, &public).unwrap();
        let secret_bytes = std::fs::read(&secret).unwrap();
        let (_, second) = load_or_init(&secret, &public).unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(&secret).unwrap(), secret_bytes);
    }

    /// Every concurrent first use must come back with the same keypair, and it
    /// must be the one on disk: a thread that minted a seed and lost the race
    /// to publish it has to hand back the winner's key, not its own.
    #[test]
    fn concurrent_first_uses_agree_on_the_key_on_disk() {
        const THREADS: usize = 16;
        for _ in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let (secret, public) = paths(dir.path());
            let barrier = Arc::new(Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (secret, public, barrier) =
                        (secret.clone(), public.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        load_or_init(&secret, &public).map(|(_, v)| v.to_bytes())
                    })
                })
                .collect();
            let keys: Vec<[u8; KEY_BYTES]> = handles
                .into_iter()
                .map(|h| h.join().unwrap().expect("no caller may fail"))
                .collect();
            let on_disk = std::fs::read(&public).unwrap();
            assert!(keys.iter().all(|k| k.as_slice() == on_disk.as_slice()));
            let seed: [u8; KEY_BYTES] = std::fs::read(&secret).unwrap().try_into().unwrap();
            assert_eq!(
                SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
                keys[0]
            );
        }
    }

    /// The window a concurrent reader can land in: the secret half is
    /// published and the public half not yet. The public half is derived, so
    /// it is written rather than refused.
    #[test]
    fn a_missing_public_half_is_rederived_from_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, public) = paths(dir.path());
        let (_, verifying) = load_or_init(&secret, &public).unwrap();
        std::fs::remove_file(&public).unwrap();
        let (_, reloaded) = load_or_init(&secret, &public).unwrap();
        assert_eq!(reloaded, verifying);
        assert_eq!(std::fs::read(&public).unwrap(), verifying.to_bytes());
        assert_eq!(mode_of(&public), PUBLIC_MODE);
    }
}
