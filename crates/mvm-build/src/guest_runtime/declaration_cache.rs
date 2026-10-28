//! A host-signed, on-disk copy of a source runtime's derived assembly
//! declaration.
//!
//! Deriving the declaration assembles the overlay, its verity tree and the
//! initramfs from the archive's members, and a process did that on every launch.
//! The result is a pure function of the archive and of the code that assembles
//! it, so it is kept once, signed under the host key, and read back by the next
//! process.
//!
//! A cached entry is only ever a shortcut to a value the caller would otherwise
//! derive, so every doubt is a miss: no host key, a bad signature, an entry for
//! another archive, architecture or `mvmctl` build, or a declaration that no
//! longer validates. A miss re-derives and re-writes. Nothing here is accepted
//! on the strength of a file's contents alone.

use crate::guest_bins::assembly::RuntimeAssembly;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use mvm_core::arch::GuestArch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const DIR: &str = "source-runtime-declarations";
const DOMAIN: &[u8] = b"mvm.source-runtime-declaration.v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    declaration: RuntimeAssembly,
    signature: String,
}

/// The cached declaration for this archive under this `mvmctl` build, if one
/// was signed by this host's key.
pub(super) fn load(cache_root: &Path, digest: &str, arch: GuestArch) -> Option<RuntimeAssembly> {
    let key = host_key()?;
    let id = entry_id(digest, arch)?;
    let entry: Entry = serde_json::from_slice(&std::fs::read(path(cache_root, &id)).ok()?).ok()?;
    let signature = Signature::from_slice(&hex::decode(&entry.signature).ok()?).ok()?;
    let message = message(&id, &entry.declaration)?;
    key.verifying_key().verify(&message, &signature).ok()?;
    entry.declaration.validate(arch).ok()?;
    Some(entry.declaration)
}

/// Keep `declaration` for the next process. Best-effort: a failure leaves the
/// next launch to derive it again.
pub(super) fn store(
    cache_root: &Path,
    digest: &str,
    arch: GuestArch,
    declaration: &RuntimeAssembly,
) {
    let Some(key) = host_key() else { return };
    let Some(id) = entry_id(digest, arch) else {
        return;
    };
    let Some(message) = message(&id, declaration) else {
        return;
    };
    let entry = Entry {
        declaration: declaration.clone(),
        signature: hex::encode(key.sign(&message).to_bytes()),
    };
    let Ok(body) = serde_json::to_vec(&entry) else {
        return;
    };
    let dir = cache_root.join(DIR);
    if mvm_core::private_fs::ensure_private_dir(&dir).is_err() {
        return;
    }
    prune_stale(&dir, &path(cache_root, &id));
    // Write beside the entry and rename, so a reader sees all of it or none.
    let Ok(mut staged) = tempfile::NamedTempFile::new_in(&dir) else {
        return;
    };
    if std::io::Write::write_all(&mut staged, &body).is_err() {
        return;
    }
    let _ = staged.persist(path(cache_root, &id));
}

/// Entries are named for one `mvmctl` build, so a rebuilt binary leaves its
/// predecessor's behind. A week old is no build in use.
fn prune_stale(dir: &Path, keep: &Path) {
    const STALE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let age = entry.metadata().and_then(|m| m.modified()).ok();
        if entry.path() != keep && age.and_then(|t| t.elapsed().ok()) > Some(STALE) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn path(cache_root: &Path, id: &str) -> PathBuf {
    cache_root.join(DIR).join(format!("{id}.json"))
}

/// Names the archive, the architecture and the running `mvmctl`. The assembling
/// code lives in this binary and not in the archive, so a rebuilt binary must
/// not read an entry an older one wrote.
fn entry_id(digest: &str, arch: GuestArch) -> Option<String> {
    let exe = std::fs::metadata(std::env::current_exe().ok()?).ok()?;
    let modified = exe
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for part in [digest.as_bytes(), arch.to_string().as_bytes()] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.update(exe.len().to_le_bytes());
    hash.update(modified.as_nanos().to_le_bytes());
    Some(hex::encode(hash.finalize()))
}

fn message(id: &str, declaration: &RuntimeAssembly) -> Option<Vec<u8>> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(id.as_bytes());
    message.push(0);
    message.extend_from_slice(&serde_json::to_vec(declaration).ok()?);
    Some(message)
}

/// The host signing key, only if both halves already exist, are private and
/// agree. The key is never created here: a host that has not signed a plan yet
/// simply does not cache.
fn host_key() -> Option<SigningKey> {
    let keys = mvm_core::config::mvm_keys_dir();
    let loaded = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys.join("host-signer.ed25519"),
        &keys.join("host-signer.pub"),
    );
    Some(loaded.ok()?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn declaration() -> RuntimeAssembly {
        RuntimeAssembly {
            assembly_format: crate::guest_bins::assembly::RUNTIME_ASSEMBLY_FORMAT,
            arch: GuestArch::Aarch64,
            protocol_version: 2,
            min_supported_protocol_version: 2,
            overlay_sha256: "a".repeat(64),
            overlay_verity_sha256: "b".repeat(64),
            overlay_roothash: "c".repeat(64),
            initramfs_sha256: "d".repeat(64),
        }
    }

    /// A fresh, private `MVM_HOME` (and `HOME`) so a test never reaches the
    /// developer's real keys.
    fn isolated_home() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    fn with_host_key(seed: u8) {
        let keys = mvm_core::config::mvm_keys_dir();
        mvm_core::private_fs::ensure_private_dir(&keys).unwrap();
        let path = keys.join("host-signer.ed25519");
        std::fs::write(&path, [seed; 32]).unwrap();
        mvm_core::private_fs::set_mode(&path, 0o600).unwrap();
        let public = keys.join("host-signer.pub");
        std::fs::write(
            &public,
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        mvm_core::private_fs::set_mode(&public, 0o644).unwrap();
    }

    #[test]
    fn a_stored_declaration_is_read_back() {
        let (_env, _home) = isolated_home();
        with_host_key(7);
        let cache = tempfile::tempdir().unwrap();
        store(
            cache.path(),
            &"e".repeat(64),
            GuestArch::Aarch64,
            &declaration(),
        );
        assert_eq!(
            load(cache.path(), &"e".repeat(64), GuestArch::Aarch64),
            Some(declaration())
        );
    }

    #[test]
    fn an_entry_for_another_archive_is_a_miss() {
        let (_env, _home) = isolated_home();
        with_host_key(7);
        let cache = tempfile::tempdir().unwrap();
        store(
            cache.path(),
            &"e".repeat(64),
            GuestArch::Aarch64,
            &declaration(),
        );
        assert_eq!(
            load(cache.path(), &"f".repeat(64), GuestArch::Aarch64),
            None
        );
    }

    #[test]
    fn an_edited_declaration_is_a_miss() {
        let (_env, _home) = isolated_home();
        with_host_key(7);
        let cache = tempfile::tempdir().unwrap();
        let digest = "e".repeat(64);
        store(cache.path(), &digest, GuestArch::Aarch64, &declaration());
        let file = path(
            cache.path(),
            &entry_id(&digest, GuestArch::Aarch64).unwrap(),
        );
        let tampered = std::fs::read_to_string(&file)
            .unwrap()
            .replace(&"a".repeat(64), &"0".repeat(64));
        std::fs::write(&file, tampered).unwrap();
        assert_eq!(load(cache.path(), &digest, GuestArch::Aarch64), None);
    }

    #[test]
    fn an_entry_signed_by_another_key_is_a_miss() {
        let (_env, _home) = isolated_home();
        with_host_key(7);
        let cache = tempfile::tempdir().unwrap();
        let digest = "e".repeat(64);
        store(cache.path(), &digest, GuestArch::Aarch64, &declaration());
        with_host_key(8);
        assert_eq!(load(cache.path(), &digest, GuestArch::Aarch64), None);
    }

    #[test]
    fn without_a_host_key_nothing_is_stored_or_read() {
        let (_env, _home) = isolated_home();
        let cache = tempfile::tempdir().unwrap();
        store(
            cache.path(),
            &"e".repeat(64),
            GuestArch::Aarch64,
            &declaration(),
        );
        assert!(!cache.path().join(DIR).exists());
        assert_eq!(
            load(cache.path(), &"e".repeat(64), GuestArch::Aarch64),
            None
        );
    }

    #[test]
    fn a_secret_that_does_not_match_the_public_key_is_not_used() {
        let (_env, _home) = isolated_home();
        with_host_key(7);
        let public = mvm_core::config::mvm_keys_dir().join("host-signer.pub");
        std::fs::write(
            &public,
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let cache = tempfile::tempdir().unwrap();
        store(
            cache.path(),
            &"e".repeat(64),
            GuestArch::Aarch64,
            &declaration(),
        );
        assert!(!cache.path().join(DIR).exists());
    }

    #[test]
    fn a_week_old_entry_of_another_build_is_pruned_and_a_fresh_one_kept() {
        let (_env, _home) = isolated_home();
        with_host_key(7);
        let cache = tempfile::tempdir().unwrap();
        let dir = cache.path().join(DIR);
        mvm_core::private_fs::ensure_private_dir(&dir).unwrap();
        let old = dir.join("old.json");
        let fresh = dir.join("fresh.json");
        std::fs::write(&old, b"{}").unwrap();
        std::fs::write(&fresh, b"{}").unwrap();
        let eight_days = std::time::Duration::from_secs(8 * 24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - eight_days)
            .unwrap();
        store(
            cache.path(),
            &"e".repeat(64),
            GuestArch::Aarch64,
            &declaration(),
        );
        assert!(!old.exists());
        assert!(fresh.exists());
    }
}
