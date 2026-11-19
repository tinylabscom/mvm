//! Install an admitted controller's distinct boot credentials for the workload UID.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mvm_core::net::actor_session::{
    ACTOR_BINDING_FILE, ACTOR_GUEST_KEY_FILE, ActorSessionBinding, MAX_ACTOR_BINDING_BYTES,
};
use zeroize::Zeroizing;

/// Retire old credentials even when this boot has no actor identity drive.
///
/// # Errors
/// Refuses to continue when stale credential files cannot be removed.
pub fn clear(run_dir: &Path) -> Result<()> {
    for name in [ACTOR_GUEST_KEY_FILE, ACTOR_BINDING_FILE] {
        match std::fs::remove_file(run_dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("retire stale actor boot identity"),
        }
    }
    Ok(())
}

fn open_optional(path: &Path) -> Result<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("open actor identity drive material"),
    }
}

fn read_bounded(file: File, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = file.metadata().context("inspect actor identity material")?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "actor identity material is not a bounded regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .context("read actor identity material")?;
    ensure!(
        bytes.len() as u64 <= limit,
        "actor identity material exceeds bound"
    );
    Ok(bytes)
}

/// Copy a validated optional pair from the read-only drive into root-owned `/run/mvm`.
///
/// The destination directory must remain root-owned and not writable by the
/// workload. Only its distinct signing seed becomes workload-owned, mode 0400;
/// the public binding remains root-owned, mode 0444. No host private key is read.
///
/// # Errors
/// Refuses missing halves, symlinks, oversized or malformed material, key mismatch,
/// or any failure to establish the requested ownership. Partial output is removed.
pub fn install_from_drive(drive_dir: &Path, run_dir: &Path, workload_uid: u32) -> Result<()> {
    clear(run_dir)?;
    let key = open_optional(&drive_dir.join(ACTOR_GUEST_KEY_FILE))?;
    let binding = open_optional(&drive_dir.join(ACTOR_BINDING_FILE))?;
    let (key, binding) = match (key, binding) {
        (None, None) => return Ok(()),
        (Some(key), Some(binding)) => (key, binding),
        _ => anyhow::bail!("actor signing key and session binding must be provisioned together"),
    };
    let seed = read_bounded(key, 32)?;
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .context("actor signing seed must contain exactly 32 bytes")?;
    let binding_bytes = read_bounded(binding, MAX_ACTOR_BINDING_BYTES as u64)?;
    let binding: ActorSessionBinding =
        serde_json::from_slice(&binding_bytes).context("decode actor session binding")?;
    binding
        .session_id()
        .context("validate actor session binding")?;
    ensure!(
        SigningKey::from_bytes(seed).verifying_key().to_bytes() == binding.guest_public_key,
        "actor signing key does not match this boot binding"
    );
    let result = (|| {
        let key_path = run_dir.join(ACTOR_GUEST_KEY_FILE);
        let mut key = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&key_path)
            .context("create workload actor key")?;
        key.write_all(seed).context("write workload actor key")?;
        std::os::unix::fs::chown(&key_path, Some(workload_uid), None)
            .context("assign actor key to workload identity")?;
        key.set_permissions(std::fs::Permissions::from_mode(0o400))
            .context("set workload actor key mode")?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .custom_flags(libc::O_NOFOLLOW)
            .open(run_dir.join(ACTOR_BINDING_FILE))
            .context("create public actor boot binding")?;
        output
            .write_all(&binding_bytes)
            .context("write public actor boot binding")?;
        output
            .set_permissions(std::fs::Permissions::from_mode(0o444))
            .context("set public actor binding mode")
    })();
    if result.is_err() {
        clear(run_dir).context("remove incomplete actor identity projection")?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    fn binding(seed: &[u8; 32]) -> ActorSessionBinding {
        ActorSessionBinding {
            protocol_version: 1,
            purpose: "host.actor.v1".into(),
            tenant: "tenant".into(),
            workflow: "workflow".into(),
            boot_id: "01".repeat(32),
            plan_digest: [3; 32],
            epoch: 1,
            controller_generation: 1,
            key_generation: 1,
            guest_public_key: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
            host_public_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        }
    }

    fn write_pair(dir: &Path, seed: &[u8; 32]) {
        std::fs::write(dir.join(ACTOR_GUEST_KEY_FILE), seed).unwrap();
        std::fs::write(
            dir.join(ACTOR_BINDING_FILE),
            serde_json::to_vec(&binding(seed)).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn projection_installs_a_workload_owned_private_key_and_public_binding() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        write_pair(drive.path(), &[7; 32]);
        let uid = run.path().metadata().unwrap().uid();
        install_from_drive(drive.path(), run.path(), uid).unwrap();
        let key = run.path().join(ACTOR_GUEST_KEY_FILE);
        assert_eq!(std::fs::read(&key).unwrap(), [7; 32]);
        let metadata = key.metadata().unwrap();
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
        assert_eq!(
            run.path()
                .join(ACTOR_BINDING_FILE)
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        let projected: ActorSessionBinding =
            serde_json::from_slice(&std::fs::read(run.path().join(ACTOR_BINDING_FILE)).unwrap())
                .unwrap();
        assert_eq!(projected, binding(&[7; 32]));
    }

    #[test]
    fn absence_removes_stale_authority_without_creating_any_files() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        write_pair(run.path(), &[7; 32]);
        install_from_drive(
            drive.path(),
            run.path(),
            run.path().metadata().unwrap().uid(),
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(run.path()).unwrap().count(), 0);
        clear(run.path()).unwrap();
    }

    #[test]
    fn incomplete_malformed_or_mismatched_pairs_never_install_authority() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let uid = run.path().metadata().unwrap().uid();
        std::fs::write(drive.path().join(ACTOR_GUEST_KEY_FILE), [7; 32]).unwrap();
        assert!(install_from_drive(drive.path(), run.path(), uid).is_err());
        for bytes in [vec![7; 31], vec![7; 33]] {
            write_pair(drive.path(), &[7; 32]);
            std::fs::write(drive.path().join(ACTOR_GUEST_KEY_FILE), bytes).unwrap();
            assert!(install_from_drive(drive.path(), run.path(), uid).is_err());
            assert_eq!(std::fs::read_dir(run.path()).unwrap().count(), 0);
        }
        write_pair(drive.path(), &[7; 32]);
        std::fs::write(drive.path().join(ACTOR_GUEST_KEY_FILE), [8; 32]).unwrap();
        assert!(install_from_drive(drive.path(), run.path(), uid).is_err());
        for bytes in [b"{}".to_vec(), vec![b' '; MAX_ACTOR_BINDING_BYTES + 1]] {
            write_pair(drive.path(), &[7; 32]);
            std::fs::write(drive.path().join(ACTOR_BINDING_FILE), bytes).unwrap();
            assert!(install_from_drive(drive.path(), run.path(), uid).is_err());
            assert_eq!(std::fs::read_dir(run.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn source_symlinks_are_refused_and_destination_symlinks_do_not_receive_keys() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let sentinel = elsewhere.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        let uid = run.path().metadata().unwrap().uid();
        write_pair(drive.path(), &[7; 32]);
        symlink(&sentinel, run.path().join(ACTOR_GUEST_KEY_FILE)).unwrap();
        install_from_drive(drive.path(), run.path(), uid).unwrap();
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        std::fs::remove_file(drive.path().join(ACTOR_GUEST_KEY_FILE)).unwrap();
        symlink(&sentinel, drive.path().join(ACTOR_GUEST_KEY_FILE)).unwrap();
        assert!(install_from_drive(drive.path(), run.path(), uid).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        assert_eq!(std::fs::read_dir(run.path()).unwrap().count(), 0);
    }
}
