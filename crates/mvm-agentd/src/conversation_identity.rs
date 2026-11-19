//! Pin the provider's exact mailbox target before the guest drops privileges.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use mvm_core::mailbox::conversation_wire::{
    CONVERSATION_BINDING_FILE, ConversationBinding, MAX_BINDING_BYTES,
};
use mvm_core::mailbox::reader::{
    MAILBOX_READER_BOOT_FILE, MAX_MAILBOX_READER_BOOT_BYTES, MailboxReaderBootBinding,
};

/// Remove a stale projection on every boot, including boots without an identity drive.
pub fn clear(run_dir: &Path) -> Result<()> {
    match std::fs::remove_file(run_dir.join(CONVERSATION_BINDING_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("retire stale mailbox conversation binding"),
    }
}

fn open(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn read(file: File, limit: u64) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .context("inspect mailbox identity projection")?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "mailbox identity must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .context("read mailbox identity projection")?;
    ensure!(
        bytes.len() as u64 <= limit,
        "mailbox identity projection exceeds bound"
    );
    Ok(bytes)
}

/// Install only a bounded public projection matching the reader already copied for this boot.
///
/// Both directories must be root-owned and not writable by the workload. Missing
/// conversation material means no conversation authority, not an inferred target.
///
/// # Errors
/// Refuses symlinks, nonregular or oversized input, malformed bindings, absent
/// readers, mismatched boot/plan/mailbox/epoch/authority, and incomplete writes.
pub fn install_from_drive(drive_dir: &Path, run_dir: &Path) -> Result<()> {
    clear(run_dir)?;
    let file = match open(&drive_dir.join(CONVERSATION_BINDING_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("open mailbox conversation projection"),
    };
    let bytes = read(file, MAX_BINDING_BYTES as u64)?;
    let binding: ConversationBinding =
        serde_json::from_slice(&bytes).context("decode mailbox conversation projection")?;
    let reader = read(
        open(&run_dir.join(MAILBOX_READER_BOOT_FILE)).context("open current mailbox reader")?,
        MAX_MAILBOX_READER_BOOT_BYTES,
    )?;
    let reader: MailboxReaderBootBinding =
        serde_json::from_slice(&reader).context("decode current mailbox reader")?;
    binding.check_reader(&reader).map_err(|_| {
        anyhow::anyhow!("mailbox conversation differs from this boot's reader authority")
    })?;
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .custom_flags(libc::O_NOFOLLOW)
            .open(run_dir.join(CONVERSATION_BINDING_FILE))
            .context("create public mailbox conversation binding")?;
        output
            .write_all(&bytes)
            .context("write public mailbox conversation binding")?;
        output
            .set_permissions(std::fs::Permissions::from_mode(0o444))
            .context("set public mailbox conversation binding mode")
    })();
    if result.is_err() {
        clear(run_dir).context("retire incomplete mailbox conversation projection")?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::{Nonce, PlanId};
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, BootId, ExecutionEpoch, MailboxAddress, MailboxId, PrincipalId,
        TenantId,
    };
    use mvm_core::mailbox::conversation_wire::ConversationTarget;
    use std::os::unix::fs::symlink;

    fn binding() -> ConversationBinding {
        let reader = MailboxReaderBootBinding {
            plan_id: PlanId("sha256:parent".into()),
            plan_nonce: Nonce::from_bytes([1; 16]),
            mailbox: MailboxId::from_bytes([2; 32]),
            authority_key: [3; 32],
            execution_epoch: ExecutionEpoch::new(4).unwrap(),
            boot: BootId::from_bytes([5; 32]),
            guest_identity_key: [6; 32],
            ack_public_key: [7; 32],
        };
        ConversationTarget {
            address: MailboxAddress {
                tenant: TenantId::from_bytes([8; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([9; 32]),
                mailbox: reader.mailbox,
                recipient: PrincipalId::from_bytes([10; 32]),
            },
            policy_epoch: 11,
        }
        .bind(&reader)
        .unwrap()
    }

    fn write_binding(drive: &Path, run: &Path, binding: &ConversationBinding) {
        std::fs::write(
            drive.join(CONVERSATION_BINDING_FILE),
            serde_json::to_vec(binding).unwrap(),
        )
        .unwrap();
        std::fs::write(
            run.join(MAILBOX_READER_BOOT_FILE),
            serde_json::to_vec(&binding.reader).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn provider_address_and_policy_are_copied_exactly_and_removed_when_absent() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let binding = binding();
        write_binding(drive.path(), run.path(), &binding);
        install_from_drive(drive.path(), run.path()).unwrap();
        let path = run.path().join(CONVERSATION_BINDING_FILE);
        assert_eq!(
            serde_json::from_slice::<ConversationBinding>(&std::fs::read(&path).unwrap()).unwrap(),
            binding
        );
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o444);
        std::fs::remove_file(drive.path().join(CONVERSATION_BINDING_FILE)).unwrap();
        install_from_drive(drive.path(), run.path()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn wrong_reader_plan_nonce_mailbox_authority_epoch_boot_or_keys_are_refused() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let valid = binding();
        for field in [
            "plan",
            "nonce",
            "mailbox",
            "authority",
            "epoch",
            "boot",
            "guest_key",
            "ack_key",
            "address",
        ] {
            write_binding(drive.path(), run.path(), &valid);
            let mut changed = valid.clone();
            match field {
                "plan" => changed.reader.plan_id.0 = "other".into(),
                "nonce" => changed.reader.plan_nonce = Nonce::from_bytes([12; 16]),
                "mailbox" => changed.reader.mailbox = MailboxId::from_bytes([12; 32]),
                "authority" => changed.reader.authority_key = [12; 32],
                "epoch" => changed.reader.execution_epoch = ExecutionEpoch::new(12).unwrap(),
                "boot" => changed.reader.boot = BootId::from_bytes([12; 32]),
                "guest_key" => changed.reader.guest_identity_key = [12; 32],
                "ack_key" => changed.reader.ack_public_key = [12; 32],
                "address" => changed.address.mailbox = MailboxId::from_bytes([12; 32]),
                _ => unreachable!(),
            }
            std::fs::write(
                drive.path().join(CONVERSATION_BINDING_FILE),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
            assert!(
                install_from_drive(drive.path(), run.path()).is_err(),
                "{field}"
            );
            assert!(!run.path().join(CONVERSATION_BINDING_FILE).exists());
        }
    }

    #[test]
    fn missing_reader_oversize_unknown_fields_and_symlinks_are_refused() {
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        write_binding(drive.path(), run.path(), &binding());
        std::fs::remove_file(run.path().join(MAILBOX_READER_BOOT_FILE)).unwrap();
        assert!(install_from_drive(drive.path(), run.path()).is_err());
        write_binding(drive.path(), run.path(), &binding());
        std::fs::write(
            drive.path().join(CONVERSATION_BINDING_FILE),
            vec![b' '; MAX_BINDING_BYTES + 1],
        )
        .unwrap();
        assert!(install_from_drive(drive.path(), run.path()).is_err());
        let mut invalid = serde_json::to_value(binding()).unwrap();
        invalid["host_socket"] = serde_json::json!("/tmp/forbidden");
        std::fs::write(
            drive.path().join(CONVERSATION_BINDING_FILE),
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        assert!(install_from_drive(drive.path(), run.path()).is_err());
        std::fs::remove_file(drive.path().join(CONVERSATION_BINDING_FILE)).unwrap();
        symlink(
            run.path().join(MAILBOX_READER_BOOT_FILE),
            drive.path().join(CONVERSATION_BINDING_FILE),
        )
        .unwrap();
        assert!(install_from_drive(drive.path(), run.path()).is_err());
        assert!(!run.path().join(CONVERSATION_BINDING_FILE).exists());
    }
}
