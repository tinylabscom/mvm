//! Turning a `--mailbox <id>` request into the grant minted into the plan.
//!
//! The id names the mailbox; the authority is always the host's own signer, so
//! the guest never chooses whose capabilities are accepted.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};

/// Parse a 64-character hex mailbox id.
pub fn parse_mailbox_id(raw: &str) -> Result<MailboxId> {
    let bytes = hex::decode(raw.trim()).context("--mailbox must be a hex mailbox id")?;
    ensure!(
        bytes.len() == 32,
        "--mailbox must be 64 hex characters (32 bytes), got {}",
        bytes.len() * 2
    );
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(MailboxId::from_bytes(id))
}

/// The grant for `mailbox`, authorized by `authority` at `epoch`.
pub fn grant_for(
    mailbox: MailboxId,
    authority: &VerifyingKey,
    epoch: ExecutionEpoch,
) -> MailboxGrant {
    MailboxGrant {
        mailbox,
        authority_key: authority.to_bytes(),
        epoch,
    }
}

/// `grant` re-minted for `workload`'s current execution epoch, the same ledger
/// value that stamps `plan.execution_epoch`. The authority key is derived per
/// epoch, so a replaced workload's grant names a new key as well as a new
/// number. Run where the workload's name is first known.
pub fn at_workload_epoch(grant: MailboxGrant, workload: &str) -> Result<MailboxGrant> {
    let epoch = mvm_core::plan::synthesis::current_local_epoch(workload)?;
    let epoch = ExecutionEpoch::new(epoch).context("the workload's execution epoch is zero")?;
    let authority = mvm_hostd::mailbox_launch::authority_key_for(
        &mvm_core::config::mvm_keys_dir(),
        &grant.mailbox,
        epoch,
    )
    .context("deriving the mailbox authority")?;
    Ok(grant_for(grant.mailbox, &authority, epoch))
}

/// Key in a Workload IR's `extensions` map that declares a mailbox:
/// `{"mvm.mailbox": {"id": "<64 hex>"}}`.
pub const MAILBOX_EXTENSION: &str = "mvm.mailbox";

/// The mailbox a Workload IR declares, if any.
pub fn declared_in(workload: &mvm_contract::ir::Workload) -> Result<Option<MailboxId>> {
    let Some(ext) = workload.extensions.get(MAILBOX_EXTENSION) else {
        return Ok(None);
    };
    let id = ext
        .get("id")
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("workload extension {MAILBOX_EXTENSION} needs a string `id`"))?;
    parse_mailbox_id(id).map(Some)
}

/// Combine the two sources of a mailbox: the `--mailbox` flag and the
/// workload's own declaration. Either alone grants it; both must name the same
/// mailbox, since two answers to one question would leave one of them ignored.
pub fn combine(flag: Option<MailboxId>, declared: Option<MailboxId>) -> Result<Option<MailboxId>> {
    match (flag, declared) {
        (Some(f), Some(d)) => {
            ensure!(
                f == d,
                "--mailbox disagrees with the mailbox the workload declares"
            );
            Ok(Some(f))
        }
        (one, other) => Ok(one.or(other)),
    }
}

/// Resolve both sources against the host signer. Neither means no grant and no
/// key is loaded. The grant is at the first epoch; admission re-mints it for
/// the workload's own epoch with [`at_workload_epoch`].
pub fn resolve(
    flag: Option<&str>,
    workload_ir: Option<&std::path::Path>,
) -> Result<Option<MailboxGrant>> {
    let flag = flag.map(parse_mailbox_id).transpose()?;
    let declared = super::secrets::load_workload_ir(workload_ir)?
        .as_ref()
        .map(declared_in)
        .transpose()?
        .flatten();
    let Some(id) = combine(flag, declared)? else {
        return Ok(None);
    };
    let keys_dir = mvm_core::config::mvm_keys_dir();
    // Ensure the host signer exists; the authority is derived from it.
    mvm_hostd::audit::host_keypair::load_or_init_at(&keys_dir)
        .context("loading the host signer as the mailbox authority")?;
    let first = ExecutionEpoch::new(1).expect("epoch 1 is nonzero");
    let authority = mvm_hostd::mailbox_launch::authority_key_for(&keys_dir, &id, first)
        .context("deriving the mailbox authority")?;
    Ok(Some(grant_for(id, &authority, first)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_64_hex_id_parses_and_anything_else_is_refused() {
        let id = parse_mailbox_id(&"ab".repeat(32)).unwrap();
        assert_eq!(id.as_bytes(), &[0xab; 32]);
        assert!(parse_mailbox_id("abcd").is_err());
        assert!(parse_mailbox_id(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn the_grant_names_the_host_authority_at_the_given_epoch() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key();
        let epoch = ExecutionEpoch::new(3).unwrap();
        let grant = grant_for(MailboxId::from_bytes([1; 32]), &key, epoch);
        assert_eq!(grant.authority_key, key.to_bytes());
        assert_eq!(grant.epoch.get(), 3);
    }

    #[test]
    fn a_replaced_workloads_grant_carries_the_ledger_epoch_and_a_new_authority() {
        use mvm_core::host_interface::workload::WorkloadLedger;
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        mvm_hostd::audit::host_keypair::load_or_init_at(&mvm_core::config::mvm_keys_dir()).unwrap();
        let id = MailboxId::from_bytes([8; 32]);
        let first = resolve(Some(&hex::encode([8; 32])), None).unwrap().unwrap();
        let at1 = at_workload_epoch(first, "w").unwrap();
        assert_eq!((at1.mailbox, at1.epoch.get()), (id, 1));

        let mut ledger = WorkloadLedger::load_at(home.path()).unwrap();
        ledger.replace("w");
        ledger.save_at(home.path()).unwrap();
        let at2 = at_workload_epoch(first, "w").unwrap();
        assert_eq!(at2.epoch.get(), 2);
        assert_ne!(at1.authority_key, at2.authority_key);
        // Another workload is untouched by the replacement.
        assert_eq!(at_workload_epoch(first, "other").unwrap(), at1);
    }

    #[test]
    fn no_flag_grants_nothing() {
        assert!(resolve(None, None).unwrap().is_none());
    }

    fn workload_with(ext: serde_json::Value) -> mvm_contract::ir::Workload {
        let mut w: mvm_contract::ir::Workload = serde_json::from_value(serde_json::json!({
            "schema_version": "1", "id": "w", "apps": []
        }))
        .unwrap();
        w.extensions.insert(MAILBOX_EXTENSION.into(), ext);
        w
    }

    #[test]
    fn a_workload_declaration_is_read_and_a_malformed_one_is_refused() {
        let id = "cd".repeat(32);
        let w = workload_with(serde_json::json!({ "id": id }));
        assert_eq!(declared_in(&w).unwrap().unwrap().as_bytes(), &[0xcd; 32]);
        assert!(declared_in(&workload_with(serde_json::json!({}))).is_err());
        let bare: mvm_contract::ir::Workload = serde_json::from_value(serde_json::json!({
            "schema_version": "1", "id": "w", "apps": []
        }))
        .unwrap();
        assert!(declared_in(&bare).unwrap().is_none());
    }

    #[test]
    fn flag_and_declaration_combine_and_conflicts_are_refused() {
        let a = MailboxId::from_bytes([1; 32]);
        let b = MailboxId::from_bytes([2; 32]);
        assert_eq!(combine(Some(a), None).unwrap(), Some(a));
        assert_eq!(combine(None, Some(b)).unwrap(), Some(b));
        assert_eq!(combine(Some(a), Some(a)).unwrap(), Some(a));
        assert!(combine(Some(a), Some(b)).is_err());
        assert_eq!(combine(None, None).unwrap(), None);
    }
}
