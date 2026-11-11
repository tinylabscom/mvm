//! Persist the exact destination-signed reader authority across helper restarts.

use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    ConsumerSessionId, MailboxCapabilityGrant, MailboxGrant, MailboxGuestReaderEnrollment,
    MailboxGuestReaderScope, ProtocolVersion, SignatureAlgorithm, SignedMailboxCapability,
    SignedMailboxGuestReaderEnrollment,
};
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, mint_guest_receive_capability, sign_guest_reader_enrollment,
    verify_guest_reader_enrollment,
};
use mvm_core::mailbox::sign_capability;
use mvm_core::util::atomic_io::atomic_write_new;
use sha2::{Digest as _, Sha256};

use crate::mailbox_service::durable::GuestReaderAuthority;

const READER_FILE: &str = "mailbox-reader-authority.json";
const MAX_READER_FILE_BYTES: u64 = 64 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderRecord {
    version: u8,
    boot: MailboxReaderBootBinding,
    send: SignedMailboxCapability,
    receive: SignedMailboxCapability,
    enrollment: SignedMailboxGuestReaderEnrollment,
}

fn invalid(reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("mailbox reader authority refused: {reason}"),
    )
}

fn session_for(binding: &MailboxReaderBootBinding) -> ConsumerSessionId {
    let mut digest = Sha256::new();
    digest.update(b"mvm.mailbox.guest-session.v1\0");
    digest.update(binding.boot.as_bytes());
    digest.update(binding.plan_id.0.as_bytes());
    digest.update(binding.plan_nonce.as_hex().as_bytes());
    digest.update(binding.ack_public_key);
    ConsumerSessionId::from_bytes(digest.finalize().into())
}

fn now_unix_ms() -> io::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}

fn read_record(path: &Path) -> io::Result<Option<ReaderRecord>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_READER_FILE_BYTES {
        return Err(invalid("record is not a bounded single-link regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_READER_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_READER_FILE_BYTES {
        return Err(invalid("record exceeds the encoded bound"));
    }
    serde_json::from_slice(&bytes).map(Some).map_err(invalid)
}

pub(super) fn load_or_enroll(
    state_dir: &Path,
    grant: &MailboxGrant,
    binding: MailboxReaderBootBinding,
    send_grant: &MailboxCapabilityGrant,
    signer: &SigningKey,
) -> io::Result<GuestReaderAuthority> {
    // Re-read the host's persisted boot identity: stdin alone cannot change
    // which cold guest this per-VM helper is authorized to serve.
    if MailboxReaderBootBinding::load(state_dir).map_err(invalid)? != binding
        || binding.mailbox != grant.mailbox
        || binding.execution_epoch != grant.epoch
        || binding.authority_key != grant.authority_key
        || signer.verifying_key().to_bytes() != grant.authority_key
    {
        return Err(invalid("boot, signed grant or authority changed"));
    }
    // The reader wire caps the entire JSON/base64 delivery at 64 KiB. A
    // larger granted message could otherwise acquire a durable lease that
    // the guest can never receive or ACK.
    if send_grant.max_payload_bytes > 32 * 1024 {
        return Err(invalid("granted payload exceeds the guest reader frame"));
    }
    let now = now_unix_ms()?;
    let path = state_dir.join(READER_FILE);
    let record = match read_record(&path)? {
        Some(record) => record,
        None => {
            let send = sign_capability(send_grant.clone(), signer).map_err(invalid)?;
            let receive =
                mint_guest_receive_capability(grant, &binding, &send, send_grant.address, signer)
                    .map_err(invalid)?;
            let enrollment = sign_guest_reader_enrollment(
                MailboxGuestReaderEnrollment {
                    protocol_version: ProtocolVersion::V1,
                    signature_algorithm: SignatureAlgorithm::ED25519,
                    plan_id: binding.plan_id.clone(),
                    plan_nonce: binding.plan_nonce.clone(),
                    address: receive.grant.address,
                    consumer: receive.grant.subject,
                    consumer_boot: binding.boot,
                    consumer_session: session_for(&binding),
                    receive_capability_id: receive.grant.capability_id,
                    ack_public_key: binding.ack_public_key,
                    execution_epoch: grant.epoch,
                    policy_epoch: receive.grant.policy_epoch,
                    issued_at_unix_ms: now.max(receive.grant.not_before_unix_ms),
                    expires_at_unix_ms: receive.grant.expires_at_unix_ms,
                },
                signer,
            )
            .map_err(invalid)?;
            let record = ReaderRecord {
                version: 1,
                boot: binding.clone(),
                send,
                receive,
                enrollment,
            };
            let bytes = serde_json::to_vec(&record).map_err(invalid)?;
            if bytes.len() as u64 > MAX_READER_FILE_BYTES {
                return Err(invalid("record exceeds the encoded bound"));
            }
            atomic_write_new(&path, &bytes).map_err(io::Error::other)?;
            record
        }
    };
    if record.version != 1
        || record.boot != binding
        || record.enrollment.enrollment.consumer_session != session_for(&binding)
    {
        return Err(invalid("reader belongs to a different boot or session"));
    }
    // The default sender template has a new time window when the helper is
    // restarted. Do not silently mint a new Receive lease: retain the exact
    // signed original, while requiring all non-time policy fields to agree.
    let mut expected_send = send_grant.clone();
    expected_send.not_before_unix_ms = record.send.grant.not_before_unix_ms;
    expected_send.expires_at_unix_ms = record.send.grant.expires_at_unix_ms;
    if record.send.grant != expected_send {
        return Err(invalid("sender policy changed across helper restart"));
    }
    let expected_receive =
        mint_guest_receive_capability(grant, &binding, &record.send, send_grant.address, signer)
            .map_err(invalid)?;
    if record.receive != expected_receive
        || record.enrollment.enrollment.ack_public_key != binding.ack_public_key
    {
        return Err(invalid("signed Receive grant or enrolled key changed"));
    }
    let scope = MailboxGuestReaderScope {
        plan: grant,
        plan_id: &binding.plan_id,
        plan_nonce: &binding.plan_nonce,
        receive: &record.receive.grant,
        current_boot: binding.boot,
        current_session: session_for(&binding),
        now_unix_ms: now,
    };
    verify_guest_reader_enrollment(
        &record.enrollment,
        &record.receive,
        &scope,
        &signer.verifying_key(),
        &[],
    )
    .map_err(invalid)?;
    Ok(GuestReaderAuthority {
        grant: *grant,
        boot: binding,
        capability: record.receive,
        enrollment: record.enrollment,
        revocations_path: state_dir.join("mailbox-reader-revocations.json"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};

    #[test]
    fn helper_restart_reuses_exact_signed_receive_and_enrollment() {
        let keys = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
        let mailbox = MailboxId::from_bytes([42; 32]);
        let grant = MailboxGrant {
            mailbox,
            authority_key: crate::mailbox_launch::authority_key_for(keys.path(), &mailbox)
                .unwrap()
                .to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
        };
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant);
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let ack = SigningKey::from_bytes(&[44; 32]);
        let binding = MailboxReaderBootBinding::mint(
            &plan,
            SigningKey::from_bytes(&[45; 32]).verifying_key(),
            ack.verifying_key().to_bytes(),
        )
        .unwrap();
        binding.persist(state.path()).unwrap();
        let derive = || crate::mailbox_launch::derive_launch_keys(keys.path(), &grant).unwrap();
        let first_keys = derive();
        let first_send = first_keys.trust().1.capability;
        let first = load_or_enroll(
            state.path(),
            &grant,
            binding.clone(),
            &first_send,
            &first_keys.durable_material().0,
        )
        .unwrap();
        let second_keys = derive();
        let second_send = second_keys.trust().1.capability;
        let second = load_or_enroll(
            state.path(),
            &grant,
            binding.clone(),
            &second_send,
            &second_keys.durable_material().0,
        )
        .unwrap();
        assert_eq!(first.capability, second.capability);
        assert_eq!(first.enrollment, second.enrollment);
        assert_ne!(
            first.capability.grant.capability_id,
            first_send.capability_id
        );

        let path = state.path().join(READER_FILE);
        let mut forged: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        forged["receive"]["signature"] = serde_json::json!("AAAAAAAA");
        std::fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(
            load_or_enroll(
                state.path(),
                &grant,
                binding.clone(),
                &second_send,
                &second_keys.durable_material().0,
            )
            .is_err(),
            "a changed signed Receive grant must fail closed after restart"
        );
        let mut other_boot = binding;
        other_boot.boot = mvm_contract::protocol::mailbox::BootId::from_bytes([99; 32]);
        assert!(
            load_or_enroll(
                state.path(),
                &grant,
                other_boot,
                &second_send,
                &second_keys.durable_material().0,
            )
            .is_err()
        );
    }
}
