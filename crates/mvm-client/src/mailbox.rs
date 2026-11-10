//! Read the oldest message a granted guest has sent to its VM's mailbox.
//!
//! The queue lives in the VM's `mvm-mailbox` process, which holds derived keys
//! and cannot sign audit entries. The read is made here, as the host user, and
//! this side signs the entry: `mailbox.read`, carrying the VM name, the
//! message's byte length and the queue's lifetime accepted and read counts,
//! never the message. A delivery the process accepts is therefore audited when
//! it is read, as part of those counts, and not as it arrives; a poll that
//! finds nothing leaves no entry. The entry is signed before the message is
//! returned, so a read whose entry cannot be written is refused and the
//! message it took is not delivered.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;
use mvm_hostd::audit::emitter::AuditEmitter;

/// Take the oldest message from the mailbox of the VM named `name`.
pub fn recv(name: &str) -> Result<Option<Vec<u8>>> {
    let plan = mvm_hostd::audit::plan_persist::read_plan(name)
        .with_context(|| format!("no admitted plan for {name}; is it a granted machine?"))?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init().context("host signer")?;
    let emitter = AuditEmitter::new(signer.signing).context("audit emitter")?;
    let socket = mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(name));
    recv_at(&socket, name, &plan, &emitter)
}

fn recv_at(
    socket: &Path,
    name: &str,
    plan: &ExecutionPlan,
    emitter: &AuditEmitter,
) -> Result<Option<Vec<u8>>> {
    let got = mvm_hostd::mailbox_service::recv(socket)
        .with_context(|| format!("{name} has no reachable mailbox"))?;
    let Some(message) = got.message else {
        return Ok(None);
    };
    let body = hex::decode(message).context("mailbox message")?;
    emitter
        .emit_mailbox_read(plan, name, body.len(), got.accepted, got.read)
        .context("refusing an unaudited mailbox read")?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    /// A stand-in mailbox process that answers one request with `reply`.
    fn serve_once(dir: &Path, reply: &'static str) -> std::path::PathBuf {
        let path = dir.join("mailbox.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, br#"{"request":"recv"}"#);
            stream.write_all(reply.as_bytes()).unwrap();
        });
        path
    }

    fn emitter(dir: &Path) -> AuditEmitter {
        let signer = mvm_hostd::audit::host_keypair::load_or_init_at(&dir.join("keys")).unwrap();
        AuditEmitter::with_dir(signer.signing, &dir.join("audit")).unwrap()
    }

    #[test]
    fn a_read_returns_the_body_and_audits_its_length_not_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let socket = serve_once(
            dir.path(),
            r#"{"Ok":{"message":"73656372657421","accepted":3,"read":1}}"#,
        );
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .build();
        let body = recv_at(&socket, "vm", &plan, &emitter(dir.path())).unwrap();
        assert_eq!(body.as_deref(), Some(&b"secret!"[..]));
        let audit = std::fs::read_to_string(dir.path().join("audit/local.jsonl")).unwrap();
        assert!(audit.contains("mailbox.read") && audit.contains("\"bytes\":\"7\""));
        assert!(!audit.contains("secret") && !audit.contains("73656372657421"));
    }

    #[test]
    fn an_empty_queue_is_none_and_leaves_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let socket = serve_once(
            dir.path(),
            r#"{"Ok":{"message":null,"accepted":0,"read":0}}"#,
        );
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .build();
        assert!(
            recv_at(&socket, "vm", &plan, &emitter(dir.path()))
                .unwrap()
                .is_none()
        );
        assert!(!dir.path().join("audit/local.jsonl").exists());
    }
}
