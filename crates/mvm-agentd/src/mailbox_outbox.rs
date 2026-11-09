//! Guest side of the mailbox port: when the host dials it, send the one
//! plaintext message the workload left in the outbox and return the host's
//! verdict.
//!
//! The guest holds no key and seals nothing. The outbox carries a recipient
//! and a body; the host seals and signs it under the capability the signed
//! plan granted, then admits it. Encryption is host to host.
//!
//! [`write_outbox`] is the workload side: it leaves that one message where
//! [`forward_outbox`] will find it, using the same [`OutboxMessage`] encoding
//! and size limits the host decodes with.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use mvm_contract::protocol::mailbox::MAX_MAILBOX_PAYLOAD_BYTES;
use mvm_core::mailbox::frame::{OutboxMessage, Refusal, send_outbox_message};

/// Where the workload leaves its message and the agent reads it.
pub const OUTBOX_PATH: &str = "/run/mvm/mailbox/outbox";

/// The launch assertion that grants a guest a mailbox. The agent creates the
/// outbox directory and binds the mailbox port only when the kernel cmdline
/// carries it.
pub const MAILBOX_CMDLINE_TOKEN: &str = "mvm.mailbox=1";

/// Owner only. The agent and the workload both run as the one fixed workload
/// identity (one guest, one workload), so the owner is both writer and
/// reader. No other uid in the guest, including the egress and DNS helpers,
/// can list, read or replace anything in it.
pub const OUTBOX_DIR_MODE: u32 = 0o700;

/// Owner read/write, group read. Nobody else may read the plaintext.
pub const OUTBOX_FILE_MODE: u32 = 0o640;

/// The recipient bytes beside the largest body the host will seal.
const MAX_OUTBOX_BYTES: u64 = MAX_MAILBOX_PAYLOAD_BYTES as u64 + 32;

/// Forward the outbox message over `stream`. An absent, oversized or
/// malformed outbox is refused here, before a byte is sent to the host.
pub fn forward_outbox<S: Read + Write>(stream: &mut S, outbox: &Path) -> Result<(), Refusal> {
    let mut bytes = Vec::new();
    std::fs::File::open(outbox)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::Malformed)?;
    send_outbox_message(stream, &OutboxMessage::decode(&bytes)?)
}

/// Create the outbox directory, owned by `uid`:`gid` at [`OUTBOX_DIR_MODE`].
/// Idempotent. The caller must hold root to chown to another identity, and
/// must call this only on a boot that asserts [`MAILBOX_CMDLINE_TOKEN`].
pub fn provision_outbox_dir(dir: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(OUTBOX_DIR_MODE)
        .create(dir)?;
    // The mode above is subject to the umask and skipped when the directory exists.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(OUTBOX_DIR_MODE))?;
    std::os::unix::fs::chown(dir, Some(uid), Some(gid))
}

/// [`provision_outbox_dir`], but only when `cmdline` asserts a mailbox; an
/// ungranted guest creates nothing. Returns whether it created the directory.
pub fn provision_outbox_dir_if_asserted(
    cmdline: &str,
    dir: &Path,
    uid: u32,
    gid: u32,
) -> std::io::Result<bool> {
    if !cmdline
        .split_ascii_whitespace()
        .any(|t| t == MAILBOX_CMDLINE_TOKEN)
    {
        return Ok(false);
    }
    provision_outbox_dir(dir, uid, gid).map(|()| true)
}

/// Workload side: atomically leave `message` at `outbox`. The directory must
/// already exist, since it is how the launch grants a mailbox; without it this
/// refuses and creates nothing. Written to a sibling temp file, then renamed,
/// so the agent never reads a partial frame.
pub fn write_outbox(outbox: &Path, message: &OutboxMessage) -> Result<(), Refusal> {
    let bytes = message.encode();
    // Same validation the host applies on receipt (empty, oversized).
    OutboxMessage::decode(&bytes)?;
    let dir = outbox
        .parent()
        .filter(|d| d.is_dir())
        .ok_or(Refusal::Malformed)?;
    let tmp = dir.join(format!(".outbox.{}.tmp", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OUTBOX_FILE_MODE)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&bytes))
        .and_then(|()| std::fs::rename(&tmp, outbox));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Refusal::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::PrincipalId;

    fn message(body: &[u8]) -> OutboxMessage {
        OutboxMessage {
            recipient: PrincipalId::from_bytes([7; 32]),
            body: body.to_vec(),
        }
    }

    #[test]
    fn a_written_outbox_is_forwarded_as_the_same_message() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        write_outbox(&outbox, &message(b"hello")).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":null}").unwrap();
            body
        });
        forward_outbox(&mut ours, &outbox).unwrap();
        // The host decoder (serve_guest uses OutboxMessage::decode) gets it back.
        assert_eq!(
            OutboxMessage::decode(&host.join().unwrap()),
            Ok(message(b"hello"))
        );
    }

    #[test]
    fn the_outbox_file_is_group_readable_never_world_readable_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        write_outbox(&outbox, &message(b"x")).unwrap();
        let mode = std::fs::metadata(&outbox).unwrap().permissions().mode() & 0o777;
        // umask may only clear bits, never add them.
        assert_eq!(mode & !OUTBOX_FILE_MODE, 0);
        assert_eq!(mode & 0o007, 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn the_outbox_dir_is_owner_only_owned_by_the_given_identity_and_idempotent() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("mailbox");
        let (uid, gid) = (
            root.path().metadata().unwrap().uid(),
            root.path().metadata().unwrap().gid(),
        );
        for _ in 0..2 {
            provision_outbox_dir(&dir, uid, gid).unwrap();
            let meta = std::fs::metadata(&dir).unwrap();
            assert_eq!(meta.permissions().mode() & 0o7777, OUTBOX_DIR_MODE);
            assert_eq!((meta.uid(), meta.gid()), (uid, gid));
        }
        // A loosened directory is tightened again.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        provision_outbox_dir(&dir, uid, gid).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            OUTBOX_DIR_MODE
        );
        // The writer works inside it.
        write_outbox(&dir.join("outbox"), &message(b"x")).unwrap();
    }

    #[test]
    fn no_outbox_dir_is_created_unless_the_cmdline_asserts_a_mailbox() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("mailbox");
        for cmdline in ["console=ttyS0", "mvm.mailbox=0", "xmvm.mailbox=1", ""] {
            assert!(!provision_outbox_dir_if_asserted(cmdline, &dir, 0, 0).unwrap());
            assert!(!dir.exists());
        }
        let meta = root.path().metadata().unwrap();
        use std::os::unix::fs::MetadataExt;
        assert!(
            provision_outbox_dir_if_asserted("a mvm.mailbox=1", &dir, meta.uid(), meta.gid())
                .unwrap()
        );
        assert!(dir.is_dir());
    }

    #[test]
    fn a_second_write_replaces_the_first_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        write_outbox(&outbox, &message(b"one")).unwrap();
        write_outbox(&outbox, &message(b"two")).unwrap();
        let on_disk = std::fs::read(&outbox).unwrap();
        assert_eq!(OutboxMessage::decode(&on_disk), Ok(message(b"two")));
    }

    #[test]
    fn oversized_empty_and_ungranted_writes_are_refused_without_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let big = message(&vec![1u8; MAX_MAILBOX_PAYLOAD_BYTES + 1]);
        assert!(matches!(
            write_outbox(&outbox, &big),
            Err(Refusal::Oversized(_))
        ));
        assert_eq!(
            write_outbox(&outbox, &message(b"")),
            Err(Refusal::Malformed)
        );
        let at_cap = message(&vec![1u8; MAX_MAILBOX_PAYLOAD_BYTES]);
        write_outbox(&outbox, &at_cap).unwrap();
        // No grant: the directory is absent, nothing is created.
        let absent = dir.path().join("nogrant").join("outbox");
        assert_eq!(
            write_outbox(&absent, &message(b"x")),
            Err(Refusal::Malformed)
        );
        assert!(!dir.path().join("nogrant").exists());
    }

    #[test]
    fn a_missing_or_malformed_outbox_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            forward_outbox(&mut ours, &dir.path().join("none")),
            Err(Refusal::Malformed)
        );
        let junk = dir.path().join("junk");
        std::fs::write(&junk, b"short").unwrap();
        assert_eq!(forward_outbox(&mut ours, &junk), Err(Refusal::Malformed));
        let big = dir.path().join("big");
        std::fs::write(&big, vec![1u8; MAX_OUTBOX_BYTES as usize + 8]).unwrap();
        assert!(matches!(
            forward_outbox(&mut ours, &big),
            Err(Refusal::Oversized(_))
        ));
        drop(ours);
        let mut seen = Vec::new();
        theirs.read_to_end(&mut seen).unwrap();
        assert!(seen.is_empty(), "nothing reached the host");
    }

    /// The wire carries the plaintext message and nothing else: no
    /// capability, envelope, signature or key, and this path names no key
    /// type to build one from.
    #[test]
    fn the_frame_on_the_wire_is_exactly_the_plaintext_message() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let message = [&[9u8; 32][..], b"hello"].concat();
        std::fs::write(&outbox, &message).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":null}").unwrap();
            body
        });
        assert_eq!(forward_outbox(&mut ours, &outbox), Ok(()));
        assert_eq!(host.join().unwrap(), message);
        let source = include_str!("mailbox_outbox.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for key_type in [
            "SigningKey",
            "aead::Key",
            "seal_envelope",
            "sign_capability",
        ] {
            assert!(!code.contains(key_type), "guest outbox names {key_type}");
        }
    }
}
