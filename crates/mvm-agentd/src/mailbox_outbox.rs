//! Guest side of the mailbox port: when the host dials it, send the one
//! plaintext message the workload left in the outbox and return the host's
//! verdict.
//!
//! The guest holds no key and seals nothing. The outbox carries a stable
//! message ID, recipient and body; the host seals and signs under the capability the signed
//! plan granted, then admits it. Encryption is host to host.
//!
//! [`write_outbox`] is the workload side: it leaves that one message where
//! [`forward_outbox`] will find it, using the same [`OutboxMessage`] encoding
//! and size limits the host decodes with.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use mvm_contract::protocol::mailbox::MAX_MAILBOX_PAYLOAD_BYTES;
use mvm_core::mailbox::frame::{OutboxMessage, Refusal, send_outbox_message};
use mvm_core::util::atomic_io::{atomic_write_new, sync_dir};

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

/// Owner-only read/write. Nobody else may read the plaintext.
pub const OUTBOX_FILE_MODE: u32 = 0o600;

/// The recipient and stable message ID beside the largest body the host seals.
const MAX_OUTBOX_BYTES: u64 = MAX_MAILBOX_PAYLOAD_BYTES as u64 + 64;
const MAX_ARCHIVED_OUTBOX: usize = 64;
const IDLE_CHECKS: usize = 16;
const IDLE_INTERVAL: Duration = Duration::from_millis(250);

/// Wait at most four seconds for a later workload write on an already
/// connected mailbox port. The host's read deadline is longer than this
/// window; an idle window closes cleanly so teardown is always bounded.
pub fn wait_and_forward_outbox<S: Read + Write>(
    stream: &mut S,
    outbox: &Path,
) -> Result<(), Refusal> {
    for _ in 0..IDLE_CHECKS {
        if outbox.exists() {
            return forward_outbox(stream, outbox);
        }
        std::thread::sleep(IDLE_INTERVAL);
    }
    Err(Refusal::Unavailable)
}

/// Forward one immutable outbox operation over `stream`. A refused or uncertain
/// send leaves it in place for a same-ID retry; only an accepted verdict removes
/// it under the writer lock.
pub fn forward_outbox<S: Read + Write>(stream: &mut S, outbox: &Path) -> Result<(), Refusal> {
    let dir = outbox.parent().ok_or(Refusal::Malformed)?;
    let _lock = lock_outbox_dir(dir)?;
    let mut bytes = Vec::new();
    open_outbox(outbox)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::Malformed)?;
    let message = OutboxMessage::decode(&bytes)?;
    match send_outbox_message(stream, &message) {
        Ok(()) => {}
        Err(refusal @ (Refusal::RetriesExhausted | Refusal::Oversized(_))) => {
            let prefix = if matches!(refusal, Refusal::Oversized(_)) {
                "rejected"
            } else {
                "uncertain"
            };
            archive_outbox(outbox, &message, prefix)?;
            return Err(refusal);
        }
        Err(error) => return Err(error),
    }
    std::fs::remove_file(outbox).map_err(|_| Refusal::Unavailable)?;
    sync_dir(dir).map_err(|_| Refusal::Unavailable)
}

fn archive_outbox(outbox: &Path, message: &OutboxMessage, prefix: &str) -> Result<(), Refusal> {
    let dir = outbox.parent().ok_or(Refusal::Malformed)?;
    let id = message
        .message_id
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let archived = dir.join(format!("{prefix}-{id}"));
    let bytes = message.encode();
    let mut previous = Vec::new();
    match open_outbox(&archived)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut previous))
    {
        Ok(_) if previous != bytes => return Err(Refusal::Malformed),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut count = 0;
            for entry in std::fs::read_dir(dir).map_err(|_| Refusal::Unavailable)? {
                let entry = entry.map_err(|_| Refusal::Unavailable)?;
                if entry.file_name() != "outbox" {
                    count += 1;
                    if count >= MAX_ARCHIVED_OUTBOX {
                        return Err(Refusal::QueueFull(MAX_ARCHIVED_OUTBOX));
                    }
                }
            }
            atomic_write_new(&archived, &bytes).map_err(|_| Refusal::Unavailable)?;
        }
        Err(_) => return Err(Refusal::Unavailable),
    }
    std::fs::remove_file(outbox).map_err(|_| Refusal::Unavailable)?;
    sync_dir(dir).map_err(|_| Refusal::Unavailable)
}

fn lock_outbox_dir(dir: &Path) -> Result<std::fs::File, Refusal> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|_| Refusal::Unavailable)?;
    file.try_lock().map_err(|_| Refusal::Unavailable)?;
    Ok(file)
}

fn open_outbox(outbox: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(outbox)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "outbox must be a single-link regular file",
        ));
    }
    Ok(file)
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

/// Workload side: atomically publish one immutable message. A second writer
/// cannot replace a pending operation; retrying identical bytes is idempotent.
/// The directory must already exist as the launch grant.
pub fn write_outbox(outbox: &Path, message: &OutboxMessage) -> Result<(), Refusal> {
    if message.body.is_empty() {
        return Err(Refusal::Malformed);
    }
    if message.body.len() > MAX_MAILBOX_PAYLOAD_BYTES {
        return Err(Refusal::Oversized(MAX_MAILBOX_PAYLOAD_BYTES));
    }
    let bytes = message.encode();
    // Same validation the host applies on receipt (empty, oversized).
    OutboxMessage::decode(&bytes)?;
    let dir = outbox
        .parent()
        .filter(|d| d.is_dir())
        .ok_or(Refusal::Malformed)?;
    let _lock = lock_outbox_dir(dir)?;
    let mut existing = Vec::new();
    match open_outbox(outbox)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut existing))
    {
        Ok(_) if existing.len() as u64 > MAX_OUTBOX_BYTES => return Err(Refusal::Malformed),
        Ok(_) if existing == bytes => return Ok(()),
        Ok(_) => return Err(Refusal::QueueFull(1)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Refusal::Unavailable),
    }
    atomic_write_new(outbox, &bytes).map_err(|_| Refusal::Unavailable)?;
    sync_dir(dir).map_err(|_| Refusal::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{MessageId, PrincipalId};

    fn message(body: &[u8]) -> OutboxMessage {
        OutboxMessage {
            recipient: PrincipalId::from_bytes([7; 32]),
            message_id: MessageId::from_bytes([8; 32]),
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
        assert!(
            !outbox.exists(),
            "accepted submission frees the single slot"
        );
    }

    #[test]
    fn a_connected_guest_delivers_a_message_written_after_the_host_dials() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":null}").unwrap();
            OutboxMessage::decode(&body).unwrap()
        });
        let written = message(b"later");
        let path = outbox.clone();
        let workload = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            write_outbox(&path, &written).unwrap();
        });
        wait_and_forward_outbox(&mut ours, &outbox).expect("late write was forwarded");
        workload.join().unwrap();
        assert_eq!(host.join().unwrap(), message(b"later"));
        assert!(!outbox.exists());
    }

    #[test]
    fn the_outbox_file_is_owner_only_and_leaves_no_temp() {
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
    fn a_pending_outbox_cannot_be_overwritten_but_an_identical_retry_is_safe() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        write_outbox(&outbox, &message(b"one")).unwrap();
        write_outbox(&outbox, &message(b"one")).unwrap();
        assert_eq!(
            write_outbox(&outbox, &message(b"two")),
            Err(Refusal::QueueFull(1))
        );
        let on_disk = std::fs::read(&outbox).unwrap();
        assert_eq!(OutboxMessage::decode(&on_disk), Ok(message(b"one")));
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

    #[test]
    fn an_unknown_verdict_keeps_the_same_operation_for_a_later_retry() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        write_outbox(&outbox, &message(b"once")).unwrap();
        let original = std::fs::read(&outbox).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            body
        });
        assert_eq!(forward_outbox(&mut ours, &outbox), Err(Refusal::Malformed));
        assert_eq!(host.join().unwrap(), original);
        assert_eq!(std::fs::read(&outbox).unwrap(), original);
        write_outbox(&outbox, &message(b"once")).expect("same-ID retry stays valid");
    }

    #[test]
    fn exhausted_retries_preserve_an_uncertain_operation_without_blocking_new_sends() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let pending = message(b"once");
        write_outbox(&outbox, &pending).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Err\":\"RetriesExhausted\"}").unwrap();
        });
        assert_eq!(
            forward_outbox(&mut ours, &outbox),
            Err(Refusal::RetriesExhausted)
        );
        host.join().unwrap();
        assert!(
            !outbox.exists(),
            "the next operation can use the single slot"
        );
        let uncertain = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .next()
            .expect("an uncertain operation is retained");
        assert_eq!(
            OutboxMessage::decode(&std::fs::read(uncertain).unwrap()),
            Ok(pending)
        );
        write_outbox(&outbox, &message(b"next")).unwrap();
    }

    #[test]
    fn a_signed_capability_payload_refusal_archives_the_exact_rejected_operation() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let pending = message(b"too large for this grant");
        write_outbox(&outbox, &pending).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Err\":{\"Oversized\":16}}").unwrap();
        });
        assert_eq!(
            forward_outbox(&mut ours, &outbox),
            Err(Refusal::Oversized(16))
        );
        host.join().unwrap();
        assert!(!outbox.exists());
        let rejected = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .next()
            .expect("retain terminal refusal");
        assert!(
            rejected
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("rejected-"),
            "a known terminal refusal is not an uncertain delivery"
        );
        assert_eq!(
            OutboxMessage::decode(&std::fs::read(rejected).unwrap()),
            Ok(pending)
        );
    }

    #[test]
    fn archive_exhaustion_retains_pending_bytes_and_refuses_more_disk_use() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let pending = message(b"once");
        write_outbox(&outbox, &pending).unwrap();
        for i in 0..MAX_ARCHIVED_OUTBOX {
            std::fs::write(dir.path().join(format!("uncertain-{i}")), b"old").unwrap();
        }
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Err\":\"RetriesExhausted\"}").unwrap();
        });
        assert_eq!(
            forward_outbox(&mut ours, &outbox),
            Err(Refusal::QueueFull(MAX_ARCHIVED_OUTBOX))
        );
        host.join().unwrap();
        assert_eq!(
            OutboxMessage::decode(&std::fs::read(&outbox).unwrap()),
            Ok(pending)
        );
    }

    #[test]
    fn an_outbox_symlink_is_never_followed_to_a_different_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("other");
        let outbox = dir.path().join("outbox");
        std::fs::write(&secret, message(b"secret").encode()).unwrap();
        std::os::unix::fs::symlink(&secret, &outbox).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(forward_outbox(&mut ours, &outbox), Err(Refusal::Malformed));
        assert_eq!(
            write_outbox(&outbox, &message(b"overwrite")),
            Err(Refusal::Unavailable)
        );
        drop(ours);
        let mut seen = Vec::new();
        theirs.read_to_end(&mut seen).unwrap();
        assert!(seen.is_empty());
        assert_eq!(std::fs::read(secret).unwrap(), message(b"secret").encode());
    }

    /// The wire carries the plaintext message and nothing else: no
    /// capability, envelope, signature or key, and this path names no key
    /// type to build one from.
    #[test]
    fn the_frame_on_the_wire_is_exactly_the_plaintext_message() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let message = [&[9u8; 32][..], &[10u8; 32][..], b"hello"].concat();
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
