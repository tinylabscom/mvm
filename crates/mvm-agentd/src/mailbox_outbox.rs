//! Guest side of the mailbox port: when the host dials it, send the oldest
//! plaintext message the workload left in the outbox, consume it, and return
//! the host's verdict.
//!
//! The guest holds no key and seals nothing. The outbox carries a stable
//! message ID, recipient (`OWN_MAILBOX_RECIPIENT` or mailbox ID for its own
//! mailbox), and body; the host seals and signs under the capability the signed
//! plan granted, then admits it. Encryption is host to host.
//!
//! The outbox is a spool directory ([`OUTBOX_PATH`]): one file per message,
//! named so that lexicographic order is write order. [`write_outbox`] is the
//! workload side; it adds one file atomically and refuses when the spool holds
//! [`MAX_SPOOLED_MESSAGES`]. [`forward_outbox`] sends the oldest file per host
//! dial and unlinks it. Dot-prefixed names are writers' temp files and are
//! never forwarded. Both sides use the same [`OutboxMessage`] encoding and
//! size limits the host decodes with. The shell recipe is the same: write a
//! dot-prefixed temp file in the spool, then `mv` it to a name that sorts after
//! every earlier one.
//! `outbox-local` is a separate, single-operation request that is removed only
//! after [`forward_local_outbox`] verifies a boot-bound signed V2 receipt.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MAX_MAILBOX_PAYLOAD_BYTES, MailboxId, SignedDestinationReceipt,
};
use mvm_core::mailbox::frame::{
    OutboxMessage, Refusal, send_local_outbox_message, send_outbox_message,
};
use mvm_core::util::atomic_io::{atomic_write_new, sync_dir};

/// The spool directory the workload writes and the agent drains. It lives
/// inside the directory [`provision_outbox_dir`] creates.
pub const OUTBOX_PATH: &str = "/run/mvm/mailbox/outbox";
/// An explicit local-durable request never accepts the older unit-verdict wire.
pub const LOCAL_OUTBOX_PATH: &str = "/run/mvm/mailbox/outbox-local";

/// How many messages the spool holds before a writer is told it is full.
pub const MAX_SPOOLED_MESSAGES: usize = 256;

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

/// Forward one spool entry, or a legacy single-file outbox operation.
pub fn forward_outbox<S: Read + Write>(stream: &mut S, outbox: &Path) -> Result<(), Refusal> {
    if outbox.is_dir() {
        forward_spooled(stream, outbox)
    } else {
        forward_with(stream, outbox, send_outbox_message)
    }
}

/// Keep a local-durable request pending until a signed V2 receipt is verified.
pub fn forward_local_outbox<S: Read + Write>(
    stream: &mut S,
    outbox: &Path,
    authority: &VerifyingKey,
    mailbox: MailboxId,
    epoch: ExecutionEpoch,
) -> Result<SignedDestinationReceipt, Refusal> {
    forward_with(stream, outbox, |stream, message| {
        send_local_outbox_message(stream, message, authority, mailbox, epoch)
    })
}

fn forward_with<S: Read + Write, R>(
    stream: &mut S,
    outbox: &Path,
    send: impl FnOnce(&mut S, &OutboxMessage) -> Result<R, Refusal>,
) -> Result<R, Refusal> {
    let dir = outbox.parent().ok_or(Refusal::Malformed)?;
    let _lock = lock_outbox_dir(dir)?;
    let mut bytes = Vec::new();
    open_outbox(outbox)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::Malformed)?;
    let message = OutboxMessage::decode(&bytes)?;
    let accepted = match send(stream, &message) {
        Ok(accepted) => accepted,
        Err(
            refusal @ (Refusal::RetriesExhausted
            | Refusal::Oversized(_)
            | Refusal::NotAuthorized
            | Refusal::Expired),
        ) => {
            let prefix = if matches!(
                refusal,
                Refusal::Oversized(_) | Refusal::NotAuthorized | Refusal::Expired
            ) {
                "rejected"
            } else {
                "uncertain"
            };
            archive_outbox(outbox, &message, prefix)?;
            return Err(refusal);
        }
        Err(error) => return Err(error),
    };
    std::fs::remove_file(outbox).map_err(|_| Refusal::Unavailable)?;
    sync_dir(dir).map_err(|_| Refusal::Unavailable)?;
    Ok(accepted)
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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

/// How long a host may stall a mailbox connection, in either direction,
/// before the agent drops it and serves the next dial.
pub const MAILBOX_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Bound every read and write on the socket `fd` to `timeout`, so a peer that
/// stalls fails the exchange instead of blocking the agent's one listener.
pub fn bound_socket_io(
    fd: std::os::fd::RawFd,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: `tv` outlives the call and the length is its exact size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&raw const tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// How long the agent holds a host connection open waiting for the workload to
/// write a message, before answering with nothing so the host dials again.
/// One long hold replaces a dial every couple of seconds on an idle guest.
pub const MAILBOX_HOLD: std::time::Duration = std::time::Duration::from_secs(120);

/// Wait up to `hold` for the spool to hold a message, checking every `tick`.
/// Stops early, returning `false`, when `abandoned` says the host went away or
/// the agent is shutting down; returns `true` as soon as a message is spooled.
pub fn wait_for_outbox(
    spool: &Path,
    hold: std::time::Duration,
    tick: std::time::Duration,
    mut abandoned: impl FnMut() -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + hold;
    loop {
        if spooled(spool).is_ok_and(|files| !files.is_empty()) {
            return true;
        }
        if abandoned() || std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(tick);
    }
}

/// Whether the peer of the connected socket `fd` has hung up or sent bytes.
/// The host sends nothing before the agent answers, so either means the
/// connection is no longer a live request.
pub fn peer_gone(fd: std::os::fd::RawFd) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `p` is one valid pollfd and the count is 1; a zero timeout never blocks.
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    rc > 0 && p.revents != 0
}

/// The spooled message files, oldest first. Temp files are skipped.
fn spooled(spool: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(spool)? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b".") {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// Forward the oldest spooled message. A malformed local frame is discarded
/// so it cannot wedge the spool; an uncertain host verdict keeps the original
/// operation for a same-ID retry. A signed V2 reply cannot be mistaken for the
/// legacy unit verdict and silently delete a production request.
fn forward_spooled<S: Read + Write>(stream: &mut S, spool: &Path) -> Result<(), Refusal> {
    let oldest = spooled(spool)
        .map_err(|_| Refusal::Malformed)?
        .into_iter()
        .next()
        .ok_or(Refusal::Malformed)?;
    let mut bytes = Vec::new();
    let read = open_outbox(&oldest)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut bytes));
    let message = read
        .map_err(|_| Refusal::Malformed)
        .and_then(|_| OutboxMessage::decode(&bytes));
    let message = match message {
        Ok(message) => message,
        Err(refusal) => {
            let _ = std::fs::remove_file(&oldest);
            return Err(refusal);
        }
    };
    let verdict = send_outbox_message(stream, &message);
    if matches!(
        verdict,
        Ok(())
            | Err(Refusal::NotAuthorized
                | Refusal::Expired
                | Refusal::Oversized(_)
                | Refusal::Mailbox(_))
    ) {
        let _ = std::fs::remove_file(&oldest);
    }
    verdict
}

/// Create the outbox directory and the spool inside it, both owned by
/// `uid`:`gid` at [`OUTBOX_DIR_MODE`]. Idempotent. The caller must hold root to chown to another identity, and
/// must call this only on a boot that asserts [`MAILBOX_CMDLINE_TOKEN`].
pub fn provision_outbox_dir(dir: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for d in [dir.to_path_buf(), dir.join("outbox")] {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(OUTBOX_DIR_MODE)
            .create(&d)?;
        // The mode above is subject to the umask and skipped when the directory exists.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(OUTBOX_DIR_MODE))?;
        std::os::unix::fs::chown(&d, Some(uid), Some(gid))?;
    }
    Ok(())
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

/// Workload side: atomically add `message` to the spool at `spool`. The
/// directory must already exist, since it is how the launch grants a mailbox;
/// without it this refuses and creates nothing. Written to a dot-prefixed temp
/// file in the spool, then renamed to `<unix_nanos>-<pid>-<counter>`, so the
/// agent never reads a partial frame and messages are delivered in write order.
/// A spool already holding [`MAX_SPOOLED_MESSAGES`] refuses with
/// [`Refusal::QueueFull`] rather than dropping anything.
pub fn write_outbox(spool: &Path, message: &OutboxMessage) -> Result<(), Refusal> {
    if spool.is_dir() {
        return write_spooled(spool, message);
    }
    if !matches!(
        spool.file_name().and_then(std::ffi::OsStr::to_str),
        Some("outbox" | "outbox-local")
    ) {
        return Err(Refusal::Malformed);
    }
    write_single_outbox(spool, message)
}

/// A single-file source request is immutable across retries, unlike the
/// ephemeral spool. It can only be replaced after a verified local receipt.
fn write_single_outbox(outbox: &Path, message: &OutboxMessage) -> Result<(), Refusal> {
    let bytes = message.encode();
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

fn write_spooled(spool: &Path, message: &OutboxMessage) -> Result<(), Refusal> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let bytes = message.encode();
    // Same validation the host applies on receipt (empty, oversized).
    OutboxMessage::decode(&bytes)?;
    if !spool.is_dir() {
        return Err(Refusal::Malformed);
    }
    if spooled(spool).map_err(|_| Refusal::Malformed)?.len() >= MAX_SPOOLED_MESSAGES {
        return Err(Refusal::QueueFull(MAX_SPOOLED_MESSAGES));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let name = format!(
        "{nanos:020}-{:010}-{:010}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let tmp = spool.join(format!(".{name}.tmp"));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OUTBOX_FILE_MODE)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&bytes))
        .and_then(|()| std::fs::rename(&tmp, spool.join(&name)));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Refusal::Malformed);
    }
    Ok(())
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
    fn a_peer_that_never_answers_fails_the_forward_within_the_bound() {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        write_outbox(outbox, &message(b"one")).unwrap();
        let (mut ours, _silent_but_open) = std::os::unix::net::UnixStream::pair().unwrap();
        bound_socket_io(ours.as_raw_fd(), std::time::Duration::from_secs(1)).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(forward_outbox(&mut ours, outbox), Err(Refusal::Malformed));
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(
            spooled(outbox).unwrap().len(),
            1,
            "unknown reply retains the operation"
        );
    }

    #[test]
    fn a_written_outbox_is_forwarded_as_the_same_message() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        write_outbox(outbox, &message(b"hello")).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        theirs
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":null}").unwrap();
            body
        });
        forward_outbox(&mut ours, outbox).unwrap();
        // The host decoder (serve_guest uses OutboxMessage::decode) gets it back.
        assert_eq!(
            OutboxMessage::decode(&host.join().unwrap()),
            Ok(message(b"hello"))
        );
        assert!(
            std::fs::read_dir(outbox).unwrap().next().is_none(),
            "accepted submission frees the spool entry"
        );
    }

    #[test]
    fn local_outbox_is_retained_until_a_signed_v2_receipt_arrives() {
        use ed25519_dalek::SigningKey;
        use mvm_contract::protocol::mailbox::{
            AuthorizationDomainId, DeliveryId, DeliveryOutcome, DestinationReceipt, MailboxAddress,
            ProtocolVersion, SignatureAlgorithm, TenantId,
        };
        use mvm_core::mailbox::sign_receipt;

        let dir = tempfile::tempdir().expect("private guest outbox");
        let path = dir.path().join("outbox-local");
        let operation = message(b"report");
        write_outbox(&path, &operation).expect("retain original operation");
        let signer = SigningKey::from_bytes(&[10; 32]);
        let mailbox = MailboxId::from_bytes([9; 32]);
        let epoch = ExecutionEpoch::new(1).expect("epoch");
        let signed = sign_receipt(
            DestinationReceipt {
                protocol_version: ProtocolVersion::V2,
                signature_algorithm: SignatureAlgorithm::ED25519,
                delivery_id: DeliveryId::from_bytes([11; 32]),
                message_id: operation.message_id,
                address: MailboxAddress {
                    tenant: TenantId::from_bytes([12; 32]),
                    authorization_domain: AuthorizationDomainId::from_bytes([13; 32]),
                    mailbox,
                    recipient: operation.recipient,
                },
                execution_epoch: epoch,
                outcome: DeliveryOutcome::AcceptedLocalDurable,
                observed_at_unix_ms: 1_500,
                ciphertext_commitment: [14; 32],
            },
            &signer,
        )
        .expect("signed local verdict");
        let exchange = |reply: Vec<u8>| {
            let (mut guest, mut host) = std::os::unix::net::UnixStream::pair().expect("socket");
            let peer = std::thread::spawn(move || {
                let mut len = [0; 4];
                host.read_exact(&mut len).expect("outbox length");
                let mut body = vec![0; u32::from_be_bytes(len) as usize];
                host.read_exact(&mut body).expect("outbox operation");
                host.write_all(&reply).expect("host verdict");
                OutboxMessage::decode(&body).expect("original operation")
            });
            let result =
                forward_local_outbox(&mut guest, &path, &signer.verifying_key(), mailbox, epoch);
            assert_eq!(peer.join().expect("host thread"), operation);
            result
        };
        assert_eq!(
            exchange(b"{\"Ok\":null}".to_vec()),
            Err(Refusal::Malformed),
            "an untyped transport success cannot remove a durable request"
        );
        assert!(path.exists(), "uncertain operation retains its stable ID");
        assert_eq!(
            exchange(
                serde_json::to_vec(&Ok::<_, Refusal>(signed.clone())).expect("V2 receipt wire")
            ),
            Ok(signed)
        );
        assert!(
            !path.exists(),
            "only verified acceptance removes the outbox"
        );
        write_outbox(&path, &operation).expect("another local attempt");
        assert_eq!(
            exchange(serde_json::to_vec(&Err::<(), _>(Refusal::Expired)).expect("expired verdict")),
            Err(Refusal::Expired)
        );
        assert!(!path.exists(), "terminal expiry leaves no pending retry");
        let archived = dir.path().join(format!("rejected-{}", "08".repeat(32)));
        assert_eq!(
            std::fs::read(archived).expect("terminal operation archived"),
            operation.encode()
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
    fn a_hung_up_spool_frame_retries_the_same_operation() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        write_outbox(outbox, &message(b"one")).unwrap();
        let original = spooled(outbox).unwrap();
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(theirs);
        assert_eq!(forward_outbox(&mut ours, outbox), Err(Refusal::Malformed));
        assert_eq!(
            spooled(outbox).unwrap(),
            original,
            "lost reply is not acceptance"
        );
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":null}").unwrap();
            OutboxMessage::decode(&body).unwrap()
        });
        assert_eq!(forward_outbox(&mut ours, outbox), Ok(()));
        assert_eq!(host.join().unwrap(), message(b"one"));
        assert!(spooled(outbox).unwrap().is_empty());
    }

    #[test]
    fn an_unexpected_v2_shaped_reply_cannot_discard_a_legacy_spool_entry() {
        let dir = tempfile::tempdir().unwrap();
        write_outbox(dir.path(), &message(b"retain")).unwrap();
        let original = spooled(dir.path()).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":{\"receipt\":{}}}").unwrap();
        });
        assert_eq!(
            forward_outbox(&mut ours, dir.path()),
            Err(Refusal::Malformed)
        );
        host.join().unwrap();
        assert_eq!(spooled(dir.path()).unwrap(), original);
    }

    #[test]
    fn the_outbox_file_is_owner_only_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        write_outbox(outbox, &message(b"x")).unwrap();
        let file = std::fs::read_dir(outbox)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mode = std::fs::metadata(file).unwrap().permissions().mode() & 0o777;
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

    /// Forward every spooled message through a real stream pair, returning the
    /// bodies the host saw and the verdicts, until the spool is empty.
    fn drain(spool: &Path) -> (Vec<OutboxMessage>, Vec<Result<(), Refusal>>) {
        let (mut seen, mut verdicts) = (Vec::new(), Vec::new());
        while std::fs::read_dir(spool).unwrap().next().is_some() {
            let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            let host = std::thread::spawn(move || {
                let mut len = [0u8; 4];
                theirs.read_exact(&mut len).ok()?;
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                theirs.read_exact(&mut body).ok()?;
                theirs.write_all(b"{\"Ok\":null}").unwrap();
                Some(body)
            });
            verdicts.push(forward_outbox(&mut ours, spool));
            drop(ours);
            seen.extend(
                host.join()
                    .unwrap()
                    .map(|b| OutboxMessage::decode(&b).unwrap()),
            );
        }
        (seen, verdicts)
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
    fn back_to_back_writes_are_all_delivered_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let want: Vec<_> = (0..50u32)
            .map(|i| message(format!("m{i}").as_bytes()))
            .collect();
        for m in &want {
            write_outbox(dir.path(), m).unwrap();
        }
        let (seen, verdicts) = drain(dir.path());
        assert_eq!(seen, want);
        assert!(verdicts.iter().all(Result::is_ok));
    }

    #[test]
    fn concurrent_writers_lose_and_duplicate_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let writers: Vec<_> = (0..2)
            .map(|w| {
                let path = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    for i in 0..40 {
                        write_outbox(&path, &message(format!("{w}-{i}").as_bytes())).unwrap();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let (seen, _) = drain(dir.path());
        for w in 0..2 {
            let mine: Vec<_> = seen
                .iter()
                .filter(|m| m.body.starts_with(format!("{w}-").as_bytes()))
                .map(|m| m.body.clone())
                .collect();
            let want: Vec<_> = (0..40).map(|i| format!("{w}-{i}").into_bytes()).collect();
            assert_eq!(mine, want, "writer {w} in order, none lost or repeated");
        }
    }

    #[test]
    fn a_refused_frame_in_the_middle_does_not_wedge_the_spool() {
        let dir = tempfile::tempdir().unwrap();
        write_outbox(dir.path(), &message(b"first")).unwrap();
        let first = spooled(dir.path()).unwrap().remove(0);
        let mut junk = first.clone().into_os_string();
        junk.push("~"); // sorts right after the first, before the third
        std::fs::write(junk, b"junk").unwrap();
        write_outbox(dir.path(), &message(b"third")).unwrap();
        let (seen, verdicts) = drain(dir.path());
        assert_eq!(seen, vec![message(b"first"), message(b"third")]);
        assert_eq!(verdicts[1], Err(Refusal::Malformed));
    }

    #[test]
    fn a_full_spool_refuses_the_writer_and_keeps_what_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..MAX_SPOOLED_MESSAGES {
            write_outbox(dir.path(), &message(b"x")).unwrap();
        }
        assert_eq!(
            write_outbox(dir.path(), &message(b"y")),
            Err(Refusal::QueueFull(MAX_SPOOLED_MESSAGES))
        );
        assert_eq!(drain(dir.path()).0.len(), MAX_SPOOLED_MESSAGES);
    }

    /// A host that answers `QueueFull` for the first `refusals` frames, then
    /// accepts. Returns the bodies it accepted and how many dials it served.
    fn serve_with_full_queue(spool: &Path, refusals: usize) -> (Vec<OutboxMessage>, usize) {
        let (mut accepted, mut dials) = (Vec::new(), 0);
        while std::fs::read_dir(spool).unwrap().next().is_some() {
            let full = dials < refusals;
            dials += 1;
            let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            let host = std::thread::spawn(move || {
                let mut len = [0u8; 4];
                theirs.read_exact(&mut len).unwrap();
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                theirs.read_exact(&mut body).unwrap();
                let verdict: Result<(), Refusal> = if full {
                    Err(Refusal::QueueFull(64))
                } else {
                    Ok(())
                };
                theirs
                    .write_all(&serde_json::to_vec(&verdict).unwrap())
                    .unwrap();
                body
            });
            let verdict = forward_outbox(&mut ours, spool);
            drop(ours);
            let body = host.join().unwrap();
            assert_eq!(verdict.is_err(), full);
            if !full {
                accepted.push(OutboxMessage::decode(&body).unwrap());
            }
        }
        (accepted, dials)
    }

    #[test]
    fn a_frame_the_host_queue_refused_as_full_stays_spooled_and_arrives_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let want: Vec<_> = (0..5u32)
            .map(|i| message(format!("m{i}").as_bytes()))
            .collect();
        for m in &want {
            write_outbox(dir.path(), m).unwrap();
        }
        let (accepted, dials) = serve_with_full_queue(dir.path(), 3);
        assert_eq!(accepted, want, "none lost, none duplicated, order kept");
        assert_eq!(dials, 3 + want.len());
    }

    #[test]
    fn a_permanent_refusal_still_consumes_the_frame() {
        let dir = tempfile::tempdir().unwrap();
        write_outbox(dir.path(), &message(b"bad")).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        theirs
            .write_all(
                &serde_json::to_vec(&Err::<(), _>(Refusal::Mailbox("no send operation".into())))
                    .unwrap(),
            )
            .unwrap();
        drop(theirs);
        assert!(matches!(
            forward_outbox(&mut ours, dir.path()),
            Err(Refusal::Mailbox(_))
        ));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_writers_temp_file_is_never_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".partial.tmp"), message(b"half").encode()).unwrap();
        let (mut ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            forward_outbox(&mut ours, dir.path()),
            Err(Refusal::Malformed)
        );
        assert!(dir.path().join(".partial.tmp").exists());
    }

    #[test]
    fn a_spooled_symlink_is_refused_without_reading_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("outbox");
        std::fs::create_dir(&spool).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, message(b"outside").encode()).unwrap();
        std::os::unix::fs::symlink(&outside, spool.join("0001")).unwrap();
        let (mut ours, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(forward_outbox(&mut ours, &spool), Err(Refusal::Malformed));
        let mut received = [0; 1];
        peer.set_nonblocking(true).unwrap();
        assert!(
            peer.read(&mut received).is_err(),
            "no frame reached the host"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            message(b"outside").encode()
        );
        assert!(spooled(&spool).unwrap().is_empty());
    }

    #[test]
    fn oversized_empty_and_ungranted_writes_are_refused_without_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        let big = message(&vec![1u8; MAX_MAILBOX_PAYLOAD_BYTES + 1]);
        assert!(matches!(
            write_outbox(outbox, &big),
            Err(Refusal::Oversized(_))
        ));
        assert_eq!(write_outbox(outbox, &message(b"")), Err(Refusal::Malformed));
        let at_cap = message(&vec![1u8; MAX_MAILBOX_PAYLOAD_BYTES]);
        write_outbox(outbox, &at_cap).unwrap();
        // No grant: the directory is absent, nothing is created.
        let absent = dir.path().join("nogrant");
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
        let spool = dir.path();
        std::fs::write(spool.join("a"), b"short").unwrap();
        assert_eq!(forward_outbox(&mut ours, spool), Err(Refusal::Malformed));
        std::fs::write(spool.join("b"), vec![1u8; MAX_OUTBOX_BYTES as usize + 8]).unwrap();
        assert!(matches!(
            forward_outbox(&mut ours, spool),
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
    fn an_unauthorized_recipient_is_terminal_without_dropping_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let pending = message(b"wrong recipient");
        write_outbox(&outbox, &pending).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Err\":\"NotAuthorized\"}").unwrap();
        });
        assert_eq!(
            forward_outbox(&mut ours, &outbox),
            Err(Refusal::NotAuthorized)
        );
        host.join().unwrap();
        let archived = dir.path().join(format!(
            "rejected-{}",
            pending
                .message_id
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        assert!(!outbox.exists());
        assert_eq!(std::fs::read(archived).unwrap(), pending.encode());
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
        theirs
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
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
