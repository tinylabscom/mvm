//! Guest side of the mailbox port: when the host dials it, send the oldest
//! plaintext message the workload left in the outbox, consume it, and return
//! the host's verdict.
//!
//! The guest holds no key and seals nothing. The outbox carries a recipient
//! (`OWN_MAILBOX_RECIPIENT` or the mailbox id, which the host maps to the
//! recipient its policy names) and a body; the host seals and signs it under the capability the signed
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

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use mvm_contract::protocol::mailbox::MAX_MAILBOX_PAYLOAD_BYTES;
use mvm_core::mailbox::frame::{OutboxMessage, Refusal, send_outbox_message};

/// The spool directory the workload writes and the agent drains. It lives
/// inside the directory [`provision_outbox_dir`] creates.
pub const OUTBOX_PATH: &str = "/run/mvm/mailbox/outbox";

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

/// Owner read/write, group read. Nobody else may read the plaintext.
pub const OUTBOX_FILE_MODE: u32 = 0o640;

/// The recipient bytes beside the largest body the host will seal.
const MAX_OUTBOX_BYTES: u64 = MAX_MAILBOX_PAYLOAD_BYTES as u64 + 32;

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

/// Forward the oldest spooled message over `stream` and consume it, whatever
/// the verdict, so a bad frame cannot wedge the spool and the next dial sees
/// the next message. An empty spool, or an oversized or malformed message, is
/// refused here, before a byte is sent to the host.
///
/// The one verdict that keeps the message is [`Refusal::QueueFull`]: the host's
/// queue has no room yet, so the message stays at the head of the spool for the
/// next dial, in order, and nothing is lost. The writer meets the limit at the
/// spool instead ([`write_outbox`]).
pub fn forward_outbox<S: Read + Write>(stream: &mut S, spool: &Path) -> Result<(), Refusal> {
    let oldest = spooled(spool)
        .map_err(|_| Refusal::Malformed)?
        .into_iter()
        .next()
        .ok_or(Refusal::Malformed)?;
    let mut bytes = Vec::new();
    let read = std::fs::File::open(&oldest)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut bytes));
    let verdict = read
        .map_err(|_| Refusal::Malformed)
        .and_then(|_| OutboxMessage::decode(&bytes))
        .and_then(|message| send_outbox_message(stream, &message));
    if !matches!(verdict, Err(Refusal::QueueFull(_))) {
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
    use mvm_contract::protocol::mailbox::PrincipalId;

    fn message(body: &[u8]) -> OutboxMessage {
        OutboxMessage {
            recipient: PrincipalId::from_bytes([7; 32]),
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
    }

    #[test]
    fn a_forwarded_outbox_is_consumed_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        write_outbox(outbox, &message(b"one")).unwrap();
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(theirs); // hangs up without a verdict; the frame is still consumed
        let _ = forward_outbox(&mut ours, outbox);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert_eq!(forward_outbox(&mut ours, outbox), Err(Refusal::Malformed));
    }

    #[test]
    fn the_outbox_file_is_group_readable_never_world_readable_and_leaves_no_temp() {
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

    /// The wire carries the plaintext message and nothing else: no
    /// capability, envelope, signature or key, and this path names no key
    /// type to build one from.
    #[test]
    fn the_frame_on_the_wire_is_exactly_the_plaintext_message() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path();
        let message = [&[9u8; 32][..], b"hello"].concat();
        std::fs::write(outbox.join("1"), &message).unwrap();
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
        assert_eq!(forward_outbox(&mut ours, outbox), Ok(()));
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
