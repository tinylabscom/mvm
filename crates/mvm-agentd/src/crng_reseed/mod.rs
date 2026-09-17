//! Immediate kernel CRNG reseed for a restored guest.
//!
//! Writing to `/dev/urandom` only mixes bytes into the kernel's input pool. The
//! generator behind `getrandom` keeps its key until the kernel's own reseed
//! schedule folds the pool in, which on a settled system can take a minute, so
//! two clones restored from one memory image return identical output until
//! then. `RNDRESEEDCRNG` rekeys the generator from the pool at once — including
//! the vDSO fast path, which watches the same generation counter — but it needs
//! `CAP_SYS_ADMIN`, and the agent deliberately does not hold that.
//!
//! So the capability lives in a separate process that does exactly one thing:
//! take a generation token, add it to the pool with `RNDADDENTROPY`, force the
//! reseed with `RNDRESEEDCRNG`, and answer with the outcome. It runs under its
//! own uid ([`crate::guest_mount::CRNG_RESEED_HELPER_UID`]), non-dumpable, with
//! a seccomp allowlist, and it is started by whatever is still root in the
//! guest, never by the unprivileged agent:
//!
//! - when the agent is PID 1, by PID 1 itself before it drops privilege, over a
//!   socket pair whose other end the agent keeps;
//! - under a shell init, by that init, listening on [`HELPER_SOCKET`]. The agent
//!   checks the peer's uid before trusting a reply.
//!
//! Either way the agent's own capability sets never contain `CAP_SYS_ADMIN`. A
//! compromised agent can make the helper reseed more often, and nothing else.
//! A guest that has no helper, or whose helper fails, reports that it did not
//! reseed, and the host refuses to treat it as a fresh clone.

mod helper;
mod protocol;

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

use mvm_core::crypto::vmgenid::GENID_BYTES;

#[cfg(target_os = "linux")]
pub use helper::{HelperSpawn, start_helper};
pub use helper::{HelperTransport, helper_transport, run_helper};
pub use protocol::{KernelEntropy, ReseedStep, reseed_with, serve, serve_connections};

use crate::genid::ReseedFailure;
use crate::vsock::ReseedShortfall;

/// First argument that makes the agent binary run as the reseed helper.
pub const HELPER_ARG: &str = "--crng-reseed-helper";

/// Second argument that makes the helper listen on [`HELPER_SOCKET`] instead
/// of serving an inherited socket pair.
pub const LISTEN_ARG: &str = "--listen";

/// Descriptor the helper finds its end of the socket pair on.
pub const HELPER_FD: i32 = 3;

/// Where a helper started by a shell init listens. The init makes the
/// directory owned by the helper uid and the agent's group, mode 0750, and the
/// helper makes the socket 0660, so only the agent's group can connect.
pub const HELPER_SOCKET: &str = "/run/mvm/crng-reseed/helper.sock";

/// How long one read or write to the helper may block. A reseed is two short
/// syscalls; anything near this long means the helper is stuck or gone.
const HELPER_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a restore reseed did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ReseedError {
    /// No helper was started in this guest.
    #[error("no CRNG reseed helper is running in this guest")]
    NoHelper,
    /// Something other than the helper answered on the helper's socket.
    #[error("the CRNG reseed socket is served by uid {uid}, not the reseed helper")]
    UntrustedHelper {
        /// The uid the peer runs as.
        uid: u32,
    },
    /// The helper did not answer.
    #[error("CRNG reseed helper did not answer: {0}")]
    Transport(#[source] io::Error),
    /// The helper answered with something that is not a reply to this request.
    #[error("CRNG reseed helper sent a malformed reply")]
    MalformedReply,
    /// The helper ran and the kernel refused one of the steps.
    #[error("{step} failed: {source}")]
    Kernel {
        /// The step that failed.
        step: ReseedStep,
        /// The kernel's error.
        #[source]
        source: io::Error,
    },
}

impl From<ReseedError> for ReseedFailure {
    fn from(error: ReseedError) -> Self {
        let shortfall = match error {
            ReseedError::NoHelper => ReseedShortfall::HelperMissing,
            _ => ReseedShortfall::Failed,
        };
        ReseedFailure {
            shortfall,
            reason: error.to_string(),
        }
    }
}

/// A connection to the helper that outlives a timeout.
///
/// Replies are read into a buffer and matched to requests by id, so a reply the
/// agent stopped waiting for is recognised and dropped when it finally arrives,
/// and a read cut off by a timeout loses no bytes.
pub struct HelperConnection<S> {
    stream: S,
    next_id: u64,
    received: Vec<u8>,
}

impl<S: Read + Write> HelperConnection<S> {
    /// Wrap a connected stream. Timeouts, if any, are the stream's own.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            next_id: 1,
            received: Vec::new(),
        }
    }

    /// Ask the helper to reseed from `token` and wait for its answer.
    ///
    /// Requests are 24 bytes, far below a socket's send buffer, so a write is
    /// only ever cut short if the helper has stopped reading altogether.
    pub fn reseed(&mut self, token: &[u8; GENID_BYTES]) -> Result<(), ReseedError> {
        let id = self.next_id;
        self.next_id += 1;
        self.stream
            .write_all(&protocol::encode_request(id, token))
            .map_err(ReseedError::Transport)?;
        self.stream.flush().map_err(ReseedError::Transport)?;
        loop {
            while self.received.len() >= protocol::REPLY_BYTES {
                let mut frame = [0u8; protocol::REPLY_BYTES];
                frame.copy_from_slice(&self.received[..protocol::REPLY_BYTES]);
                self.received.drain(..protocol::REPLY_BYTES);
                let reply = protocol::decode_reply(&frame).ok_or(ReseedError::MalformedReply)?;
                if reply.id < id {
                    // The answer to a request this connection already gave up on.
                    continue;
                }
                if reply.id > id {
                    return Err(ReseedError::MalformedReply);
                }
                return reply.outcome.map_err(|(step, errno)| ReseedError::Kernel {
                    step,
                    source: io::Error::from_raw_os_error(errno),
                });
            }
            let mut buf = [0u8; protocol::REPLY_BYTES * 4];
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    return Err(ReseedError::Transport(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the reseed helper closed its connection",
                    )));
                }
                Ok(n) => self.received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(ReseedError::Transport(e)),
            }
        }
    }
}

/// How this agent reaches its helper.
pub enum HelperLink<S> {
    /// PID 1 started a helper over a socket pair. The pair is the only way to
    /// reach it, so it is kept across every error and never replaced.
    Pair(HelperConnection<S>),
    /// A shell init may have started a listening helper; connect on demand.
    Listening(Option<HelperConnection<S>>),
}

/// The agent's link to its helper.
static HELPER: Mutex<HelperLink<UnixStream>> = Mutex::new(HelperLink::Listening(None));

/// Keep `stream` as the socket pair to this guest's helper.
pub fn install_helper(stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(HELPER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(HELPER_IO_TIMEOUT))?;
    *HELPER.lock().unwrap_or_else(|e| e.into_inner()) =
        HelperLink::Pair(HelperConnection::new(stream));
    Ok(())
}

/// Reseed through this guest's helper.
pub fn reseed_via_helper(token: &[u8; GENID_BYTES]) -> Result<(), ReseedFailure> {
    let mut link = HELPER.lock().unwrap_or_else(|e| e.into_inner());
    reseed_through(&mut link, connect_to_listening_helper, token).map_err(ReseedFailure::from)
}

/// Send one request over `link`.
///
/// A socket pair is used as it is: no error replaces it, and there is nothing
/// to connect to. A listening helper is connected to on first use; a connection
/// the helper closed is dropped so the next restore connects again, while a
/// timeout keeps it, because the late reply will be matched and discarded.
pub fn reseed_through<S: Read + Write>(
    link: &mut HelperLink<S>,
    connect: impl FnOnce() -> Result<S, ReseedError>,
    token: &[u8; GENID_BYTES],
) -> Result<(), ReseedError> {
    let slot = match link {
        HelperLink::Pair(connection) => return connection.reseed(token),
        HelperLink::Listening(slot) => slot,
    };
    if slot.is_none() {
        *slot = Some(HelperConnection::new(connect()?));
    }
    let Some(connection) = slot.as_mut() else {
        return Err(ReseedError::NoHelper);
    };
    let result = connection.reseed(token);
    if let Err(ReseedError::Transport(error)) = &result
        && helper_went_away(error)
    {
        *slot = None;
    }
    result
}

fn helper_went_away(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

/// Accept `peer_uid` as the helper only if it is the helper's own uid. Guards
/// against another process of the agent's group, or a workload sharing the
/// agent's uid, binding the socket first and answering "reseeded".
pub fn check_helper_peer(peer_uid: u32) -> Result<(), ReseedError> {
    if peer_uid == crate::guest_mount::CRNG_RESEED_HELPER_UID {
        Ok(())
    } else {
        Err(ReseedError::UntrustedHelper { uid: peer_uid })
    }
}

#[cfg(target_os = "linux")]
fn connect_to_listening_helper() -> Result<UnixStream, ReseedError> {
    let stream = UnixStream::connect(HELPER_SOCKET).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ReseedError::NoHelper,
        _ => ReseedError::Transport(error),
    })?;
    check_helper_peer(peer_uid(&stream).map_err(ReseedError::Transport)?)?;
    stream
        .set_read_timeout(Some(HELPER_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(HELPER_IO_TIMEOUT)))
        .map_err(ReseedError::Transport)?;
    Ok(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect_to_listening_helper() -> Result<UnixStream, ReseedError> {
    Err(ReseedError::NoHelper)
}

/// The uid of the process on the other end of `stream`, from `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a correctly sized `ucred` and `len` holds its size; the
    // kernel writes at most that many bytes.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc == 0 {
        Ok(cred.uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::protocol::tests::FakeKernel;
    use super::protocol::{REQUEST_BYTES, encode_reply};
    use super::*;

    const TOKEN: [u8; GENID_BYTES] = [7u8; GENID_BYTES];

    /// A stream whose reads are scripted, for the cases a live helper cannot
    /// produce on demand: a late reply, a timeout, a close.
    #[derive(Default)]
    struct ScriptedStream {
        reads: VecDeque<io::Result<Vec<u8>>>,
        written: Vec<u8>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Some(Err(e)) => Err(e),
                Some(Ok(bytes)) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    if n < bytes.len() {
                        self.reads.push_front(Ok(bytes[n..].to_vec()));
                    }
                    Ok(n)
                }
            }
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn ok_reply(id: u64) -> Vec<u8> {
        encode_reply(id, &Ok(())).to_vec()
    }

    #[test]
    fn a_late_reply_is_discarded_instead_of_answering_the_next_request() {
        let mut stream = ScriptedStream::default();
        // Request 1 times out. Its failure reply then arrives just before the
        // reply to request 2.
        stream
            .reads
            .push_back(Err(io::Error::from(io::ErrorKind::WouldBlock)));
        let late_failure = encode_reply(
            1,
            &Err((
                ReseedStep::ForceReseed,
                io::Error::from_raw_os_error(libc::EPERM),
            )),
        );
        stream.reads.push_back(Ok(late_failure.to_vec()));
        stream.reads.push_back(Ok(ok_reply(2)));

        let mut connection = HelperConnection::new(stream);
        assert!(matches!(
            connection.reseed(&TOKEN),
            Err(ReseedError::Transport(_))
        ));
        connection
            .reseed(&TOKEN)
            .expect("the second request is answered by its own reply, not the late one");
        assert_eq!(connection.stream.written.len(), 2 * REQUEST_BYTES);
    }

    #[test]
    fn a_reply_split_by_a_timeout_is_reassembled() {
        let reply = ok_reply(1);
        let mut stream = ScriptedStream::default();
        stream.reads.push_back(Ok(reply[..5].to_vec()));
        stream
            .reads
            .push_back(Err(io::Error::from(io::ErrorKind::TimedOut)));
        stream.reads.push_back(Ok(reply[5..].to_vec()));
        stream.reads.push_back(Ok(ok_reply(2)));

        let mut connection = HelperConnection::new(stream);
        assert!(
            connection.reseed(&TOKEN).is_err(),
            "the first read timed out"
        );
        connection
            .reseed(&TOKEN)
            .expect("the bytes read before the timeout were kept");
    }

    #[test]
    fn a_reply_to_a_request_not_yet_sent_is_malformed() {
        let mut stream = ScriptedStream::default();
        stream.reads.push_back(Ok(ok_reply(7)));
        let mut connection = HelperConnection::new(stream);
        assert!(matches!(
            connection.reseed(&TOKEN),
            Err(ReseedError::MalformedReply)
        ));
    }

    #[test]
    fn a_socket_pair_is_kept_across_every_error_and_never_replaced() {
        let mut stream = ScriptedStream::default();
        stream.reads.push_back(Ok(Vec::new())); // helper closed
        stream
            .reads
            .push_back(Err(io::Error::from(io::ErrorKind::TimedOut)));
        stream.reads.push_back(Ok(ok_reply(3)));
        let mut link = HelperLink::Pair(HelperConnection::new(stream));
        let never = || -> Result<ScriptedStream, ReseedError> {
            panic!("a guest with a socket pair must not look for a listening helper")
        };
        assert!(reseed_through(&mut link, never, &TOKEN).is_err());
        assert!(reseed_through(&mut link, never, &TOKEN).is_err());
        reseed_through(&mut link, never, &TOKEN).expect("the pair recovers");
        assert!(matches!(link, HelperLink::Pair(_)));
    }

    #[test]
    fn a_guest_without_a_helper_reports_that_rather_than_success() {
        let mut link: HelperLink<ScriptedStream> = HelperLink::Listening(None);
        let absent = || Err(ReseedError::NoHelper);
        assert!(matches!(
            reseed_through(&mut link, absent, &TOKEN),
            Err(ReseedError::NoHelper)
        ));
        assert!(matches!(link, HelperLink::Listening(None)));
        assert_eq!(
            ReseedFailure::from(ReseedError::NoHelper).shortfall,
            ReseedShortfall::HelperMissing
        );
    }

    #[test]
    fn a_listening_helper_that_closed_is_reconnected_but_a_timeout_is_not() {
        let mut timed_out = ScriptedStream::default();
        timed_out
            .reads
            .push_back(Err(io::Error::from(io::ErrorKind::WouldBlock)));
        let mut link = HelperLink::Listening(None);
        let _ = reseed_through(&mut link, || Ok(timed_out), &TOKEN);
        assert!(
            matches!(link, HelperLink::Listening(Some(_))),
            "a timeout keeps the connection for the late reply"
        );

        let mut closed = ScriptedStream::default();
        closed.reads.push_back(Ok(Vec::new()));
        let mut link = HelperLink::Listening(None);
        let _ = reseed_through(&mut link, || Ok(closed), &TOKEN);
        assert!(
            matches!(link, HelperLink::Listening(None)),
            "a closed connection is dropped so the next restore reconnects"
        );
    }

    #[test]
    fn only_the_helper_uid_is_trusted_on_the_helper_socket() {
        check_helper_peer(crate::guest_mount::CRNG_RESEED_HELPER_UID).expect("the helper");
        for impostor in [0, crate::guest_mount::WORKLOAD_UID, 990, 1000] {
            let error = check_helper_peer(impostor).unwrap_err();
            assert!(matches!(error, ReseedError::UntrustedHelper { uid } if uid == impostor));
            assert_eq!(
                ReseedFailure::from(error).shortfall,
                ReseedShortfall::Failed,
                "an impostor is a failure, not a missing helper"
            );
        }
    }

    /// A listening helper end to end over a real socket: connect on first use,
    /// reconnect after the connection is lost.
    #[test]
    fn a_listening_helper_is_reached_by_connecting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let mut kernel = FakeKernel::default();
            serve_connections(listener.incoming().take(2), &mut kernel);
            kernel
        });

        let connect = || UnixStream::connect(&path).map_err(ReseedError::Transport);
        let mut link = HelperLink::Listening(None);
        reseed_through(&mut link, connect, &[1u8; GENID_BYTES]).expect("first reseed connects");
        assert!(matches!(link, HelperLink::Listening(Some(_))));

        link = HelperLink::Listening(None);
        reseed_through(&mut link, connect, &[2u8; GENID_BYTES]).expect("reconnects");
        drop(link);

        let kernel = server.join().expect("helper thread");
        assert_eq!(
            kernel.calls,
            vec!["add 1 credit 128", "reseed", "add 2 credit 128", "reseed"]
        );
    }
}
