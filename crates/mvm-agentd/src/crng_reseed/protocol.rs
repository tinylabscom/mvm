//! The request/reply framing between the agent and the reseed helper, and the
//! helper's serve loop.
//!
//! Every request carries an id and every reply echoes it. That is what lets the
//! agent survive a timeout without losing the helper: a reply that arrives after
//! the agent gave up on it is recognised by its id and discarded, instead of
//! being read as the answer to the next request.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use mvm_core::crypto::vmgenid::GENID_BYTES;

/// Request: the id as a little-endian `u64`, then the generation token.
pub const REQUEST_BYTES: usize = 8 + GENID_BYTES;
/// Reply: the echoed id, one status byte, then the errno as a little-endian
/// `i32`.
pub const REPLY_BYTES: usize = 8 + 1 + 4;

const STATUS_OK: u8 = 0;
const STATUS_ADD_ENTROPY_FAILED: u8 = 1;
const STATUS_RESEED_FAILED: u8 = 2;

/// Entropy the token is credited with: all of it. It comes from the host's own
/// generator. Crediting it is what makes the forced reseed take effect on
/// kernels before 5.18, which skip a reseed when fewer than 128 bits are
/// credited.
pub const TOKEN_CREDITED_BITS: u32 = (GENID_BYTES * 8) as u32;

/// The two kernel operations a reseed is made of, behind a trait so the
/// protocol can be exercised without a Linux guest.
pub trait KernelEntropy {
    /// Mix `bytes` into the kernel's input pool, crediting `credited_bits`.
    fn add_entropy(&mut self, bytes: &[u8], credited_bits: u32) -> io::Result<()>;
    /// Rekey the kernel generator from the input pool now.
    fn force_reseed(&mut self) -> io::Result<()>;
}

/// Which half of a reseed failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReseedStep {
    /// Adding the token to the input pool.
    AddEntropy,
    /// Forcing the generator to rekey.
    ForceReseed,
}

impl std::fmt::Display for ReseedStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReseedStep::AddEntropy => "adding the generation token to the input pool",
            ReseedStep::ForceReseed => "forcing the kernel generator to rekey",
        })
    }
}

/// A decoded reply.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    /// The id of the request this answers.
    pub id: u64,
    /// `Ok`, or the step that failed and its errno.
    pub outcome: Result<(), (ReseedStep, i32)>,
}

/// Add the token, then force the generator to rekey. The order matters: a
/// reseed before the add would rekey from a pool that does not yet hold the
/// token, and two clones could still share a key.
pub fn reseed_with(
    entropy: &mut impl KernelEntropy,
    token: &[u8; GENID_BYTES],
) -> Result<(), (ReseedStep, io::Error)> {
    entropy
        .add_entropy(token, TOKEN_CREDITED_BITS)
        .map_err(|e| (ReseedStep::AddEntropy, e))?;
    entropy
        .force_reseed()
        .map_err(|e| (ReseedStep::ForceReseed, e))
}

/// Frame one request.
pub fn encode_request(id: u64, token: &[u8; GENID_BYTES]) -> [u8; REQUEST_BYTES] {
    let mut frame = [0u8; REQUEST_BYTES];
    frame[..8].copy_from_slice(&id.to_le_bytes());
    frame[8..].copy_from_slice(token);
    frame
}

fn decode_request(frame: &[u8; REQUEST_BYTES]) -> (u64, [u8; GENID_BYTES]) {
    let mut id = [0u8; 8];
    id.copy_from_slice(&frame[..8]);
    let mut token = [0u8; GENID_BYTES];
    token.copy_from_slice(&frame[8..]);
    (u64::from_le_bytes(id), token)
}

/// Frame one reply.
pub fn encode_reply(id: u64, result: &Result<(), (ReseedStep, io::Error)>) -> [u8; REPLY_BYTES] {
    let (status, errno) = match result {
        Ok(()) => (STATUS_OK, 0),
        Err((step, error)) => (
            match step {
                ReseedStep::AddEntropy => STATUS_ADD_ENTROPY_FAILED,
                ReseedStep::ForceReseed => STATUS_RESEED_FAILED,
            },
            error.raw_os_error().unwrap_or(libc::EIO),
        ),
    };
    let mut frame = [0u8; REPLY_BYTES];
    frame[..8].copy_from_slice(&id.to_le_bytes());
    frame[8] = status;
    frame[9..].copy_from_slice(&errno.to_le_bytes());
    frame
}

/// Decode one reply frame, or `None` if it is not a well-formed reply.
pub fn decode_reply(frame: &[u8; REPLY_BYTES]) -> Option<Reply> {
    let mut id = [0u8; 8];
    id.copy_from_slice(&frame[..8]);
    let errno = i32::from_le_bytes([frame[9], frame[10], frame[11], frame[12]]);
    let outcome = match (frame[8], errno) {
        (STATUS_OK, 0) => Ok(()),
        (STATUS_ADD_ENTROPY_FAILED, e) if e > 0 => Err((ReseedStep::AddEntropy, e)),
        (STATUS_RESEED_FAILED, e) if e > 0 => Err((ReseedStep::ForceReseed, e)),
        _ => return None,
    };
    Some(Reply {
        id: u64::from_le_bytes(id),
        outcome,
    })
}

/// The helper's loop: one reply per request until the agent closes its end.
///
/// A kernel refusal is an answer, not a reason to stop, and a signal
/// interrupting a read is retried. The loop ends only when the peer is gone: a
/// close between requests is a clean exit, and a close partway through one, or
/// a failed reply, is an error.
pub fn serve(stream: &mut (impl Read + Write), entropy: &mut impl KernelEntropy) -> io::Result<()> {
    loop {
        let mut frame = [0u8; REQUEST_BYTES];
        if !read_frame_or_close(stream, &mut frame)? {
            return Ok(());
        }
        let (id, token) = decode_request(&frame);
        let result = reseed_with(entropy, &token);
        stream.write_all(&encode_reply(id, &result))?;
        stream.flush()?;
    }
}

/// How long a listening helper gives one connection, in total, from the moment
/// it is accepted. The agent writes its request as soon as it connects and the
/// reseed answers at once, so a connection still open after this long is either
/// finished or not the agent; either way it gives way to the next one.
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(1);

/// A connection whose reads and writes can be bounded in time.
pub trait Deadline {
    /// Fail any single read or write that blocks longer than `limit`.
    fn set_deadline(&self, limit: Duration) -> io::Result<()>;
}

impl Deadline for UnixStream {
    fn set_deadline(&self, limit: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(limit))?;
        self.set_write_timeout(Some(limit))
    }
}

/// A connection held to one absolute deadline across all of its reads and
/// writes.
///
/// A socket timeout alone bounds each call, not the connection: a peer that
/// sends one byte just inside every timeout would keep the connection open
/// indefinitely. Before each call the remaining time is computed from the
/// deadline and set as that call's timeout, and once it has run out every call
/// fails with `TimedOut`.
struct Budgeted<S> {
    stream: S,
    until: Instant,
}

impl<S: Deadline> Budgeted<S> {
    fn new(stream: S, budget: Duration) -> Self {
        Self {
            stream,
            until: Instant::now() + budget,
        }
    }

    fn arm(&self) -> io::Result<()> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the connection used up its time",
            ));
        }
        self.stream.set_deadline(remaining)
    }
}

impl<S: Read + Deadline> Read for Budgeted<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.stream.read(buf)
    }
}

impl<S: Write + Deadline> Write for Budgeted<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Serve connections one at a time, each given `budget` in total.
///
/// One at a time means a connection that sends nothing, or sends a byte at a
/// time, would hold every later reseed behind it; the budget is what stops
/// that. A connection that fails, running out of time included, is logged and
/// closed, and the helper keeps accepting. An agent whose connection was
/// dropped this way reconnects.
pub fn serve_connections<S: Read + Write + Deadline>(
    incoming: impl Iterator<Item = io::Result<S>>,
    entropy: &mut impl KernelEntropy,
    budget: Duration,
) {
    for connection in incoming {
        let result =
            connection.and_then(|stream| serve(&mut Budgeted::new(stream, budget), entropy));
        match result {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                eprintln!(
                    "mvm-guest-agent: CRNG reseed helper dropped a connection open past {budget:?}"
                );
            }
            Err(error) => {
                eprintln!("mvm-guest-agent: CRNG reseed helper connection ended: {error}");
            }
        }
    }
}

/// Fill `frame`, or return `false` if the peer closed before sending any of it.
fn read_frame_or_close(stream: &mut impl Read, frame: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < frame.len() {
        match stream.read(&mut frame[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "reseed request cut short",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Records the order of kernel calls and fails the step it is told to.
    #[derive(Default)]
    pub(in crate::crng_reseed) struct FakeKernel {
        pub calls: Vec<String>,
        pub fail: Option<(ReseedStep, i32)>,
    }

    impl KernelEntropy for FakeKernel {
        fn add_entropy(&mut self, bytes: &[u8], credited_bits: u32) -> io::Result<()> {
            self.calls
                .push(format!("add {} credit {credited_bits}", bytes[0]));
            match self.fail {
                Some((ReseedStep::AddEntropy, errno)) => Err(io::Error::from_raw_os_error(errno)),
                _ => Ok(()),
            }
        }

        fn force_reseed(&mut self) -> io::Result<()> {
            self.calls.push("reseed".to_string());
            match self.fail {
                Some((ReseedStep::ForceReseed, errno)) => Err(io::Error::from_raw_os_error(errno)),
                _ => Ok(()),
            }
        }
    }

    const TOKEN: [u8; GENID_BYTES] = [7u8; GENID_BYTES];

    #[test]
    fn the_token_is_credited_before_the_generator_rekeys() {
        let mut kernel = FakeKernel::default();
        reseed_with(&mut kernel, &TOKEN).expect("both steps succeed");
        assert_eq!(kernel.calls, vec!["add 7 credit 128", "reseed"]);
    }

    #[test]
    fn a_failed_add_does_not_rekey_from_a_pool_without_the_token() {
        let mut kernel = FakeKernel {
            fail: Some((ReseedStep::AddEntropy, libc::EBADF)),
            ..FakeKernel::default()
        };
        let (step, _) = reseed_with(&mut kernel, &TOKEN).unwrap_err();
        assert_eq!(step, ReseedStep::AddEntropy);
        assert_eq!(kernel.calls, vec!["add 7 credit 128"]);
    }

    #[test]
    fn requests_and_replies_round_trip_with_their_id() {
        let (id, token) = decode_request(&encode_request(41, &TOKEN));
        assert_eq!((id, token), (41, TOKEN));

        assert_eq!(
            decode_reply(&encode_reply(9, &Ok(()))),
            Some(Reply {
                id: 9,
                outcome: Ok(())
            })
        );
        for step in [ReseedStep::AddEntropy, ReseedStep::ForceReseed] {
            let failed = Err((step, io::Error::from_raw_os_error(libc::EPERM)));
            assert_eq!(
                decode_reply(&encode_reply(u64::MAX, &failed)),
                Some(Reply {
                    id: u64::MAX,
                    outcome: Err((step, libc::EPERM))
                })
            );
        }
    }

    #[test]
    fn an_error_without_an_errno_still_reports_failure() {
        let failed = Err((ReseedStep::ForceReseed, io::Error::other("no errno")));
        let reply = decode_reply(&encode_reply(1, &failed)).expect("well formed");
        assert!(reply.outcome.is_err());
    }

    #[test]
    fn malformed_replies_are_never_read_as_success() {
        let with_status = |status: u8, errno: i32| {
            let mut frame = [0u8; REPLY_BYTES];
            frame[8] = status;
            frame[9..].copy_from_slice(&errno.to_le_bytes());
            frame
        };
        for frame in [
            with_status(STATUS_OK, 1),
            with_status(STATUS_ADD_ENTROPY_FAILED, 0),
            with_status(STATUS_RESEED_FAILED, -1),
            with_status(9, 0),
        ] {
            assert_eq!(decode_reply(&frame), None, "{frame:?} must be malformed");
        }
    }

    /// The helper loop over a real socket pair, on its own thread as it would
    /// be in its own process.
    fn serve_on_thread(
        kernel: FakeKernel,
    ) -> (
        UnixStream,
        std::thread::JoinHandle<(FakeKernel, io::Result<()>)>,
    ) {
        let (agent, mut helper) = UnixStream::pair().expect("socket pair");
        let server = std::thread::spawn(move || {
            let mut kernel = kernel;
            let result = serve(&mut helper, &mut kernel);
            (kernel, result)
        });
        (agent, server)
    }

    #[test]
    fn a_kernel_refusal_is_answered_and_the_helper_keeps_serving() {
        let kernel = FakeKernel {
            fail: Some((ReseedStep::ForceReseed, libc::EPERM)),
            ..FakeKernel::default()
        };
        let (mut agent, server) = serve_on_thread(kernel);
        for id in [1, 2] {
            agent.write_all(&encode_request(id, &TOKEN)).unwrap();
            let mut frame = [0u8; REPLY_BYTES];
            agent.read_exact(&mut frame).unwrap();
            assert_eq!(
                decode_reply(&frame),
                Some(Reply {
                    id,
                    outcome: Err((ReseedStep::ForceReseed, libc::EPERM))
                })
            );
        }
        drop(agent);
        let (kernel, result) = server.join().unwrap();
        result.expect("a close between requests is a clean exit");
        assert_eq!(kernel.calls.len(), 4);
    }

    #[test]
    fn a_request_cut_short_is_an_error_not_a_clean_exit() {
        let (mut agent, server) = serve_on_thread(FakeKernel::default());
        agent.write_all(&[1u8; 4]).unwrap();
        drop(agent);
        let (kernel, result) = server.join().unwrap();
        assert!(result.is_err());
        assert!(
            kernel.calls.is_empty(),
            "nothing is added from a partial request"
        );
    }

    /// A peer that connects and never sends is dropped at the deadline, and
    /// the connection queued behind it is served.
    #[test]
    fn an_idle_connection_gives_way_to_the_next_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let mut kernel = FakeKernel::default();
            serve_connections(
                listener.incoming().take(2),
                &mut kernel,
                Duration::from_millis(200),
            );
            kernel
        });

        let idle = UnixStream::connect(&path).expect("idle connector");
        let mut agent = UnixStream::connect(&path).expect("agent connects behind it");
        agent
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        agent.write_all(&encode_request(1, &TOKEN)).unwrap();
        let mut frame = [0u8; REPLY_BYTES];
        agent
            .read_exact(&mut frame)
            .expect("the agent is answered once the idle connection is dropped");
        assert_eq!(
            decode_reply(&frame),
            Some(Reply {
                id: 1,
                outcome: Ok(())
            })
        );
        drop(agent);
        let kernel = server.join().expect("helper thread");
        assert_eq!(kernel.calls, vec!["add 7 credit 128", "reseed"]);
        drop(idle);
    }

    /// A peer that sends one byte at a time, each well inside a single read's
    /// timeout, is still dropped once the connection's total budget is spent,
    /// and the connection queued behind it is served.
    #[test]
    fn a_trickling_connection_gives_way_at_its_total_budget() {
        let budget = Duration::from_millis(300);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("helper.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let mut kernel = FakeKernel::default();
            serve_connections(listener.incoming().take(2), &mut kernel, budget);
            kernel
        });

        let mut trickler = UnixStream::connect(&path).expect("trickler connects first");
        let request = encode_request(9, &TOKEN);
        let started = Instant::now();
        let trickle = std::thread::spawn(move || {
            // One byte per 100 ms would take over two seconds to finish the
            // request, seven times the budget; each byte arrives well inside
            // any single read's timeout.
            for byte in &request[..REQUEST_BYTES - 1] {
                if trickler.write_all(std::slice::from_ref(byte)).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        let mut agent = UnixStream::connect(&path).expect("agent connects behind it");
        agent
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        agent.write_all(&encode_request(1, &TOKEN)).unwrap();
        let mut frame = [0u8; REPLY_BYTES];
        agent
            .read_exact(&mut frame)
            .expect("the agent is answered once the trickler's budget runs out");
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_millis(100) * (REQUEST_BYTES as u32 - 1),
            "the agent waited {waited:?}, as long as the trickle itself"
        );
        assert_eq!(
            decode_reply(&frame),
            Some(Reply {
                id: 1,
                outcome: Ok(())
            })
        );
        drop(agent);
        let kernel = server.join().expect("helper thread");
        assert_eq!(
            kernel.calls,
            vec!["add 7 credit 128", "reseed"],
            "only the agent's request reached the kernel"
        );
        trickle.join().expect("trickler thread");
    }
}
