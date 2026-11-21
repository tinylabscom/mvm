//! One bounded commissioning exchange over an already-connected Unix stream.
//!
//! This adapter derives peer identity only from the kernel connection. It does
//! not bind an endpoint, select an intent, mutate state, or perform a durable
//! commissioning effect.

use std::{fmt, os::unix::net::UnixStream};

#[cfg(target_os = "macos")]
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
use mvm_contract::protocol::commissioning_bootstrap::{
    MAX_ENCODED_MESSAGE_BYTES, Request, Response,
};

use crate::{
    caller_identity::macos_peer::DesignatedRequirement,
    commissioning_bootstrap_session::CommissioningBootstrapPermit,
};
#[cfg(target_os = "macos")]
use crate::{
    caller_identity::macos_peer::{AUDIT_TOKEN_BYTES, MacAuditToken, VerifiedMacPeer},
    commissioning_bootstrap_session::CommissioningBootstrapSession,
};

#[cfg(target_os = "macos")]
const FRAME_DEADLINE: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const LENGTH_PREFIX_BYTES: usize = size_of::<u32>();

/// Trusted peer identity expected on one connected commissioning stream.
pub struct CommissioningPeerConfig {
    expected_uid: u32,
    #[cfg(target_os = "macos")]
    requirement: DesignatedRequirement,
}

impl CommissioningPeerConfig {
    /// Binds an expected kernel peer UID to one exact designated requirement.
    #[must_use]
    pub const fn new(expected_uid: u32, requirement: DesignatedRequirement) -> Self {
        #[cfg(not(target_os = "macos"))]
        let _ = requirement;
        Self {
            expected_uid,
            #[cfg(target_os = "macos")]
            requirement,
        }
    }
}

impl fmt::Debug for CommissioningPeerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("CommissioningPeerConfig");
        debug.field("expected_uid", &self.expected_uid);
        #[cfg(target_os = "macos")]
        debug.field("requirement", &"[REDACTED]");
        debug.finish()
    }
}

/// Payload-free refusal from the connected commissioning exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectedBootstrapError {
    /// The required kernel and code-signing primitives are unavailable.
    #[error("connected commissioning bootstrap is unsupported on this platform")]
    Unsupported,
    /// The kernel-reported peer UID differs from trusted configuration.
    #[error("connected commissioning peer UID does not match")]
    PeerUidMismatch,
    /// Kernel peer identity capture or descriptor duplication failed.
    #[error("connected commissioning peer identity is unavailable")]
    PeerIdentityUnavailable,
    /// Dynamic code identity did not satisfy trusted configuration.
    #[error("connected commissioning peer verification failed")]
    PeerVerification,
    /// A frame deadline could not be installed.
    #[error("connected commissioning frame deadline is unavailable")]
    DeadlineUnavailable,
    /// A request frame could not be read completely before its deadline.
    #[error("connected commissioning request frame is unavailable")]
    Read,
    /// A response frame could not be written completely before its deadline.
    #[error("connected commissioning response frame is unavailable")]
    Write,
    /// The announced frame body exceeds the exact protocol cap.
    #[error("connected commissioning request frame exceeds the size bound")]
    FrameTooLarge,
    /// A request frame did not decode as the required typed message.
    #[error("connected commissioning request is invalid")]
    InvalidRequest,
    /// The typed session refused the requested transition.
    #[error("connected commissioning session refused the exchange")]
    SessionRefused,
    /// Bytes beyond the current operation were already buffered at a transition.
    #[error("connected commissioning exchange contains buffered trailing data")]
    BufferedTrailingData,
}

/// Drives one peer-verified commissioning exchange on an accepted Unix stream.
///
/// `intent_digest` is selected independently of the protocol bytes. The stream
/// is consumed and no permit is returned unless challenge and acceptance frames
/// are both written successfully and the retained peer revalidates afterward.
/// Receiving `Accepted` is not evidence of durable commissioning; a future
/// effectful consumer must revalidate the permit immediately before mutation.
///
/// # Errors
///
/// Refuses unsupported hosts, identity or code mismatch, malformed or
/// out-of-order frames, buffered trailing data, deadlines, and every I/O failure.
pub fn exchange_connected(
    stream: UnixStream,
    peer: CommissioningPeerConfig,
    intent_digest: [u8; 32],
) -> Result<CommissioningBootstrapPermit, ConnectedBootstrapError> {
    #[cfg(target_os = "macos")]
    {
        exchange_connected_macos(stream, peer, intent_digest)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (stream, peer, intent_digest);
        Err(ConnectedBootstrapError::Unsupported)
    }
}

#[cfg(target_os = "macos")]
fn exchange_connected_macos(
    mut stream: UnixStream,
    peer: CommissioningPeerConfig,
    intent_digest: [u8; 32],
) -> Result<CommissioningBootstrapPermit, ConnectedBootstrapError> {
    let verified_peer = verified_peer(&stream, peer)?;
    let session = CommissioningBootstrapSession::new(verified_peer, intent_digest)
        .map_err(|_| ConnectedBootstrapError::SessionRefused)?;

    let begin = Request::decode(&read_frame(&mut stream)?)
        .map_err(|_| ConnectedBootstrapError::InvalidRequest)?;
    reject_buffered_operation(&stream)?;
    let challenge = session
        .begin(&begin)
        .map_err(|_| ConnectedBootstrapError::SessionRefused)?;
    write_frame(&mut stream, &challenge)?;

    let confirm = Request::decode(&read_frame(&mut stream)?)
        .map_err(|_| ConnectedBootstrapError::InvalidRequest)?;
    reject_buffered_operation(&stream)?;
    let (accepted, permit) = session
        .confirm(&confirm)
        .map_err(|_| ConnectedBootstrapError::SessionRefused)?;
    // Confirm revalidated while consuming the session. Check again at the
    // wire-commit boundary before revealing acceptance; a failed write then
    // drops this effect-free permit instead of returning it.
    permit
        .revalidate()
        .map_err(|_| ConnectedBootstrapError::PeerVerification)?;
    write_frame(&mut stream, &accepted)?;
    permit
        .revalidate()
        .map_err(|_| ConnectedBootstrapError::PeerVerification)?;
    Ok(permit)
}

#[cfg(target_os = "macos")]
fn verified_peer(
    stream: &UnixStream,
    peer: CommissioningPeerConfig,
) -> Result<VerifiedMacPeer, ConnectedBootstrapError> {
    use std::os::fd::AsRawFd as _;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: both output pointers are valid for the call and the descriptor is
    // borrowed from a live UnixStream.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(ConnectedBootstrapError::PeerIdentityUnavailable);
    }
    if uid != peer.expected_uid {
        return Err(ConnectedBootstrapError::PeerUidMismatch);
    }

    let recapture_stream = stream
        .try_clone()
        .map_err(|_| ConnectedBootstrapError::PeerIdentityUnavailable)?;
    let token =
        capture_peer_token(stream).ok_or(ConnectedBootstrapError::PeerIdentityUnavailable)?;
    VerifiedMacPeer::verify(token, peer.expected_uid, peer.requirement, move || {
        capture_peer_token(&recapture_stream)
    })
    .map_err(|_| ConnectedBootstrapError::PeerVerification)
}

#[cfg(target_os = "macos")]
fn capture_peer_token(stream: &UnixStream) -> Option<MacAuditToken> {
    use std::os::fd::AsRawFd as _;

    let mut bytes = [0_u8; AUDIT_TOKEN_BYTES];
    let mut length = libc::socklen_t::try_from(bytes.len()).ok()?;
    // SAFETY: Darwin libc exposes the SDK's SOL_LOCAL/LOCAL_PEERTOKEN option.
    // `bytes` is writable for exactly the supplied length, and `length` remains
    // live so the kernel can report the returned audit_token_t size.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    (result == 0 && usize::try_from(length).ok() == Some(AUDIT_TOKEN_BYTES))
        .then(|| MacAuditToken::from_bytes(bytes))
}

#[cfg(target_os = "macos")]
fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ConnectedBootstrapError> {
    let deadline = Instant::now()
        .checked_add(FRAME_DEADLINE)
        .ok_or(ConnectedBootstrapError::DeadlineUnavailable)?;
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    read_exact_before(stream, &mut prefix, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| ConnectedBootstrapError::FrameTooLarge)?;
    if length > MAX_ENCODED_MESSAGE_BYTES {
        return Err(ConnectedBootstrapError::FrameTooLarge);
    }
    let mut body = vec![0_u8; length];
    read_exact_before(stream, &mut body, deadline)?;
    Ok(body)
}

#[cfg(target_os = "macos")]
fn write_frame(
    stream: &mut UnixStream,
    response: &Response,
) -> Result<(), ConnectedBootstrapError> {
    let body = response
        .encode()
        .map_err(|_| ConnectedBootstrapError::SessionRefused)?;
    let length = u32::try_from(body.len()).map_err(|_| ConnectedBootstrapError::SessionRefused)?;
    let deadline = Instant::now()
        .checked_add(FRAME_DEADLINE)
        .ok_or(ConnectedBootstrapError::DeadlineUnavailable)?;
    write_all_before(stream, &length.to_be_bytes(), deadline)?;
    write_all_before(stream, &body, deadline)
}

#[cfg(target_os = "macos")]
fn read_exact_before(
    stream: &mut UnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), ConnectedBootstrapError> {
    while !buffer.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline, ConnectedBootstrapError::Read)?))
            .map_err(|_| ConnectedBootstrapError::Read)?;
        match stream.read(buffer) {
            Ok(0) => return Err(ConnectedBootstrapError::Read),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ConnectedBootstrapError::Read),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_all_before(
    stream: &mut UnixStream,
    mut buffer: &[u8],
    deadline: Instant,
) -> Result<(), ConnectedBootstrapError> {
    while !buffer.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline, ConnectedBootstrapError::Write)?))
            .map_err(|_| ConnectedBootstrapError::Write)?;
        match stream.write(buffer) {
            Ok(0) => return Err(ConnectedBootstrapError::Write),
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ConnectedBootstrapError::Write),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remaining(
    deadline: Instant,
    expired: ConnectedBootstrapError,
) -> Result<Duration, ConnectedBootstrapError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(expired)
}

#[cfg(target_os = "macos")]
fn reject_buffered_operation(stream: &UnixStream) -> Result<(), ConnectedBootstrapError> {
    use std::os::fd::AsRawFd as _;

    let mut byte = 0_u8;
    // SAFETY: `byte` is writable for the one-byte length passed to recv, and
    // MSG_PEEK leaves queued bytes untouched. MSG_DONTWAIT prevents this
    // sequencing check from extending the frame deadline.
    let result = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result > 0 {
        return Err(ConnectedBootstrapError::BufferedTrailingData);
    }
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(())
    } else {
        Err(ConnectedBootstrapError::Read)
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod unsupported_tests {
    use super::*;

    #[test]
    fn connected_exchange_refuses_without_macos_primitives() {
        let (stream, _peer) = UnixStream::pair().expect("socket pair");
        let config = CommissioningPeerConfig::new(
            501,
            DesignatedRequirement::new("identifier \"dev.mvm.owner\"")
                .expect("bounded requirement"),
        );
        assert_eq!(
            format!("{config:?}"),
            "CommissioningPeerConfig { expected_uid: 501 }"
        );
        assert_eq!(
            exchange_connected(stream, config, [1; 32]).expect_err("must refuse"),
            ConnectedBootstrapError::Unsupported
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod native_tests {
    use std::{
        ffi::c_void,
        io::{Read as _, Write as _},
        net::Shutdown,
        os::{
            fd::{AsRawFd as _, FromRawFd as _},
            unix::net::UnixListener,
        },
        process::Command,
        thread,
    };

    use core_foundation::{base::TCFType as _, string::CFString};
    use mvm_contract::protocol::commissioning_bootstrap::{
        CONFIRM_SEQUENCE, MAX_CHALLENGE_EXPIRES_AFTER_MS, VERSION,
    };
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    use super::*;

    const DIGEST: [u8; 32] = [7; 32];
    const CLIENT_NONCE: [u8; 32] = [8; 32];
    const CHILD_SOCKET_ENV: &str = "MVM_COMMISSIONING_BOOTSTRAP_TEST_SOCKET";
    const CHILD_READY_FD_ENV: &str = "MVM_COMMISSIONING_BOOTSTRAP_TEST_READY_FD";

    unsafe extern "C" {
        fn SecCodeCopyDesignatedRequirement(
            code: *const c_void,
            flags: u32,
            requirement: *mut *const c_void,
        ) -> i32;
        fn SecRequirementCopyString(
            requirement: *const c_void,
            flags: u32,
            text: *mut *const c_void,
        ) -> i32;
    }

    fn expected_uid() -> u32 {
        // SAFETY: geteuid takes no pointers and has no caller preconditions.
        unsafe { libc::geteuid() }
    }

    fn self_designated_requirement() -> DesignatedRequirement {
        let code = SecCode::for_self(Flags::NONE).expect("current dynamic code is available");
        let mut requirement = std::ptr::null();
        // SAFETY: Security.framework receives a valid retained SecCode and
        // initializes the create-rule output on success.
        let status = unsafe {
            SecCodeCopyDesignatedRequirement(code.as_concrete_TypeRef().cast(), 0, &mut requirement)
        };
        assert_eq!(status, 0, "current code has a designated requirement");
        assert!(!requirement.is_null(), "requirement output is non-null");

        let mut text = std::ptr::null();
        // SAFETY: `requirement` is the live create-rule object returned above.
        let status = unsafe { SecRequirementCopyString(requirement, 0, &mut text) };
        // SAFETY: transfer the create-rule requirement to the Rust wrapper.
        let _requirement =
            unsafe { SecRequirement::wrap_under_create_rule(requirement.cast_mut().cast()) };
        assert_eq!(status, 0, "designated requirement converts to source");
        assert!(!text.is_null(), "requirement source output is non-null");
        // SAFETY: transfer the create-rule string to the Rust wrapper.
        let text = unsafe { CFString::wrap_under_create_rule(text.cast_mut().cast()) };
        DesignatedRequirement::new(&text.to_string()).expect("native source satisfies bound")
    }

    fn config() -> CommissioningPeerConfig {
        CommissioningPeerConfig::new(expected_uid(), self_designated_requirement())
    }

    #[test]
    fn peer_config_debug_redacts_requirement() {
        let config = config();
        assert_eq!(
            format!("{config:?}"),
            format!(
                "CommissioningPeerConfig {{ expected_uid: {}, requirement: \"[REDACTED]\" }}",
                expected_uid()
            )
        );
    }

    fn begin() -> Request {
        Request::Begin {
            version: VERSION,
            intent_digest: DIGEST,
            client_nonce: CLIENT_NONCE,
        }
    }

    fn confirm(challenge: &Response) -> Request {
        let Response::Challenge {
            version,
            intent_digest,
            client_nonce,
            server_nonce,
            expires_after_ms,
        } = challenge
        else {
            panic!("server must issue a challenge");
        };
        assert_eq!(*expires_after_ms, MAX_CHALLENGE_EXPIRES_AFTER_MS);
        Request::Confirm {
            version: *version,
            intent_digest: *intent_digest,
            client_nonce: *client_nonce,
            server_nonce: *server_nonce,
            sequence: CONFIRM_SEQUENCE,
        }
    }

    fn write_request(stream: &mut UnixStream, request: &Request) {
        let body = request.encode().expect("request encodes");
        stream
            .write_all(
                &u32::try_from(body.len())
                    .expect("bounded request length")
                    .to_be_bytes(),
            )
            .expect("write request length");
        stream.write_all(&body).expect("write request body");
    }

    fn read_response(stream: &mut UnixStream) -> Response {
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set client deadline");
        let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
        stream
            .read_exact(&mut prefix)
            .expect("read response length");
        let length = usize::try_from(u32::from_be_bytes(prefix)).expect("response length");
        assert!(length <= MAX_ENCODED_MESSAGE_BYTES, "bounded response");
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body).expect("read response body");
        Response::decode(&body).expect("response decodes")
    }

    fn run_client(stream: &mut UnixStream) -> Response {
        write_request(stream, &begin());
        let challenge = read_response(stream);
        write_request(stream, &confirm(&challenge));
        read_response(stream)
    }

    #[test]
    fn kernel_peer_capture_and_owned_duplicate_survive_original_close_and_fd_reuse() {
        let (server, peer) = UnixStream::pair().expect("socket pair");
        let verified = verified_peer(&server, config()).expect("kernel-derived peer verifies");
        let original_fd = server.as_raw_fd();
        drop(server);

        let mut reused = false;
        let mut sockets = Vec::new();
        for _ in 0..256 {
            let pair = UnixStream::pair().expect("reuse socket pair");
            reused |= pair.0.as_raw_fd() == original_fd || pair.1.as_raw_fd() == original_fd;
            sockets.push(pair);
            if reused {
                break;
            }
        }
        assert!(
            reused,
            "closed descriptor number was reused by a new socket"
        );
        verified
            .revalidate()
            .expect("recapture stays on the owned duplicate");
        drop(peer);
        drop(sockets);
    }

    #[test]
    fn wrong_expected_uid_refuses_before_exchange() {
        let (server, _peer) = UnixStream::pair().expect("socket pair");
        let wrong = CommissioningPeerConfig::new(
            expected_uid().wrapping_add(1),
            self_designated_requirement(),
        );
        assert_eq!(
            exchange_connected(server, wrong, DIGEST).expect_err("wrong UID must refuse"),
            ConnectedBootstrapError::PeerUidMismatch
        );
    }

    #[test]
    fn exact_socket_pair_exchange_returns_one_bound_permit() {
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let server_thread = thread::spawn(move || exchange_connected(server, config(), DIGEST));
        let accepted = run_client(&mut client);
        assert!(matches!(
            accepted,
            Response::Accepted {
                intent_digest: DIGEST,
                ..
            }
        ));
        let permit = server_thread
            .join()
            .expect("server thread does not panic")
            .expect("exact exchange succeeds");
        assert_eq!(permit.intent_digest(), &DIGEST);
        permit.revalidate().expect("returned permit retains peer");
    }

    #[test]
    fn oversize_and_truncated_frames_return_no_permit() {
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let server_thread = thread::spawn(move || exchange_connected(server, config(), DIGEST));
        client
            .write_all(
                &u32::try_from(MAX_ENCODED_MESSAGE_BYTES + 1)
                    .expect("cap fits u32")
                    .to_be_bytes(),
            )
            .expect("write oversize prefix");
        assert!(matches!(
            server_thread.join().expect("server thread"),
            Err(ConnectedBootstrapError::FrameTooLarge)
        ));

        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let server_thread = thread::spawn(move || exchange_connected(server, config(), DIGEST));
        thread::sleep(Duration::from_millis(100));
        client
            .write_all(&16_u32.to_be_bytes())
            .expect("write truncated prefix");
        client.write_all(b"{").expect("write truncated body");
        client
            .shutdown(Shutdown::Write)
            .expect("half-close truncated request");
        let error = server_thread
            .join()
            .expect("server thread")
            .expect_err("truncated frame must refuse");
        assert_eq!(error, ConnectedBootstrapError::Read);
    }

    #[test]
    fn wrong_binding_and_timeout_return_no_permit() {
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let server_thread = thread::spawn(move || exchange_connected(server, config(), DIGEST));
        write_request(
            &mut client,
            &Request::Begin {
                version: VERSION,
                intent_digest: [6; 32],
                client_nonce: CLIENT_NONCE,
            },
        );
        assert!(matches!(
            server_thread.join().expect("server thread"),
            Err(ConnectedBootstrapError::SessionRefused)
        ));

        let (mut server, _idle_client) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        assert_eq!(
            read_frame(&mut server).expect_err("idle frame must time out"),
            ConnectedBootstrapError::Read
        );
        assert!(
            started.elapsed() >= Duration::from_secs(4)
                && started.elapsed() < Duration::from_secs(7),
            "frame timeout stays close to the fixed five-second bound"
        );
    }

    #[test]
    fn already_buffered_trailing_data_refuses_deterministically() {
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        client
            .write_all(b"trailing operation")
            .expect("queue trailing bytes");
        assert_eq!(
            reject_buffered_operation(&server),
            Err(ConnectedBootstrapError::BufferedTrailingData)
        );
    }

    #[test]
    fn live_self_requirement_identifies_same_signed_subprocess() {
        let directory = tempfile::Builder::new()
            .prefix("mvm-cb-")
            .tempdir_in("/tmp")
            .expect("short temporary socket directory");
        let socket_path = directory.path().join("bootstrap.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind test listener");
        listener
            .set_nonblocking(true)
            .expect("set bounded accept mode");
        let (mut ready_parent, ready_child) = UnixStream::pair().expect("readiness socket pair");
        let ready_fd = ready_child.as_raw_fd();
        let executable = std::env::current_exe().expect("current test executable");
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg("commissioning_bootstrap_connection::native_tests::subprocess_client_helper")
            .arg("--nocapture")
            .env(CHILD_SOCKET_ENV, &socket_path)
            .env(CHILD_READY_FD_ENV, ready_fd.to_string());
        // A separately signed fixture would require release signing infrastructure.
        // Re-exec the live signed test image to exercise a real subprocess token
        // without weakening the production requirement check.
        // SAFETY: the pre-exec closure invokes only async-signal-safe fcntl on
        // the inherited descriptor and does not access shared process state.
        unsafe {
            use std::os::unix::process::CommandExt as _;
            command.pre_exec(move || {
                if libc::fcntl(ready_fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("spawn live self child");
        drop(ready_child);
        ready_parent
            .set_read_timeout(Some(Duration::from_secs(6)))
            .expect("set readiness deadline");
        let mut ready = [0_u8; 1];
        ready_parent
            .read_exact(&mut ready)
            .expect("child queued begin before identity capture");
        assert_eq!(ready, [1]);
        let (server, _address) = listener
            .accept()
            .expect("connected child is queued after readiness");

        let observed = verified_peer(&server, config()).expect("child peer identity verifies");
        assert_eq!(observed.pid(), child.id(), "kernel token identifies child");
        drop(observed);

        ready_parent
            .write_all(&[2])
            .expect("release child after identity verification");
        assert!(
            child.wait().expect("wait for child").success(),
            "subprocess client succeeds"
        );
    }

    #[test]
    fn subprocess_client_helper() {
        let Ok(socket_path) = std::env::var(CHILD_SOCKET_ENV) else {
            return;
        };
        let ready_fd = std::env::var(CHILD_READY_FD_ENV)
            .expect("parent supplies readiness descriptor")
            .parse()
            .expect("readiness descriptor number");
        let mut stream = UnixStream::connect(socket_path).expect("connect test listener");
        // SAFETY: the parent passes one uniquely owned readiness descriptor.
        let mut ready = unsafe { UnixStream::from_raw_fd(ready_fd) };
        write_request(&mut stream, &begin());
        ready.write_all(&[1]).expect("signal queued begin");
        ready
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set completion deadline");
        let mut completed = [0_u8; 1];
        ready
            .read_exact(&mut completed)
            .expect("parent completed child identity verification");
        assert_eq!(completed, [2]);
    }
}
