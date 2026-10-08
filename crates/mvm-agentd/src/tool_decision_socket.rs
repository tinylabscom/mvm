//! The agent's tool-decision socket: how the tool helper coordinates with the
//! agent that owns the attribution registry and the `MediatedExec` decisions.
//!
//! The helper answers the in-guest shim on one socket and asks the agent on
//! this one, for two questions only. "Was this relay already decided by the
//! host?" — the agent recorded the decision under the relay's pid when it
//! spawned the `MediatedExec`, and consuming it here is what keeps a
//! host-initiated declared command decided exactly once. "Record (or retire)
//! this tool session under its binding" — the push that makes a
//! helper-spawned tool's loopback egress attributable, exactly the entry
//! [`crate::tool_attribution`] would have made had the agent spawned the tool
//! itself.
//!
//! The socket is abstract-namespace and bound by PID 1 before any workload
//! runs, and every connection is authorized by `SO_PEERCRED`: only the tool
//! helper's identity ([`crate::guest_mount::TOOL_HELPER_IDENTITY`])
//! and root are answered. The workload's uid is refused, so workload code can
//! neither consume a relay decision it did not earn nor register a session
//! under a binding it does not hold.

use std::io::{self, BufRead, BufReader, Write};

use crate::tool_map::{DecisionReply, DecisionRequest, MAX_DECISION_FRAME_BYTES};

/// Abstract-namespace name of the agent's decision listener.
pub const DECISION_SOCKET_NAME: &[u8] = b"mvm-tool-decision";

/// One bounded JSON line in either direction.
fn read_line(stream: &mut impl io::Read) -> io::Result<DecisionRequest> {
    let mut line = String::new();
    BufReader::new(io::Read::take(stream, MAX_DECISION_FRAME_BYTES)).read_line(&mut line)?;
    serde_json::from_str(line.trim_end()).map_err(io::Error::other)
}

fn write_line(stream: &mut (impl io::Read + Write), reply: &DecisionReply) -> io::Result<()> {
    let mut line = serde_json::to_vec(reply).map_err(io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)
}

/// Run one request/response exchange. Split from the socket plumbing so the
/// authorization and dispatch rules are testable on a plain stream pair.
fn answer(stream: &mut (impl io::Read + Write)) -> io::Result<()> {
    match read_line(stream)? {
        DecisionRequest::Decided { pid } => {
            let reply = match crate::tool_attribution::consume_decided(pid) {
                Some(binding) => DecisionReply::Decided { binding },
                None => DecisionReply::NotDecided,
            };
            write_line(stream, &reply)
        }
        DecisionRequest::Record { session, binding } => {
            let reply = if let Some(binding) = binding {
                match crate::tool_attribution::record_external(session, binding) {
                    Ok(()) => DecisionReply::Ok,
                    Err(error) => {
                        eprintln!(
                            "mvm-guest-agent: tool session {session} left unattributed: {error}"
                        );
                        DecisionReply::Unavailable
                    }
                }
            } else {
                DecisionReply::Ok
            };
            write_line(stream, &reply)
        }
        DecisionRequest::Retire { session } => {
            crate::tool_attribution::retire_external(session);
            write_line(stream, &DecisionReply::Ok)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener, UnixStream};
    use std::time::Duration;

    use super::*;

    /// How long either side waits on the other before giving up.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn peer_credentials(stream: &UnixStream) -> io::Result<libc::ucred> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a correctly sized `ucred` and `len` holds its
        // size; the kernel writes at most that many bytes.
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
            Ok(cred)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn authorized(cred: &libc::ucred) -> bool {
        if cred.uid == 0 {
            return true;
        }
        let helper = crate::guest_mount::TOOL_HELPER_IDENTITY;
        cred.uid == helper.uid() && cred.gid == helper.gid()
    }

    fn address() -> io::Result<UnixAddr> {
        UnixAddr::from_abstract_name(DECISION_SOCKET_NAME)
    }

    /// Bind the decision listener. Called by PID 1 before any workload runs,
    /// so no workload process can hold the name first.
    pub fn bind_listener() -> io::Result<UnixListener> {
        UnixListener::bind_addr(&address()?)
    }

    pub(super) fn serve_connection(mut stream: UnixStream) {
        if !peer_credentials(&stream).is_ok_and(|cred| authorized(&cred)) {
            return;
        }
        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        if let Err(error) = answer(&mut stream) {
            eprintln!("mvm-guest-agent: tool decision request failed: {error}");
        }
    }

    /// Answer requests for the life of the agent. Only the tool helper
    /// identity and root are served.
    pub fn serve(listener: UnixListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                continue;
            };
            serve_connection(stream);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{bind_listener, serve};

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    fn exchange(request: &DecisionRequest) -> DecisionReply {
        let (mut agent, mut client) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut framed = serde_json::to_vec(request).expect("serialize");
        framed.push(b'\n');
        client.write_all(&framed).expect("write request");
        // The client holds its end open while the agent answers, then reads
        // the one reply line.
        answer(&mut agent).expect("answer");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("timeout");
        let mut line = String::new();
        std::io::BufReader::new(Read::take(&mut client, MAX_DECISION_FRAME_BYTES))
            .read_line(&mut line)
            .expect("read reply");
        serde_json::from_str(line.trim_end()).expect("reply parses")
    }

    #[test]
    fn retire_and_unknown_pid_round_trip() {
        assert_eq!(
            exchange(&DecisionRequest::Retire { session: 42 }),
            DecisionReply::Ok
        );
        assert_eq!(
            exchange(&DecisionRequest::Decided { pid: 1 }),
            DecisionReply::NotDecided
        );
    }

    #[test]
    fn malformed_request_is_an_io_error_not_a_panic() {
        let (mut agent, mut client) = std::os::unix::net::UnixStream::pair().expect("pair");
        client.write_all(b"{\"op\":\"nope\"}\n").expect("write");
        drop(client);
        assert!(answer(&mut agent).is_err());
    }

    #[test]
    fn record_without_binding_is_accepted_without_attribution() {
        assert_eq!(
            exchange(&DecisionRequest::Record {
                session: 7,
                binding: None,
            }),
            DecisionReply::Ok
        );
    }

    #[test]
    fn a_missing_session_refuses_attribution() {
        let binding =
            mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding::from_random(
                [8; 16],
            );
        assert_eq!(
            exchange(&DecisionRequest::Record {
                session: u32::MAX,
                binding: Some(binding),
            }),
            DecisionReply::Unavailable
        );
    }
}
