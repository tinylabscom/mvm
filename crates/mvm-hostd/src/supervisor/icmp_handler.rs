//! Policy-gated ICMP-echo-over-vsock request handling.
//!
//! One JSON [`IcmpEchoRequest`] line in, one [`IcmpEchoReply`] line per sequence
//! out. Admission runs before any packet exists: a refused request is answered
//! with a single terminal `Refused` and no socket is ever opened, so a guest
//! cannot use ping to discover whether a destination it was never granted
//! happens to be reachable.
//!
//! Echo is metered by the same [`EgressRateGuard`] DNS uses. Ping is the
//! cheapest possible request to issue and one of the easier ones to abuse — a
//! loop asking for the maximum count is a packet amplifier — so a request that
//! cannot be admitted right now is refused rather than queued.

use std::time::Duration;

use mvm_core::icmp_wire::{IcmpEchoReply, IcmpEchoRequest, MAX_LINE_LEN};
use mvm_runtime::vmm::egress_gate::{EgressGate, EgressVerdict};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::egress_rate::EgressRateGuard;
use crate::supervisor::icmp_audit::{self, EchoAudit};
use crate::supervisor::icmp_echo::EchoTransport;

/// First-line marker that selects ICMP framing on the shared egress stream.
pub const FRAME_LINE: &str = mvm_core::guest_netd::ICMP_FRAME_LINE;

/// How long the host waits for a guest to finish its request line.
///
/// [`MAX_LINE_LEN`] bounds the request's *size*; this bounds its *time*. Without
/// it a guest that opens the ICMP frame and then writes one byte — or none —
/// holds a host task for as long as it likes, which is a denial of service that
/// costs the guest nothing to mount. Fail closed by hanging up.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve one ICMP echo request over an asynchronous guest stream.
///
/// Never returns `Err` for a *refused* request — a refusal is an answer, and the
/// guest gets it as a `Refused` line. `Err` is reserved for the stream itself
/// failing.
pub async fn serve_icmp<S>(
    guest: S,
    gate: &EgressGate,
    recorder: Option<&Recorder>,
    rate_guard: &EgressRateGuard,
    echo: &dyn EchoTransport,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(guest);
    let mut line = String::new();
    // Bound the request line before parsing: a guest that never sends a newline
    // must not make the host buffer without limit.
    let read = match tokio::time::timeout(
        REQUEST_READ_TIMEOUT,
        (&mut stream).take(MAX_LINE_LEN as u64).read_line(&mut line),
    )
    .await
    {
        Ok(result) => result?,
        // A guest that never finishes its line gets no answer and no task.
        Err(_elapsed) => return Ok(()),
    };
    if read == 0 {
        return Ok(());
    }

    let (replies, audit) = serve_request(&line, gate, rate_guard, echo);
    if let Some(recorder) = recorder {
        icmp_audit::emit_icmp_echo(recorder, &audit).await;
    }
    for reply in replies {
        write_line(stream.get_mut(), &reply).await?;
    }
    Ok(())
}

/// Serve one request line, blocking. The Linux AF_VSOCK accept threads have no
/// async context; the decision and the echoes are [`serve_request`], shared with
/// the async path above, so only the line I/O differs.
#[cfg(target_os = "linux")]
pub fn serve_icmp_blocking<S>(
    mut guest: S,
    gate: &EgressGate,
    recorder: Option<&Recorder>,
    rate_guard: &EgressRateGuard,
    echo: &dyn EchoTransport,
) -> std::io::Result<()>
where
    S: std::io::Read + std::io::Write,
{
    use std::io::{BufRead, BufReader, Read, Write};

    let mut reader = BufReader::new(&mut guest);
    let mut line = String::new();
    let read = reader
        .by_ref()
        .take(MAX_LINE_LEN as u64)
        .read_line(&mut line)?;
    if read == 0 {
        return Ok(());
    }
    let (replies, audit) = serve_request(&line, gate, rate_guard, echo);
    if let Some(recorder) = recorder {
        icmp_audit::emit_icmp_echo_blocking(recorder, &audit);
    }
    for reply in replies {
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        guest.write_all(&bytes)?;
    }
    guest.flush()
}

/// Decide one request line and perform its echoes, returning the replies to
/// write.
///
/// This is the whole of the verb: parse, bounds, admission, rate, echo. It is
/// free of stream framing so the async and blocking front ends cannot drift on
/// any of it — a second copy of admission is exactly the bug that would not
/// surface until a Linux host refused something a macOS host allowed.
fn serve_request(
    line: &str,
    gate: &EgressGate,
    rate_guard: &EgressRateGuard,
    echo: &dyn EchoTransport,
) -> (Vec<IcmpEchoReply>, EchoAudit) {
    // Every refusal answers the guest and records the same reason, so the chain
    // and the caller never disagree about why.
    let refused = |host: &str, message: String| {
        (
            vec![IcmpEchoReply::Refused {
                message: message.clone(),
            }],
            EchoAudit::Refused {
                host: host.to_string(),
                reason: message,
            },
        )
    };

    let request = match serde_json::from_str::<IcmpEchoRequest>(line.trim_end()) {
        Ok(request) => request,
        Err(error) => return refused("", format!("malformed echo request: {error}")),
    };
    if let Err(bounds) = request.validate() {
        return refused(&request.host, bounds.to_string());
    }

    let ips = match gate.decide_icmp_request(&request.host) {
        EgressVerdict::Allow { ips, .. } => ips,
        EgressVerdict::Deny(reason) => {
            tracing::warn!(host = %request.host, %reason, "icmp echo refused");
            return refused(&request.host, reason.to_string());
        }
        EgressVerdict::Malformed => {
            return refused(&request.host, "malformed destination".to_string());
        }
    };
    // The gate orders admitted addresses IPv4 first; echo the first, which is
    // the address a stream to the same host would use.
    let Some(&ip) = ips.first() else {
        return refused(&request.host, "no admitted address".to_string());
    };

    let Some(_permit) = rate_guard.try_admit() else {
        return refused(&request.host, "echo rate limit reached".to_string());
    };

    let timeout = Duration::from_millis(u64::from(request.timeout_ms));
    let mut replies = Vec::with_capacity(usize::from(request.count));
    for seq in 0..request.count {
        match echo.echo(ip, seq, request.payload_len, timeout) {
            Ok(Some(rtt)) => replies.push(IcmpEchoReply::Reply {
                seq,
                ip: ip.to_string(),
                host_leg_us: rtt.as_micros().min(u128::from(u64::MAX)) as u64,
                payload_len: request.payload_len,
            }),
            Ok(None) => replies.push(IcmpEchoReply::Timeout { seq }),
            // A socket the kernel will not open is terminal for the whole
            // request — retrying the remaining sequences would report the same
            // failure `count` times.
            Err(error) => {
                replies.push(IcmpEchoReply::Refused {
                    message: format!("echo failed: {error}"),
                });
                break;
            }
        }
    }
    (
        replies,
        EchoAudit::Admitted {
            host: request.host.clone(),
            ip: ip.to_string(),
            count: request.count,
        },
    )
}

async fn write_line<W>(guest: &mut W, reply: &IcmpEchoReply) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(reply)?;
    line.push(b'\n');
    guest.write_all(&line).await?;
    guest.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex;

    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use tokio::io::AsyncReadExt;

    /// Records what it was asked to echo and answers from a script, so the
    /// handler's admission/bounds/framing can be driven without a network.
    struct ScriptedEcho {
        outcomes: Mutex<Vec<std::io::Result<Option<Duration>>>>,
        seen: Mutex<Vec<(IpAddr, u16, u16)>>,
    }

    impl ScriptedEcho {
        fn new(outcomes: Vec<std::io::Result<Option<Duration>>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn never_called() -> Self {
            Self::new(Vec::new())
        }
    }

    impl EchoTransport for ScriptedEcho {
        fn echo(
            &self,
            ip: IpAddr,
            seq: u16,
            payload_len: u16,
            _timeout: Duration,
        ) -> std::io::Result<Option<Duration>> {
            self.seen.lock().unwrap().push((ip, seq, payload_len));
            let mut outcomes = self.outcomes.lock().unwrap();
            if outcomes.is_empty() {
                panic!("echo called more times than the script allows");
            }
            outcomes.remove(0)
        }
    }

    fn admitted_gate() -> EgressGate {
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "example.com",
            vec!["93.184.216.34".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort {
            host: "example.com".into(),
            port: 443,
        }]);
        EgressGate::from_network_policy(&policy, &pins, "2026-01-01T00:00:00Z")
    }

    async fn run(request: &str, gate: &EgressGate, echo: &dyn EchoTransport) -> Vec<IcmpEchoReply> {
        let (mut client, server) = tokio::io::duplex(4096);
        let guard = EgressRateGuard::default();
        let task = async move { serve_icmp(server, gate, None, &guard, echo).await.unwrap() };
        let drive = async {
            // The handler reads a *line*; without the terminator it waits for a
            // newline that never comes while this side waits to read, and the
            // two block on each other.
            let mut framed = request.to_string();
            if !framed.ends_with('\n') {
                framed.push('\n');
            }
            client.write_all(framed.as_bytes()).await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        };
        let (_, out) = tokio::join!(task, drive);
        out.lines()
            .map(|l| serde_json::from_str(l).expect("each line is a reply"))
            .collect()
    }

    /// A guest that opens the frame and never finishes its request line must be
    /// hung up on, not waited on forever. `MAX_LINE_LEN` bounds the size; only a
    /// deadline bounds the time, and without one this is a free denial of
    /// service against the host.
    #[tokio::test(start_paused = true)]
    async fn a_guest_that_never_finishes_its_line_is_dropped() {
        let echo = ScriptedEcho::never_called();
        let gate = admitted_gate();
        let guard = EgressRateGuard::default();
        let (mut client, server) = tokio::io::duplex(4096);

        // A partial line, no terminator, and the client keeps its half open.
        client.write_all(br#"{"host":"exam"#).await.unwrap();

        let served = tokio::time::timeout(
            REQUEST_READ_TIMEOUT * 3,
            serve_icmp(server, &gate, None, &guard, &echo),
        )
        .await;
        assert!(
            served.is_ok(),
            "the handler must give up on its own rather than wait forever"
        );
        served.unwrap().expect("hanging up is not a stream error");
        assert!(
            echo.seen.lock().unwrap().is_empty(),
            "an unfinished request must never echo"
        );
    }

    #[tokio::test]
    async fn an_admitted_host_gets_one_reply_per_sequence() {
        let echo = ScriptedEcho::new(vec![
            Ok(Some(Duration::from_micros(9_800))),
            Ok(None),
            Ok(Some(Duration::from_micros(11_200))),
        ]);
        let replies = run(
            r#"{"host":"example.com","count":3,"payload_len":56,"timeout_ms":1000}"#,
            &admitted_gate(),
            &echo,
        )
        .await;

        assert_eq!(replies.len(), 3);
        assert_eq!(
            replies[0],
            IcmpEchoReply::Reply {
                seq: 0,
                ip: "93.184.216.34".into(),
                host_leg_us: 9_800,
                payload_len: 56,
            }
        );
        assert_eq!(replies[1], IcmpEchoReply::Timeout { seq: 1 });
        // Every echo went to the pinned address with the requested payload.
        let seen = echo.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                ("93.184.216.34".parse::<IpAddr>().unwrap(), 0, 56),
                ("93.184.216.34".parse().unwrap(), 1, 56),
                ("93.184.216.34".parse().unwrap(), 2, 56),
            ]
        );
    }

    /// The property that keeps ping from becoming a reachability oracle: a
    /// refused host must produce no packet at all, not a packet whose reply is
    /// withheld.
    #[tokio::test]
    async fn an_unadmitted_host_is_refused_without_echoing() {
        let echo = ScriptedEcho::never_called();
        let replies = run(
            r#"{"host":"evil.test","count":4,"payload_len":56,"timeout_ms":1000}"#,
            &admitted_gate(),
            &echo,
        )
        .await;

        assert_eq!(replies.len(), 1, "a refusal is terminal");
        let IcmpEchoReply::Refused { message } = &replies[0] else {
            panic!("expected a refusal, got {:?}", replies[0]);
        };
        assert!(message.contains("example.com"), "{message}");
        assert!(
            echo.seen.lock().unwrap().is_empty(),
            "no echo may be sent for a refused host"
        );
    }

    #[tokio::test]
    async fn an_out_of_bounds_request_is_refused_without_echoing() {
        let echo = ScriptedEcho::never_called();
        let replies = run(
            r#"{"host":"example.com","count":9999,"payload_len":56,"timeout_ms":1000}"#,
            &admitted_gate(),
            &echo,
        )
        .await;

        assert_eq!(replies.len(), 1);
        let IcmpEchoReply::Refused { message } = &replies[0] else {
            panic!("expected a refusal, got {:?}", replies[0]);
        };
        assert!(message.contains("count"), "{message}");
        assert!(echo.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_malformed_line_is_refused_without_echoing() {
        let echo = ScriptedEcho::never_called();
        let replies = run("not json at all\n", &admitted_gate(), &echo).await;
        assert_eq!(replies.len(), 1);
        assert!(matches!(replies[0], IcmpEchoReply::Refused { .. }));
        assert!(echo.seen.lock().unwrap().is_empty());
    }

    /// A deny-all workload cannot ping, and the refusal says so as policy rather
    /// than as an unknown host.
    #[tokio::test]
    async fn a_deny_all_workload_cannot_echo() {
        let echo = ScriptedEcho::never_called();
        let replies = run(
            r#"{"host":"example.com","count":1,"payload_len":0,"timeout_ms":100}"#,
            &EgressGate::default_deny(),
            &echo,
        )
        .await;
        let IcmpEchoReply::Refused { message } = &replies[0] else {
            panic!("expected a refusal, got {:?}", replies[0]);
        };
        assert!(message.contains("deny-all"), "{message}");
    }

    /// A socket the kernel refuses ends the whole request once, rather than
    /// repeating the same failure for every remaining sequence.
    #[tokio::test]
    async fn an_unopenable_socket_ends_the_request_once() {
        let echo = ScriptedEcho::new(vec![Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ping sockets not permitted",
        ))]);
        let replies = run(
            r#"{"host":"example.com","count":5,"payload_len":0,"timeout_ms":100}"#,
            &admitted_gate(),
            &echo,
        )
        .await;

        assert_eq!(replies.len(), 1);
        let IcmpEchoReply::Refused { message } = &replies[0] else {
            panic!("expected a refusal, got {:?}", replies[0]);
        };
        assert!(message.contains("not permitted"), "{message}");
    }
}
