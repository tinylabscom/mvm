//! In-guest client for host-mediated ICMP echo.
//!
//! A NIC-less guest cannot originate ICMP: there is no route and no raw socket,
//! so `ping` fails at `socket()` before a packet exists. This asks the host to
//! echo on the guest's behalf, through the guest's own loopback mediator
//! ([`crate::icmp_mediator`]) — the same shape as every other thing a workload
//! sends outward, which reaches the host through the loopback SOCKS proxy or
//! the loopback DNS stub rather than dialling it directly. The workload runs
//! unprivileged and the FlowMux identity is root-only, so the mediator is what
//! makes the echo reachable at all.
//!
//! The round trip this measures is the *guest's*, not the host's. The timer
//! starts before the request goes to the mediator and stops when the reply line
//! lands, so it covers the loopback hop, the vsock hop and the host's mediation
//! as well as the network — which is the whole path any request from this
//! workload takes. The host also reports its own leg, so the two can be
//! compared rather than conflated. The mediator's session is established before
//! the first timer starts, so what is timed is the echo and not the handshake.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_core::guest_netd::ICMP_MEDIATOR_LISTEN;
use mvm_core::icmp_wire::{IcmpEchoReply, IcmpEchoRequest};

use crate::icmp_mediator::MediatorHello;

/// The host refused the echo. A policy answer, not a failure to reach it.
///
/// Distinguished from every other error so a caller can say which one happened:
/// pointing at `--allow-host` when the mediator itself was unreachable sends
/// the user to fix a flag that was never the problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// One echo's outcome as the guest saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchoOutcome {
    /// A reply came back.
    Reply {
        /// Sequence number, from zero.
        seq: u16,
        /// The address the host echoed.
        ip: String,
        /// Guest end-to-end round trip: loopback out, vsock, host mediation,
        /// network, and back. This is what the workload experiences.
        rtt: Duration,
        /// The host's own leg, for comparison against `rtt`.
        host_leg: Duration,
        /// Payload bytes echoed.
        payload_len: u16,
    },
    /// No reply inside the per-echo timeout.
    Timeout {
        /// Sequence number, from zero.
        seq: u16,
    },
}

/// Ask the host to echo `request`, returning one outcome per sequence.
///
/// Each echo is sent and awaited on its own, because that is the only way its
/// round trip is real. Writing them all and then timing the reply lines as they
/// are read measures the reader's buffer, not the network: later lines are
/// already in memory and clock in at ~0 ms. `ping` times each packet separately
/// and so does this.
///
/// A refusal is an error rather than an outcome: it is terminal and applies to
/// the whole request, so the caller should print the reason rather than report
/// loss.
pub fn echo(request: &IcmpEchoRequest, host_wait_slack_secs: u64) -> Result<Vec<EchoOutcome>> {
    request
        .validate()
        .map_err(|bounds| anyhow::anyhow!("{bounds}"))?;

    // Outlast the host's own wait, or the guest reports a failure for a reply
    // the host is still legitimately waiting on.
    let budget = Duration::from_millis(u64::from(request.timeout_ms))
        .saturating_add(Duration::from_secs(host_wait_slack_secs));
    let mut mediator = Mediator::connect(budget)?;

    let mut outcomes = Vec::with_capacity(usize::from(request.count));
    for seq in 0..request.count {
        outcomes.push(mediator.echo_once(request, seq)?);
    }
    Ok(outcomes)
}

/// An open conversation with the guest's ICMP mediator.
struct Mediator {
    writer: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Mediator {
    /// Dial the mediator and wait for it to announce a session.
    ///
    /// The hello is read here rather than folded into the first echo so that
    /// session setup lands outside every timer.
    fn connect(budget: Duration) -> Result<Self> {
        let stream = TcpStream::connect(ICMP_MEDIATOR_LISTEN).with_context(|| {
            format!(
                "connect to the guest ICMP mediator on {ICMP_MEDIATOR_LISTEN} \
                 (served by the egress client, which a run with no admitted egress \
                 does not start)"
            )
        })?;
        stream
            .set_read_timeout(Some(budget))
            .context("set the mediator read timeout")?;
        // Nagle would hold a short request back waiting for more, which on a
        // request/reply exchange is added latency inside the number being
        // reported.
        stream.set_nodelay(true).ok();

        let mut mediator = Self {
            writer: stream.try_clone().context("clone the mediator socket")?,
            reader: BufReader::new(stream),
        };
        match mediator.read_line().context("read the mediator hello")? {
            Some(line) => match serde_json::from_str::<MediatorHello>(&line)
                .context("decode the mediator hello")?
            {
                MediatorHello::Ready => Ok(mediator),
                MediatorHello::Unavailable { message } => bail!("{message}"),
            },
            None => bail!("the ICMP mediator closed the connection without a hello"),
        }
    }

    /// One echo, timed guest-side across the whole path.
    fn echo_once(&mut self, request: &IcmpEchoRequest, seq: u16) -> Result<EchoOutcome> {
        // One echo per request; the sequence the guest reports is its own.
        let single = IcmpEchoRequest {
            host: request.host.clone(),
            count: 1,
            payload_len: request.payload_len,
            timeout_ms: request.timeout_ms,
        };
        let mut encoded = serde_json::to_vec(&single).context("encode the echo request")?;
        encoded.push(b'\n');

        let started = Instant::now();
        self.writer
            .write_all(&encoded)
            .context("send the echo request to the mediator")?;
        self.writer.flush().context("flush the echo request")?;
        let line = self
            .read_line()
            .context("read the echo reply")?
            .ok_or_else(|| anyhow::anyhow!("the ICMP mediator closed before answering"))?;
        let rtt = started.elapsed();

        match serde_json::from_str::<IcmpEchoReply>(&line).context("decode the echo reply")? {
            IcmpEchoReply::Reply {
                ip,
                host_leg_us,
                payload_len,
                ..
            } => Ok(EchoOutcome::Reply {
                seq,
                ip,
                rtt,
                host_leg: Duration::from_micros(host_leg_us),
                payload_len,
            }),
            IcmpEchoReply::Timeout { .. } => Ok(EchoOutcome::Timeout { seq }),
            IcmpEchoReply::Refused { message } => Err(Refused(message).into()),
        }
    }

    /// Read one line, `None` at a clean end of stream.
    fn read_line(&mut self) -> Result<Option<String>> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim().to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};

    /// Stand in for the mediator: announce `hello`, then answer each request
    /// line with the next canned reply.
    fn fake_mediator(hello: MediatorHello, replies: Vec<IcmpEchoReply>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            let mut writer = conn.try_clone().unwrap();
            let mut reader = BufReader::new(conn);
            writeln!(writer, "{}", serde_json::to_string(&hello).unwrap()).unwrap();
            for reply in replies {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    return;
                }
                writeln!(writer, "{}", serde_json::to_string(&reply).unwrap()).unwrap();
            }
        });
        addr
    }

    /// Drive the client against `addr` rather than the fixed mediator address,
    /// so the tests need no VM and no fixed port.
    fn echo_against(addr: SocketAddr, request: &IcmpEchoRequest) -> Result<Vec<EchoOutcome>> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut mediator = Mediator {
            writer: stream.try_clone()?,
            reader: BufReader::new(stream),
        };
        let hello = mediator.read_line()?.expect("the mediator sends a hello");
        match serde_json::from_str::<MediatorHello>(&hello)? {
            MediatorHello::Ready => {}
            MediatorHello::Unavailable { message } => bail!("{message}"),
        }
        (0..request.count)
            .map(|seq| mediator.echo_once(request, seq))
            .collect()
    }

    fn request(count: u16) -> IcmpEchoRequest {
        IcmpEchoRequest {
            host: "example.com".into(),
            count,
            payload_len: 56,
            timeout_ms: 1000,
        }
    }

    /// The request the guest puts on the wire carries exactly one echo, whatever
    /// the caller asked for in total: batching is what made the round trips
    /// meaningless.
    #[test]
    fn each_wire_request_carries_a_single_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let asked = request(3);
        let seen = std::thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            let mut writer = conn.try_clone().unwrap();
            let mut reader = BufReader::new(conn);
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&MediatorHello::Ready).unwrap()
            )
            .unwrap();
            let mut requests = Vec::new();
            for _ in 0..3 {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                requests.push(serde_json::from_str::<IcmpEchoRequest>(line.trim()).unwrap());
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&IcmpEchoReply::Timeout { seq: 0 }).unwrap()
                )
                .unwrap();
            }
            requests
        });

        echo_against(addr, &asked).unwrap();
        let requests = seen.join().unwrap();
        assert_eq!(requests.len(), 3, "one request per echo, not one batch");
        for sent in requests {
            assert_eq!(sent.count, 1);
            assert_eq!(sent.host, asked.host);
            assert_eq!(sent.payload_len, asked.payload_len);
            assert_eq!(sent.timeout_ms, asked.timeout_ms);
        }
    }

    /// An out-of-bounds request is refused before anything is dialled, so a bad
    /// `-c` costs nothing.
    #[test]
    fn an_invalid_request_is_refused_before_dialling() {
        let bad = IcmpEchoRequest {
            host: String::new(),
            count: 1,
            payload_len: 0,
            timeout_ms: 1,
        };
        assert!(echo(&bad, 1).is_err());
    }

    /// The reply's own fields reach the caller, including the host's leg — the
    /// number that makes mediation cost visible rather than folding it into the
    /// round trip.
    #[test]
    fn a_reply_carries_the_address_and_the_host_leg() {
        let addr = fake_mediator(
            MediatorHello::Ready,
            vec![IcmpEchoReply::Reply {
                seq: 0,
                ip: "93.184.216.34".into(),
                host_leg_us: 12_500,
                payload_len: 56,
            }],
        );
        let outcomes = echo_against(addr, &request(1)).unwrap();
        match &outcomes[0] {
            EchoOutcome::Reply {
                ip,
                host_leg,
                payload_len,
                ..
            } => {
                assert_eq!(ip, "93.184.216.34");
                assert_eq!(*host_leg, Duration::from_micros(12_500));
                assert_eq!(*payload_len, 56);
            }
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    /// A refusal is typed, so the caller can point at `--allow-host` for a
    /// policy answer and stay quiet about it for anything else.
    #[test]
    fn a_refusal_is_distinguishable_from_a_transport_failure() {
        let refused = fake_mediator(
            MediatorHello::Ready,
            vec![IcmpEchoReply::Refused {
                message: "host not admitted by policy".into(),
            }],
        );
        let error = echo_against(refused, &request(1)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Refused>(),
            Some(&Refused("host not admitted by policy".into()))
        );

        let unavailable = fake_mediator(
            MediatorHello::Unavailable {
                message: "no FlowMux session".into(),
            },
            Vec::new(),
        );
        let error = echo_against(unavailable, &request(1)).unwrap_err();
        assert!(
            error.downcast_ref::<Refused>().is_none(),
            "an unreachable mediator is not a policy refusal"
        );
    }
}
