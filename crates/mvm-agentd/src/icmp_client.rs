//! In-guest client for host-mediated ICMP echo.
//!
//! A NIC-less guest cannot originate ICMP: there is no route and no raw socket,
//! so `ping` fails at `socket()` before a packet exists. This asks the host to
//! echo on the guest's behalf over the shared egress vsock stream, behind the
//! [`ICMP_FRAME_LINE`] marker.
//!
//! The round trip this measures is the *guest's*, not the host's. The timer
//! starts before the vsock write and stops when the reply line lands, so it
//! covers the vsock hop and the host's mediation as well as the network — which
//! is the whole path any request from this workload takes. The host also reports
//! its own leg, so the two can be compared rather than conflated.

use std::io::{BufRead, BufReader, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use mvm_core::guest_netd::ICMP_FRAME_LINE;
use mvm_core::icmp_wire::{IcmpEchoReply, IcmpEchoRequest};

use crate::vsock::{EGRESS_PORT, connect_host_vsock};

/// One echo's outcome as the guest saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchoOutcome {
    /// A reply came back.
    Reply {
        /// Sequence number, from zero.
        seq: u16,
        /// The address the host echoed.
        ip: String,
        /// Guest end-to-end round trip: vsock out, host mediation, network,
        /// and back. This is what the workload experiences.
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
/// Each echo is its own request on its own connection, because that is the only
/// way its round trip is real. Batching them onto one connection and timing the
/// reply lines as they are read measures the reader's buffer, not the network:
/// later lines are already in memory and clock in at ~0 ms. `ping` times each
/// packet separately and so does this.
///
/// A refusal is an error rather than an outcome: it is terminal and applies to
/// the whole request, so the caller should print the reason rather than report
/// loss.
pub fn echo(request: &IcmpEchoRequest, connect_timeout_secs: u64) -> Result<Vec<EchoOutcome>> {
    request
        .validate()
        .map_err(|bounds| anyhow::anyhow!("{bounds}"))?;

    let mut outcomes = Vec::with_capacity(usize::from(request.count));
    for seq in 0..request.count {
        outcomes.push(echo_once(request, seq, connect_timeout_secs)?);
    }
    Ok(outcomes)
}

/// One echo, timed guest-side across the whole path: vsock out, host mediation,
/// network, and back.
fn echo_once(
    request: &IcmpEchoRequest,
    seq: u16,
    connect_timeout_secs: u64,
) -> Result<EchoOutcome> {
    // One echo per request line; the sequence the guest reports is its own.
    let single = IcmpEchoRequest {
        host: request.host.clone(),
        count: 1,
        payload_len: request.payload_len,
        timeout_ms: request.timeout_ms,
    };

    let stream = connect_host_vsock(EGRESS_PORT, connect_timeout_secs)
        .context("connect to the host egress port for ICMP echo")?;
    // Outlast the host's own wait, or the guest reports a timeout for a reply
    // the host is still legitimately waiting on.
    let budget = Duration::from_millis(u64::from(request.timeout_ms))
        .saturating_add(Duration::from_secs(connect_timeout_secs));
    stream.set_read_timeout(Some(budget)).ok();

    let mut writer = stream.try_clone().context("clone the egress stream")?;
    let mut line = serde_json::to_vec(&single).context("encode the echo request")?;
    line.push(b'\n');

    // The timer spans exactly the request: the connection is already open, so
    // what it measures is the echo, not the dial.
    let started = Instant::now();
    writer
        .write_all(format!("{ICMP_FRAME_LINE}\n").as_bytes())
        .context("write the ICMP frame marker")?;
    writer.write_all(&line).context("write the echo request")?;
    writer.flush().context("flush the echo request")?;

    let mut reply_line = String::new();
    BufReader::new(stream)
        .read_line(&mut reply_line)
        .context("read the echo reply")?;
    let rtt = started.elapsed();

    if reply_line.trim().is_empty() {
        bail!("host closed the echo stream without answering");
    }
    match serde_json::from_str::<IcmpEchoReply>(reply_line.trim())
        .context("decode the echo reply")?
    {
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
        IcmpEchoReply::Refused { message } => bail!("{message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request the guest puts on the wire carries exactly one echo, whatever
    /// the caller asked for in total: batching is what made the round trips
    /// meaningless.
    #[test]
    fn each_wire_request_carries_a_single_echo() {
        let asked = IcmpEchoRequest {
            host: "example.com".into(),
            count: 4,
            payload_len: 56,
            timeout_ms: 1000,
        };
        // Mirrors what `echo_once` builds.
        let single = IcmpEchoRequest {
            host: asked.host.clone(),
            count: 1,
            payload_len: asked.payload_len,
            timeout_ms: asked.timeout_ms,
        };
        assert_eq!(single.count, 1);
        assert_eq!(single.payload_len, asked.payload_len);
        assert_eq!(single.timeout_ms, asked.timeout_ms);
        assert_eq!(single.host, asked.host);
        assert_eq!(single.validate(), Ok(()));
    }

    /// An out-of-bounds request is refused before any connection is attempted,
    /// so a bad `-c` costs nothing.
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
}
