//! `mvm-ping` — `ping` for a NIC-less guest.
//!
//! Installed ahead of busybox on `PATH`, so `ping example.com` inside a workload
//! resolves to this rather than to a binary that will fail at `socket()`. A
//! NIC-less guest has no route and no raw socket; the host echoes on its behalf
//! over vsock, gated by the same allow-list every other egress verb uses. The
//! workload cannot open that vsock session itself — the guest identity is
//! root-only — so this asks the guest's loopback mediator, the same way a
//! workload's HTTP reaches the host through the loopback proxy.
//!
//! Output is ping-shaped on purpose — the familiar lines are the point of
//! shadowing `ping` at all — with one addition: each reply reports the host's own
//! leg alongside the round trip. The round trip is the guest's true end-to-end
//! time, vsock hop and mediation included, because that is the path a workload's
//! traffic actually takes; the host leg makes the mediation cost visible instead
//! of folding it invisibly into the total.

use std::process::ExitCode;

use mvm_core::icmp_wire::{IcmpEchoRequest, MAX_ECHO_COUNT, MAX_PAYLOAD_LEN};

/// `ping`'s own default payload, so a default run is comparable to one.
const DEFAULT_PAYLOAD_LEN: u16 = 56;
/// Per-echo wait, matching `ping`'s customary default.
const DEFAULT_TIMEOUT_MS: u32 = 4_000;
/// Default echo count. Unlike `ping`, this terminates: a workload's `ping` with
/// no bound is a hang in a place nobody is watching.
const DEFAULT_COUNT: u16 = 4;
/// Slack over the per-echo wait before giving up on the mediator, which is
/// waiting on the host in turn.
const HOST_WAIT_SLACK_SECS: u64 = 10;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("mvm-ping: {message}");
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match mvm_agentd::icmp_client::echo(&parsed, HOST_WAIT_SLACK_SECS) {
        Ok(outcomes) => report(&parsed, &outcomes),
        Err(error) => {
            // A refusal is the common case here and it is a policy answer, not
            // a crash: say what the host said and point at the flag that fixes
            // it. Only for a refusal, though — printing the flag hint after a
            // transport failure sends the reader to re-check a flag they
            // already passed, which is the one place the message must not
            // point.
            eprintln!("mvm-ping: {error:#}");
            if error
                .downcast_ref::<mvm_agentd::icmp_client::Refused>()
                .is_some()
            {
                eprintln!(
                    "mvm-ping: a host must be admitted to be pinged — \
                     pass `--allow-host {}` to the run",
                    parsed.host
                );
            }
            ExitCode::from(2)
        }
    }
}

const USAGE: &str = "\
usage: ping [-c count] [-s payload] [-W timeout_ms] <host>

Echoes <host> through the host, which performs the ICMP on this guest's behalf:
a NIC-less guest has no raw socket of its own. <host> must be admitted by the
run's egress policy (`--allow-host`).

  -c count       echoes to send (default 4, max 64)
  -s payload     payload bytes (default 56, max 1024)
  -W timeout_ms  per-echo wait in milliseconds (default 4000)
";

/// Parse the `ping`-compatible subset. `Ok(None)` means help was requested.
fn parse_args(args: &[String]) -> Result<Option<IcmpEchoRequest>, String> {
    let mut count = DEFAULT_COUNT;
    let mut payload_len = DEFAULT_PAYLOAD_LEN;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut host = None;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "-c" => count = take_number(&mut rest, "-c")?,
            "-s" => payload_len = take_number(&mut rest, "-s")?,
            "-W" => timeout_ms = take_number(&mut rest, "-W")?,
            other if other.starts_with('-') => {
                return Err(format!("unsupported option {other}"));
            }
            other => {
                if host.replace(other.to_string()).is_some() {
                    return Err("only one host may be given".to_string());
                }
            }
        }
    }

    let host = host.ok_or("a host is required")?;
    // Bounds are the wire contract's, reported here so the message names the
    // flag the caller typed rather than a field name they never saw.
    if count == 0 || count > MAX_ECHO_COUNT {
        return Err(format!("-c must be between 1 and {MAX_ECHO_COUNT}"));
    }
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(format!("-s must be at most {MAX_PAYLOAD_LEN}"));
    }
    Ok(Some(IcmpEchoRequest {
        host,
        count,
        payload_len,
        timeout_ms,
    }))
}

fn take_number<'a, T: std::str::FromStr>(
    rest: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<T, String> {
    let raw = rest.next().ok_or(format!("{flag} needs a value"))?;
    raw.parse()
        .map_err(|_| format!("{flag} value {raw:?} is not a number"))
}

/// Print ping-shaped output and pick the exit code.
fn report(
    request: &IcmpEchoRequest,
    outcomes: &[mvm_agentd::icmp_client::EchoOutcome],
) -> ExitCode {
    use mvm_agentd::icmp_client::EchoOutcome;

    println!(
        "PING {} ({} bytes) via host",
        request.host, request.payload_len
    );
    let mut received = 0usize;
    for outcome in outcomes {
        match outcome {
            EchoOutcome::Reply {
                seq,
                ip,
                rtt,
                host_leg,
                payload_len,
            } => {
                received += 1;
                println!(
                    "{payload_len} bytes from {ip}: seq={seq} time={:.1} ms (host leg {:.1} ms)",
                    rtt.as_secs_f64() * 1000.0,
                    host_leg.as_secs_f64() * 1000.0,
                );
            }
            EchoOutcome::Timeout { seq } => {
                println!("no reply: seq={seq}");
            }
        }
    }
    let sent = outcomes.len();
    let loss = if sent == 0 {
        100.0
    } else {
        (sent - received) as f64 * 100.0 / sent as f64
    };
    println!("--- {} statistics ---", request.host);
    println!("{sent} sent, {received} received, {loss:.0}% packet loss");

    // `ping`'s convention: any reply is success.
    if received > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_bare_host_uses_the_ping_defaults() {
        let parsed = parse_args(&args(&["example.com"])).unwrap().unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.count, DEFAULT_COUNT);
        assert_eq!(parsed.payload_len, DEFAULT_PAYLOAD_LEN);
        assert_eq!(parsed.timeout_ms, DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn flags_override_the_defaults_in_either_order() {
        let parsed = parse_args(&args(&["-c", "2", "-s", "8", "-W", "500", "host.test"]))
            .unwrap()
            .unwrap();
        assert_eq!(
            (parsed.count, parsed.payload_len, parsed.timeout_ms),
            (2, 8, 500)
        );

        let trailing = parse_args(&args(&["host.test", "-c", "9"]))
            .unwrap()
            .unwrap();
        assert_eq!(trailing.count, 9);
        assert_eq!(trailing.host, "host.test");
    }

    #[test]
    fn help_is_not_an_error() {
        assert_eq!(parse_args(&args(&["--help"])), Ok(None));
        assert_eq!(parse_args(&args(&["-h"])), Ok(None));
    }

    /// The bounds are reported against the flag the caller typed, because a
    /// message naming `count` when they wrote `-c` sends them looking in the
    /// wrong place.
    #[test]
    fn out_of_range_flags_name_the_flag() {
        let err = parse_args(&args(&["-c", "9999", "h.test"])).unwrap_err();
        assert!(err.contains("-c"), "{err}");
        let err = parse_args(&args(&["-s", "99999", "h.test"])).unwrap_err();
        assert!(err.contains("-s"), "{err}");
    }

    #[test]
    fn missing_or_duplicate_hosts_are_rejected() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["a.test", "b.test"])).is_err());
    }

    #[test]
    fn unsupported_options_are_rejected_rather_than_ignored() {
        let err = parse_args(&args(&["-Q", "1", "h.test"])).unwrap_err();
        assert!(err.contains("-Q"), "{err}");
    }

    #[test]
    fn a_flag_without_its_value_is_an_error() {
        assert!(parse_args(&args(&["-c"])).is_err());
        assert!(parse_args(&args(&["-c", "notanumber", "h.test"])).is_err());
    }
}
