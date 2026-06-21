//! Live over-the-wire driver for a single `FlakeCheck` against a running
//! builder daemon.
//!
//! `mvmctl doctor` only proves the handshake reaches the resident daemon.
//! This harness exercises a real typed operation end-to-end: connect the
//! host-side [`BuilderdClient`] to the per-port control socket a running
//! builder VM forwards, send one `FlakeCheck`, stream every progress/log
//! frame the daemon emits, and print the terminal outcome. It stages no
//! source — `--flake` is a path *inside the builder VM*, so the caller is
//! responsible for the flake already being reachable there.
//!
//! It is a diagnostic, not a build-routing path: it drives exactly one
//! allowlisted operation and exits.
//!
//! Usage:
//!
//!   builderd-flakecheck --socket <vsock-21473.sock> --flake <guest-path>
//!                       [--timeout-secs <n>]
//!
//! Exit codes: 0 on `Completed`; 1 on any other typed terminal
//! (`Failed`/`Cancelled`/artifact/store-path, none of which a flake
//! check should produce); 2 on a connect/transport/protocol error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use mvm_build::builderd_client::{BuilderdClient, OperationEvent, OperationOutcome};
use mvm_build::builderd_protocol::{BuilderRequest, OperationId};

struct Args {
    socket: PathBuf,
    flake: String,
    timeout: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut socket: Option<PathBuf> = None;
    let mut flake: Option<String> = None;
    let mut timeout = Duration::from_secs(120);
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => socket = Some(PathBuf::from(next(&mut it, "--socket")?)),
            "--flake" => flake = Some(next(&mut it, "--flake")?),
            "--timeout-secs" => {
                let secs: u64 = next(&mut it, "--timeout-secs")?
                    .parse()
                    .map_err(|e| format!("--timeout-secs: {e}"))?;
                timeout = Duration::from_secs(secs);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        socket: socket.ok_or("missing --socket")?,
        flake: flake.ok_or("missing --flake")?,
        timeout,
    })
}

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    println!(
        "connecting to {} (timeout {:?})",
        args.socket.display(),
        args.timeout
    );
    let mut client = match BuilderdClient::connect(&args.socket, args.timeout) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect failed: {e}");
            return ExitCode::from(2);
        }
    };
    println!("handshake OK — protocol v{}", client.negotiated_version());

    let request = BuilderRequest::FlakeCheck {
        op: OperationId::new(),
        flake_path: args.flake.clone(),
    };
    println!("FlakeCheck flake_path={}", args.flake);

    let mut sink = |event: OperationEvent| match event {
        OperationEvent::Progress { fraction, label } => {
            println!("  progress {:>5.1}% {label}", fraction * 100.0)
        }
        OperationEvent::Log { text } => print!("  log: {text}"),
    };

    match client.run_operation(&request, &mut sink) {
        Ok(OperationOutcome::Completed) => {
            println!("outcome: Completed (flake check passed)");
            ExitCode::SUCCESS
        }
        Ok(outcome) => {
            println!("outcome: {outcome:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("operation error: {e}");
            ExitCode::from(2)
        }
    }
}
