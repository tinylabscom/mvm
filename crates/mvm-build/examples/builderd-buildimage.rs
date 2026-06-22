//! Live over-the-wire driver for a single `BuildGuestImage` against a running
//! builder daemon.
//!
//! Sibling of `builderd-flakecheck`: connects the host-side [`BuilderdClient`]
//! to the per-port control socket a running builder VM forwards, sends one
//! `BuildGuestImage` for an in-guest `<flake>#<attr>`, streams progress/log
//! frames, and prints the terminal store path. It stages no source — `--flake`
//! is a path *inside the builder VM* (e.g. `/work/nix/images/default-tenant`),
//! so the caller is responsible for the flake already being reachable there.
//!
//! Used to prove the typed `BuildGuestImage` dispatch is artifact-equal to the
//! legacy shell dispatch: both run the identical `nix build <ref>#<attr>
//! --no-link --print-out-paths`, so the reported store path (a content hash)
//! must match. Compare this tool's store path against a plain in-VM `nix build`
//! of the same target.
//!
//! Usage:
//!
//!   builderd-buildimage --socket <vsock-21473.sock> --flake <guest-path>
//!                       --attr <attr-path> [--timeout-secs <n>]
//!
//! Exit codes: 0 on a store-path-bearing terminal (store path printed on the
//! `store-path=` line); 1 on any other typed terminal; 2 on a
//! connect/transport/protocol error.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use mvm_build::builderd_client::{BuilderdClient, OperationEvent, OperationOutcome};
use mvm_build::builderd_protocol::{BuilderRequest, OperationId};

struct Args {
    socket: PathBuf,
    flake: String,
    attr: String,
    timeout: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut socket: Option<PathBuf> = None;
    let mut flake: Option<String> = None;
    let mut attr: Option<String> = None;
    let mut timeout = Duration::from_secs(1800);
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => socket = Some(PathBuf::from(next(&mut it, "--socket")?)),
            "--flake" => flake = Some(next(&mut it, "--flake")?),
            "--attr" => attr = Some(next(&mut it, "--attr")?),
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
        attr: attr.ok_or("missing --attr")?,
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

    let request = BuilderRequest::BuildGuestImage {
        op: OperationId::new(),
        flake_ref: args.flake.clone(),
        attr_path: args.attr.clone(),
        fingerprint: None,
        output_dir: None,
    };
    println!(
        "BuildGuestImage flake_ref={} attr={}",
        args.flake, args.attr
    );

    let mut sink = |event: OperationEvent| match event {
        OperationEvent::Progress { fraction, label } => {
            println!("  progress {:>5.1}% {label}", fraction * 100.0)
        }
        OperationEvent::Log { text } => print!("  log: {text}"),
    };

    match client.run_operation(&request, &mut sink) {
        Ok(OperationOutcome::Artifact { store_path, .. }) => {
            let path = store_path.unwrap_or_default();
            println!("store-path={path}");
            ExitCode::SUCCESS
        }
        Ok(OperationOutcome::StorePath { store_path, .. }) => {
            println!("store-path={store_path}");
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
