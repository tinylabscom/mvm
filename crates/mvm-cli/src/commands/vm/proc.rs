//! `mvmctl proc <verb> <vm> <args>` — process control RPC against
//! a running microVM.
//!
//! **Dev-only.** Production guest agents strip the handler module,
//! so calls against a prod agent return
//! `ProcErrorKind::UnsupportedInProduction`. The host CLI
//! surface is always available — only the guest-side handler is
//! gated.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use std::collections::BTreeMap;
use std::io::Write;

use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_guest::vsock::{GuestRequest, ProcResult, ProcWaitEvent};

use super::Cli;
use super::shared::clap_vm_name;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: ProcCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ProcCmd {
    /// Spawn a process inside the VM
    Start {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Absolute path of the program plus its arguments. Use `--`
        /// before the argv to separate it from `mvmctl proc start`
        /// flags.
        #[arg(num_args = 1..)]
        argv: Vec<String>,
        /// Environment variable in `KEY=VALUE` form. Repeatable.
        #[arg(short = 'e', long = "env")]
        envs: Vec<String>,
        /// Working directory inside the VM
        #[arg(long)]
        cwd: Option<String>,
    },
    /// List processes tracked by the VM agent
    Ls {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Send a signal to a process (numeric `signum`).
    Signal {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// `pid_token` returned by `mvmctl proc start`
        token: String,
        /// Signal number (e.g. 15 for SIGTERM, 2 for SIGINT)
        signum: i32,
    },
    /// Send SIGKILL to a process
    Kill {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// `pid_token` returned by `mvmctl proc start`
        token: String,
    },
    /// Append stdin (or `--content`) to a process's stdin pipe
    Stdin {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// `pid_token` returned by `mvmctl proc start`
        token: String,
        /// Inline content (otherwise stdin is read from mvmctl's stdin)
        #[arg(long)]
        content: Option<String>,
    },
    /// Wait for a process to exit, streaming stdout / stderr to mvmctl's stdout / stderr
    Wait {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// `pid_token` returned by `mvmctl proc start`
        token: String,
        /// Optional timeout in seconds — agent kills the pgroup if it elapses
        #[arg(long)]
        timeout: Option<u64>,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        ProcCmd::Start {
            name,
            argv,
            envs,
            cwd,
        } => cmd_start(&name, &argv, &envs, cwd.as_deref()),
        ProcCmd::Ls { name, json } => cmd_ls(&name, json),
        ProcCmd::Signal {
            name,
            token,
            signum,
        } => cmd_signal(&name, &token, signum),
        ProcCmd::Kill { name, token } => cmd_kill(&name, &token),
        ProcCmd::Stdin {
            name,
            token,
            content,
        } => cmd_stdin(&name, &token, content),
        ProcCmd::Wait {
            name,
            token,
            timeout,
        } => cmd_wait(&name, &token, timeout),
    }
}

/// Send a non-streaming proc-control RPC to `name`'s guest agent over the
/// backend-aware transport. Like `fs::fs_request`, the
/// `--hypervisor mock` fast path (a mock agent at the VM dir's
/// `runtime/v.sock`) stays ahead of the `vsock_transport::for_vm` probe,
/// which resolves the right socket per VMM (Firecracker's `v.sock`, or the
/// per-port UNIX socket libkrun/QEMU expose) but is unaware of the in-memory
/// mock backend.
fn proc_request(name: &str, req: GuestRequest) -> Result<ProcResult> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    let mock_dir = mvm_backend::MockBackend::vm_dir(name);
    if mock_dir.join("runtime").join("v.sock").exists() {
        return mvm_guest::vsock::send_proc_request(&mock_dir.to_string_lossy(), req);
    }
    let mut stream =
        mvm::vsock_transport::for_vm(name)?.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::send_proc_request_on(&mut stream, req)
}

/// Stream a `ProcWait` for `name`'s guest agent over the backend-aware
/// transport, same mock-vs-`for_vm` resolution as [`proc_request`].
fn proc_wait<F: FnMut(&ProcWaitEvent)>(
    name: &str,
    token: &str,
    timeout: Option<u64>,
    on_event: F,
) -> Result<ProcWaitEvent> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    let mock_dir = mvm_backend::MockBackend::vm_dir(name);
    if mock_dir.join("runtime").join("v.sock").exists() {
        return mvm_guest::vsock::send_proc_wait(
            &mock_dir.to_string_lossy(),
            token,
            timeout,
            on_event,
        );
    }
    let mut stream =
        mvm::vsock_transport::for_vm(name)?.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::send_proc_wait_on(&mut stream, token, timeout, on_event)
}

fn unwrap_proc(result: ProcResult) -> Result<ProcResult> {
    if let ProcResult::Error { kind, message } = &result {
        bail!("Guest proc error ({:?}): {}", kind, message);
    }
    Ok(result)
}

fn parse_envs(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for s in raw {
        let (k, v) = s
            .split_once('=')
            .with_context(|| format!("Invalid --env value (expected KEY=VALUE): {:?}", s))?;
        if k.is_empty() {
            bail!("env key cannot be empty: {:?}", s);
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

fn cmd_start(name: &str, argv: &[String], envs: &[String], cwd: Option<&str>) -> Result<()> {
    if argv.is_empty() {
        bail!("argv cannot be empty");
    }
    let env = parse_envs(envs)?;
    let req = GuestRequest::ProcStart {
        argv: argv.to_vec(),
        env,
        cwd: cwd.map(str::to_string),
        stdin: vec![],
        timeout_secs: None,
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_proc(proc_request(name, req)?)?;
    match result {
        ProcResult::Started { pid_token } => {
            println!("{pid_token}");
            mvm_core::audit_emit!(VmProcStart, vm: name, "argv0={} token={pid_token}" , argv[0]);
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for Start: {:?}", other),
    }
}

fn cmd_ls(name: &str, json: bool) -> Result<()> {
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &GuestRequest::ProcList);
    let result = unwrap_proc(proc_request(name, GuestRequest::ProcList)?)?;
    match result {
        ProcResult::List { processes } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&processes)?);
                return Ok(());
            }
            if processes.is_empty() {
                println!("(no tracked processes)");
                return Ok(());
            }
            println!("{:<28} {:<22} {:<10} ARGV0", "TOKEN", "STARTED", "STATE");
            for p in &processes {
                let state = match &p.state {
                    mvm_guest::vsock::ProcState::Running => "running".to_string(),
                    mvm_guest::vsock::ProcState::Exited(c) => format!("exited({c})"),
                    mvm_guest::vsock::ProcState::Killed(s) => format!("killed({s})"),
                    mvm_guest::vsock::ProcState::TimedOut => "timed_out".to_string(),
                };
                println!(
                    "{:<28} {:<22} {:<10} {}",
                    p.pid_token, p.started_at, state, p.argv0
                );
            }
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for List: {:?}", other),
    }
}

fn cmd_signal(name: &str, token: &str, signum: i32) -> Result<()> {
    let req = GuestRequest::ProcSignal {
        pid_token: token.to_string(),
        signum,
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_proc(proc_request(name, req)?)?;
    match result {
        ProcResult::Signaled => {
            mvm_core::audit_emit!(VmProcSignal, vm: name, "token={token} signum={signum}");
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for Signal: {:?}", other),
    }
}

fn cmd_kill(name: &str, token: &str) -> Result<()> {
    let req = GuestRequest::ProcKill {
        pid_token: token.to_string(),
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_proc(proc_request(name, req)?)?;
    match result {
        ProcResult::Killed => {
            mvm_core::audit_emit!(Kill, vm: name, "scope=guest_proc token={token}");
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for Kill: {:?}", other),
    }
}

fn cmd_stdin(name: &str, token: &str, content: Option<String>) -> Result<()> {
    use std::io::Read;
    let bytes = match content {
        Some(s) => s.into_bytes(),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };
    let req = GuestRequest::ProcSendInput {
        pid_token: token.to_string(),
        bytes,
    };
    // Inbound vsock RPC audit.
    super::shared::emit_vsock_rpc_audit(name, &req);
    let result = unwrap_proc(proc_request(name, req)?)?;
    match result {
        ProcResult::InputAccepted { bytes_accepted } => {
            eprintln!("accepted {bytes_accepted} bytes");
            mvm_core::audit_emit!(VmProcStdin, vm: name, "token={token} bytes={bytes_accepted}");
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for SendInput: {:?}", other),
    }
}

fn cmd_wait(name: &str, token: &str, timeout: Option<u64>) -> Result<()> {
    // Inbound vsock RPC audit. The `proc_wait` helper constructs
    // the wire-format ProcWait internally; we synthesize an
    // equivalent request here purely so the audit kind_name lines
    // up with what the guest receives.
    super::shared::emit_vsock_rpc_audit(
        name,
        &GuestRequest::ProcWait {
            pid_token: token.to_string(),
            timeout_secs: timeout,
        },
    );
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let terminal = proc_wait(name, token, timeout, |ev| match ev {
        ProcWaitEvent::Stdout { chunk } => {
            let _ = stdout.write_all(chunk);
            let _ = stdout.flush();
        }
        ProcWaitEvent::Stderr { chunk } => {
            let _ = stderr.write_all(chunk);
            let _ = stderr.flush();
        }
        ProcWaitEvent::Backpressure { reason, detail } => {
            // A streaming resource is throttled. Surface the typed
            // reason + bounded detail to stderr with a clearly-labeled
            // prefix so the wait continues without polluting the
            // captured stdout the user is consuming. `detail` is
            // metadata-only (byte counts, threshold, cap) —
            // payload bytes never appear here.
            let _ = writeln!(stderr, "[mvmctl-backpressure] {reason:?}: {detail}");
            let _ = stderr.flush();
        }
        _ => {}
    })?;
    drop(stdout);
    drop(stderr);

    match terminal {
        ProcWaitEvent::Exit { code } => std::process::exit(code),
        ProcWaitEvent::Killed { signal } => {
            eprintln!("killed by signal {signal}");
            std::process::exit(128 + signal);
        }
        ProcWaitEvent::TimedOut => {
            eprintln!("timed out");
            std::process::exit(124);
        }
        ProcWaitEvent::Error { kind, message } => {
            bail!("ProcWait error ({:?}): {}", kind, message)
        }
        other => bail!("Unexpected terminal event: {:?}", other),
    }
}
