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

use mvm_agentd::vsock::ProcWaitEvent;
use mvm_client::guest;
use mvm_core::env_hygiene::{EnvFilter, EnvReadmit};
use mvm_core::user_config::MvmConfig;

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
        /// Re-admit a denied env variable by exact name. Repeatable.
        #[arg(long = "allow-env", value_name = "NAME")]
        allow_env: Vec<String>,
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
            allow_env,
            cwd,
        } => cmd_start(&name, proc_start(argv, &envs, &allow_env, cwd)?),
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

/// The start request for `proc start`: parsed `--env`, refused if it carries
/// a denied variable the caller did not re-admit with `--allow-env`.
fn proc_start(
    argv: Vec<String>,
    envs: &[String],
    allow_env: &[String],
    cwd: Option<String>,
) -> Result<guest::ProcStart> {
    let env = parse_envs(envs)?;
    let allow_env = EnvReadmit::from_names(allow_env).context("--allow-env")?;
    super::exec::env_args::refuse(
        &EnvFilter::new(allow_env.clone()),
        env.keys().map(String::as_str),
        "--env",
    )?;
    Ok(guest::ProcStart {
        argv,
        env,
        cwd,
        allow_env,
    })
}

fn cmd_start(name: &str, start: guest::ProcStart) -> Result<()> {
    let token = guest::start_process(name, start)?;
    println!("{token}");
    Ok(())
}

fn cmd_ls(name: &str, json: bool) -> Result<()> {
    let processes = guest::list_processes(name)?;
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
            mvm_agentd::vsock::ProcState::Running => "running".to_string(),
            mvm_agentd::vsock::ProcState::Exited(c) => format!("exited({c})"),
            mvm_agentd::vsock::ProcState::Killed(s) => format!("killed({s})"),
            mvm_agentd::vsock::ProcState::TimedOut => "timed_out".to_string(),
        };
        println!(
            "{:<28} {:<22} {:<10} {}",
            p.pid_token, p.started_at, state, p.argv0
        );
    }
    Ok(())
}

fn cmd_signal(name: &str, token: &str, signum: i32) -> Result<()> {
    guest::signal_process(name, token, signum)
}

fn cmd_kill(name: &str, token: &str) -> Result<()> {
    guest::kill_process(name, token)
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
    let accepted = guest::send_process_input(name, token, &bytes)?;
    eprintln!("accepted {accepted} bytes");
    Ok(())
}

fn cmd_wait(name: &str, token: &str, timeout: Option<u64>) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let terminal = guest::wait_process(name, token, timeout, |ev| match ev {
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
        ProcWaitEvent::Exit { code } => mvm_observability::exit(code),
        ProcWaitEvent::Killed { signal } => {
            eprintln!("killed by signal {signal}");
            mvm_observability::exit(128 + signal);
        }
        ProcWaitEvent::TimedOut => {
            eprintln!("timed out");
            mvm_observability::exit(124);
        }
        ProcWaitEvent::Error { kind, message } => {
            bail!("ProcWait error ({:?}): {}", kind, message)
        }
        other => bail!("Unexpected terminal event: {:?}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(envs: &[&str], allow_env: &[&str]) -> Result<guest::ProcStart> {
        let envs: Vec<String> = envs.iter().map(|e| (*e).to_string()).collect();
        let allow_env: Vec<String> = allow_env.iter().map(|e| (*e).to_string()).collect();
        proc_start(vec!["/bin/true".to_string()], &envs, &allow_env, None)
    }

    #[test]
    fn proc_start_passes_ordinary_env() {
        let request = start(&["APP_MODE=dev"], &[]).expect("ordinary env passes");
        assert_eq!(request.env.get("APP_MODE").map(String::as_str), Some("dev"));
    }

    #[test]
    fn proc_start_refuses_a_denied_variable_by_name() {
        let err = start(&["NODE_OPTIONS=--require /tmp/x.js"], &[]).expect_err("denied");
        let message = format!("{err:#}");
        assert!(message.contains("NODE_OPTIONS (interpreter)"), "{message}");
        assert!(message.contains("--allow-env"), "{message}");
        assert!(!message.contains("/tmp/x.js"), "{message}");
    }

    #[test]
    fn proc_start_readmits_by_exact_name_and_carries_it_to_the_client() {
        let request = start(&["LD_LIBRARY_PATH=/opt/lib"], &["LD_LIBRARY_PATH"])
            .expect("exact-name re-admission");
        assert!(request.allow_env.contains("LD_LIBRARY_PATH"));
        assert!(start(&["LD_LIBRARY_PATH=/opt/lib"], &["LD_*"]).is_err());
    }
}
