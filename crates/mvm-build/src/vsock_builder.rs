use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use mvm_guest::builder_agent::{BuilderRequest, BuilderResponse};

fn builder_agent_port() -> u32 {
    std::env::var("MVM_BUILDER_AGENT_PORT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(mvm_guest::builder_agent::BUILDER_AGENT_PORT)
}

pub fn build_via_vsock(
    vsock_uds: &str,
    flake_ref: &str,
    attr: &str,
    timeout_secs: u64,
) -> Result<String> {
    wait_for_agent_ready(vsock_uds, timeout_secs.clamp(15, 90))?;

    let mut stream = UnixStream::connect(vsock_uds)
        .with_context(|| format!("failed to connect vsock UDS {}", vsock_uds))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    // Firecracker UDS CONNECT handshake.
    writeln!(stream, "CONNECT {}", builder_agent_port())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("OK ") {
        return Err(anyhow!("vsock CONNECT failed: {}", line.trim()));
    }

    let req = BuilderRequest::Build {
        flake_ref: flake_ref.to_string(),
        attr: attr.to_string(),
        timeout_secs: Some(timeout_secs),
    };
    let req_json = serde_json::to_string(&req)?;
    {
        let s = reader.get_mut();
        writeln!(s, "{}", req_json)?;
        s.flush()?;
    }

    let mut resp_line = String::new();
    // Collect recent log lines so we can surface them on build failure.
    let mut recent_logs: Vec<String> = Vec::new();
    const MAX_LOG_LINES: usize = 50;

    loop {
        resp_line.clear();
        if reader.read_line(&mut resp_line)? == 0 {
            return Err(anyhow!("vsock EOF before build response"));
        }
        let trimmed = resp_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp: BuilderResponse = serde_json::from_str(trimmed)
            .with_context(|| format!("invalid builder response: {}", trimmed))?;
        match resp {
            BuilderResponse::Log { line } => {
                if !line.is_empty() {
                    eprintln!("[mvm][builder-agent] {}", line);
                    if recent_logs.len() >= MAX_LOG_LINES {
                        recent_logs.remove(0);
                    }
                    recent_logs.push(line);
                }
            }
            BuilderResponse::Ok { out_path } => return Ok(out_path),
            BuilderResponse::Err { message } => {
                if recent_logs.is_empty() {
                    return Err(anyhow!("nix build failed: {}", message));
                }
                let log_tail = recent_logs.join("\n");
                return Err(anyhow!(
                    "nix build failed: {}. Builder output (last {} lines):\n{}",
                    message,
                    recent_logs.len(),
                    log_tail
                ));
            }
            BuilderResponse::Pong => continue,
        }
    }
}

fn wait_for_agent_ready(vsock_uds: &str, max_wait_secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match ping_once(vsock_uds) {
            Ok(()) => {
                let elapsed =
                    Instant::now().duration_since(deadline - Duration::from_secs(max_wait_secs));
                eprintln!(
                    "[mvm] Builder agent ready after {:.1}s ({} attempts)",
                    elapsed.as_secs_f64(),
                    attempts
                );
                return Ok(());
            }
            Err(_) if Instant::now() < deadline => {
                if attempts.is_multiple_of(5) {
                    let remaining = deadline.duration_since(Instant::now());
                    eprintln!(
                        "[mvm] Waiting for builder agent... ({:.0}s remaining)",
                        remaining.as_secs_f64()
                    );
                }
                std::thread::sleep(Duration::from_millis(400));
            }
            Err(e) => {
                return Err(anyhow!(
                    "builder vsock agent did not become ready in {}s: {}",
                    max_wait_secs,
                    e
                ));
            }
        }
    }
}

fn ping_once(vsock_uds: &str) -> Result<()> {
    let mut stream = UnixStream::connect(vsock_uds)
        .with_context(|| format!("failed to connect vsock UDS {}", vsock_uds))?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
    writeln!(stream, "CONNECT {}", builder_agent_port())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("OK ") {
        return Err(anyhow!("vsock CONNECT failed: {}", line.trim()));
    }

    let req = BuilderRequest::Ping;
    {
        let s = reader.get_mut();
        writeln!(s, "{}", serde_json::to_string(&req)?)?;
        s.flush()?;
    }

    let mut resp_line = String::new();
    reader.read_line(&mut resp_line)?;
    let resp: BuilderResponse = serde_json::from_str(resp_line.trim())
        .with_context(|| format!("invalid ping response: {}", resp_line.trim()))?;
    match resp {
        BuilderResponse::Pong => Ok(()),
        BuilderResponse::Err { message } => Err(anyhow!("builder agent ping failed: {}", message)),
        other => Err(anyhow!("unexpected ping response: {:?}", other)),
    }
}
