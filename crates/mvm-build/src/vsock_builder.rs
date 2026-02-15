use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use mvm_guest::builder_agent::{BuilderRequest, BuilderResponse};

pub fn build_via_vsock(
    vsock_uds: &str,
    flake_ref: &str,
    attr: &str,
    timeout_secs: u64,
) -> Result<String> {
    wait_for_agent_ready(vsock_uds, timeout_secs.clamp(5, 30))?;

    let mut stream = UnixStream::connect(vsock_uds)
        .with_context(|| format!("failed to connect vsock UDS {}", vsock_uds))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    // Firecracker UDS CONNECT handshake.
    writeln!(stream, "CONNECT {}", mvm_guest::vsock::GUEST_AGENT_PORT)?;
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
                }
            }
            BuilderResponse::Ok { out_path } => return Ok(out_path),
            BuilderResponse::Err { message } => return Err(anyhow!(message)),
            BuilderResponse::Pong => continue,
        }
    }
}

fn wait_for_agent_ready(vsock_uds: &str, max_wait_secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);
    loop {
        match ping_once(vsock_uds) {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
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
    writeln!(stream, "CONNECT {}", mvm_guest::vsock::GUEST_AGENT_PORT)?;
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
