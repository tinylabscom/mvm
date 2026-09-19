//! `mvmctl machine display` — a local, view-only display-frame viewer.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_contract::stream::{DisplayFrame, DisplayMime, StreamKind};
use mvm_core::naming::validate_vm_name;
use mvm_core::stream_client::{
    KindFilter, OutputRequest, StreamOpts, VmOutputStream, open_vm_output,
};
use mvm_core::user_config::MvmConfig;
use rand::Rng as _;

use super::Cli;
use super::shared::clap_vm_name;

const REQUEST_LIMIT: usize = 8 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const BOUNDARY: &str = "mvm-display-frame";

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM whose view-only frames to show
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    let request = OutputRequest {
        opts: StreamOpts::builder()
            .follow(true)
            .kinds(KindFilter::only(StreamKind::Frame))
            .build(),
        history_tail: Some(1),
        console_tail_bytes: None,
        console_tail_lines: None,
    };
    let stream = open_vm_output(&args.name, request)
        .with_context(|| format!("open display frames for microVM {:?}", args.name))?;
    let viewer = Viewer::bind(stream).context("bind the local display viewer")?;
    println!("Open {} (the token works once)", viewer.url());
    viewer.serve_once()
}

struct Viewer {
    listener: TcpListener,
    token: [u8; 32],
    stream: VmOutputStream,
}

impl Viewer {
    fn bind(stream: VmOutputStream) -> std::io::Result<Self> {
        let listener = bind_loopback()?;
        let mut token = [0u8; 32];
        rand::rng().fill_bytes(&mut token);
        Ok(Self {
            listener,
            token,
            stream,
        })
    }

    fn url(&self) -> String {
        format!(
            "http://{}/{}",
            self.listener.local_addr().expect("bound viewer address"),
            hex::encode(self.token)
        )
    }

    fn serve_once(mut self) -> Result<()> {
        loop {
            let (mut client, peer) = self.listener.accept().context("accept local viewer")?;
            if !peer.ip().is_loopback() {
                continue;
            }
            match request_authorization(&mut client, &self.token, REQUEST_TIMEOUT) {
                RequestAuthorization::Malformed => {
                    let _ = client.write_all(
                        b"HTTP/1.1 400 Bad Request\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
                RequestAuthorization::Forbidden => {
                    client.write_all(
                        b"HTTP/1.1 403 Forbidden\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )?;
                    continue;
                }
                RequestAuthorization::Authorized => {}
            }
            self.token.fill(0);
            return serve_frames(&mut client, &mut self.stream);
        }
    }
}

/// The only network bind in the display path. It accepts no configurable
/// address, so a viewer cannot be exposed by a flag or environment variable.
fn bind_loopback() -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestAuthorization {
    Authorized,
    Forbidden,
    Malformed,
}

fn request_authorization(
    stream: &mut TcpStream,
    token: &[u8; 32],
    timeout: Duration,
) -> RequestAuthorization {
    match read_request_with_timeout(stream, timeout) {
        Ok(request) if authorized(&request, token) => RequestAuthorization::Authorized,
        Ok(_) => RequestAuthorization::Forbidden,
        Err(_) => RequestAuthorization::Malformed,
    }
}

fn read_request_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(timeout))?;
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    while request.len() < REQUEST_LIMIT {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "viewer request is incomplete or too large",
    ))
}

fn authorized(request: &[u8], token: &[u8; 32]) -> bool {
    let Ok(request) = std::str::from_utf8(request) else {
        return false;
    };
    let Some(first_line) = request.lines().next() else {
        return false;
    };
    let wanted = format!("GET /{} HTTP/1.1", hex::encode(token));
    first_line == wanted
}

fn serve_frames(client: &mut TcpStream, stream: &mut VmOutputStream) -> Result<()> {
    client.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Type: multipart/x-mixed-replace; boundary={BOUNDARY}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    while let Some(record) = stream.next_output()? {
        let frame =
            DisplayFrame::decode(&record.payload).context("decode retained display frame")?;
        let mime = match frame.mime {
            DisplayMime::Jpeg => "image/jpeg",
            DisplayMime::Png => "image/png",
        };
        let step = frame.step_id.as_deref().unwrap_or("");
        let header = format!(
            "--{BOUNDARY}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nX-MVM-Frame-Digest: {}\r\nX-MVM-Agent-Step: {step}\r\n\r\n",
            frame.bytes.len(),
            hex::encode(frame.digest()),
        );
        client.write_all(header.as_bytes())?;
        client.write_all(&frame.bytes)?;
        client.write_all(b"\r\n")?;
        client.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn display_frames_never_leave_loopback() {
        let listener = bind_loopback().unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn the_session_token_authorizes_exactly_its_get_path() {
        let token = [0x5a; 32];
        let request = format!(
            "GET /{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            hex::encode(token)
        );
        assert!(authorized(request.as_bytes(), &token));
        assert!(!authorized(b"GET /wrong HTTP/1.1\r\n\r\n", &token));
        assert!(!authorized(
            format!("POST /{} HTTP/1.1\r\n\r\n", hex::encode(token)).as_bytes(),
            &token,
        ));
    }

    #[test]
    fn the_viewer_bind_has_no_non_loopback_parameter() {
        let bind: fn() -> std::io::Result<TcpListener> = bind_loopback;
        let listener = bind().unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
    }

    #[test]
    fn an_idle_client_cannot_hold_the_viewer_before_authentication() {
        let listener = bind_loopback().unwrap();
        let _idle_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut viewer, _) = listener.accept().unwrap();

        assert_eq!(
            request_authorization(&mut viewer, &[0; 32], Duration::from_millis(25)),
            RequestAuthorization::Malformed
        );
    }
}
