use std::path::Path;

use anyhow::{Context, Result};

fn build_blocking_client(timeout: std::time::Duration) -> Result<mvm_http::blocking::Client> {
    mvm_http::blocking::Client::builder()
        .user_agent(concat!("mvmctl/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .build()
        .context("Failed to build HTTP client")
}

/// Fetch a URL and return the response body as a string.
pub fn fetch_text(url: &str) -> Result<String> {
    let client = build_blocking_client(std::time::Duration::from_secs(30))?;

    let resp = client
        .get(url)
        .send()
        .with_context(|| format!("HTTP request failed: {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} for {}", status, url);
    }

    resp.text()
        .with_context(|| format!("Failed to read response body from {}", url))
}

/// Fetch a URL and parse the response as JSON.
pub fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let client = build_blocking_client(std::time::Duration::from_secs(30))?;

    let resp = client
        .get(url)
        .header("accept", "application/json")
        .send()
        .with_context(|| format!("HTTP request failed: {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} for {}", status, url);
    }

    resp.json::<serde_json::Value>()
        .with_context(|| format!("Failed to parse JSON from {}", url))
}

/// Download a URL to a file on disk. Shows no progress (use for small files).
pub fn download_file(url: &str, dest: &Path) -> Result<()> {
    download_file_with_limit(url, dest, None)
}

/// Stream a download without accepting more than the caller's byte budget.
pub(crate) fn download_file_bounded(url: &str, dest: &Path, limit: u64) -> Result<()> {
    download_file_with_limit(url, dest, Some(limit))
}

fn download_file_with_limit(url: &str, dest: &Path, limit: Option<u64>) -> Result<()> {
    let mut builder = mvm_http::blocking::Client::builder()
        .user_agent(concat!("mvmctl/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(600));
    if let Some(limit) = limit {
        builder = builder.max_response_bytes(limit);
    }
    let client = builder.build().context("Failed to build HTTP client")?;

    let mut resp = client
        .get(url)
        .send()
        .with_context(|| format!("Download failed: {}", url))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} downloading {}", status, url);
    }

    if limit.is_some_and(|limit| resp.content_length().is_some_and(|size| size > limit)) {
        anyhow::bail!("download exceeds its byte budget");
    }

    let mut file = std::fs::File::create(dest)
        .with_context(|| format!("Failed to create file: {}", dest.display()))?;

    std::io::copy(&mut resp, &mut file)
        .with_context(|| format!("Failed to stream download to: {}", dest.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn read_request(socket: &mut std::net::TcpStream) {
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while request.len() < 8192 {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                return;
            }
        }
        panic!("test request headers exceed bound");
    }

    #[test]
    fn bounded_download_streams_exact_bytes_and_refuses_oversize_or_interruption() {
        for (body, declared) in [
            (b"four".as_slice(), true),
            (b"oversize".as_slice(), true),
            (b"oversize".as_slice(), false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/bundle", listener.local_addr().unwrap());
            let body = body.to_vec();
            let expected = body.len() <= 4;
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                read_request(&mut socket);
                let _ = write!(socket, "HTTP/1.1 200 OK\r\n");
                if declared {
                    let _ = write!(socket, "Content-Length: {}\r\n", body.len());
                }
                let _ = write!(socket, "Connection: close\r\n\r\n");
                let _ = socket.write_all(&body);
            });
            let destination = tempfile::NamedTempFile::new().unwrap();
            let result = download_file_bounded(&url, destination.path(), 4);
            assert_eq!(result.is_ok(), expected);
            if expected {
                assert_eq!(std::fs::read(destination.path()).unwrap(), b"four");
            }
            server.join().unwrap();
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/bundle", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_request(&mut socket);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nx")
                .unwrap();
        });
        let destination = tempfile::NamedTempFile::new().unwrap();
        assert!(download_file_bounded(&url, destination.path(), 4).is_err());
        server.join().unwrap();
    }
}
