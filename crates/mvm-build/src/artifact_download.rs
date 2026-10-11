//! In-process release transport. Integrity and publisher verification remain
//! with the caller; HTTP success is not evidence that an artifact is trusted.

use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use mvm_http::Url;
use mvm_http::blocking::{Client, Response};

const MAX_REDIRECTS: usize = 10;
const ATTEMPTS: usize = 4;

/// Stream an artifact into an exclusive sibling, publishing only a complete
/// response. Failed attempts restart in that sibling, never append unchecked
/// bytes to an existing destination. The destination is unchanged on failure.
///
/// This transport neither runs executables nor relaxes signature/digest checks.
pub fn download(url: &str, destination: &Path) -> Result<()> {
    // Keep the blocking HTTP runtime off an embedder's async runtime thread.
    // This is an in-process thread, not a helper executable or child process.
    std::thread::scope(|scope| {
        scope
            .spawn(|| download_with(url, destination, ATTEMPTS, Duration::from_secs(2)))
            .join()
            .map_err(|_| anyhow::anyhow!("artifact transfer thread panicked"))?
    })
}

fn download_with(
    url: &str,
    destination: &Path,
    attempts: usize,
    retry_delay: Duration,
) -> Result<()> {
    let url = Url::parse(url).context("invalid artifact URL")?;
    // Explicit local release sources were supported by the old transport.
    // Preserve them using filesystem IO, but never allow an HTTP redirect to
    // switch to a local file.
    if url.scheme() == "file" {
        ensure!(
            url.host_str().is_none_or(|host| host == "localhost")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "artifact file URL must name a local file without credentials or query"
        );
        let source = url
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("invalid local artifact file URL"))?;
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent)?;
        std::io::copy(&mut std::fs::File::open(source)?, staged.as_file_mut())?;
        staged.as_file().sync_all()?;
        staged.persist(destination).map_err(|e| e.error)?;
        return Ok(());
    }
    validate_url(&url)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(3600))
        .build()?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged =
        tempfile::NamedTempFile::new_in(parent).context("create artifact download staging file")?;
    for attempt in 0..attempts {
        staged.as_file_mut().set_len(0)?;
        staged.as_file_mut().seek(SeekFrom::Start(0))?;
        let result = (|| -> Result<()> {
            let mut response = response(&client, url.clone())?;
            let expected = response.content_length();
            let copied = std::io::copy(&mut response, staged.as_file_mut())
                .context("stream artifact response")?;
            if let Some(expected) = expected {
                ensure!(copied == expected, "incomplete artifact response");
            }
            staged.as_file().sync_all()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                staged
                    .persist(destination)
                    .map_err(|e| e.error)
                    .context("publish downloaded artifact")?;
                return Ok(());
            }
            Err(error) if attempt + 1 == attempts => return Err(error),
            Err(_) => std::thread::sleep(retry_delay),
        }
    }
    bail!("artifact download requires at least one attempt")
}

fn validate_url(url: &Url) -> Result<()> {
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "artifact download requires an HTTP or HTTPS URL"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "artifact URL must not contain credentials"
    );
    Ok(())
}

fn response(client: &Client, mut url: Url) -> Result<Response> {
    for redirects in 0..=MAX_REDIRECTS {
        let response = client
            .get(url.as_str())
            .header("accept-encoding", "identity")
            .send()
            .context("request artifact")?;
        match response.status().as_u16() {
            200 => return Ok(response),
            301 | 302 | 303 | 307 | 308 => {
                ensure!(
                    redirects < MAX_REDIRECTS,
                    "artifact redirect limit exceeded"
                );
                let location = response
                    .headers()
                    .get("location")
                    .context("artifact redirect has no location")?
                    .to_str()
                    .context("invalid artifact redirect location")?;
                let next = url
                    .join(location)
                    .context("invalid artifact redirect URL")?;
                validate_url(&next)?;
                ensure!(
                    url.scheme() != "https" || next.scheme() == "https",
                    "artifact redirect would downgrade HTTPS"
                );
                url = next;
            }
            status => bail!("artifact server returned HTTP {status}"),
        }
    }
    bail!("artifact redirect limit exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // Each server is an in-process thread with bounded accept/read waits. No
    // external HTTP server, shell, executable discovery or environment mutation.
    fn server(replies: Vec<&'static [u8]>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/asset", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            for reply in replies {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "missing HTTP request");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                stream.write_all(reply).unwrap();
            }
        });
        (url, worker)
    }

    #[test]
    fn follows_relative_redirect_and_publishes_complete_bytes() {
        let (url, worker) = server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        ]);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        download(&url, &destination).unwrap();
        worker.join().unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"hello");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn interrupted_response_restarts_without_appending_partial_bytes() {
        let (url, worker) = server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\npartial",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nwhole",
        ]);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        download_with(&url, &destination, 2, Duration::ZERO).unwrap();
        worker.join().unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"whole");
    }

    #[test]
    fn error_status_and_partial_success_preserve_existing_destination() {
        for reply in [
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\noops"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\nshort".as_slice(),
            b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\npart"
                .as_slice(),
        ] {
            let (url, worker) = server(vec![reply]);
            let root = tempfile::tempdir().unwrap();
            let destination = root.path().join("artifact");
            std::fs::write(&destination, b"original").unwrap();
            assert!(download_with(&url, &destination, 1, Duration::ZERO).is_err());
            worker.join().unwrap();
            assert_eq!(std::fs::read(destination).unwrap(), b"original");
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn non_http_redirect_is_refused_without_touching_destination() {
        let (url, worker) = server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: file:///etc/passwd\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        assert!(download_with(&url, &destination, 1, Duration::ZERO).is_err());
        worker.join().unwrap();
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn redirect_cycles_are_bounded() {
        let (url, worker) = server(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            MAX_REDIRECTS + 1
        ]);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        let error = download_with(&url, &destination, 1, Duration::ZERO).unwrap_err();
        worker.join().unwrap();
        assert!(error.to_string().contains("redirect limit"));
        assert!(!destination.exists());
    }

    #[test]
    fn invalid_urls_are_refused_before_creating_staging_files() {
        let root = tempfile::tempdir().unwrap();
        for url in [
            "ftp://localhost/asset",
            "http://user:password@localhost/asset",
        ] {
            assert!(download_with(url, &root.path().join("artifact"), 1, Duration::ZERO).is_err());
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn chunked_response_replaces_hardlink_without_changing_other_names() {
        let (url, worker) = server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nnew\r\n5\r\nbytes\r\n0\r\n\r\n",
        ]);
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        let original = root.path().join("original");
        std::fs::write(&original, b"keep").unwrap();
        std::fs::hard_link(&original, &destination).unwrap();
        download_with(&url, &destination, 1, Duration::ZERO).unwrap();
        worker.join().unwrap();
        assert_eq!(std::fs::read(original).unwrap(), b"keep");
        assert_eq!(std::fs::read(destination).unwrap(), b"newbytes");
    }

    #[test]
    fn explicit_local_release_source_uses_filesystem_io() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("asset with spaces");
        let destination = root.path().join("download");
        std::fs::write(&source, b"local artifact").unwrap();
        let url = Url::from_file_path(&source).unwrap();
        download(url.as_str(), &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"local artifact");
        std::fs::remove_file(source).unwrap();
        assert!(download(url.as_str(), &destination).is_err());
        assert_eq!(std::fs::read(destination).unwrap(), b"local artifact");
    }
}
