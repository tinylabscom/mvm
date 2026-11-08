use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mvm_contract::policy::restricted_address::classify;
use mvm_http::Url;
use mvm_http::resolve::{Resolve, SystemResolver};

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
/// Redirects are not followed.
pub fn download_file(url: &str, dest: &Path) -> Result<()> {
    let client = build_blocking_client(Duration::from_secs(600))?;
    let mut resp = client
        .get(url)
        .send()
        .with_context(|| format!("Download failed: {}", url))?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} downloading {}", status, url);
    }
    let mut file = std::fs::File::create(dest)
        .with_context(|| format!("Failed to create file: {}", dest.display()))?;
    std::io::copy(&mut resp, &mut file)
        .with_context(|| format!("Failed to stream download to: {}", dest.display()))?;
    Ok(())
}

const MAX_REDIRECT_HOPS: usize = 5;
const MAX_LOCATION_BYTES: usize = 4096;
const BOUNDED_DEADLINE: Duration = Duration::from_secs(600);

/// Stream a download without accepting more than the caller's byte budget.
///
/// Unlike every other fetch here this follows HTTPS redirects (a GitHub
/// release asset always answers 302 to its CDN), under [`redirect_target`]'s
/// policy. One deadline and one byte budget span every hop; the final bytes
/// are still held to the caller's digest by the caller.
pub(crate) fn download_file_bounded(url: &str, dest: &Path, limit: u64) -> Result<()> {
    let start = Url::parse(url).map_err(|_| anyhow::anyhow!("download URL is not valid"))?;
    let deadline = Instant::now() + BOUNDED_DEADLINE;
    let mut send = |target: &Url, hop: usize, remaining: Duration| -> Result<Hop> {
        let mut builder = mvm_http::blocking::Client::builder()
            .user_agent(concat!("mvmctl/", env!("CARGO_PKG_VERSION")))
            .timeout(remaining)
            .max_response_bytes(limit);
        if hop > 0 {
            builder = builder.resolver(Arc::new(PublicOnlyResolver));
        }
        // A fresh client with no default headers per hop: nothing
        // credential-like exists to forward across hosts.
        let resp = builder
            .build()
            .context("Failed to build HTTP client")?
            .get(target.as_str())
            .send()
            .map_err(|e| anyhow::anyhow!("request failed: {e}"))?;
        Ok(Hop {
            status: resp.status().as_u16(),
            location: resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            content_length: resp.content_length(),
            body: Box::new(resp),
        })
    };
    follow_download(&start, dest, limit, deadline, &mut send)
}

struct Hop {
    status: u16,
    location: Option<String>,
    content_length: Option<u64>,
    body: Box<dyn Read>,
}

type SendHop<'a> = dyn FnMut(&Url, usize, Duration) -> Result<Hop> + 'a;

fn follow_download(
    start: &Url,
    dest: &Path,
    limit: u64,
    deadline: Instant,
    send: &mut SendHop<'_>,
) -> Result<()> {
    let mut current = start.clone();
    for hop in 0..=MAX_REDIRECT_HOPS {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| anyhow::anyhow!("download deadline exceeded at hop {hop}"))?;
        let shown = redacted(&current);
        let mut resp = send(&current, hop, remaining)
            .map_err(|e| anyhow::anyhow!("download failed at hop {hop} ({shown}): {e}"))?;
        if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
            if hop == MAX_REDIRECT_HOPS {
                anyhow::bail!(
                    "download refused at hop {}: more than {MAX_REDIRECT_HOPS} redirects",
                    hop + 1
                );
            }
            let location = resp.location.as_deref().ok_or_else(|| {
                anyhow::anyhow!("download refused at hop {hop}: redirect without Location")
            })?;
            current = redirect_target(&current, location)
                .map_err(|why| anyhow::anyhow!("download refused at hop {}: {why}", hop + 1))?;
            continue;
        }
        if !(200..300).contains(&resp.status) {
            anyhow::bail!("HTTP {} downloading {shown} (hop {hop})", resp.status);
        }
        if resp.content_length.is_some_and(|size| size > limit) {
            anyhow::bail!("download exceeds its byte budget");
        }
        let mut file = std::fs::File::create(dest)
            .with_context(|| format!("Failed to create file: {}", dest.display()))?;
        std::io::copy(&mut resp.body, &mut file).map_err(|e| {
            anyhow::anyhow!("failed to stream download from hop {hop} ({shown}): {e}")
        })?;
        return Ok(());
    }
    unreachable!("the loop returns or bails by the last hop")
}

/// scheme+host+path only: a signed redirect target's query is a bearer token.
fn redacted(url: &Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or("?"),
        url.path()
    )
}

/// Resolve and vet one redirect. HTTPS only (from an HTTPS page), a named
/// host on the same port, no userinfo. Address classes are enforced at
/// connect time by [`PublicOnlyResolver`].
fn redirect_target(current: &Url, location: &str) -> std::result::Result<Url, String> {
    if current.scheme() != "https" {
        return Err("redirects are followed only from https".into());
    }
    if location.len() > MAX_LOCATION_BYTES || !location.is_ascii() {
        return Err("Location is too long or not ASCII".into());
    }
    let next = current
        .join(location)
        .map_err(|_| "Location is not a valid URL".to_string())?;
    if next.scheme() != "https" {
        return Err(format!("scheme {} is not https", next.scheme()));
    }
    if !next.username().is_empty() || next.password().is_some() {
        return Err("target carries userinfo".into());
    }
    let host = next.host_str().ok_or("target has no host")?;
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
        return Err("target host is an IP literal".into());
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Err("target host is localhost".into());
    }
    if next.port_or_known_default() != current.port_or_known_default() {
        return Err("target changes the port".into());
    }
    Ok(next)
}

/// Resolver for redirect hops: drops every loopback, private, link-local,
/// CGNAT and metadata address; the client dials only what this returns.
#[derive(Debug)]
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        let inner = SystemResolver.resolve(host, port);
        Box::pin(async move {
            let mut addrs = inner.await?;
            addrs.retain(|a| classify(a.ip()).is_none());
            Ok(addrs)
        })
    }
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

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn redirect_policy_accepts_https_and_refuses_everything_else() {
        let cur = u("https://github.com/o/r/releases/download/t/a.mvmpkg");
        let ok =
            redirect_target(&cur, "https://release-assets.githubusercontent.com/x?sig=s").unwrap();
        assert_eq!(ok.host_str(), Some("release-assets.githubusercontent.com"));
        assert_eq!(redirect_target(&cur, "/other").unwrap().path(), "/other");
        for (loc, why) in [
            ("http://cdn.example.com/a", "not https"),
            ("https://127.0.0.1/a", "IP literal"),
            ("https://[::1]/a", "IP literal"),
            ("https://169.254.169.254/a", "IP literal"),
            ("https://0x7f.1/a", "IP literal"),
            ("https://localhost/a", "localhost"),
            ("https://a.localhost/a", "localhost"),
            ("https://u:p@cdn.example.com/a", "userinfo"),
            ("https://cdn.example.com:8443/a", "port"),
            ("ftp://cdn.example.com/a", "not https"),
        ] {
            let err = redirect_target(&cur, loc).unwrap_err();
            assert!(err.contains(why), "{loc}: {err}");
        }
        assert!(redirect_target(&cur, &format!("https://c.example/{}", "a".repeat(5000))).is_err());
        assert!(redirect_target(&u("http://c.example/a"), "https://d.example/").is_err());
    }

    #[test]
    fn public_resolver_filter_classes() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
        ] {
            assert!(classify(ip.parse().unwrap()).is_some(), "{ip}");
        }
        assert!(classify("140.82.112.3".parse().unwrap()).is_none());
    }

    /// Scripted transport: hop N answers `script[N]` (status, location, body).
    fn run(
        start: &str,
        limit: u64,
        script: Vec<(u16, Option<&'static str>, &'static [u8])>,
    ) -> (Result<()>, Vec<String>) {
        let dest = tempfile::NamedTempFile::new().unwrap();
        let mut seen = Vec::new();
        let mut send = |url: &Url, hop: usize, _r: Duration| -> Result<Hop> {
            seen.push(url.as_str().to_string());
            let (status, location, body) = script[hop.min(script.len() - 1)];
            Ok(Hop {
                status,
                location: location.map(str::to_owned),
                content_length: None,
                body: Box::new(std::io::Cursor::new(body.to_vec())),
            })
        };
        let r = follow_download(
            &u(start),
            dest.path(),
            limit,
            Instant::now() + Duration::from_secs(60),
            &mut send,
        );
        if r.is_ok() {
            assert_eq!(std::fs::read(dest.path()).unwrap(), b"four");
        }
        (r, seen)
    }

    const A: &str = "https://github.com/a";

    #[test]
    fn follows_a_redirect_then_serves() {
        let (r, seen) = run(
            A,
            4,
            vec![
                (302, Some("https://cdn.example.com/b?sig=SECRET"), b""),
                (200, None, b"four"),
            ],
        );
        r.unwrap();
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn five_hops_pass_and_six_fail_naming_the_hop() {
        let mut ok = vec![(302, Some("/n"), b"".as_slice()); 5];
        ok.push((200, None, b"four"));
        run(A, 4, ok).0.unwrap();
        let (r, seen) = run(A, 4, vec![(302, Some("/n"), b"")]);
        let err = r.unwrap_err().to_string();
        assert!(err.contains("hop 6") && err.contains("redirects"), "{err}");
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn downgrade_loopback_and_missing_location_are_refused() {
        for loc in ["http://cdn.example.com/b", "https://127.0.0.1/b"] {
            let (r, seen) = run(A, 4, vec![(302, Some(loc), b""), (200, None, b"four")]);
            assert!(r.unwrap_err().to_string().contains("hop 1"));
            assert_eq!(seen.len(), 1, "never contacted the refused target");
        }
        assert!(run(A, 4, vec![(302, None, b"")]).0.is_err());
    }

    #[test]
    fn errors_never_carry_the_query() {
        let (r, _) = run(
            A,
            4,
            vec![
                (302, Some("https://cdn.example.com/b?sig=SECRET"), b""),
                (500, None, b""),
            ],
        );
        let err = r.unwrap_err().to_string();
        assert!(
            err.contains("cdn.example.com/b") && !err.contains("SECRET"),
            "{err}"
        );
    }

    #[test]
    fn byte_budget_applies_to_the_body_after_a_redirect() {
        let mut send = |_: &Url, hop: usize, _: Duration| -> Result<Hop> {
            Ok(if hop == 0 {
                Hop {
                    status: 302,
                    location: Some("/b".into()),
                    content_length: None,
                    body: Box::new(std::io::empty()),
                }
            } else {
                Hop {
                    status: 200,
                    location: None,
                    content_length: Some(99),
                    body: Box::new(std::io::empty()),
                }
            })
        };
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = follow_download(
            &u(A),
            dest.path(),
            4,
            Instant::now() + Duration::from_secs(5),
            &mut send,
        )
        .unwrap_err();
        assert!(err.to_string().contains("byte budget"));
    }
}
