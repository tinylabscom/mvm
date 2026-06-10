//! Plan 129 Stage 2 — server-side TLS termination for bound-host `https` egress.
//!
//! The nft `nat` chain REDIRECTs the guest's outbound `:443` here alongside
//! `:80`. We peek the TLS ClientHello SNI **without consuming the stream**:
//!   - **bound SNI** (a host the plan's secrets are allowed to reach) → terminate
//!     TLS under a leaf minted by the per-VM name-constrained intermediate,
//!     decrypt, substitute (the Stage 1b `handle_request` core), re-originate a
//!     real upstream TLS connection (root-validated, via the reused reqwest
//!     forwarder), stream the response back encrypted.
//!   - **unbound SNI** → byte-splice passthrough; the terminator never decrypts,
//!     so end-to-end TLS is preserved and the host gains zero added visibility.
//!
//! **Honest boundary (defense in depth, not the control):** Python `ssl` and
//! older Node don't enforce X.509 `nameConstraints` client-side, so the in-guest
//! cert constraint is a courtesy. The real egress boundary is the host-side
//! allow-list check in `prepare_request` (claim 12); the name constraint only
//! bounds blast radius if a per-VM intermediate ever leaked.
//!
//! This module's SNI peek/parse is pure + host-testable; the live terminate /
//! splice glue (Linux accept loop) lives in `substitution_proxy.rs`.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mvm_core::crypto::egress_ca::VmIntermediate;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use mvm_sdk::ir::AuthType;

use super::read::read_http_request;
use super::request::proxy_request_from_origin_form_https;
use crate::keyholder::substitution::SubstitutionEndpoint;
use crate::supervisor::substitution_proxy::{
    PreparedRequest, collect_substituted_meta, destination_host, prepare_request,
};

/// What a terminated connection substituted — handed back so the caller emits
/// the same `secret.substituted` audit (metadata only, claim 13) the `:80` path
/// does. Captured from the decrypted request BEFORE substitution.
pub struct TerminateOutcome {
    pub substituted: Vec<(String, AuthType)>,
    pub destination: Option<String>,
}

/// Peek (without consuming) the ClientHello SNI from a blocking std `TcpStream`.
/// `Ok(None)` when no SNI is present or a full ClientHello hasn't been buffered
/// within the peek window — the caller then splices (can't bind-check). The
/// stream is untouched, so the caller can hand it to a rustls server (bound) or
/// splice it raw (unbound). Bounded retries cover a ClientHello fragmented
/// across packets; the socket's read timeout bounds the total wait.
pub fn peek_sni(stream: &TcpStream) -> std::io::Result<Option<String>> {
    let mut buf = vec![0u8; MAX_CLIENT_HELLO_PEEK];
    for _ in 0..8 {
        let n = stream.peek(&mut buf)?;
        if let Some(sni) = parse_sni(&buf[..n]) {
            return Ok(Some(sni));
        }
        if n >= buf.len() {
            break; // full window, still no SNI
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(None)
}

/// Cap on the bytes we peek looking for the SNI. A ClientHello carrying SNI is
/// far smaller; this bounds the peek so a guest can't make us buffer unboundedly
/// before we've even decided bound-vs-unbound.
pub const MAX_CLIENT_HELLO_PEEK: usize = 8 * 1024;

/// Build a rustls `ServerConfig` that presents a freshly-minted leaf for `sni`
/// chained to the per-VM intermediate (`[leaf, intermediate]`), so a guest that
/// trusts the intermediate validates the terminated connection. We already
/// peeked the SNI, so we mint directly rather than via a `ResolvesServerCert`.
pub fn server_config_for_sni(
    intermediate: &VmIntermediate,
    sni: &str,
) -> Result<rustls::ServerConfig> {
    let leaf = intermediate
        .mint_leaf(sni)
        .map_err(|e| anyhow!("mint leaf for {sni}: {e}"))?;

    let mut chain = pem_certs(&leaf.cert_pem).context("parse minted leaf cert")?;
    chain.extend(pem_certs(intermediate.cert_pem()).context("parse intermediate cert")?);
    let key = pem_private_key(&leaf.key_pem).context("parse minted leaf key")?;

    rustls::ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("rustls server config from minted leaf")
}

/// Terminate the guest's TLS on `stream` under `config`, read the one decrypted
/// HTTP/1.1 request, substitute placeholders against `endpoint` (claim-12
/// bind-checked — refused before `forward` runs), forward via `forward`
/// (the upstream-https leg), and write the response back encrypted.
///
/// `forward` is injected so the substitution + termination core stays testable
/// with a mock upstream; production passes the reused reqwest forwarder. A
/// substitution refusal closes the connection without forwarding — the same
/// fail-closed invariant as the Stage 1b `:80` path.
pub fn terminate_and_substitute<S, F>(
    stream: S,
    config: Arc<rustls::ServerConfig>,
    orig_dst: SocketAddr,
    endpoint: &SubstitutionEndpoint<'_>,
    forward: F,
) -> Result<TerminateOutcome>
where
    S: Read + Write,
    F: Fn(&PreparedRequest) -> Result<Vec<u8>>,
{
    let conn = rustls::ServerConnection::new(config).context("new rustls server connection")?;
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let raw = read_http_request(&mut tls).context("read decrypted request")?;
    let req = proxy_request_from_origin_form_https(&raw, orig_dst)?;
    // Capture audit metadata before substitution consumes the request (claim-13
    // safe — resolve_meta touches no value), mirroring the `:80` path exactly.
    let substituted = collect_substituted_meta(endpoint, &req.headers);
    let destination = destination_host(&req.url).ok();

    let prepared =
        prepare_request(endpoint, req).map_err(|e| anyhow!("substitution refused: {e}"))?;
    let resp = forward(&prepared)?;

    tls.write_all(&resp).context("write terminated response")?;
    tls.flush().context("flush terminated response")?;
    Ok(TerminateOutcome {
        substituted,
        destination,
    })
}

/// Serialize a forwarded upstream response to HTTP/1.1 wire bytes for the
/// terminated TLS stream. reqwest already decoded transfer-encoding, so we drop
/// the upstream framing headers and emit our own `Content-Length` + `close`.
pub fn serialize_http_response(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status)).as_bytes());
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        // Drop framing/hop-by-hop headers reqwest already resolved; we re-frame.
        if matches!(
            lk.as_str(),
            "transfer-encoding" | "content-length" | "connection"
        ) {
            continue;
        }
        // Defensive: never let a header smuggle CRLF into the response.
        if k.bytes().chain(v.bytes()).any(|b| b == b'\r' || b == b'\n') {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// A minimal reason phrase for common statuses; "" for the rest (clients accept
/// an empty reason phrase per RFC 7230).
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Splice an **unbound**-SNI connection straight through to `orig_dst` without
/// decrypting — end-to-end TLS is preserved and the host gains zero added
/// visibility. The ClientHello was only peeked, so the guest's first flight is
/// still buffered on `guest` and flows through verbatim. No leaf is minted; the
/// per-VM intermediate is never touched on this path.
pub fn splice_unbound(guest: TcpStream, orig_dst: SocketAddr, timeout: Duration) -> Result<()> {
    let upstream = TcpStream::connect_timeout(&orig_dst, timeout)
        .with_context(|| format!("connecting unbound splice to {orig_dst}"))?;
    splice_bidirectional(guest, upstream);
    Ok(())
}

/// Copy bytes between two TCP streams in both directions until either closes,
/// half-closing the peer on EOF so a blocked `read` unwinds. Lifted from the
/// QEMU vsock relay (`qemu.rs`) and specialized to TCP↔TCP.
fn splice_bidirectional(a: TcpStream, b: TcpStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let t = std::thread::spawn(move || copy_until_eof(a2, b2));
    copy_until_eof(b, a);
    let _ = t.join();
}

/// Copy `r`→`w` until EOF/error, then half-close `w`'s write side.
fn copy_until_eof(mut r: TcpStream, mut w: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 || w.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = w.shutdown(Shutdown::Write);
}

/// Parse a PEM bundle into DER certs (the leaf + intermediate chain).
fn pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = std::io::Cursor::new(pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut rd).collect();
    let certs = certs.context("read PEM certs")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate in PEM"));
    }
    Ok(certs)
}

/// Parse a PEM private key (PKCS#8 — rcgen emits PKCS#8) into a rustls key.
fn pem_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut rd = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut rd)
        .context("read PEM private key")?
        .ok_or_else(|| anyhow!("no private key in PEM"))
}

/// Extract the SNI `host_name` from a buffered TLS ClientHello record, or `None`
/// when the buffer isn't a ClientHello, carries no SNI, or is malformed/truncated
/// before the name. Pure + total: every length is bounds-checked, so hostile or
/// partial input yields `None`, never a panic.
///
/// Parses exactly enough of the record/handshake framing to reach the
/// `server_name` extension (type 0x0000) and read its first `host_name` entry.
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    let mut c = Cursor::new(buf);

    // ── TLS record header ──
    // content_type == 22 (handshake); we don't gate on the legacy version.
    if c.u8()? != 0x16 {
        return None;
    }
    c.skip(2)?; // legacy record version
    let rec_len = c.u16()? as usize;
    // Constrain the rest of the parse to the record body we actually have.
    let body = c.take(rec_len)?;
    let mut h = Cursor::new(body);

    // ── Handshake header ──
    if h.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let hs_len = h.u24()? as usize;
    let hs = h.take(hs_len)?;
    let mut b = Cursor::new(hs);

    b.skip(2)?; // client_version
    b.skip(32)?; // random
    let sid_len = b.u8()? as usize;
    b.skip(sid_len)?; // session_id
    let cs_len = b.u16()? as usize;
    b.skip(cs_len)?; // cipher_suites
    let comp_len = b.u8()? as usize;
    b.skip(comp_len)?; // compression_methods

    // ── Extensions ──
    let ext_total = b.u16()? as usize;
    let exts = b.take(ext_total)?;
    let mut e = Cursor::new(exts);
    while e.remaining() >= 4 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let ext_data = e.take(ext_len)?;
        if ext_type == 0x0000 {
            return parse_server_name_list(ext_data);
        }
    }
    None
}

/// Parse the `server_name` extension body, returning the first `host_name`.
fn parse_server_name_list(data: &[u8]) -> Option<String> {
    let mut c = Cursor::new(data);
    let list_len = c.u16()? as usize;
    let list = c.take(list_len)?;
    let mut l = Cursor::new(list);
    while l.remaining() >= 3 {
        let name_type = l.u8()?;
        let name_len = l.u16()? as usize;
        let name = l.take(name_len)?;
        if name_type == 0x00 {
            // host_name: must be valid UTF-8 (a DNS name). Reject otherwise.
            return std::str::from_utf8(name).ok().map(str::to_string);
        }
    }
    None
}

/// A bounds-checked forward cursor over a byte slice. Every accessor returns
/// `None` rather than panicking when the slice is too short — the parser stays
/// total over arbitrary (hostile, truncated) input.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }
    fn u24(&mut self) -> Option<u32> {
        Some(((self.u8()? as u32) << 16) | ((self.u8()? as u32) << 8) | self.u8()? as u32)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }
    /// Borrow the next `n` bytes and advance past them.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce a real TLS ClientHello carrying `sni` by driving a rustls client
    /// connection and capturing the first flight it writes.
    fn client_hello_with_sni(sni: &str) -> Vec<u8> {
        use rustls::RootCertStore;
        use rustls::pki_types::ServerName;
        let roots = RootCertStore::empty();
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let server_name = ServerName::try_from(sni.to_string()).unwrap();
        let mut conn =
            rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn peek_sni_extracts_servername_from_clienthello() {
        let hello = client_hello_with_sni("api.openai.com");
        assert_eq!(parse_sni(&hello).as_deref(), Some("api.openai.com"));
    }

    #[test]
    fn parse_sni_handles_a_different_name() {
        let hello = client_hello_with_sni("example.com");
        assert_eq!(parse_sni(&hello).as_deref(), Some("example.com"));
    }

    #[test]
    fn truncated_clienthello_yields_none_not_panic() {
        let hello = client_hello_with_sni("api.openai.com");
        // Every prefix of a real ClientHello must parse to None (or the full
        // name once enough bytes are present) — never panic.
        for cut in 0..hello.len() {
            let _ = parse_sni(&hello[..cut]);
        }
    }

    #[test]
    fn non_handshake_record_is_none() {
        // An application-data record (0x17), not a handshake.
        assert_eq!(parse_sni(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None);
    }

    #[test]
    fn empty_input_is_none() {
        assert_eq!(parse_sni(&[]), None);
    }

    #[test]
    fn garbage_is_none() {
        assert_eq!(parse_sni(&[0x16, 0xff, 0xff, 0xff, 0xff]), None);
    }

    // ── terminate + substitute (loopback, no VM) ──

    use crate::keyholder::{LocalResolver, SubstitutionRegistry};
    use mvm_core::crypto::egress_ca::{EgressCa, VmIntermediate};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    /// A rustls client config that trusts exactly `intermediate_cert_pem` — the
    /// guest's posture after the S2.3 boot step installs the per-VM cert.
    fn client_config_trusting(intermediate_cert_pem: &str) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        for c in super::pem_certs(intermediate_cert_pem).unwrap() {
            roots.add(c).unwrap();
        }
        rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    #[test]
    fn bound_sni_terminates_substitutes_and_reoriginates() {
        let dir = tempfile::tempdir().unwrap();
        let ca = EgressCa::load_or_init_at(dir.path()).unwrap();
        let inter = ca.mint_vm_intermediate(&["api.openai.com"]).unwrap();
        // Reconstruct exactly as the endpoint would, from the delivered PEMs.
        let inter = VmIntermediate::from_pem(inter.cert_pem(), &inter.key_pem()).unwrap();

        // Substitution registry: placeholder → real token, bound to the host.
        let sdir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(sdir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("REALTOKEN".to_string())),
            )
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        let resolver = LocalResolver::new("local", store);
        let mut reg = SubstitutionRegistry::new();
        let placeholder = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();

        let server_cfg = Arc::new(server_config_for_sni(&inter, "api.openai.com").unwrap());
        let captured: Arc<Mutex<Option<PreparedRequest>>> = Arc::new(Mutex::new(None));

        // Terminator side: accept one connection, terminate+substitute, mock the
        // upstream by capturing the prepared request and replying canned bytes.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cap = Arc::clone(&captured);
        let cfg = Arc::clone(&server_cfg);
        let server = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let endpoint = SubstitutionEndpoint::new(&reg, &resolver);
            let orig_dst: SocketAddr = "203.0.113.7:443".parse().unwrap();
            terminate_and_substitute(sock, cfg, orig_dst, &endpoint, |prepared| {
                *cap.lock().unwrap() = Some(prepared.clone());
                Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec())
            })
            .unwrap();
        });

        // Guest side: a real rustls client trusting the per-VM intermediate.
        let client_cfg = Arc::new(client_config_trusting(inter.cert_pem()));
        let server_name = rustls::pki_types::ServerName::try_from("api.openai.com").unwrap();
        let mut conn = rustls::ClientConnection::new(client_cfg, server_name).unwrap();
        let mut sock = TcpStream::connect(addr).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let req = format!(
            "GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer {placeholder}\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).unwrap();
        tls.flush().unwrap();
        let mut resp = Vec::new();
        let _ = tls.read_to_end(&mut resp);
        server.join().unwrap();

        // The handshake succeeded (client trusted the minted leaf) AND the
        // response came back through the terminated tunnel.
        assert!(
            resp.starts_with(b"HTTP/1.1 200 OK"),
            "client got: {:?}",
            String::from_utf8_lossy(&resp)
        );
        // The upstream (mock) saw the REAL credential — placeholder substituted.
        let seen = captured.lock().unwrap().clone().expect("forward ran");
        let auth = seen
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        assert_eq!(auth, "Bearer REALTOKEN");
        // And the re-origination URL is https (upstream dialled over TLS).
        assert!(seen.url.starts_with("https://api.openai.com/v1/x"));
    }

    #[test]
    fn serialize_http_response_reframes_with_content_length() {
        let body = b"hello";
        let out = serialize_http_response(
            200,
            &[
                ("content-type".into(), "text/plain".into()),
                // framing headers must be dropped + re-emitted
                ("transfer-encoding".into(), "chunked".into()),
                ("content-length".into(), "999".into()),
            ],
            body,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("content-type: text/plain\r\n"));
        assert!(!text.contains("chunked"));
        assert!(text.contains("Content-Length: 5\r\n")); // body.len(), not 999
        assert!(text.contains("Connection: close\r\n\r\n"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn serialize_http_response_drops_crlf_smuggling_header() {
        let out = serialize_http_response(200, &[("x".into(), "a\r\nInjected: b".into())], b"");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("Injected"));
    }

    #[test]
    fn unbound_sni_is_spliced_without_termination() {
        // A mock upstream that records the raw bytes it received and replies.
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let rx = Arc::clone(&received);
        let up = std::thread::spawn(move || {
            let (mut conn, _) = upstream.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = conn.read(&mut buf).unwrap();
            rx.lock().unwrap().extend_from_slice(&buf[..n]);
            conn.write_all(b"SERVERHELLO-RAW").unwrap();
            conn.shutdown(Shutdown::Write).ok();
        });

        // Terminator side: accept the guest conn and splice it straight to the
        // upstream — no TLS config, no intermediate, no leaf minted.
        let term = TcpListener::bind("127.0.0.1:0").unwrap();
        let term_addr = term.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (guest, _) = term.accept().unwrap();
            splice_unbound(guest, up_addr, Duration::from_secs(5)).unwrap();
        });

        // Guest sends raw (would-be ClientHello) bytes; they must arrive verbatim.
        let mut client = TcpStream::connect(term_addr).unwrap();
        let raw_hello = b"\x16\x03\x01RAW-CLIENT-HELLO-BYTES";
        client.write_all(raw_hello).unwrap();
        client.shutdown(Shutdown::Write).ok();
        let mut back = Vec::new();
        client.read_to_end(&mut back).unwrap();

        server.join().unwrap();
        up.join().unwrap();

        // Bytes passed through unchanged in BOTH directions — proof the
        // terminator never decrypted or rewrote the stream.
        assert_eq!(received.lock().unwrap().as_slice(), raw_hello);
        assert_eq!(back, b"SERVERHELLO-RAW");
    }
}
