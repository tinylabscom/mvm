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

/// Cap on the bytes we peek looking for the SNI. A ClientHello carrying SNI is
/// far smaller; this bounds the peek so a guest can't make us buffer unboundedly
/// before we've even decided bound-vs-unbound.
pub const MAX_CLIENT_HELLO_PEEK: usize = 8 * 1024;

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
}
