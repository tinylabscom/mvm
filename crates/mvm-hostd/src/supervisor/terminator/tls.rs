//! Server-side TLS configuration for terminated egress and ingress.
//!
//! A terminated flow to a bound host presents a leaf minted for that host under
//! the per-VM name-constrained CA, so a guest trusting only that CA validates
//! it. The helpers that write a response back onto a terminated stream live
//! here too, because every terminated response is re-framed rather than copied.
//!
//! **Honest boundary (defense in depth, not the control):** Python `ssl` and
//! older Node don't enforce X.509 `nameConstraints` client-side, so the in-guest
//! cert constraint is a courtesy. The real egress boundary is the host-side
//! allow-list check in `prepare_request` (claim 12); the name constraint only
//! bounds blast radius if a per-VM CA ever leaked.

use anyhow::{Context, Result, anyhow};
use mvm_core::crypto::egress_ca::VmEgressCa;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Build a rustls `ServerConfig` that presents a freshly-minted leaf for `sni`
/// chained to the per-VM intermediate (`[leaf, intermediate]`), so a guest that
/// trusts the intermediate validates the terminated connection. The name is
/// already known, so we mint directly rather than via a `ResolvesServerCert`.
pub fn server_config_for_sni(intermediate: &VmEgressCa, sni: &str) -> Result<rustls::ServerConfig> {
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

/// Build a TLS 1.3-capable server config from one host-owned PEM bundle.
/// The bundle may contain a leaf plus intermediates and exactly one private
/// key. Callers resolve it inside the endpoint and drop the zeroizing source
/// immediately after this function returns.
pub fn server_config_from_pem_bundle(pem: &str) -> Result<rustls::ServerConfig> {
    let chain = pem_certs(pem).context("parse ingress TLS certificate chain")?;
    let key = pem_private_key(pem).context("parse ingress TLS private key")?;
    rustls::ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .context("rustls ingress protocol versions")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("rustls ingress server config")
}

/// Whether a response header belongs to the upstream leg's transfer framing
/// rather than to the response itself. The terminator re-frames what it writes
/// back, so carrying these across would describe the wrong message.
pub(super) fn is_framing_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "transfer-encoding" | "content-length" | "connection"
    )
}

/// Whether a header name or value carries a bare CR or LF, which would end the
/// header line early and let an upstream response inject one of its own.
pub(super) fn smuggles_crlf(name: &str, value: &str) -> bool {
    name.bytes()
        .chain(value.bytes())
        .any(|b| b == b'\r' || b == b'\n')
}

/// A minimal reason phrase for common statuses; "" for the rest (clients accept
/// an empty reason phrase per RFC 7230).
pub(super) fn reason_phrase(status: u16) -> &'static str {
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
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// Parse a PEM bundle into DER certs (the leaf + intermediate chain).
fn pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
    let certs = certs.context("read PEM certs")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate in PEM"));
    }
    Ok(certs)
}

/// Parse a PEM private key (PKCS#8 — rcgen emits PKCS#8) into a rustls key.
fn pem_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).context("read PEM private key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_server_config_accepts_one_host_owned_pem_bundle() {
        let intermediate = mvm_core::crypto::egress_ca::VmEgressCa::mint(&["localhost"]).unwrap();
        let leaf = intermediate.mint_leaf("localhost").unwrap();
        let bundle = format!(
            "{}{}{}",
            leaf.cert_pem,
            intermediate.cert_pem(),
            leaf.key_pem
        );
        server_config_from_pem_bundle(&bundle).unwrap();
    }

    #[test]
    fn upstream_transfer_framing_is_recognised_in_any_case() {
        for name in ["transfer-encoding", "Content-Length", "CONNECTION"] {
            assert!(is_framing_header(name), "{name}");
        }
        assert!(!is_framing_header("content-type"));
    }

    #[test]
    fn a_bare_cr_or_lf_in_a_header_name_or_value_is_smuggling() {
        assert!(smuggles_crlf("x", "a\r\nInjected: b"));
        assert!(smuggles_crlf("x", "a\nb"));
        assert!(smuggles_crlf("x\r", "a"));
        assert!(!smuggles_crlf("content-type", "text/plain"));
    }
}
