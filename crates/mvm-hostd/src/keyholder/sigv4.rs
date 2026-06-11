//! AWS SigV4 canonical-request construction.
//!
//! [`Signer::sign_sigv4`](super::signer::Signer::sign_sigv4) takes a
//! *prepared* [`SigV4Input`] (a canonical request + scope). This module builds
//! that canonical request from an actual HTTP request so the substitution
//! endpoint can sign a SigV4 secret's request on the forward path — the signing
//! key never leaves the signer.
//!
//! Canonicalization follows the AWS SigV4 spec; it is validated against the
//! published `aws-sig-v4-test-suite` **get-vanilla** vector (exact canonical
//! request + end-to-end signature) plus structural tests (query sort, payload
//! hash, header sort).
//!
//! Scope / known limitation: the canonical URI passes the request path through
//! as-is (correct for clean API paths — `/v1/chat/completions` — and the S3
//! single-encode rule). The non-S3 *double-encode* rule and the UTF-8 / reserved-
//! char path edge cases need the full test-suite vector matrix and are a tracked
//! follow-up; do not rely on this for paths containing percent-encoded or
//! reserved characters on a non-S3 service until those vectors are wired.

use sha2::{Digest, Sha256};
use url::Url;

use super::signer::SigV4Input;

/// Errors building a [`SigV4Input`] from an HTTP request.
#[derive(Debug, thiserror::Error)]
pub enum SigV4BuildError {
    #[error("invalid request url: {0}")]
    BadUrl(String),
    #[error("SigV4 requires an `x-amz-date` header (yyyymmddThhmmssZ)")]
    MissingAmzDate,
    #[error("`x-amz-date` value {0:?} is not yyyymmddThhmmssZ")]
    BadAmzDate(String),
}

/// Build a [`SigV4Input`] from an HTTP request. `region`/`service` name the
/// credential scope; the `x-amz-date` header supplies the timestamp (and its
/// `yyyymmdd` prefix the scope date). All provided headers are signed (sorted,
/// lowercased) — a superset of the SDK default is valid as long as
/// `SignedHeaders` lists them.
pub fn build_sigv4_input(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    region: &str,
    service: &str,
) -> Result<SigV4Input, SigV4BuildError> {
    let parsed = Url::parse(url).map_err(|_| SigV4BuildError::BadUrl(url.to_string()))?;

    let canonical_uri = canonical_uri(parsed.path());
    let canonical_query = canonical_query(&parsed);

    let amz_date = headers
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("x-amz-date"))
        .map(|(_, v)| v.trim().to_string())
        .ok_or(SigV4BuildError::MissingAmzDate)?;
    if amz_date.len() < 8 || !amz_date.contains('T') {
        return Err(SigV4BuildError::BadAmzDate(amz_date));
    }
    let date_stamp = amz_date[..8].to_string();

    // Canonical headers: lowercased name, trimmed value, sorted by name.
    let mut hdrs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    hdrs.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers: String = hdrs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = hdrs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let hashed_payload = hex::encode(Sha256::digest(body));

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
    );

    Ok(SigV4Input {
        canonical_request,
        amz_date,
        date_stamp,
        region: region.to_string(),
        service: service.to_string(),
    })
}

/// Canonical URI: the request path, or `/` when empty. (See the module-level
/// note on the encoding limitation.)
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// Canonical query string: params sorted by key (then value), each key and
/// value URI-encoded, joined `k=v&…`. Empty when there is no query.
fn canonical_query(url: &Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (uri_encode(&k), uri_encode(&v)))
        .collect();
    if pairs.is_empty() {
        return String::new();
    }
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC 3986 percent-encoding of the unreserved set (used for query keys/values).
fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SecretResolver, Signer, SubstitutionRegistry};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn get_vanilla() -> SigV4Input {
        build_sigv4_input(
            "GET",
            "https://example.amazonaws.com/",
            &[
                ("Host".into(), "example.amazonaws.com".into()),
                ("X-Amz-Date".into(), "20150830T123600Z".into()),
            ],
            b"",
            "us-east-1",
            "service",
        )
        .unwrap()
    }

    #[test]
    fn builds_the_aws_get_vanilla_canonical_request_exactly() {
        // The published aws-sig-v4-test-suite `get-vanilla` canonical request.
        let expected = "GET\n/\n\nhost:example.amazonaws.com\n\
             x-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(get_vanilla().canonical_request, expected);
    }

    #[test]
    fn get_vanilla_signs_to_the_published_signature_end_to_end() {
        // From raw request → canonical → string-to-sign → signature, against
        // the published get-vanilla signature (closes the loop with the signer).
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "aws",
                &SecretBox::new(Box::new(
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
                )),
            )
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        let resolver = LocalResolver::new("local", store);
        let _reg = SubstitutionRegistry::new();
        let secret = SecretRef {
            name: "aws".into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Sigv4,
            allowed_hosts: vec!["example.amazonaws.com".into()],
        };
        let sig = Signer::new(&resolver as &dyn SecretResolver)
            .sign_sigv4(&secret, &get_vanilla())
            .unwrap();
        assert_eq!(
            sig.hex,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn canonical_query_is_sorted_and_encoded() {
        let input = build_sigv4_input(
            "GET",
            "https://h/p?b=2&a=1&c=x%20y",
            &[("X-Amz-Date".into(), "20150830T123600Z".into())],
            b"",
            "us-east-1",
            "service",
        )
        .unwrap();
        // Sorted by key; the space in `c`'s value re-encoded as %20.
        assert!(
            input.canonical_request.contains("\na=1&b=2&c=x%20y\n"),
            "canonical request:\n{}",
            input.canonical_request
        );
    }

    #[test]
    fn payload_is_hashed_and_headers_sorted() {
        let input = build_sigv4_input(
            "POST",
            "https://h/p",
            &[
                ("X-Amz-Date".into(), "20150830T123600Z".into()),
                ("Host".into(), "h".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            b"{}",
            "us-east-1",
            "service",
        )
        .unwrap();
        // Headers sorted: content-type < host < x-amz-date; signed-headers too.
        assert!(
            input
                .canonical_request
                .contains("content-type:application/json\nhost:h\nx-amz-date:")
        );
        assert!(
            input
                .canonical_request
                .contains("\ncontent-type;host;x-amz-date\n")
        );
        // Payload hash = sha256("{}").
        let want = hex::encode(Sha256::digest(b"{}"));
        assert!(input.canonical_request.ends_with(&want));
    }

    #[test]
    fn missing_amz_date_is_rejected() {
        let err = build_sigv4_input(
            "GET",
            "https://h/p",
            &[("Host".into(), "h".into())],
            b"",
            "us-east-1",
            "service",
        )
        .unwrap_err();
        assert!(matches!(err, SigV4BuildError::MissingAmzDate));
    }

    #[test]
    fn bad_url_is_rejected() {
        let err = build_sigv4_input(
            "GET",
            "not a url",
            &[("X-Amz-Date".into(), "20150830T123600Z".into())],
            b"",
            "us-east-1",
            "service",
        )
        .unwrap_err();
        assert!(matches!(err, SigV4BuildError::BadUrl(_)));
    }
}
