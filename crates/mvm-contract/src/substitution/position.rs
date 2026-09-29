//! Where a placeholder sits in a request, and putting a value there.
//!
//! A binding declares one [`InjectionMode`]; its placeholder is substituted in
//! that position and refused in any other. This module finds every placeholder
//! a request carries outside its body, names the position each is in, and
//! does the per-position encoding: a value in a URL is percent-encoded, and a
//! value in a Basic credential is substituted inside the decoded
//! `user:password` and re-encoded.
//!
//! The URL is split by hand rather than parsed, to keep this crate
//! `url`-free. The split only has to be as good as the question it answers:
//! which component a placeholder is in. A placeholder is hex after a fixed
//! prefix, so it never straddles a `/`, `?`, `&`, `=` or `#`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine as _;

use super::{SECRET_PLACEHOLDER_PREFIX, find_placeholder};
use crate::ir::InjectionMode;

/// Where a placeholder was found in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderPosition {
    /// In a header value, as written.
    Header,
    /// Inside the decoded credential of `Authorization: Basic`.
    BasicAuth,
    /// In a query parameter's value.
    QueryParam,
    /// In a path segment.
    UrlPath,
    /// Anywhere else in the URL: the authority, a query parameter's name, the
    /// fragment. No binding substitutes there.
    UrlOther,
}

impl PlaceholderPosition {
    /// The mode that substitutes in this position, or `None` where nothing
    /// does.
    #[must_use]
    pub fn mode(&self) -> Option<InjectionMode> {
        match self {
            Self::Header => Some(InjectionMode::Header),
            Self::BasicAuth => Some(InjectionMode::BasicAuth),
            Self::QueryParam => Some(InjectionMode::QueryParam),
            Self::UrlPath => Some(InjectionMode::UrlPath),
            Self::UrlOther => None,
        }
    }

    /// Whether this position is part of the request URL.
    #[must_use]
    pub fn in_url(&self) -> bool {
        matches!(self, Self::QueryParam | Self::UrlPath | Self::UrlOther)
    }

    /// The fixed label a refusal records for a placeholder found here.
    #[must_use]
    pub fn refusal_label(&self) -> &'static str {
        match self {
            Self::Header => "placeholder_in_header",
            Self::BasicAuth => "placeholder_in_basic_auth",
            Self::QueryParam | Self::UrlPath | Self::UrlOther => "placeholder_in_url",
        }
    }
}

/// One placeholder found in a request, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedPlaceholder {
    pub position: PlaceholderPosition,
    pub placeholder: String,
}

/// Every placeholder in `url` and `headers`, with the position of each.
///
/// A Basic credential is decoded and searched; a placeholder in it is reported
/// once, as [`PlaceholderPosition::BasicAuth`], and a header that is not a
/// valid Basic credential is searched as written.
#[must_use]
pub fn locate_placeholders(url: &str, headers: &[(String, String)]) -> Vec<LocatedPlaceholder> {
    let mut found = Vec::new();
    for (name, value) in headers {
        let (position, text) = match basic_credential(name, value) {
            Some(decoded) if find_placeholder(&decoded).is_some() => {
                (PlaceholderPosition::BasicAuth, decoded)
            }
            _ => (PlaceholderPosition::Header, value.clone()),
        };
        push_all(&mut found, position, &text);
    }
    let parts = UrlParts::split(url);
    push_all(&mut found, PlaceholderPosition::UrlOther, parts.head);
    push_all(&mut found, PlaceholderPosition::UrlPath, parts.path);
    if let Some(query) = parts.query {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            push_all(&mut found, PlaceholderPosition::UrlOther, key);
            push_all(&mut found, PlaceholderPosition::QueryParam, value);
        }
    }
    if let Some(fragment) = parts.fragment {
        push_all(&mut found, PlaceholderPosition::UrlOther, fragment);
    }
    found
}

fn push_all(found: &mut Vec<LocatedPlaceholder>, position: PlaceholderPosition, text: &str) {
    let mut rest = text;
    while let Some(ph) = find_placeholder(rest) {
        found.push(LocatedPlaceholder {
            position,
            placeholder: ph.to_string(),
        });
        let at = rest.find(ph).unwrap_or(0) + ph.len();
        rest = &rest[at..];
    }
}

/// The decoded `user:password` of an `Authorization: Basic` header, or `None`
/// for any other header or a credential that does not decode to UTF-8.
#[must_use]
pub fn basic_credential(name: &str, value: &str) -> Option<String> {
    if !name.eq_ignore_ascii_case("authorization") {
        return None;
    }
    let (scheme, token) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token.trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// The `Authorization` value carrying `credential` as Basic.
#[must_use]
pub fn basic_header(credential: &str) -> String {
    let mut out = String::from("Basic ");
    out.push_str(&base64::engine::general_purpose::STANDARD.encode(credential));
    out
}

/// `value` percent-encoded for a URL path segment or query value: every byte
/// but the RFC 3986 unreserved set.
#[must_use]
pub fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0xf)] as char);
        }
    }
    out
}

/// A URL split into the components a placeholder position is named by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UrlParts<'a> {
    /// Scheme and authority, `https://host:port`, or empty for an
    /// origin-form request target.
    pub head: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub fragment: Option<&'a str>,
}

impl<'a> UrlParts<'a> {
    pub(super) fn split(url: &'a str) -> Self {
        let (rest, fragment) = match url.split_once('#') {
            Some((rest, fragment)) => (rest, Some(fragment)),
            None => (url, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((rest, query)) => (rest, Some(query)),
            None => (rest, None),
        };
        let path_start = match rest.find("://") {
            Some(scheme_end) => {
                let authority = scheme_end + 3;
                rest[authority..]
                    .find('/')
                    .map_or(rest.len(), |slash| authority + slash)
            }
            None => 0,
        };
        Self {
            head: &rest[..path_start],
            path: &rest[path_start..],
            query,
            fragment,
        }
    }

    pub(super) fn join(&self, path: &str, query: Option<&str>) -> String {
        let mut out = String::from(self.head);
        out.push_str(path);
        if let Some(query) = query {
            out.push('?');
            out.push_str(query);
        }
        if let Some(fragment) = self.fragment {
            out.push('#');
            out.push_str(fragment);
        }
        out
    }
}

/// Whether `text` mentions the placeholder prefix at all — the cheap test
/// before any splitting.
#[must_use]
pub(super) fn mentions_placeholder(text: &str) -> bool {
    text.contains(SECRET_PLACEHOLDER_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const PH: &str = "mvm-secret-00112233445566778899aabbccddeeff0011223344556677";

    fn located(url: &str, headers: &[(&str, String)]) -> Vec<(PlaceholderPosition, String)> {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        locate_placeholders(url, &headers)
            .into_iter()
            .map(|l| (l.position, l.placeholder))
            .collect()
    }

    #[test]
    fn every_position_is_named() {
        use PlaceholderPosition::*;
        let basic = basic_header(&alloc::format!("user:{PH}"));
        let bearer = alloc::format!("Bearer {PH}");
        let found = located(
            &alloc::format!("https://h.example/bot{PH}/send?key={PH}&{PH}=v#{PH}"),
            &[("Authorization", basic), ("X-Api-Key", bearer)],
        );
        let positions: Vec<_> = found.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            positions,
            vec![BasicAuth, Header, UrlPath, QueryParam, UrlOther, UrlOther]
        );
        assert!(found.iter().all(|(_, ph)| ph == PH));
    }

    #[test]
    fn a_placeholder_in_the_authority_is_not_in_the_path() {
        let found = located(&alloc::format!("https://{PH}.example/x"), &[]);
        assert_eq!(found, vec![(PlaceholderPosition::UrlOther, PH.to_string())]);
        let found = located(&alloc::format!("/v1/{PH}"), &[]);
        assert_eq!(found, vec![(PlaceholderPosition::UrlPath, PH.to_string())]);
    }

    #[test]
    fn a_basic_header_without_a_placeholder_in_it_is_searched_as_written() {
        let found = located(
            "https://h/",
            &[("Authorization", alloc::format!("Basic {PH}"))],
        );
        assert_eq!(found, vec![(PlaceholderPosition::Header, PH.to_string())]);
        assert!(basic_credential("X-Other", &basic_header("a:b")).is_none());
        assert_eq!(
            basic_credential("authorization", &basic_header("a:b")).as_deref(),
            Some("a:b")
        );
    }

    #[test]
    fn percent_encoding_keeps_only_the_unreserved_set() {
        assert_eq!(percent_encode("aZ09-._~"), "aZ09-._~");
        assert_eq!(
            percent_encode("a b/c?d&e=f+g%"),
            "a%20b%2Fc%3Fd%26e%3Df%2Bg%25"
        );
    }

    #[test]
    fn a_split_url_joins_back_unchanged() {
        for url in [
            "https://h.example:8443/a/b?x=1&y=2#frag",
            "https://h.example",
            "/origin/form?q",
            "https://h.example/?",
        ] {
            let parts = UrlParts::split(url);
            assert_eq!(parts.join(parts.path, parts.query), url, "{url}");
        }
    }
}
