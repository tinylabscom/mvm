//! The common parser for workload egress allow-host requests.

use crate::network_policy::{HostPort, is_banned_ssh_port};
use anyhow::Result;
use mvm_contract::policy::network_policy::CLEARTEXT_SCHEME_PREFIX;

/// Parse one `--allow-host` entry, defaulting a bare host to HTTPS. The
/// refusal names the flag; see [`parse_destination`] for the rules.
///
/// # Errors
///
/// Whatever [`parse_destination`] refuses.
pub fn parse_allow_host(entry: &str) -> Result<HostPort> {
    // One message, not a chain, so every caller shows the whole reason.
    parse_destination(entry)
        .map_err(|error| anyhow::anyhow!("invalid --allow-host {entry:?}: {error:#}"))
}

/// Parse one user-authored egress destination — a `--allow-host` value or a
/// workload file's `allow_hosts` entry — defaulting a bare host to HTTPS.
///
/// `http://HOST[:PORT]` admits plain HTTP to that destination, defaulting
/// the port to 80; it is the only way a production workload may send
/// cleartext to it. This is the one parser that reads the scheme; the
/// canonical `HOST:PORT` parser does not.
///
/// # Errors
///
/// Empty hosts, malformed explicit ports, hosts that
/// [`check_destination_host`] refuses, and SSH destinations are refused.
pub fn parse_destination(entry: &str) -> Result<HostPort> {
    let (rest, cleartext) = match entry.strip_prefix(CLEARTEXT_SCHEME_PREFIX) {
        Some(rest) => (rest, true),
        None => (entry, false),
    };
    let default_port = if cleartext { 80 } else { 443 };
    let mut parsed = match bracketed_ipv6(rest, default_port) {
        Some(parsed) => parsed,
        None => parse_unbracketed(rest, default_port),
    }?;
    parsed.cleartext = cleartext;
    check_destination_host(&parsed.host)?;
    if is_banned_ssh_port(parsed.port) {
        anyhow::bail!("{entry:?} requests TCP/22, but SSH sessions are banned in microVMs");
    }
    Ok(parsed)
}

/// `[v6]` or `[v6]:port`, the bracketed spelling of an IPv6 literal. `None`
/// when `entry` is not brackets around an IPv6 address.
fn bracketed_ipv6(entry: &str, default_port: u16) -> Option<Result<HostPort>> {
    let (inner, tail) = entry.strip_prefix('[')?.split_once(']')?;
    let addr = inner.parse::<std::net::Ipv6Addr>().ok()?;
    let port = match tail.strip_prefix(':') {
        _ if tail.is_empty() => Ok(default_port),
        Some(port) => port
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid port {port:?}")),
        None => Err(anyhow::anyhow!("unexpected {tail:?} after the address")),
    };
    Some(port.map(|port| HostPort::new(addr.to_string(), port)))
}

fn parse_unbracketed(entry: &str, default_port: u16) -> Result<HostPort> {
    match entry.rsplit_once(':') {
        Some(_) => Ok(entry.parse()?),
        None if entry.is_empty() => anyhow::bail!("a destination cannot be empty"),
        None => Ok(HostPort::new(entry, default_port)),
    }
}

/// Refuse an egress destination host the endpoint's gate could never pin.
///
/// The gate admits a destination only as an IP literal or a DNS name it
/// resolves at endpoint start, and one entry it cannot pin turns the whole
/// allow-list into deny-all. So a wildcard, CIDR text, a bracketed
/// non-address or anything else that is not a host name is refused here, by shape. A
/// well-formed name that does not resolve is not caught: that needs a DNS
/// lookup, which admission does not do.
///
/// # Errors
///
/// Names the refused host and why.
pub fn check_destination_host(host: &str) -> Result<()> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let reason = if host.contains('*') {
        "a wildcard is not a host; list each host"
    } else if host.contains('/') {
        "CIDR ranges are not supported; list each host or address"
    } else if host.starts_with('[') || host.ends_with(']') {
        "only an IPv6 address may be bracketed"
    } else if is_dns_name(host) {
        return Ok(());
    } else {
        "not a host name"
    };
    anyhow::bail!("{host:?}: {reason}")
}

fn is_dns_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_and_ip_literals_are_accepted() {
        for host in [
            "api.github.com",
            "localhost",
            "my-service_1.internal",
            "93.184.216.34",
            "2001:db8::1",
        ] {
            check_destination_host(host).unwrap_or_else(|e| panic!("{host}: {e:#}"));
        }
        assert_eq!(parse_allow_host("api.github.com").unwrap().port, 443);
        assert_eq!(parse_allow_host("::1:8443").unwrap().host, "::1");
        let bracketed = parse_allow_host("[2001:db8::1]:8443").unwrap();
        assert_eq!(
            (bracketed.host.as_str(), bracketed.port),
            ("2001:db8::1", 8443)
        );
        assert_eq!(parse_allow_host("[::1]").unwrap().port, 443);
    }

    #[test]
    fn shapes_the_gate_cannot_pin_are_refused_naming_the_entry() {
        for (entry, hint) in [
            ("*.example.com", "wildcard"),
            ("*.example.com:443", "wildcard"),
            ("10.0.0.0/8:443", "CIDR"),
            ("[api.example.com]:443", "bracket"),
            ("[::1]:http", "invalid port"),
            ("exa mple.com", "not a host name"),
            ("bad..name", "not a host name"),
            ("-lead.example.com", "not a host name"),
            ("trail-.example.com", "not a host name"),
        ] {
            let err = format!("{:#}", parse_allow_host(entry).unwrap_err());
            assert!(err.contains(entry), "{entry}: {err}");
            assert!(err.contains(hint), "{entry}: {err}");
        }
    }

    /// `http://` is the opt-in: it marks the entry cleartext and moves the
    /// default port to 80. Without it nothing is marked, whatever the port.
    #[test]
    fn an_http_entry_opts_its_destination_into_cleartext() {
        let opted = parse_allow_host("http://example.com").unwrap();
        assert_eq!(opted, HostPort::new("example.com", 80).with_cleartext());
        let on_port = parse_allow_host("http://example.com:8080").unwrap();
        assert_eq!(on_port, HostPort::new("example.com", 8080).with_cleartext());
        let v6 = parse_allow_host("http://[2001:db8::1]").unwrap();
        assert_eq!(v6, HostPort::new("2001:db8::1", 80).with_cleartext());
        assert!(!parse_allow_host("example.com:80").unwrap().cleartext);
        assert!(!parse_allow_host("example.com").unwrap().cleartext);
    }

    /// The opt-in is a scheme, not a free-form prefix: anything else that
    /// looks like a URL is refused rather than read as a host name.
    #[test]
    fn other_schemes_and_paths_are_refused() {
        for entry in [
            "https://example.com",
            "http://",
            "http://example.com/path",
            "http://example.com:22",
        ] {
            assert!(parse_allow_host(entry).is_err(), "{entry}");
        }
    }

    #[test]
    fn an_overlong_name_is_refused() {
        let label = "a".repeat(64);
        assert!(check_destination_host(&format!("{label}.com")).is_err());
        let name = vec!["a".repeat(60); 5].join(".");
        assert!(check_destination_host(&name).is_err());
    }
}
