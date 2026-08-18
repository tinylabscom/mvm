//! Host-side hostname resolution for the egress path.
//!
//! This module used to be the raw-TCP egress serve loop: a guest opened the
//! relayed stream, wrote an unauthenticated `host:port` line or an `MVM_*` verb
//! marker, and the host dispatched on it. That protocol is gone — every guest
//! speaks FlowMux, where the same verbs are typed frames on an authenticated
//! session.
//!
//! What survives is the resolution half, which was never part of that dispatch.
//! `dns_handler` and `socks5_udp` call [`resolve_hostname_ips_pure`] to pin a
//! name to the addresses the claim-10 gate then admits, on the FlowMux path as
//! much as anywhere. The gate decision itself is the shared [`EgressGate`]
//! every backend agrees on — never a second one here.

// Both halves of `resolve_hostname_ips_pure` take these; only the Linux half
// speaks DNS itself.
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[cfg(target_os = "linux")]
use hickory_proto::op::{Message, MessageType, OpCode, Query};
#[cfg(target_os = "linux")]
use hickory_proto::rr::rdata::{A, AAAA};
#[cfg(target_os = "linux")]
use hickory_proto::rr::{Name, RData, RecordType};
#[cfg(target_os = "linux")]
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

#[cfg(target_os = "linux")]
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

// The guest-facing raw dispatcher is gone.
//
// It read an unauthenticated first line — a bare `host:port`, or one of the
// `MVM_*` verb markers — and then spliced or dispatched on it. Every guest that
// used it now speaks FlowMux, where the same verbs are typed frames on an
// authenticated, sequence-numbered session. `xtask check-one-guest-protocol`
// fails the build if a second guest→host protocol comes back.
//
// What remains below is DNS resolution, which was never part of that dispatch:
// `dns_handler` and `socks5_udp` call `resolve_hostname_ips_pure` to pin a name
// to its admitted addresses, on the FlowMux path as much as anywhere.

#[cfg(target_os = "linux")]
pub(crate) fn resolve_hostname_ips_pure(
    host: &str,
    timeout: Duration,
) -> std::io::Result<Vec<IpAddr>> {
    let upstreams = load_upstreams_from_resolv_conf(RESOLV_CONF_PATH)?;
    if upstreams.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no nameservers found in {RESOLV_CONF_PATH}"),
        ));
    }
    let timeout = timeout.min(DNS_QUERY_TIMEOUT);
    let mut ips = Vec::new();
    ips.extend(query_upstreams(host, RecordType::A, &upstreams, timeout)?);
    ips.extend(query_upstreams(
        host,
        RecordType::AAAA,
        &upstreams,
        timeout,
    )?);
    if ips.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("dns lookup {host}: no A/AAAA records returned"),
        ));
    }
    Ok(ips)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn resolve_hostname_ips_pure(
    host: &str,
    timeout: Duration,
) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    use std::sync::mpsc;
    use std::thread;

    let host = host.to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (host.as_str(), 0u16)
            .to_socket_addrs()
            .map(|iter| iter.map(|addr| addr.ip()).collect());
        let _ = tx.send(result);
    });

    let dns_timeout = timeout.min(Duration::from_secs(3));
    match rx.recv_timeout(dns_timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS resolution timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(std::io::Error::other("DNS resolution thread disconnected"))
        }
    }
}

#[cfg(target_os = "linux")]
fn load_upstreams_from_resolv_conf(path: &str) -> std::io::Result<Vec<SocketAddr>> {
    let body = std::fs::read_to_string(path)?;
    let mut upstreams = Vec::new();
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = parts.next() else {
            continue;
        };
        let ip = addr.parse::<IpAddr>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid nameserver {addr:?} in {path}: {e}"),
            )
        })?;
        upstreams.push(SocketAddr::new(ip, 53));
    }
    Ok(upstreams)
}

#[cfg(target_os = "linux")]
fn query_upstreams(
    host: &str,
    record_type: RecordType,
    upstreams: &[SocketAddr],
    timeout: Duration,
) -> std::io::Result<Vec<IpAddr>> {
    let packet = build_dns_query(host, record_type)?;
    let request = decode_dns_message(&packet)?;
    for upstream in upstreams {
        if let Ok(response) = query_upstream(*upstream, &packet, timeout) {
            let ips = parse_dns_response(&request, &response, record_type)?;
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
    }
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn build_dns_query(host: &str, record_type: RecordType) -> std::io::Result<Vec<u8>> {
    let name = Name::from_ascii(host).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid dns hostname {host:?}: {e}"),
        )
    })?;
    let mut message = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    encode_dns_message(message)
}

#[cfg(target_os = "linux")]
fn encode_dns_message(message: Message) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut out);
    message.emit(&mut encoder).map_err(invalid_dns_data)?;
    Ok(out)
}

#[cfg(target_os = "linux")]
fn decode_dns_message(packet: &[u8]) -> std::io::Result<Message> {
    let mut decoder = hickory_proto::serialize::binary::BinDecoder::new(packet);
    Message::read(&mut decoder).map_err(invalid_dns_data)
}

#[cfg(target_os = "linux")]
fn parse_dns_response(
    request: &Message,
    packet: &[u8],
    record_type: RecordType,
) -> std::io::Result<Vec<IpAddr>> {
    let response = decode_dns_message(packet)?;
    if response.metadata.message_type != MessageType::Response
        || response.metadata.id != request.metadata.id
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "upstream DNS response did not match the forwarded query",
        ));
    }
    Ok(response
        .answers
        .iter()
        .filter_map(|answer| match (record_type, &answer.data) {
            (RecordType::A, RData::A(A(ipv4))) => Some(IpAddr::V4(*ipv4)),
            (RecordType::AAAA, RData::AAAA(AAAA(ipv6))) => Some(IpAddr::V6(*ipv6)),
            _ => None,
        })
        .collect())
}

#[cfg(target_os = "linux")]
fn query_upstream(
    upstream: SocketAddr,
    packet: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let bind_addr = match upstream.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.connect(upstream)?;
    socket.send(packet)?;
    let mut buf = vec![0u8; 1232];
    let len = socket.recv(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(target_os = "linux")]
fn invalid_dns_data(err: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

#[cfg(test)]
mod tests {
    // Linux-only: every test below exercises the DNS helpers, which are
    // themselves `cfg(target_os = "linux")`. Left ungated this import reads as
    // unused on macOS, and removing it there breaks the Linux build — the
    // blind spot `just check-gated` exists for.
    #[cfg(target_os = "linux")]
    use super::*;

    #[cfg(target_os = "linux")]
    use hickory_proto::rr::{Name, Record};

    #[cfg(target_os = "linux")]
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    /// A default-deny gate + a well-formed target ⇒ the host nacks the connect and
    /// closes without ever opening an upstream socket (fail closed).
    #[cfg(target_os = "linux")]
    #[cfg(target_os = "linux")]
    #[cfg(target_os = "linux")]
    #[cfg(target_os = "linux")]
    #[test]
    fn load_upstreams_from_resolv_conf_parses_nameservers() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("resolv.conf");
        std::fs::write(
            &path,
            "\
# comment
nameserver 1.1.1.1
options edns0 trust-ad
nameserver 2606:4700:4700::1111
",
        )
        .unwrap();

        let upstreams = load_upstreams_from_resolv_conf(path.to_str().unwrap()).unwrap();
        assert_eq!(
            upstreams,
            vec![
                "1.1.1.1:53".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_dns_response_extracts_ip_answers() {
        let request =
            decode_dns_message(&build_dns_query("cache.nixos.org", RecordType::A).unwrap())
                .unwrap();

        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.add_query(Query::query(
            Name::from_ascii("cache.nixos.org").unwrap(),
            RecordType::A,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("cache.nixos.org").unwrap(),
            30,
            RData::A(A(Ipv4Addr::new(151, 101, 1, 91))),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("cache.nixos.org").unwrap(),
            30,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111))),
        ));

        let encoded = encode_dns_message(response).unwrap();
        let a_records = parse_dns_response(&request, &encoded, RecordType::A).unwrap();
        let aaaa_records = parse_dns_response(&request, &encoded, RecordType::AAAA).unwrap();

        assert_eq!(a_records, vec!["151.101.1.91".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            aaaa_records,
            vec!["2606:4700::1111".parse::<IpAddr>().unwrap()]
        );
    }
}
