//! Pure, policy-agnostic DNS resolution helpers used by the FlowMux path and
//! the legacy DNS-over-vsock handler. Extracted from the retired raw-egress
//! module so the shared upstream resolver fallback survives its deletion.

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

/// Per-address connect budget when trying an admitted set: small so an
/// unreachable address (e.g. an AAAA with no host IPv6 egress) fails over to the
/// next candidate quickly instead of stalling the request on the first.
const PER_IP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(target_os = "linux")]
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Resolve `host` to its upstream A/AAAA IPs without consulting the claim-10
/// gate. Callers are responsible for gating the name before calling this
/// fallback; the function itself performs only the upstream lookup.
pub fn resolve_hostname_ips(host: &str, timeout: Duration) -> std::io::Result<Vec<IpAddr>> {
    resolve_hostname_ips_impl(host, timeout)
}

#[cfg(target_os = "linux")]
fn resolve_hostname_ips_impl(host: &str, timeout: Duration) -> std::io::Result<Vec<IpAddr>> {
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
fn resolve_hostname_ips_impl(host: &str, timeout: Duration) -> std::io::Result<Vec<IpAddr>> {
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

    let dns_timeout = timeout.min(PER_IP_CONNECT_TIMEOUT);
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
