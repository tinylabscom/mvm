//! In-guest DNS resolver for configured local addon hostnames.
//!
//! Thin wrapper over `hickory-dns`. Listens on `127.0.0.1:53` and
//! `::1:53` only; authoritative only for exact hostnames configured
//! in the per-instance zone; forwards everything else upstream. The
//! zone is loaded from the config disk's `addon_dns_zone` (see
//! `mvm/specs/contracts/local-addon-dns.md`).
//!
//! This crate intentionally contains no distributed mesh logic.

#![warn(missing_docs)]

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// One A-record entry the resolver serves. The config-disk zone is a
/// JSON array of these (see contract spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRecord {
    /// Fully-qualified hostname (e.g. `db.dev.internal`).
    pub hostname: String,
    /// IPv4 address the resolver returns for `A` queries against
    /// `hostname`.
    pub address: Ipv4Addr,
}

/// Parse the config disk's `addon_dns_zone` JSON file into a list of
/// records. The on-disk format is the JSON shape spec'd in
/// `mvm/specs/contracts/local-addon-dns.md`:
///
/// ```jsonc
/// [
///   {"hostname": "db.dev.internal", "address": "10.255.0.1"},
///   {"hostname": "cache.dev.internal", "address": "10.255.0.2"}
/// ]
/// ```
pub fn load_zone(path: &Path) -> Result<Vec<ZoneRecord>> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("could not read zone file at {}", path.display()))?;
    if body.trim().is_empty() {
        return Ok(vec![]);
    }
    serde_json::from_str(&body).with_context(|| {
        format!(
            "could not parse zone file at {} as a JSON array of {{hostname, address}} entries",
            path.display()
        )
    })
}

/// Load upstream resolver addresses from a `resolv.conf`-style file.
///
/// Only `nameserver` lines are consumed. IPv4/IPv6 literals are
/// mapped to port 53. Missing files are handled by the caller so init
/// can choose whether an upstream snapshot is required.
pub fn load_upstreams_from_resolv_conf(path: &Path) -> Result<Vec<SocketAddr>> {
    let body = std::fs::read_to_string(path).with_context(|| {
        format!(
            "could not read upstream resolver file at {}",
            path.display()
        )
    })?;
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
        let ip = IpAddr::from_str(addr).with_context(|| {
            format!("invalid nameserver address {addr:?} in {}", path.display())
        })?;
        upstreams.push(SocketAddr::new(ip, 53));
    }
    Ok(upstreams)
}

/// In-process zone state. Owned by the resolver loop; refreshed on
/// SIGHUP. Methods are intentionally read-only at this layer — zone
/// updates flow through `load_zone` + `Zone::set_records`.
#[derive(Debug, Clone)]
pub struct Zone {
    records: Vec<ZoneRecord>,
}

impl Zone {
    /// Build a `Zone` from a parsed record list.
    pub fn new(records: Vec<ZoneRecord>) -> Self {
        Self { records }
    }

    /// Replace the in-memory zone wholesale. Caller responsibility:
    /// take a write lock if the resolver is reading concurrently.
    pub fn set_records(&mut self, records: Vec<ZoneRecord>) {
        self.records = records;
    }

    /// Borrow the current record list. Useful for callers that want
    /// to snapshot the zone under a read lock without re-cloning per
    /// query.
    pub fn records(&self) -> &[ZoneRecord] {
        &self.records
    }

    /// Look up an A record. Case-insensitive on the hostname.
    /// Returns the first matching record; the contract spec
    /// guarantees at most one entry per hostname per instance.
    pub fn lookup(&self, hostname: &str) -> Option<&ZoneRecord> {
        let hostname = normalize_hostname(hostname);
        self.records
            .iter()
            .find(|r| normalize_hostname(&r.hostname).eq_ignore_ascii_case(hostname))
    }

    /// Whether the zone is authoritative for `hostname`. Authority
    /// is intentionally limited to exact configured records so local
    /// addon DNS can mirror production hostnames without hijacking a
    /// whole domain or suffix.
    pub fn is_authoritative_for(&self, hostname: &str) -> bool {
        self.lookup(hostname).is_some()
    }

    /// Number of records currently loaded. Useful for "no-op when
    /// zone is empty" diagnostics in the binary.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the zone has zero records loaded (and thus the
    /// resolver should idle as a no-op).
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Reload-friendly zone handle. Shared between the UDP serve loop and
/// the SIGHUP reload task. Read-locked briefly while snapshotting per
/// datagram so the lock never crosses an `.await` boundary; the write
/// lock taken by [`reload_zone_from_path`] is held only long enough to
/// swap the record list. In-flight queries observe either the old or
/// new zone — never a partially updated zone.
pub type SharedZone = Arc<RwLock<Zone>>;

/// Wrap an existing [`Zone`] for use as a [`SharedZone`].
pub fn shared_zone(zone: Zone) -> SharedZone {
    Arc::new(RwLock::new(zone))
}

/// Reload a zone file from disk into a [`SharedZone`] without dropping
/// in-flight queries.
///
/// The file is parsed up-front; the write lock on `zone` is acquired
/// only after the new record list is constructed, so a malformed or
/// missing file leaves the previous zone untouched. An empty file
/// (the no-op contract) is honored and produces a zero-record zone.
///
/// Returns the number of records now loaded.
pub async fn reload_zone_from_path(zone: &SharedZone, path: &Path) -> Result<usize> {
    let records = load_zone(path)?;
    let count = records.len();
    let mut guard = zone.write().await;
    guard.set_records(records);
    Ok(count)
}

fn normalize_hostname(hostname: &str) -> &str {
    hostname.trim_end_matches('.')
}

/// Runtime configuration for the in-guest DNS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerConfig {
    /// Loopback addresses the DNS server binds.
    pub bind_addrs: Vec<SocketAddr>,
    /// Explicit upstream recursive resolvers used for non-configured
    /// names. This must be captured before `/etc/resolv.conf` points
    /// at the addon DNS server.
    pub upstream_addrs: Vec<SocketAddr>,
    /// Timeout for each upstream forwarding attempt.
    pub upstream_timeout: Duration,
}

impl DnsServerConfig {
    /// Production default bind set. Upstreams are intentionally empty
    /// until init wiring provides a pre-rewrite resolver snapshot.
    pub fn production_default() -> Self {
        Self {
            bind_addrs: vec![
                SocketAddr::from(([127, 0, 0, 1], 53)),
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 53)),
            ],
            upstream_addrs: vec![],
            upstream_timeout: Duration::from_secs(2),
        }
    }

    /// Validate the security-sensitive network shape before binding.
    pub fn validate(&self) -> std::io::Result<()> {
        if self.bind_addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "addon DNS server requires at least one loopback bind address",
            ));
        }
        for bind in &self.bind_addrs {
            if !bind.ip().is_loopback() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("addon DNS bind address must be loopback, got {bind}"),
                ));
            }
        }
        for upstream in &self.upstream_addrs {
            if self.bind_addrs.contains(upstream) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("addon DNS upstream must not point at its own listener {upstream}"),
                ));
            }
        }
        Ok(())
    }
}

/// Serve DNS over UDP on the configured loopback addresses, sharing
/// a reload-aware zone handle with any concurrent SIGHUP task.
pub async fn run_udp_server(zone: SharedZone, config: DnsServerConfig) -> std::io::Result<()> {
    config.validate()?;
    let config = Arc::new(config);

    let mut sockets = Vec::with_capacity(config.bind_addrs.len());
    for bind_addr in &config.bind_addrs {
        sockets.push((UdpSocket::bind(bind_addr).await?, *bind_addr));
    }

    for (socket, bind_addr) in sockets {
        let zone = Arc::clone(&zone);
        let config = Arc::clone(&config);
        tracing::info!(%bind_addr, "addon DNS UDP listener started");
        tokio::spawn(async move {
            if let Err(err) = serve_udp_socket(socket, zone, config).await {
                tracing::warn!(error = %err, "addon DNS UDP listener stopped");
            }
        });
    }

    std::future::pending::<std::io::Result<()>>().await
}

async fn serve_udp_socket(
    socket: UdpSocket,
    zone: SharedZone,
    config: Arc<DnsServerConfig>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 1232];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        // Snapshot the zone under the read lock and release it before
        // any `.await` on upstream forwarding. Zone records are tiny
        // (hostname + IPv4) so this clone is cheap relative to the
        // network round-trip we'd otherwise hold the lock across.
        let snapshot = Zone::new(zone.read().await.records().to_vec());
        let response = handle_dns_packet(&buf[..len], &snapshot, &config).await;
        if let Some(response) = response {
            let _ = socket.send_to(&response, peer).await;
        }
    }
}

/// Handle one DNS packet. Malformed packets are answered with
/// `FORMERR` when possible and otherwise dropped.
pub async fn handle_dns_packet(
    packet: &[u8],
    zone: &Zone,
    config: &DnsServerConfig,
) -> Option<Vec<u8>> {
    let request = match decode_message(packet) {
        Ok(message) => message,
        Err(_) => return None,
    };

    if request.metadata.message_type != MessageType::Query || request.queries.len() != 1 {
        return encode_response(error_response(&request, ResponseCode::FormErr, config)).ok();
    }

    let query = &request.queries[0];
    let query_name = query.name().to_ascii();
    if let Some(record) = zone.lookup(&query_name) {
        return encode_response(local_response(&request, record, config)).ok();
    }

    forward_upstream(packet, config).await
}

fn decode_message(packet: &[u8]) -> Result<Message, hickory_proto::ProtoError> {
    let mut decoder = hickory_proto::serialize::binary::BinDecoder::new(packet);
    Message::read(&mut decoder).map_err(Into::into)
}

fn encode_response(message: Message) -> Result<Vec<u8>, hickory_proto::ProtoError> {
    let mut out = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut out);
    message.emit(&mut encoder)?;
    Ok(out)
}

fn response_base(request: &Message, recursion_available: bool) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.recursion_available = recursion_available;
    response.add_queries(request.queries.clone());
    response
}

fn local_response(
    request: &Message,
    zone_record: &ZoneRecord,
    config: &DnsServerConfig,
) -> Message {
    let mut response = response_base(request, !config.upstream_addrs.is_empty());
    response.metadata.authoritative = true;

    let query = &request.queries[0];
    if query.query_type() == RecordType::A && query.query_class() == DNSClass::IN {
        let name = query.name().clone();
        response.add_answer(Record::from_rdata(
            name,
            30,
            RData::A(A(zone_record.address)),
        ));
    }

    response
}

fn error_response(request: &Message, code: ResponseCode, config: &DnsServerConfig) -> Message {
    let mut response = response_base(request, !config.upstream_addrs.is_empty());
    response.metadata.response_code = code;
    response
}

async fn forward_upstream(packet: &[u8], config: &DnsServerConfig) -> Option<Vec<u8>> {
    for upstream in &config.upstream_addrs {
        if let Ok(response) = forward_to_upstream(packet, *upstream, config.upstream_timeout).await
        {
            return Some(response);
        }
    }

    let request = decode_message(packet).ok()?;
    encode_response(error_response(&request, ResponseCode::ServFail, config)).ok()
}

async fn forward_to_upstream(
    packet: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let bind_addr = match upstream.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(upstream).await?;
    socket.send(packet).await?;
    let mut buf = vec![0u8; 1232];
    let len = tokio::time::timeout(timeout, socket.recv(&mut buf)).await??;
    buf.truncate(len);
    let request = decode_message(packet)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let response = decode_message(&buf)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    if response.metadata.message_type != MessageType::Response
        || response.metadata.id != request.metadata.id
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "upstream DNS response did not match the forwarded query",
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::Name;
    use tempfile::tempdir;

    #[test]
    fn load_zone_parses_minimal_records() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("zone.json");
        std::fs::write(
            &path,
            r#"[
              {"hostname": "db.dev.internal", "address": "10.255.0.1"},
              {"hostname": "cache.dev.internal", "address": "10.255.0.2"}
            ]"#,
        )
        .unwrap();
        let records = load_zone(&path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].hostname, "db.dev.internal");
        assert_eq!(records[0].address, Ipv4Addr::new(10, 255, 0, 1));
    }

    #[test]
    fn load_zone_accepts_empty_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("zone.json");
        std::fs::write(&path, "").unwrap();
        assert!(load_zone(&path).unwrap().is_empty());
    }

    #[test]
    fn load_upstreams_from_resolv_conf_parses_nameservers() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("upstream-resolv.conf");
        std::fs::write(
            &path,
            "search dev.internal\nnameserver 192.0.2.53\nnameserver 2001:db8::53 # comment\n",
        )
        .unwrap();
        let upstreams = load_upstreams_from_resolv_conf(&path).unwrap();
        assert_eq!(
            upstreams,
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn zone_lookup_is_case_insensitive() {
        let zone = Zone::new(vec![ZoneRecord {
            hostname: "db.dev.internal".to_string(),
            address: Ipv4Addr::new(10, 255, 0, 1),
        }]);
        assert!(zone.lookup("db.dev.internal").is_some());
        assert!(zone.lookup("DB.DEV.INTERNAL").is_some());
        assert!(zone.lookup("missing.dev.internal").is_none());
    }

    #[test]
    fn is_authoritative_for_only_recognizes_configured_names() {
        let zone = Zone::new(vec![ZoneRecord {
            hostname: "db.dev.internal".to_string(),
            address: Ipv4Addr::new(10, 255, 0, 1),
        }]);
        assert!(zone.is_authoritative_for("db.dev.internal"));
        assert!(zone.is_authoritative_for("db.dev.internal."));
        assert!(zone.is_authoritative_for("DB.DEV.INTERNAL"));
        assert!(!zone.is_authoritative_for("cache.dev.internal"));
        assert!(!zone.is_authoritative_for("dev.internal"));
        assert!(!zone.is_authoritative_for("example.com"));
        assert!(!zone.is_authoritative_for("evil.db.dev.internal.attacker.com"));
    }

    #[test]
    fn zone_set_records_replaces_state() {
        let mut zone = Zone::new(vec![ZoneRecord {
            hostname: "old.dev.internal".to_string(),
            address: Ipv4Addr::new(10, 255, 0, 1),
        }]);
        assert_eq!(zone.len(), 1);
        zone.set_records(vec![]);
        assert_eq!(zone.len(), 0);
        assert!(zone.is_empty());
    }

    #[test]
    fn server_config_rejects_non_loopback_bind() {
        let config = DnsServerConfig {
            bind_addrs: vec!["0.0.0.0:5353".parse().unwrap()],
            upstream_addrs: vec![],
            upstream_timeout: Duration::from_millis(50),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn server_config_rejects_self_upstream() {
        let config = DnsServerConfig {
            bind_addrs: vec!["127.0.0.1:5353".parse().unwrap()],
            upstream_addrs: vec!["127.0.0.1:5353".parse().unwrap()],
            upstream_timeout: Duration::from_millis(50),
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn exact_configured_a_record_is_answered_locally() {
        let zone = Zone::new(vec![ZoneRecord {
            hostname: "db.dev.internal".to_string(),
            address: Ipv4Addr::new(127, 77, 0, 10),
        }]);
        let config = test_config(vec![]);
        let response = handle_dns_packet(
            &query_packet("DB.DEV.INTERNAL.", RecordType::A),
            &zone,
            &config,
        )
        .await
        .unwrap();
        let message = decode_message(&response).unwrap();

        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.metadata.authoritative);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(
            &message.answers[0].data,
            &RData::A(A(Ipv4Addr::new(127, 77, 0, 10)))
        );
    }

    #[tokio::test]
    async fn configured_non_a_query_is_authoritative_no_data() {
        let zone = Zone::new(vec![ZoneRecord {
            hostname: "db.dev.internal".to_string(),
            address: Ipv4Addr::new(127, 77, 0, 10),
        }]);
        let config = test_config(vec![]);
        let response = handle_dns_packet(
            &query_packet("db.dev.internal.", RecordType::AAAA),
            &zone,
            &config,
        )
        .await
        .unwrap();
        let message = decode_message(&response).unwrap();

        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.metadata.authoritative);
        assert!(message.answers.is_empty());
    }

    #[tokio::test]
    async fn sibling_name_is_forwarded_upstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let request = decode_message(&buf[..len]).unwrap();
            let mut response = response_base(&request, true);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                30,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
            ));
            let encoded = encode_response(response).unwrap();
            upstream.send_to(&encoded, peer).await.unwrap();
        });

        let zone = Zone::new(vec![ZoneRecord {
            hostname: "db.dev.internal".to_string(),
            address: Ipv4Addr::new(127, 77, 0, 10),
        }]);
        let config = test_config(vec![upstream_addr]);
        let response = handle_dns_packet(
            &query_packet("api.dev.internal.", RecordType::A),
            &zone,
            &config,
        )
        .await
        .unwrap();
        upstream_task.await.unwrap();
        let message = decode_message(&response).unwrap();

        assert!(!message.metadata.authoritative);
        assert_eq!(
            &message.answers[0].data,
            &RData::A(A(Ipv4Addr::new(192, 0, 2, 99)))
        );
    }

    #[tokio::test]
    async fn upstream_response_with_wrong_id_is_rejected() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let request = decode_message(&buf[..len]).unwrap();
            let mut response = response_base(&request, true);
            response.metadata.id = request.metadata.id.wrapping_add(1);
            let encoded = encode_response(response).unwrap();
            upstream.send_to(&encoded, peer).await.unwrap();
        });

        let zone = Zone::new(vec![]);
        let config = DnsServerConfig {
            bind_addrs: vec!["127.0.0.1:5353".parse().unwrap()],
            upstream_addrs: vec![upstream_addr],
            upstream_timeout: Duration::from_millis(100),
        };
        let response =
            handle_dns_packet(&query_packet("example.com.", RecordType::A), &zone, &config)
                .await
                .unwrap();
        upstream_task.await.unwrap();
        let message = decode_message(&response).unwrap();

        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(message.answers.is_empty());
    }

    #[tokio::test]
    async fn reload_zone_from_path_swaps_records_without_dropping_state() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("zone.json");
        std::fs::write(
            &path,
            r#"[{"hostname":"db.dev.internal","address":"127.77.0.10"}]"#,
        )
        .unwrap();
        let zone = shared_zone(Zone::new(load_zone(&path).unwrap()));

        // Concurrent readers must keep observing the old zone until
        // the write lock is released — never a partial state.
        let read_zone = Arc::clone(&zone);
        let reader = tokio::spawn(async move {
            let guard = read_zone.read().await;
            guard.lookup("db.dev.internal").cloned()
        });
        assert_eq!(
            reader.await.unwrap().unwrap().address,
            Ipv4Addr::new(127, 77, 0, 10)
        );

        // Rewrite the file with a new record set and reload.
        std::fs::write(
            &path,
            r#"[{"hostname":"cache.dev.internal","address":"127.77.0.20"}]"#,
        )
        .unwrap();
        let count = reload_zone_from_path(&zone, &path).await.unwrap();
        assert_eq!(count, 1);

        let guard = zone.read().await;
        assert!(guard.lookup("db.dev.internal").is_none());
        assert_eq!(
            guard.lookup("cache.dev.internal").unwrap().address,
            Ipv4Addr::new(127, 77, 0, 20)
        );
    }

    #[tokio::test]
    async fn reload_zone_from_path_keeps_previous_state_on_parse_error() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("zone.json");
        std::fs::write(
            &path,
            r#"[{"hostname":"db.dev.internal","address":"127.77.0.10"}]"#,
        )
        .unwrap();
        let zone = shared_zone(Zone::new(load_zone(&path).unwrap()));

        std::fs::write(&path, "this is not valid json").unwrap();
        let err = reload_zone_from_path(&zone, &path).await.unwrap_err();
        // Error path leaves the previous record set in place.
        assert!(format!("{err:#}").contains("could not parse zone file"));
        let guard = zone.read().await;
        assert_eq!(
            guard.lookup("db.dev.internal").unwrap().address,
            Ipv4Addr::new(127, 77, 0, 10)
        );
    }

    #[tokio::test]
    async fn reload_zone_from_path_keeps_previous_state_on_missing_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("zone.json");
        std::fs::write(
            &path,
            r#"[{"hostname":"db.dev.internal","address":"127.77.0.10"}]"#,
        )
        .unwrap();
        let zone = shared_zone(Zone::new(load_zone(&path).unwrap()));

        std::fs::remove_file(&path).unwrap();
        let err = reload_zone_from_path(&zone, &path).await.unwrap_err();
        assert!(format!("{err:#}").contains("could not read zone file"));
        let guard = zone.read().await;
        assert_eq!(
            guard.lookup("db.dev.internal").unwrap().address,
            Ipv4Addr::new(127, 77, 0, 10)
        );
    }

    #[tokio::test]
    async fn reload_zone_from_path_accepts_empty_file_as_no_op() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("zone.json");
        std::fs::write(
            &path,
            r#"[{"hostname":"db.dev.internal","address":"127.77.0.10"}]"#,
        )
        .unwrap();
        let zone = shared_zone(Zone::new(load_zone(&path).unwrap()));

        std::fs::write(&path, "").unwrap();
        let count = reload_zone_from_path(&zone, &path).await.unwrap();
        assert_eq!(count, 0);
        let guard = zone.read().await;
        assert!(guard.is_empty());
    }

    #[tokio::test]
    async fn running_server_observes_zone_reload_without_restart() {
        // Bind a real UDP socket on an ephemeral loopback port and
        // drive run_udp_server through its public API. The same
        // listener must answer the second query authoritatively after
        // a mid-run reload, proving no socket was torn down.
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        drop(server_socket);

        let zone = shared_zone(Zone::new(vec![]));
        let config = DnsServerConfig {
            bind_addrs: vec![server_addr],
            upstream_addrs: vec![],
            upstream_timeout: Duration::from_millis(100),
        };
        let server_zone = Arc::clone(&zone);
        let server = tokio::spawn(async move {
            // run_udp_server never completes on its own — drive it in
            // the background and abort after the assertions.
            run_udp_server(server_zone, config).await
        });

        // Wait briefly for the listener to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();

        // Before reload: empty zone, no upstreams → SERVFAIL.
        client
            .send(&query_packet("db.dev.internal.", RecordType::A))
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let len = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let pre = decode_message(&buf[..len]).unwrap();
        assert_eq!(pre.metadata.response_code, ResponseCode::ServFail);

        // Reload: populate the zone via the same handle the SIGHUP
        // task would use in production.
        {
            let mut guard = zone.write().await;
            guard.set_records(vec![ZoneRecord {
                hostname: "db.dev.internal".to_string(),
                address: Ipv4Addr::new(127, 77, 0, 42),
            }]);
        }

        // After reload: same socket, new authoritative answer.
        client
            .send(&query_packet("db.dev.internal.", RecordType::A))
            .await
            .unwrap();
        let len = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let post = decode_message(&buf[..len]).unwrap();
        assert_eq!(post.metadata.response_code, ResponseCode::NoError);
        assert!(post.metadata.authoritative);
        assert_eq!(
            &post.answers[0].data,
            &RData::A(A(Ipv4Addr::new(127, 77, 0, 42)))
        );

        server.abort();
    }

    #[test]
    fn load_upstreams_from_resolv_conf_rejects_invalid_address() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("upstream-resolv.conf");
        std::fs::write(&path, "nameserver not-an-address\n").unwrap();
        let err = load_upstreams_from_resolv_conf(&path).unwrap_err();
        assert!(format!("{err:#}").contains("invalid nameserver address"));
    }

    #[test]
    fn load_upstreams_from_resolv_conf_skips_options_and_comments() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("upstream-resolv.conf");
        std::fs::write(
            &path,
            "# host-baked default\n\
             options edns0 trust-ad\n\
             search corp.example\n\
             nameserver 192.0.2.53\n\
             ; this is a different-style comment\n\
             nameserver # inline comment swallows the address\n\
             nameserver 198.51.100.53\n",
        )
        .unwrap();
        let upstreams = load_upstreams_from_resolv_conf(&path).unwrap();
        assert_eq!(
            upstreams,
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "198.51.100.53:53".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn unconfigured_name_without_upstream_servfails() {
        let zone = Zone::new(vec![]);
        let config = test_config(vec![]);
        let response =
            handle_dns_packet(&query_packet("example.com.", RecordType::A), &zone, &config)
                .await
                .unwrap();
        let message = decode_message(&response).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(!message.metadata.recursion_available);
    }

    fn test_config(upstream_addrs: Vec<SocketAddr>) -> DnsServerConfig {
        DnsServerConfig {
            bind_addrs: vec!["127.0.0.1:5353".parse().unwrap()],
            upstream_addrs,
            upstream_timeout: Duration::from_secs(1),
        }
    }

    fn query_packet(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
        encode_response(message).unwrap()
    }
}
