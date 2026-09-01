//! In-guest loopback proxy → FlowMux egress bridge.
//!
//! `mvm-egress-client` owns exactly one authenticated, reconnecting FlowMux
//! session and multiplexes SOCKS5 CONNECT, HTTP CONNECT, absolute-form HTTP
//! forwarding, and SOCKS5 UDP ASSOCIATE over it. A loopback DNS stub also
//! rides the same session's `Resolve` frames.
//!
//! This replaces the legacy raw-egress line-prelude protocol
//! (`"host:port\n"`, `"MVM_HTTP_FORWARD/1\n"`, `"MVM_DNS/1\n"`,
//! `"MVM_SOCKS5_UDP/1\n"`) with typed FlowMux frames.

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::egress_client::{
    ProxyReplyStyle, ProxyRoute, http_forward_target, read_route, reply_http_bad_request,
    write_connect_reply, write_http_response,
};
use crate::flowmux::{FlowMuxError, FlowMuxReconnectClient};
use crate::guest_vsock_session::splice_streams;
use mvm_core::guest_netd::ConnectAck;
use mvm_core::socks5_udp::{self, Address, Datagram};

/// Default loopback address for the in-guest DNS stub.
pub(crate) const DEFAULT_DNS_STUB_LISTEN: &str = mvm_core::guest_netd::DEFAULT_DNS_STUB_LISTEN;

/// Convert a FlowMux error into an `io::Error` for the proxy layer.
fn flowmux_to_io(error: FlowMuxError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
}

fn http_failure_status(error: &FlowMuxError) -> &'static str {
    match error {
        FlowMuxError::Refused(_) => "403 Forbidden",
        FlowMuxError::Handshake(_)
        | FlowMuxError::Frame(_)
        | FlowMuxError::SessionClosed(_)
        | FlowMuxError::Transport(_)
        | FlowMuxError::UpstreamConnect(_)
        | FlowMuxError::ChannelClosed => "502 Bad Gateway",
    }
}

/// Bind the loopback proxy at `listen` and serve egress over one FlowMux
/// session indefinitely.
pub async fn run(listen: SocketAddr, flowmux: FlowMuxReconnectClient) -> io::Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_until_shutdown(listen, flowmux, shutdown_rx).await
}

/// Bind the loopback proxy at `listen` and serve until `shutdown` flips to
/// `true`.
pub async fn run_until_shutdown(
    listen: SocketAddr,
    flowmux: FlowMuxReconnectClient,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let dns_task = spawn_default_dns_stub(flowmux.clone());
    info!(%listen, "FlowMux egress proxy started");
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => break,
                    Ok(()) => continue,
                    Err(_) => break,
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((client, peer)) => {
                        debug!(%peer, "accepted egress client connection");
                        let flowmux = flowmux.clone();
                        tokio::spawn(async move {
                            if let Err(error) = serve(client, flowmux).await {
                                log_serve_failure(&error);
                            }
                        });
                    }
                    Err(error) => warn!(%error, "egress client accept failed"),
                }
            }
        }
    }
    if let Some(task) = dns_task {
        task.abort();
    }
    Ok(())
}

async fn serve(mut client: TcpStream, flowmux: FlowMuxReconnectClient) -> io::Result<()> {
    let route = match read_route(&mut client).await {
        Ok(route) => route,
        Err(error) => {
            let _ = reply_http_bad_request(&mut client).await;
            return Err(error);
        }
    };
    match route {
        ProxyRoute::Socks { target } => serve_socks(client, &target, flowmux).await,
        ProxyRoute::SocksUdpAssociate => serve_socks_udp(client, flowmux).await,
        ProxyRoute::HttpConnect { target } => serve_http_connect(client, &target, flowmux).await,
        ProxyRoute::HttpForward { head } => serve_http_forward(client, &head, flowmux).await,
    }
}

async fn serve_socks(
    client: TcpStream,
    target: &str,
    flowmux: FlowMuxReconnectClient,
) -> io::Result<()> {
    match flowmux.open_tcp(target).await {
        Ok(upstream) => {
            let mut client = client;
            write_connect_reply(&mut client, ProxyReplyStyle::Socks, ConnectAck::Ok).await?;
            splice_streams(client, upstream).await
        }
        Err(error) => {
            let mut client = client;
            write_connect_reply(&mut client, ProxyReplyStyle::Socks, ConnectAck::Fail)
                .await
                .ok();
            Err(flowmux_to_io(error))
        }
    }
}

async fn serve_http_connect(
    client: TcpStream,
    target: &str,
    flowmux: FlowMuxReconnectClient,
) -> io::Result<()> {
    match flowmux.open_tcp(target).await {
        Ok(upstream) => {
            let mut client = client;
            write_connect_reply(&mut client, ProxyReplyStyle::HttpConnect, ConnectAck::Ok).await?;
            splice_streams(client, upstream).await
        }
        Err(error) => {
            let mut client = client;
            write_http_response(&mut client, http_failure_status(&error))
                .await
                .ok();
            Err(flowmux_to_io(error))
        }
    }
}

/// What a client asking this proxy to fetch an `https://` URL is told.
///
/// The reason travels in the status line because that is the only part of the
/// refusal most clients surface: BusyBox `wget` prints the whole line, so an
/// operator sees what to do instead of a bare code.
const TLS_ABSOLUTE_URI_STATUS: &str =
    "501 Not Implemented (https absolute-URI needs CONNECT or SOCKS)";

/// Refuse an absolute-form `https://` request rather than forwarding it.
///
/// A forward proxy asked for `GET https://host/…` is being asked to speak TLS
/// on the client's behalf. This proxy never originates TLS — it relays bytes
/// so the host can authorize and log every connection — so forwarding the head
/// would write a cleartext request to a port that expects TLS: the origin
/// answers with an error or hangs up, and the request line, `Host` and every
/// header have already crossed the network in the clear. Refusing keeps that
/// from happening and names the two transports that do work.
async fn refuse_tls_absolute_uri(mut client: TcpStream, target: &str) -> io::Result<()> {
    warn!(
        %target,
        "refusing an https absolute-URI proxy request: this proxy tunnels TLS \
         (CONNECT or SOCKS5) and never originates it, so forwarding the head \
         would send it in cleartext"
    );
    write_http_response(&mut client, TLS_ABSOLUTE_URI_STATUS)
        .await
        .ok();
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "https absolute-URI proxy request",
    ))
}

async fn serve_http_forward(
    client: TcpStream,
    head: &[u8],
    flowmux: FlowMuxReconnectClient,
) -> io::Result<()> {
    let forward = http_forward_target(head)?;
    if forward.tls {
        return refuse_tls_absolute_uri(client, &forward.target).await;
    }
    let target = forward.target;
    match flowmux.open_tcp(&target).await {
        Ok(mut upstream) => {
            upstream.write_all(head).await?;
            upstream.flush().await?;
            splice_streams(client, upstream).await
        }
        Err(error) => {
            let mut client = client;
            write_http_response(&mut client, http_failure_status(&error))
                .await
                .ok();
            Err(flowmux_to_io(error))
        }
    }
}

const SOCKS5: u8 = 0x05;
const ATYP_IPV4: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;

async fn serve_socks_udp(
    mut control: TcpStream,
    flowmux: FlowMuxReconnectClient,
) -> io::Result<()> {
    let mut upstream = match flowmux.open_udp().await {
        Ok(upstream) => upstream,
        Err(error) => {
            reply_udp_failure(&mut control).await.ok();
            return Err(flowmux_to_io(error));
        }
    };

    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let port = udp.local_addr()?.port();
    control
        .write_all(&[SOCKS5, REP_SUCCESS, 0, ATYP_IPV4, 127, 0, 0, 1])
        .await?;
    control.write_all(&port.to_be_bytes()).await?;
    control.flush().await?;

    let udp = Arc::new(udp);
    let mut last_peer = None;
    let mut control_buf = [0u8; 1];

    loop {
        let mut udp_buf = vec![0u8; socks5_udp::MAX_DATAGRAM_BYTES];
        tokio::select! {
            result = udp.recv_from(&mut udp_buf) => {
                let (length, peer) = result?;
                last_peer = Some(peer);
                let packet = match Datagram::decode(&udp_buf[..length]) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                };
                let destination = match packet.address {
                    Address::Ip(ip) => SocketAddr::new(ip, packet.port),
                    Address::Domain(_) => continue,
                };
                if let Err(error) = upstream.send_to(destination, &packet.payload).await {
                    warn!(%error, "FlowMux UDP send failed");
                    return Err(flowmux_to_io(error));
                }
            }
            result = upstream.recv_from() => {
                let (source, payload) = match result {
                    Ok(pair) => pair,
                    Err(error) => return Err(flowmux_to_io(error)),
                };
                let packet = Datagram {
                    address: Address::Ip(source.ip()),
                    port: source.port(),
                    payload,
                };
                let frame = match packet.encode() {
                    Ok(frame) => frame,
                    Err(_) => continue,
                };
                if let Some(peer) = last_peer
                    && let Err(error) = udp.send_to(&frame, peer).await
                {
                    warn!(%error, %peer, "UDP relay send failed");
                }
            }
            result = control.read(&mut control_buf) => {
                if result? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

async fn reply_udp_failure(control: &mut TcpStream) -> io::Result<()> {
    // VER, REP, RSV, ATYP=ipv4, BND.ADDR=0.0.0.0, BND.PORT=0.
    control
        .write_all(&[SOCKS5, REP_GENERAL_FAILURE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    control.flush().await
}

fn spawn_default_dns_stub(flowmux: FlowMuxReconnectClient) -> Option<tokio::task::JoinHandle<()>> {
    let listen = match DEFAULT_DNS_STUB_LISTEN.parse() {
        Ok(listen) => listen,
        Err(error) => {
            warn!(%error, "default DNS stub address is invalid");
            return None;
        }
    };
    Some(tokio::spawn(async move {
        if let Err(error) = dns_stub::run_dns_stub(listen, flowmux).await {
            warn!(%error, %listen, "guest DNS stub unavailable; proxy remains active");
        }
    }))
}

fn log_serve_failure(error: &io::Error) {
    use crate::guest_vsock_session::{ProxyEnd, is_peer_hangup, proxy_end_of};

    match proxy_end_of(error) {
        Some(ProxyEnd::Client) if is_peer_hangup(error) => {
            debug!(error = %error, "egress client disconnected");
        }
        _ => warn!(error = %error, "egress client connection failed"),
    }
}

/// Loopback DNS stub forwarding queries over the shared FlowMux session.
pub mod dns_stub {
    use super::*;
    use mvm_contract::protocol::dns::{DnsQuestion, DnsRecordType, decode_query};

    /// Bind UDP and TCP DNS listeners and forward each query through FlowMux.
    pub async fn run_dns_stub(
        listen: SocketAddr,
        flowmux: FlowMuxReconnectClient,
    ) -> io::Result<()> {
        if !listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS stub listen address must be loopback",
            ));
        }
        let udp = UdpSocket::bind(listen).await?;
        let tcp = TcpListener::bind(listen).await?;
        info!(%listen, "guest DNS stub started");
        tokio::try_join!(serve_udp(udp, flowmux.clone()), serve_tcp(tcp, flowmux)).map(|_| ())
    }

    async fn serve_udp(socket: UdpSocket, flowmux: FlowMuxReconnectClient) -> io::Result<()> {
        let socket = Arc::new(socket);
        let mut buffer = vec![0u8; mvm_core::protocol::dns::MAX_DNS_MESSAGE + 1];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await?;
            if length > mvm_core::protocol::dns::MAX_DNS_MESSAGE {
                warn!(%peer, length, "dropping oversized UDP DNS query");
                continue;
            }
            let query = buffer[..length].to_vec();
            let original_id = u16::from_be_bytes([query[0], query[1]]);
            let socket = Arc::clone(&socket);
            let flowmux = flowmux.clone();
            tokio::spawn(async move {
                match forward_query_over_flowmux(&query, flowmux).await {
                    Ok(mut response) => {
                        rewrite_dns_response_id(&mut response, original_id);
                        if let Err(error) = socket.send_to(&response, peer).await {
                            warn!(%error, %peer, "sending UDP DNS response failed");
                        }
                    }
                    Err(error) => {
                        warn!(%error, %peer, "forwarding UDP DNS query failed");
                    }
                }
            });
        }
    }

    async fn serve_tcp(listener: TcpListener, flowmux: FlowMuxReconnectClient) -> io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let flowmux = flowmux.clone();
            tokio::spawn(async move {
                if let Err(error) = serve_tcp_connection(stream, flowmux).await {
                    warn!(%error, %peer, "serving TCP DNS connection failed");
                }
            });
        }
    }

    async fn serve_tcp_connection(
        mut stream: TcpStream,
        flowmux: FlowMuxReconnectClient,
    ) -> io::Result<()> {
        loop {
            let mut length = [0u8; 2];
            if stream.read(&mut length[..1]).await? == 0 {
                return Ok(());
            }
            stream.read_exact(&mut length[1..]).await?;
            let length = usize::from(u16::from_be_bytes(length));
            validate_dns_length(length)?;
            let mut query = vec![0u8; length];
            stream.read_exact(&mut query).await?;
            let original_id = u16::from_be_bytes([query[0], query[1]]);
            let mut response = forward_query_over_flowmux(&query, flowmux.clone())
                .await
                .map_err(flowmux_to_io)?;
            rewrite_dns_response_id(&mut response, original_id);
            let response_length =
                u16::try_from(response.len()).map_err(|_| invalid_dns_length())?;
            stream.write_all(&response_length.to_be_bytes()).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
        }
    }

    async fn forward_query_over_flowmux(
        query: &[u8],
        flowmux: FlowMuxReconnectClient,
    ) -> Result<Vec<u8>, FlowMuxError> {
        let DnsQuestion { name, qtype, id: _ } = decode_query(query)
            .map_err(|error| FlowMuxError::Refused(format!("invalid DNS query: {error:?}")))?;
        let qtype = match qtype {
            DnsRecordType::A => 1,
            DnsRecordType::Aaaa => 28,
        };
        flowmux.resolve(&name, qtype).await
    }

    fn rewrite_dns_response_id(response: &mut [u8], id: u16) {
        if response.len() >= 2 {
            response[..2].copy_from_slice(&id.to_be_bytes());
        }
    }

    fn validate_dns_length(length: usize) -> io::Result<()> {
        if length > mvm_core::protocol::dns::MAX_DNS_MESSAGE {
            Err(invalid_dns_length())
        } else {
            Ok(())
        }
    }

    fn invalid_dns_length() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS frame exceeds the configured message limit",
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use mvm_contract::protocol::network_flow::hello::Handshake;
        use mvm_contract::protocol::network_flow::{Opcode, encode_into};
        use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

        fn generate_keypair() -> (SigningKey, VerifyingKey) {
            let bytes: [u8; 32] = rand::random();
            let signing = SigningKey::from_bytes(&bytes);
            let verifying = signing.verifying_key();
            (signing, verifying)
        }

        async fn send_frame<S>(
            stream: &mut S,
            session: &mut mvm_core::net::session::Session,
            opcode: Opcode,
            stream_id: u32,
            payload: &[u8],
        ) where
            S: AsyncWrite + Unpin,
        {
            let mut wire = Vec::new();
            encode_into(&mut wire, opcode, stream_id, payload).unwrap();
            let sealed = session.seal(&wire).unwrap();
            let mut sealed_bytes = Vec::new();
            sealed.encode(&mut sealed_bytes).unwrap();
            let len = u32::try_from(sealed_bytes.len()).unwrap();
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(&sealed_bytes).await.unwrap();
            stream.flush().await.unwrap();
        }

        async fn read_frame<S>(
            stream: &mut S,
            session: &mut mvm_core::net::session::Session,
        ) -> Option<(Opcode, u32, u32, Vec<u8>)>
        where
            S: AsyncRead + Unpin,
        {
            crate::flowmux::read_sealed_frame_from(stream, session)
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn dns_stub_forwards_udp_query_and_rewrites_id() {
            let (guest_stream, host_stream) = tokio::io::duplex(4096);
            let (guest_key, _guest_anchor) = generate_keypair();
            let (host_key, host_anchor) = generate_keypair();

            let host = tokio::spawn(async move {
                let handle = tokio::runtime::Handle::try_current().unwrap();
                let (mut host_stream, mut host_session) = tokio::task::spawn_blocking(move || {
                    let mut adapter =
                        crate::flowmux::AsyncStreamSyncAdapter::new(host_stream, handle);
                    let result = mvm_core::net::session::Session::host(
                        &mut adapter,
                        "test-session",
                        host_key,
                    );
                    let stream = adapter.into_inner();
                    result.map(|(session, _peer)| (stream, session))
                })
                .await
                .unwrap()
                .unwrap();

                let (_opcode, _sid, _payload_len, _payload) =
                    read_frame(&mut host_stream, &mut host_session)
                        .await
                        .unwrap();
                send_frame(
                    &mut host_stream,
                    &mut host_session,
                    Opcode::HelloAck,
                    0,
                    &Handshake::local("test-host").encode(),
                )
                .await;

                let (opcode, sid, _payload_len, payload) =
                    read_frame(&mut host_stream, &mut host_session)
                        .await
                        .unwrap();
                assert_eq!(opcode, Opcode::Resolve);
                let question = decode_query(&payload).unwrap();
                assert_eq!(question.name, "example.com");

                // Build a minimal positive response; the stub will rewrite the ID.
                let mut response = vec![0u8; 12];
                response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                response[4..6].copy_from_slice(&0_u16.to_be_bytes());
                response[6..12].copy_from_slice(&[0; 6]);
                send_frame(
                    &mut host_stream,
                    &mut host_session,
                    Opcode::Resolved,
                    sid,
                    &response,
                )
                .await;
            });

            let client =
                crate::flowmux::FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
                    .await
                    .unwrap();
            let (tx, rx) = watch::channel(Some(Arc::new(client)));
            // Keep the sender alive for the duration of the test.
            let _tx = tx;
            let resolver = crate::flowmux::FlowMuxReconnectClient::from_receiver(rx);

            // Bind the DNS stub on an ephemeral loopback port.
            let stub = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let stub_addr = stub.local_addr().unwrap();
            let task = tokio::spawn(serve_udp(stub, resolver));

            // Build a query for example.com A.
            let mut query = vec![0u8; 12];
            query[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
            query[2..4].copy_from_slice(&0x0100_u16.to_be_bytes());
            query[4..6].copy_from_slice(&1_u16.to_be_bytes());
            query.extend_from_slice(&[
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ]);
            query.extend_from_slice(&1_u16.to_be_bytes());
            query.extend_from_slice(&1_u16.to_be_bytes());

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client_socket.send_to(&query, stub_addr).await.unwrap();

            let mut buf = vec![0u8; 512];
            let (_len, _) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                client_socket.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&buf[..2], &0x1234_u16.to_be_bytes());

            task.abort();
            host.await.unwrap();
        }
    }
}

#[cfg(test)]
mod http_forward_tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_contract::protocol::network_flow::hello::Handshake;
    use mvm_contract::protocol::network_flow::{Opcode, encode_into};
    use tokio::io::{AsyncRead, AsyncWrite};

    fn keypair() -> (SigningKey, VerifyingKey) {
        let bytes: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[test]
    fn policy_refusal_and_upstream_failure_have_distinct_http_statuses() {
        assert_eq!(
            http_failure_status(&FlowMuxError::Refused("not admitted".into())),
            "403 Forbidden"
        );
        assert_eq!(
            http_failure_status(&FlowMuxError::UpstreamConnect("connection failed".into())),
            "502 Bad Gateway"
        );
    }

    async fn send_frame<S>(
        stream: &mut S,
        session: &mut mvm_core::net::session::Session,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) where
        S: AsyncWrite + Unpin,
    {
        let mut wire = Vec::new();
        encode_into(&mut wire, opcode, stream_id, payload).unwrap();
        let sealed = session.seal(&wire).unwrap();
        let mut sealed_bytes = Vec::new();
        sealed.encode(&mut sealed_bytes).unwrap();
        let len = u32::try_from(sealed_bytes.len()).unwrap();
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        stream.write_all(&sealed_bytes).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_frame<S>(
        stream: &mut S,
        session: &mut mvm_core::net::session::Session,
    ) -> Option<(Opcode, u32, u32, Vec<u8>)>
    where
        S: AsyncRead + Unpin,
    {
        crate::flowmux::read_sealed_frame_from(stream, session)
            .await
            .unwrap()
    }

    /// The regression this exists for: BusyBox `wget` asks a plain HTTP proxy
    /// for `GET https://host/ HTTP/1.1`. The proxy used to resolve that to
    /// `host:443`, open a TCP flow and write the head — a cleartext request to
    /// a port that expects TLS. The origin answered with an error or hung up,
    /// which read as "mvm egress is broken", and the request line and every
    /// header had already crossed the network in the clear.
    ///
    /// Nothing may reach the host, and the client must be told which
    /// transports do work.
    #[tokio::test]
    async fn an_https_absolute_uri_is_refused_without_opening_a_flow() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = keypair();
        let (host_key, host_anchor) = keypair();

        let host = tokio::spawn(async move {
            let handle = tokio::runtime::Handle::try_current().unwrap();
            let (mut host_stream, mut host_session) = tokio::task::spawn_blocking(move || {
                let mut adapter = crate::flowmux::AsyncStreamSyncAdapter::new(host_stream, handle);
                let result =
                    mvm_core::net::session::Session::host(&mut adapter, "test-session", host_key);
                let stream = adapter.into_inner();
                result.map(|(session, _peer)| (stream, session))
            })
            .await
            .unwrap()
            .unwrap();

            let _hello = read_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            // Whatever the proxy decides, it decides without us: anything that
            // arrives after the handshake is a flow it should never have opened.
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                read_frame(&mut host_stream, &mut host_session),
            )
            .await
            .ok()
            .flatten()
            .map(|(opcode, _, _, _)| opcode)
        });

        let client = crate::flowmux::FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .unwrap();
        let (tx, rx) = watch::channel(Some(Arc::new(client)));
        let _tx = tx;
        let flowmux = crate::flowmux::FlowMuxReconnectClient::from_receiver(rx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut caller = TcpStream::connect(addr).await.unwrap();
        let (served, _) = listener.accept().await.unwrap();

        let head = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let err = serve_http_forward(served, head, flowmux)
            .await
            .expect_err("an https absolute-URI must be refused");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let mut reply = String::new();
        caller.read_to_string(&mut reply).await.unwrap();
        assert!(
            reply.starts_with("HTTP/1.1 501 Not Implemented"),
            "unexpected reply: {reply}"
        );
        assert!(
            reply.contains("CONNECT"),
            "the refusal must name the way through: {reply}"
        );

        assert_eq!(
            host.await.unwrap(),
            None,
            "no frame may reach the host for a request that is never forwarded"
        );
    }

    /// The path that still works, and must keep working: a `http://` absolute
    /// URI is forwarded, so the guest opens a flow for it.
    #[tokio::test]
    async fn a_plain_http_absolute_uri_still_opens_a_flow() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = keypair();
        let (host_key, host_anchor) = keypair();

        let host = tokio::spawn(async move {
            let handle = tokio::runtime::Handle::try_current().unwrap();
            let (mut host_stream, mut host_session) = tokio::task::spawn_blocking(move || {
                let mut adapter = crate::flowmux::AsyncStreamSyncAdapter::new(host_stream, handle);
                let result =
                    mvm_core::net::session::Session::host(&mut adapter, "test-session", host_key);
                let stream = adapter.into_inner();
                result.map(|(session, _peer)| (stream, session))
            })
            .await
            .unwrap()
            .unwrap();

            let _hello = read_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            let (opcode, _sid, _len, payload) = read_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            (opcode, String::from_utf8_lossy(&payload).to_string())
        });

        let client = crate::flowmux::FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .unwrap();
        let (tx, rx) = watch::channel(Some(Arc::new(client)));
        let _tx = tx;
        let flowmux = crate::flowmux::FlowMuxReconnectClient::from_receiver(rx);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _caller = TcpStream::connect(addr).await.unwrap();
        let (served, _) = listener.accept().await.unwrap();

        let head = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let forward = tokio::spawn(async move {
            let _ = serve_http_forward(served, head, flowmux).await;
        });

        let (opcode, target) = host.await.unwrap();
        assert_eq!(opcode, Opcode::OpenTcp);
        assert!(
            target.contains("example.com:80"),
            "unexpected open target: {target}"
        );
        forward.abort();
    }
}
