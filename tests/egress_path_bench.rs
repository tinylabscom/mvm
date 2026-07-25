//! Optional local benchmark for the two user-space egress shapes.
//!
//! This is intentionally opt-in because it opens local listeners and takes
//! wall-clock measurements. It compares a direct kernel UDP/TCP socket path
//! (the transport shape used by TAP/NAT) with the extra SOCKS5 framing and
//! relay hop used by the NIC-less vsock path. It does not claim to measure a
//! particular hypervisor or host VPN.
//!
//! ```text
//! MVM_EGRESS_BENCH=1 MVM_EGRESS_BENCH_RUNS=1000 \
//!   cargo test --test egress_path_bench -- --nocapture
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use mvm_core::socks5_udp::{Address, Datagram};

const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RUNS: usize = 250;
const DEFAULT_PAYLOAD_BYTES: usize = 1024;

#[test]
fn compare_direct_and_socks5_egress_paths() {
    if std::env::var("MVM_EGRESS_BENCH").as_deref() != Ok("1") {
        eprintln!("[egress_path_bench] skipped; set MVM_EGRESS_BENCH=1 to run");
        return;
    }

    let runs = env_usize("MVM_EGRESS_BENCH_RUNS", DEFAULT_RUNS);
    let payload_bytes = env_usize("MVM_EGRESS_BENCH_PAYLOAD_BYTES", DEFAULT_PAYLOAD_BYTES);
    assert!(runs > 0, "MVM_EGRESS_BENCH_RUNS must be positive");
    assert!(
        payload_bytes > 0,
        "MVM_EGRESS_BENCH_PAYLOAD_BYTES must be positive"
    );
    let payload = vec![0x5a; payload_bytes];

    let udp = benchmark_udp(runs, &payload);
    let tcp = benchmark_tcp(runs, &payload);
    print_summary("udp-direct-kernel", &udp.direct, payload_bytes);
    print_summary("udp-socks5-framed", &udp.socks5, payload_bytes);
    print_summary("tcp-direct-kernel", &tcp.direct, payload_bytes);
    print_summary("tcp-socks5-relayed", &tcp.socks5, payload_bytes);
}

#[derive(Debug)]
struct PathSamples {
    direct: Vec<Duration>,
    socks5: Vec<Duration>,
}

fn benchmark_udp(runs: usize, payload: &[u8]) -> PathSamples {
    let echo = UdpSocket::bind("127.0.0.1:0").expect("bind UDP echo");
    echo.set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("set UDP echo timeout");
    let echo_addr = echo.local_addr().expect("read UDP echo address");
    let payload_len = payload.len();
    let echo_thread = thread::spawn(move || {
        let mut buf = vec![0u8; payload_len.max(65_535)];
        for _ in 0..runs.saturating_mul(2) {
            let (len, peer) = echo.recv_from(&mut buf).expect("receive UDP echo packet");
            echo.send_to(&buf[..len], peer)
                .expect("send UDP echo packet");
        }
    });

    let direct_socket = UdpSocket::bind("127.0.0.1:0").expect("bind direct UDP client");
    direct_socket
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("set direct UDP timeout");
    let mut direct = Vec::with_capacity(runs);
    let mut buf = vec![0u8; 65_535];
    for _ in 0..runs {
        let started = Instant::now();
        direct_socket
            .send_to(payload, echo_addr)
            .expect("send direct UDP payload");
        let (len, _) = direct_socket
            .recv_from(&mut buf)
            .expect("receive direct UDP payload");
        assert_eq!(&buf[..len], payload);
        direct.push(started.elapsed());
    }

    let relay = UdpSocket::bind("127.0.0.1:0").expect("bind SOCKS5 UDP relay");
    relay
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("set SOCKS5 UDP relay timeout");
    let relay_addr = relay.local_addr().expect("read SOCKS5 UDP relay address");
    let relay_payload = payload.to_vec();
    let relay_thread = thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        for _ in 0..runs {
            let (len, peer) = relay
                .recv_from(&mut buf)
                .expect("receive SOCKS5 UDP packet");
            let request = Datagram::decode(&buf[..len]).expect("decode SOCKS5 UDP packet");
            assert_eq!(request.payload, relay_payload);
            relay
                .send_to(&request.payload, echo_addr)
                .expect("send relayed UDP payload");
            let (response_len, source) = relay.recv_from(&mut buf).expect("receive relayed UDP");
            assert_eq!(source, echo_addr);
            let response = Datagram {
                address: Address::Ip(echo_addr.ip()),
                port: echo_addr.port(),
                payload: buf[..response_len].to_vec(),
            };
            let encoded = response.encode().expect("encode SOCKS5 UDP response");
            relay
                .send_to(&encoded, peer)
                .expect("send SOCKS5 UDP response");
        }
    });

    let socks_socket = UdpSocket::bind("127.0.0.1:0").expect("bind SOCKS5 UDP client");
    socks_socket
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("set SOCKS5 UDP client timeout");
    let mut socks5 = Vec::with_capacity(runs);
    for _ in 0..runs {
        let started = Instant::now();
        let request = Datagram {
            address: Address::Ip(echo_addr.ip()),
            port: echo_addr.port(),
            payload: payload.to_vec(),
        };
        let encoded = request.encode().expect("encode SOCKS5 UDP request");
        socks_socket
            .send_to(&encoded, relay_addr)
            .expect("send SOCKS5 UDP request");
        let (len, _) = socks_socket
            .recv_from(&mut buf)
            .expect("receive SOCKS5 UDP response");
        let response = Datagram::decode(&buf[..len]).expect("decode SOCKS5 UDP response");
        assert_eq!(response.payload, payload);
        socks5.push(started.elapsed());
    }

    relay_thread.join().expect("join SOCKS5 UDP relay");
    echo_thread.join().expect("join UDP echo");
    PathSamples { direct, socks5 }
}

fn benchmark_tcp(runs: usize, payload: &[u8]) -> PathSamples {
    let echo = TcpListener::bind("127.0.0.1:0").expect("bind TCP echo");
    let echo_addr = echo.local_addr().expect("read TCP echo address");
    let payload_len = payload.len();
    let echo_thread = thread::spawn(move || {
        for _ in 0..runs.saturating_mul(2) {
            let (mut stream, _) = echo.accept().expect("accept TCP echo connection");
            stream
                .set_read_timeout(Some(SOCKET_TIMEOUT))
                .expect("set TCP echo timeout");
            let mut buf = vec![0u8; payload_len];
            stream.read_exact(&mut buf).expect("read TCP echo payload");
            stream.write_all(&buf).expect("write TCP echo payload");
        }
    });

    let mut direct = Vec::with_capacity(runs);
    for _ in 0..runs {
        let started = Instant::now();
        let mut stream = TcpStream::connect(echo_addr).expect("connect direct TCP");
        stream
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .expect("set direct TCP timeout");
        stream.write_all(payload).expect("write direct TCP payload");
        let mut response = vec![0u8; payload.len()];
        stream
            .read_exact(&mut response)
            .expect("read direct TCP payload");
        assert_eq!(response, payload);
        direct.push(started.elapsed());
    }

    let relay = TcpListener::bind("127.0.0.1:0").expect("bind SOCKS5 TCP relay");
    let relay_addr = relay.local_addr().expect("read SOCKS5 TCP relay address");
    let relay_payload_len = payload.len();
    let relay_thread = thread::spawn(move || {
        for _ in 0..runs {
            let (mut client, _) = relay.accept().expect("accept SOCKS5 TCP client");
            client
                .set_read_timeout(Some(SOCKET_TIMEOUT))
                .expect("set SOCKS5 TCP timeout");
            let mut greeting = [0u8; 3];
            client
                .read_exact(&mut greeting)
                .expect("read SOCKS5 greeting");
            assert_eq!(greeting, [5, 1, 0]);
            client
                .write_all(&[5, 0])
                .expect("write SOCKS5 method response");
            let mut request = [0u8; 10];
            client
                .read_exact(&mut request)
                .expect("read SOCKS5 request");
            assert_eq!(request[0..4], [5, 1, 0, 1]);
            client
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("write SOCKS5 connect response");
            let mut upstream = TcpStream::connect(echo_addr).expect("connect relayed TCP");
            upstream
                .set_read_timeout(Some(SOCKET_TIMEOUT))
                .expect("set relayed TCP timeout");
            let mut body = vec![0u8; relay_payload_len];
            client
                .read_exact(&mut body)
                .expect("read relayed TCP payload");
            upstream
                .write_all(&body)
                .expect("write relayed TCP payload");
            upstream
                .read_exact(&mut body)
                .expect("read upstream TCP payload");
            client.write_all(&body).expect("write relayed TCP response");
        }
    });

    let mut socks5 = Vec::with_capacity(runs);
    for _ in 0..runs {
        let started = Instant::now();
        let mut stream = TcpStream::connect(relay_addr).expect("connect SOCKS5 TCP relay");
        stream
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .expect("set SOCKS5 TCP client timeout");
        stream.write_all(&[5, 1, 0]).expect("write SOCKS5 greeting");
        let mut method = [0u8; 2];
        stream
            .read_exact(&mut method)
            .expect("read SOCKS5 method response");
        assert_eq!(method, [5, 0]);
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => unreachable!("benchmark uses IPv4 loopback"),
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&ip);
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        stream.write_all(&request).expect("write SOCKS5 request");
        let mut response = [0u8; 10];
        stream
            .read_exact(&mut response)
            .expect("read SOCKS5 connect response");
        assert_eq!(response[0..2], [5, 0]);
        stream.write_all(payload).expect("write SOCKS5 TCP payload");
        let mut body = vec![0u8; payload.len()];
        stream
            .read_exact(&mut body)
            .expect("read SOCKS5 TCP response");
        assert_eq!(body, payload);
        socks5.push(started.elapsed());
    }

    relay_thread.join().expect("join SOCKS5 TCP relay");
    echo_thread.join().expect("join TCP echo");
    PathSamples { direct, socks5 }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn print_summary(name: &str, samples: &[Duration], payload_bytes: usize) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[(sorted.len() * 95 / 100).min(sorted.len() - 1)];
    let total = samples.iter().copied().sum::<Duration>();
    let throughput = payload_bytes as f64 * samples.len() as f64 / total.as_secs_f64();
    eprintln!(
        "[egress_path_bench] {name} runs={} p50_us={} p95_us={} throughput_mib_s={:.2}",
        samples.len(),
        p50.as_micros(),
        p95.as_micros(),
        throughput / (1024.0 * 1024.0),
    );
}
