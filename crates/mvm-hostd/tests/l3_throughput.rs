//! Measured overhead of the L3 tunnel's per-packet path.
//!
//! No new benchmarking dependency: the workspace has none, and one crate's
//! throughput numbers do not justify adding one. These are ordinary tests
//! that time a bounded loop and print the result, so `cargo test -- --nocapture`
//! reports real figures on whatever host runs them.
//!
//! They assert only generous ceilings — enough to catch a change that makes
//! the hot path an order of magnitude worse, never tight enough to flake on
//! a loaded CI box. The numbers themselves are the point; the assertions
//! just stop the measurement from silently becoming meaningless.
//!
//! **The ceilings apply only to release builds.** A timing figure from an
//! unoptimized build measures the optimizer's absence, not the code, and
//! asserting on one would either fail constantly or have to be so loose it
//! caught nothing. The default `cargo nextest run` is a debug build, so
//! there the numbers are printed and the assertions skipped; run
//! `cargo test --release -p mvm-hostd --test l3_throughput -- --nocapture`
//! for the gated figures.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_hostd::netd::{LoopbackDatapath, packet::build_udp_v4};
use mvm_net::l3::{
    AddressAllocator, DnsBindingStore, FlowTable, IngressTable, L3Admitter, L3PolicyConfig,
    OutboundVerdict,
};
use mvm_protocol::l3::{MessageType, frame, ip, limits, proto};

const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
/// Enough iterations to swamp timer granularity, small enough that the
/// suite stays fast.
const ITERATIONS: usize = 200_000;

fn mtu_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    // A full-MTU TCP segment: the worst case for the copy path.
    let payload_len = limits::MTU_V1 as usize - 20 - 20;
    let mut tcp = vec![0u8; 20 + payload_len];
    tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = ip::TCP_ACK;
    let total = 20 + tcp.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto::TCP;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(&tcp);
    p
}

/// Assert a per-operation ceiling, but only where the number means
/// something. In a debug build the measurement is dominated by the missing
/// optimizer, so it is reported and not judged.
fn assert_ceiling(label: &str, per_op_ns: f64, ceiling_ns: f64) {
    if cfg!(debug_assertions) {
        println!("  (debug build: {label} ceiling of {ceiling_ns:.0} ns not asserted)");
        return;
    }
    assert!(
        per_op_ns < ceiling_ns,
        "{label} regressed: {per_op_ns:.0} ns/op exceeds the {ceiling_ns:.0} ns ceiling"
    );
}

/// Report one measurement in the shape a reader can compare across hosts.
fn report(label: &str, iterations: usize, elapsed: std::time::Duration, bytes_each: usize) {
    let per_op_ns = elapsed.as_nanos() as f64 / iterations as f64;
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    let gbps = (ops_per_sec * bytes_each as f64 * 8.0) / 1e9;
    println!(
        "{label}: {per_op_ns:.0} ns/packet, {:.2} M packets/s, {gbps:.2} Gb/s at {bytes_each} B",
        ops_per_sec / 1e6
    );
}

fn admitter() -> L3Admitter {
    let lease = AddressAllocator::with_defaults().allocate().unwrap();
    let mut a = L3Admitter::new(
        lease,
        L3PolicyConfig {
            egress: CanonicalEgress::Rules(vec![CanonicalRule {
                proto: Proto::Tcp,
                net: "93.184.216.34/32".parse().unwrap(),
                port_lo: 443,
                port_hi: 443,
            }]),
            ..L3PolicyConfig::default()
        },
        FlowTable::with_defaults(),
        DnsBindingStore::with_defaults(),
        IngressTable::with_defaults(),
    );
    a.set_ready(true);
    a
}

#[test]
fn measure_frame_encode_decode() {
    let payload = vec![0xABu8; limits::MTU_V1 as usize];
    let mut buf = Vec::with_capacity(limits::MAX_WIRE_LEN);

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        buf.clear();
        frame::encode_into(&mut buf, MessageType::Packet, 42, 0, &payload).unwrap();
        std::hint::black_box(&buf);
    }
    let encode = start.elapsed();
    report("frame encode", ITERATIONS, encode, payload.len());

    let wire = frame::encode(MessageType::Packet, 42, 0, &payload).unwrap();
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let parsed = frame::decode(&wire).unwrap();
        std::hint::black_box(parsed.payload.len());
    }
    let decode = start.elapsed();
    report("frame decode", ITERATIONS, decode, payload.len());

    // Framing must stay a rounding error next to the copy it wraps. A
    // microsecond per packet would cap the tunnel at ~1 Mpps on framing
    // alone, which would mean something had gone badly wrong.
    let encode_ns = encode.as_nanos() as f64 / ITERATIONS as f64;
    let decode_ns = decode.as_nanos() as f64 / ITERATIONS as f64;
    assert_ceiling("frame encode", encode_ns, 1000.0);
    assert_ceiling("frame decode", decode_ns, 1000.0);
}

#[test]
fn measure_ip_validation() {
    let packet = mtu_packet(Ipv4Addr::new(10, 201, 0, 6), REMOTE);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let parsed = ip::parse(&packet).unwrap();
        std::hint::black_box(parsed.dst_port);
    }
    let elapsed = start.elapsed();
    report("ip validation", ITERATIONS, elapsed, packet.len());
    let per_op_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    assert_ceiling("ip validation", per_op_ns, 1000.0);
}

#[test]
fn measure_admission_decision() {
    let mut admitter = admitter();
    let guest = admitter.lease().guest;
    let packet = mtu_packet(guest, REMOTE);

    // Warm the flow so the steady-state path is what gets measured, not
    // first-packet insertion.
    assert!(matches!(
        admitter.admit_outbound(&packet, 0),
        OutboundVerdict::Forward(_)
    ));

    let start = Instant::now();
    for i in 0..ITERATIONS {
        let verdict = admitter.admit_outbound(&packet, i as u64);
        std::hint::black_box(matches!(verdict, OutboundVerdict::Forward(_)));
    }
    let elapsed = start.elapsed();
    report(
        "admission (established flow)",
        ITERATIONS,
        elapsed,
        packet.len(),
    );

    // One flow only: admission must not be leaking table entries.
    assert_eq!(
        admitter.flows().len(),
        1,
        "steady state must not grow the table"
    );

    let per_op_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    assert_ceiling("admission", per_op_ns, 5000.0);
}

#[test]
fn measure_admission_refusal() {
    // The refusal path matters as much as the accept path: a guest that
    // floods denied packets must not cost more per packet than one sending
    // admitted traffic, or the drop path becomes the attack.
    let mut admitter = admitter();
    let guest = admitter.lease().guest;
    let denied = mtu_packet(guest, Ipv4Addr::new(1, 2, 3, 4));

    let start = Instant::now();
    for i in 0..ITERATIONS {
        let verdict = admitter.admit_outbound(&denied, i as u64);
        std::hint::black_box(matches!(verdict, OutboundVerdict::Deny(_)));
    }
    let elapsed = start.elapsed();
    report("admission (refused)", ITERATIONS, elapsed, denied.len());

    assert!(
        admitter.flows().is_empty(),
        "a refused packet must create no flow state"
    );
    let per_op_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    assert_ceiling("the refusal path", per_op_ns, 5000.0);
}

#[test]
fn measure_end_to_end_host_side() {
    // Frame decode → admission → datapath handoff: everything the host
    // does per guest packet, minus the platform write itself.
    use mvm_hostd::netd::{DatapathRequest, L3Datapath};

    let dp = LoopbackDatapath::sink();
    let mut admitter = admitter();
    let guest = admitter.lease().guest;
    let mut handle = dp
        .open(&DatapathRequest {
            machine_id: "bench".into(),
            gateway: admitter.lease().gateway,
            guest,
            prefix_len: 30,
            mtu: limits::MTU_V1,
        })
        .expect("open the datapath");

    let packet = mtu_packet(guest, REMOTE);
    let wire = frame::encode(MessageType::Packet, 42, 0, &packet).unwrap();
    admitter.admit_outbound(&packet, 0);

    let iterations = ITERATIONS / 4;
    let start = Instant::now();
    for i in 0..iterations {
        let parsed = frame::decode(&wire).unwrap();
        if let OutboundVerdict::Forward(admitted) =
            admitter.admit_outbound(parsed.payload, i as u64)
        {
            handle.send_to_network(&admitted).unwrap();
        }
    }
    let elapsed = start.elapsed();
    report(
        "host path (decode+admit+forward)",
        iterations,
        elapsed,
        packet.len(),
    );

    let per_op_ns = elapsed.as_nanos() as f64 / iterations as f64;
    assert_ceiling("the host path", per_op_ns, 20_000.0);
}

#[test]
fn measure_dns_reply_construction() {
    let gateway = Ipv4Addr::new(10, 201, 0, 5);
    let guest = Ipv4Addr::new(10, 201, 0, 6);
    let answer = vec![0u8; 128];
    let iterations = ITERATIONS / 4;

    let start = Instant::now();
    for i in 0..iterations {
        let reply = build_udp_v4(gateway, guest, 53, 40000, &answer, 64, i as u16);
        std::hint::black_box(reply.len());
    }
    let elapsed = start.elapsed();
    report("dns reply build", iterations, elapsed, answer.len());
}

#[test]
fn measure_dns_binding_lookup() {
    let mut store = DnsBindingStore::with_defaults();
    store
        .bind_answer(
            "api.example.com",
            &[IpAddr::V4(REMOTE)],
            &[443],
            60_000,
            0,
            0,
        )
        .unwrap();

    let ip = IpAddr::V4(REMOTE);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        std::hint::black_box(store.permits(&ip, 443, 0, 1));
    }
    let elapsed = start.elapsed();
    report("dns binding lookup", ITERATIONS, elapsed, 0);
    let per_op_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    assert_ceiling("the dns binding lookup", per_op_ns, 1000.0);
}
