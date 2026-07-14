// Fuzz the guest-side transparent-network packet translator.
//
// `GuestPacketTranslator::translate_outbound_ipv4` is the first parser on the
// guest's hostile-byte path after the TUN read: arbitrary IPv4 bytes become DNS,
// TCP, UDP, and ICMP authority events plus state transitions. The harness
// contract is "never panic on any input". For any outbound event the translator
// accepts, the matching synthesis path must also fail closed to `Err`/`None`,
// never panic, when driven with a conservative host-side response.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_net::guest_packet::{GuestPacketTranslator, OutboundPacketEvent};
use mvm_net::proto::{
    CloseFlow, CloseReason, DnsResponse, DnsResponseCode, FlowDirection, IcmpEchoResponse,
    IcmpEchoStatus, StreamChunk, TcpOpenResult, UdpDatagram,
};

fuzz_target!(|data: &[u8]| {
    let mut translator = GuestPacketTranslator::default();
    let mut cursor = data;
    let mut steps = 0usize;

    while !cursor.is_empty() && steps < 64 {
        let chunk_len = usize::from(cursor[0]);
        cursor = &cursor[1..];
        let take = chunk_len.min(cursor.len());
        let packet = &cursor[..take];
        cursor = &cursor[take..];
        steps += 1;

        let Ok(events) = translator.translate_outbound_ipv4(packet) else {
            continue;
        };

        for event in events {
            match event {
                OutboundPacketEvent::DnsQuery(query) => {
                    let _ = translator.synthesize_dns_response(&DnsResponse {
                        query_id: query.query_id,
                        code: DnsResponseCode::Refused,
                        answers: Vec::new(),
                        denial: None,
                    });
                }
                OutboundPacketEvent::OpenTcp(open) => {
                    let _ = translator
                        .synthesize_tcp_open_result(&TcpOpenResult::opened(open.flow_id));
                }
                OutboundPacketEvent::TcpData(chunk) => {
                    let _ = translator.synthesize_tcp_data(&StreamChunk::new(
                        chunk.flow_id,
                        FlowDirection::HostToGuest,
                        0,
                        chunk.bytes.clone(),
                    ));
                    if chunk.end_stream {
                        let _ = translator.synthesize_tcp_close(&CloseFlow {
                            flow_id: chunk.flow_id,
                            reason: CloseReason::HostClosed,
                        });
                    }
                }
                OutboundPacketEvent::CloseFlow(_) => {}
                OutboundPacketEvent::UdpDatagram(datagram) => {
                    let _ = translator.synthesize_udp_datagram(&UdpDatagram {
                        flow_id: datagram.flow_id,
                        target: datagram.target,
                        direction: FlowDirection::HostToGuest,
                        bytes: datagram.bytes,
                    });
                }
                OutboundPacketEvent::IcmpEchoRequest(request) => {
                    let _ = translator.synthesize_icmp_echo_response(&IcmpEchoResponse {
                        query_id: request.query_id,
                        status: IcmpEchoStatus::Replied,
                        round_trip_micros: Some(1),
                        denial: None,
                    });
                }
            }
        }
    }
});
