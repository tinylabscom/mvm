// Fuzz the dependency-light host-netd config + stdio seam.
//
// `host_netd` owns manual launch-config parsing, JSON config decoding, and the
// in-memory stdio contract above `host_runner`. The harness contract is "never
// panic on any config/message cadence". Arbitrary bytes become launch args/env,
// raw JSON, generated config JSON, and bounded guest authority messages that
// run through `run_host_netd_on_stdio_parts()` without live sockets.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use mvm_net::host_netd::{
    ENV_CONFIG, ENV_LISTEN_UDS, JsonLineAuditSink, config_from_json_str,
    launch_config_from_args_and_env, run_host_netd_on_stdio_parts,
};
use mvm_net::proto::{
    AlpnProtocol, Capability, CloseFlow, CloseReason, DatagramStatus, Denial, DenialReason,
    DnsName, DnsQuery, DnsRecordType, DnsResponse, DnsResponseCode, EndpointRole, FlowDirection,
    FlowId, Hello, HelloAck, IcmpEchoRequest, IcmpEchoResponse, IcmpEchoStatus, NetMessage,
    OpenTcp, PluginId, QueryId, StreamChunk, Target, TcpOpenResult, TlsTermination,
    TlsTransformRoute, TransportError, UdpDatagram, UdpDelivery,
};
use mvm_net::wire_json::LengthPrefixedJsonAuthority;

const MAX_MESSAGES: usize = 32;
const MAX_CHUNK_BYTES: usize = 32;
const NOW: &str = "2030-01-01T00:00:00Z";

fuzz_target!(|data: &[u8]| {
    let split = data.len().min(16);
    let (config_bytes, runtime_bytes) = data.split_at(split);

    exercise_launch_config(config_bytes);

    let raw_json = String::from_utf8_lossy(runtime_bytes);
    let _ = config_from_json_str(&raw_json);

    let generated_json = build_config_json(config_bytes);
    let Ok(config) = config_from_json_str(&generated_json) else {
        return;
    };

    let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
    let mut cursor = runtime_bytes;
    let mut steps = 0usize;
    while !cursor.is_empty() && steps < MAX_MESSAGES {
        let opcode = cursor[0];
        cursor = &cursor[1..];
        let take = cursor
            .first()
            .map_or(0usize, |len| usize::from(*len).min(cursor.len().saturating_sub(1)));
        let payload = if cursor.is_empty() {
            &[][..]
        } else {
            let payload = &cursor[1..1 + take];
            cursor = &cursor[1 + take..];
            payload
        };
        steps += 1;
        let _ = encoded.write_message(build_message(opcode, payload));
    }

    let input = Cursor::new(encoded.into_inner().into_inner());
    let mut output = Cursor::new(Vec::new());
    let mut audit = Vec::new();
    let _ = run_host_netd_on_stdio_parts(
        &config,
        input,
        &mut output,
        JsonLineAuditSink::new(&mut audit),
    );
});

fn exercise_launch_config(bytes: &[u8]) {
    let config_path = if bytes.first().copied().unwrap_or(0) & 0x01 == 0 {
        "/tmp/mvm-host-netd.json"
    } else {
        ""
    };
    let listen_path = if bytes.get(1).copied().unwrap_or(0) & 0x01 == 0 {
        "/tmp/mvm-host-netd.sock"
    } else {
        ""
    };

    let mut args = Vec::<String>::new();
    if bytes.get(2).copied().unwrap_or(0) & 0x01 == 0 {
        args.push("--config".to_string());
        args.push(config_path.to_string());
    } else {
        args.push(format!("--config={config_path}"));
    }
    if bytes.get(3).copied().unwrap_or(0) & 0x01 != 0 {
        if bytes.get(4).copied().unwrap_or(0) & 0x01 == 0 {
            args.push("--listen-uds".to_string());
            args.push(listen_path.to_string());
        } else {
            args.push(format!("--listen-uds={listen_path}"));
        }
    }
    if bytes.get(5).copied().unwrap_or(0) & 0x01 != 0 {
        args.push("--bogus".to_string());
    }

    let mut env = Vec::<(&str, String)>::new();
    if bytes.get(6).copied().unwrap_or(0) & 0x01 != 0 {
        env.push((ENV_CONFIG, "/tmp/env-host-netd.json".to_string()));
    }
    if bytes.get(7).copied().unwrap_or(0) & 0x01 != 0 {
        env.push((ENV_LISTEN_UDS, "/tmp/env-host-netd.sock".to_string()));
    }

    let _ = launch_config_from_args_and_env(args, env);
}

fn build_config_json(bytes: &[u8]) -> String {
    let preset = if bytes.first().copied().unwrap_or(0) & 0x01 == 0 {
        "none"
    } else {
        "unrestricted"
    };
    let mut fields = vec![
        format!(r#""network_policy":{{"type":"preset","preset":"{preset}"}}"#),
        format!(r#""now":"{NOW}""#),
    ];

    if bytes.get(1).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""max_messages_per_run":{}"#,
            usize::from(bytes.get(2).copied().unwrap_or(0))
        ));
    }
    if bytes.get(3).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""max_wire_frame_bytes":{}"#,
            usize::from(bytes.get(4).copied().unwrap_or(0))
        ));
    }
    if bytes.get(5).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""max_open_flows":{}"#,
            usize::from(bytes.get(6).copied().unwrap_or(0))
        ));
    }
    if bytes.get(7).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""max_guest_requests_per_window":{}"#,
            usize::from(bytes.get(8).copied().unwrap_or(0))
        ));
    }
    if bytes.get(9).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""guest_request_rate_window_millis":{}"#,
            u64::from(bytes.get(10).copied().unwrap_or(0))
        ));
    }
    if bytes.get(11).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""max_pending_guest_tls_bytes":{}"#,
            usize::from(bytes.get(12).copied().unwrap_or(0))
        ));
    }
    if bytes.get(13).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(format!(
            r#""max_pending_upstream_tls_plaintext_bytes":{}"#,
            usize::from(bytes.get(14).copied().unwrap_or(0))
        ));
    }
    if bytes.get(15).copied().unwrap_or(0) & 0x01 != 0 {
        fields.push(r#""extra":true"#.to_string());
    }

    format!("{{{}}}", fields.join(","))
}

fn build_message(opcode: u8, payload: &[u8]) -> NetMessage {
    match opcode % 12 {
        0 => NetMessage::Hello(Hello::new(
            if opcode & 1 == 0 {
                EndpointRole::Guest
            } else {
                EndpointRole::Host
            },
            capabilities_from_bits(payload.first().copied().unwrap_or(0)),
        )),
        1 => NetMessage::OpenTcp(build_open_tcp(payload)),
        2 => NetMessage::TcpData(build_stream_chunk(payload)),
        3 => NetMessage::CloseFlow(CloseFlow {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            reason: close_reason_from_byte(payload.get(1).copied().unwrap_or(0)),
        }),
        4 => NetMessage::DnsQuery(DnsQuery {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            name: DnsName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
                .expect("fixed DNS name must be valid"),
            record_type: dns_record_type_from_byte(payload.get(2).copied().unwrap_or(0)),
        }),
        5 => NetMessage::UdpDatagram(UdpDatagram {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            target: Target::new(
                host_for_byte(payload.get(1).copied().unwrap_or(0)),
                port_for_byte(payload.get(2).copied().unwrap_or(0)),
            )
            .expect("fixed UDP target must be valid"),
            direction: if payload.get(3).copied().unwrap_or(0) & 1 == 0 {
                FlowDirection::GuestToHost
            } else {
                FlowDirection::HostToGuest
            },
            bytes: bounded_bytes(payload.get(4..).unwrap_or(&[])),
        }),
        6 => NetMessage::IcmpEchoRequest(IcmpEchoRequest {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            host: mvm_net::proto::HostName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
                .expect("fixed ICMP host must be valid"),
            payload_len: u16::from(payload.get(2).copied().unwrap_or(0)),
        }),
        7 => NetMessage::HelloAck(HelloAck::new(capabilities_from_bits(
            payload.first().copied().unwrap_or(0),
        ))),
        8 => NetMessage::TcpOpenResult(TcpOpenResult::failed(
            flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            transport_error_from_byte(payload.get(1).copied().unwrap_or(0)),
        )),
        9 => NetMessage::DnsResponse(DnsResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            code: DnsResponseCode::Refused,
            answers: Vec::new(),
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        }),
        10 => NetMessage::UdpDelivery(UdpDelivery {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: DatagramStatus::Failed(TransportError::ProtocolError),
        }),
        11 => NetMessage::IcmpEchoResponse(IcmpEchoResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: IcmpEchoStatus::Denied,
            round_trip_micros: None,
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        }),
        _ => NetMessage::HelloAck(HelloAck::new(Vec::new())),
    }
}

fn build_open_tcp(payload: &[u8]) -> OpenTcp {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let host = host_for_byte(payload.get(1).copied().unwrap_or(0));
    let port = port_for_byte(payload.get(2).copied().unwrap_or(0));
    let target = Target::new(host, port).expect("fixed target must be valid");
    let mut open = OpenTcp::new(flow_id, target);
    if payload.get(3).copied().unwrap_or(0) & 0x01 != 0 {
        let server_name =
            DnsName::new(host_for_byte(payload.get(4).copied().unwrap_or(0))).expect("fixed DNS name");
        let termination = if payload.get(3).copied().unwrap_or(0) & 0x02 == 0 {
            TlsTermination::TerminateAndReoriginate
        } else {
            TlsTermination::RefusePinnedClient
        };
        let mut route = TlsTransformRoute::new(server_name, termination);
        if payload.get(3).copied().unwrap_or(0) & 0x04 != 0 {
            route = route.with_alpn_protocols(vec![
                AlpnProtocol::new("h2").expect("fixed ALPN must be valid"),
            ]);
        }
        let plugins = plugin_chain_for_byte(payload.get(5).copied().unwrap_or(0));
        if !plugins.is_empty() {
            route = route.with_transform_chain(plugins);
        }
        open = open.with_tls_transform(route);
    }
    open
}

fn build_stream_chunk(payload: &[u8]) -> StreamChunk {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let direction = if payload.get(1).copied().unwrap_or(0) & 1 == 0 {
        FlowDirection::GuestToHost
    } else {
        FlowDirection::HostToGuest
    };
    let sequence = u64::from(payload.get(2).copied().unwrap_or(0));
    let chunk = StreamChunk::new(flow_id, direction, sequence, bounded_bytes(payload.get(3..).unwrap_or(&[])));
    if payload.get(1).copied().unwrap_or(0) & 0x02 != 0 {
        return chunk.with_end_stream();
    }
    chunk
}

fn bounded_bytes(payload: &[u8]) -> Vec<u8> {
    payload.iter().copied().take(MAX_CHUNK_BYTES).collect()
}

fn capabilities_from_bits(bits: u8) -> Vec<Capability> {
    let mut capabilities = vec![
        Capability::Dns,
        Capability::Tcp,
        Capability::AuditCorrelation,
        Capability::PolicyDigest,
    ];
    if bits & 0x01 != 0 {
        capabilities.push(Capability::Udp);
    }
    if bits & 0x02 != 0 {
        capabilities.push(Capability::IcmpEcho);
    }
    if bits & 0x04 != 0 {
        capabilities.push(Capability::TlsTransform);
    }
    if bits & 0x08 != 0 {
        capabilities.push(Capability::StreamTransforms);
    }
    capabilities
}

fn plugin_chain_for_byte(value: u8) -> Vec<PluginId> {
    match value % 5 {
        0 => Vec::new(),
        1 => vec![PluginId::new("audit").expect("fixed plugin id must be valid")],
        2 => vec![PluginId::new("metadata-endpoint-deny").expect("fixed plugin id must be valid")],
        3 => vec![PluginId::new("secret-replacement").expect("fixed plugin id must be valid")],
        _ => vec![PluginId::new("response-leak-guard").expect("fixed plugin id must be valid")],
    }
}

fn flow_id_from_byte(value: u8) -> FlowId {
    FlowId::new(u64::from(value) + 1).expect("fuzz flow id must be non-zero")
}

fn query_id_from_byte(value: u8) -> QueryId {
    QueryId::new(u64::from(value) + 1).expect("fuzz query id must be non-zero")
}

fn host_for_byte(value: u8) -> &'static str {
    match value % 5 {
        0 => "example.com",
        1 => "api.example.com",
        2 => "metadata.google.internal",
        3 => "localhost",
        _ => "test.invalid",
    }
}

fn port_for_byte(value: u8) -> u16 {
    match value % 5 {
        0 => 53,
        1 => 80,
        2 => 443,
        3 => 8080,
        _ => 22,
    }
}

fn dns_record_type_from_byte(value: u8) -> DnsRecordType {
    match value % 4 {
        0 => DnsRecordType::A,
        1 => DnsRecordType::Aaaa,
        2 => DnsRecordType::Cname,
        _ => DnsRecordType::Txt,
    }
}

fn transport_error_from_byte(value: u8) -> TransportError {
    match value % 7 {
        0 => TransportError::DnsFailed,
        1 => TransportError::TimedOut,
        2 => TransportError::Refused,
        3 => TransportError::Unreachable,
        4 => TransportError::Reset,
        5 => TransportError::TlsHandshakeFailed,
        _ => TransportError::ProtocolError,
    }
}

fn close_reason_from_byte(value: u8) -> CloseReason {
    match value % 5 {
        0 => CloseReason::GuestClosed,
        1 => CloseReason::HostClosed,
        2 => CloseReason::PolicyDenied,
        3 => CloseReason::ProtocolError,
        _ => CloseReason::TransformError,
    }
}
