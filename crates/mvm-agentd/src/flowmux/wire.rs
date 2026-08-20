use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use mvm_contract::protocol::network_flow::UDP_ADDR_PREFIX_LEN;

use super::FlowMuxError;

/// Encode one DNS A or AAAA question for a FlowMux `Resolve` frame.
pub fn build_dns_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, FlowMuxError> {
    let mut query = Vec::with_capacity(64);

    // Header: ID, flags (standard recursive query), QDCOUNT=1, others 0.
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());

    let normalized = name.trim_end_matches('.');
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(FlowMuxError::Frame("invalid DNS name".into()));
    }
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(FlowMuxError::Frame("invalid DNS label".into()));
        }
        query.push(
            u8::try_from(label.len()).map_err(|_| FlowMuxError::Frame("label too long".into()))?,
        );
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);

    let qtype_value = match qtype {
        1 => 1u16,
        28 => 28u16,
        _ => return Err(FlowMuxError::Frame(format!("unsupported qtype {qtype}"))),
    };
    query.extend_from_slice(&qtype_value.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN

    Ok(query)
}

/// Encode the destination prefix carried by a FlowMux UDP frame.
pub fn encode_udp_addr(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDP_ADDR_PREFIX_LEN);
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&[0; 10]);
            out.extend_from_slice(&[0xff, 0xff]);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Decode the source prefix and datagram body carried by a FlowMux UDP frame.
pub fn decode_udp_addr(bytes: &[u8]) -> Result<(SocketAddr, &[u8]), FlowMuxError> {
    if bytes.len() < UDP_ADDR_PREFIX_LEN {
        return Err(FlowMuxError::Frame(format!(
            "short UDP address: {} < {UDP_ADDR_PREFIX_LEN}",
            bytes.len()
        )));
    }
    let address: [u8; 16] = bytes[1..17]
        .try_into()
        .map_err(|_| FlowMuxError::Frame("truncated UDP address slot".into()))?;
    let ip =
        match bytes[0] {
            0x01 => {
                let v6 = Ipv6Addr::from(address);
                IpAddr::V4(v6.to_ipv4_mapped().ok_or_else(|| {
                    FlowMuxError::Frame("IPv4-mapped UDP address expected".into())
                })?)
            }
            0x04 => IpAddr::V6(Ipv6Addr::from(address)),
            tag => {
                return Err(FlowMuxError::Frame(format!(
                    "unknown UDP address tag {tag}"
                )));
            }
        };
    let port = u16::from_be_bytes([bytes[17], bytes[18]]);
    let addr = SocketAddr::new(ip, port);
    Ok((addr, &bytes[UDP_ADDR_PREFIX_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_addr_roundtrips_ipv4_and_ipv6() {
        let v4 = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 1234);
        let encoded = encode_udp_addr(v4.ip(), v4.port());
        assert_eq!(encoded.len(), UDP_ADDR_PREFIX_LEN);
        assert_eq!(
            &encoded[..13],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        );
        let (decoded, rest) = decode_udp_addr(&encoded).unwrap();
        assert_eq!(decoded, v4);
        assert!(rest.is_empty());

        let v6 = SocketAddr::new(IpAddr::from(Ipv6Addr::LOCALHOST), 5678);
        let encoded = encode_udp_addr(v6.ip(), v6.port());
        let (decoded, rest) = decode_udp_addr(&encoded).unwrap();
        assert_eq!(decoded, v6);
        assert!(rest.is_empty());
    }

    #[test]
    fn udp_addr_refuses_a_short_or_non_mapped_ipv4_slot() {
        assert!(decode_udp_addr(&[0x01, 127, 0, 0, 1, 0, 53]).is_err());
        let mut non_mapped = vec![0x01];
        non_mapped.extend_from_slice(&[0; 16]);
        non_mapped.extend_from_slice(&53_u16.to_be_bytes());
        assert!(decode_udp_addr(&non_mapped).is_err());
    }

    #[test]
    fn dns_query_encodes_a_and_aaaa() {
        let a = build_dns_query("example.com", 1, 0x1234).unwrap();
        assert_eq!(&a[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([a[2], a[3]]), 0x0100);
        assert_eq!(u16::from_be_bytes([a[4], a[5]]), 1);
        assert!(a.len() > 12);

        let aaaa = build_dns_query("example.com", 28, 0xabcd).unwrap();
        assert_eq!(&aaaa[0..2], &[0xab, 0xcd]);
    }
}
