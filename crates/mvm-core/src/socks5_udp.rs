//! SOCKS5 UDP datagrams shared by the guest proxy and host relay.

use std::net::IpAddr;

/// First-line marker selecting the SOCKS5 UDP relay on the shared egress stream.
pub const FRAME_LINE: &str = "MVM_SOCKS5_UDP/1";
/// Maximum SOCKS5 UDP datagram payload accepted by the relay.
pub const MAX_DATAGRAM_BYTES: usize = 65_535;

/// An address carried by a SOCKS5 UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// A numeric IPv4 or IPv6 destination.
    Ip(IpAddr),
    /// A hostname that the host resolves and admits.
    Domain(String),
}

impl Address {
    /// Render the address and port in the host egress gate's target format.
    pub fn target(&self, port: u16) -> String {
        match self {
            Self::Ip(ip) => match ip {
                IpAddr::V4(_) => format!("{ip}:{port}"),
                IpAddr::V6(_) => format!("[{ip}]:{port}"),
            },
            Self::Domain(host) => format!("{host}:{port}"),
        }
    }
}

/// One RFC 1928 §7 SOCKS5 UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The destination or source address in the SOCKS5 envelope.
    pub address: Address,
    /// The destination or source UDP port.
    pub port: u16,
    /// The application payload.
    pub payload: Vec<u8>,
}

impl Datagram {
    /// Decode a SOCKS5 UDP datagram. Fragmented datagrams are rejected because
    /// the relay does not retain unbounded reassembly state.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::TooShort);
        }
        if bytes[0] != 0 || bytes[1] != 0 {
            return Err(DecodeError::InvalidReserved);
        }
        if bytes[2] != 0 {
            return Err(DecodeError::Fragmented);
        }

        let mut cursor: usize = 4;
        let address = match bytes[3] {
            0x01 => {
                let end = cursor.checked_add(4).ok_or(DecodeError::TooShort)?;
                let octets: [u8; 4] = bytes
                    .get(cursor..end)
                    .ok_or(DecodeError::TooShort)?
                    .try_into()
                    .map_err(|_| DecodeError::TooShort)?;
                cursor = end;
                Address::Ip(IpAddr::from(octets))
            }
            0x03 => {
                let length = usize::from(*bytes.get(cursor).ok_or(DecodeError::TooShort)?);
                cursor += 1;
                if length == 0 {
                    return Err(DecodeError::EmptyDomain);
                }
                let end = cursor.checked_add(length).ok_or(DecodeError::TooShort)?;
                let host =
                    std::str::from_utf8(bytes.get(cursor..end).ok_or(DecodeError::TooShort)?)
                        .map_err(|_| DecodeError::InvalidDomain)?
                        .to_string();
                cursor = end;
                Address::Domain(host)
            }
            0x04 => {
                let end = cursor.checked_add(16).ok_or(DecodeError::TooShort)?;
                let octets: [u8; 16] = bytes
                    .get(cursor..end)
                    .ok_or(DecodeError::TooShort)?
                    .try_into()
                    .map_err(|_| DecodeError::TooShort)?;
                cursor = end;
                Address::Ip(IpAddr::from(octets))
            }
            _ => return Err(DecodeError::UnknownAddressType),
        };

        let port_end = cursor.checked_add(2).ok_or(DecodeError::TooShort)?;
        let port_bytes = bytes.get(cursor..port_end).ok_or(DecodeError::TooShort)?;
        let port = u16::from_be_bytes(port_bytes.try_into().map_err(|_| DecodeError::TooShort)?);
        let payload = bytes.get(port_end..).ok_or(DecodeError::TooShort)?.to_vec();
        Ok(Self {
            address,
            port,
            payload,
        })
    }

    /// Encode this datagram in RFC 1928 §7 wire form.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let (atyp, address_bytes) = match &self.address {
            Address::Ip(IpAddr::V4(ip)) => (0x01, ip.octets().to_vec()),
            Address::Ip(IpAddr::V6(ip)) => (0x04, ip.octets().to_vec()),
            Address::Domain(host) => {
                let length = u8::try_from(host.len()).map_err(|_| EncodeError::DomainTooLong)?;
                if length == 0 {
                    return Err(EncodeError::EmptyDomain);
                }
                if !host.is_ascii() {
                    return Err(EncodeError::DomainNotAscii);
                }
                let mut bytes = Vec::with_capacity(1 + host.len());
                bytes.push(length);
                bytes.extend_from_slice(host.as_bytes());
                (0x03, bytes)
            }
        };
        let overhead = 4 + address_bytes.len() + 2;
        let length = overhead
            .checked_add(self.payload.len())
            .ok_or(EncodeError::DatagramTooLarge)?;
        if length > MAX_DATAGRAM_BYTES {
            return Err(EncodeError::DatagramTooLarge);
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(&[0, 0, 0, atyp]);
        bytes.extend_from_slice(&address_bytes);
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

/// A malformed SOCKS5 UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The datagram does not contain the required header and address fields.
    TooShort,
    /// The reserved bytes were not zero.
    InvalidReserved,
    /// Fragmentation is not supported.
    Fragmented,
    /// The address type is not IPv4, domain, or IPv6.
    UnknownAddressType,
    /// The domain field was empty.
    EmptyDomain,
    /// The domain field was not UTF-8.
    InvalidDomain,
}

/// An unrepresentable SOCKS5 UDP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The domain field is empty.
    EmptyDomain,
    /// The domain field is not ASCII, as required by the SOCKS5 wire format.
    DomainNotAscii,
    /// The domain field exceeds its one-byte length prefix.
    DomainTooLong,
    /// The encoded datagram exceeds the relay's cap.
    DatagramTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_datagram_roundtrips() {
        let datagram = Datagram {
            address: Address::Ip("192.0.2.10".parse().expect("valid test address")),
            port: 5353,
            payload: b"hello".to_vec(),
        };
        assert_eq!(
            Datagram::decode(&datagram.encode().expect("encodes")),
            Ok(datagram)
        );
    }

    #[test]
    fn domain_datagram_roundtrips_and_formats_target() {
        let datagram = Datagram {
            address: Address::Domain("example.test".to_string()),
            port: 443,
            payload: vec![1, 2, 3],
        };
        assert_eq!(datagram.address.target(443), "example.test:443");
        assert_eq!(
            Datagram::decode(&datagram.encode().expect("encodes")),
            Ok(datagram)
        );
    }

    #[test]
    fn rejects_reserved_fragment_and_unknown_address() {
        assert_eq!(
            Datagram::decode(&[1, 0, 0, 1]),
            Err(DecodeError::InvalidReserved)
        );
        assert_eq!(
            Datagram::decode(&[0, 0, 1, 1]),
            Err(DecodeError::Fragmented)
        );
        assert_eq!(
            Datagram::decode(&[0, 0, 0, 9]),
            Err(DecodeError::UnknownAddressType)
        );
    }

    #[test]
    fn rejects_oversized_payload_and_non_ascii_domain() {
        let oversized = Datagram {
            address: Address::Ip("192.0.2.1".parse().expect("valid test address")),
            port: 7,
            payload: vec![0; MAX_DATAGRAM_BYTES],
        };
        assert_eq!(oversized.encode(), Err(EncodeError::DatagramTooLarge));

        let non_ascii = Datagram {
            address: Address::Domain("exämple.test".to_string()),
            port: 7,
            payload: Vec::new(),
        };
        assert_eq!(non_ascii.encode(), Err(EncodeError::DomainNotAscii));
    }
}
