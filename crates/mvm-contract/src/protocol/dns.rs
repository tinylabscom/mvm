//! Bounded DNS question decoding and A/AAAA response encoding.
//!
//! This deliberately implements only the small DNS subset needed by the
//! host-mediated resolver. Unsupported or ambiguous inputs fail closed.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

const DNS_HEADER_LEN: usize = 12;
const QUESTION_TAIL_LEN: usize = 4;
const RESPONSE_TTL_SECONDS: u32 = 120;

/// Largest DNS message this codec will parse or emit.
pub const MAX_DNS_MESSAGE: usize = 4096;

/// DNS record families supported by the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// An IPv4 address record.
    A,
    /// An IPv6 address record.
    Aaaa,
}

impl DnsRecordType {
    const fn wire_value(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// A validated, single-question DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Lower-cased, trailing-dot-stripped ASCII name, bounded to 253 bytes.
    pub name: String,
    /// Requested address-record family.
    pub qtype: DnsRecordType,
    /// Client-supplied DNS transaction identifier.
    pub id: u16,
}

/// A reason an untrusted DNS query was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCodecError {
    /// The message exceeds [`MAX_DNS_MESSAGE`].
    TooLong,
    /// The message is shorter than a DNS header.
    TooShort,
    /// The message has the response bit set.
    NotAQuery,
    /// The question requests a record type other than A or AAAA.
    UnsupportedQType,
    /// The encoded name or question class is invalid.
    BadLabel,
    /// Bytes or unsupported resource-record sections follow the question.
    TrailingGarbage,
    /// The message does not contain exactly one question.
    MultiQuestion,
}

/// Parse a single-question A/AAAA query.
///
/// Names are returned as lower-case ASCII without a trailing dot. Compression
/// pointers and every record family other than A/AAAA are rejected.
pub fn decode_query(bytes: &[u8]) -> Result<DnsQuestion, DnsCodecError> {
    if bytes.len() > MAX_DNS_MESSAGE {
        return Err(DnsCodecError::TooLong);
    }
    if bytes.len() < DNS_HEADER_LEN {
        return Err(DnsCodecError::TooShort);
    }
    if bytes[2] & 0x80 != 0 {
        return Err(DnsCodecError::NotAQuery);
    }
    if read_u16(bytes, 4) != 1 {
        return Err(DnsCodecError::MultiQuestion);
    }
    if bytes[6..DNS_HEADER_LEN].iter().any(|value| *value != 0) {
        return Err(DnsCodecError::TrailingGarbage);
    }

    let (name, offset) = decode_name(bytes)?;
    let question_end = offset
        .checked_add(QUESTION_TAIL_LEN)
        .ok_or(DnsCodecError::BadLabel)?;
    let tail = bytes
        .get(offset..question_end)
        .ok_or(DnsCodecError::BadLabel)?;
    let qtype = match u16::from_be_bytes([tail[0], tail[1]]) {
        1 => DnsRecordType::A,
        28 => DnsRecordType::Aaaa,
        _ => return Err(DnsCodecError::UnsupportedQType),
    };
    if u16::from_be_bytes([tail[2], tail[3]]) != 1 {
        return Err(DnsCodecError::BadLabel);
    }
    if question_end != bytes.len() {
        return Err(DnsCodecError::TrailingGarbage);
    }

    Ok(DnsQuestion {
        name,
        qtype,
        id: read_u16(bytes, 0),
    })
}

fn decode_name(bytes: &[u8]) -> Result<(String, usize), DnsCodecError> {
    let mut offset = DNS_HEADER_LEN;
    let mut name = String::new();

    loop {
        let length = usize::from(*bytes.get(offset).ok_or(DnsCodecError::BadLabel)?);
        offset = offset.checked_add(1).ok_or(DnsCodecError::BadLabel)?;
        if length == 0 {
            if name.is_empty() {
                return Err(DnsCodecError::BadLabel);
            }
            return Ok((name, offset));
        }
        if length > 63 {
            return Err(DnsCodecError::BadLabel);
        }

        let label_end = offset.checked_add(length).ok_or(DnsCodecError::BadLabel)?;
        let label = bytes
            .get(offset..label_end)
            .ok_or(DnsCodecError::BadLabel)?;
        if !label.iter().all(|byte| valid_label_byte(*byte)) {
            return Err(DnsCodecError::BadLabel);
        }

        let separator_len = usize::from(!name.is_empty());
        let next_name_len = name
            .len()
            .checked_add(separator_len)
            .and_then(|value| value.checked_add(length))
            .ok_or(DnsCodecError::BadLabel)?;
        if next_name_len > 253 {
            return Err(DnsCodecError::BadLabel);
        }
        if separator_len == 1 {
            name.push('.');
        }
        name.extend(
            label
                .iter()
                .map(|byte| char::from(*byte).to_ascii_lowercase()),
        );
        offset = label_end;
    }
}

const fn valid_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

const fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

/// RCODE for an encoded DNS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRcode {
    /// The request was admitted and processed successfully.
    NoError,
    /// Policy refused the request.
    Refused,
}

impl DnsRcode {
    const fn wire_value(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::Refused => 5,
        }
    }
}

/// Encode a bounded response with one A/AAAA record per matching address.
///
/// Addresses from the wrong family are skipped. A `DnsQuestion` constructed
/// with an invalid name produces a header-only response instead of emitting an
/// invalid question section.
#[must_use]
pub fn encode_response(q: &DnsQuestion, rcode: DnsRcode, ips: &[IpAddr]) -> Vec<u8> {
    let mut response = Vec::with_capacity(MAX_DNS_MESSAGE.min(512));
    response.extend_from_slice(&q.id.to_be_bytes());
    response.extend_from_slice(&(0x8080_u16 | rcode.wire_value()).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());

    let Some(question) = encode_question(q) else {
        return response;
    };
    response[4..6].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&question);

    let mut answer_count = 0_u16;
    for ip in ips.iter().filter(|ip| address_matches(q.qtype, ip)) {
        let record_len = match ip {
            IpAddr::V4(_) => 16,
            IpAddr::V6(_) => 28,
        };
        if response.len().saturating_add(record_len) > MAX_DNS_MESSAGE {
            break;
        }
        append_answer(&mut response, q.qtype, ip);
        answer_count = answer_count.saturating_add(1);
    }
    response[6..8].copy_from_slice(&answer_count.to_be_bytes());
    response
}

fn encode_question(q: &DnsQuestion) -> Option<Vec<u8>> {
    if q.name.is_empty() || q.name.len() > 253 {
        return None;
    }
    let mut encoded = Vec::with_capacity(q.name.len().saturating_add(QUESTION_TAIL_LEN + 2));
    for label in q.name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(valid_label_byte)
            || label.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return None;
        }
        encoded.push(u8::try_from(label.len()).ok()?);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded.extend_from_slice(&q.qtype.wire_value().to_be_bytes());
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    Some(encoded)
}

const fn address_matches(qtype: DnsRecordType, ip: &IpAddr) -> bool {
    matches!(
        (qtype, ip),
        (DnsRecordType::A, IpAddr::V4(_)) | (DnsRecordType::Aaaa, IpAddr::V6(_))
    )
}

fn append_answer(response: &mut Vec<u8>, qtype: DnsRecordType, ip: &IpAddr) {
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&qtype.wire_value().to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&RESPONSE_TTL_SECONDS.to_be_bytes());
    match ip {
        IpAddr::V4(address) => {
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            response.extend_from_slice(&16_u16.to_be_bytes());
            response.extend_from_slice(&address.octets());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn decode_rejects_oversized_and_short() {
        assert_eq!(
            decode_query(&[0_u8; MAX_DNS_MESSAGE + 1]),
            Err(DnsCodecError::TooLong)
        );
        assert_eq!(decode_query(&[0_u8; 4]), Err(DnsCodecError::TooShort));
    }

    #[test]
    fn decode_parses_single_a_question() {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["ExAmPlE", "COM"] {
            message.push(u8::try_from(label.len()).expect("test label length fits in u8"));
            message.extend_from_slice(label.as_bytes());
        }
        message.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

        let question = decode_query(&message).unwrap();
        assert_eq!(
            question,
            DnsQuestion {
                name: "example.com".into(),
                qtype: DnsRecordType::A,
                id: 0x1234,
            }
        );
    }

    #[test]
    fn decode_rejects_response_bit_and_multi_question() {
        let mut response = vec![0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        response.extend_from_slice(&[0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(decode_query(&response), Err(DnsCodecError::NotAQuery));

        let mut multi = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
        multi.extend_from_slice(&[0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(decode_query(&multi), Err(DnsCodecError::MultiQuestion));
    }

    #[test]
    fn decode_rejects_invalid_question_shapes() {
        let cases = [
            (
                vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1],
                DnsCodecError::BadLabel,
            ),
            (
                vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 2, 0, 1],
                DnsCodecError::UnsupportedQType,
            ),
            (
                vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 2],
                DnsCodecError::BadLabel,
            ),
            (
                vec![
                    0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 9,
                ],
                DnsCodecError::TrailingGarbage,
            ),
        ];

        for (message, expected) in cases {
            assert_eq!(decode_query(&message), Err(expected));
        }
    }

    #[test]
    fn encode_a_response_roundtrips_answer_ips() {
        let question = DnsQuestion {
            name: "example.com".into(),
            qtype: DnsRecordType::A,
            id: 0x1234,
        };
        let out = encode_response(
            &question,
            DnsRcode::NoError,
            &[
                "93.184.216.34".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        );

        assert_eq!(&out[0..2], &[0x12, 0x34]);
        assert_eq!(out[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1);
        assert!(out.len() <= MAX_DNS_MESSAGE);
    }

    #[test]
    fn encode_refused_has_zero_answers_and_rcode_five() {
        let question = DnsQuestion {
            name: "evil.test".into(),
            qtype: DnsRecordType::Aaaa,
            id: 7,
        };
        let out = encode_response(&question, DnsRcode::Refused, &[]);

        assert_eq!(out[3] & 0x0f, 5);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0);
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        for seed in 0_u16..2000 {
            let bytes: Vec<u8> = (0..usize::from(seed) % 300)
                .map(|index| (index as u8) ^ (seed as u8))
                .collect();
            let _ = decode_query(&bytes);
        }
    }
}
