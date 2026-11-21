//! Strict, bounded vocabulary for one commissioning-bootstrap exchange.
//!
//! This module defines bytes only. It opens no transport and grants no authority.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// The only supported commissioning-bootstrap protocol version.
pub const VERSION: u8 = 1;
/// Maximum accepted or emitted JSON message size.
pub const MAX_ENCODED_MESSAGE_BYTES: usize = 512;
/// The only valid confirmation and acceptance sequence.
pub const CONFIRM_SEQUENCE: u8 = 1;
/// Maximum lifetime advertised by a challenge.
pub const MAX_CHALLENGE_EXPIRES_AFTER_MS: u32 = 30_000;

/// A commissioning-bootstrap request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Starts one exchange bound to an exact public commissioning intent.
    Begin {
        /// Protocol version.
        version: u8,
        /// Digest of the exact commissioning intent.
        intent_digest: [u8; 32],
        /// Fresh nonce selected by the client.
        client_nonce: [u8; 32],
    },
    /// Confirms the one issued challenge.
    Confirm {
        /// Protocol version.
        version: u8,
        /// Digest from the accepted begin request.
        intent_digest: [u8; 32],
        /// Client nonce from the accepted begin request.
        client_nonce: [u8; 32],
        /// Server nonce from the challenge.
        server_nonce: [u8; 32],
        /// One-based exchange sequence.
        sequence: u8,
    },
}

/// A commissioning-bootstrap response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Binds a short-lived server nonce to an accepted begin request.
    Challenge {
        /// Protocol version.
        version: u8,
        /// Digest from the accepted begin request.
        intent_digest: [u8; 32],
        /// Client nonce from the accepted begin request.
        client_nonce: [u8; 32],
        /// Fresh nonce selected by the server.
        server_nonce: [u8; 32],
        /// Remaining challenge lifetime, in milliseconds.
        expires_after_ms: u32,
    },
    /// Confirms consumption of the one accepted confirmation.
    Accepted {
        /// Protocol version.
        version: u8,
        /// Digest from the accepted exchange.
        intent_digest: [u8; 32],
        /// Client nonce from the accepted exchange.
        client_nonce: [u8; 32],
        /// Server nonce from the accepted exchange.
        server_nonce: [u8; 32],
        /// Consumed exchange sequence.
        sequence: u8,
    },
}

/// Payload-free refusal from bounded commissioning-bootstrap JSON handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The input or output exceeds the protocol byte cap.
    #[error("commissioning-bootstrap message exceeds the size bound")]
    TooLarge,
    /// JSON did not have exactly one recognized tagged-object shape.
    #[error("commissioning-bootstrap message is malformed")]
    Malformed,
    /// A recognized message violates a protocol invariant.
    #[error("commissioning-bootstrap message is invalid")]
    Invalid,
}

impl Request {
    /// Decodes one bounded, strict request object.
    ///
    /// # Errors
    ///
    /// Refuses oversized, malformed, unknown, or semantically invalid input.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let value: Self = decode::<RequestWire>(bytes)?.into();
        value.validate()?;
        Ok(value)
    }

    /// Encodes one validated request within the protocol bound.
    ///
    /// # Errors
    ///
    /// Refuses semantically invalid values or an output exceeding the byte cap.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Checks all request invariants independently of JSON handling.
    ///
    /// # Errors
    ///
    /// Refuses the wrong version, zero bindings, or a non-one confirmation sequence.
    pub fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Begin {
                version,
                intent_digest,
                client_nonce,
            } => validate_common(*version, intent_digest, client_nonce),
            Self::Confirm {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                sequence,
            } => {
                validate_common(*version, intent_digest, client_nonce)?;
                validate_nonzero(server_nonce)?;
                if *sequence != CONFIRM_SEQUENCE {
                    return Err(CodecError::Invalid);
                }
                Ok(())
            }
        }
    }
}

impl Response {
    /// Decodes one bounded, strict response object.
    ///
    /// # Errors
    ///
    /// Refuses oversized, malformed, unknown, or semantically invalid input.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let value: Self = decode::<ResponseWire>(bytes)?.into();
        value.validate()?;
        Ok(value)
    }

    /// Encodes one validated response within the protocol bound.
    ///
    /// # Errors
    ///
    /// Refuses semantically invalid values or an output exceeding the byte cap.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        encode(self)
    }

    /// Checks all response invariants independently of JSON handling.
    ///
    /// # Errors
    ///
    /// Refuses invalid bindings, sequence, or challenge lifetime.
    pub fn validate(&self) -> Result<(), CodecError> {
        match self {
            Self::Challenge {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                expires_after_ms,
            } => {
                validate_common(*version, intent_digest, client_nonce)?;
                validate_nonzero(server_nonce)?;
                if !(1..=MAX_CHALLENGE_EXPIRES_AFTER_MS).contains(expires_after_ms) {
                    return Err(CodecError::Invalid);
                }
                Ok(())
            }
            Self::Accepted {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                sequence,
            } => {
                validate_common(*version, intent_digest, client_nonce)?;
                validate_nonzero(server_nonce)?;
                if *sequence != CONFIRM_SEQUENCE {
                    return Err(CodecError::Invalid);
                }
                Ok(())
            }
        }
    }
}

fn decode<T>(bytes: &[u8]) -> Result<T, CodecError>
where
    T: for<'de> Deserialize<'de>,
{
    if bytes.len() > MAX_ENCODED_MESSAGE_BYTES {
        return Err(CodecError::TooLarge);
    }
    if bytes
        .iter()
        .copied()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        != Some(b'{')
    {
        return Err(CodecError::Malformed);
    }
    serde_json::from_slice(bytes).map_err(|_| CodecError::Malformed)
}

fn encode<T>(value: &T) -> Result<Vec<u8>, CodecError>
where
    T: Serialize + Validate,
{
    value.validate()?;
    let bytes = serde_json::to_vec(value).map_err(|_| CodecError::Malformed)?;
    if bytes.len() > MAX_ENCODED_MESSAGE_BYTES {
        return Err(CodecError::TooLarge);
    }
    Ok(bytes)
}

trait Validate {
    fn validate(&self) -> Result<(), CodecError>;
}

impl Validate for Request {
    fn validate(&self) -> Result<(), CodecError> {
        Request::validate(self)
    }
}

impl Validate for Response {
    fn validate(&self) -> Result<(), CodecError> {
        Response::validate(self)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RequestWire {
    Begin {
        version: u8,
        intent_digest: [u8; 32],
        client_nonce: [u8; 32],
    },
    Confirm {
        version: u8,
        intent_digest: [u8; 32],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        sequence: u8,
    },
}

impl From<RequestWire> for Request {
    fn from(wire: RequestWire) -> Self {
        match wire {
            RequestWire::Begin {
                version,
                intent_digest,
                client_nonce,
            } => Self::Begin {
                version,
                intent_digest,
                client_nonce,
            },
            RequestWire::Confirm {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                sequence,
            } => Self::Confirm {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                sequence,
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ResponseWire {
    Challenge {
        version: u8,
        intent_digest: [u8; 32],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        expires_after_ms: u32,
    },
    Accepted {
        version: u8,
        intent_digest: [u8; 32],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        sequence: u8,
    },
}

impl From<ResponseWire> for Response {
    fn from(wire: ResponseWire) -> Self {
        match wire {
            ResponseWire::Challenge {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                expires_after_ms,
            } => Self::Challenge {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                expires_after_ms,
            },
            ResponseWire::Accepted {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                sequence,
            } => Self::Accepted {
                version,
                intent_digest,
                client_nonce,
                server_nonce,
                sequence,
            },
        }
    }
}

fn validate_common(
    version: u8,
    intent_digest: &[u8; 32],
    client_nonce: &[u8; 32],
) -> Result<(), CodecError> {
    if version != VERSION {
        return Err(CodecError::Invalid);
    }
    validate_nonzero(intent_digest)?;
    validate_nonzero(client_nonce)
}

fn validate_nonzero(value: &[u8; 32]) -> Result<(), CodecError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(CodecError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> [u8; 32] {
        [1; 32]
    }

    fn client_nonce() -> [u8; 32] {
        [2; 32]
    }

    fn server_nonce() -> [u8; 32] {
        [3; 32]
    }

    fn begin() -> Request {
        Request::Begin {
            version: VERSION,
            intent_digest: digest(),
            client_nonce: client_nonce(),
        }
    }

    fn confirm() -> Request {
        Request::Confirm {
            version: VERSION,
            intent_digest: digest(),
            client_nonce: client_nonce(),
            server_nonce: server_nonce(),
            sequence: CONFIRM_SEQUENCE,
        }
    }

    fn challenge() -> Response {
        Response::Challenge {
            version: VERSION,
            intent_digest: digest(),
            client_nonce: client_nonce(),
            server_nonce: server_nonce(),
            expires_after_ms: MAX_CHALLENGE_EXPIRES_AFTER_MS,
        }
    }

    fn accepted() -> Response {
        Response::Accepted {
            version: VERSION,
            intent_digest: digest(),
            client_nonce: client_nonce(),
            server_nonce: server_nonce(),
            sequence: CONFIRM_SEQUENCE,
        }
    }

    #[test]
    fn begin_has_stable_golden_json() {
        let encoded = begin().encode().expect("valid begin encodes");
        assert_eq!(
            encoded,
            br#"{"type":"begin","version":1,"intent_digest":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"client_nonce":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]}"#
        );
    }

    #[test]
    fn every_message_round_trips() {
        for message in [begin(), confirm()] {
            let encoded = message.encode().expect("valid request encodes");
            assert_eq!(Request::decode(&encoded), Ok(message));
        }
        for message in [challenge(), accepted()] {
            let encoded = message.encode().expect("valid response encodes");
            assert_eq!(Response::decode(&encoded), Ok(message));
        }
    }

    #[test]
    fn input_bound_is_checked_before_json_parsing() {
        let oversized = vec![b' '; MAX_ENCODED_MESSAGE_BYTES + 1];
        assert_eq!(Request::decode(&oversized), Err(CodecError::TooLarge));
        assert_eq!(Response::decode(&oversized), Err(CodecError::TooLarge));
    }

    #[test]
    fn malformed_non_object_unknown_and_extra_forms_refuse() {
        for input in [
            &b"{"[..],
            br#"[]"#,
            br#""begin""#,
            br#"{"type":"unknown","version":1}"#,
            br#"{"type":"begin","version":1,"intent_digest":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"client_nonce":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"extra":true}"#,
        ] {
            assert_eq!(Request::decode(input), Err(CodecError::Malformed));
        }
    }

    #[test]
    fn positional_arrays_refuse_for_every_message_variant() {
        let digest = vec![1_u8; 32];
        let client_nonce = vec![2_u8; 32];
        let server_nonce = vec![3_u8; 32];
        let requests = [
            serde_json::json!(["begin", VERSION, digest, client_nonce]),
            serde_json::json!([
                "confirm",
                VERSION,
                digest,
                client_nonce,
                server_nonce,
                CONFIRM_SEQUENCE
            ]),
        ];
        for request in requests {
            let mut encoded = b" \t\r\n".to_vec();
            encoded.extend(serde_json::to_vec(&request).expect("fixture encodes"));
            assert_eq!(Request::decode(&encoded), Err(CodecError::Malformed));
        }

        let responses = [
            serde_json::json!([
                "challenge",
                VERSION,
                digest,
                client_nonce,
                server_nonce,
                MAX_CHALLENGE_EXPIRES_AFTER_MS
            ]),
            serde_json::json!([
                "accepted",
                VERSION,
                digest,
                client_nonce,
                server_nonce,
                CONFIRM_SEQUENCE
            ]),
        ];
        for response in responses {
            let mut encoded = b" \t\r\n".to_vec();
            encoded.extend(serde_json::to_vec(&response).expect("fixture encodes"));
            assert_eq!(Response::decode(&encoded), Err(CodecError::Malformed));
        }
    }

    #[test]
    fn wrong_version_and_zero_bindings_refuse() {
        let requests = [
            Request::Begin {
                version: VERSION + 1,
                intent_digest: digest(),
                client_nonce: client_nonce(),
            },
            Request::Begin {
                version: VERSION,
                intent_digest: [0; 32],
                client_nonce: client_nonce(),
            },
            Request::Begin {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: [0; 32],
            },
            Request::Confirm {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: [0; 32],
                sequence: CONFIRM_SEQUENCE,
            },
        ];
        for message in requests {
            assert_eq!(message.encode(), Err(CodecError::Invalid));
        }

        let responses = [
            Response::Challenge {
                version: VERSION + 1,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: server_nonce(),
                expires_after_ms: 1,
            },
            Response::Challenge {
                version: VERSION,
                intent_digest: [0; 32],
                client_nonce: client_nonce(),
                server_nonce: server_nonce(),
                expires_after_ms: 1,
            },
            Response::Challenge {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: [0; 32],
                server_nonce: server_nonce(),
                expires_after_ms: 1,
            },
            Response::Challenge {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: [0; 32],
                expires_after_ms: 1,
            },
        ];
        for message in responses {
            assert_eq!(message.encode(), Err(CodecError::Invalid));
        }
    }

    #[test]
    fn wrong_sequences_refuse() {
        for sequence in [0, 2, u8::MAX] {
            let request = Request::Confirm {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: server_nonce(),
                sequence,
            };
            assert_eq!(request.encode(), Err(CodecError::Invalid));

            let response = Response::Accepted {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: server_nonce(),
                sequence,
            };
            assert_eq!(response.encode(), Err(CodecError::Invalid));
        }
    }

    #[test]
    fn challenge_expiry_is_inclusive_and_bounded() {
        for expires_after_ms in [0, MAX_CHALLENGE_EXPIRES_AFTER_MS + 1] {
            let response = Response::Challenge {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: server_nonce(),
                expires_after_ms,
            };
            assert_eq!(response.encode(), Err(CodecError::Invalid));
        }

        for expires_after_ms in [1, MAX_CHALLENGE_EXPIRES_AFTER_MS] {
            let response = Response::Challenge {
                version: VERSION,
                intent_digest: digest(),
                client_nonce: client_nonce(),
                server_nonce: server_nonce(),
                expires_after_ms,
            };
            assert!(response.encode().is_ok(), "expiry {expires_after_ms}");
        }
    }

    #[test]
    fn worst_case_valid_messages_fit_the_output_bound() {
        let request = Request::Confirm {
            version: VERSION,
            intent_digest: [u8::MAX; 32],
            client_nonce: [u8::MAX; 32],
            server_nonce: [u8::MAX; 32],
            sequence: CONFIRM_SEQUENCE,
        };
        let response = Response::Challenge {
            version: VERSION,
            intent_digest: [u8::MAX; 32],
            client_nonce: [u8::MAX; 32],
            server_nonce: [u8::MAX; 32],
            expires_after_ms: MAX_CHALLENGE_EXPIRES_AFTER_MS,
        };
        assert!(request.encode().is_ok(), "largest request must fit");
        assert!(response.encode().is_ok(), "largest response must fit");
    }
}
