//! `host.kv.v1` payload types — a per-workload key-value store.
//!
//! The store lives on the host. A workload reaches it over the broker channel,
//! which means it needs no network path to get durable storage, and the host
//! keeps the only handle to the bytes.
//!
//! The workload identity is *not* a payload field. It comes from the
//! supervisor's `ServiceCallCtx`, so a workload cannot name another workload's
//! namespace by asking for it — the same reason the time service takes no
//! caller field.
//!
//! Every type here is `deny_unknown_fields`: an unexpected field fails closed
//! rather than being ignored, so a client built against a newer contract is
//! refused instead of silently having half its request honoured.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Longest key accepted, in bytes.
///
/// Bounded so a key cannot be used as a side channel for bulk data, and so the
/// on-disk name derived from it stays a fixed-width digest rather than
/// something a caller controls the length of.
pub const MAX_KEY_LEN: usize = 256;

/// Largest value accepted, in bytes.
///
/// The broker is a control channel, not a bulk transport: a payload crosses
/// two JSON hops before it lands, so a large value costs far more than its
/// size. Callers with bulk data want a volume, not this.
pub const MAX_VALUE_LEN: usize = 64 * 1024;

/// Request for `host.kv.v1::get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvGetRequest {
    /// The key to read.
    pub key: String,
}

/// Response for `host.kv.v1::get`. A missing key is a successful read with
/// `value: None`, not an error — absence is an ordinary outcome here, and
/// making it an error would push callers into treating every failure alike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvGetResponse {
    /// The stored bytes, or `None` when the key is absent.
    pub value: Option<Vec<u8>>,
}

/// Request for `host.kv.v1::put`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvPutRequest {
    /// The key to write.
    pub key: String,
    /// The bytes to store, at most [`MAX_VALUE_LEN`].
    pub value: Vec<u8>,
}

/// Response for `host.kv.v1::put`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvPutResponse {
    /// Whether the key already held a value that this call replaced.
    pub replaced: bool,
}

/// Request for `host.kv.v1::delete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvDeleteRequest {
    /// The key to remove.
    pub key: String,
}

/// Response for `host.kv.v1::delete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvDeleteResponse {
    /// Whether a value was present and has now been removed.
    pub removed: bool,
}

/// Request for `host.kv.v1::list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvListRequest {
    /// Only keys starting with this prefix are returned. An empty prefix
    /// lists the workload's whole namespace.
    #[serde(default)]
    pub prefix: String,
}

/// Response for `host.kv.v1::list`. Keys are returned in sorted order so a
/// caller comparing two listings sees a stable sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct KvListResponse {
    /// Matching keys, sorted.
    pub keys: Vec<String>,
}

/// Why a key is not acceptable.
///
/// Keys are validated rather than sanitized. A key that would need rewriting
/// to be safe is refused, because a caller that reads back a different key
/// than it wrote has no way to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyInvalid {
    /// The key is the empty string.
    Empty,
    /// Longer than [`MAX_KEY_LEN`].
    TooLong,
    /// Contains a byte outside printable ASCII, or a path separator.
    IllegalCharacter,
}

impl core::fmt::Display for KeyInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Empty => "key must not be empty",
            Self::TooLong => "key is longer than 256 bytes",
            Self::IllegalCharacter => {
                "key allows only printable ASCII, excluding `/`, `\\`, and `.`"
            }
        };
        f.write_str(msg)
    }
}

impl core::error::Error for KeyInvalid {}

/// Validate a key.
///
/// Path separators and `.` are excluded outright so that no key can express a
/// traversal. The store still hashes the key to derive a filename, so this is
/// the second of two independent reasons a key cannot escape its namespace,
/// not the only one.
pub fn validate_key(key: &str) -> Result<(), KeyInvalid> {
    if key.is_empty() {
        return Err(KeyInvalid::Empty);
    }
    if key.len() > MAX_KEY_LEN {
        return Err(KeyInvalid::TooLong);
    }
    let legal = key
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'/' && b != b'\\' && b != b'.');
    if !legal {
        return Err(KeyInvalid::IllegalCharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    #[test]
    fn get_response_roundtrips_present_and_absent() {
        for value in [Some(vec![1u8, 2, 3]), None] {
            let resp = KvGetResponse {
                value: value.clone(),
            };
            let bytes = serde_json::to_vec(&resp).unwrap();
            let parsed: KvGetResponse = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed, resp);
        }
    }

    #[test]
    fn put_request_roundtrips() {
        let req = KvPutRequest {
            key: "session".to_string(),
            value: vec![7, 7, 7],
        };
        let parsed: KvPutRequest =
            serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn list_prefix_defaults_to_the_whole_namespace() {
        let parsed: KvListRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(parsed.prefix, "");
    }

    /// An unexpected field is the shape a client built against a different
    /// contract sends. It fails closed rather than being half-honoured.
    #[test]
    fn every_request_rejects_unknown_fields() {
        let err = serde_json::from_value::<KvGetRequest>(
            serde_json::json!({"key": "k", "workload": "other"}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));

        let err = serde_json::from_value::<KvPutRequest>(
            serde_json::json!({"key": "k", "value": [], "ttl": 5}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));

        let err = serde_json::from_value::<KvListRequest>(
            serde_json::json!({"prefix": "a", "limit": 10}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn keys_are_validated_not_sanitized() {
        assert!(validate_key("session-token").is_ok());
        assert_eq!(validate_key(""), Err(KeyInvalid::Empty));
        assert_eq!(
            validate_key(&"k".repeat(MAX_KEY_LEN + 1)),
            Err(KeyInvalid::TooLong)
        );
    }

    /// No key may express a traversal, independently of how the store maps a
    /// key onto a filename.
    #[test]
    fn keys_cannot_express_a_traversal() {
        for bad in ["../escape", "a/b", "a\\b", ".", "..", "a.b"] {
            assert_eq!(
                validate_key(bad),
                Err(KeyInvalid::IllegalCharacter),
                "expected `{bad}` to be refused"
            );
        }
    }

    #[test]
    fn keys_reject_control_bytes_and_whitespace() {
        for bad in ["a b", "a\tb", "a\nb", "a\0b"] {
            assert_eq!(validate_key(bad), Err(KeyInvalid::IllegalCharacter));
        }
    }

    #[test]
    fn invalid_reasons_render() {
        assert!(!KeyInvalid::Empty.to_string().is_empty());
    }
}
