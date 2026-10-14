//! Version-one requests. Authority is never supplied by JSON.

use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_FRAME: usize = 16 * 1024;

/// An unguessable lookup key, not a transferable authorization capability.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RegistrationId(String);

impl RegistrationId {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RegistrationId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("invalid registration ID"));
        }
        Ok(Self(value))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Register {
        pid: i32,
        owner_uid: u32,
        state_dir: String,
        api_socket: String,
    },
    Stop {
        id: RegistrationId,
    },
    Query {
        id: RegistrationId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    StopRequested,
    Exited,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Registered { id: RegistrationId },
    Status { status: Status },
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_reject_traversal_case_length_nonhex_and_unicode() {
        for value in [
            "../".repeat(22),
            "A".repeat(64),
            "0".repeat(63),
            "0".repeat(65),
            "g".repeat(64),
            "é".repeat(32),
            "/".repeat(64),
            "\0".repeat(64),
        ] {
            assert!(
                serde_json::from_value::<RegistrationId>(serde_json::Value::String(value)).is_err()
            );
        }
        serde_json::from_value::<RegistrationId>(serde_json::Value::String("a".repeat(64)))
            .unwrap();
    }
}
