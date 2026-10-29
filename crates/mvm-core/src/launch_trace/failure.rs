//! Payload-free, opt-in observations on the existing stderr channel.
//! These records are unauthenticated and never authorize an operation.

use serde::{Deserialize, Serialize};
use std::io::{self, Write};

pub const ENABLE_ENV: &str = "MVM_FAILURE_DIAGNOSTICS";
pub const PREFIX: &[u8] = b"MVM_FAILURE_V1 ";
pub const MAX_RECORD_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    TransientBoot,
    TransientCommand,
    BuilderJob,
    HvfReadiness,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Unknown,
    Internal,
    InvalidRequest,
    Unsupported,
    Version,
    Fetch,
    NixBuild,
    NixEval,
    Timeout,
    OutputContract,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Absent,
    Unknown,
    SignCheck,
    SigningLock,
    Signing,
    Reexec,
    ConfigRead,
    ConfigParse,
    StatusPublish,
    StartupInputs,
    CapturePolicy,
    CaptureSetup,
    PidPublish,
    PidPublished,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub phase: Phase,
    pub category: Category,
    pub stage: Stage,
    #[serde(deserialize_with = "Option::<i32>::deserialize")]
    pub exit_code: Option<i32>,
}

impl Record {
    pub const fn new(phase: Phase) -> Self {
        Self {
            phase,
            category: Category::Unknown,
            stage: Stage::Absent,
            exit_code: None,
        }
    }

    /// Best-effort write to the existing stderr seam. No logger callback,
    /// retries, background worker, or changes to the original failure.
    pub fn emit(self) {
        if std::env::var_os(ENABLE_ENV).as_deref() == Some(std::ffi::OsStr::new("1")) {
            let _ = write_record(&mut io::stderr().lock(), self);
        }
    }
}

pub fn decode(bytes: &[u8]) -> Option<Record> {
    if bytes.len() > MAX_RECORD_BYTES {
        return None;
    }
    serde_json::from_slice(bytes).ok()
}

fn write_record(writer: &mut impl Write, record: Record) -> io::Result<()> {
    let mut bytes = PREFIX.to_vec();
    serde_json::to_writer(&mut bytes, &record).map_err(io::Error::other)?;
    if bytes.len() > PREFIX.len() + MAX_RECORD_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    bytes.push(b'\n');
    match writer.write(&bytes) {
        Ok(written) if written == bytes.len() => Ok(()),
        Ok(_) => Err(io::ErrorKind::WriteZero.into()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_closed_schema() {
        let good =
            br#"{"phase":"transient_boot","category":"unknown","stage":"absent","exit_code":null}"#;
        assert!(decode(good).is_some());
        for bad in [
            br#"{"phase":"secret","category":"unknown","stage":"absent","exit_code":null}"#.as_slice(),
            br#"{"phase":"transient_boot","category":"unknown","stage":"absent","exit_code":null,"detail":"SENTINEL_SECRET"}"#,
            br#"{"phase":"transient_boot","category":"unknown","stage":"absent","exit_code":"SENTINEL_SECRET"}"#,
            br#"{"phase":"transient_boot","category":"unknown","stage":"absent"}"#,
            br#"{"phase":"transient_boot","category":"unknown","stage":"absent","exit_code":2147483648}"#,
            br#"{"phase":"transient_boot","phase":"transient_boot","category":"unknown","stage":"absent","exit_code":null}"#,
            b"malformed",
        ] {
            assert!(decode(bad).is_none());
        }
        assert!(decode(&vec![b' '; MAX_RECORD_BYTES + 1]).is_none());
    }

    #[test]
    fn serialization_contains_only_typed_observations() {
        let record = Record::new(Phase::TransientBoot);
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(bytes.len() <= MAX_RECORD_BYTES);
        assert_eq!(decode(&bytes), Some(record));
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("SENTINEL_SECRET")
        );
    }

    #[test]
    fn failed_writer_is_observational() {
        struct Refuse;
        impl std::io::Write for Refuse {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(write_record(&mut Refuse, Record::new(Phase::TransientBoot)).is_err());
    }

    #[test]
    fn a_short_write_is_not_retried() {
        struct Short(usize);
        impl Write for Short {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Short(0);
        assert!(write_record(&mut writer, Record::new(Phase::TransientBoot)).is_err());
        assert_eq!(writer.0, 1);
    }
}
