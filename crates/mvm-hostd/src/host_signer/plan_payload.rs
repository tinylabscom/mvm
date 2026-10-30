//! Pure payload checks at the existing plan-signing choke point.
//!
//! This does not authorize a principal, resolve policy, open an archive or admit
//! a workload. Keep serde's default recursion limit and sign only original bytes.

use std::io::{self, Write};

use mvm_core::plan::{ExecutionPlan, SCHEMA_VERSION, content_id::verify_plan_id};

pub(super) fn is_supported_canonical_plan(bytes: &[u8]) -> bool {
    // A decoded byte vector cannot be larger than its containing default frame.
    // Enforce that conservative bound even for direct in-process dispatch calls.
    if bytes.is_empty() || bytes.len() > super::DEFAULT_MAX_FRAME_BYTES {
        return false;
    }
    let Ok(plan) = serde_json::from_slice::<ExecutionPlan>(bytes) else {
        return false;
    };
    if plan.schema_version > SCHEMA_VERSION {
        return false;
    }
    let mut comparison = MatchOriginal { bytes, cursor: 0 };
    // Compare the actual sign_plan serde format before content_id builds a Value.
    // Never substitute content_id's sorted/excluded-field encoding for this one.
    if serde_json::to_writer(&mut comparison, &plan).is_err() || comparison.cursor != bytes.len() {
        return false;
    }
    verify_plan_id(&plan).is_ok()
}

struct MatchOriginal<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl Write for MatchOriginal<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or_else(noncanonical)?;
        if self.bytes.get(self.cursor..end) != Some(bytes) {
            return Err(noncanonical());
        }
        self.cursor = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn noncanonical() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "noncanonical execution plan")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_never_normalizes_or_writes_past_original_bytes() {
        let mut comparison = MatchOriginal {
            bytes: b"abc",
            cursor: 0,
        };
        comparison.write_all(b"ab").unwrap();
        assert!(comparison.write_all(b"x").is_err());
        assert_eq!(comparison.cursor, 2);
        assert!(comparison.write_all(b"cd").is_err());
        comparison.write_all(b"c").unwrap();
        assert_eq!(comparison.cursor, 3);
        assert!(comparison.write_all(b"d").is_err());
    }

    #[test]
    fn comparison_checks_cursor_overflow_before_slicing() {
        let mut comparison = MatchOriginal {
            bytes: b"",
            cursor: usize::MAX,
        };
        assert!(comparison.write_all(b"x").is_err());
    }
}
