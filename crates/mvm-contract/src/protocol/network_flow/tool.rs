//! Bounded payloads for the authenticated, session-level tool decision.

use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Maximum UTF-8 bytes in a declared tool name.
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Maximum UTF-8 bytes in the command line checked before spawn.
pub const MAX_TOOL_ARGV_BYTES: usize = 16 * 1024;

/// One guest-reported invocation, sent before the command is spawned.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCheckRequest {
    /// Name in the admitted plan's tool rules.
    pub tool: String,
    /// Exact command line to compare with the admitted argv patterns.
    pub argv: String,
}

impl fmt::Debug for ToolCheckRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCheckRequest")
            .field("tool", &"[redacted]")
            .field("argv", &"[redacted]")
            .finish()
    }
}

impl ToolCheckRequest {
    /// Reject empty, oversized, or NUL-containing fields before policy lookup.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.tool.is_empty()
            && self.tool.len() <= MAX_TOOL_NAME_BYTES
            && !self.tool.contains('\0')
            && !self.argv.is_empty()
            && self.argv.len() <= MAX_TOOL_ARGV_BYTES
            && !self.argv.contains('\0')
    }
}

/// Fixed denial reason returned to the guest. It never contains command text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCheckDenial {
    /// Safe reason from the rule evaluator or endpoint failure path.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_and_rejects_unknown_fields() {
        let request = ToolCheckRequest {
            tool: "shell".into(),
            argv: "echo ok".into(),
        };
        let json = serde_json::to_vec(&request).expect("serialize");
        assert_eq!(
            serde_json::from_slice::<ToolCheckRequest>(&json).expect("parse"),
            request
        );
        assert!(
            serde_json::from_str::<ToolCheckRequest>(
                r#"{"tool":"shell","argv":"echo ok","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn request_validation_covers_empty_oversized_and_nul_fields() {
        let mut request = ToolCheckRequest {
            tool: "shell".into(),
            argv: "echo ok".into(),
        };
        assert!(request.is_valid());
        request.tool.clear();
        assert!(!request.is_valid());
        request.tool = "x".repeat(MAX_TOOL_NAME_BYTES + 1);
        assert!(!request.is_valid());
        request.tool = "shell".into();
        request.argv.clear();
        assert!(!request.is_valid());
        request.argv = "x".repeat(MAX_TOOL_ARGV_BYTES + 1);
        assert!(!request.is_valid());
        request.argv = "x\0y".into();
        assert!(!request.is_valid());
    }

    #[test]
    fn debug_never_prints_the_tool_or_command() {
        let request = ToolCheckRequest {
            tool: "private-tool".into(),
            argv: "secret-on-command-line".into(),
        };
        let debug = alloc::format!("{request:?}");
        assert!(!debug.contains("private-tool"));
        assert!(!debug.contains("secret-on-command-line"));
    }
}
