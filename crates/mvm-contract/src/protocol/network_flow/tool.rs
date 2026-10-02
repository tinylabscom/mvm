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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Build the policy-visible command line from the exact argv vector that
    /// the guest will execute. Shell metacharacters are quoted for display;
    /// the guest still spawns argv directly, without a shell.
    #[must_use]
    pub fn from_argv(tool: String, argv: &[String]) -> Option<Self> {
        let first = argv.first()?;
        if first.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
            return None;
        }
        let raw_len = argv.iter().try_fold(0usize, |len, arg| {
            len.checked_add(arg.len())?.checked_add(1)
        })?;
        if raw_len > MAX_TOOL_ARGV_BYTES {
            return None;
        }
        let mut command_line = String::new();
        for (index, arg) in argv.iter().enumerate() {
            if index > 0 {
                command_line.push(' ');
            }
            if !arg.is_empty()
                && arg
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._/-+=:@".contains(&byte))
            {
                command_line.push_str(arg);
            } else {
                command_line.push('\'');
                for character in arg.chars() {
                    if character == '\'' {
                        command_line.push_str("'\\''");
                    } else {
                        command_line.push(character);
                    }
                }
                command_line.push('\'');
            }
        }
        let request = Self {
            tool,
            argv: command_line,
        };
        request.is_valid().then_some(request)
    }

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

/// Host-local reply after the per-VM endpoint has audited a tool decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDecisionReply {
    /// The admitted rules and audit write allowed the invocation.
    Allow,
    /// The invocation was denied or its decision could not be audited.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_local_reply_roundtrips_and_rejects_unknown_values() {
        for reply in [ToolDecisionReply::Allow, ToolDecisionReply::Deny] {
            let json = serde_json::to_string(&reply).expect("serialize decision");
            assert_eq!(
                serde_json::from_str::<ToolDecisionReply>(&json).expect("parse decision"),
                reply
            );
        }
        assert!(serde_json::from_str::<ToolDecisionReply>("\"maybe\"").is_err());
    }

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

    #[test]
    fn argv_rendering_preserves_arguments_without_shell_interpretation() {
        let request = ToolCheckRequest::from_argv(
            "git".into(),
            &["git".into(), "status; rm -rf /".into(), "a'b".into()],
        )
        .expect("valid argv");
        assert_eq!(request.argv, "git 'status; rm -rf /' 'a'\\''b'");
        assert!(ToolCheckRequest::from_argv("git".into(), &[]).is_none());
        assert!(ToolCheckRequest::from_argv("git".into(), &["".into()]).is_none());
        assert!(
            ToolCheckRequest::from_argv("git".into(), &["git".into(), "x\0y".into()]).is_none()
        );
    }
}
