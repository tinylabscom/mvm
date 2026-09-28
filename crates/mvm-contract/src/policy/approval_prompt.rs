//! The question a paused flow asks, and the answer it waits for.
//!
//! When a runtime decision is `ask` — an egress route rule, a secret bound
//! with `approve = "ask"`, a tool rule — the host endpoint holds the flow and
//! puts one [`ApprovalPrompt`] to the approval broker the operator's `mvmctl`
//! runs. The broker answers with one [`ApprovalAnswer`]. Both are single JSON
//! lines over a host-local socket; both refuse unknown fields and are bounded.
//!
//! The request's lifecycle — requested, approved, denied, expired — is
//! recorded in the endpoint's [`crate::policy::approval::ApprovalLedger`].
//! This module is only the transport shape between the two processes.
//!
//! Some prompt fields are guest-derived (a request path, a method). A backend
//! that shows them to a person must pass them through [`display_safe`], which
//! removes every control, escape and bidirectional-override sequence a
//! workload could use to redraw or disguise the prompt.

use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::policy::approval::{ApprovalOutcome, ApprovalRequestId};

/// Longest encoded prompt line accepted.
pub const MAX_PROMPT_LINE_BYTES: usize = 16 * 1024;
/// Longest encoded answer line accepted.
pub const MAX_ANSWER_LINE_BYTES: usize = 1024;
/// Longest guest-derived string a prompt carries; longer is truncated by the
/// endpoint before it is sent.
pub const MAX_SUBJECT_FIELD_CHARS: usize = 512;

/// What is being asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ApprovalSubject {
    /// An HTTP request an egress route rule answered with `ask`.
    Egress {
        /// The route that asked.
        route_id: String,
        /// The rule within it (`rule-N`, its id, or `otherwise`).
        rule: String,
        /// `host:port`.
        destination: String,
        /// The request method (guest-derived).
        method: String,
        /// The request path, without query (guest-derived).
        path: String,
    },
    /// The first use of a secret bound with `approve = "ask"`.
    SecretUse {
        /// The secret's name.
        secret: String,
        /// Where the request carrying it is going.
        destination: String,
    },
    /// A tool call a tool rule answered with `ask`.
    ToolCall {
        /// The tool's name (guest-derived).
        tool: String,
    },
}

impl ApprovalSubject {
    /// Stable audit label for the kind of question.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Egress { .. } => "egress",
            Self::SecretUse { .. } => "secret_use",
            Self::ToolCall { .. } => "tool_call",
        }
    }
}

/// How far an approval reaches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ApprovalScope {
    /// This request only.
    #[default]
    Once,
    /// This question, for the rest of the VM's session or until the
    /// endpoint's session TTL, whichever is first. Never written to a
    /// profile or manifest.
    Session,
}

impl ApprovalScope {
    /// Stable audit label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
        }
    }
}

/// One question from the endpoint to the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApprovalPrompt {
    /// The ledger's id for this request; the answer must echo it.
    pub request_id: ApprovalRequestId,
    /// What is being asked.
    pub subject: ApprovalSubject,
    /// How long the endpoint will wait before denying, in milliseconds.
    pub expires_in_ms: u64,
}

/// The broker's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ApprovalAnswer {
    /// Echo of [`ApprovalPrompt::request_id`].
    pub request_id: ApprovalRequestId,
    /// Approved or denied.
    pub outcome: ApprovalOutcome,
    /// How far an approval reaches. Ignored for a denial.
    #[serde(default)]
    pub scope: ApprovalScope,
    /// A fixed label for why, recorded on the chain: which backend answered,
    /// or why it could not (`no_tty`, `timed_out`, `webhook_refused`, …).
    /// Lower-case `[a-z0-9_]`, at most 64 bytes; anything else is replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ApprovalAnswer {
    /// A denial for `request_id` with a fixed reason.
    #[must_use]
    pub fn denied(request_id: ApprovalRequestId, reason: &str) -> Self {
        Self {
            request_id,
            outcome: ApprovalOutcome::Denied,
            scope: ApprovalScope::Once,
            reason: Some(String::from(reason)),
        }
    }

    /// An approval for `request_id`.
    #[must_use]
    pub fn approved(request_id: ApprovalRequestId, scope: ApprovalScope, reason: &str) -> Self {
        Self {
            request_id,
            outcome: ApprovalOutcome::Approved,
            scope,
            reason: Some(String::from(reason)),
        }
    }

    /// The reason as an audit label: kept if it is a short `[a-z0-9_]` word,
    /// `unlabelled` otherwise, so a broker cannot put arbitrary text on the
    /// chain.
    #[must_use]
    pub fn reason_label(&self) -> &str {
        match self.reason.as_deref() {
            Some(reason)
                if !reason.is_empty()
                    && reason.len() <= 64
                    && reason
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') =>
            {
                reason
            }
            _ => "unlabelled",
        }
    }
}

/// `text` made safe to show on a terminal: escape sequences (CSI, OSC, DCS,
/// and every other `ESC`-introduced sequence, 7- and 8-bit) removed, other
/// control characters and bidirectional or zero-width formatting characters
/// replaced by `?`, and the result cut to `max_chars` characters with a
/// trailing `…`.
#[must_use]
pub fn display_safe(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_chars * 4));
    let mut chars = text.chars().peekable();
    let mut shown = 0usize;
    while let Some(c) = chars.next() {
        let replacement = match c {
            // 7-bit escape: consume the whole sequence.
            '\u{1b}' => {
                skip_escape(&mut chars);
                None
            }
            // 8-bit CSI / OSC / DCS / SOS / PM / APC introducers.
            '\u{9b}' => {
                skip_csi_body(&mut chars);
                None
            }
            '\u{9d}' | '\u{90}' | '\u{98}' | '\u{9e}' | '\u{9f}' => {
                skip_string_body(&mut chars);
                None
            }
            c if c.is_control() || is_format_hazard(c) => Some('?'),
            c => Some(c),
        };
        if let Some(c) = replacement {
            if shown == max_chars {
                out.push('…');
                break;
            }
            out.push(c);
            shown += 1;
        }
    }
    out
}

/// Bidirectional overrides and isolates, and zero-width characters: all can
/// make displayed text read differently from what it is.
fn is_format_hazard(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'
    )
}

fn skip_escape<I: Iterator<Item = char>>(chars: &mut core::iter::Peekable<I>) {
    match chars.next() {
        Some('[') => skip_csi_body(chars),
        Some(']' | 'P' | 'X' | '^' | '_') => skip_string_body(chars),
        // Two-character escape (`ESC c`, `ESC 7`, charset selection…). A
        // charset designation (`ESC ( B`) carries one more byte.
        Some('(' | ')' | '*' | '+' | '-' | '.' | '/' | '#' | '%') => {
            chars.next();
        }
        _ => {}
    }
}

/// CSI parameters and intermediates end at a final byte `@`..`~`.
fn skip_csi_body<I: Iterator<Item = char>>(chars: &mut I) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            break;
        }
    }
}

/// OSC / DCS / APC / PM / SOS strings end at BEL, ST (`ESC \`) or 8-bit ST.
fn skip_string_body<I: Iterator<Item = char>>(chars: &mut core::iter::Peekable<I>) {
    while let Some(c) = chars.next() {
        match c {
            '\u{07}' | '\u{9c}' => break,
            '\u{1b}' => {
                if chars.peek() == Some(&'\\') {
                    chars.next();
                }
                break;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sequences_are_removed_and_controls_replaced() {
        let cases = [
            ("/v1/\u{1b}[2J\u{1b}[Hmodels", "/v1/models"),
            ("GET\u{1b}]0;pwned title\u{07}", "GET"),
            (
                "a\u{1b}]8;;http://evil\u{1b}\\link\u{1b}]8;;\u{1b}\\b",
                "alinkb",
            ),
            ("x\u{9b}31my", "xy"),
            ("x\u{9d}2;title\u{9c}y", "xy"),
            ("line\r\nApprove? [y/N] y", "line??Approve? [y/N] y"),
            ("bell\u{07}back\u{08}", "bell?back?"),
            ("\u{202e}gnp.exe", "?gnp.exe"),
            ("zero\u{200b}width", "zero?width"),
            ("\u{1b}(Bplain", "plain"),
            ("\u{1b}Pq#0;2;0;0;0\u{1b}\\after", "after"),
        ];
        for (input, expected) in cases {
            assert_eq!(display_safe(input, 100), expected, "{input:?}");
        }
    }

    #[test]
    fn a_long_field_is_truncated_with_an_ellipsis() {
        let long = "a".repeat(600);
        let shown = display_safe(&long, MAX_SUBJECT_FIELD_CHARS);
        assert_eq!(shown.chars().count(), MAX_SUBJECT_FIELD_CHARS + 1);
        assert!(shown.ends_with('…'));
        assert_eq!(display_safe("short", 10), "short");
    }

    #[test]
    fn a_prompt_and_answer_round_trip_and_refuse_unknown_fields() {
        let prompt = ApprovalPrompt {
            request_id: ApprovalRequestId::parse("appr-1").unwrap(),
            subject: ApprovalSubject::Egress {
                route_id: "github".into(),
                rule: "rule-1".into(),
                destination: "api.github.com:443".into(),
                method: "POST".into(),
                path: "/repos/o/r/issues".into(),
            },
            expires_in_ms: 60_000,
        };
        let line = serde_json::to_string(&prompt).unwrap();
        assert_eq!(
            serde_json::from_str::<ApprovalPrompt>(&line).unwrap(),
            prompt
        );
        let extra = line.replacen("\"expires_in_ms\"", "\"extra\":1,\"expires_in_ms\"", 1);
        assert!(serde_json::from_str::<ApprovalPrompt>(&extra).is_err());

        let answer =
            ApprovalAnswer::approved(prompt.request_id.clone(), ApprovalScope::Session, "tty");
        let line = serde_json::to_string(&answer).unwrap();
        assert_eq!(
            serde_json::from_str::<ApprovalAnswer>(&line).unwrap(),
            answer
        );
        let minimal = r#"{"request_id":"appr-1","outcome":"denied"}"#;
        let parsed: ApprovalAnswer = serde_json::from_str(minimal).unwrap();
        assert_eq!(parsed.scope, ApprovalScope::Once);
        assert_eq!(parsed.reason_label(), "unlabelled");
    }

    #[test]
    fn a_reason_that_is_not_a_label_is_not_recorded_as_one() {
        let id = ApprovalRequestId::parse("appr-1").unwrap();
        assert_eq!(
            ApprovalAnswer::denied(id.clone(), "no_tty").reason_label(),
            "no_tty"
        );
        assert_eq!(
            ApprovalAnswer::denied(id.clone(), "Denied by Bob\n").reason_label(),
            "unlabelled"
        );
        assert_eq!(
            ApprovalAnswer::denied(id, &"x".repeat(65)).reason_label(),
            "unlabelled"
        );
    }
}
