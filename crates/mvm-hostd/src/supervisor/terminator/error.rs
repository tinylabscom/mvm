//! The terminator core's typed error.
//!
//! The two cleartext-visible substitution cores (`:80` `handle_request`, the
//! TLS-terminated `:443` `terminate_and_substitute`) separate the distinct
//! failure causes so the caller can react per-cause: a claim-12 *refusal* of a
//! placeholder-bearing request is audited as a placeholder drop; a *fail-closed*
//! refusal of an unscannable body is audited as such; a parse or forward failure
//! is just a closed socket. Collapsing these into one `anyhow::Error` (the prior
//! shape) made every cause indistinguishable at the call site, so the redaction
//! audit couldn't be emitted. **Every variant means the socket closes without
//! forwarding un-substituted / un-redacted bytes** — the fail-closed invariant.
#[derive(Debug, thiserror::Error)]
pub enum TerminatorError {
    #[error("request parse failed: {0}")]
    Parse(String),
    /// claim-12: substitution refused (unbound destination / unknown
    /// placeholder), BEFORE forwarding.
    #[error("substitution refused: {0}")]
    Refused(String),
    /// fail-closed: a body we cannot scan in cleartext (compressed / over the
    /// scan cap) when the destination opted into redaction.
    #[error("fail-closed: {0}")]
    FailClosed(&'static str),
    #[error("forward failed: {0}")]
    Forward(String),
}
