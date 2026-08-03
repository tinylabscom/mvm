//! Verified, normalized local audit events for UI consumers.
//!
//! Issue #2082 extracts chain reading and verification behind a reusable
//! service returning `VerifiedAuditEvent`s only after signature and chain
//! integrity checks pass; unverifiable sources yield typed refusals, never
//! events.
