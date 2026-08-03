//! Verified, normalized local audit events for UI consumers.
//!
//! Extracts chain reading and verification behind a reusable service that
//! returns normalized events only after signature and chain integrity
//! checks pass; unverifiable sources yield typed refusals, never events.
