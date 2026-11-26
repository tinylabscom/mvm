//! Effect-free authentication primitives for a one-use commissioning bootstrap.
//!
//! This crate owns dynamic macOS peer verification and the in-memory session
//! that turns one verified exchange into one unforgeable permit. It opens no
//! endpoint and performs no durable, key, journal, VM, or factory effect.

#![deny(unreachable_pub)]

/// One-use, peer-bound commissioning-bootstrap session and permit.
pub mod commissioning_bootstrap_session;
/// Audit-token-bound dynamic code identity verification for macOS peers.
pub mod macos_peer;
