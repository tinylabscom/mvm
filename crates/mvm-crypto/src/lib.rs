//! Shared cryptographic primitives, optimized independently of protocol owners.
//!
//! Algorithms live in modules within this crate; protocol state and key custody
//! remain with their callers.

#![forbid(unsafe_code)]

pub mod aead;
