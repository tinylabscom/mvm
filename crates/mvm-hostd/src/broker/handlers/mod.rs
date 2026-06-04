//! Concrete `ServiceHandler` implementations hosted by `mvm-broker`.
//!
//! Each submodule is one handler; the binary's `main` wires them into
//! the [`crate::broker::registry::Registry`] at startup.

pub mod host_audit_v1;
