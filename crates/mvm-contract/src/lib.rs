// schemars 0.8's `derive(JsonSchema)` unconditionally emits code rooted
// at `std::…` (it has no no_std mode), so a crate that derives it can't
// itself be `#![no_std]`. The `schema` feature exists only for
// `mvm-sdk`'s host-side `emit_schema`/`emit_addon_schema` codegen bins —
// never for the wasm32 target — so this drops `no_std` in that one
// build configuration and keeps it everywhere else, including the
// default build the wasm-clean gate exercises.
//
// `not(test)` keeps the crate `std` under `cargo test`: libtest itself
// needs `std` to link, so a `no_std` lib can't host the harness. The
// wasm32-unknown-unknown *library* build (the wasm-clean gate) is never
// built `--test`, so it stays `no_std` regardless of this clause.
#![cfg_attr(
    all(not(feature = "schema"), not(feature = "volume"), not(test)),
    no_std
)]
#![forbid(unsafe_code)]
//! Shared mvm contracts. The default `protocol` feature is a no_std + alloc
//! surface for the Workload IR, wire protocol, and policy DTOs. The optional
//! `volume` and `local` features add the storage backend contract and the
//! host-directory implementation without changing the protocol-only closure.

extern crate alloc;

/// Admission-bound AI assurance sessions: the input envelope an AI
/// workload receives after admission, the authority it runs under, and
/// the host-derived outcome of a trial.
#[cfg(feature = "protocol")]
pub mod assurance;
/// The one error a generated builder returns: a required field was
/// never set. Shared so every input struct reports it identically.
pub mod builder;
#[cfg(feature = "protocol")]
pub mod entrypoint;
/// A workload's permission set — CPU, wall clock, egress destinations.
#[cfg(feature = "protocol")]
pub mod grants;
/// Which C library a guest rootfs is built against. Shared vocabulary between
/// the crate that detects it and the crate that keys the SDK sidecar cache on
/// it; those are siblings, so it sits underneath both.
pub mod guest_libc;
#[cfg(feature = "protocol")]
pub mod ir;
/// Guest lifecycle markers + snapshot timing (the `mvm-init` ↔ host contract).
#[cfg(feature = "protocol")]
pub mod lifecycle;
/// RFC 6962 Merkle transparency-log inclusion proofs over the audit log.
#[cfg(feature = "protocol")]
pub mod merkle;
/// OCI distribution types with no host dependency (manifest parsing).
pub mod oci;
/// Names one workload uses to address another over the existing
/// host-mediated egress path.
#[cfg(feature = "protocol")]
pub mod peer;
#[cfg(feature = "protocol")]
pub mod plan;
#[cfg(feature = "protocol")]
pub mod policy;
#[cfg(feature = "protocol")]
pub mod protocol;
#[cfg(feature = "protocol")]
pub mod provenance;
#[cfg(feature = "protocol")]
pub mod service_catalog;
pub mod stream;
/// The guest-side placeholder token a secret-bearing request carries: its
/// reserved namespace, its opaque newtype, and the header scan. Minting and
/// custody stay host-side.
#[cfg(feature = "protocol")]
pub mod substitution;
#[cfg(feature = "protocol")]
pub mod verify;

#[cfg(feature = "volume")]
pub mod volume;
pub mod workload_identity;
#[cfg(feature = "local")]
pub use volume::LocalBackend;
#[cfg(feature = "volume")]
pub use volume::contract;
#[cfg(feature = "volume")]
pub use volume::{VolumeBackend, VolumeEntry, VolumeError, VolumeFuture, VolumePath};
