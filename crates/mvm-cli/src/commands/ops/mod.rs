//! Operational commands — config, networks, audit, metrics, cache.
//! (Plan 40 folded `mvmctl security` into `mvmctl doctor`.)

pub(super) mod attest;
pub(super) mod audit;
pub(super) mod audit_posture;
pub(super) mod bench;
pub(super) mod bench_probe;
pub(super) mod cache;
pub(super) mod config;
pub(super) mod mcp;
pub(super) mod metrics;
pub(super) mod network;
pub(super) mod secret;

pub(super) use super::{Cli, shared};
