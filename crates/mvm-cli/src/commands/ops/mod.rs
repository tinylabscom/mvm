//! Operational commands — config, networks, audit, metrics, cache.
//! (Plan 40 folded `mvmctl security` into `mvmctl doctor`.)

pub(super) mod audit;
pub(super) mod cache;
pub(super) mod config;
pub(super) mod mcp;
pub(super) mod metrics;
pub(super) mod network;

pub(super) use super::{Cli, shared};
