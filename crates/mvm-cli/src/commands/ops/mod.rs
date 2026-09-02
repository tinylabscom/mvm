//! Operational commands — config, networks, audit, metrics, MCP, cache.
//! (`mvmctl security` is folded into `mvmctl doctor`.)

pub(super) mod attest;
pub(super) mod audit;
pub(super) mod audit_posture;
pub(super) mod cache;
pub(super) mod config;
pub(super) mod group;
pub(super) mod mcp;
pub(super) mod metrics;
pub(super) mod network;
pub(super) mod reconcile;
pub(super) mod secret;
pub(super) mod transcript;

pub(super) use super::{Cli, shared};
