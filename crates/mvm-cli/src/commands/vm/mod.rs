//! VM lifecycle commands — start, stop, list, attach, exec.

pub(super) mod artifact;
pub(super) mod audit_chain;
pub(super) mod checkpoint;
pub(super) mod console;
pub(super) mod cp;
pub(super) mod diff;
pub(super) mod down;
pub(super) mod exec;
pub(super) mod forward;
pub(super) mod fs;
pub(super) mod group;
pub(super) mod host_signer;
pub(super) mod invoke;
pub(super) mod invoke_no_vm;
pub(super) mod logs;
pub(super) mod managed_secrets;
pub(super) mod pause;
pub(super) mod plan_admission;
pub(super) mod plan_builder;
pub(super) mod plan_persist;
pub(super) mod policy_resolver;
pub(super) mod proc;
pub(super) mod ps;
pub(super) mod readiness;
pub(super) mod redaction_flags;
pub(super) mod run_plan;
pub(super) mod sandbox;
pub(super) mod session;
pub(super) mod set_ttl;
pub(super) mod tenant_resolution;
pub(super) mod up;
pub(super) mod volume;
pub(super) mod wait;

pub(super) use super::{Cli, shared};
