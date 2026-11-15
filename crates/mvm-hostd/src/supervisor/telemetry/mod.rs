//! Per-VM measurement: AI token budgets, the action ledger, instance sampling, the supervisor's self-usage and host vsock egress telemetry.

pub mod action_ledger;
pub mod ai_meter;
/// Host-side vsock egress telemetry (eBPF/procfs).
pub mod ebpf_telemetry;
pub mod instance_sampler;
/// What a per-VM supervisor consumed on behalf of its machine — the
/// self-measurement the in-process VMM tiers record at teardown.
pub mod self_usage;
