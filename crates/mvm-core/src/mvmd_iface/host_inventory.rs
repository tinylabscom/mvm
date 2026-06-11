//! Host inventory wire types — how `mvm` describes a host to `mvmd`.
//!
//! `mvmd` runs placement against an aggregated inventory of hosts. Each
//! host's local `mvm` reports its capacity and current state up to `mvmd`
//! over a signed envelope. This module declares the contract.

use serde::{Deserialize, Serialize};

/// A host's identity, capacity, and current orchestration state.
///
/// `mvm` produces this; `mvmd` consumes it. The supervisor refreshes it
/// on a heartbeat cadence and on local state changes (e.g. when entering
/// `Draining` after a `mvmctl cordon`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostInventory {
    /// Stable host identifier (machine-id or equivalent).
    pub host_id: String,
    /// Total physical capacity available to mvm workloads.
    pub capacity: HostCapacity,
    /// Current orchestration state. See [`HostState`].
    pub state: HostState,
    /// Unix seconds of the most recent local-state observation.
    pub last_heartbeat_unix_secs: u64,
}

/// Total physical capacity a host can offer to mvm workloads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostCapacity {
    pub total_vcpus: u32,
    pub total_mem_mib: u64,
    pub total_disk_gib: u64,
}

/// Orchestration state of a host as observed by `mvm` and consumed by
/// `mvmd`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum HostState {
    /// Accepting new workloads.
    Ready,
    /// No new workloads; existing ones unaffected.
    Cordoned,
    /// Existing workloads being migrated off; no new ones.
    Draining,
    /// Reachable but failing health checks. `mvmd` may reschedule.
    Degraded,
    /// Lost contact past the deadline. `mvmd` reschedules.
    Dead,
    /// Coming back online after a restart; not yet `Ready`.
    Recovering,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_inventory_roundtrip() {
        let inv = HostInventory {
            host_id: "host-abc".into(),
            capacity: HostCapacity {
                total_vcpus: 16,
                total_mem_mib: 65_536,
                total_disk_gib: 1024,
            },
            state: HostState::Ready,
            last_heartbeat_unix_secs: 1_780_000_000,
        };
        let json = serde_json::to_string(&inv).unwrap();
        let parsed: HostInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, parsed);
    }

    #[test]
    fn host_inventory_rejects_unknown_field() {
        let json = r#"{
            "host_id": "h",
            "capacity": {"total_vcpus": 1, "total_mem_mib": 1, "total_disk_gib": 1},
            "state": "ready",
            "last_heartbeat_unix_secs": 0,
            "extra": null
        }"#;
        assert!(serde_json::from_str::<HostInventory>(json).is_err());
    }

    #[test]
    fn host_state_roundtrip_each_variant() {
        for s in [
            HostState::Ready,
            HostState::Cordoned,
            HostState::Draining,
            HostState::Degraded,
            HostState::Dead,
            HostState::Recovering,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: HostState = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }
    }
}
