//! Machine-readable pool status output types, and the reporting built on them.

use anyhow::Result;
use mvm_core::vm_backend::{StandbyHandle, StandbyState};
use mvm_runtime::standby_pool::SupervisorStandbyPool;

#[derive(serde::Serialize)]
pub(super) struct PoolStatus {
    pub(super) idle: usize,
    pub(super) claimed: usize,
    pub(super) parked: usize,
    pub(super) dead: usize,
    pub(super) standbys: Vec<PoolStatusEntry>,
}

#[derive(serde::Serialize)]
pub(super) struct PoolStatusEntry {
    pub(super) id: String,
    pub(super) state: &'static str,
    pub(super) pid: u32,
    pub(super) kernel_sha256: String,
    pub(super) vcpus: u8,
    pub(super) mem_mib: u32,
    /// The image half of the compat key: sha256 of the rootfs the parent
    /// booted. Every standby carries one, since a parent is only ever spawned
    /// for a resolved launch shape; absent marks a record predating that.
    pub(super) image_sha256: Option<String>,
}

pub(super) fn build_pool_status(standbys: &[StandbyHandle]) -> PoolStatus {
    let idle = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Idle && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let parked = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Parked && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let claimed = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Claimed && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let dead = standbys
        .iter()
        .filter(|h| !SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    PoolStatus {
        idle,
        claimed,
        parked,
        dead,
        standbys: standbys
            .iter()
            .map(|h| PoolStatusEntry {
                id: h.id.clone(),
                state: if SupervisorStandbyPool::is_live_or_saved(h) {
                    match h.state {
                        StandbyState::Idle => "idle",
                        StandbyState::Claimed => "claimed",
                        StandbyState::Parked => "parked",
                    }
                } else {
                    "dead"
                },
                pid: h.pid,
                kernel_sha256: h.kernel_sha256.clone(),
                vcpus: h.vcpus,
                mem_mib: h.mem_mib,
                image_sha256: h.image_sha256.clone(),
            })
            .collect(),
    }
}

pub(super) fn run_status(pool: &SupervisorStandbyPool, json: bool) -> Result<()> {
    let standbys = pool.list()?;
    let report = build_pool_status(&standbys);
    if json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    println!(
        "Supervisor standby pool: {} idle, {} claimed, {} parked, {} dead",
        report.idle, report.claimed, report.parked, report.dead
    );
    for e in &report.standbys {
        let image_tag = e
            .image_sha256
            .as_deref()
            .map(|s| format!(" · image {}", &s[..s.len().min(12)]))
            .unwrap_or_default();
        println!(
            "  {} · {} · {} · {} vcpu / {} MiB · kernel {}{}",
            e.id,
            e.state,
            if e.pid == 0 {
                "saved-state".to_string()
            } else {
                format!("pid {}", e.pid)
            },
            e.vcpus,
            e.mem_mib,
            &e.kernel_sha256[..e.kernel_sha256.len().min(12)],
            image_tag,
        );
    }
    Ok(())
}
