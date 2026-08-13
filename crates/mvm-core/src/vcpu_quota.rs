//! Read-back of the HVF vCPU quota record written by the supervisor.
//!
//! Mirrors [`crate::cpu_scope`] in shape: the enforced tier is derived from
//! reading the record back, not from the value that was written.

use std::path::{Path, PathBuf};

use mvm_contract::protocol::resource_controls::EnforcedTier;
pub use mvm_contract::protocol::vcpu_quota::VcpuQuotaRecord;

const RECORD_FILE: &str = "vcpu_quota.json";

fn record_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RECORD_FILE)
}

/// Persist a quota record into a VM's state directory.
pub fn write_record(state_dir: &Path, record: &VcpuQuotaRecord) -> std::io::Result<()> {
    let path = record_path(state_dir);
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, json)
}

/// Read the persisted quota record, if one exists and is valid.
pub fn read_record(state_dir: &Path) -> Option<VcpuQuotaRecord> {
    let path = record_path(state_dir);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The tier this VM's *measurement* witnesses. Never derived from config.
pub fn tier_for_vm(state_dir: &Path) -> EnforcedTier {
    let Some(record) = read_record(state_dir) else {
        return EnforcedTier::Declared;
    };
    if record.bounded() {
        EnforcedTier::HvfVcpuQuota
    } else {
        EnforcedTier::Declared
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(target: u32, achieved: u32, periods: u32) -> VcpuQuotaRecord {
        VcpuQuotaRecord {
            target_millicores: target,
            achieved_millicores: achieved,
            period_ms: 10,
            measured_wall_ms: u64::from(periods) * 10,
            measured_cpu_ms: u64::from(periods) * 10 * u64::from(achieved) / 1000,
            periods,
        }
    }

    #[test]
    fn a_vm_with_no_quota_record_reads_back_as_declared() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(tier_for_vm(dir.path()), EnforcedTier::Declared);
    }

    #[test]
    fn an_unparseable_quota_record_reads_back_as_declared() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RECORD_FILE), b"not json").unwrap();
        assert_eq!(tier_for_vm(dir.path()), EnforcedTier::Declared);
    }

    #[test]
    fn a_run_too_short_to_measure_reads_back_as_declared() {
        let dir = tempfile::tempdir().unwrap();
        write_record(dir.path(), &record(500, 500, 19)).unwrap();
        assert_eq!(tier_for_vm(dir.path()), EnforcedTier::Declared);
    }

    #[test]
    fn a_run_that_overshot_its_target_reads_back_as_declared() {
        let dir = tempfile::tempdir().unwrap();
        write_record(dir.path(), &record(500, 700, 20)).unwrap();
        assert_eq!(tier_for_vm(dir.path()), EnforcedTier::Declared);
    }

    #[test]
    fn a_run_inside_tolerance_reads_back_as_enforced() {
        let dir = tempfile::tempdir().unwrap();
        write_record(dir.path(), &record(500, 505, 20)).unwrap();
        assert_eq!(tier_for_vm(dir.path()), EnforcedTier::HvfVcpuQuota);
    }

    #[test]
    fn a_run_under_its_target_is_still_a_bound() {
        let dir = tempfile::tempdir().unwrap();
        write_record(dir.path(), &record(500, 300, 20)).unwrap();
        assert_eq!(tier_for_vm(dir.path()), EnforcedTier::HvfVcpuQuota);
    }

    #[test]
    fn a_quota_record_round_trips_through_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let r = record(500, 505, 20);
        write_record(dir.path(), &r).unwrap();
        assert_eq!(read_record(dir.path()), Some(r));
    }
}
