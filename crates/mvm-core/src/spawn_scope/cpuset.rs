//! Confining a spawn scope to a set of host cores.
//!
//! The scope that already carries a VMM's CPU, memory and task bounds can also
//! carry `AllowedCPUs=` (systemd 244 and later), which systemd writes to the
//! scope's `cpuset.cpus`. It does so only when the cpuset controller reaches
//! the user manager: the stock `user@.service` delegates `cpu`, `memory` and
//! `pids`, and `cpuset` needs a `Delegate=` drop-in. Without it systemd accepts
//! the property and applies it to nothing, which is why the mechanism is
//! probed before a placement is admitted and the effective set is read back
//! after the launch rather than assumed from the request.

use std::path::{Path, PathBuf};

use mvm_contract::protocol::cpu_set::CpuSet;

use super::{CGROUP_ROOT, MechanismGap, ScopeProbe, mechanism_gap, read_scope_unit};

const CPUSET_CONTROLLER: &str = "cpuset";
const EFFECTIVE_CPUS_FILE: &str = "cpuset.cpus.effective";
const ONLINE_CPUS: &str = "/sys/devices/system/cpu/online";
const ISOLATED_CPUS: &str = "/sys/devices/system/cpu/isolated";

/// The file under a VM's state dir recording the CPU set its scope was asked
/// for. Its presence is what tells the read-back to look at the scope's
/// cpuset; a scope created without a set is not reported as confined to
/// whatever cores it happens to inherit.
pub(super) const SCOPE_CPUS_FILE: &str = "spawn-scope-cpus";

/// The file under a VM's state dir naming the topology unit a placed boot
/// runs. Written by admission after the read-back; cleared here at every
/// scoped boot and on stop, so it never outlives the boot that wrote it.
pub const PLACEMENT_OWNER_FILE: &str = "placement-owner.json";

/// Why this host's spawn scope cannot carry an allowed-CPU set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpusetGap {
    /// No spawn scope at all.
    Scope(MechanismGap),
    /// The scope exists, but the cpuset controller is not delegated to the
    /// user manager it is created under.
    NotDelegated,
}

impl CpusetGap {
    /// Operator-facing explanation, including the fix.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Scope(gap) => gap.describe(),
            Self::NotDelegated => {
                "the cpuset controller is not delegated to the systemd user manager, so no \
                 allowed-CPU set can be attached to a VM — add `Delegate=cpu cpuset io memory \
                 pids` in a drop-in for user@.service and log in again"
            }
        }
    }
}

/// Whether a spawn scope on this host can carry an allowed-CPU set. `None`
/// means it can.
#[must_use]
pub fn cpuset_gap() -> Option<CpusetGap> {
    if let Some(gap) = mechanism_gap() {
        return Some(CpusetGap::Scope(gap));
    }
    let delegated =
        current_uid().is_some_and(|uid| cpuset_delegated_at(Path::new(CGROUP_ROOT), uid));
    (!delegated).then_some(CpusetGap::NotDelegated)
}

/// Whether the user manager for `uid` under the hierarchy at `cgroup_root` has
/// the cpuset controller available to hand to its scopes.
#[must_use]
pub fn cpuset_delegated_at(cgroup_root: &Path, uid: u32) -> bool {
    std::fs::read_to_string(user_manager_controllers(cgroup_root, uid))
        .is_ok_and(|controllers| lists_cpuset(&controllers))
}

fn user_manager_controllers(cgroup_root: &Path, uid: u32) -> PathBuf {
    cgroup_root
        .join("user.slice")
        .join(format!("user-{uid}.slice"))
        .join(format!("user@{uid}.service"))
        .join("cgroup.controllers")
}

fn lists_cpuset(controllers: &str) -> bool {
    controllers
        .split_whitespace()
        .any(|controller| controller == CPUSET_CONTROLLER)
}

/// The effective uid, read off the owner of this process's own `/proc` entry
/// rather than through a libc call.
fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self").ok().map(|meta| meta.uid())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The CPUs the kernel has online, or `None` where it publishes no list.
#[must_use]
pub fn online_cpus() -> Option<CpuSet> {
    read_cpu_list(Path::new(ONLINE_CPUS))
}

/// The CPUs isolated from the general scheduler (`isolcpus=`), or `None`
/// where the kernel publishes no list. Empty on a host that isolates none.
#[must_use]
pub fn isolated_cpus() -> Option<CpuSet> {
    read_cpu_list(Path::new(ISOLATED_CPUS))
}

/// A kernel CPU list file, or `None` when it is absent or unparseable.
#[must_use]
pub fn read_cpu_list(path: &Path) -> Option<CpuSet> {
    CpuSet::parse(&std::fs::read_to_string(path).ok()?).ok()
}

/// The `-p` value confining a scope to `cpus`.
pub(super) fn allowed_cpus_property(cpus: &CpuSet) -> String {
    format!("AllowedCPUs={cpus}")
}

/// Record, or clear, the set this boot's scope is asked for. A state dir is
/// reused across boots of one machine, so a boot without a set must clear the
/// previous boot's record or its read-back would look for one. The previous
/// boot's placement owner is cleared with it, whatever this boot asks for.
pub(super) fn record_requested(state_dir: &Path, cpus: Option<&CpuSet>) -> std::io::Result<()> {
    clear_placement_owner(state_dir)?;
    let path = state_dir.join(SCOPE_CPUS_FILE);
    match cpus {
        Some(cpus) => std::fs::write(path, cpus.to_string()),
        None => remove_if_present(&path),
    }
}

/// Remove the placement owner record, if there is one.
///
/// # Errors
///
/// The record exists and cannot be removed.
pub fn clear_placement_owner(state_dir: &Path) -> std::io::Result<()> {
    remove_if_present(&state_dir.join(PLACEMENT_OWNER_FILE))
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Whether this VM's scope was asked for a CPU set.
pub(super) fn requested_for_vm(state_dir: &Path) -> bool {
    state_dir.join(SCOPE_CPUS_FILE).is_file()
}

/// The CPU set this VM's scope was born confined to, or `None` when it was
/// not confined (or its record cannot be read, which reads as unconfined).
#[must_use]
pub fn recorded_cpus(state_dir: &Path) -> Option<CpuSet> {
    read_cpu_list(&state_dir.join(SCOPE_CPUS_FILE))
}

impl ScopeProbe {
    /// The `cpuset.cpus.effective` of the scope this VM was born into, or
    /// `None` when there is no recorded scope or its cpuset cannot be read.
    #[must_use]
    pub fn effective_cpus_for_vm(&self, state_dir: &Path) -> Option<CpuSet> {
        let unit = read_scope_unit(state_dir)?;
        let control_group = self.control_group(&unit)?;
        read_cpu_list(&self.cgroup_file(&control_group, EFFECTIVE_CPUS_FILE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_is_read_off_the_user_manager_controllers() {
        let root = tempfile::tempdir().unwrap();
        assert!(!cpuset_delegated_at(root.path(), 1000), "absent file");
        let file = user_manager_controllers(root.path(), 1000);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "cpu memory pids\n").unwrap();
        assert!(!cpuset_delegated_at(root.path(), 1000), "stock delegation");
        std::fs::write(&file, "cpuset cpu io memory pids\n").unwrap();
        assert!(cpuset_delegated_at(root.path(), 1000));
        assert!(!cpuset_delegated_at(root.path(), 1001), "another user");
    }

    #[test]
    fn a_controller_merely_containing_the_name_is_not_cpuset() {
        assert!(!lists_cpuset("cpusetx cpu"));
        assert!(lists_cpuset("cpu cpuset"));
    }

    #[test]
    fn the_property_spells_the_kernel_list() {
        let cpus = CpuSet::parse("3,1,2,6").unwrap();
        assert_eq!(allowed_cpus_property(&cpus), "AllowedCPUs=1-3,6");
    }

    #[test]
    fn the_requested_record_is_written_and_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let cpus = CpuSet::parse("2-3").unwrap();
        record_requested(dir.path(), Some(&cpus)).unwrap();
        assert!(requested_for_vm(dir.path()));
        assert_eq!(
            std::fs::read_to_string(dir.path().join(SCOPE_CPUS_FILE)).unwrap(),
            "2-3"
        );
        record_requested(dir.path(), None).unwrap();
        assert!(!requested_for_vm(dir.path()));
        record_requested(dir.path(), None).expect("clearing nothing is fine");
    }

    #[test]
    fn every_scoped_boot_clears_the_previous_placement_owner() {
        let dir = tempfile::tempdir().unwrap();
        let owner = dir.path().join(PLACEMENT_OWNER_FILE);
        std::fs::write(&owner, "{}").unwrap();
        record_requested(dir.path(), None).unwrap();
        assert!(!owner.exists(), "an unconfined boot clears it");
        std::fs::write(&owner, "{}").unwrap();
        record_requested(dir.path(), Some(&CpuSet::parse("1").unwrap())).unwrap();
        assert!(
            !owner.exists(),
            "a placed boot clears it until admission writes its own"
        );
        clear_placement_owner(dir.path()).expect("clearing nothing is fine");
    }

    #[test]
    fn the_recorded_set_reads_back_or_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(recorded_cpus(dir.path()), None);
        record_requested(dir.path(), Some(&CpuSet::parse("4-5").unwrap())).unwrap();
        assert_eq!(
            recorded_cpus(dir.path()),
            Some(CpuSet::parse("4,5").unwrap())
        );
    }

    #[test]
    fn a_cpu_list_file_reads_or_answers_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("online");
        assert_eq!(read_cpu_list(&path), None);
        std::fs::write(&path, "0-7\n").unwrap();
        assert_eq!(read_cpu_list(&path), Some(CpuSet::parse("0-7").unwrap()));
        std::fs::write(&path, "garbage").unwrap();
        assert_eq!(read_cpu_list(&path), None);
    }

    #[test]
    fn a_host_without_a_scope_reports_that_gap_first() {
        let gap = CpusetGap::Scope(MechanismGap::NoUserSessionBus);
        assert_eq!(gap.describe(), MechanismGap::NoUserSessionBus.describe());
        assert!(CpusetGap::NotDelegated.describe().contains("Delegate="));
    }
}
