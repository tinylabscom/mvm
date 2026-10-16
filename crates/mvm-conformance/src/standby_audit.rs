//! Classify the VM state directories a live run left behind.
//!
//! An unnamed `machine run` deliberately leaves a standby behind for the next
//! run: a detached refill registers `pool/<id>/standby.json` and, on a
//! preloading backend, parks a paused child beside it. Both own a directory
//! under `vms/`, so a leak check that counted every new directory would fail
//! on the run doing exactly what it should. This classifier tells those two
//! registered shapes apart from everything else, and everything else is a
//! leak.

use std::path::{Path, PathBuf};

use mvm_core::vm_backend::StandbyHandle;

/// Every new `vms/` directory, sorted into what registered it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StateDirAudit {
    /// `vms/<id>` directories backed by a claimable `pool/<id>` record.
    pub registered_standbys: Vec<PathBuf>,
    /// Paused children a claimable record names as its preloaded child.
    pub preloaded_children: Vec<PathBuf>,
    /// Everything no claimable record accounts for. A standby whose refill
    /// has not registered yet lands here too, which is why a caller polls
    /// before treating this as a leak.
    pub unregistered: Vec<PathBuf>,
}

impl StateDirAudit {
    /// True when every new directory is accounted for by a claimable record.
    pub fn is_clean(&self) -> bool {
        self.unregistered.is_empty()
    }
}

/// Sort `new_dirs` by the claimable records in `standbys`.
///
/// A record that is claimed or otherwise not claimable accounts for nothing:
/// its directories are a launch's transient state and must be gone by the
/// time the launch returns. Output vectors are sorted so a failure message is
/// stable.
pub fn audit_new_state_dirs<I>(new_dirs: I, standbys: &[StandbyHandle]) -> StateDirAudit
where
    I: IntoIterator<Item = PathBuf>,
{
    let claimable: Vec<&StandbyHandle> = standbys
        .iter()
        .filter(|handle| handle.state.is_claimable())
        .collect();
    let mut audit = StateDirAudit::default();
    for dir in new_dirs {
        let Some(name) = dir_name(&dir) else {
            audit.unregistered.push(dir);
            continue;
        };
        if claimable.iter().any(|handle| handle.id == name) {
            audit.registered_standbys.push(dir);
        } else if claimable
            .iter()
            .any(|handle| handle.preloaded_child_vm_name.as_deref() == Some(name))
        {
            audit.preloaded_children.push(dir);
        } else {
            audit.unregistered.push(dir);
        }
    }
    audit.registered_standbys.sort();
    audit.preloaded_children.sort();
    audit.unregistered.sort();
    audit
}

fn dir_name(dir: &Path) -> Option<&str> {
    dir.file_name().and_then(|name| name.to_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::{RuntimeSourceRootStrategy, StandbyState};

    fn handle(id: &str, state: StandbyState, child: Option<&str>) -> StandbyHandle {
        StandbyHandle {
            id: id.to_string(),
            template_id: None,
            control_socket: String::new(),
            pid: 0,
            kernel_sha256: "k".repeat(64),
            vcpus: 1,
            mem_mib: 256,
            binding_nonce: "n".repeat(64),
            spawned_unix_secs: 0,
            state,
            image_sha256: None,
            root_strategy: RuntimeSourceRootStrategy::default(),
            parent_checkpoint: Some("standby-ckpt".into()),
            preloaded_child_vm_name: child.map(str::to_string),
            vsock_egress: false,
        }
    }

    fn dirs(names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|name| PathBuf::from("/home/vms").join(name))
            .collect()
    }

    #[test]
    fn a_registered_standby_and_its_preloaded_child_are_not_leaks() {
        let standbys = [handle("standby-aaaa", StandbyState::Idle, Some("vm-child"))];
        let audit = audit_new_state_dirs(dirs(&["vm-child", "standby-aaaa"]), &standbys);
        assert_eq!(audit.registered_standbys, dirs(&["standby-aaaa"]));
        assert_eq!(audit.preloaded_children, dirs(&["vm-child"]));
        assert!(audit.is_clean(), "{audit:?}");
    }

    #[test]
    fn a_parked_record_still_accounts_for_its_directory() {
        let standbys = [handle("standby-aaaa", StandbyState::Parked, None)];
        let audit = audit_new_state_dirs(dirs(&["standby-aaaa"]), &standbys);
        assert!(audit.is_clean(), "{audit:?}");
    }

    #[test]
    fn a_claimed_record_accounts_for_nothing() {
        let standbys = [handle(
            "standby-aaaa",
            StandbyState::Claimed,
            Some("vm-child"),
        )];
        let audit = audit_new_state_dirs(dirs(&["standby-aaaa", "vm-child"]), &standbys);
        assert_eq!(audit.unregistered, dirs(&["standby-aaaa", "vm-child"]));
        assert!(audit.registered_standbys.is_empty());
        assert!(audit.preloaded_children.is_empty());
    }

    #[test]
    fn an_unregistered_standby_and_a_stray_vm_dir_are_reported() {
        let standbys = [handle("standby-aaaa", StandbyState::Idle, None)];
        let audit = audit_new_state_dirs(
            dirs(&["vm-stray", "standby-bbbb", "standby-aaaa", "bdd-journey"]),
            &standbys,
        );
        assert_eq!(audit.registered_standbys, dirs(&["standby-aaaa"]));
        assert_eq!(
            audit.unregistered,
            dirs(&["bdd-journey", "standby-bbbb", "vm-stray"])
        );
        assert!(!audit.is_clean());
    }

    #[test]
    fn no_new_directories_is_clean_whatever_the_pool_holds() {
        let standbys = [handle("standby-aaaa", StandbyState::Idle, Some("vm-child"))];
        assert!(audit_new_state_dirs(Vec::new(), &standbys).is_clean());
        assert!(audit_new_state_dirs(Vec::new(), &[]).is_clean());
    }
}
