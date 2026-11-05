//! Local persistence for the host interface: the node record and the policy.
//!
//! Both live under `<mvm_home>/host-interface/`. An absent file is the local
//! default (an `Active` node, no policy limits), so nothing needs to be set up.
//! A present-but-unreadable or malformed file is an error, never a default: a
//! tampered record must not quietly turn into permissive behavior.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    ExecutionEpoch, HostPolicy, NodeState,
    error::{Denial, HostInterfaceError},
};

const DIR: &str = "host-interface";

/// This node's lifecycle state and current execution epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRecord {
    pub node_id: String,
    pub state: NodeState,
    pub epoch: ExecutionEpoch,
}

impl Default for NodeRecord {
    fn default() -> Self {
        Self {
            node_id: "local".into(),
            state: NodeState::Active,
            epoch: ExecutionEpoch(1),
        }
    }
}

fn dir_at(home: &Path) -> PathBuf {
    home.join(DIR)
}

fn load_or_default<T: for<'a> Deserialize<'a> + Default>(
    path: &Path,
) -> Result<T, HostInterfaceError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| corrupt(path, &e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(corrupt(path, &e.to_string())),
    }
}

fn corrupt(path: &Path, why: &str) -> HostInterfaceError {
    HostInterfaceError::Denied(Denial::StateUnreadable(format!(
        "{}: {why}",
        path.display()
    )))
}

pub fn load_node_record_at(home: &Path) -> Result<NodeRecord, HostInterfaceError> {
    load_or_default(&dir_at(home).join("node.json"))
}

pub fn load_policy_at(home: &Path) -> Result<HostPolicy, HostInterfaceError> {
    load_or_default(&dir_at(home).join("policy.json"))
}

pub fn save_node_record_at(home: &Path, record: &NodeRecord) -> std::io::Result<()> {
    let dir = dir_at(home);
    crate::private_fs::ensure_private_dir(&dir)?;
    let tmp = dir.join("node.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(record)?)?;
    crate::private_fs::set_mode(&tmp, 0o600)?;
    std::fs::rename(tmp, dir.join("node.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_files_are_the_permissive_local_default() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            load_node_record_at(d.path()).unwrap(),
            NodeRecord::default()
        );
        assert_eq!(load_policy_at(d.path()).unwrap(), HostPolicy::default());
    }

    #[test]
    fn a_malformed_record_fails_closed_instead_of_defaulting() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("host-interface")).unwrap();
        std::fs::write(d.path().join("host-interface/node.json"), b"{not json").unwrap();
        assert!(matches!(
            load_node_record_at(d.path()),
            Err(HostInterfaceError::Denied(Denial::StateUnreadable(_)))
        ));
    }

    #[test]
    fn saved_record_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let r = NodeRecord {
            state: NodeState::Quarantined,
            ..Default::default()
        };
        save_node_record_at(d.path(), &r).unwrap();
        assert_eq!(load_node_record_at(d.path()).unwrap(), r);
    }
}
