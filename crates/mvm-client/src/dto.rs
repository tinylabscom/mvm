//! The wire contract. These types are the seam between a caller and any
//! backend; the same structs will be deserialized by mvmd-gateway from the
//! network, so they fail closed on unknown fields and carry intent only —
//! never local host artifacts (keys, paths).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineStatus {
    Starting,
    Running,
    Stopped,
    Failed,
}

/// What to run — intent only. No host paths, no signing material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mib: u32,
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineState {
    pub id: MachineId,
    pub name: String,
    pub status: MachineStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineFilter {
    pub name: Option<String>,
    pub status: Option<MachineStatus>,
}

impl MachineFilter {
    /// The unconstrained filter — matches every machine.
    pub fn all() -> Self {
        Self::default()
    }

    /// Whether `m` passes this filter. Absent fields don't constrain.
    pub fn matches(&self, m: &MachineState) -> bool {
        self.name.as_ref().is_none_or(|n| *n == m.name) && self.status.is_none_or(|s| s == m.status)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogOpts {
    pub follow: bool,
    pub tail_lines: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_spec_serde_round_trips() {
        let spec = MachineSpec {
            name: "web".into(),
            image: "docker.io/lib/nginx:1".into(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("PORT".into(), "8080".into())],
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: MachineSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn unknown_field_is_rejected_fail_closed() {
        // A gateway deserializes these from the network; unexpected fields must
        // fail closed, not be silently ignored.
        let err = serde_json::from_str::<MachineSpec>(
            r#"{"name":"w","image":"i","cpus":1,"memory_mib":64,"env":[],"rogue":true}"#,
        );
        assert!(err.is_err(), "unknown field must be rejected");
    }

    #[test]
    fn machine_status_wire_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&MachineStatus::Running).unwrap(),
            "\"running\""
        );
    }

    #[test]
    fn filter_all_matches_nothing_set() {
        let f = MachineFilter::all();
        assert!(f.name.is_none() && f.status.is_none());
    }
}
