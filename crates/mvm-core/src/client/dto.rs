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
///
/// Build one fluently with [`MachineSpec::builder`]:
///
/// ```
/// use super::MachineSpec;
///
/// let spec = MachineSpec::builder("web", "nginx")
///     .cpus(2)
///     .memory_mib(512)
///     .env("PORT", "8080")
///     .build();
/// assert_eq!(spec.name, "web");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mib: u32,
    pub env: Vec<(String, String)>,
}

impl MachineSpec {
    /// Start building a spec. `name` and `image` are the two required fields;
    /// everything else defaults (1 vCPU, 512 MiB, no env) and is overridable on
    /// the returned [`MachineSpecBuilder`].
    pub fn builder(name: impl Into<String>, image: impl Into<String>) -> MachineSpecBuilder {
        MachineSpecBuilder {
            name: name.into(),
            image: image.into(),
            cpus: 1,
            memory_mib: 512,
            env: Vec::new(),
        }
    }
}

/// Fluent builder for [`MachineSpec`]. Obtain one from [`MachineSpec::builder`].
///
/// `name` and `image` are required (supplied up front), so [`build`] is
/// infallible; `cpus`/`memory_mib` default to 1 vCPU / 512 MiB and `env`
/// accumulates across calls.
///
/// [`build`]: MachineSpecBuilder::build
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSpecBuilder {
    name: String,
    image: String,
    cpus: u32,
    memory_mib: u32,
    env: Vec<(String, String)>,
}

impl MachineSpecBuilder {
    /// Set the vCPU count (default 1).
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    /// Set the guest memory in MiB (default 512).
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Append one environment variable. Repeatable.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Append many environment variables at once.
    #[must_use]
    pub fn envs(mut self, vars: impl IntoIterator<Item = (String, String)>) -> Self {
        self.env.extend(vars);
        self
    }

    /// Finish building. Infallible — `name` and `image` were required up front.
    #[must_use]
    pub fn build(self) -> MachineSpec {
        MachineSpec {
            name: self.name,
            image: self.image,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            env: self.env,
        }
    }
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

/// The result of a non-interactive `exec_machine`: the process's exit code and
/// captured output. (Interactive shells are not a facade operation — they need
/// a duplex PTY the request/response trait can't model, and stay a CLI concern.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A patch over a machine's reconfigurable fields — intent only. Every
/// field is optional: `None` means "leave unchanged" (patch semantics).
/// `mem_initial` is intentionally absent — it stays a CLI-only field
/// (the facade doesn't model it at launch either).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconfigureRequest {
    pub net: Option<bool>,
    pub allow_host: Option<Vec<String>>,
    pub cpus: Option<u32>,
    pub memory_mib: Option<u32>,
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
    fn builder_applies_defaults_and_overrides() {
        let spec = MachineSpec::builder("web", "nginx").build();
        assert_eq!(
            spec,
            MachineSpec {
                name: "web".into(),
                image: "nginx".into(),
                cpus: 1,
                memory_mib: 512,
                env: vec![],
            }
        );

        let spec = MachineSpec::builder("web", "nginx")
            .cpus(4)
            .memory_mib(1024)
            .env("A", "1")
            .envs([("B".to_string(), "2".to_string())])
            .env("C", "3")
            .build();
        assert_eq!(spec.cpus, 4);
        assert_eq!(spec.memory_mib, 1024);
        assert_eq!(
            spec.env,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "2".into()),
                ("C".into(), "3".into()),
            ]
        );
    }

    #[test]
    fn builder_equals_struct_literal() {
        let built = MachineSpec::builder("web", "docker.io/lib/nginx:1")
            .cpus(2)
            .memory_mib(512)
            .env("PORT", "8080")
            .build();
        let literal = MachineSpec {
            name: "web".into(),
            image: "docker.io/lib/nginx:1".into(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("PORT".into(), "8080".into())],
        };
        assert_eq!(built, literal);
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

    #[test]
    fn reconfigure_request_serde_round_trips() {
        let req = ReconfigureRequest {
            net: Some(true),
            allow_host: Some(vec!["api.stripe.com:443".into()]),
            cpus: Some(4),
            memory_mib: Some(1024),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ReconfigureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn reconfigure_request_all_none_is_valid_noop() {
        let req: ReconfigureRequest = serde_json::from_str("{}").expect("all fields optional");
        assert_eq!(req, ReconfigureRequest::default());
    }

    #[test]
    fn reconfigure_request_rejects_unknown_field_fail_closed() {
        let err = serde_json::from_str::<ReconfigureRequest>(r#"{"rogue":true}"#);
        assert!(err.is_err(), "unknown field must be rejected");
    }
}
