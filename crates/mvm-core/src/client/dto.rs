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
    /// vCPUs paused with the VMM still alive. Kept distinct from `Stopped` so a
    /// paused machine stays visible in a default listing instead of folding
    /// away. Any detail behind a non-happy status (e.g. a `Failed` reason)
    /// travels in [`MachineState::status_detail`], which keeps this enum `Copy`.
    Paused,
    Failed,
}

/// What to run — intent only. No host paths, no signing material.
///
/// Build one fluently with [`MachineSpec::builder`]:
///
/// ```
/// use mvm_core::client::dto::MachineSpec;
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

/// A host:guest port forwarding on a machine — plain listing data that mirrors a
/// backend's port mapping so a machine record can carry its forwards without
/// exposing a runtime type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    pub host: u16,
    pub guest: u16,
}

/// A machine's observed runtime state — the shared listing/inspect record. Every
/// field is REST-satisfiable plain data (no host handles, no paths, no keys), so
/// the same struct crosses the gateway wire. New fields carry `#[serde(default)]`
/// so an older serialized record still deserializes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineState {
    pub id: MachineId,
    pub name: String,
    pub status: MachineStatus,
    /// Free-text detail for a non-happy `status` — e.g. the reason behind
    /// [`MachineStatus::Failed`]. `None` when the status needs no elaboration.
    /// Kept off `MachineStatus` so that enum stays `Copy` and cheap to compare.
    #[serde(default)]
    pub status_detail: Option<String>,
    /// Backend that owns this machine (e.g. `"firecracker"`, `"hvf"`,
    /// `"libkrun"`). Empty when unknown.
    #[serde(default)]
    pub backend: String,
    /// Guest IP, when networking is configured.
    #[serde(default)]
    pub guest_ip: Option<String>,
    /// vCPU count. `0` when unknown (e.g. a registered-but-stopped machine).
    #[serde(default)]
    pub cpus: u32,
    /// Guest memory in MiB. `0` when unknown.
    #[serde(default)]
    pub memory_mib: u32,
    /// Flake profile name, when built from a profile.
    #[serde(default)]
    pub profile: Option<String>,
    /// Nix store revision hash, when known.
    #[serde(default)]
    pub revision: Option<String>,
    /// Original flake reference, when known.
    #[serde(default)]
    pub flake_ref: Option<String>,
    /// Active host:guest port forwardings.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// Caller-supplied metadata tags.
    #[serde(default)]
    pub tags: std::collections::BTreeMap<String, String>,
    /// RFC 3339 TTL expiry, when set. Whether it has elapsed is a caller
    /// (presentation) decision, not modeled here.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Whether connecting auto-resumes a sleeping machine.
    #[serde(default = "default_auto_resume")]
    pub auto_resume: bool,
    /// Finer-grained host-observed readiness, when tracked.
    #[serde(default)]
    pub readiness: Option<crate::domain::instance::InstanceReadiness>,
    /// RFC 3339 timestamp of the last `readiness` change.
    #[serde(default)]
    pub last_readiness_change_at: Option<String>,
}

fn default_auto_resume() -> bool {
    true
}

impl Default for MachineState {
    fn default() -> Self {
        Self {
            id: MachineId(String::new()),
            name: String::new(),
            status: MachineStatus::Stopped,
            status_detail: None,
            backend: String::new(),
            guest_ip: None,
            cpus: 0,
            memory_mib: 0,
            profile: None,
            revision: None,
            flake_ref: None,
            ports: Vec::new(),
            tags: std::collections::BTreeMap::new(),
            expires_at: None,
            auto_resume: true,
            readiness: None,
            last_readiness_change_at: None,
        }
    }
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
        assert_eq!(
            serde_json::to_string(&MachineStatus::Paused).unwrap(),
            "\"paused\""
        );
    }

    #[test]
    fn machine_state_serde_round_trips_with_all_fields() {
        let state = MachineState {
            id: MachineId("m1".into()),
            name: "web".into(),
            status: MachineStatus::Failed,
            status_detail: Some("boom".into()),
            backend: "firecracker".into(),
            guest_ip: Some("172.16.0.2".into()),
            cpus: 2,
            memory_mib: 512,
            profile: Some("worker".into()),
            revision: Some("abc123".into()),
            flake_ref: Some(".#worker".into()),
            ports: vec![PortMapping {
                host: 8080,
                guest: 80,
            }],
            tags: std::collections::BTreeMap::from([("env".into(), "prod".into())]),
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            auto_resume: false,
            readiness: Some(crate::domain::instance::InstanceReadiness::AgentReady),
            last_readiness_change_at: Some("2026-01-01T00:00:00Z".into()),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: MachineState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn machine_state_deserializes_legacy_three_field_record() {
        // A record serialized before the listing fields existed still loads:
        // the added fields fall back to their serde defaults.
        let legacy = r#"{"id":"m1","name":"web","status":"running"}"#;
        let state: MachineState = serde_json::from_str(legacy).unwrap();
        assert_eq!(state.status, MachineStatus::Running);
        assert!(state.status_detail.is_none());
        assert!(state.backend.is_empty());
        assert_eq!(state.cpus, 0);
        assert!(state.ports.is_empty());
        assert!(state.tags.is_empty());
        // auto_resume defaults true (matches the registry default), not false.
        assert!(state.auto_resume);
    }

    #[test]
    fn machine_state_default_is_stopped_and_empty() {
        let d = MachineState::default();
        assert_eq!(d.status, MachineStatus::Stopped);
        assert!(d.auto_resume);
        assert!(d.backend.is_empty() && d.ports.is_empty() && d.tags.is_empty());
    }

    #[test]
    fn machine_state_rejects_unknown_field_fail_closed() {
        let err = serde_json::from_str::<MachineState>(
            r#"{"id":"m1","name":"w","status":"running","rogue":true}"#,
        );
        assert!(err.is_err(), "unknown field must be rejected");
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
