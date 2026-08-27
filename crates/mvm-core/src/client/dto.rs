//! The wire contract. These types are the seam between a caller and any
//! backend; the same structs will be deserialized by mvmd-gateway from the
//! network, so they fail closed on unknown fields and carry intent only —
//! never local host artifacts (keys, paths).

use serde::{Deserialize, Serialize};

use crate::rootfs_source::{RootfsSource, RootfsSourceParseError};

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

impl MachineStatus {
    /// The snake_case wire label — the exact string the serde form emits,
    /// which SDK facades parse out of machine listings.
    pub fn wire_label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Paused => "paused",
            Self::Failed => "failed",
        }
    }
}

/// What to run — intent only. No host paths, no signing material.
///
/// Build one fluently with [`MachineSpec::builder`]:
///
/// ```
/// use mvm_core::client::dto::MachineSpec;
///
/// let spec = MachineSpec::builder("web", "nginx")?
///     .cpus(2)
///     .memory_mib(512)
///     .env("PORT", "8080")
///     .build();
/// assert_eq!(spec.name, "web");
/// assert_eq!(spec.image.to_string(), "nginx");
/// # Ok::<(), mvm_core::rootfs_source::RootfsSourceParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub name: String,
    /// What to boot — the parsed declaration, not a string still waiting to be
    /// interpreted: an absolute, `./`-relative or `~/`-relative path (or an
    /// explicit `path:<p>`) is a local rootfs, a `flake:<ref>#<attr>` is a
    /// flake output, and anything else (or an explicit `oci:<ref>`) is an OCI
    /// reference. Serialized as that same string, so a spec on a wire carries
    /// the token a user typed.
    ///
    /// Typed here because the alternative was a boundary that accepted every
    /// string and found out at boot. A declared path that is absent is still a
    /// boot-time refusal — no filesystem is consulted at this layer — but a
    /// string that names nothing at all no longer reaches one.
    pub image: RootfsSource,
    pub cpus: u32,
    pub memory_mib: u32,
    pub env: Vec<(String, String)>,
    /// Path to an operator-authored assurance campaign declaration.
    ///
    /// Host-local and meaningful only to a backend running on this machine: it
    /// names a file the *host* reads, so a remote backend must refuse a spec
    /// carrying one rather than resolve it against its own filesystem.
    /// `#[serde(default)]` so a record written before campaigns existed still
    /// deserializes, and skip-serialized when absent so the ordinary spec's
    /// bytes do not move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_campaign: Option<std::path::PathBuf>,
    /// What this workload is permitted to consume or reach. `None` leaves
    /// every dimension unspecified, which each resolves its own way: no CPU
    /// cap, no wall-clock bound, and deny-all egress.
    ///
    /// This is the only way a library caller expresses an egress allow-list —
    /// there is no separate network field, because a second representation of
    /// the same decision is a second thing that can disagree with the signed
    /// plan. `#[serde(default)]` so a record written before grants existed
    /// still deserializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<mvm_contract::grants::Grants>,
}

impl MachineSpec {
    /// Start building a spec. `name` and `image` are the two required fields;
    /// everything else defaults (1 vCPU, 512 MiB, no env, no grants) and is
    /// overridable on the returned [`MachineSpecBuilder`].
    ///
    /// # Errors
    ///
    /// Returns [`RootfsSourceParseError`] when `image` names no rootfs source —
    /// an empty declaration, or a scheme with nothing after it. The refusal
    /// lands here rather than at boot because that is where the caller can
    /// still see which value they passed.
    pub fn builder(
        name: impl Into<String>,
        image: impl AsRef<str>,
    ) -> Result<MachineSpecBuilder, RootfsSourceParseError> {
        Ok(MachineSpecBuilder {
            name: name.into(),
            image: image.as_ref().parse()?,
            cpus: 1,
            memory_mib: 512,
            env: Vec::new(),
            grants: mvm_contract::grants::Grants::default(),
            assurance_campaign: None,
        })
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
    image: RootfsSource,
    cpus: u32,
    memory_mib: u32,
    env: Vec<(String, String)>,
    grants: mvm_contract::grants::Grants,
    assurance_campaign: Option<std::path::PathBuf>,
}

impl MachineSpecBuilder {
    /// Run a declared assurance campaign against this machine.
    ///
    /// Host-local: the path is read by the backend's own process, so this is
    /// meaningful only against a local backend.
    #[must_use]
    pub fn assurance_campaign(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.assurance_campaign = Some(path.into());
        self
    }

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

    /// Bound the workload to `millicores` thousandths of one host core.
    ///
    /// A share of host CPU *time*, unrelated to [`cpus`], which sets how many
    /// vCPUs the guest sees. A workload can hold four vCPUs and be bounded to
    /// half a core; conflating the two is the mistake every container runtime
    /// made once.
    ///
    /// [`cpus`]: MachineSpecBuilder::cpus
    #[must_use]
    pub fn cpu_millicores(mut self, millicores: u32) -> Self {
        self.grants.cpu = Some(mvm_contract::grants::CpuGrant::Share { millicores });
        self
    }

    /// Bound the workload to a deterministic executed-instruction budget.
    /// A different unit from [`cpu_millicores`], not a finer one; the later
    /// call wins.
    ///
    /// [`cpu_millicores`]: MachineSpecBuilder::cpu_millicores
    #[must_use]
    pub fn cpu_fuel(mut self, instructions: u64) -> Self {
        self.grants.cpu = Some(mvm_contract::grants::CpuGrant::Fuel { instructions });
        self
    }

    /// Bound the workload's wall-clock runtime. `NonZeroU32` because zero
    /// seconds means "no time allowed", which is not a bound anyone wants, and
    /// the legacy encoding it resembles reads zero as *unbounded*.
    #[must_use]
    pub fn wall_clock_secs(mut self, secs: std::num::NonZeroU32) -> Self {
        self.grants.wall_clock = Some(mvm_contract::grants::WallClockGrant::Secs { secs });
        self
    }

    /// Permit outbound access to one `host:port`. Repeatable; each call
    /// appends. Calling it at all is what lifts the workload off deny-all.
    #[must_use]
    pub fn allow_egress(mut self, host: impl Into<String>, port: u16) -> Self {
        self.grants
            .egress
            .get_or_insert_with(Default::default)
            .allow
            .push(crate::policy::network_policy::HostPort::new(host, port));
        self
    }

    /// Replace the whole permission set at once, for a caller that already has
    /// one in hand (read from a file, received over a wire). Overwrites every
    /// dimension the per-dimension setters above may have set.
    #[must_use]
    pub fn grants(mut self, grants: mvm_contract::grants::Grants) -> Self {
        self.grants = grants;
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
            // An untouched permission set serializes as absent, so a spec that
            // granted nothing is byte-identical to one written before grants
            // existed.
            grants: (self.grants != mvm_contract::grants::Grants::default()).then_some(self.grants),
            assurance_campaign: self.assurance_campaign,
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

/// Options for `pause_machine` — intent only, so a remote gateway can carry them
/// over REST. The snapshot transport (a live Firecracker socket vs the mock's
/// canned bytes) is host-local and chosen by the backend, never named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseOpts {
    /// Wait for the workload to signal "primed" (a fully-warmed base) before
    /// sealing, failing closed on timeout so no half-warmed snapshot is sealed.
    /// A backend with no guest agent to answer (the mock) ignores it.
    #[serde(default)]
    pub primed_barrier: bool,
    /// Seconds to wait for the primed signal when `primed_barrier` is set.
    #[serde(default = "default_primed_timeout_secs")]
    pub primed_timeout_secs: u64,
}

fn default_primed_timeout_secs() -> u64 {
    120
}

impl Default for PauseOpts {
    fn default() -> Self {
        Self {
            primed_barrier: false,
            primed_timeout_secs: default_primed_timeout_secs(),
        }
    }
}

/// The outcome of a successful `pause_machine`. A sealed-snapshot backend
/// reports its replay epoch and artifact lengths; a backend-native vCPU pause
/// reports zeroes because it creates no sealed artifacts. Plain data the caller
/// renders in its success line and audit entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PauseOutcome {
    /// Monotonic replay-defence counter stamped into the sealed envelope; a
    /// resume refuses any snapshot whose epoch is below the high-water mark.
    /// Zero for a backend-native pause that creates no sealed snapshot.
    pub epoch: u64,
    /// Length in bytes of the sealed `vmstate.bin`; zero for backend-native pause.
    pub vmstate_len: u64,
    /// Length in bytes of the sealed `mem.bin`; zero for backend-native pause.
    pub mem_len: u64,
}

/// Options for `resume_machine` — intent only, REST-satisfiable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeOpts {
    /// Drive the resume through the backend's live-memory warm-start path
    /// instead of the plain verify-and-resume. Fails closed with a typed
    /// recovery hint on a disk-only backend that cannot warm-start at the
    /// live-memory tier.
    #[serde(default)]
    pub warm: bool,
}

/// What a `resume_machine` did — the detail the caller renders in its success
/// line and, crucially, the chain-signed `WorkloadWake` audit entry, at parity
/// with [`PauseOutcome`]. Plain data, REST-satisfiable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeOutcome {
    /// The verified snapshot's epoch (plain resume). `0` for a warm resume or
    /// backend-native vCPU resume, neither of which restores a sealed snapshot.
    #[serde(default)]
    pub epoch: u64,
    /// Length in bytes of the restored `vmstate.bin` (plain resume); `0` for warm.
    #[serde(default)]
    pub vmstate_len: u64,
    /// Length in bytes of the restored `mem.bin` (plain resume); `0` for warm.
    #[serde(default)]
    pub mem_len: u64,
    /// The warm-start reseed summary (whether the guest rotated its VMGenID and
    /// reseeded). `Some` for a warm resume, `None` for a plain verify-and-resume.
    #[serde(default)]
    pub reseed: Option<String>,
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

    #[test]
    fn a_declared_campaign_survives_the_builder_and_absence_changes_no_bytes() {
        let plain = MachineSpec::builder("m", "alpine:3.20")
            .expect("spec")
            .build();
        assert!(plain.assurance_campaign.is_none());
        // Skip-serialized when absent, so an ordinary spec's bytes do not move.
        let json = serde_json::to_string(&plain).expect("json");
        assert!(!json.contains("assurance_campaign"), "{json}");

        let declared = MachineSpec::builder("m", "alpine:3.20")
            .expect("spec")
            .assurance_campaign("/tmp/campaign.json")
            .build();
        assert_eq!(
            declared.assurance_campaign.as_deref(),
            Some(std::path::Path::new("/tmp/campaign.json"))
        );
        let round: MachineSpec =
            serde_json::from_str(&serde_json::to_string(&declared).expect("json")).expect("parse");
        assert_eq!(round.assurance_campaign, declared.assurance_campaign);
    }
    use super::*;

    #[test]
    fn machine_spec_serde_round_trips() {
        let spec = MachineSpec {
            name: "web".into(),
            image: "docker.io/lib/nginx:1".parse().unwrap(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("PORT".into(), "8080".into())],
            grants: None,
            assurance_campaign: None,
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: MachineSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn a_persisted_machine_spec_without_grants_still_loads() {
        // Specs written before grants existed are on disk and in flight; the
        // field has to be optional in the wire form, not merely in the type.
        let legacy = r#"{"name":"web","image":"nginx","cpus":1,"memory_mib":512,"env":[]}"#;
        let spec: MachineSpec = serde_json::from_str(legacy).expect("legacy spec still loads");
        assert_eq!(spec.grants, None);
        // And a spec that grants nothing must round-trip back to that same
        // legacy shape, so writing one does not gratuitously change the bytes.
        assert_eq!(serde_json::to_string(&spec).unwrap(), legacy);
    }

    #[test]
    fn the_builder_expresses_an_egress_allow_list() {
        // The library surface's reason to exist: before this, a caller could
        // not ask for outbound access at all without shelling out to the CLI.
        let spec = MachineSpec::builder("web", "nginx")
            .expect("declared image parses")
            .cpu_millicores(1500)
            .allow_egress("api.example.com", 443)
            .allow_egress("db.internal", 5432)
            .build();
        let grants = spec.grants.expect("grants were authored");
        assert_eq!(
            grants.cpu,
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 })
        );
        let allow = &grants.egress.expect("egress authored").allow;
        assert_eq!(allow.len(), 2);
        assert_eq!(
            allow[0],
            crate::policy::network_policy::HostPort::new("api.example.com", 443)
        );
    }

    #[test]
    fn cpus_and_cpu_millicores_are_independent_controls() {
        // vCPU count and host CPU share are different questions; setting one
        // must not move the other.
        let spec = MachineSpec::builder("web", "nginx")
            .expect("declared image parses")
            .cpus(4)
            .cpu_millicores(500)
            .build();
        assert_eq!(spec.cpus, 4);
        assert_eq!(
            spec.grants.and_then(|g| g.cpu),
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 })
        );
    }

    #[test]
    fn builder_applies_defaults_and_overrides() {
        let spec = MachineSpec::builder("web", "nginx")
            .expect("declared image parses")
            .build();
        assert_eq!(
            spec,
            MachineSpec {
                name: "web".into(),
                image: "nginx".parse().unwrap(),
                cpus: 1,
                memory_mib: 512,
                env: vec![],
                grants: None,
                assurance_campaign: None,
            }
        );

        let spec = MachineSpec::builder("web", "nginx")
            .expect("declared image parses")
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
            .expect("declared image parses")
            .cpus(2)
            .memory_mib(512)
            .env("PORT", "8080")
            .build();
        let literal = MachineSpec {
            name: "web".into(),
            image: "docker.io/lib/nginx:1".parse().unwrap(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("PORT".into(), "8080".into())],
            grants: None,
            assurance_campaign: None,
        };
        assert_eq!(built, literal);
    }

    #[test]
    fn a_declaration_that_names_nothing_is_refused_at_construction() {
        // The property typing this field exists to add. A `String` here took
        // every one of these and handed the caller a spec that could not boot,
        // deferring the refusal to whichever backend eventually parsed it —
        // which for the mock backend was never.
        assert_eq!(
            MachineSpec::builder("web", "").unwrap_err(),
            RootfsSourceParseError::Empty
        );
        assert_eq!(
            MachineSpec::builder("web", "  \n ").unwrap_err(),
            RootfsSourceParseError::Empty
        );
        assert_eq!(
            MachineSpec::builder("web", "path:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload { scheme: "path:" }
        );
        assert_eq!(
            MachineSpec::builder("web", "oci:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload { scheme: "oci:" }
        );
    }

    #[test]
    fn a_declaration_that_names_nothing_is_refused_at_deserialization() {
        // Same refusal on the way in from a wire, where the caller is not a
        // Rust one and the builder cannot speak for them. `deny_unknown_fields`
        // already fails closed on a field nobody declared; this fails closed on
        // a declared field that says nothing.
        for image in ["", "   ", "path:", "oci:", "flake:"] {
            let json = format!(
                r#"{{"name":"web","image":{},"cpus":1,"memory_mib":512,"env":[]}}"#,
                serde_json::to_string(image).unwrap()
            );
            let err = serde_json::from_str::<MachineSpec>(&json)
                .expect_err("a declaration naming nothing must not deserialize");
            assert!(
                err.to_string().contains("rootfs source")
                    || err.to_string().contains("prefix with no value"),
                "{image:?} was refused for the wrong reason: {err}"
            );
        }
    }

    #[test]
    fn a_declaration_is_stored_as_the_value_it_names_not_the_bytes_that_carried_it() {
        // A pasted or command-substituted image arrives with whitespace around
        // it. With a `String` field the spec kept those bytes, so the value a
        // listing showed and the value that booted were different strings.
        let spec = MachineSpec::builder("web", "  alpine:3.20\n")
            .expect("declared image parses")
            .build();
        assert_eq!(
            spec.image,
            RootfsSource::Oci {
                image_ref: "alpine:3.20".to_string()
            }
        );
        // And it leaves as the same token a user would have typed, which is
        // what the SDKs forward as `--image`.
        assert_eq!(spec.image.to_string(), "alpine:3.20");
    }

    #[test]
    fn a_local_path_declaration_survives_the_wire_as_a_path() {
        // Typing the field must not quietly reclassify a path as a reference on
        // the way through serde — the two take different verification routes.
        let spec = MachineSpec::builder("web", "/var/lib/mvm/rootfs.ext4")
            .expect("declared image parses")
            .build();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(
            json.contains(r#""image":"/var/lib/mvm/rootfs.ext4""#),
            "path lost its plain form: {json}"
        );
        let back: MachineSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.image, spec.image);
        assert!(matches!(back.image, RootfsSource::LocalPath(_)));
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
    fn wire_label_matches_the_serde_form_for_every_variant() {
        for status in [
            MachineStatus::Starting,
            MachineStatus::Running,
            MachineStatus::Stopped,
            MachineStatus::Paused,
            MachineStatus::Failed,
        ] {
            let serde_form = serde_json::to_value(status).unwrap();
            assert_eq!(serde_form, status.wire_label(), "{status:?}");
        }
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

    #[test]
    fn pause_opts_default_is_off_with_120s_timeout() {
        let d = PauseOpts::default();
        assert!(!d.primed_barrier);
        assert_eq!(d.primed_timeout_secs, 120);
    }

    #[test]
    fn pause_opts_serde_round_trips_and_defaults_timeout() {
        let opts = PauseOpts {
            primed_barrier: true,
            primed_timeout_secs: 30,
        };
        let json = serde_json::to_string(&opts).unwrap();
        assert_eq!(serde_json::from_str::<PauseOpts>(&json).unwrap(), opts);
        // An omitted timeout falls back to the 120s default, not 0.
        let partial: PauseOpts = serde_json::from_str(r#"{"primed_barrier":true}"#).unwrap();
        assert_eq!(partial.primed_timeout_secs, 120);
    }

    #[test]
    fn pause_opts_rejects_unknown_field_fail_closed() {
        assert!(serde_json::from_str::<PauseOpts>(r#"{"rogue":true}"#).is_err());
    }

    #[test]
    fn pause_outcome_serde_round_trips() {
        let outcome = PauseOutcome {
            epoch: 7,
            vmstate_len: 4096,
            mem_len: 1 << 20,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert_eq!(
            serde_json::from_str::<PauseOutcome>(&json).unwrap(),
            outcome
        );
        assert_eq!(
            PauseOutcome::default(),
            PauseOutcome {
                epoch: 0,
                vmstate_len: 0,
                mem_len: 0
            }
        );
    }

    #[test]
    fn resume_opts_serde_round_trips_and_defaults_warm_off() {
        let opts = ResumeOpts { warm: true };
        let json = serde_json::to_string(&opts).unwrap();
        assert_eq!(serde_json::from_str::<ResumeOpts>(&json).unwrap(), opts);
        assert!(!ResumeOpts::default().warm);
        // Omitted `warm` defaults false.
        assert!(!serde_json::from_str::<ResumeOpts>("{}").unwrap().warm);
    }

    #[test]
    fn resume_opts_rejects_unknown_field_fail_closed() {
        assert!(serde_json::from_str::<ResumeOpts>(r#"{"rogue":true}"#).is_err());
    }
}
