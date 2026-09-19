//! The persisted machine spec a `machine run` produces.
//!
//! The CLI's `machine run` and the host library's launch express a run in
//! different forms, but they must persist the same spec for the same request:
//! the spec is what the plan is admitted from, so two builders are two plans.
//! [`RunSpec`] is the part of a run both express, and
//! [`RunSpec::into_machine_spec`] is the one place it becomes a spec. The CLI
//! then sets what only it can express (volume strings, a healthcheck, agent
//! verbs, a caller commitment).

use std::path::PathBuf;

use anyhow::Result;
use mvm_core::network_policy::NetworkPreset;
use mvm_runtime::machine::persist as mp;

use super::profile::RunProfile;
use crate::admission::run_grants::{GrantInputs, resolve_run_grants};
use crate::admission::run_network::{persisted_run_network, resolve_ai_policy};

/// Where a persistent machine boots from. Exactly one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunSource {
    /// An OCI image reference.
    Image(String),
    /// A built manifest slot or manifest reference.
    Manifest(String),
    /// A validated local deployment directory.
    Deployment(PathBuf),
    /// The verified runtime pack.
    RuntimePack,
    /// The direct-boot test path, whose kernel and rootfs come from the
    /// environment at start.
    DirectBoot,
}

/// The part of a `machine run` the CLI and the host library both express.
#[derive(Debug, Clone)]
pub struct RunSpec {
    name: String,
    source: RunSource,
    profile: RunProfile,
    cpus: u32,
    memory: String,
    ports: Vec<String>,
    net: bool,
    network_preset: Option<NetworkPreset>,
    allow_host: Vec<String>,
    peer: Vec<String>,
    cpu_limit_millicores: Option<u32>,
    timeout_secs: Option<u64>,
    grants_file: Option<PathBuf>,
    ai_token_budget: Option<u64>,
}

impl RunSpec {
    /// A run of `name` from `source` under `profile`, with one vCPU, 512 MiB,
    /// no ports, and no egress until something grants it.
    pub fn builder(name: impl Into<String>, source: RunSource, profile: RunProfile) -> Self {
        Self {
            name: name.into(),
            source,
            profile,
            cpus: 1,
            memory: "512M".to_string(),
            ports: Vec::new(),
            net: false,
            network_preset: None,
            allow_host: Vec::new(),
            peer: Vec::new(),
            cpu_limit_millicores: None,
            timeout_secs: None,
            grants_file: None,
            ai_token_budget: None,
        }
    }

    /// The vCPU count the guest sees.
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    /// Guest memory, in the human form a spec stores (`512M`, `2G`).
    #[must_use]
    pub fn memory(mut self, memory: impl Into<String>) -> Self {
        self.memory = memory.into();
        self
    }

    /// Loopback ingress mappings, each `HOST:GUEST` or a single port.
    #[must_use]
    pub fn ports(mut self, ports: Vec<String>) -> Self {
        self.ports = ports;
        self
    }

    /// The dev-tier egress preset (`--net`).
    #[must_use]
    pub fn net(mut self, net: bool) -> Self {
        self.net = net;
        self
    }

    /// A maintained egress preset.
    #[must_use]
    pub fn network_preset(mut self, preset: Option<NetworkPreset>) -> Self {
        self.network_preset = preset;
        self
    }

    /// Egress destinations, each `HOST[:PORT]`.
    #[must_use]
    pub fn allow_host(mut self, allow_host: Vec<String>) -> Self {
        self.allow_host = allow_host;
        self
    }

    /// Peer routes, each `NAME:PORT=ADDR:PORT`.
    #[must_use]
    pub fn peer(mut self, peer: Vec<String>) -> Self {
        self.peer = peer;
        self
    }

    /// A share of host CPU time, in millicores.
    #[must_use]
    pub fn cpu_limit_millicores(mut self, millicores: Option<u32>) -> Self {
        self.cpu_limit_millicores = millicores;
        self
    }

    /// A wall-clock bound, in seconds.
    #[must_use]
    pub fn timeout_secs(mut self, secs: Option<u64>) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// A JSON grants document.
    #[must_use]
    pub fn grants_file(mut self, path: Option<PathBuf>) -> Self {
        self.grants_file = path;
        self
    }

    /// An AI egress token budget.
    #[must_use]
    pub fn ai_token_budget(mut self, budget: Option<u64>) -> Self {
        self.ai_token_budget = budget;
        self
    }

    /// The spec this run persists. Grants are resolved against the operator's
    /// host config exactly as the CLI resolves them, and memory is validated.
    pub fn into_machine_spec(self) -> Result<mp::MachineSpec> {
        mvm_core::naming::validate_id(&self.name, "machine name")?;
        let (image, manifest, deployment, runtime_pack) = match self.source {
            RunSource::Image(image) => (Some(image), None, None, false),
            RunSource::Manifest(manifest) => (None, Some(manifest), None, false),
            RunSource::Deployment(path) => {
                let deployment = super::machine_start::resolve_local_deployment(&path)?;
                (
                    None,
                    None,
                    Some(deployment.directory.display().to_string()),
                    false,
                )
            }
            RunSource::RuntimePack => (None, None, None, true),
            RunSource::DirectBoot => (None, None, None, false),
        };
        let config = mvm_core::user_config::load(None);
        let ai = resolve_ai_policy(self.ai_token_budget);
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: self.cpu_limit_millicores,
            timeout_secs: self.timeout_secs,
            allow_host: &self.allow_host,
            peer: &self.peer,
            net: self.net,
            network_preset: self.network_preset,
            grants_file: self.grants_file.as_deref(),
            // A persistent run names its source directly and reads no project
            // manifest; `machine create` is the verb that sources a `[grants]`
            // table.
            manifest: None,
            config: &config,
            ai: ai.as_ref(),
        })?;
        let (net, allow_host) =
            persisted_run_network(self.net, self.network_preset, &self.allow_host);
        mp::validate_machine_memory(&self.memory, None)?;
        Ok(mp::MachineSpec {
            schema_version: mp::MACHINE_SPEC_SCHEMA_VERSION,
            name: self.name,
            image,
            manifest,
            deployment,
            resolved_digest: None,
            runtime_pack,
            net,
            allow_host,
            peer: Vec::new(),
            ai,
            ports: self.ports,
            cpus: self.cpus,
            memory: self.memory,
            mem_initial: None,
            profile: self.profile.as_str().to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            agent_verb: Vec::new(),
            caller_commitment: None,
            created_at: Some(mvm_core::time::utc_now()),
            last_started_at: None,
            health_check: None,
            grants: resolved.plan_grants,
        })
    }
}

/// Refuse a source the caller cannot name. Kept beside the builder so the
/// CLI's error for a run with no source is the one every surface gives.
pub fn missing_source(name: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "machine run needs `--image <ref>`, `--manifest <path>`, `--flake <path>`, `--deployment <dir>`, or \
         `--runtime-pack` to create machine {name:?}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use std::path::Path;

    fn isolated() -> (tempfile::TempDir, TestEnv) {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        (home, env)
    }

    #[test]
    fn an_image_run_persists_the_reference_profile_and_ports() {
        let (_home, _env) = isolated();
        let spec = RunSpec::builder(
            "web",
            RunSource::Image("alpine:3.20".into()),
            RunProfile::Dev,
        )
        .cpus(2)
        .memory("1G")
        .ports(vec!["8080:80".into()])
        .into_machine_spec()
        .unwrap();
        assert_eq!(spec.image.as_deref(), Some("alpine:3.20"));
        assert_eq!(spec.manifest, None);
        assert_eq!(spec.profile, "dev");
        assert_eq!(spec.cpus, 2);
        assert_eq!(spec.memory, "1G");
        assert_eq!(spec.ports, vec!["8080:80".to_string()]);
        assert!(
            !spec.net && spec.allow_host.is_empty(),
            "deny-all by default"
        );
    }

    #[test]
    fn a_manifest_run_persists_the_slot() {
        let (_home, _env) = isolated();
        let spec = RunSpec::builder(
            "tpl",
            RunSource::Manifest("abc123".into()),
            RunProfile::Standard,
        )
        .into_machine_spec()
        .unwrap();
        assert_eq!(spec.manifest.as_deref(), Some("abc123"));
        assert_eq!(spec.image, None);
    }

    /// An allow-list becomes an egress grant in the signed plan, not only a
    /// legacy field the plan never sees.
    #[test]
    fn an_allow_list_is_granted_not_only_recorded() {
        let (_home, _env) = isolated();
        let spec = RunSpec::builder(
            "web",
            RunSource::Image("alpine:3.20".into()),
            RunProfile::Standard,
        )
        .allow_host(vec!["api.example.com:443".into()])
        .into_machine_spec()
        .unwrap();
        assert_eq!(spec.allow_host, vec!["api.example.com:443".to_string()]);
        let grants = spec.grants.expect("an allow-list is a grant");
        assert!(grants.egress.is_some(), "{grants:?}");
    }

    #[test]
    fn an_invalid_name_or_memory_is_refused() {
        let (_home, _env) = isolated();
        let bad_name = RunSpec::builder("Not Valid", RunSource::RuntimePack, RunProfile::Standard);
        assert!(bad_name.into_machine_spec().is_err());
        let bad_memory =
            RunSpec::builder("web", RunSource::RuntimePack, RunProfile::Standard).memory("lots");
        assert!(bad_memory.into_machine_spec().is_err());
    }

    #[test]
    fn a_missing_deployment_is_refused() {
        let (_home, _env) = isolated();
        let run = RunSpec::builder(
            "d",
            RunSource::Deployment(Path::new("/definitely/not/here").to_path_buf()),
            RunProfile::Standard,
        );
        assert!(run.into_machine_spec().is_err());
    }
}
