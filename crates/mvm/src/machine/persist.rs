//! On-disk persistent machine spec and its accessors.
//!
//! This module owns the `MachineSpec` that is stored at
//! `~/.mvm/machines/<name>/machine.json` and the functions that read and write
//! it.  It is intentionally distinct from the *builder* `MachineSpec` in the
//! parent `mod.rs`, which is the in-memory construction abstraction used by the
//! CLI, mvmd, and the SDKs.  The two types serve different layers: this one is
//! the on-disk declarative record; the parent one is the validated, in-process
//! description of a workload.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use mvm_core::atomic_io::atomic_write;
use mvm_core::{config, naming};

/// Schema version stored in every `machine.json`.  Bump only if a breaking
/// field change is introduced; new optional fields use `#[serde(default)]`.
pub const MACHINE_SPEC_SCHEMA_VERSION: u32 = 1;

/// Declarative persistent machine spec. Runtime state lives elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub schema_version: u32,
    pub name: String,
    /// OCI image reference. Present for image-backed machines.
    /// Absent for manifest-backed machines (`manifest` is set instead).
    /// Kept optional to remain deserializable from old spec files that
    /// always serialised `image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Pre-built manifest slot hash or path. Present when the machine was
    /// created with `--manifest` or (after a build) `--flake`. Absent for
    /// image-backed machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_digest: Option<String>,
    pub net: bool,
    pub allow_host: Vec<String>,
    pub cpus: u32,
    pub memory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_initial: Option<String>,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ssh_agent: bool,
    /// Explicit agent verb allowlist from `--agent-verb`. Empty ⇒ use the
    /// computed sealed-prod default at each start.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_verb: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_started_at: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Persist `spec` to disk. Fails if the spec already exists and `force` is
/// `false`.
pub fn save_machine_spec(spec: &MachineSpec, force: bool) -> Result<()> {
    let path = config::machine_spec_path(&spec.name);
    if path.exists() && !force {
        bail!(
            "machine {:?} already exists; pass --force to overwrite",
            spec.name
        );
    }
    let bytes = serde_json::to_vec_pretty(spec).context("serializing machine spec")?;
    atomic_write(&path, &bytes)
        .with_context(|| format!("writing machine spec {}", path.display()))?;
    Ok(())
}

/// Overwrite an existing spec unconditionally (no `force` flag required).
pub fn overwrite_machine_spec(spec: &MachineSpec) -> Result<()> {
    let path = config::machine_spec_path(&spec.name);
    let bytes = serde_json::to_vec_pretty(spec).context("serializing machine spec")?;
    atomic_write(&path, &bytes)
        .with_context(|| format!("writing machine spec {}", path.display()))?;
    Ok(())
}

/// Load the spec for `name` from `~/.mvm/machines/<name>/machine.json`.
///
/// Returns a clear actionable error when the machine does not exist rather than
/// leaking the internal file path.
pub fn load_machine_spec(name: &str) -> Result<MachineSpec> {
    naming::validate_id(name, "machine name")?;
    let path = config::machine_spec_path(name);
    if !path.exists() {
        // A missing spec is the common beginner error (typo'd name, or the
        // machine was never created). Give an actionable message with the two
        // recovery verbs instead of leaking the internal `machine.json` path
        // through a raw `No such file or directory`.
        bail!(
            "machine {name:?} does not exist. \
             Run `mvmctl machine ls` to list machines, \
             or `mvmctl machine create --name {name} --image <ref>` to create one."
        );
    }
    load_machine_spec_from_path(&path)
}

/// Load a spec directly from `path` (no name validation).
pub fn load_machine_spec_from_path(path: &Path) -> Result<MachineSpec> {
    let bytes =
        fs::read(path).with_context(|| format!("reading machine spec {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing machine spec {}", path.display()))
}

/// Return all persisted machine specs, sorted by name.
pub fn list_machine_specs() -> Result<Vec<MachineSpec>> {
    let root = config::machine_state_root();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut specs = Vec::new();
    for entry in fs::read_dir(&root).with_context(|| format!("listing {}", root.display()))? {
        let entry = entry.with_context(|| format!("reading entry in {}", root.display()))?;
        if !entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?
            .is_dir()
        {
            continue;
        }
        let spec_path = entry.path().join("machine.json");
        if spec_path.exists() {
            specs.push(load_machine_spec_from_path(&spec_path)?);
        }
    }
    specs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    struct IsolatedMachineState {
        _env: TestEnv,
        _tmp: tempfile::TempDir,
    }

    impl IsolatedMachineState {
        fn new() -> Self {
            let mut env = TestEnv::new();
            let tmp = tempfile::tempdir().expect("tempdir");
            env.set("MVM_DATA_DIR", tmp.path());
            Self {
                _env: env,
                _tmp: tmp,
            }
        }
    }

    fn spec_fixture(name: &str) -> MachineSpec {
        MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: Some("alpine:latest".to_string()),
            manifest: None,
            resolved_digest: None,
            net: false,
            allow_host: vec![],
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: vec![],
            init: vec![],
            ssh_agent: false,
            agent_verb: vec![],
            created_at: None,
            last_started_at: None,
        }
    }

    #[test]
    fn spec_serde_roundtrip() {
        let spec = spec_fixture("web");
        let bytes = serde_json::to_vec_pretty(&spec).expect("serialize");
        let loaded: MachineSpec = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(loaded, spec);
    }

    #[test]
    fn spec_optional_fields_default_when_absent() {
        // Fields with `#[serde(default)]` must deserialize gracefully when the
        // key is absent from an older spec file.
        let json = br#"{
          "schema_version": 1,
          "name": "other",
          "image": "alpine:latest",
          "net": false,
          "allow_host": [],
          "cpus": 2,
          "memory": "512M",
          "profile": "standard"
        }"#;
        let spec: MachineSpec = serde_json::from_slice(json).expect("deserialize old spec");
        assert!(
            spec.agent_verb.is_empty(),
            "agent_verb should default empty"
        );
        assert!(!spec.ssh_agent, "ssh_agent should default false");
        assert!(spec.volumes.is_empty(), "volumes should default empty");
        assert!(spec.init.is_empty(), "init should default empty");
        assert!(spec.created_at.is_none());
        assert!(spec.last_started_at.is_none());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let _state = IsolatedMachineState::new();
        let spec = spec_fixture("web");
        save_machine_spec(&spec, false).expect("save");
        let loaded = load_machine_spec("web").expect("load");
        assert_eq!(loaded, spec);
        assert_eq!(loaded.schema_version, MACHINE_SPEC_SCHEMA_VERSION);
    }

    #[test]
    fn save_refuses_overwrite_without_force() {
        let _state = IsolatedMachineState::new();
        let spec = spec_fixture("web");
        save_machine_spec(&spec, false).expect("first save");
        let err = save_machine_spec(&spec, false).expect_err("overwrite rejected");
        assert!(err.to_string().contains("already exists"));
        // Force flag allows overwrite.
        save_machine_spec(&spec, true).expect("force overwrites");
    }

    #[test]
    fn overwrite_spec_unconditionally() {
        let _state = IsolatedMachineState::new();
        let mut spec = spec_fixture("web");
        save_machine_spec(&spec, false).expect("initial save");
        spec.cpus = 8;
        overwrite_machine_spec(&spec).expect("overwrite");
        let loaded = load_machine_spec("web").expect("load");
        assert_eq!(loaded.cpus, 8);
    }

    #[test]
    fn load_missing_machine_gives_actionable_error() {
        let _state = IsolatedMachineState::new();
        let err = load_machine_spec("nonexistent").expect_err("missing machine");
        let msg = err.to_string();
        assert!(msg.contains("does not exist"), "message: {msg}");
        assert!(msg.contains("mvmctl machine ls"), "hints ls: {msg}");
        assert!(msg.contains("mvmctl machine create"), "hints create: {msg}");
    }

    #[test]
    fn inspect_rejects_unknown_spec_fields() {
        let _state = IsolatedMachineState::new();
        let path = config::machine_spec_path("web");
        atomic_write(
            &path,
            br#"{
              "schema_version": 1,
              "name": "web",
              "image": "alpine:latest",
              "resolved_digest": null,
              "net": false,
              "allow_host": [],
              "cpus": 2,
              "memory": "512M",
              "profile": "standard",
              "created_at": "2026-06-18T00:00:00Z",
              "last_started_at": null,
              "unexpected": true
            }"#,
        )
        .expect("write");
        let err = load_machine_spec("web").expect_err("unknown field rejected");
        assert!(err.to_string().contains("parsing machine spec"));
    }

    #[test]
    fn list_machine_specs_returns_sorted_specs() {
        let _state = IsolatedMachineState::new();
        for name in ["zeta", "alpha"] {
            let spec = spec_fixture(name);
            save_machine_spec(&spec, false).expect("save");
        }
        let names = list_machine_specs()
            .expect("list")
            .into_iter()
            .map(|spec| spec.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn list_machine_specs_empty_when_no_root() {
        let _state = IsolatedMachineState::new();
        // Root dir doesn't exist yet — must return empty, not error.
        let specs = list_machine_specs().expect("list empty");
        assert!(specs.is_empty());
    }
}
