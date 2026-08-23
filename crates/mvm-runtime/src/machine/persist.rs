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
use mvm_core::network_policy::AiPolicy;
use serde::{Deserialize, Serialize};

use mvm_core::atomic_io::atomic_write;
use mvm_core::util::parse_human_size;
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
    /// Local attested deployment directory containing `deploy.json` and
    /// `rootfs.ext4`. Present for machines created with `--deployment`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_digest: Option<String>,
    /// Boot from the verified downloadable runtime pack instead of an OCI
    /// image or a manifest slot. Mutually exclusive with `image`/`manifest`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub runtime_pack: bool,
    pub net: bool,
    pub allow_host: Vec<String>,
    /// Optional AI egress metering/budget policy, carried from the manifest's
    /// `[network.ai]` table so the policy survives across machine starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<AiPolicy>,
    /// Declared loopback ingress mappings (`HOST:GUEST`). These are persisted
    /// so the backend can pre-open only the corresponding vsock channels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    pub cpus: u32,
    pub memory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_initial: Option<String>,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init: Vec<String>,
    /// Explicit agent verb allowlist from `--agent-verb`. Empty ⇒ use the
    /// computed sealed-prod default at each start.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_verb: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_started_at: Option<String>,
    /// Liveness check declared via `--healthcheck` at `machine run` time.
    /// Recorded for inspection now; consumed by active probing later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<mvm_contract::ir::HealthCheck>,
    /// The permission set resolved when this machine was created, baked into
    /// the signed plan on every start. `None` means nothing was granted, which
    /// is also what every machine created before grants existed carries —
    /// hence `#[serde(default)]`, without which those specs stop loading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<mvm_contract::grants::Grants>,
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
             or `mvmctl machine create {name} --image <ref>` to create one."
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

// ---------------------------------------------------------------------------
// Config comparison, reconciliation, patch, and memory validation
// ---------------------------------------------------------------------------

/// Two specs share a launch config when every boot-affecting field matches.
/// Runtime metadata (resolved digest, timestamps) is deliberately excluded —
/// it changes on every start and must not trigger a collision.
pub fn machine_config_matches(a: &MachineSpec, b: &MachineSpec) -> bool {
    a.image == b.image
        && a.manifest == b.manifest
        && a.deployment == b.deployment
        && a.runtime_pack == b.runtime_pack
        && a.net == b.net
        && a.allow_host == b.allow_host
        && a.ports == b.ports
        && a.cpus == b.cpus
        && a.memory == b.memory
        && a.mem_initial == b.mem_initial
        && a.profile == b.profile
        && a.volumes == b.volumes
        && a.init == b.init
        && a.agent_verb == b.agent_verb
        && a.grants == b.grants
}

/// Human summary of which boot-affecting fields differ, for the loud
/// "config changed, recreating" notice. Mirrors [`machine_config_matches`].
pub fn machine_config_diff(current: &MachineSpec, desired: &MachineSpec) -> String {
    let mut changed = Vec::new();
    // `image` and `manifest` are mutually-exclusive sources; report either as a
    // single "source" change. `machine_config_matches` already compares both, so
    // without this a manifest-only swap recreates with an empty `changed` list.
    if current.image != desired.image
        || current.manifest != desired.manifest
        || current.deployment != desired.deployment
        || current.runtime_pack != desired.runtime_pack
    {
        changed.push("source");
    }
    if current.net != desired.net {
        changed.push("net");
    }
    if current.allow_host != desired.allow_host {
        changed.push("allow-host");
    }
    if current.ports != desired.ports {
        changed.push("ports");
    }
    if current.cpus != desired.cpus {
        changed.push("cpus");
    }
    if current.memory != desired.memory || current.mem_initial != desired.mem_initial {
        changed.push("memory");
    }
    if current.profile != desired.profile {
        changed.push("profile");
    }
    if current.volumes != desired.volumes {
        changed.push("volumes");
    }
    if current.init != desired.init {
        changed.push("init");
    }
    if current.agent_verb != desired.agent_verb {
        changed.push("agent-verb");
    }
    // A changed permission set is a changed launch: the running VM was
    // admitted under the old one, so reusing it would leave the machine
    // running under bounds nobody asked for any more.
    if current.grants != desired.grants {
        changed.push("grants");
    }
    changed.join(", ")
}

/// What the persistent path should do with the on-disk spec for the target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecReconcile {
    /// No spec on disk — write `desired` and boot.
    Create,
    /// A spec with the same launch config already exists — keep it.
    Reuse,
    /// A spec with a different config exists — stop the old instance, overwrite,
    /// and reboot. `changed` is a human summary of the differing fields for the
    /// loud notice.
    Recreate { changed: String },
}

/// Decide how to reconcile a desired spec against what's on disk. A
/// same-config spec is reused; a different-config spec **auto-recreates**
/// (the caller stops the old instance, overwrites the spec, and reboots) so a
/// config change converges like `compose up`. The machine is cattle —
/// durable data belongs in `--volume` host shares, which live on the host and
/// survive the recreate. The recreate is announced loudly by the caller (never
/// silent) so an unintended clobber (e.g. a typo'd `--image`) is observable.
pub fn reconcile_machine_spec(
    existing: Option<&MachineSpec>,
    desired: &MachineSpec,
    force: bool,
) -> Result<SpecReconcile> {
    match existing {
        None => Ok(SpecReconcile::Create),
        Some(current) if machine_config_matches(current, desired) => Ok(SpecReconcile::Reuse),
        Some(current) if force => Ok(SpecReconcile::Recreate {
            changed: machine_config_diff(current, desired),
        }),
        Some(_) => bail!(
            "machine {:?} exists with a different config; pass --force to recreate, \
             or use a different name",
            desired.name
        ),
    }
}

/// A resolved patch over the reconfigurable `MachineSpec` fields. `None`
/// means "leave unchanged".
pub struct ReconfigurePatch {
    pub net: Option<bool>,
    pub allow_host: Option<Vec<String>>,
    pub cpus: Option<u32>,
    pub memory: Option<String>,
    pub mem_initial: Option<String>,
}

/// Apply the patch: each `Some` overrides the corresponding field; the
/// rest of `spec` is inherited unchanged.
pub fn apply_patch(mut spec: MachineSpec, patch: &ReconfigurePatch) -> MachineSpec {
    if let Some(v) = patch.net {
        spec.net = v;
    }
    if let Some(v) = &patch.allow_host {
        spec.allow_host = v.clone();
    }
    if let Some(v) = patch.cpus {
        spec.cpus = v;
    }
    if let Some(v) = &patch.memory {
        spec.memory = v.clone();
    }
    if let Some(v) = &patch.mem_initial {
        spec.mem_initial = Some(v.clone());
    }
    spec
}

/// Validate the `--memory` / `--mem-initial` pair using the same parser as
/// the run path. Returns `(memory_mib, mem_initial_mib)`.
pub fn validate_machine_memory(
    memory: &str,
    mem_initial: Option<&str>,
) -> Result<(u32, Option<u32>)> {
    let memory_mib = parse_human_size(memory).context("invalid machine memory")?;
    let mem_initial_mib = match mem_initial {
        Some(value) => {
            let parsed = parse_human_size(value).context("invalid machine mem_initial")?;
            if parsed == 0 {
                bail!("machine mem_initial must be > 0 when set");
            }
            if parsed >= memory_mib {
                bail!(
                    "machine mem_initial ({parsed} MiB) must be strictly less than memory ({memory_mib} MiB)"
                );
            }
            Some(parsed)
        }
        None => None,
    };
    Ok((memory_mib, mem_initial_mib))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    struct IsolatedMachineState {
        _lock: std::sync::MutexGuard<'static, ()>,
        _env: TestEnv,
        _tmp: tempfile::TempDir,
    }

    impl IsolatedMachineState {
        fn new() -> Self {
            let lock = crate::vm::DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut env = TestEnv::new();
            let tmp = tempfile::tempdir().expect("tempdir");
            env.set("MVM_HOME", tmp.path());
            Self {
                _lock: lock,
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
            deployment: None,
            resolved_digest: None,
            runtime_pack: false,
            net: false,
            allow_host: vec![],
            ai: None,
            ports: vec![],
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: vec![],
            init: vec![],
            agent_verb: vec![],
            created_at: None,
            last_started_at: None,
            health_check: None,
            grants: None,
        }
    }

    #[test]
    fn a_persisted_machine_spec_without_grants_still_loads() {
        // Machines created before grants existed are on disk right now. The
        // struct is `deny_unknown_fields`, so the *absence* of the new key has
        // to be accepted explicitly or every one of them stops starting.
        let legacy = serde_json::json!({
            "schema_version": MACHINE_SPEC_SCHEMA_VERSION,
            "name": "web",
            "image": "alpine:latest",
            "net": false,
            "allow_host": [],
            "cpus": 2,
            "memory": "512M",
            "profile": "standard",
        })
        .to_string();
        let spec: MachineSpec =
            serde_json::from_str(&legacy).expect("a pre-grants spec still loads");
        assert_eq!(spec.grants, None);
        // And a spec that granted nothing must not start emitting the key, so
        // rewriting an old spec does not gratuitously change its bytes.
        assert!(!serde_json::to_string(&spec).unwrap().contains("grants"));
    }

    #[test]
    fn ai_policy_round_trips_through_json_and_skips_when_absent() {
        let mut spec = spec_fixture("web");
        spec.ai = Some(mvm_core::network_policy::AiPolicy::metered_with_total_budget(50_000));
        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: MachineSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.ai, spec.ai);

        let no_ai = spec_fixture("web");
        let json = serde_json::to_string(&no_ai).expect("serialize");
        assert!(
            !json.contains("\"ai\""),
            "absent ai must be omitted from JSON"
        );
    }

    #[test]
    fn a_changed_grant_is_a_changed_launch_config() {
        // The running VM was admitted under the old permission set; reusing it
        // would leave it running under bounds nobody asked for any more.
        let current = spec_fixture("web");
        let mut desired = current.clone();
        desired.grants = Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        });
        assert!(!machine_config_matches(&current, &desired));
        assert!(machine_config_diff(&current, &desired).contains("grants"));
    }

    #[test]
    fn machine_spec_roundtrips_health_check() {
        let mut spec = spec_fixture("web");
        spec.health_check = Some(mvm_contract::ir::HealthCheck {
            command: vec!["/bin/sh".into(), "-lc".into(), "true".into()],
            interval_secs: 30,
            timeout_secs: 5,
            retries: 3,
            start_period_secs: 0,
        });
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(spec, serde_json::from_str::<MachineSpec>(&json).unwrap());

        // Absent healthcheck skip-serializes (old spec files stay readable).
        let bare = spec_fixture("bare");
        assert!(
            !serde_json::to_string(&bare)
                .unwrap()
                .contains("health_check")
        );
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
        assert!(spec.deployment.is_none());
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

    // ---------------------------------------------------------------------------
    // Tests for config-diff / reconcile / patch / memory-validation
    // ---------------------------------------------------------------------------

    /// A fixture with a volume so patch tests can confirm it is preserved.
    fn reconfigure_spec_fixture() -> MachineSpec {
        MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".into(),
            image: Some("img:1".into()),
            manifest: None,
            deployment: None,
            resolved_digest: None,
            runtime_pack: false,
            net: false,
            allow_host: vec![],
            ai: None,
            ports: vec![],
            cpus: 2,
            memory: "512M".into(),
            mem_initial: None,
            profile: "standard".into(),
            volumes: vec!["/data:/data:ro".into()],
            init: vec![],
            agent_verb: vec![],
            created_at: None,
            last_started_at: None,
            health_check: None,
            grants: None,
        }
    }

    #[test]
    fn config_match_ignores_runtime_metadata_but_not_launch_config() {
        let mut a = spec_fixture("web");
        let mut b = spec_fixture("web");
        // Runtime metadata differs — still the same launch config.
        a.resolved_digest = Some("sha256:aaa".to_string());
        a.created_at = Some("t0".to_string());
        b.last_started_at = Some("t1".to_string());
        assert!(machine_config_matches(&a, &b));
        // A launch-config field differs — no longer a match.
        b.cpus = 4;
        assert!(!machine_config_matches(&a, &b));
    }

    #[test]
    fn reconcile_creates_reuses_and_force_recreates_on_config_change() {
        let desired = spec_fixture("web");

        assert_eq!(
            reconcile_machine_spec(None, &desired, false).expect("create"),
            SpecReconcile::Create
        );

        let same = spec_fixture("web");
        assert_eq!(
            reconcile_machine_spec(Some(&same), &desired, false).expect("reuse"),
            SpecReconcile::Reuse
        );

        // A different config is force-gated: error without --force, recreate with.
        let mut different = spec_fixture("web");
        different.image = Some("ubuntu:24.04".to_string());
        different.cpus += 1;
        // A different config errors without --force, and recreates (reporting
        // what changed) with it.
        let err = reconcile_machine_spec(Some(&different), &desired, false)
            .expect_err("different config errors without --force");
        assert!(err.to_string().contains("different config"), "msg: {err}");
        match reconcile_machine_spec(Some(&different), &desired, true).expect("recreate") {
            SpecReconcile::Recreate { changed } => {
                assert!(changed.contains("source"), "changed: {changed}");
                assert!(changed.contains("cpus"), "changed: {changed}");
            }
            other => panic!("expected Recreate, got {other:?}"),
        }
    }

    #[test]
    fn config_diff_names_a_manifest_only_source_change() {
        // A manifest-only swap (no image) must be named — `machine_config_matches`
        // compares `manifest`, so without this the recreate notice would be empty.
        let mut current = spec_fixture("web");
        current.image = None;
        current.manifest = Some("slot-aaaa".to_string());
        let mut desired = spec_fixture("web");
        desired.image = None;
        desired.manifest = Some("slot-bbbb".to_string());
        let changed = machine_config_diff(&current, &desired);
        assert!(changed.contains("source"), "changed: {changed}");
    }

    #[test]
    fn config_diff_reports_deployment_source_change() {
        let current = spec_fixture("web");
        let mut desired = spec_fixture("web");
        desired.image = None;
        desired.deployment = Some("/tmp/deployment".to_string());
        let changed = machine_config_diff(&current, &desired);
        assert!(changed.contains("source"), "changed: {changed}");
        assert!(!machine_config_matches(&current, &desired));
    }

    #[test]
    fn config_match_false_when_only_runtime_pack_differs() {
        let a = spec_fixture("web");
        let mut b = spec_fixture("web");
        b.runtime_pack = true;
        assert!(!machine_config_matches(&a, &b));
    }

    #[test]
    fn config_diff_reports_source_for_runtime_pack_flip() {
        let current = spec_fixture("web");
        let mut desired = spec_fixture("web");
        desired.runtime_pack = true;
        let changed = machine_config_diff(&current, &desired);
        assert!(changed.contains("source"), "changed: {changed}");
    }

    #[test]
    fn spec_serde_roundtrip_with_runtime_pack_true() {
        let mut spec = spec_fixture("web");
        spec.runtime_pack = true;
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"runtime_pack\":true"), "json: {json}");
        assert_eq!(spec, serde_json::from_str::<MachineSpec>(&json).unwrap());

        // Default `false` skip-serializes (old spec files stay readable, and
        // a no-op field doesn't bloat every persisted spec).
        let bare = spec_fixture("bare");
        assert!(
            !serde_json::to_string(&bare)
                .unwrap()
                .contains("runtime_pack")
        );
    }

    #[test]
    fn apply_patch_overrides_only_set_fields_and_preserves_rest() {
        // Construct patch directly (patch_from_args stays in mvm-cli; ported
        // here as a direct struct construction so the apply_patch logic is
        // exercised without the clap layer).
        let patch = ReconfigurePatch {
            net: None,
            allow_host: None,
            cpus: Some(8),
            memory: None,
            mem_initial: None,
        };
        let out = apply_patch(reconfigure_spec_fixture(), &patch);
        assert_eq!(out.cpus, 8);
        // Everything else preserved.
        assert_eq!(out.memory, "512M");
        assert_eq!(out.volumes, vec!["/data:/data:ro".to_string()]);
        assert!(!out.net);
    }

    #[test]
    fn apply_patch_no_flags_is_noop() {
        let patch = ReconfigurePatch {
            net: None,
            allow_host: None,
            cpus: None,
            memory: None,
            mem_initial: None,
        };
        assert_eq!(
            apply_patch(reconfigure_spec_fixture(), &patch),
            reconfigure_spec_fixture()
        );
    }

    #[test]
    fn apply_patch_allow_host_replace_and_clear() {
        // Replace: Some(vec) overrides the allow_host field.
        let patch = ReconfigurePatch {
            net: None,
            allow_host: Some(vec!["a:443".into()]),
            cpus: None,
            memory: None,
            mem_initial: None,
        };
        let out = apply_patch(reconfigure_spec_fixture(), &patch);
        assert_eq!(out.allow_host, vec!["a:443".to_string()]);

        // Clear: Some(vec![]) empties the list.
        let base = MachineSpec {
            allow_host: vec!["old:443".into()],
            ai: None,
            ..reconfigure_spec_fixture()
        };
        let clear_patch = ReconfigurePatch {
            net: None,
            allow_host: Some(vec![]),
            cpus: None,
            memory: None,
            mem_initial: None,
        };
        let out = apply_patch(base, &clear_patch);
        assert!(out.allow_host.is_empty());
    }

    #[test]
    fn validate_machine_memory_rejects_invalid_size() {
        assert!(validate_machine_memory("notasize", None).is_err());
    }

    #[test]
    fn validate_machine_memory_rejects_mem_initial_ge_memory() {
        // mem_initial must be strictly less than memory.
        assert!(validate_machine_memory("512M", Some("1G")).is_err());
        assert!(validate_machine_memory("512M", Some("512M")).is_err());
    }

    #[test]
    fn validate_machine_memory_accepts_valid_pair() {
        let (mem, mem_initial) = validate_machine_memory("1G", Some("256M")).expect("valid pair");
        assert_eq!(mem, 1024);
        assert_eq!(mem_initial, Some(256));
    }

    #[test]
    fn validate_machine_memory_none_initial_is_ok() {
        let (mem, mem_initial) = validate_machine_memory("512M", None).expect("no initial");
        assert_eq!(mem, 512);
        assert!(mem_initial.is_none());
    }
}
