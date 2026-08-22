//! Canonical host-wide machine inventory for CLI and non-CLI consumers.
//!
//! Home of the persisted-spec × live-backend join: three stores describe a
//! microVM and none of them is complete on its own — the persisted spec
//! registry (a machine the user created by name), the live backend scan
//! joined with the VM name registry (what is actually booted), and the
//! per-VM state dirs underneath both. This module joins them into one typed
//! [`MachineInventoryRecord`] stream so `mvmctl machine ls` and local UI
//! surfaces such as mvm-studio consume identical semantics instead of
//! assembling their own.
//!
//! The record contract and visibility semantics live in the client DTO layer
//! ([`mvm_core::client::inventory`], re-exported here); this module adds the
//! join, the fail-closed posture resolution, and the local collection that
//! composes any [`MvmClient`] with the on-disk spec registry.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use mvm_core::client::dto::{MachineFilter, MachineId, MachineState, MachineStatus};
use mvm_core::client::{MvmClient, MvmError, Result};
use mvm_runtime::machine::persist::{self, MachineSpec as PersistedMachineSpec};

pub use mvm_core::client::inventory::{
    InventoryQuery, MachineInventoryRecord, MachineInventoryRecordBuilder, MachineKind,
    VolumeAttachment, VolumeAttachmentKind, WorkloadPosture,
};

/// Resolve a machine's dev/prod posture the same way the boot-time SDK
/// envelope does, fail-closed: a manifest-backed machine reads its template
/// revision's recorded build mode; otherwise the per-VM runtime metadata's
/// `accessible` flag is the only thing that can open dev. Anything missing,
/// unreadable, or unknown is production.
pub fn resolve_workload_posture(manifest: Option<&str>, name: &str) -> WorkloadPosture {
    if let Some(manifest) = manifest {
        let slot_name = manifest
            .trim_end_matches('/')
            .split('/')
            .next_back()
            .unwrap_or(manifest);
        if let Ok(Some(revision)) =
            mvm_runtime::vm::template::lifecycle::template_load_current_revision(slot_name)
        {
            return WorkloadPosture::from_label(revision.build_mode.as_deref().unwrap_or("prod"));
        }
    }
    match mvm_runtime::vm::runtime_meta::read(name) {
        Ok(Some(meta)) if meta.accessible => WorkloadPosture::Dev,
        _ => WorkloadPosture::Prod,
    }
}

/// Summarize one persisted volume spec (`host:guest[:ro|rw]` dir share or
/// `host:guest:SIZE[:ro|rw][:enc]` disk) for the inventory record. The host
/// path is deliberately dropped — the record never carries host filesystem
/// locations. Tolerant by design: a malformed spec degrades to an empty
/// guest mount rather than failing the listing; strict validation stays at
/// the admission choke point that materializes volumes.
pub fn summarize_volume_spec(raw: &str) -> VolumeAttachment {
    let mut parts = raw.split(':');
    let _host = parts.next();
    let guest_mount = parts.next().unwrap_or("").to_string();
    let mut read_only = false;
    let mut encrypted = false;
    let mut kind = VolumeAttachmentKind::DirShare;
    for token in parts {
        match token.to_ascii_lowercase().as_str() {
            "ro" => read_only = true,
            "rw" => read_only = false,
            "enc" => encrypted = true,
            "" => {}
            // Any other token is the size slot, which only disks carry.
            _ => kind = VolumeAttachmentKind::Disk,
        }
    }
    VolumeAttachment {
        guest_mount,
        kind,
        read_only,
        encrypted,
    }
}

/// Join the two stores by name: every persisted spec becomes a persistent
/// record (carrying its live state when booted), and every live VM left over
/// is transient. Persistent records come first, each block name-sorted, so
/// the listing is stable and the two kinds read as groups. `posture`
/// resolves the dev/prod posture per record — pass
/// [`resolve_workload_posture`] on a live host, or a stub in tests.
///
/// Builder VMs are dropped from the spec-less remainder. The HVF builder
/// family writes its runtime state into `~/.mvm/vms/` alongside workload
/// machines, so the live scan finds a running `nix build` and, having no spec
/// to join it to, was presenting it as a transient machine the user owned —
/// with every spec-derived column blank and every spec-requiring verb
/// (`shell`, `inspect`, `rm`) refusing the name it had just printed. A spec
/// with a builder-shaped name is still listed: that one the user did create.
pub fn join_inventory(
    specs: Vec<PersistedMachineSpec>,
    live: Vec<MachineState>,
    posture: impl Fn(Option<&str>, &str) -> WorkloadPosture,
) -> Vec<MachineInventoryRecord> {
    let mut by_name = dedup_live_by_name(live);

    let mut persistent: Vec<MachineInventoryRecord> = specs
        .into_iter()
        .map(|spec| {
            let live = by_name.remove(&spec.name);
            let posture = posture(spec.manifest.as_deref(), &spec.name);
            persistent_record(spec, live, posture)
        })
        .collect();
    persistent.sort_by(|a, b| a.name.cmp(&b.name));

    // Whatever the spec registry did not claim is running without a spec.
    let transient = by_name
        .into_values()
        .filter(|state| !mvm_core::naming::is_builder_owned_vm_name(&state.name))
        .map(|state| {
            let posture = posture(None, &state.name);
            transient_record(state, posture)
        });

    persistent.into_iter().chain(transient).collect()
}

/// Collapse duplicate live rows onto one entry per name. A non-stopped row
/// wins over a stopped duplicate (a stale stopped registry row must never
/// mask the actually-running VM); otherwise the later-listed row wins, so
/// the fold is deterministic.
fn dedup_live_by_name(live: Vec<MachineState>) -> BTreeMap<String, MachineState> {
    let mut by_name: BTreeMap<String, MachineState> = BTreeMap::new();
    for state in live {
        match by_name.entry(state.name.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(state);
            }
            Entry::Occupied(mut slot) => {
                let keep_existing = slot.get().status != MachineStatus::Stopped
                    && state.status == MachineStatus::Stopped;
                if !keep_existing {
                    slot.insert(state);
                }
            }
        }
    }
    by_name
}

/// Guest memory in MiB declared by the spec; `0` when unparseable (the
/// listing must not fail on a hand-edited spec file).
fn spec_memory_mib(spec: &PersistedMachineSpec) -> u32 {
    mvm_core::util::parse_human_size(&spec.memory).unwrap_or(0)
}

/// Build the record for a persisted definition, folding in its live state
/// when booted. Declared resources back-fill anything the live row does not
/// know (a stopped machine reports `0` from the backend).
fn persistent_record(
    spec: PersistedMachineSpec,
    live: Option<MachineState>,
    posture: WorkloadPosture,
) -> MachineInventoryRecord {
    let source = spec
        .image
        .clone()
        .or_else(|| spec.manifest.clone())
        .or_else(|| live.as_ref().and_then(live_source));
    let volumes = spec
        .volumes
        .iter()
        .map(|raw| summarize_volume_spec(raw))
        .collect();

    let mut builder = MachineInventoryRecord::builder(&spec.name, MachineKind::Persistent)
        .build_mode(posture)
        .source(source)
        .cpus(spec.cpus)
        .memory_mib(spec_memory_mib(&spec))
        .created_at(spec.created_at)
        .last_started_at(spec.last_started_at)
        .volumes(volumes)
        // The pure join carries no host reach; the local composition
        // back-fills the real count from the machine's `secret-refs.json`
        // sidecar via [`apply_secret_ref_counts`] — a count, never a value.
        .secret_ref_count(0);

    if let Some(live) = live {
        builder = builder
            .id(MachineId(live.id.0))
            .status(live.status)
            .backend(non_empty(live.backend))
            .readiness(live.readiness)
            .ports(live.ports)
            .tags(live.tags)
            .expires_at(live.expires_at);
        if let Some(detail) = live.status_detail {
            builder = builder.status_detail(detail);
        }
        if live.cpus > 0 {
            builder = builder.cpus(live.cpus);
        }
        if live.memory_mib > 0 {
            builder = builder.memory_mib(live.memory_mib);
        }
    }
    builder.build()
}

/// Build the record for a live VM with no persisted definition.
fn transient_record(live: MachineState, posture: WorkloadPosture) -> MachineInventoryRecord {
    let source = live_source(&live);
    let mut builder = MachineInventoryRecord::builder(&live.name, MachineKind::Transient)
        .id(MachineId(live.id.0))
        .status(live.status)
        .build_mode(posture)
        .source(source)
        .backend(non_empty(live.backend))
        .cpus(live.cpus)
        .memory_mib(live.memory_mib)
        .readiness(live.readiness)
        .ports(live.ports)
        .tags(live.tags)
        .expires_at(live.expires_at);
    if let Some(detail) = live.status_detail {
        builder = builder.status_detail(detail);
    }
    builder.build()
}

/// What a spec-less machine was made from: whatever the backend knows.
fn live_source(live: &MachineState) -> Option<String> {
    live.flake_ref.clone().or_else(|| live.profile.clone())
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Join the given persisted specs against `client`'s live listing, resolving
/// posture from host state. The testable core of [`list_local_inventory`];
/// also the entry point for a caller that already holds the specs (or wants
/// a spec-less inventory over a mock backend).
pub async fn inventory_with_specs(
    client: &dyn MvmClient,
    specs: Vec<PersistedMachineSpec>,
) -> Result<Vec<MachineInventoryRecord>> {
    let live = client.list_machines(MachineFilter::all()).await?;
    Ok(join_inventory(specs, live, resolve_workload_posture))
}

/// Back-fill readiness from the local VM name registry for records the live
/// listing left blank, so a freshly-attached consumer sees the same health a
/// long-poll would.
pub fn apply_registry_readiness(records: &mut [MachineInventoryRecord]) {
    for record in records {
        if record.readiness.is_none() {
            record.readiness = crate::readiness_of(&record.name);
        }
    }
}

/// Count of secret references recorded in `name`'s metadata-only
/// `secret-refs.json` sidecar under `machines_root`. Tolerant by design: an
/// absent or unreadable sidecar reads as `0` — the listing must not fail on
/// one bad sidecar (deletion decisions fail closed at the service seam, not
/// here).
pub fn secret_ref_count_of(machines_root: &std::path::Path, name: &str) -> u32 {
    crate::secret::refs::load_refs(machines_root, name)
        .ok()
        .flatten()
        .map(|record| record.references.len() as u32)
        .unwrap_or(0)
}

/// Back-fill each record's `secret_ref_count` from the machine's persisted
/// secret-reference sidecar — the count only, never a name-to-value reach.
pub fn apply_secret_ref_counts(records: &mut [MachineInventoryRecord]) {
    let root = mvm_core::config::machine_state_root();
    for record in records {
        record.secret_ref_count = secret_ref_count_of(&root, &record.name);
    }
}

/// The full local inventory: every persisted machine definition joined with
/// every live VM `client` can see, readiness back-filled from the registry
/// and secret-reference counts from the per-machine sidecars.
/// Read-only — no state dir, registry entry, or audit log is mutated.
/// Filter with [`InventoryQuery::matches`]; the unfiltered stream includes
/// stopped and expired machines so callers own visibility policy.
pub async fn list_local_inventory(client: &dyn MvmClient) -> Result<Vec<MachineInventoryRecord>> {
    let specs = persist::list_machine_specs().map_err(|e| MvmError::Backend {
        reason: format!("listing machine specs: {e:#}"),
    })?;
    let mut records = inventory_with_specs(client, specs).await?;
    apply_registry_readiness(&mut records);
    apply_secret_ref_counts(&mut records);
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::client::mock::MockBackend;
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::machine::persist::MACHINE_SPEC_SCHEMA_VERSION;

    /// Serializes the tests that redirect `MVM_HOME` (env vars are
    /// process-global under plain `cargo test`).
    static MVM_HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct IsolatedHome {
        _lock: std::sync::MutexGuard<'static, ()>,
        _env: TestEnv,
        _tmp: tempfile::TempDir,
    }

    impl IsolatedHome {
        fn new() -> Self {
            let lock = MVM_HOME_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let mut env = TestEnv::new();
            env.set("MVM_HOME", tmp.path());
            Self {
                _lock: lock,
                _env: env,
                _tmp: tmp,
            }
        }
    }

    fn spec(name: &str) -> PersistedMachineSpec {
        PersistedMachineSpec {
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
            created_at: Some("2026-07-01T00:00:00Z".to_string()),
            last_started_at: None,
            health_check: None,
            grants: None,
        }
    }

    fn live(name: &str, status: MachineStatus) -> MachineState {
        MachineState {
            id: MachineId(format!("vm-{name}")),
            name: name.to_string(),
            status,
            ..Default::default()
        }
    }

    /// A posture stub for pure join tests — every machine named `dev-*`
    /// resolves dev, the rest prod.
    fn stub_posture(_manifest: Option<&str>, name: &str) -> WorkloadPosture {
        if name.starts_with("dev-") {
            WorkloadPosture::Dev
        } else {
            WorkloadPosture::Prod
        }
    }

    #[test]
    fn persistent_only_spec_lists_as_stopped_definition() {
        let records = join_inventory(vec![spec("web")], vec![], stub_posture);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.kind, MachineKind::Persistent);
        assert_eq!(r.status, MachineStatus::Stopped);
        assert_eq!(r.id, MachineId("web".into()), "identity falls back to name");
        assert_eq!(r.source.as_deref(), Some("alpine:latest"));
        assert_eq!(r.cpus, 2);
        assert_eq!(r.memory_mib, 512, "declared memory parses to MiB");
        assert!(r.backend.is_none());
        assert_eq!(r.created_at.as_deref(), Some("2026-07-01T00:00:00Z"));
    }

    #[test]
    fn transient_only_live_vm_lists_as_transient() {
        let mut vm = live("adhoc", MachineStatus::Running);
        vm.backend = "firecracker".into();
        vm.cpus = 1;
        vm.memory_mib = 256;
        let records = join_inventory(vec![], vec![vm], stub_posture);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.kind, MachineKind::Transient);
        assert_eq!(r.status, MachineStatus::Running);
        assert_eq!(r.id, MachineId("vm-adhoc".into()));
        assert_eq!(r.backend.as_deref(), Some("firecracker"));
        assert_eq!((r.cpus, r.memory_mib), (1, 256));
        assert!(r.created_at.is_none(), "no definition, no creation time");
    }

    #[test]
    fn joined_running_persistent_machine_carries_live_state_over_spec_defaults() {
        let mut vm = live("web", MachineStatus::Running);
        vm.backend = "hvf".into();
        vm.cpus = 4;
        vm.tags.insert("env".into(), "prod".into());
        vm.expires_at = Some("2099-01-01T00:00:00Z".into());

        let records = join_inventory(vec![spec("web")], vec![vm], stub_posture);
        assert_eq!(
            records.len(),
            1,
            "the spec and its live row are one machine"
        );
        let r = &records[0];
        assert_eq!(r.kind, MachineKind::Persistent);
        assert_eq!(r.status, MachineStatus::Running);
        assert_eq!(r.id, MachineId("vm-web".into()), "live id wins");
        assert_eq!(r.cpus, 4, "live cpus win over the declared value");
        assert_eq!(r.memory_mib, 512, "zero live memory falls back to the spec");
        assert_eq!(r.backend.as_deref(), Some("hvf"));
        assert_eq!(r.tags.get("env").map(String::as_str), Some("prod"));
        assert_eq!(r.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
    }

    /// The reported bug: an HVF builder shell job stages its runtime state in
    /// `~/.mvm/vms/` like a workload, so the live scan found it and the join,
    /// having no spec for it, rendered it as a transient machine — which
    /// `machine shell`/`rm` then said did not exist.
    #[test]
    fn a_live_builder_vm_without_a_spec_is_not_a_machine() {
        let job = mvm_core::naming::builder_shell_vm_name("92326-1787337475138993000");
        let persistent = mvm_core::naming::persistent_builder_vm_name(
            mvm_core::naming::BuilderVmSlot::Hvf,
            "session",
        );
        let records = join_inventory(
            vec![spec("web")],
            vec![
                live(&job, MachineStatus::Running),
                live(&persistent, MachineStatus::Running),
                live("adhoc", MachineStatus::Running),
            ],
            stub_posture,
        );
        let names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["web", "adhoc"],
            "builder VMs are the build system's, not the user's"
        );
    }

    /// The filter keys on "live and spec-less", not on the name alone: a
    /// machine the user created is theirs whatever they called it.
    #[test]
    fn a_user_spec_with_a_builder_shaped_name_is_still_listed() {
        let name = mvm_core::naming::builder_shell_vm_name("mine");
        let records = join_inventory(
            vec![spec(&name)],
            vec![live(&name, MachineStatus::Running)],
            stub_posture,
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, name);
        assert_eq!(records[0].kind, MachineKind::Persistent);
    }

    #[test]
    fn persistent_records_sort_first_then_transients() {
        let records = join_inventory(
            vec![spec("zeta"), spec("alpha")],
            vec![
                live("beta-adhoc", MachineStatus::Running),
                live("alpha", MachineStatus::Running),
            ],
            stub_posture,
        );
        let names: Vec<(&str, MachineKind)> =
            records.iter().map(|r| (r.name.as_str(), r.kind)).collect();
        assert_eq!(
            names,
            vec![
                ("alpha", MachineKind::Persistent),
                ("zeta", MachineKind::Persistent),
                ("beta-adhoc", MachineKind::Transient),
            ]
        );
    }

    #[test]
    fn paused_machine_keeps_its_paused_status() {
        let records = join_inventory(
            vec![spec("web")],
            vec![live("web", MachineStatus::Paused)],
            stub_posture,
        );
        assert_eq!(records[0].status, MachineStatus::Paused);
        // And a paused machine stays visible in the default inventory.
        let now = mvm_core::util::time::parse_iso8601("2026-07-31T12:00:00Z").unwrap();
        assert!(InventoryQuery::active().matches(&records[0], now));
    }

    #[test]
    fn failed_machine_carries_its_reason_in_status_detail() {
        let mut failed = live("adhoc", MachineStatus::Failed);
        failed.status_detail = Some("boot wedged".into());
        let records = join_inventory(vec![], vec![failed], stub_posture);
        assert_eq!(records[0].status, MachineStatus::Failed);
        assert_eq!(records[0].status_detail.as_deref(), Some("boot wedged"));
    }

    #[test]
    fn duplicate_live_names_collapse_to_the_live_row() {
        // A stale stopped row must never mask the running VM, in either order.
        let stopped = live("web", MachineStatus::Stopped);
        let mut running = live("web", MachineStatus::Running);
        running.id = MachineId("vm-web-2".into());

        for order in [
            vec![stopped.clone(), running.clone()],
            vec![running.clone(), stopped.clone()],
        ] {
            let records = join_inventory(vec![], order, stub_posture);
            assert_eq!(records.len(), 1, "duplicates collapse to one record");
            assert_eq!(records[0].status, MachineStatus::Running);
            assert_eq!(records[0].id, MachineId("vm-web-2".into()));
        }
    }

    #[test]
    fn unknown_posture_resolution_is_prod_never_dev() {
        // The stub resolves unknown names to prod — assert the join threads
        // that through instead of inferring dev from anything else.
        let records = join_inventory(
            vec![spec("web")],
            vec![live("mystery", MachineStatus::Running)],
            |_, _| WorkloadPosture::from_label("unrecognized"),
        );
        for r in &records {
            assert_eq!(r.build_mode, WorkloadPosture::Prod, "{}", r.name);
        }
    }

    #[test]
    fn dev_posture_is_only_ever_explicit() {
        let records = join_inventory(vec![spec("dev-box"), spec("web")], vec![], stub_posture);
        assert_eq!(records[0].build_mode, WorkloadPosture::Dev); // dev-box
        assert_eq!(records[1].build_mode, WorkloadPosture::Prod); // web
    }

    #[test]
    fn volume_summaries_drop_the_host_path() {
        let mut with_volumes = spec("web");
        with_volumes.volumes = vec![
            "/home/user/data:/data:ro".to_string(),
            "/home/user/scratch:/scratch:2G:rw:enc".to_string(),
        ];
        let records = join_inventory(vec![with_volumes], vec![], stub_posture);
        let volumes = &records[0].volumes;
        assert_eq!(
            volumes,
            &vec![
                VolumeAttachment {
                    guest_mount: "/data".into(),
                    kind: VolumeAttachmentKind::DirShare,
                    read_only: true,
                    encrypted: false,
                },
                VolumeAttachment {
                    guest_mount: "/scratch".into(),
                    kind: VolumeAttachmentKind::Disk,
                    read_only: false,
                    encrypted: true,
                },
            ]
        );
        let json = serde_json::to_string(&records[0]).unwrap();
        assert!(
            !json.contains("/home/user"),
            "no host path may reach the serialized record: {json}"
        );
    }

    #[test]
    fn summarize_volume_spec_degrades_gracefully_on_malformed_input() {
        let attachment = summarize_volume_spec("just-a-host-path");
        assert_eq!(attachment.guest_mount, "");
        assert_eq!(attachment.kind, VolumeAttachmentKind::DirShare);
        assert!(!attachment.read_only && !attachment.encrypted);
        // A bare dir share defaults to read-write, matching the run grammar.
        let rw = summarize_volume_spec("/h:/g");
        assert!(!rw.read_only);
    }

    #[test]
    fn secret_ref_count_is_zero_with_no_secret_source() {
        let records = join_inventory(vec![spec("web")], vec![], stub_posture);
        assert_eq!(records[0].secret_ref_count, 0);
    }

    /// Record a sidecar fixture for `machine` under `root`.
    fn record_ref_fixture(root: &std::path::Path, machine: &str) {
        std::fs::create_dir_all(root.join(machine)).unwrap();
        std::fs::write(root.join(machine).join("machine.json"), b"{}").unwrap();
        crate::secret::refs::record_refs(
            root,
            machine,
            &[crate::secret::MachineSecretRef {
                tenant: "local".into(),
                name: "openai".into(),
                placeholder_var: Some("API_KEY".into()),
                destinations: vec!["api.openai.com".into()],
            }],
        )
        .unwrap();
    }

    #[test]
    fn secret_ref_count_reads_the_recorded_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        record_ref_fixture(tmp.path(), "web");
        assert_eq!(secret_ref_count_of(tmp.path(), "web"), 1);
        // Absent sidecar → 0; malformed sidecar degrades to 0 (listing
        // tolerance — deletion decisions fail closed elsewhere).
        assert_eq!(secret_ref_count_of(tmp.path(), "other"), 0);
        std::fs::write(
            tmp.path()
                .join("web")
                .join(crate::secret::refs::MACHINE_SECRET_REFS_FILENAME),
            b"not-json",
        )
        .unwrap();
        assert_eq!(secret_ref_count_of(tmp.path(), "web"), 0);
    }

    #[tokio::test]
    async fn list_local_inventory_reports_recorded_secret_ref_counts() {
        let _home = IsolatedHome::new();
        persist::save_machine_spec(&spec("web"), false).expect("save spec");
        crate::secret::refs::record_refs(
            &mvm_core::config::machine_state_root(),
            "web",
            &[crate::secret::MachineSecretRef {
                tenant: "local".into(),
                name: "openai".into(),
                placeholder_var: Some("API_KEY".into()),
                destinations: vec!["api.openai.com".into()],
            }],
        )
        .unwrap();

        let mock = MockBackend::default();
        let records = list_local_inventory(&mock).await.expect("inventory");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].secret_ref_count, 1, "count from the sidecar");
        // The serialized record carries the count, never the reference names.
        let json = serde_json::to_string(&records[0]).unwrap();
        assert!(!json.contains("openai"), "no secret name in record: {json}");
    }

    #[test]
    fn unparseable_spec_memory_degrades_to_zero() {
        let mut bad = spec("web");
        bad.memory = "not-a-size".to_string();
        let records = join_inventory(vec![bad], vec![], stub_posture);
        assert_eq!(records[0].memory_mib, 0);
    }

    #[tokio::test]
    async fn mock_backend_inventory_lists_its_machines_as_transients() {
        let _home = IsolatedHome::new();
        let mock = MockBackend::default();
        let spec = mvm_core::client::dto::MachineSpec::builder("adhoc", "img")
            .expect("declared image parses")
            .build();
        mock.run_machine(spec).await.unwrap();

        let records = inventory_with_specs(&mock, vec![]).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, MachineKind::Transient);
        assert_eq!(records[0].status, MachineStatus::Running);
        assert_eq!(
            records[0].build_mode,
            WorkloadPosture::Prod,
            "no runtime meta means no dev posture"
        );
    }

    #[tokio::test]
    async fn mock_backend_inventory_joins_persisted_specs() {
        let _home = IsolatedHome::new();
        let mock = MockBackend::default();
        let boot = mvm_core::client::dto::MachineSpec::builder("web", "img")
            .expect("declared image parses")
            .build();
        mock.run_machine(boot).await.unwrap();

        let records = inventory_with_specs(&mock, vec![spec("web"), spec("db")])
            .await
            .unwrap();
        let shape: Vec<(&str, MachineKind, MachineStatus)> = records
            .iter()
            .map(|r| (r.name.as_str(), r.kind, r.status))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("db", MachineKind::Persistent, MachineStatus::Stopped),
                ("web", MachineKind::Persistent, MachineStatus::Running),
            ]
        );
    }

    #[tokio::test]
    async fn list_local_inventory_reads_the_isolated_spec_registry() {
        let _home = IsolatedHome::new();
        persist::save_machine_spec(&spec("web"), false).expect("save spec");

        let mock = MockBackend::default();
        let records = list_local_inventory(&mock).await.expect("inventory");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "web");
        assert_eq!(records[0].kind, MachineKind::Persistent);
        assert_eq!(records[0].status, MachineStatus::Stopped);
    }
}
