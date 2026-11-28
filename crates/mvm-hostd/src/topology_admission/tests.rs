use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::SigningKey;
use mvm_contract::plan::topology::{
    CoreId, CorePlacement, CryptoSuite, IsolationTier, KeyEstablishmentSuite, SealedTransitions,
    StandbyClass, StandbyPair, StateCell, TOPOLOGY_SCHEMA_VERSION, Unit, UnitResources, UnitRole,
    UnmetRequirement,
};
use mvm_contract::timestamp::UtcTimestamp;
use mvm_core::plan::WorkloadId;
use mvm_core::util::test_env::TestEnv;

use super::*;
use crate::audit::audit_file::verify_audit_chain;
use crate::audit::host_keypair::HostSigner;

const TENANT: &str = "acme";

fn t0() -> UtcTimestamp {
    "2026-11-01T00:00:00Z".parse::<UtcTimestamp>().unwrap()
}

struct FixedClock(UtcTimestamp);

impl Clock for FixedClock {
    fn now(&self) -> UtcTimestamp {
        self.0
    }
}

/// A host with its own `MVM_HOME`, host signer and audit chain. Every test
/// holds one, so nothing here reaches the real home.
struct Host {
    _env: TestEnv,
    home: tempfile::TempDir,
    signer: HostSigner,
    emitter: AuditEmitter,
    host_cpus: HostCpus,
}

/// A host whose spawn scope cannot carry a CPU set, whatever the machine
/// running the test can do.
fn no_scope_cpuset() -> HostCpus {
    HostCpus {
        scope_cpuset: false,
        online: None,
        isolated: None,
        live: Vec::new(),
    }
}

impl Host {
    fn new() -> Self {
        let (env, home) = crate::test_fixtures::isolated_mvm_home();
        let signer = crate::audit::host_keypair::load_or_init_at(&self::keys_dir(home.path()))
            .expect("host signer");
        let emitter = AuditEmitter::with_dir(signer.signing.clone(), &home.path().join("audit"))
            .expect("emitter");
        Self {
            _env: env,
            home,
            signer,
            emitter,
            host_cpus: no_scope_cpuset(),
        }
    }

    /// A host whose scope carries a CPU set and that has `online` CPUs.
    fn with_cpus(online: &str) -> Self {
        Self {
            host_cpus: HostCpus {
                scope_cpuset: true,
                online: Some(mvm_contract::protocol::cpu_set::CpuSet::parse(online).unwrap()),
                isolated: None,
                live: Vec::new(),
            },
            ..Self::new()
        }
    }

    fn admit_for(&self, tenant: &str, topology: &Topology) -> Result<TopologyAdmission> {
        let keys = self.keys();
        let mut topology = topology.clone();
        topology.tenant = TenantId(tenant.to_string());
        admit_topology(&TopologyAdmissionRequest {
            tenant: &topology.tenant,
            signed: &self.sign(&topology),
            backend: BackendKind::Firecracker,
            measured_failover: None,
            host_cpus: &self.host_cpus,
            clock: &FixedClock(
                t0().checked_add(std::time::Duration::from_secs(86_400))
                    .unwrap(),
            ),
            host_signer_keys_dir: Some(&keys),
            emitter: &self.emitter,
        })
    }

    fn with_memory_budget(memory_mib: u64) -> Self {
        let host = Self::new();
        let cfg = mvm_core::user_config::MvmConfig {
            host_budget_memory_mib: Some(memory_mib),
            ..mvm_core::user_config::MvmConfig::default()
        };
        mvm_core::user_config::save(&cfg, None).expect("writing the host config");
        host
    }

    fn keys(&self) -> PathBuf {
        keys_dir(self.home.path())
    }

    fn sign(&self, topology: &Topology) -> SignedTopology {
        sign_topology_as_host(topology, Some(&self.keys())).expect("signing as the host")
    }

    fn admit_with(
        &self,
        signed: &SignedTopology,
        backend: BackendKind,
        measured: Option<MeasuredFailoverMs>,
        now: UtcTimestamp,
    ) -> Result<TopologyAdmission> {
        let keys = self.keys();
        admit_topology(&TopologyAdmissionRequest {
            tenant: &TenantId(TENANT.to_string()),
            signed,
            backend,
            measured_failover: measured,
            host_cpus: &self.host_cpus,
            clock: &FixedClock(now),
            host_signer_keys_dir: Some(&keys),
            emitter: &self.emitter,
        })
    }

    fn admit(&self, signed: &SignedTopology) -> Result<TopologyAdmission> {
        self.admit_with(
            signed,
            BackendKind::Firecracker,
            None,
            t0().checked_add(std::time::Duration::from_secs(86_400))
                .unwrap(),
        )
    }

    fn tenant_dir(&self) -> PathBuf {
        record::tenant_dir(self.home.path(), TENANT)
    }

    fn records(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.tenant_dir()) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn chain_path(&self) -> PathBuf {
        self.home
            .path()
            .join("audit")
            .join(format!("{TENANT}.jsonl"))
    }

    fn entries(&self) -> Vec<serde_json::Value> {
        let Ok(content) = std::fs::read_to_string(self.chain_path()) else {
            return Vec::new();
        };
        content
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
            .collect()
    }

    fn last_entry(&self) -> serde_json::Value {
        self.entries().pop().expect("an audit entry")
    }
}

fn keys_dir(home: &Path) -> PathBuf {
    mvm_core::config::mvm_keys_dir_at(home)
}

fn unit(name: &str, role: UnitRole) -> Unit {
    Unit {
        workload: WorkloadId(name.to_string()),
        role,
        recipe: Sha256Digest::from_bytes(&[name.len() as u8; 32]),
        resources: UnitResources {
            cpus: 1,
            mem_mib: 256,
            disk_mib: 512,
        },
        placement: CorePlacement::Floating,
        min_isolation: None,
        liveness_period_ms: None,
        require_isolated_cores: false,
        permits: SealedTransitions::default(),
    }
}

pub(super) fn topology(generation: u64) -> Topology {
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId(TENANT.to_string()),
        generation,
        valid_from: t0(),
        valid_until: t0()
            .checked_add(std::time::Duration::from_secs(2_592_000))
            .unwrap(),
        suite: CryptoSuite::CLASSICAL,
        units: vec![
            unit("controller", UnitRole::Controller),
            unit("worker", UnitRole::Worker),
        ],
        standby_pairs: Vec::new(),
        cells: Vec::new(),
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

fn warm_pair(bound_ms: u32) -> StandbyPair {
    StandbyPair {
        active: WorkloadId("controller".to_string()),
        standby: WorkloadId("worker".to_string()),
        class: StandbyClass::Warm,
        recovery_bound_ms: NonZeroU32::new(bound_ms),
    }
}

fn refusal(err: &anyhow::Error) -> &TopologyRefused {
    err.downcast_ref::<TopologyRefused>()
        .unwrap_or_else(|| panic!("expected a topology refusal, got {err:#}"))
}

fn admitted(outcome: TopologyAdmission) -> AdmittedTopology {
    match outcome {
        TopologyAdmission::Admitted(a) => a,
        TopologyAdmission::AlreadyAdmitted(_) => panic!("expected a new admission"),
    }
}

#[test]
fn a_host_signed_topology_is_admitted_sealed_and_audited() {
    let host = Host::new();
    let topology = topology(3);
    let signed = host.sign(&topology);

    let admitted = admitted(host.admit(&signed).expect("admits"));

    assert_eq!(admitted.digest, topology.digest());
    assert_eq!(admitted.topology, topology);
    let record: AdmittedTopologyRecord =
        serde_json::from_slice(&std::fs::read(&admitted.record_path).unwrap()).unwrap();
    assert_eq!(record.generation, 3);
    assert_eq!(record.digest, topology.digest());
    assert_eq!(
        record.admitted_at,
        t0().checked_add(std::time::Duration::from_secs(86_400))
            .unwrap()
    );
    let trusted = trusted_topology_signers(Some(&host.keys())).unwrap();
    let refs: Vec<(&str, &VerifyingKey)> = trusted.iter().map(|(i, k)| (i.as_str(), k)).collect();
    assert_eq!(verify_topology(&record.signed, &refs).unwrap(), topology);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&admitted.record_path), 0o600);
    assert_eq!(mode(&host.tenant_dir()), 0o700);

    let entry = host.last_entry();
    assert_eq!(entry["event"], TOPOLOGY_ADMITTED_EVENT);
    assert_eq!(entry["tenant"], TENANT);
    assert_eq!(
        entry["labels"]["topology_digest"],
        topology.digest().as_str()
    );
    assert_eq!(entry["labels"]["generation"], "3");
    assert_eq!(entry["labels"]["signer_id"], host_signer_id());
}

#[test]
fn a_topology_from_an_unknown_signer_is_refused_with_only_the_payload_hash() {
    let host = Host::new();
    let stranger = SigningKey::from_bytes(&[9; 32]);
    let signed = sign_topology(&topology(1), &stranger, "fleet:stranger").unwrap();

    let err = host
        .admit(&signed)
        .expect_err("an unknown signer is refused");

    assert_eq!(refusal(&err).stage, RefusalStage::Signature);
    assert!(host.records().is_empty());
    let entry = host.last_entry();
    assert_eq!(entry["event"], TOPOLOGY_ADMISSION_REFUSED_EVENT);
    assert_eq!(entry["labels"]["stage"], "signature");
    assert_eq!(
        entry["labels"]["payload_sha256"],
        Sha256Digest::from_bytes(&sha256(&signed.signed.payload)).as_str()
    );
    assert!(entry["labels"].get("topology_digest").is_none());
    assert!(entry["labels"].get("generation").is_none());
}

#[test]
fn a_tampered_topology_is_refused_at_the_signature() {
    let host = Host::new();
    let mut signed = host.sign(&topology(1));
    signed.signed.payload = serde_json::to_vec(&topology(2)).unwrap();

    let err = host.admit(&signed).expect_err("a tampered body is refused");

    assert_eq!(refusal(&err).stage, RefusalStage::Signature);
    assert!(host.records().is_empty());
    assert_eq!(host.last_entry()["labels"]["stage"], "signature");
}

#[test]
fn a_topology_is_refused_before_and_after_its_validity_window() {
    let host = Host::new();
    let topology = topology(1);
    let signed = host.sign(&topology);

    for now in [
        t0().checked_sub(std::time::Duration::from_secs(1)).unwrap(),
        topology.valid_until,
    ] {
        let err = host
            .admit_with(&signed, BackendKind::Firecracker, None, now)
            .expect_err("outside the window");
        assert_eq!(refusal(&err).stage, RefusalStage::Window, "at {now}");
        let entry = host.last_entry();
        assert_eq!(entry["labels"]["stage"], "validity_window");
        assert_eq!(entry["labels"]["generation"], "1");
    }
    assert!(host.records().is_empty());
}

#[test]
fn a_generation_lower_than_the_last_admitted_is_refused() {
    let host = Host::new();
    admitted(host.admit(&host.sign(&topology(5))).unwrap());

    let err = host
        .admit(&host.sign(&topology(4)))
        .expect_err("lower generation");

    assert_eq!(refusal(&err).stage, RefusalStage::Generation);
    assert_eq!(host.records().len(), 1);
    let entry = host.last_entry();
    assert_eq!(entry["labels"]["stage"], "generation");
    assert_eq!(entry["labels"]["generation"], "4");
}

#[test]
fn readmitting_the_same_generation_and_digest_writes_nothing() {
    let host = Host::new();
    let signed = host.sign(&topology(2));
    let first = admitted(host.admit(&signed).unwrap());
    let sealed = std::fs::read(&first.record_path).unwrap();
    let entries = host.entries().len();

    let again = host
        .admit_with(
            &signed,
            BackendKind::Firecracker,
            None,
            t0().checked_add(std::time::Duration::from_secs(172_800))
                .unwrap(),
        )
        .unwrap();

    let TopologyAdmission::AlreadyAdmitted(again) = again else {
        panic!("expected the generation on record");
    };
    assert_eq!(again.record_path, first.record_path);
    assert_eq!(std::fs::read(&first.record_path).unwrap(), sealed);
    assert_eq!(host.entries().len(), entries, "no second entry");
}

#[test]
fn the_same_generation_with_another_digest_is_refused() {
    let host = Host::new();
    admitted(host.admit(&host.sign(&topology(2))).unwrap());
    let mut other = topology(2);
    other.units[1].resources.mem_mib = 512;

    let err = host
        .admit(&host.sign(&other))
        .expect_err("conflicting digest");

    assert_eq!(refusal(&err).stage, RefusalStage::Generation);
    assert_eq!(host.records().len(), 1);
    assert_eq!(
        host.last_entry()["labels"]["topology_digest"],
        other.digest().as_str()
    );
}

#[test]
fn a_higher_generation_is_a_new_record_beside_the_earlier_one() {
    let host = Host::new();
    let first = admitted(host.admit(&host.sign(&topology(1))).unwrap());
    let sealed = std::fs::read(&first.record_path).unwrap();

    let second = admitted(host.admit(&host.sign(&topology(2))).unwrap());

    assert_ne!(first.record_path, second.record_path);
    assert_eq!(std::fs::read(&first.record_path).unwrap(), sealed);
    assert_eq!(host.records().len(), 2);
}

#[test]
fn each_unmet_requirement_is_refused_named_and_persists_nothing() {
    let host = Host::new();
    let fifty = MeasuredFailoverMs(NonZeroU32::new(50).unwrap());
    let two_hundred = MeasuredFailoverMs(NonZeroU32::new(200).unwrap());
    let mut cases: Vec<(Topology, BackendKind, Option<MeasuredFailoverMs>)> = Vec::new();

    let mut exclusive = topology(1);
    exclusive.units[0].placement = CorePlacement::Exclusive(vec![CoreId(0)]);
    cases.push((exclusive, BackendKind::Firecracker, None));

    let mut isolation = topology(1);
    isolation.units[0].min_isolation = Some(IsolationTier::Vm);
    cases.push((isolation, BackendKind::Qemu, None));

    let mut unmeasured = topology(1);
    unmeasured.standby_pairs = vec![warm_pair(100)];
    cases.push((unmeasured.clone(), BackendKind::Firecracker, None));
    cases.push((
        unmeasured.clone(),
        BackendKind::Firecracker,
        Some(two_hundred),
    ));
    cases.push((unmeasured, BackendKind::Firecracker, Some(fifty)));

    let mut cell = topology(1);
    cell.cells = vec![StateCell {
        name: "setpoint".to_string(),
        writer: WorkloadId("controller".to_string()),
        readers: Vec::new(),
        size_bytes: NonZeroU64::new(64).unwrap(),
        update: Default::default(),
        per_write_audit: false,
    }];
    cases.push((cell.clone(), BackendKind::Wasm, None));
    let mut follow = cell.clone();
    follow.cells[0].update = mvm_contract::plan::topology::CellUpdate::Follow;
    cases.push((follow, BackendKind::Firecracker, None));
    let mut per_write = cell;
    per_write.cells[0].per_write_audit = true;
    cases.push((per_write, BackendKind::Firecracker, None));

    let mut liveness = topology(1);
    liveness.units[0].liveness_period_ms = NonZeroU32::new(50);
    cases.push((liveness, BackendKind::Firecracker, None));

    let mut suite = topology(1);
    suite.suite.key_establishment = KeyEstablishmentSuite::X25519MlKem768;
    cases.push((suite, BackendKind::Firecracker, None));

    let mut kinds = Vec::new();
    for (topology, backend, measured) in cases {
        let unmet: UnmetRequirement =
            check_requirements(&topology, ResourceControls::for_backend(backend), measured)
                .expect_err("the case states an unmet requirement");
        kinds.push(std::mem::discriminant(&unmet));

        let err = host
            .admit_with(
                &host.sign(&topology),
                backend,
                measured,
                t0().checked_add(std::time::Duration::from_secs(86_400))
                    .unwrap(),
            )
            .expect_err("an unmet requirement is refused");

        let refused = refusal(&err);
        assert_eq!(refused.stage, RefusalStage::Requirements);
        assert_eq!(refused.reason, unmet.to_string());
        assert!(host.records().is_empty(), "{unmet} persisted a record");
        let entry = host.last_entry();
        assert_eq!(entry["labels"]["stage"], "requirements");
        assert_eq!(entry["labels"]["reason"], unmet.to_string());
        assert_eq!(
            entry["labels"]["topology_digest"],
            topology.digest().as_str()
        );
    }
    kinds.dedup();
    assert_eq!(kinds.len(), 10, "every requirement kind is covered once");
}

#[test]
fn a_liveness_period_is_admitted_where_a_supervisor_holds_the_deadline() {
    use mvm_contract::plan::topology::requirements::{
        MAX_LIVENESS_PERIOD_MS, MIN_LIVENESS_PERIOD_MS,
    };
    let host = Host::new();
    let now = t0()
        .checked_add(std::time::Duration::from_secs(86_400))
        .unwrap();
    let watched = |period_ms: u32| {
        let mut topology = topology(1);
        topology.units[0].liveness_period_ms = NonZeroU32::new(period_ms);
        topology
    };
    let unit = topology(1).units[0].workload.clone();

    // No owner for the deadline: refused, whatever the period.
    for backend in [
        BackendKind::Firecracker,
        BackendKind::Qemu,
        BackendKind::Wasm,
        BackendKind::WebLinux,
    ] {
        let topology = watched(5_000);
        let err = host
            .admit_with(&host.sign(&topology), backend, None, now)
            .expect_err("no process holds a deadline on this backend");
        assert_eq!(
            refusal(&err).reason,
            UnmetRequirement::LivenessPeriod {
                unit: unit.clone(),
                period_ms: NonZeroU32::new(5_000).unwrap(),
            }
            .to_string(),
            "{backend:?}"
        );
    }

    // An owner, and the range still applies.
    for backend in [
        BackendKind::Libkrun,
        BackendKind::Hvf,
        BackendKind::AppleContainer,
    ] {
        for period_ms in [MIN_LIVENESS_PERIOD_MS - 1, MAX_LIVENESS_PERIOD_MS + 1] {
            let topology = watched(period_ms);
            let err = host
                .admit_with(&host.sign(&topology), backend, None, now)
                .expect_err("outside the range the host holds");
            assert_eq!(
                refusal(&err).reason,
                UnmetRequirement::LivenessPeriodOutOfRange {
                    unit: unit.clone(),
                    period_ms: NonZeroU32::new(period_ms).unwrap(),
                }
                .to_string(),
                "{backend:?} {period_ms}"
            );
        }
    }
    assert!(host.records().is_empty(), "no refusal persisted a record");

    // The same generation presented on each: admitted once, then recognised.
    let topology = watched(MIN_LIVENESS_PERIOD_MS);
    for backend in [
        BackendKind::Libkrun,
        BackendKind::Hvf,
        BackendKind::AppleContainer,
    ] {
        host.admit_with(&host.sign(&topology), backend, None, now)
            .unwrap_or_else(|e| panic!("{backend:?} holds the deadline: {e:#}"));
    }
    assert_eq!(host.records().len(), 1);
}

#[test]
fn a_topology_over_the_host_budget_is_refused() {
    let host = Host::with_memory_budget(300);

    let err = host
        .admit(&host.sign(&topology(1)))
        .expect_err("512 MiB of units over a 300 MiB budget");

    assert_eq!(refusal(&err).stage, RefusalStage::Budget);
    assert!(host.records().is_empty());
    assert_eq!(host.last_entry()["labels"]["stage"], "budget");
}

#[test]
fn a_topology_within_the_host_budget_leaves_no_hold_behind() {
    let host = Host::with_memory_budget(600);

    admitted(host.admit(&host.sign(&topology(1))).unwrap());
    // A held probe would charge 512 MiB and refuse the next generation.
    admitted(host.admit(&host.sign(&topology(2))).unwrap());
}

#[test]
fn a_topology_naming_another_tenant_is_refused() {
    let host = Host::new();
    let mut other = topology(1);
    other.tenant = TenantId("globex".to_string());

    let err = host.admit(&host.sign(&other)).expect_err("tenant mismatch");

    assert_eq!(refusal(&err).stage, RefusalStage::Tenant);
    assert!(host.records().is_empty());
    assert_eq!(host.last_entry()["labels"]["stage"], "tenant");
}

#[test]
fn a_tenant_that_is_not_one_path_component_is_refused_before_anything_is_written() {
    let host = Host::new();
    let signed = host.sign(&topology(1));
    let keys = host.keys();

    let err = admit_topology(&TopologyAdmissionRequest {
        tenant: &TenantId("../acme".to_string()),
        signed: &signed,
        backend: BackendKind::Firecracker,
        measured_failover: None,
        host_cpus: &no_scope_cpuset(),
        clock: &FixedClock(
            t0().checked_add(std::time::Duration::from_secs(86_400))
                .unwrap(),
        ),
        host_signer_keys_dir: Some(&keys),
        emitter: &host.emitter,
    })
    .expect_err("a path is not a tenant");

    assert_eq!(refusal(&err).stage, RefusalStage::Tenant);
    assert!(!mvm_core::config::topologies_dir_at(host.home.path()).exists());
}

#[test]
fn the_topology_audit_chain_verifies_after_admissions_and_refusals() {
    let host = Host::new();
    admitted(host.admit(&host.sign(&topology(1))).unwrap());
    let stranger = SigningKey::from_bytes(&[7; 32]);
    host.admit(&sign_topology(&topology(2), &stranger, "fleet:x").unwrap())
        .unwrap_err();
    host.admit(&host.sign(&topology(1))).unwrap();
    host.admit(&host.sign(&topology(0))).unwrap_err();
    admitted(host.admit(&host.sign(&topology(2))).unwrap());

    let events: Vec<String> = host
        .entries()
        .iter()
        .map(|e| e["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        events,
        [
            TOPOLOGY_ADMITTED_EVENT,
            TOPOLOGY_ADMISSION_REFUSED_EVENT,
            TOPOLOGY_ADMISSION_REFUSED_EVENT,
            TOPOLOGY_ADMITTED_EVENT,
        ]
    );
    assert_eq!(
        verify_audit_chain(&host.chain_path(), &host.signer.verifying).expect("chain verifies"),
        4
    );
}

fn placed(generation: u64, cores: &[u32]) -> Topology {
    let mut topology = topology(generation);
    topology.units[1].placement =
        CorePlacement::Exclusive(cores.iter().map(|c| CoreId(*c)).collect());
    topology
}

#[test]
fn exclusive_placement_is_admitted_where_the_scope_carries_a_cpu_set() {
    let host = Host::with_cpus("0-7");
    admitted(host.admit_for(TENANT, &placed(1, &[2, 3])).unwrap());
}

#[test]
fn exclusive_placement_on_a_core_the_host_lacks_is_refused_and_persists_nothing() {
    let host = Host::with_cpus("0-3");
    let err = host.admit_for(TENANT, &placed(1, &[3, 4])).unwrap_err();
    let refused = refusal(&err);
    assert_eq!(refused.stage, RefusalStage::Requirements);
    assert!(
        refused.reason.contains("no such core"),
        "{}",
        refused.reason
    );
    assert!(host.records().is_empty());
}

#[test]
fn exclusive_placement_another_tenant_holds_is_refused() {
    let host = Host::with_cpus("0-7");
    admitted(host.admit_for("other", &placed(1, &[3, 4])).unwrap());
    let err = host.admit_for(TENANT, &placed(1, &[2, 3])).unwrap_err();
    let refused = refusal(&err);
    assert_eq!(refused.stage, RefusalStage::Requirements);
    assert!(
        refused.reason.contains("tenant other"),
        "{}",
        refused.reason
    );
    // A disjoint set beside it is fine.
    admitted(host.admit_for(TENANT, &placed(1, &[5])).unwrap());
}

#[test]
fn exclusive_placement_without_a_scope_cpu_set_is_refused_by_requirement() {
    let host = Host::new();
    let err = host.admit_for(TENANT, &placed(1, &[0])).unwrap_err();
    let refused = refusal(&err);
    assert_eq!(refused.stage, RefusalStage::Requirements);
    assert!(
        refused.reason.contains("exclusive core placement"),
        "{}",
        refused.reason
    );
}
