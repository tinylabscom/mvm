use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::fs::PermissionsExt;

use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use mvm_contract::plan::topology::{
    CoreId, CorePlacement, CryptoSuite, IsolationTier, KeyEstablishmentSuite, SealedTransitions,
    StandbyClass, StandbyPair, StateCell, TOPOLOGY_SCHEMA_VERSION, Unit, UnitResources, UnitRole,
    UnmetRequirement,
};
use mvm_core::plan::WorkloadId;
use mvm_core::util::test_env::TestEnv;

use super::*;
use crate::audit::audit_file::verify_audit_chain;
use crate::audit::host_keypair::HostSigner;

const TENANT: &str = "acme";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap()
}

struct FixedClock(DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
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
        }
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
        now: DateTime<Utc>,
    ) -> Result<TopologyAdmission> {
        let keys = self.keys();
        admit_topology(&TopologyAdmissionRequest {
            tenant: &TenantId(TENANT.to_string()),
            signed,
            backend,
            measured_failover: measured,
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
            t0() + Duration::days(1),
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
        permits: SealedTransitions::default(),
    }
}

fn topology(generation: u64) -> Topology {
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId(TENANT.to_string()),
        generation,
        valid_from: t0(),
        valid_until: t0() + Duration::days(30),
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
    assert_eq!(record.admitted_at, t0() + Duration::days(1));
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

    for now in [t0() - Duration::seconds(1), topology.valid_until] {
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
            t0() + Duration::days(2),
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
    cases.push((cell, BackendKind::Firecracker, None));

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
                t0() + Duration::days(1),
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
    assert_eq!(kinds.len(), 7, "every requirement kind is covered once");
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
        clock: &FixedClock(t0() + Duration::days(1)),
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
