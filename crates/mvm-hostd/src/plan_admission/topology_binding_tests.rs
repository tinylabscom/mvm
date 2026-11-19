//! A plan held to the topology admitted for its tenant, through the whole
//! admission path.

use std::path::{Path, PathBuf};

use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, TOPOLOGY_SCHEMA_VERSION, Topology,
    TopologyBinding, TopologyBindingRefusal, Unit, UnitResources, UnitRole,
};
use mvm_core::plan::{TenantId, WorkloadId};

use super::test_support::*;
use super::*;
use crate::topology_admission::{TopologyAdmissionRequest, admit_topology, sign_topology_as_host};

const UNIT: &str = "vm1";

/// A host with its own `MVM_HOME` and keys. The guard and the home must
/// outlive every admission the test makes.
struct Host {
    _env: TestEnv,
    home: tempfile::TempDir,
    ledger: InMemoryNonceLedger,
}

impl Host {
    fn new() -> Self {
        let (env, home) = host_with_ceiling(Default::default());
        Self {
            _env: env,
            home,
            ledger: InMemoryNonceLedger::new(),
        }
    }

    fn keys(&self) -> PathBuf {
        mvm_core::config::mvm_keys_dir_at(self.home.path())
    }

    fn admit_topology(&self, topology: &Topology) {
        let keys = self.keys();
        let signed = sign_topology_as_host(topology, Some(&keys)).expect("signs");
        let emitter = emitter(self.home.path(), &keys);
        admit_topology(&TopologyAdmissionRequest {
            tenant: &topology.tenant,
            signed: &signed,
            backend: mvm_core::vm_backend::BackendKind::Firecracker,
            measured_failover: None,
            clock: &SystemClock,
            host_signer_keys_dir: Some(&keys),
            emitter: &emitter,
        })
        .expect("the topology is admitted");
    }

    fn admit(&self, plan: &ExecutionPlan) -> Result<AdmittedPlan> {
        admit_plan_for_run(
            plan,
            &SystemClock,
            &self.ledger,
            Some(&self.keys()),
            None,
            None,
            RunPosture::without_backend(Variant::Dev),
        )
    }

    fn last_entry(&self, tenant: &str) -> serde_json::Value {
        let chain = self
            .home
            .path()
            .join("audit")
            .join(format!("{tenant}.jsonl"));
        let content = std::fs::read_to_string(chain).expect("an audit chain");
        let line = content.lines().last().expect("an audit entry");
        serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone()
    }
}

fn emitter(home: &Path, keys: &Path) -> crate::audit::emitter::AuditEmitter {
    let signer = crate::audit::host_keypair::load_or_init_at(keys).expect("host signer");
    crate::audit::emitter::AuditEmitter::with_dir(signer.signing, &home.join("audit"))
        .expect("emitter")
}

fn plan() -> ExecutionPlan {
    synthesize_plan(&fixture_input(UNIT)).expect("synthesizes")
}

/// One unit the fixture plan matches exactly, for the fixture plan's tenant.
fn topology_for(plan: &ExecutionPlan, generation: u64) -> Topology {
    let now = Utc::now();
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: plan.tenant.clone(),
        generation,
        valid_from: now - Duration::days(1),
        valid_until: now + Duration::days(30),
        suite: CryptoSuite::CLASSICAL,
        units: vec![Unit {
            workload: WorkloadId(UNIT.to_string()),
            role: UnitRole::Worker,
            recipe: Sha256Digest::parse(format!("sha256:{FIXTURE_SHA}")).unwrap(),
            resources: UnitResources {
                cpus: plan.resources.cpus,
                mem_mib: plan.resources.mem_mib,
                disk_mib: plan.resources.disk_mib,
            },
            placement: CorePlacement::Floating,
            min_isolation: None,
            permits: SealedTransitions::default(),
            liveness_period_ms: None,
        }],
        standby_pairs: Vec::new(),
        cells: Vec::new(),
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// `plan` bound to `topology`'s unit, with its content address recomputed.
fn bind(mut plan: ExecutionPlan, topology: &Topology, unit: &str) -> ExecutionPlan {
    plan.topology = Some(TopologyBinding {
        topology: topology.digest(),
        unit: WorkloadId(unit.to_string()),
    });
    readdress(plan)
}

fn readdress(mut plan: ExecutionPlan) -> ExecutionPlan {
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    plan
}

fn refusal(result: Result<AdmittedPlan>) -> TopologyBindingRefusal {
    let Err(err) = result else {
        panic!("expected the plan to be refused")
    };
    err.downcast_ref::<TopologyBindingRefusal>()
        .unwrap_or_else(|| panic!("expected a topology binding refusal, got {err:#}"))
        .clone()
}

#[test]
fn an_unbound_plan_on_a_host_with_no_topology_is_admitted_as_before() {
    let host = Host::new();
    host.admit(&plan()).expect("admitted");
}

#[test]
fn a_plan_bound_to_the_admitted_topology_is_admitted() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    let admitted = host.admit(&bind(plan, &topology, UNIT)).expect("admitted");
    assert_eq!(
        admitted.plan().topology.as_ref().unwrap().topology,
        topology.digest()
    );
}

#[test]
fn an_unbound_plan_is_refused_without_spending_its_nonce_and_the_refusal_is_audited() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);

    let expected = TopologyBindingRefusal::Unbound {
        admitted: topology.digest(),
    };
    assert_eq!(refusal(host.admit(&plan)), expected);
    let entry = host.last_entry(&plan.tenant.0);
    assert_eq!(entry["event"], "plan.admission_refused");
    assert_eq!(entry["plan_id"], plan.plan_id.0.as_str());
    assert_eq!(entry["labels"]["stage"], TOPOLOGY_BINDING_STAGE);

    // Presented again, the same plan is refused for the same reason, not as a
    // replay: the first refusal spent nothing.
    assert_eq!(refusal(host.admit(&plan)), expected);

    // And the same nonce, once bound, is still admissible.
    host.admit(&bind(plan, &topology, UNIT))
        .expect("the nonce was never spent");
    let tenant = topology.tenant.0.clone();
    crate::audit::audit_file::verify_audit_chain(
        &host
            .home
            .path()
            .join("audit")
            .join(format!("{tenant}.jsonl")),
        &crate::audit::host_keypair::load_or_init_at(&host.keys())
            .unwrap()
            .verifying,
    )
    .expect("the chain verifies");
}

#[test]
fn a_bound_plan_on_a_host_with_no_topology_is_refused() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1);
    assert!(matches!(
        refusal(host.admit(&bind(plan, &topology, UNIT))),
        TopologyBindingRefusal::NoAdmittedTopology { .. }
    ));
}

#[test]
fn a_plan_bound_to_an_earlier_generation_is_refused_against_the_highest() {
    let host = Host::new();
    let plan = plan();
    let first = topology_for(&plan, 1);
    let mut second = topology_for(&plan, 2);
    second.valid_until = first.valid_until + Duration::days(1);
    host.admit_topology(&first);
    host.admit_topology(&second);
    assert_eq!(
        refusal(host.admit(&bind(plan, &first, UNIT))),
        TopologyBindingRefusal::DigestMismatch {
            bound: first.digest(),
            admitted: second.digest(),
        }
    );
}

#[test]
fn a_plan_naming_a_unit_the_topology_lacks_is_refused() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    assert_eq!(
        refusal(host.admit(&bind(plan, &topology, "vm-absent"))),
        TopologyBindingRefusal::UnknownUnit {
            unit: WorkloadId("vm-absent".to_string())
        }
    );
}

#[test]
fn a_plan_booting_another_recipe_is_refused() {
    let host = Host::new();
    let mut plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    plan.image.sha256 = "c".repeat(64);
    assert!(matches!(
        refusal(host.admit(&bind(plan, &topology, UNIT))),
        TopologyBindingRefusal::RecipeMismatch { .. }
    ));
}

#[test]
fn a_plan_sized_differently_from_its_unit_is_refused() {
    let host = Host::new();
    let mut plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    plan.resources.mem_mib += 64;
    assert!(matches!(
        refusal(host.admit(&bind(plan, &topology, UNIT))),
        TopologyBindingRefusal::ResourcesMismatch { .. }
    ));
}

#[test]
fn another_tenants_topology_does_not_bind_this_tenants_plans() {
    let host = Host::new();
    let plan = plan();
    let mut other = topology_for(&plan, 1);
    other.tenant = TenantId("globex".to_string());
    host.admit_topology(&other);
    host.admit(&plan).expect("admitted");
}
