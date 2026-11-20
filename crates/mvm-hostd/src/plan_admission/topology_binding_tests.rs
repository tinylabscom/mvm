//! A plan held to the topology admitted for its tenant, through the whole
//! admission path.

use std::path::{Path, PathBuf};

use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, Edge, EdgeKind, SealedTransitions, TOPOLOGY_SCHEMA_VERSION,
    Topology, TopologyBinding, TopologyBindingRefusal, Unit, UnitResources, UnitRole,
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
        self.admit_topology_on(topology, false);
    }

    /// Admit on a host whose scope carries a CPU set, so exclusive placement
    /// is served.
    fn admit_topology_on(&self, topology: &Topology, scope_cpuset: bool) {
        let keys = self.keys();
        let signed = sign_topology_as_host(topology, Some(&keys)).expect("signs");
        let emitter = emitter(self.home.path(), &keys);
        admit_topology(&TopologyAdmissionRequest {
            tenant: &topology.tenant,
            signed: &signed,
            backend: mvm_core::vm_backend::BackendKind::Firecracker,
            measured_failover: None,
            host_cpus: &crate::topology_admission::HostCpus {
                scope_cpuset,
                online: Some(mvm_contract::protocol::cpu_set::CpuSet::parse("0-7").unwrap()),
                isolated: None,
                live: Vec::new(),
            },
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
            require_isolated_cores: false,
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
    let mut topology = topology_for(&plan, 1);
    topology.units[0].workload = WorkloadId("vm-other".to_string());
    host.admit_topology(&topology);
    assert_eq!(
        refusal(host.admit(&bind(plan, &topology, UNIT))),
        TopologyBindingRefusal::UnknownUnit {
            unit: WorkloadId(UNIT.to_string())
        }
    );
}

#[test]
fn a_plan_for_another_workload_cannot_take_a_units_slot() {
    let host = Host::new();
    let mut plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    plan.workload = WorkloadId("vm-other".to_string());
    assert_eq!(
        refusal(host.admit(&bind(plan, &topology, UNIT))),
        TopologyBindingRefusal::WorkloadMismatch {
            unit: WorkloadId(UNIT.to_string()),
            workload: WorkloadId("vm-other".to_string()),
        }
    );
}

#[test]
fn a_tenant_no_topology_store_can_hold_is_refused() {
    let host = Host::new();
    let mut plan = plan();
    plan.tenant = TenantId("acme/east".to_string());
    let err = host
        .admit(&readdress(plan))
        .err()
        .map(|e| format!("{e:#}"))
        .expect("the plan is refused");
    assert!(err.contains("not a single path component"), "got: {err}");
    assert!(
        crate::topology_admission::last_admitted_topology(
            host.home.path(),
            &TenantId("acme/east".to_string()),
            Some(&host.keys()),
        )
        .is_err()
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

/// `topology_for` with a producer unit whose output feeds the unit's stdin.
fn topology_with_stream_into_unit(plan: &ExecutionPlan) -> Topology {
    let mut topology = topology_for(plan, 1);
    let mut producer = topology.units[0].clone();
    producer.workload = WorkloadId("producer".to_string());
    // Units are kept in ascending order, and "producer" sorts before the unit.
    topology.units.insert(0, producer);
    topology.edges.push(Edge {
        kind: EdgeKind::Stream,
        from: WorkloadId("producer".to_string()),
        to: WorkloadId(UNIT.to_string()),
    });
    topology
}

fn with_stream_edges(mut plan: ExecutionPlan, count: usize) -> ExecutionPlan {
    plan.stream_edges = (0..count)
        .map(|i| mvm_contract::stream::StreamEdge::new(format!("input-{i}")))
        .collect();
    plan
}

#[test]
fn a_stream_edge_the_topology_does_not_grant_is_refused_without_spending_its_nonce() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    let tenant = topology.tenant.0.clone();
    let ungranted = bind(with_stream_edges(plan.clone(), 1), &topology, UNIT);

    let expected = TopologyBindingRefusal::UngrantedStreamEdges {
        unit: WorkloadId(UNIT.to_string()),
        granted: 0,
        declared: 1,
    };
    assert_eq!(refusal(host.admit(&ungranted)), expected);
    let entry = host.last_entry(&tenant);
    assert_eq!(entry["event"], "plan.admission_refused");
    assert_eq!(entry["labels"]["stage"], TOPOLOGY_BINDING_STAGE);
    assert_eq!(refusal(host.admit(&ungranted)), expected);

    // The refused plan's nonce was never spent.
    host.admit(&bind(plan, &topology, UNIT))
        .expect("the nonce was never spent");
}

#[test]
fn stream_edges_the_topology_grants_are_admitted() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_with_stream_into_unit(&plan);
    host.admit_topology(&topology);
    host.admit(&bind(with_stream_edges(plan, 1), &topology, UNIT))
        .expect("admitted");
}

#[test]
fn more_stream_edges_than_the_topology_grants_are_refused() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_with_stream_into_unit(&plan);
    host.admit_topology(&topology);
    assert_eq!(
        refusal(host.admit(&bind(with_stream_edges(plan, 2), &topology, UNIT))),
        TopologyBindingRefusal::UngrantedStreamEdges {
            unit: WorkloadId(UNIT.to_string()),
            granted: 1,
            declared: 2,
        }
    );
}

#[test]
fn an_unbound_plan_with_stream_edges_is_admitted_as_before() {
    let host = Host::new();
    host.admit(&readdress(with_stream_edges(plan(), 1)))
        .expect("admitted");
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

/// The fleet issuer a host pins for externally signed plans.
fn fleet_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn trust_fleet() {
    let cfg = MvmConfig {
        trusted_plan_signers: vec![TrustedPlanSigner {
            signer_id: "fleet-prod".to_string(),
            ed25519_pubkey_hex: hex::encode(fleet_key().verifying_key().as_bytes()),
        }],
        ..MvmConfig::default()
    };
    mvm_core::user_config::save(&cfg, None).expect("writing the host config");
}

#[test]
fn an_externally_signed_plan_is_refused_the_same_way_without_spending_its_nonce() {
    let host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1);
    host.admit_topology(&topology);
    trust_fleet();
    let admit = |plan: &ExecutionPlan| {
        admit_signed_plan_for_run(
            &sign_plan(plan, &fleet_key(), "fleet-prod"),
            &SystemClock,
            &host.ledger,
            None,
            RunPosture::without_backend(Variant::Dev),
        )
    };

    let expected = TopologyBindingRefusal::Unbound {
        admitted: topology.digest(),
    };
    assert_eq!(refusal(admit(&plan)), expected);
    assert_eq!(refusal(admit(&plan)), expected);
    let admitted = admit(&bind(plan, &topology, UNIT)).expect("the nonce was never spent");
    assert_eq!(admitted.signer_id(), "fleet-prod");
}

fn refused_entries(host: &Host, tenant: &str) -> usize {
    let chain = host
        .home
        .path()
        .join("audit")
        .join(format!("{tenant}.jsonl"));
    std::fs::read_to_string(chain)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"]["event"]
                == "plan.admission_refused"
        })
        .count()
}

/// Boot through the shared admitted-boot entrypoint with a chain emitter, the
/// path whose caller also records admission failures.
fn admit_and_start_on_mock(host: &Host) -> Result<StartedMachine> {
    on_boot_path(host, |backend, params| admit_and_start(backend, params))
}

/// Run `admit` over the boot path's parameters for the fixture workload.
fn on_boot_path<T>(
    host: &Host,
    admit: impl FnOnce(&mvm_runtime::AnyBackend, AdmitAndStartParams<'_>) -> Result<T>,
) -> Result<T> {
    let keys = host.keys();
    let emitter = emitter(host.home.path(), &keys);
    admit(
        &mvm_runtime::AnyBackend::from_hypervisor("mock"),
        AdmitAndStartParams {
            synthesis: &fixture_input(UNIT),
            config: mvm_core::vm_backend::VmStartConfig {
                name: UNIT.into(),
                rootfs_path: "/store/rootfs.ext4".into(),
                ..Default::default()
            },
            clock: &SystemClock,
            ledger: &host.ledger,
            host_signer_keys_dir: Some(&keys),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
}

#[test]
fn a_refusal_on_the_boot_path_is_recorded_once() {
    let host = Host::new();
    let mut topology = topology_for(&plan(), 1);
    topology.units[0].workload = WorkloadId("vm-other".to_string());
    host.admit_topology(&topology);
    let tenant = topology.tenant.0.clone();

    let Err(err) = admit_and_start_on_mock(&host) else {
        panic!("expected the launch to be refused")
    };
    assert!(err.downcast_ref::<TopologyBindingRefusal>().is_some());
    assert_eq!(refused_entries(&host, &tenant), 1);
}

#[test]
fn an_unreadable_topology_record_refuses_and_is_recorded_once() {
    let host = Host::new();
    let topology = topology_for(&plan(), 1);
    host.admit_topology(&topology);
    let tenant = topology.tenant.0.clone();
    let dir = mvm_core::config::topologies_dir_at(host.home.path()).join(&tenant);
    for entry in std::fs::read_dir(&dir).unwrap() {
        std::fs::write(entry.unwrap().path(), b"not a record").unwrap();
    }

    let Err(err) = admit_and_start_on_mock(&host) else {
        panic!("expected the launch to be refused")
    };
    assert!(
        format!("{err:#}").contains("reading the topology admitted"),
        "got: {err:#}"
    );
    assert_eq!(refused_entries(&host, &tenant), 1);
}

/// Another tenant's topology holding core 0 exclusively.
fn holding_core_zero(plan: &ExecutionPlan) -> Topology {
    let mut topology = topology_for(plan, 1);
    topology.tenant = TenantId("other-tenant".to_string());
    topology.units[0].placement =
        CorePlacement::Exclusive(vec![mvm_contract::plan::topology::CoreId(0)]);
    topology
}

#[test]
fn nothing_is_refused_for_placement_while_no_core_is_held() {
    let host = Host::new();
    let admitted = host.admit(&plan()).expect("admitted as before");
    assert_eq!(admitted.allowed_cpus(), None);
}

#[test]
fn a_plan_that_cannot_be_confined_is_refused_while_cores_are_held_and_keeps_its_nonce() {
    let host = Host::new();
    let plan = plan();
    let holder = holding_core_zero(&plan);
    host.admit_topology_on(&holder, true);

    // No backend is known to this admission, so nothing can confine it.
    let err = host.admit(&plan).expect_err("refused while core 0 is held");
    assert!(
        matches!(
            err.downcast_ref::<super::placement::PlanPlacementRefusal>(),
            Some(super::placement::PlanPlacementRefusal::BackendCannotConfine { .. })
        ),
        "{err:#}"
    );
    assert!(
        err.downcast_ref::<super::topology_binding::TopologyRefusalAudited>()
            .is_some(),
        "the refusal is recorded by the check itself"
    );
    let entry = host.last_entry(&plan.tenant.0);
    assert_eq!(entry["event"], "plan.admission_refused");
    assert_eq!(entry["labels"]["stage"], CORE_PLACEMENT_STAGE);
    assert_eq!(refused_entries(&host, &plan.tenant.0), 1);

    // Once nothing holds a core, the same plan is admitted: its nonce was
    // never spent by the refusal.
    std::fs::remove_dir_all(
        mvm_core::config::topologies_dir_at(host.home.path()).join(&holder.tenant.0),
    )
    .unwrap();
    host.admit(&plan).expect("the nonce was never spent");
}

/// The two places hostd synthesizes a plan and then signs it.
#[derive(Debug, Clone, Copy)]
enum SynthesisSite {
    AdmitForRun,
    BootPath,
}

const SITES: [SynthesisSite; 2] = [SynthesisSite::AdmitForRun, SynthesisSite::BootPath];

impl Host {
    /// Synthesize the fixture workload's plan at `site` and admit it.
    fn synthesize_and_admit(&self, site: SynthesisSite) -> Result<AdmittedPlan> {
        match site {
            SynthesisSite::AdmitForRun => admit_for_run(
                &fixture_input(UNIT),
                &SystemClock,
                &self.ledger,
                Some(&self.keys()),
                None,
                RunPosture::without_backend(Variant::Dev),
            ),
            SynthesisSite::BootPath => on_boot_path(self, |backend, params| {
                admit_synthesized_with_verified_release(backend, &params, None)
            }),
        }
    }
}

#[test]
fn with_no_admitted_topology_a_synthesized_plan_keeps_its_exact_bytes() {
    let host = Host::new();
    let synthesized = plan();
    let mut bound = synthesized.clone();
    super::topology_binding::bind_synthesized_plan_at(
        host.home.path(),
        &mut bound,
        Some(&host.keys()),
    );
    let bytes = serde_json::to_vec(&bound).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&synthesized).unwrap());
    assert!(
        !String::from_utf8(bytes).unwrap().contains("\"topology\""),
        "an unbound plan omits the field"
    );
    // Each host holds the process-wide environment lock.
    drop(host);

    for site in SITES {
        let host = Host::new();
        let admitted = host.synthesize_and_admit(site).expect("admitted as before");
        assert_eq!(admitted.plan().topology, None, "{site:?}");
    }
}

#[test]
fn a_synthesized_plan_is_bound_to_the_admitted_topology_and_admitted() {
    for site in SITES {
        let host = Host::new();
        let topology = topology_for(&plan(), 1);
        host.admit_topology(&topology);
        let admitted = host.synthesize_and_admit(site).expect("admitted");
        assert_eq!(
            admitted.plan().topology,
            Some(TopologyBinding {
                topology: topology.digest(),
                unit: WorkloadId(UNIT.to_string()),
            }),
            "{site:?}"
        );
        assert_eq!(
            admitted.plan().plan_id,
            mvm_core::plan::compute_plan_id(admitted.plan()),
            "{site:?}: the id addresses the bound plan"
        );
    }
}

#[test]
fn a_synthesized_plan_the_topology_does_not_name_is_refused_as_an_unknown_unit_once() {
    for site in SITES {
        let host = Host::new();
        let mut topology = topology_for(&plan(), 1);
        topology.units[0].workload = WorkloadId("vm-other".to_string());
        host.admit_topology(&topology);
        let tenant = topology.tenant.0.clone();

        assert_eq!(
            refusal(host.synthesize_and_admit(site)),
            TopologyBindingRefusal::UnknownUnit {
                unit: WorkloadId(UNIT.to_string())
            },
            "{site:?}"
        );
        assert_eq!(refused_entries(&host, &tenant), 1, "{site:?}");
        let entry = host.last_entry(&tenant);
        assert_eq!(entry["event"], "plan.admission_refused", "{site:?}");
        assert_eq!(entry["labels"]["stage"], TOPOLOGY_BINDING_STAGE, "{site:?}");
    }
}

#[test]
fn a_synthesized_plan_for_another_recipe_is_refused() {
    for site in SITES {
        let host = Host::new();
        let mut topology = topology_for(&plan(), 1);
        topology.units[0].recipe =
            Sha256Digest::parse(format!("sha256:{}", "c".repeat(64))).unwrap();
        host.admit_topology(&topology);
        assert!(
            matches!(
                refusal(host.synthesize_and_admit(site)),
                TopologyBindingRefusal::RecipeMismatch { .. }
            ),
            "{site:?}"
        );
    }
}

#[test]
fn a_synthesized_plan_sized_differently_from_its_unit_is_refused() {
    for site in SITES {
        let host = Host::new();
        let mut topology = topology_for(&plan(), 1);
        topology.units[0].resources.mem_mib += 64;
        host.admit_topology(&topology);
        assert!(
            matches!(
                refusal(host.synthesize_and_admit(site)),
                TopologyBindingRefusal::ResourcesMismatch { .. }
            ),
            "{site:?}"
        );
    }
}
