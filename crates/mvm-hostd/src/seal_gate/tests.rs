use std::os::unix::fs::PermissionsExt;

use mvm_contract::plan::topology::SealedTransitions;
use mvm_core::util::test_env::TestEnv;

use super::test_support::{admit, seal, topology_for};
use super::*;

const VM: &str = "sealed-vm";

/// An isolated mvm home. The guard holds the process environment.
struct Host {
    _env: TestEnv,
    home: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("scratch mvm home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        Self { _env: env, home }
    }

    fn refusals(&self, tenant: &str) -> Vec<serde_json::Value> {
        let chain = self
            .home
            .path()
            .join("audit")
            .join(format!("{tenant}.jsonl"));
        let Ok(content) = std::fs::read_to_string(chain) else {
            return Vec::new();
        };
        content
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
            .filter(|entry| entry["event"] == MUTATION_REFUSED_EVENT)
            .collect()
    }
}

fn plan() -> ExecutionPlan {
    mvm_core::plan::test_support::PlanFixture::new()
        .tenant("seal-tenant")
        .workload(VM)
        .build()
}

fn refusal(result: Result<()>) -> SealRefusal {
    let err = result.expect_err("expected a refusal");
    err.downcast_ref::<SealRefusal>()
        .unwrap_or_else(|| panic!("expected a seal refusal, got {err:#}"))
        .clone()
}

const ALL_PERMITS: SealedTransitions = SealedTransitions {
    sleep: true,
    wake: true,
    pause: true,
    checkpoint: true,
};

#[test]
fn a_vm_with_no_persisted_plan_is_unsealed_and_every_change_is_allowed() {
    let host = Host::new();
    for mutation in Mutation::ALL {
        authorize(VM, mutation).unwrap_or_else(|e| panic!("{mutation}: {e:#}"));
    }
    assert!(host.refusals(mvm_core::plan::DEFAULT_TENANT).is_empty());
}

#[test]
fn a_vm_whose_plan_is_unbound_is_unsealed() {
    let host = Host::new();
    plan_persist::write_plan(VM, &plan()).unwrap();
    for mutation in Mutation::ALL {
        authorize(VM, mutation).unwrap_or_else(|e| panic!("{mutation}: {e:#}"));
    }
    assert!(host.refusals("seal-tenant").is_empty());
}

#[test]
fn a_sealed_unit_that_declares_nothing_refuses_every_change_and_audits_each_once() {
    let host = Host::new();
    let plan = seal(VM, plan(), SealedTransitions::default()).unwrap();
    for (i, mutation) in Mutation::ALL.into_iter().enumerate() {
        let expected = if mutation.declarable() {
            SealRefusal::NotDeclared {
                vm: VM.into(),
                unit: VM.into(),
                mutation,
            }
        } else {
            SealRefusal::Sealed {
                vm: VM.into(),
                unit: VM.into(),
                mutation,
            }
        };
        assert_eq!(refusal(authorize(VM, mutation)), expected);
        let refusals = host.refusals("seal-tenant");
        assert_eq!(refusals.len(), i + 1, "exactly one entry per refusal");
        let entry = refusals.last().unwrap();
        assert_eq!(entry["plan_id"], plan.plan_id.0.as_str());
        assert_eq!(entry["labels"]["vm"], VM);
        assert_eq!(entry["labels"]["mutation"], mutation.label());
        assert_eq!(entry["labels"]["reason"], expected.to_string());
    }
}

#[test]
fn a_sealed_unit_allows_exactly_the_transitions_it_declares() {
    let host = Host::new();
    seal(VM, plan(), ALL_PERMITS).unwrap();
    let mut refused = 0;
    for mutation in Mutation::ALL {
        let result = authorize(VM, mutation);
        if mutation.declarable() {
            result.unwrap_or_else(|e| panic!("{mutation} is declared: {e:#}"));
        } else {
            assert!(matches!(refusal(result), SealRefusal::Sealed { .. }));
            refused += 1;
        }
    }
    assert_eq!(host.refusals("seal-tenant").len(), refused);
}

#[test]
fn resume_follows_either_pause_or_wake() {
    let none = SealedTransitions::default();
    let pause = SealedTransitions {
        pause: true,
        ..none
    };
    let wake = SealedTransitions { wake: true, ..none };
    let sleep = SealedTransitions {
        sleep: true,
        ..none
    };
    assert!(Mutation::Resume.permitted_by(&pause));
    assert!(Mutation::Resume.permitted_by(&wake));
    assert!(!Mutation::Resume.permitted_by(&sleep));
    assert!(!Mutation::Resume.permitted_by(&none));
    assert!(!Mutation::Pause.permitted_by(&wake));
    assert!(!Mutation::Checkpoint.permitted_by(&pause));
}

#[test]
fn a_plan_file_that_cannot_be_read_is_refused_on_the_default_chain() {
    let host = Host::new();
    let dir = mvm_core::config::vm_state_dir(VM);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(plan_persist::PLAN_FILENAME);
    std::fs::write(&path, b"not a plan").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let refused = refusal(authorize(VM, Mutation::Pause));
    assert!(
        matches!(refused, SealRefusal::PlanUnreadable { .. }),
        "{refused:?}"
    );
    let refusals = host.refusals(mvm_core::plan::DEFAULT_TENANT);
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["labels"]["mutation"], "pause");
}

#[test]
fn a_sealed_unit_whose_topology_was_superseded_is_refused_even_a_declared_change() {
    let host = Host::new();
    let plan = seal(VM, plan(), ALL_PERMITS).unwrap();
    admit(&topology_for(&plan, 2, ALL_PERMITS)).unwrap();

    let refused = refusal(authorize(VM, Mutation::Pause));
    assert!(
        matches!(
            refused,
            SealRefusal::TopologyMismatch {
                refusal: TopologyBindingRefusal::DigestMismatch { .. },
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(host.refusals("seal-tenant").len(), 1);
}

#[test]
fn a_bound_plan_is_persisted_and_an_unbound_one_is_left_alone() {
    let _host = Host::new();
    let unbound = plan();
    persist_sealed_plan("unbound", &unbound).unwrap();
    assert!(!plan_persist::plan_path("unbound").unwrap().exists());

    let topology = topology_for(&unbound, 1, SealedTransitions::default());
    let bound = test_support::bind(unbound, &topology);
    persist_sealed_plan("bound", &bound).unwrap();
    assert_eq!(plan_persist::read_plan("bound").unwrap(), bound);
}

#[test]
fn a_bound_plan_that_cannot_be_persisted_fails() {
    let _host = Host::new();
    let plan = plan();
    let topology = topology_for(&plan, 1, SealedTransitions::default());
    let bound = test_support::bind(plan, &topology);
    // A file where the VM's state directory belongs.
    let dir = mvm_core::config::vm_state_dir("blocked");
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::fs::write(&dir, b"").unwrap();
    persist_sealed_plan("blocked", &bound).expect_err("the bound plan cannot be persisted");
}
