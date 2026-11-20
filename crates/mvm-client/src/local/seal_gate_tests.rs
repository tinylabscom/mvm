//! The seal gate at `LocalBackend`'s mutation surface, over the mock backend:
//! a sealed unit refuses and audits each change, an unsealed one and one that
//! declares the change go through, and stopping and quarantine are never
//! gated.

use mvm_contract::plan::topology::SealedTransitions;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::seal_gate::test_support::{seal, seal_all};
use mvm_hostd::seal_gate::{MUTATION_REFUSED_EVENT, SealRefusal};

use super::*;

const TEST_SNAPSHOT_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// An isolated mvm home with a snapshot key, so a mock pause can seal.
struct Host {
    _env: TestEnv,
    _home: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.set(
            mvm_runtime::vm::instance_snapshot::SNAPSHOT_TENANT_KEY_ENV,
            TEST_SNAPSHOT_KEY_HEX,
        );
        Self {
            _env: env,
            _home: home,
        }
    }
}

/// A registered mock machine `name`, sealed with `permits` unless `None`.
fn machine(name: &str, permits: Option<SealedTransitions>) -> MachineId {
    std::fs::create_dir_all(mvm_runtime::MockBackend::vm_dir(name)).unwrap();
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    let mut registry = VmNameRegistry::load(&registry_path).unwrap();
    registry
        .register(mvm_runtime::vm::name_registry::RegisterParams::minimal(
            name,
            &format!("/vms/{name}"),
            "default",
        ))
        .unwrap();
    registry.save(&registry_path).unwrap();
    if let Some(permits) = permits {
        seal(name, plan_for(name), permits).expect("sealed");
    }
    MachineId(name.into())
}

fn plan_for(name: &str) -> mvm_core::plan::ExecutionPlan {
    mvm_core::plan::test_support::PlanFixture::new()
        .workload(name)
        .build()
}

fn set_paused(name: &str, paused: bool) {
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    let mut registry = VmNameRegistry::load(&registry_path).unwrap();
    registry.set_paused(name, paused).unwrap();
    registry.save(&registry_path).unwrap();
}

fn is_paused(name: &str) -> bool {
    VmNameRegistry::load(&mvm_runtime::vm::name_registry::registry_path())
        .unwrap()
        .lookup(name)
        .is_some_and(|record| record.paused)
}

fn expiry(name: &str) -> Option<String> {
    VmNameRegistry::load(&mvm_runtime::vm::name_registry::registry_path())
        .unwrap()
        .lookup(name)
        .and_then(|record| record.expires_at.clone())
}

fn refusals() -> usize {
    std::fs::read_to_string(mvm_hostd::audit::emitter::audit_path_for_tenant(
        &mvm_core::config::mvm_audit_dir(),
        mvm_core::plan::DEFAULT_TENANT,
    ))
    .unwrap_or_default()
    .matches(MUTATION_REFUSED_EVENT)
    .count()
}

#[derive(Clone, Copy, Debug)]
enum Site {
    Pause,
    Resume,
    SetTtl,
}

const SITES: [Site; 3] = [Site::Pause, Site::Resume, Site::SetTtl];

async fn drive(be: &LocalBackend, id: &MachineId, site: Site) -> Result<()> {
    match site {
        Site::Pause => be.pause_machine(id, PauseOpts::default()).await.map(|_| ()),
        Site::Resume => be
            .resume_machine(id, ResumeOpts::default())
            .await
            .map(|_| ()),
        Site::SetTtl => be.set_ttl(id, Some("2030-01-02T03:04:05Z".into())).await,
    }
}

/// What the site would have changed, so a refusal can be shown to change
/// nothing.
fn effect(name: &str, site: Site) -> bool {
    match site {
        Site::Pause => is_paused(name),
        // The resume's own setup marks the machine paused; a refused resume
        // leaves it so.
        Site::Resume => !is_paused(name),
        Site::SetTtl => expiry(name).is_some(),
    }
}

#[tokio::test]
async fn each_site_refuses_and_audits_once_for_a_sealed_unit_and_changes_nothing() {
    let _host = Host::new();
    let be = LocalBackend::with_hypervisor("mock");
    let names: Vec<String> = (0..SITES.len()).map(|i| format!("sealed-{i}")).collect();
    let units: Vec<_> = names
        .iter()
        .map(|name| {
            machine(name, None);
            (name.as_str(), plan_for(name), SealedTransitions::default())
        })
        .collect();
    seal_all(&units).expect("sealed");
    for (i, (site, name)) in SITES.into_iter().zip(&names).enumerate() {
        let id = MachineId(name.clone());
        if matches!(site, Site::Resume) {
            set_paused(name, true);
        }
        let err = drive(&be, &id, site)
            .await
            .expect_err("a sealed unit refuses");
        let MvmError::Rejected { reason } = &err else {
            panic!("{site:?}: expected a rejection, got {err:?}");
        };
        assert!(reason.contains("is sealed"), "{site:?}: {reason}");
        assert_eq!(refusals(), i + 1, "{site:?}: exactly one entry per refusal");
        assert!(
            !effect(name, site),
            "{site:?}: a refusal changed the machine"
        );
    }
}

#[tokio::test]
async fn each_site_is_allowed_for_an_unsealed_unit() {
    let _host = Host::new();
    let be = LocalBackend::with_hypervisor("mock");
    for (i, site) in SITES.into_iter().enumerate() {
        let name = format!("open-{i}");
        let id = machine(&name, None);
        if matches!(site, Site::Resume) {
            be.pause_machine(&id, PauseOpts::default()).await.unwrap();
        }
        drive(&be, &id, site)
            .await
            .unwrap_or_else(|e| panic!("{site:?}: {e:?}"));
        assert!(effect(&name, site), "{site:?}: the change did not happen");
    }
    assert_eq!(refusals(), 0);
}

#[tokio::test]
async fn pause_and_resume_go_through_when_the_topology_declares_them() {
    let _host = Host::new();
    let be = LocalBackend::with_hypervisor("mock");
    let permits = SealedTransitions {
        pause: true,
        ..SealedTransitions::default()
    };
    let id = machine("declared", Some(permits));
    be.pause_machine(&id, PauseOpts::default())
        .await
        .expect("a declared pause");
    be.resume_machine(&id, ResumeOpts::default())
        .await
        .expect("a resume follows a declared pause");
    let err = be
        .set_ttl(&id, None)
        .await
        .expect_err("an expiry change is never declarable");
    assert!(matches!(err, MvmError::Rejected { .. }), "{err:?}");
    assert_eq!(refusals(), 1);
}

#[tokio::test]
async fn a_sealed_unit_can_still_be_stopped_and_quarantined() {
    let host = Host::new();
    let rootfs = host._home.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"hashable-rootfs-bytes\n").unwrap();
    let be = LocalBackend::with_hypervisor("mock");
    let state = be
        .run_machine(MachineSpec {
            name: "stoppable".into(),
            image: rootfs.to_string_lossy().parse().expect("a path parses"),
            cpus: 1,
            memory_mib: 128,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        })
        .await
        .expect("boot");
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .workload(state.id.0.as_str())
        .build();
    seal(&state.id.0, plan, SealedTransitions::default()).expect("sealed");
    let id = state.id;
    be.stop_machine(&id).await.expect("stopping is not gated");
    assert!(
        !be.list_machines(MachineFilter::all())
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == id),
        "the sealed machine stopped"
    );
    crate::containment::quarantine(&id.0, "contained").expect("quarantine is not gated");
    assert_eq!(refusals(), 0);
}

#[test]
fn the_refusal_is_the_gates_typed_reason() {
    let _host = Host::new();
    machine("typed", Some(SealedTransitions::default()));
    let err = mvm_hostd::seal_gate::authorize("typed", mvm_hostd::seal_gate::Mutation::Expiry)
        .expect_err("refused");
    assert!(matches!(
        err.downcast_ref::<SealRefusal>(),
        Some(SealRefusal::Sealed { .. })
    ));
}
