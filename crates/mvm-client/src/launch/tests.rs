//! Mock-backed lifecycle tests for the launch module.
//!
//! Everything here drives the hermetic in-memory mock backend under an
//! isolated `MVM_HOME`, so the full admitted-boot path (signing, admission,
//! chain audit, leases, sidecars, registry) runs against real on-disk state
//! with no hypervisor.

#![cfg(feature = "test-support")]

use std::sync::Arc;

use super::*;
use crate::secret::{SecretService, SecretValueInput};
use mvm_core::client::MvmClient;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::keyholder::{FileBindingStore, SecretBindingMeta};
use mvm_protocol::ir::AuthType;

/// Isolated `MVM_HOME` for every test in this module. `TestEnv` serializes
/// process-wide env mutation behind its global lock.
struct Isolated {
    _env: TestEnv,
    dir: tempfile::TempDir,
}

impl Isolated {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        Self { _env: env, dir }
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }

    /// A minimal hashable rootfs file the mock backend boots.
    fn rootfs(&self) -> String {
        let path = self.path().join("rootfs.ext4");
        std::fs::write(&path, b"hashable-rootfs-bytes\n").expect("write rootfs");
        path.to_string_lossy().into_owned()
    }

    /// The tenant audit chain the admitted boot writes.
    fn audit_text(&self) -> String {
        let audit = std::path::PathBuf::from(mvm_core::config::mvm_home())
            .join("audit")
            .join("local.jsonl");
        std::fs::read_to_string(audit).unwrap_or_default()
    }
}

fn mock_client() -> LocalBackend {
    LocalBackend::with_hypervisor("mock")
}

/// A file-store-backed secret service rooted inside the isolated home whose
/// machines root matches the launch path's sidecar location.
fn fixture_secret_service(home: &Isolated) -> Arc<SecretService> {
    let service = SecretService::builder()
        .store(Arc::new(
            mvm_core::crypto::secret_store::FileSecretStore::with_dir(home.path().join("secrets")),
        ))
        .bindings(Arc::new(FileBindingStore::with_dir(
            home.path().join("bindings"),
        )))
        .machines_root(machine_state_root())
        .build()
        .expect("fixture secret service");
    Arc::new(service)
}

/// Store + bind one secret and return its typed reference.
fn seeded_secret_ref(service: &SecretService) -> MachineSecretRef {
    service
        .put(
            "local",
            "openai",
            SecretValueInput::new("sk-live-zzz".into()),
        )
        .expect("store secret");
    service
        .bind(
            "local",
            "openai",
            SecretBindingMeta {
                auth_type: AuthType::Bearer,
                allowed_hosts: vec!["api.openai.com".into()],
                sigv4: None,
            },
        )
        .expect("bind secret");
    MachineSecretRef {
        tenant: "local".into(),
        name: "openai".into(),
        placeholder_var: Some("API_KEY".into()),
        destinations: vec!["api.openai.com".into()],
    }
}

fn transient_request(image: &str) -> LaunchRequestBuilder {
    LaunchRequest::builder(LifecycleMode::Transient, image)
}

fn persistent_request(image: &str, name: &str) -> LaunchRequestBuilder {
    LaunchRequest::builder(LifecycleMode::Persistent, image).name(name)
}

async fn listed_names(client: &LocalBackend) -> Vec<String> {
    client
        .list_machines(mvm_core::client::dto::MachineFilter::all())
        .await
        .expect("list")
        .into_iter()
        .map(|m| m.name)
        .collect()
}

// ── Transient lifecycle ─────────────────────────────────────────────

#[tokio::test]
async fn transient_launch_boots_admitted_and_audited() {
    let home = Isolated::new();
    let client = mock_client();
    let request = transient_request(&home.rootfs())
        .name("t-happy")
        .build()
        .expect("request");

    let outcome = client.launch(request).await.expect("launch");
    assert_eq!(
        outcome.machine.status,
        mvm_core::client::dto::MachineStatus::Running
    );
    assert_eq!(outcome.machine.name, "t-happy");
    assert!(outcome.plan_id.starts_with("sha256:"), "content-addressed");
    assert!(listed_names(&client).await.contains(&"t-happy".to_string()));

    // The canonical admission emitted the chain-signed pair.
    let audit = home.audit_text();
    assert!(audit.contains("plan.admitted"), "got: {audit}");
    assert!(audit.contains("plan.launched"), "got: {audit}");
}

#[tokio::test]
async fn transient_launch_without_a_name_generates_one() {
    let home = Isolated::new();
    let client = mock_client();
    let request = transient_request(&home.rootfs()).build().expect("request");
    let outcome = client.launch(request).await.expect("launch");
    assert!(
        outcome.machine.name.starts_with("transient-"),
        "generated name: {}",
        outcome.machine.name
    );
}

#[tokio::test]
async fn transient_exit_reports_code_and_cleanup_is_idempotent() {
    let home = Isolated::new();
    let client = mock_client();
    let service = fixture_secret_service(&home);
    let secret_ref = seeded_secret_ref(&service);
    let client = client.with_secret_service(service);

    let request = transient_request(&home.rootfs())
        .name("t-exit")
        .secret_ref(secret_ref)
        .build()
        .expect("request");
    let outcome = client.launch(request).await.expect("launch");

    // The sidecar was recorded before boot.
    assert!(
        machine_state_dir("t-exit")
            .join(crate::secret::refs::MACHINE_SECRET_REFS_FILENAME)
            .exists()
    );

    // Simulate run-to-completion: the guest reports exit 7, then powers off.
    let state_dir = vm_state_dir("t-exit");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(mvm_core::exit_capture::exit_file_path(&state_dir), b"7\n").unwrap();
    client
        .stop_machine(&outcome.machine.id)
        .await
        .expect("stop");

    let report = client
        .wait_for_exit(
            &outcome,
            std::time::Duration::from_millis(10),
            std::time::Duration::from_secs(2),
        )
        .expect("wait for exit");
    assert_eq!(report.exit_code, Some(7));

    // Everything session-owned is gone …
    assert!(!machine_state_dir("t-exit").exists(), "sidecar dir removed");
    assert!(!listed_names(&client).await.contains(&"t-exit".to_string()));
    // … the exit landed in the chain …
    assert!(home.audit_text().contains("plan.exited"));
    // … and cleanup is idempotent.
    client.cleanup_transient("t-exit").expect("re-clean");
    client
        .cleanup_transient("never-launched")
        .expect("absent ok");
}

#[tokio::test]
async fn transient_failed_launch_rolls_back_session_state() {
    let home = Isolated::new();
    let service = fixture_secret_service(&home);
    let secret_ref = seeded_secret_ref(&service);
    let client = mock_client().with_secret_service(service);

    // An unparseable image reference fails resolution after the secret
    // refs were validated + recorded, before any boot.
    let request = transient_request("not a valid ref!!")
        .name("t-fail")
        .secret_ref(secret_ref)
        .build()
        .expect("request");
    let err = client.launch(request).await.unwrap_err();
    assert!(
        err.to_string().contains("parse image reference"),
        "got: {err}"
    );

    // Nothing session-owned leaks: no sidecar, no machine dir, no listing.
    assert!(!machine_state_dir("t-fail").exists());
    assert!(!listed_names(&client).await.contains(&"t-fail".to_string()));
}

#[tokio::test]
async fn transient_name_collisions_are_refused() {
    let home = Isolated::new();
    let client = mock_client();
    let rootfs = home.rootfs();

    // Collides with a running machine of the same name.
    let first = transient_request(&rootfs).name("t-dup").build().unwrap();
    client.launch(first).await.expect("first launch");
    let second = transient_request(&rootfs).name("t-dup").build().unwrap();
    let err = client.launch(second).await.unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Conflict { .. }),
        "got: {err}"
    );

    // Collides with a persisted definition of the same name.
    client
        .create_from_request(&persistent_request(&rootfs, "p-claimed").build().unwrap())
        .expect("create definition");
    let third = transient_request(&rootfs)
        .name("p-claimed")
        .build()
        .unwrap();
    let err = client.launch(third).await.unwrap_err();
    assert!(err.to_string().contains("persistent machine"), "got: {err}");
}

#[tokio::test]
async fn ttl_reaper_stops_and_cleans_expired_transients_only() {
    let home = Isolated::new();
    let client = mock_client();
    let rootfs = home.rootfs();

    let short = transient_request(&rootfs)
        .name("t-ttl")
        .ttl_seconds(1)
        .build()
        .unwrap();
    client.launch(short).await.expect("launch with ttl");

    // A persistent machine with an elapsed registry TTL must never be reaped
    // by the transient reaper.
    client
        .create_from_request(&persistent_request(&rootfs, "p-keep").build().unwrap())
        .expect("create persistent");

    // Before expiry nothing is reaped.
    let now = chrono::Utc::now().to_rfc3339();
    assert!(
        client
            .reap_expired_transients(&now)
            .expect("reap")
            .is_empty()
    );

    // Past expiry the transient is stopped + cleaned; the definition stays.
    let later = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let reaped = client.reap_expired_transients(&later).expect("reap");
    assert_eq!(reaped, vec!["t-ttl".to_string()]);
    assert!(!listed_names(&client).await.contains(&"t-ttl".to_string()));
    assert!(machine_spec_path("p-keep").exists(), "definition survives");

    // Idempotent: a second reap finds nothing.
    assert!(
        client
            .reap_expired_transients(&later)
            .expect("reap")
            .is_empty()
    );
}

// ── Persistent lifecycle ────────────────────────────────────────────

#[tokio::test]
async fn persistent_create_start_stop_restart_remove_roundtrip() {
    let home = Isolated::new();
    let service = fixture_secret_service(&home);
    let secret_ref = seeded_secret_ref(&service);
    let client = mock_client().with_secret_service(service);
    let rootfs = home.rootfs();

    // Create (persist without boot): definition + secret-ref sidecar land.
    let request = persistent_request(&rootfs, "p-web")
        .cpus(2)
        .memory_mib(256)
        .secret_ref(secret_ref)
        .build()
        .unwrap();
    let created = client.create_from_request(&request).expect("create");
    assert_eq!(
        created.status,
        mvm_core::client::dto::MachineStatus::Stopped
    );
    assert!(machine_spec_path("p-web").exists(), "definition persisted");
    assert!(
        machine_state_dir("p-web")
            .join(crate::secret::refs::MACHINE_SECRET_REFS_FILENAME)
            .exists(),
        "secret refs recorded at create"
    );

    // Start boots from the persisted definition through admission.
    let id = mvm_core::client::dto::MachineId("p-web".into());
    let started = client.start_machine(&id).await.expect("start");
    assert_eq!(
        started.status,
        mvm_core::client::dto::MachineStatus::Running
    );
    assert!(home.audit_text().contains("plan.launched"));
    // Starting again is a no-op reporting the running state.
    let again = client.start_machine(&id).await.expect("re-start");
    assert_eq!(again.status, mvm_core::client::dto::MachineStatus::Running);
    // The start stamped last_started_at on the spec.
    let spec = mvm_runtime::machine::persist::load_machine_spec("p-web").unwrap();
    assert!(spec.last_started_at.is_some());

    // Stop never deletes the definition; the machine stays in inventory.
    client.stop_machine(&id).await.expect("stop");
    assert!(machine_spec_path("p-web").exists(), "stop keeps the spec");
    let records = crate::inventory::list_local_inventory(&client)
        .await
        .expect("inventory");
    let record = records.iter().find(|r| r.name == "p-web").expect("listed");
    assert_eq!(record.kind, crate::inventory::MachineKind::Persistent);
    assert_eq!(record.status, mvm_core::client::dto::MachineStatus::Stopped);
    assert_eq!(record.secret_ref_count, 1, "sidecar count surfaces");

    // Restart = start from the stopped definition.
    let restarted = client.restart_persistent("p-web").await.expect("restart");
    assert_eq!(
        restarted.status,
        mvm_core::client::dto::MachineStatus::Running
    );
    client.stop_machine(&id).await.expect("stop again");

    // Remove is the separate confirmed action that deletes the definition
    // and clears the secret-reference sidecar.
    client.remove_machine(&id).await.expect("remove stopped");
    assert!(!machine_spec_path("p-web").exists());
    assert!(!machine_state_dir("p-web").exists());
    assert!(
        !mvm_core::config::vm_state_dir("p-web").exists(),
        "remove drops the per-VM runtime dir; a stale endpoint socket there \
         blocks the next launch under the same name"
    );
    // Idempotent: removing again is Ok.
    client.remove_machine(&id).await.expect("re-remove");

    // The name is immediately reusable: a fresh definition launches clean.
    let request = persistent_request(&home.rootfs(), "p-web").build().unwrap();
    let outcome = client.launch(request).await.expect("recreate same name");
    assert_eq!(
        outcome.machine.status,
        mvm_core::client::dto::MachineStatus::Running
    );
    client.stop_machine(&id).await.expect("stop recreated");
    client
        .remove_machine_with(&id, RemoveOptions { force: false })
        .await
        .expect("remove recreated");
}

#[tokio::test]
async fn persistent_launch_boots_and_reuses_same_config() {
    let home = Isolated::new();
    let client = mock_client();
    let rootfs = home.rootfs();

    let request = persistent_request(&rootfs, "p-run").build().unwrap();
    let outcome = client.launch(request).await.expect("launch persistent");
    assert_eq!(
        outcome.machine.status,
        mvm_core::client::dto::MachineStatus::Running
    );
    assert!(machine_spec_path("p-run").exists());

    // Launching again while running: same config reuses the definition but
    // refuses the double boot.
    let request = persistent_request(&rootfs, "p-run").build().unwrap();
    let err = client.launch(request).await.unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Conflict { .. }),
        "got: {err}"
    );
}

#[tokio::test]
async fn persistent_name_collision_needs_force_to_recreate() {
    let home = Isolated::new();
    let client = mock_client();
    let rootfs = home.rootfs();

    client
        .create_from_request(
            &persistent_request(&rootfs, "p-dup")
                .cpus(1)
                .build()
                .unwrap(),
        )
        .expect("create");

    // A different config without force is refused …
    let changed = persistent_request(&rootfs, "p-dup")
        .cpus(4)
        .build()
        .unwrap();
    let err = client.create_from_request(&changed).unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Conflict { .. }),
        "got: {err}"
    );
    assert!(err.to_string().contains("different config"), "got: {err}");

    // … and recreates with the explicit force flow.
    let forced = persistent_request(&rootfs, "p-dup")
        .cpus(4)
        .force(true)
        .build()
        .unwrap();
    client
        .create_from_request(&forced)
        .expect("forced recreate");
    let spec = mvm_runtime::machine::persist::load_machine_spec("p-dup").unwrap();
    assert_eq!(spec.cpus, 4);
}

#[tokio::test]
async fn removing_a_running_persistent_machine_needs_the_force_flow() {
    let home = Isolated::new();
    let client = mock_client();
    let request = persistent_request(&home.rootfs(), "p-live")
        .build()
        .unwrap();
    client.launch(request).await.expect("launch");

    let id = mvm_core::client::dto::MachineId("p-live".into());
    let err = client.remove_machine(&id).await.unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Conflict { .. }),
        "got: {err}"
    );
    assert!(
        machine_spec_path("p-live").exists(),
        "refusal keeps the spec"
    );

    client
        .remove_machine_with(&id, RemoveOptions { force: true })
        .await
        .expect("force remove");
    assert!(!machine_spec_path("p-live").exists());
    assert!(!listed_names(&client).await.contains(&"p-live".to_string()));
}

#[tokio::test]
async fn start_refuses_spec_shapes_the_in_process_backend_cannot_honor() {
    let _home = Isolated::new();
    let client = mock_client();
    let mut spec = mvm_runtime::machine::persist::MachineSpec {
        schema_version: mvm_runtime::machine::persist::MACHINE_SPEC_SCHEMA_VERSION,
        name: "p-net".into(),
        image: Some("alpine:latest".into()),
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        net: true,
        allow_host: vec![],
        cpus: 1,
        memory: "128M".into(),
        mem_initial: None,
        profile: "standard".into(),
        volumes: vec![],
        init: vec![],
        agent_verb: vec![],
        created_at: None,
        last_started_at: None,
        health_check: None,
    };
    mvm_runtime::machine::persist::save_machine_spec(&spec, false).unwrap();
    let err = client
        .start_machine(&mvm_core::client::dto::MachineId("p-net".into()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("deny-all"), "got: {err}");

    spec.name = "p-vol".into();
    spec.net = false;
    spec.volumes = vec!["/h:/data".into()];
    mvm_runtime::machine::persist::save_machine_spec(&spec, false).unwrap();
    let err = client
        .start_machine(&mvm_core::client::dto::MachineId("p-vol".into()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("volume"), "got: {err}");

    // A machine that was never created is NotFound.
    let err = client
        .start_machine(&mvm_core::client::dto::MachineId("p-ghost".into()))
        .await
        .unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::NotFound { .. }),
        "got: {err}"
    );
}

// ── Admission refusals ──────────────────────────────────────────────

#[tokio::test]
async fn launch_refuses_secret_ref_without_binding_and_boots_nothing() {
    let home = Isolated::new();
    let service = fixture_secret_service(&home);
    // Stored value but no egress binding → admission must fail closed.
    service
        .put("local", "unbound", SecretValueInput::new("sk-x".into()))
        .unwrap();
    let client = mock_client().with_secret_service(service);

    let request = transient_request(&home.rootfs())
        .name("t-refused")
        .secret_ref(MachineSecretRef {
            tenant: "local".into(),
            name: "unbound".into(),
            placeholder_var: None,
            destinations: vec![],
        })
        .build()
        .unwrap();
    let err = client.launch(request).await.unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Rejected { .. }),
        "got: {err}"
    );
    assert!(err.to_string().contains("no egress binding"), "got: {err}");

    // Refused before boot: nothing listed, no chain launch entry.
    assert!(
        !listed_names(&client)
            .await
            .contains(&"t-refused".to_string())
    );
    assert!(!home.audit_text().contains("plan.launched"));
}

#[tokio::test]
async fn launch_refuses_cross_scope_secret_reference() {
    let home = Isolated::new();
    let service = fixture_secret_service(&home);
    let client = mock_client().with_secret_service(service);
    let request = transient_request(&home.rootfs())
        .name("t-cross")
        .secret_ref(MachineSecretRef {
            tenant: "acme".into(),
            name: "openai".into(),
            placeholder_var: None,
            destinations: vec![],
        })
        .build()
        .unwrap();
    let err = client.launch(request).await.unwrap_err();
    assert!(err.to_string().contains("cross-scope"), "got: {err}");
}

#[tokio::test]
async fn persistent_relaunch_revalidates_sidecar_refs_recorded_earlier() {
    let home = Isolated::new();
    let service = fixture_secret_service(&home);
    let secret_ref = seeded_secret_ref(&service);
    let client = mock_client().with_secret_service(service.clone());
    let rootfs = home.rootfs();

    // Create the definition WITH a secret reference, then stop the machine.
    let with_refs = persistent_request(&rootfs, "p-refs")
        .secret_ref(secret_ref)
        .build()
        .unwrap();
    let outcome = client.launch(with_refs).await.expect("first launch");
    client
        .stop_machine(&outcome.machine.id)
        .await
        .expect("stop");

    // Revoke the binding out from under the recorded sidecar.
    service.unbind("local", "openai").expect("revoke binding");

    // An identical-config launch carrying NO refs hits the Reuse arm — the
    // sidecar's recorded references must still be re-validated fail-closed.
    let without_refs = persistent_request(&rootfs, "p-refs").build().unwrap();
    let err = client.launch(without_refs).await.unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Rejected { .. }),
        "got: {err}"
    );
    assert!(err.to_string().contains("no egress binding"), "got: {err}");
    assert!(
        !listed_names(&client).await.contains(&"p-refs".to_string()),
        "nothing boots on a refused relaunch"
    );
}

#[tokio::test]
async fn launch_over_a_deployment_backed_spec_refuses_a_silent_image_boot() {
    let home = Isolated::new();
    let client = mock_client();
    let rootfs = home.rootfs();

    // A definition carrying an attested-deployment source (created by the
    // CLI's deployment flow, which this backend cannot honor).
    let spec = mvm_runtime::machine::persist::MachineSpec {
        deployment: Some("/deployments/web".into()),
        ..super::persisted_spec_from_request(
            &persistent_request(&rootfs, "p-deploy").build().unwrap(),
            "p-deploy",
        )
    };
    mvm_runtime::machine::persist::save_machine_spec(&spec, false).unwrap();

    // The bootability gate refuses the source outright …
    let err = super::ensure_spec_bootable_in_process(&spec).unwrap_err();
    assert!(
        err.to_string().contains("attested-deployment"),
        "got: {err}"
    );

    // … and a same-image launch never silently boots it as a plain image:
    // the deployment field is part of the launch config, so the reconcile
    // refuses without the explicit force flow.
    let request = persistent_request(&rootfs, "p-deploy").build().unwrap();
    let err = client.launch(request).await.unwrap_err();
    assert!(
        matches!(err, mvm_core::client::MvmError::Conflict { .. }),
        "got: {err}"
    );
    assert!(err.to_string().contains("different config"), "got: {err}");

    // `start` refuses the same source fail-closed.
    let err = client
        .start_machine(&mvm_core::client::dto::MachineId("p-deploy".into()))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("attested-deployment"),
        "got: {err}"
    );
}

// ── Per-backend workload-kernel resolution ──────────────────────────

#[test]
fn firecracker_admitted_boot_receives_a_concrete_kernel_path() {
    let home = Isolated::new();
    let fc = mvm_runtime::AnyBackend::from_hypervisor("firecracker");

    // Cold cache: the Firecracker arm fails with the CLI's build hint —
    // never `Ok(None)`, which the FC driver would hard-refuse as a
    // bundled-kernel spec at boot time.
    let err = LocalBackend::resolve_workload_kernel(&fc).unwrap_err();
    assert!(
        err.to_string().contains("mvmctl kernel build"),
        "got: {err}"
    );

    // Seed the exact cache location the CLI's machine-run boot path reads:
    // `<cache>/builder-vm/<arch>/kernels/workload/vmlinux`.
    let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let cached = mvm_build::kernel_fetch::cached_kernel_path(&cache, &arch, "workload");
    std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
    std::fs::write(&cached, b"kernel-bytes").unwrap();

    let resolved = LocalBackend::resolve_workload_kernel(&fc)
        .expect("cached kernel resolves")
        .expect("firecracker must receive a concrete kernel path");
    assert_eq!(resolved, cached);

    // Bundled-kernel backends need no host kernel path: libkrun boots the
    // libkrunfw kernel, the hermetic mock boots nothing.
    let libkrun = mvm_runtime::AnyBackend::from_hypervisor("libkrun");
    assert_eq!(
        LocalBackend::resolve_workload_kernel(&libkrun).unwrap(),
        None
    );
    let mock = mvm_runtime::AnyBackend::from_hypervisor("mock");
    assert_eq!(LocalBackend::resolve_workload_kernel(&mock).unwrap(), None);

    drop(home);
}

// ── Typed volume attachments ────────────────────────────────────────

#[tokio::test]
async fn launch_with_managed_volume_takes_and_releases_the_lease() {
    use crate::volume::{CreateBlockVolumeRequest, VolumeService as _};

    let home = Isolated::new();
    let client = mock_client();
    let rootfs = home.rootfs();

    // A managed encrypted block volume, unlocked so it can be attached.
    let volumes = crate::volume::LocalVolumeService::new();
    volumes
        .create_block_volume(
            &CreateBlockVolumeRequest::builder("work")
                .unwrap()
                .capacity_mib(16)
                .build()
                .unwrap(),
        )
        .expect("create volume");
    volumes.unlock_volume("work").expect("unlock");

    let request = persistent_request(&rootfs, "p-vols")
        .volume(LaunchVolumeSpec {
            volume: "work".into(),
            guest_path: "/data/work".into(),
            access: AccessMode::ReadOnly,
        })
        .build()
        .unwrap();
    let outcome = client.launch(request).await.expect("launch with volume");
    assert_eq!(
        outcome.machine.status,
        mvm_core::client::dto::MachineStatus::Running
    );

    // The lease is held by the running machine …
    let record = volumes.describe_volume("work").expect("describe");
    assert_eq!(record.attached_to.as_deref(), Some("p-vols"));

    // … a second launch attaching the same artifact is refused …
    let rival = persistent_request(&rootfs, "p-rival")
        .volume(LaunchVolumeSpec {
            volume: "work".into(),
            guest_path: "/data/work".into(),
            access: AccessMode::ReadOnly,
        })
        .build()
        .unwrap();
    let err = client.launch(rival).await.unwrap_err();
    assert!(err.to_string().contains("already attached"), "got: {err}");

    // … and the stop path releases it.
    client
        .stop_machine(&mvm_core::client::dto::MachineId("p-vols".into()))
        .await
        .expect("stop");
    let record = volumes.describe_volume("work").expect("describe");
    assert_eq!(record.attached_to, None, "lease released on stop");
}

// ── Audit hygiene ───────────────────────────────────────────────────

#[tokio::test]
async fn lifecycle_audit_carries_no_secret_values_or_env() {
    let home = Isolated::new();
    let service = fixture_secret_service(&home);
    let secret_ref = seeded_secret_ref(&service);
    let client = mock_client().with_secret_service(service);

    let request = transient_request(&home.rootfs())
        .name("t-hygiene")
        .secret_ref(secret_ref)
        .build()
        .unwrap();
    let outcome = client.launch(request).await.expect("launch");
    client
        .stop_machine(&outcome.machine.id)
        .await
        .expect("stop");
    client.report_exit(&outcome).expect("exit report");

    // Walk every file the lifecycle wrote under the audit dir plus the
    // machine dirs: the stored secret value must appear nowhere, and no
    // environment-shaped assignment leaks either.
    let audit = home.audit_text();
    assert!(audit.contains("plan.admitted") && audit.contains("plan.exited"));
    assert!(
        !audit.contains("sk-live-zzz"),
        "secret value in audit: {audit}"
    );
    assert!(
        !audit.contains("API_KEY="),
        "env assignment in audit: {audit}"
    );

    let mut stack = vec![std::path::PathBuf::from(mvm_core::config::mvm_home())];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // The encrypted secret store itself is allowed to hold the
                // (encrypted) value; everything else must not.
                if path.ends_with("secrets") {
                    continue;
                }
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("sk-live-zzz"),
                    "secret value leaked into {}",
                    path.display()
                );
            }
        }
    }
}
