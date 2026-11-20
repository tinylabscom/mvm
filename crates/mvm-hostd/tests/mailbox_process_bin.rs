//! The `mvm-mailbox` binary refuses a config it does not recognise before it
//! binds or dials anything.

use std::io::Write as _;
use std::process::{Command, Stdio};

#[path = "mailbox_process_bin/actor_crash.rs"]
mod actor_crash;

fn run_with(stdin: &[u8]) -> std::process::ExitStatus {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mvm-mailbox"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mvm-mailbox");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait().expect("wait")
}

#[test]
fn an_empty_config_and_an_unknown_field_are_refused() {
    assert!(!run_with(b"").success());
    assert!(!run_with(br#"{"seed":"00"}"#).success());
}

struct ActorFixture {
    home: std::path::PathBuf,
    owner: mvm_hostd::actor_lifecycle::local_mailboxes::LocalActorMailboxes,
    plan: mvm_contract::plan::ExecutionPlan,
}

fn actor_fixture(home: &std::path::Path) -> ActorFixture {
    use mvm_contract::assurance::Sha256Digest;
    use mvm_contract::protocol::mailbox::*;
    use mvm_contract::protocol::workload_actor::*;
    use mvm_core::plan::{compute_plan_id, test_support::PlanFixture};
    use mvm_hostd::actor_lifecycle::local_mailboxes::{ActorMailboxPolicy, LocalActorMailboxes};
    use std::num::NonZeroU64;

    let keys_dir = home.join("keys");
    mvm_hostd::audit::host_keypair::load_or_init_at(&keys_dir).unwrap();
    let mut plan = PlanFixture::new().build();
    let epoch = ExecutionEpoch::new(1).unwrap();
    plan.workflow = Some(WorkflowBinding {
        version: ActorProtocolVersion::V1,
        workflow_id: ActorBindingId::new("workflow").unwrap(),
        constraint_snapshot_digest: Sha256Digest::from_bytes(&[5; 32]),
        role: WorkflowRole::Controller {
            grant: LifecycleGrant {
                id: ActorBindingId::new("controller").unwrap(),
                controller: ControllerIdentity {
                    tenant: plan.tenant.clone(),
                    workload: plan.workload.clone(),
                    execution_epoch: epoch,
                    boot_id: BootId::from_bytes([3; 32]),
                    generation: NonZeroU64::new(1).unwrap(),
                },
                depth: DelegationDepth::One,
                templates: vec![TemplateBinding {
                    id: ActorBindingId::new("child").unwrap(),
                    digest: Sha256Digest::from_bytes(&[6; 32]),
                }],
                operations: vec![LifecycleOperation::Launch],
                not_before_unix_ms: plan.valid_from.timestamp_millis(),
                expires_at_unix_ms: plan.valid_until.timestamp_millis(),
                workflow_deadline_unix_ms: plan.valid_until.timestamp_millis(),
            },
        },
    });
    plan.mailbox = Some(MailboxGrant {
        mailbox: MailboxId::from_bytes([7; 32]),
        authority_key: [0; 32],
        epoch,
        report: None,
        retention: Some(MailboxRetentionPolicy::new(10_000).unwrap()),
        service_blind: None,
    });
    let owner = LocalActorMailboxes::new(
        keys_dir.clone(),
        ActorMailboxPolicy {
            tenant: TenantId::from_bytes([1; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
            content_types: vec![ContentType::parse("application/vnd.mvm.actor-test", 1).unwrap()],
            max_payload_bytes: 1024,
            max_messages_per_minute: 60,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 4096,
            max_storage_bytes: 8 * 1024 * 1024,
            max_send_attempts: 8,
            policy_epoch: 1,
            not_before_unix_ms: plan.valid_from.timestamp_millis(),
            expires_at_unix_ms: plan.valid_until.timestamp_millis(),
        },
        [5; 32],
    )
    .unwrap();
    plan.mailbox = Some(owner.install_controller(&plan).unwrap());
    plan.plan_id = compute_plan_id(&plan);
    ActorFixture {
        home: home.to_owned(),
        owner,
        plan,
    }
}

fn actor_process_config(
    home: &std::path::Path,
    plan: &mvm_contract::plan::ExecutionPlan,
    ack_seed: u8,
) -> mvm_hostd::mailbox_process::MailboxProcessConfig {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::sign_plan;
    use mvm_hostd::mailbox_launch::{actor_template, derive_launch_keys, mint_epoch_secret};
    use mvm_hostd::mailbox_process::MailboxProcessConfig;
    use mvm_vmm::host::flowmux_identity::{InheritableIdentity, MailboxReaderBootBinding};

    let keys_dir = home.join("keys");
    let state = mvm_core::config::vm_state_dir_at(home, &plan.image.name);
    std::fs::create_dir_all(mvm_core::config::vm_socket_dir_at(&state)).unwrap();
    let signed = sign_plan(plan, &SigningKey::from_bytes(&[41; 32]), "test");
    std::fs::write(
        state.join("plan.json"),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    let identity = SigningKey::from_bytes(&[45; 32]).verifying_key();
    let boot = MailboxReaderBootBinding::mint(
        plan,
        identity,
        SigningKey::from_bytes(&[ack_seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    boot.persist(&state).unwrap();
    InheritableIdentity {
        session_id: "actor-test".into(),
        guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
            .encode(identity.as_bytes()),
    }
    .persist(&state)
    .unwrap();
    let grant = plan.mailbox.unwrap();
    let secret = mint_epoch_secret(&state).unwrap();
    MailboxProcessConfig {
        grant,
        keys: derive_launch_keys(&keys_dir, &grant, &secret).unwrap(),
        actor: actor_template::endpoint_material(&keys_dir, plan).unwrap(),
        // The helper must never need to open the launcher's root keys.
        keys_dir: home.join("unavailable-root-keys"),
        socket: mvm_core::config::vm_mailbox_socket_at(&state),
        route: mvm_core::vm_backend::HostDialRoute::PortSocket(state.join("guest.sock")),
        posture: Some(
            serde_json::from_value(serde_json::json!({
                "variant": "prod",
                "plan_id": plan.plan_id,
                "plan_nonce": plan.nonce,
                "vm_name": plan.image.name,
                "grant": grant,
                "reader_boot": boot.boot,
            }))
            .unwrap(),
        ),
        reader_boot: Some(boot),
        vm_state_dir: state,
        coordinator: None,
    }
}

#[test]
fn actor_helper_assembles_current_plan_and_reader_before_ready() {
    use std::io::Read as _;
    use std::time::Duration;

    let home = tempfile::tempdir_in("/tmp").unwrap();
    let fixture = actor_fixture(home.path());
    let config = actor_process_config(&fixture.home, &fixture.plan, 44);
    let mut child = Command::new(env!("CARGO_BIN_EXE_mvm-mailbox"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&config).unwrap())
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut ready = [0; 6];
        let result = stdout.read_exact(&mut ready).map(|()| ready);
        let _ = tx.send(result);
    });
    let ready = rx.recv_timeout(Duration::from_secs(10));
    // Model a guest whose mailbox port starts after the host helper is ready.
    std::thread::sleep(Duration::from_millis(200));
    let reconnect = (|| -> std::io::Result<()> {
        use std::os::fd::AsRawFd as _;
        let listener =
            std::os::unix::net::UnixListener::bind(config.vm_state_dir.join("guest.sock"))?;
        for _ in 0..2 {
            let mut event = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: event is a valid pollfd and the listener stays open for the call.
            let count = unsafe { libc::poll(&mut event, 1, 3000) };
            if count != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "actor helper did not reconnect to the guest port",
                ));
            }
            let (stream, _) = listener.accept()?;
            drop(stream);
        }
        Ok(())
    })();
    let _ = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert_eq!(
        ready
            .unwrap()
            .unwrap_or_else(|error| panic!("helper exited: {status}: {error}")),
        *b"READY\n"
    );
    reconnect.expect("delayed guest port and normal close must permit redial");
    assert!(
        config
            .vm_state_dir
            .join("mailbox-reader-authority.json")
            .exists()
    );
}
