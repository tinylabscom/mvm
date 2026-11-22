use super::*;
use crate::actor_lifecycle::local_mailboxes::ActorMailboxPolicy;
use crate::actor_reservations::ReservationCeilings;
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::protocol::actor_budget::ActorResources;
use mvm_contract::protocol::broker::ServiceId;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, BootId, ContentType, ExecutionEpoch, MailboxGrant, MailboxId,
    MailboxRetentionPolicy, TenantId,
};
use mvm_contract::protocol::workload_actor::{
    ActorProtocolVersion, ControllerIdentity, DelegationDepth, LifecycleGrant, LifecycleOperation,
    WorkflowBinding,
};
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::protocol::runtime_release::{
    CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
};

// This fixture proves authoring and cross-binding, not runtime artifact verification.
pub(crate) fn authored() -> ActorBootstrap {
    let mut parent = PlanFixture::new()
        .runtime_profile("hvf")
        .sdk_uses_sidecar(false)
        .grants(Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
            ..Default::default()
        }))
        .mailbox(MailboxGrant {
            mailbox: MailboxId::from_bytes([1; 32]),
            authority_key: ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                .verifying_key()
                .to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            report: None,
            retention: Some(MailboxRetentionPolicy::new(60_000).unwrap()),
            service_blind: None,
        })
        .build();
    parent.environment = Some(mvm_contract::plan::types::EnvironmentRef {
        kernel_sha256: "c".repeat(64),
    });
    let worker = parent.clone();
    let launch = ColdLaunch {
        rootfs_path: "/host/actor.ext4".into(),
        kernel_path: Some("/host/vmlinux".into()),
        runtime: RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Source {
                version: "fixture".into(),
                arch: mvm_core::arch::GuestArch::Aarch64,
                archive_sha256: "a".repeat(64),
            },
            overlay_path: "/host/runtime.ext4".into(),
            overlay_verity_path: "/host/runtime.verity".into(),
            initramfs_path: "/host/initramfs".into(),
            overlay_roothash: "b".repeat(64),
        }),
        verity_path: None,
        roothash: None,
        config_files: vec![],
        network_policy: NetworkPolicy::deny_all(),
        sdk_sidecar: None,
        sdk_source_checkout: None,
    };
    let charge = ActorResources {
        live_vms: 1,
        resident_vmms: 1,
        concurrent_launches: 1,
        memory_bytes: 128 * 1024 * 1024,
        cpu_millicores: 1000,
        mailbox_bytes: 4096,
        file_descriptors: 32,
        host_sockets: 8,
        vsock_channels: 8,
        ..Default::default()
    };
    let budget = ActorBudget {
        resources: ActorResources {
            live_vms: 2,
            resident_vmms: 2,
            controllers: 1,
            memory_bytes: charge.memory_bytes * 2,
            cpu_millicores: charge.cpu_millicores * 2,
            mailbox_bytes: charge.mailbox_bytes * 2,
            file_descriptors: charge.file_descriptors * 2,
            host_sockets: charge.host_sockets * 2,
            vsock_channels: charge.vsock_channels * 2,
            ..charge
        },
        max_total_attempts: 2,
    };
    let constraints = ActorConstraints {
        parent_charge: ActorResources {
            controllers: 1,
            ..charge
        },
        ceilings: ReservationCeilings {
            tenant: budget,
            workflow: budget,
            controller: budget,
        },
        child_resources: parent.resources.clone(),
        network: NetworkPolicy::deny_all(),
        effective_policy: Default::default(),
        capabilities: vec![],
        mailbox_policy: ActorMailboxPolicy {
            tenant: TenantId::from_bytes([3; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([4; 32]),
            content_types: vec![ContentType::parse("application/json", 1).unwrap()],
            max_payload_bytes: 1024,
            max_messages_per_minute: 60,
            max_send_attempts: 8,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 4096,
            max_storage_bytes: 4096,
            policy_epoch: 1,
            not_before_unix_ms: parent.valid_from.unix_millis(),
            expires_at_unix_ms: parent.valid_until.unix_millis(),
        },
    };
    parent
        .services
        .push(ServiceId::parse("host.actor.v1").unwrap());
    parent.workflow = Some(WorkflowBinding {
        version: ActorProtocolVersion::V1,
        workflow_id: ActorBindingId::new("workflow").unwrap(),
        constraint_snapshot_digest: Sha256Digest::from_bytes(&[0; 32]),
        role: WorkflowRole::Controller {
            grant: LifecycleGrant {
                id: ActorBindingId::new("children").unwrap(),
                controller: ControllerIdentity {
                    tenant: parent.tenant.clone(),
                    workload: parent.workload.clone(),
                    execution_epoch: ExecutionEpoch::new(1).unwrap(),
                    boot_id: BootId::from_bytes([5; 32]),
                    generation: std::num::NonZeroU64::new(1).unwrap(),
                },
                depth: DelegationDepth::One,
                templates: vec![],
                operations: vec![
                    LifecycleOperation::Launch,
                    LifecycleOperation::ObserveChild,
                    LifecycleOperation::ReleaseChild,
                ],
                not_before_unix_ms: parent.valid_from.unix_millis(),
                expires_at_unix_ms: parent.valid_until.unix_millis(),
                workflow_deadline_unix_ms: parent.valid_until.unix_millis(),
            },
        },
    });
    ActorBootstrap {
        version: 1,
        parent,
        launch: launch.clone(),
        templates: vec![NamedActorTemplate {
            id: ActorBindingId::new("worker").unwrap(),
            definition: TemplateDefinition {
                plan: worker,
                launch,
                effective_policy: Default::default(),
                capabilities: vec![],
                charge,
            },
        }],
        constraints,
        host_budget: budget,
    }
}

#[test]
fn complete_manifest_roundtrip_pins_exact_template_and_constraints() {
    let bootstrap = authored().bind().unwrap();
    let bytes = serde_json::to_vec(&bootstrap).unwrap();
    let decoded = ActorBootstrap::read(bytes.as_slice()).unwrap();
    assert_eq!(decoded.parent.plan_id, bootstrap.parent.plan_id);
    decoded.validate().unwrap();
}

#[test]
fn identity_and_template_substitution_refuse_before_spawn() {
    let bootstrap = authored().bind().unwrap();
    let mut mismatch = bootstrap.clone();
    mismatch.parent.tenant.0 = "different".into();
    mismatch.parent.plan_id = mvm_core::plan::compute_plan_id(&mismatch.parent);
    assert!(
        mismatch
            .validate()
            .unwrap_err()
            .to_string()
            .contains("identity mismatch")
    );
    let mut mismatch = bootstrap.clone();
    mismatch.templates[0].definition.launch.rootfs_path = "/host/another.ext4".into();
    assert!(mismatch.validate().is_err());
    let mut mismatch = bootstrap;
    mismatch.constraints.mailbox_policy.max_payload_bytes += 1;
    assert!(
        mismatch
            .validate()
            .unwrap_err()
            .to_string()
            .contains("snapshot digest mismatch")
    );
}

#[test]
fn strict_manifest_rejects_key_injection_and_direct_parent() {
    let bootstrap = authored().bind().unwrap();
    let mut value = serde_json::to_value(&bootstrap).unwrap();
    value["host_seed"] = serde_json::json!([1, 2, 3]);
    assert!(ActorBootstrap::read(serde_json::to_vec(&value).unwrap().as_slice()).is_err());
    let mut direct = bootstrap;
    direct.parent.workflow = None;
    direct.parent.plan_id = mvm_core::plan::compute_plan_id(&direct.parent);
    assert!(
        direct
            .validate()
            .unwrap_err()
            .to_string()
            .contains("direct workload")
    );
}

#[test]
fn actor_preflight_requires_both_operator_ceilings_before_any_spawn() {
    let bootstrap = authored().bind().unwrap();
    let mut config = mvm_core::user_config::MvmConfig::default();
    assert!(
        require_host_budget(&config, bootstrap.host_budget)
            .unwrap_err()
            .to_string()
            .contains("host_budget_memory_mib")
    );
    config.host_budget_memory_mib = Some(256);
    assert!(
        require_host_budget(&config, bootstrap.host_budget)
            .unwrap_err()
            .to_string()
            .contains("host_budget_cpu_millicores")
    );
    config.host_budget_cpu_millicores = Some(2000);
    require_host_budget(&config, bootstrap.host_budget).unwrap();
    config.host_budget_memory_mib = Some(127);
    assert!(require_host_budget(&config, bootstrap.host_budget).is_err());
    config.host_budget_memory_mib = Some(256);
    config.host_budget_cpu_millicores = Some(999);
    assert!(require_host_budget(&config, bootstrap.host_budget).is_err());
    config.host_budget_cpu_millicores = Some(0);
    assert!(require_host_budget(&config, bootstrap.host_budget).is_err());
}

#[test]
fn parent_resource_charge_is_explicit_and_snapshot_authenticated() {
    let bootstrap = authored().bind().unwrap();
    let mut changed = bootstrap.clone();
    changed.constraints.parent_charge.memory_bytes = 1;
    assert!(changed.bind().is_err());
    let mut changed = bootstrap;
    changed.constraints.parent_charge.controllers = 0;
    assert!(changed.bind().is_err());
}

#[test]
fn parent_cpu_charge_covers_signed_share_not_nominal_vcpu_count() {
    let mut bootstrap = authored();
    bootstrap.parent.grants.as_mut().unwrap().cpu =
        Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 });
    bootstrap.constraints.parent_charge.cpu_millicores = 500;
    let mut bootstrap = bootstrap.bind().unwrap();
    bootstrap.constraints.parent_charge.cpu_millicores = 499;
    assert!(bootstrap.bind().is_err());
}

#[test]
fn unsafe_root_names_refuse_before_provisioning_material() {
    for name in ["", "../escape", "parent/child", "/absolute", "UPPER"] {
        let mut bootstrap = authored();
        bootstrap.parent.workload.0 = name.into();
        // Provisioning ordinarily accesses signing material. The naming gate
        // must win even over this fixture's not-yet-bound plan and SDK inputs.
        let error = bootstrap.provision().unwrap_err();
        assert!(error.to_string().contains("VM name"), "{name:?}: {error}");
    }
    let mut bootstrap = authored();
    bootstrap.parent.tenant.0 = "../tenant".into();
    assert!(
        bootstrap
            .provision()
            .unwrap_err()
            .to_string()
            .contains("tenant")
    );
}

#[test]
fn root_cannot_authorize_a_host_path_by_copying_the_sdk_share_tag() {
    let mut bootstrap = authored();
    bootstrap
        .parent
        .shares
        .push(mvm_core::plan::HostShareGrant {
            tag: mvm_runtime::sdk_sidecar::SDK_SIDECAR_SHARE_TAG.into(),
            host_path: "/host/unverified-disk".into(),
            guest_path: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
            kind: mvm_core::plan::ShareKind::Disk,
            read_only: true,
            encrypted: false,
            content_sha256: None,
            include: Vec::new(),
            exclude: Vec::new(),
        });
    assert!(bootstrap.bind().is_err());
}
