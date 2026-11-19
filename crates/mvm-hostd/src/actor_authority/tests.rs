use super::*;
use mvm_contract::grants::CpuGrant;
use mvm_contract::plan::types::{HostShareGrant, SecretBinding, SecretSource, ShareKind};
use mvm_contract::protocol::agent_capability::CapabilityId;
use mvm_contract::protocol::broker::ServiceId;
use mvm_core::plan::test_support::PlanFixture;

fn plans() -> (ExecutionPlan, ExecutionPlan) {
    let parent = PlanFixture::new().build();
    let mut child = parent.clone();
    child.workload.0 = "child".into();
    child.plan_id.0 = "child-plan".into();
    child.nonce = mvm_contract::plan::types::Nonce::from_bytes([1; 16]);
    (parent, child)
}

fn check(parent: &ExecutionPlan, child: &ExecutionPlan) -> Result<(), ChildAuthorityError> {
    let network = NetworkPolicy::deny_all();
    let effective = EffectivePolicy::default();
    let policy = PolicyMaterial {
        resolved_digest: [1; 32],
        network: &network,
        effective: &effective,
        capabilities: &[],
    };
    validate_child_authority(
        parent,
        child,
        &ChildAuthorityContext {
            resource_ceiling: &parent.resources,
            parent_policy: policy,
            child_policy: policy,
            mailbox: None,
        },
    )
}

fn refused(parent: &ExecutionPlan, child: &ExecutionPlan, dimension: AuthorityDimension) {
    assert_eq!(check(parent, child), Err(ChildAuthorityError { dimension }));
}

fn secret() -> SecretBinding {
    SecretBinding {
        name: "slot".into(),
        source: SecretSource::Keystore {
            address: "sensitive-reference".into(),
        },
        destinations: vec!["api.example.com".into()],
        approval_required: true,
    }
}

fn share() -> HostShareGrant {
    HostShareGrant {
        tag: "data".into(),
        host_path: "/host/data".into(),
        guest_path: "/data".into(),
        kind: ShareKind::Disk,
        read_only: true,
        encrypted: true,
        content_sha256: None,
        include: vec![],
        exclude: vec![],
    }
}

#[test]
fn accepts_identical_authority_with_distinct_identity_and_restricted_child() {
    let (mut parent, mut child) = plans();
    assert_eq!(check(&parent, &child), Ok(()));
    parent.secrets = vec![secret()];
    parent.shares = vec![share()];
    parent.services = vec![ServiceId::parse("host.kv.v1").unwrap()];
    parent.network_mode = NetworkMode::HostVsockProxy;
    parent.artifact_policy.capture_paths = vec!["/artifacts".into()];
    parent.artifact_policy.retention_days = 10;
    parent.resources.mem_mib *= 2;
    parent.grants = Some(Grants {
        cpu: Some(CpuGrant::Share { millicores: 1000 }),
        ..Grants::default()
    });
    child.grants = Some(Grants {
        cpu: Some(CpuGrant::Share { millicores: 500 }),
        ..Grants::default()
    });
    child.valid_until -= chrono::Duration::seconds(1);
    child.network_limits.max_tcp_flows = 1;
    child.action_budget = Some(ActionBudget::default().with_max_output_bytes(1));
    assert_eq!(check(&parent, &child), Ok(()));
}

#[test]
fn individual_plan_widenings_are_refused() {
    use AuthorityDimension as D;
    type Mutation = fn(&mut ExecutionPlan);
    let cases: &[(D, Mutation)] = &[
        (D::Identity, |p| p.tenant.0 = "other".into()),
        (D::Identity, |p| p.runtime_profile.0 = "other".into()),
        (D::Policy, |p| p.network_policy.0 = "other".into()),
        (D::Policy, |p| p.egress_policy.0 = "other".into()),
        (D::Policy, |p| p.fs_policy.0 = "other".into()),
        (D::Policy, |p| p.admission_profile.id = "other".into()),
        (D::Network, |p| p.network_mode = NetworkMode::HostVsockProxy),
        (D::Secrets, |p| p.secrets.push(secret())),
        (D::Filesystem, |p| p.shares.push(share())),
        (D::Resources, |p| p.resources.cpus += 1),
        (D::Resources, |p| p.resources.mem_mib += 1),
        (D::Resources, |p| p.resources.disk_mib += 1),
        (D::Resources, |p| p.resources.timeouts.boot_secs += 1),
        (D::Services, |p| {
            p.services.push(ServiceId::parse("host.kv.v1").unwrap());
        }),
        (D::Artifacts, |p| {
            p.artifact_policy.capture_paths.push("/out".into())
        }),
        (D::Artifacts, |p| p.artifact_policy.retention_days += 1),
        (D::Attestation, |p| p.key_rotation.interval_days = 1),
        (D::Lifetime, |p| {
            p.valid_until += chrono::Duration::seconds(1)
        }),
        (D::Lifetime, |p| {
            p.valid_from -= chrono::Duration::seconds(1)
        }),
        (D::Lifetime, |p| p.post_run.destroy_on_exit = false),
        (D::Lifetime, |p| p.post_run.snapshot_on_idle = true),
    ];
    for (dimension, mutate) in cases {
        let (parent, mut child) = plans();
        mutate(&mut child);
        refused(&parent, &child, *dimension);
    }
}

#[test]
fn each_network_limit_is_independent_not_lexicographic() {
    type Mutation = fn(&mut mvm_contract::plan::types::NetworkLimits);
    let widenings: &[Mutation] = &[
        |l| l.max_tcp_flows += 1,
        |l| l.max_udp_associations += 1,
        |l| l.max_dns_bindings += 1,
        |l| l.max_ingress_listeners += 1,
        |l| l.max_stream_credit_bytes += 1,
    ];
    for widen in widenings {
        let (mut parent, mut child) = plans();
        parent.network_limits = mvm_contract::plan::types::NetworkLimits::builder()
            .max_tcp_flows(2)
            .max_udp_associations(2)
            .max_dns_bindings(2)
            .max_ingress_listeners(2)
            .max_stream_credit_bytes(2)
            .build()
            .unwrap();
        child.network_limits = parent.network_limits;
        widen(&mut child.network_limits);
        refused(&parent, &child, AuthorityDimension::Network);
    }
}

#[test]
fn secret_source_destination_empty_and_approval_cannot_widen() {
    type Mutation = fn(&mut SecretBinding);
    let widenings: &[Mutation] = &[
        |s| s.approval_required = false,
        |s| s.destinations.clear(),
        |s| s.destinations.push("elsewhere.example".into()),
        |s| {
            s.source = SecretSource::Keystore {
                address: "other".into(),
            }
        },
        |s| s.name = "other".into(),
    ];
    for widen in widenings {
        let (mut parent, mut child) = plans();
        parent.secrets = vec![secret()];
        child.secrets = parent.secrets.clone();
        widen(&mut child.secrets[0]);
        refused(&parent, &child, AuthorityDimension::Secrets);
        let message = check(&parent, &child).unwrap_err().to_string();
        assert!(!message.contains("sensitive-reference"));
    }
    let (mut parent, mut child) = plans();
    parent.secrets = vec![secret()];
    parent.secrets[0].destinations.clear();
    child.secrets = vec![secret()];
    assert_eq!(check(&parent, &child), Ok(()));
}

#[test]
fn filesystem_cannot_change_path_or_remove_readonly_or_encryption() {
    type Mutation = fn(&mut HostShareGrant);
    let widenings: &[Mutation] = &[
        |s| s.host_path = "/host".into(),
        |s| s.guest_path = "/".into(),
        |s| s.read_only = false,
        |s| s.encrypted = false,
        |s| s.tag = "other".into(),
        |s| s.content_sha256 = Some("a".repeat(64)),
    ];
    for widen in widenings {
        let (mut parent, mut child) = plans();
        parent.shares = vec![share()];
        child.shares = parent.shares.clone();
        widen(&mut child.shares[0]);
        refused(&parent, &child, AuthorityDimension::Filesystem);
    }
}

#[test]
fn dropped_cpu_agent_and_lifetime_bounds_are_not_deny_all() {
    let (mut parent, mut child) = plans();
    parent.grants = Some(Grants {
        cpu: Some(CpuGrant::Share { millicores: 1000 }),
        ..Grants::default()
    });
    refused(&parent, &child, AuthorityDimension::Grants);
    child.grants = parent.grants.clone();
    parent.agent_verbs = Some(vec![]);
    refused(&parent, &child, AuthorityDimension::AgentVerbs);
    child.agent_verbs = Some(vec![]);
    parent.action_budget = Some(ActionBudget::default().with_max_egress_bytes(10));
    refused(&parent, &child, AuthorityDimension::Lifetime);
    child.action_budget = Some(ActionBudget::default().with_max_egress_bytes(9));
    assert_eq!(check(&parent, &child), Ok(()));
}

#[test]
fn resource_ceiling_is_not_parent_own_ram_and_policy_content_is_required() {
    let (parent, mut child) = plans();
    child.resources.mem_mib *= 2;
    let ceiling = child.resources.clone();
    let network = NetworkPolicy::deny_all();
    let effective = EffectivePolicy::default();
    let policy = PolicyMaterial {
        resolved_digest: [1; 32],
        network: &network,
        effective: &effective,
        capabilities: &[],
    };
    let mut context = ChildAuthorityContext {
        resource_ceiling: &ceiling,
        parent_policy: policy,
        child_policy: policy,
        mailbox: None,
    };
    assert_eq!(validate_child_authority(&parent, &child, &context), Ok(()));
    context.child_policy.resolved_digest = [2; 32];
    assert_eq!(
        validate_child_authority(&parent, &child, &context),
        Err(ChildAuthorityError {
            dimension: AuthorityDimension::Policy
        })
    );
    context.child_policy = policy;
    let changed =
        NetworkPolicy::allow_list(vec![mvm_contract::policy::network_policy::HostPort::new(
            "example.com",
            443,
        )]);
    context.child_policy.network = &changed;
    assert_eq!(
        validate_child_authority(&parent, &child, &context),
        Err(ChildAuthorityError {
            dimension: AuthorityDimension::Policy
        })
    );
    context.child_policy = policy;
    let capabilities = [CapabilityBinding {
        capability: CapabilityId::new(ServiceId::parse("host.kv.v1").unwrap(), "read").unwrap(),
        descriptor_digest: [3; 32],
    }];
    context.child_policy.capabilities = &capabilities;
    assert_eq!(
        validate_child_authority(&parent, &child, &context),
        Err(ChildAuthorityError {
            dimension: AuthorityDimension::Services
        })
    );
    context.parent_policy.capabilities = &capabilities;
    assert_eq!(validate_child_authority(&parent, &child, &context), Ok(()));
}

fn signed_mailbox(
    plan: &mut ExecutionPlan,
    key: &ed25519_dalek::SigningKey,
    id: u8,
) -> SignedMailboxCapability {
    use mvm_contract::protocol::mailbox::*;
    let epoch = ExecutionEpoch::new(plan.execution_epoch).unwrap();
    let mailbox = MailboxId::from_bytes([id; 32]);
    plan.mailbox = Some(MailboxGrant {
        mailbox,
        authority_key: key.verifying_key().to_bytes(),
        epoch,
        report: None,
        retention: None,
        service_blind: None,
    });
    mvm_core::mailbox::sign_capability(
        MailboxCapabilityGrant {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            capability_id: mvm_contract::protocol::mailbox::CapabilityId::from_bytes([id; 32]),
            issuer: PrincipalId::from_bytes(key.verifying_key().to_bytes()),
            subject: PrincipalId::from_bytes([id; 32]),
            address: MailboxAddress {
                tenant: TenantId::from_bytes([5; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([6; 32]),
                mailbox,
                recipient: PrincipalId::from_bytes([id; 32]),
            },
            operations: CapabilityOperations::from_operations(&[MailboxOperation::Send]),
            message_kinds: vec![MailboxMessageKind::Cast],
            content_types: vec![ContentType::parse("application/json", 1).unwrap()],
            max_payload_bytes: 64,
            max_messages_per_minute: 60,
            max_outstanding_calls: 1,
            max_queue_contribution_bytes: 1024,
            minimum_execution_epoch: epoch,
            maximum_execution_epoch: epoch,
            policy_epoch: 1,
            not_before_unix_ms: plan.valid_from.timestamp_millis(),
            expires_at_unix_ms: plan.valid_until.timestamp_millis(),
            revocation_id: RevocationId::from_bytes([id; 32]),
            delegation_depth: 0,
        },
        key,
    )
    .unwrap()
}

#[test]
fn mailbox_requires_derived_identity_signed_proof_and_narrow_operations() {
    use mvm_contract::protocol::mailbox::CapabilityOperations;
    let (mut parent, mut child) = plans();
    let parent_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let child_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let pc = signed_mailbox(&mut parent, &parent_key, 1);
    let cc = signed_mailbox(&mut child, &child_key, 2);
    refused(&parent, &child, AuthorityDimension::Mailbox);
    let expected = child.mailbox.unwrap();
    let pk = parent_key.verifying_key();
    let ck = child_key.verifying_key();
    let proof = MailboxDerivation {
        child_grant: &expected,
        parent_capability: &pc,
        child_capability: &cc,
        parent_issuer_key: &pk,
        child_issuer_key: &ck,
    };
    assert_eq!(validate_mailbox(&parent, &child, Some(proof)), Ok(()));
    let mut forged = cc.clone();
    forged.signature[0] ^= 1;
    assert!(
        validate_mailbox(
            &parent,
            &child,
            Some(MailboxDerivation {
                child_capability: &forged,
                ..proof
            })
        )
        .is_err()
    );
    type Mutation = fn(&mut mvm_contract::protocol::mailbox::MailboxCapabilityGrant);
    let widenings: &[Mutation] = &[
        |c| c.max_payload_bytes += 1,
        |c| c.max_messages_per_minute += 1,
        |c| c.max_outstanding_calls += 1,
        |c| c.max_queue_contribution_bytes += 1,
        |c| c.expires_at_unix_ms += 1,
        |c| c.not_before_unix_ms -= 1,
        |c| c.policy_epoch += 1,
        |c| c.delegation_depth = 1,
        |c| c.operations = CapabilityOperations::from_operations(&[MailboxOperation::Administer]),
    ];
    for widen in widenings {
        let mut grant = cc.grant.clone();
        widen(&mut grant);
        let wider = mvm_core::mailbox::sign_capability(grant, &child_key).unwrap();
        assert_eq!(
            validate_mailbox(
                &parent,
                &child,
                Some(MailboxDerivation {
                    child_capability: &wider,
                    ..proof
                })
            ),
            Err(ChildAuthorityError {
                dimension: AuthorityDimension::Mailbox
            })
        );
    }
    child.mailbox.as_mut().unwrap().mailbox =
        mvm_contract::protocol::mailbox::MailboxId::from_bytes([99; 32]);
    assert!(validate_mailbox(&parent, &child, Some(proof)).is_err());
}

#[test]
fn output_destinations_and_bounds_cannot_widen() {
    use mvm_contract::plan::output_grant::OutputGrant;
    let (mut parent, mut child) = plans();
    let mut disk = share();
    disk.read_only = false;
    parent.shares = vec![disk];
    parent.outputs = vec![OutputGrant {
        guest_path: "/data".into(),
        host_path: "/host/result".into(),
        max_bytes: 10,
        max_entries: 5,
    }];
    child.shares = parent.shares.clone();
    child.outputs = parent.outputs.clone();
    child.outputs[0].max_bytes = 9;
    assert_eq!(check(&parent, &child), Ok(()));
    child.outputs[0].max_entries = 6;
    refused(&parent, &child, AuthorityDimension::Artifacts);
    child.outputs[0].max_entries = 5;
    child.outputs[0].host_path = "/host/other".into();
    refused(&parent, &child, AuthorityDimension::Artifacts);
}

#[test]
fn every_action_budget_dimension_refuses_removal_and_increase() {
    type Bound = fn(&mut ActionBudget) -> &mut Option<u64>;
    let bounds: &[Bound] = &[
        |b| &mut b.max_egress_flows,
        |b| &mut b.max_egress_bytes,
        |b| &mut b.max_dns_queries,
        |b| &mut b.max_secret_substitutions,
        |b| &mut b.max_stdin_grants,
        |b| &mut b.max_output_bytes,
        |b| &mut b.max_output_entries,
    ];
    for bound in bounds {
        let (mut parent, mut child) = plans();
        let mut budget = ActionBudget::default();
        *bound(&mut budget) = Some(10);
        parent.action_budget = Some(budget);
        refused(&parent, &child, AuthorityDimension::Lifetime);
        *bound(&mut budget) = Some(11);
        child.action_budget = Some(budget);
        refused(&parent, &child, AuthorityDimension::Lifetime);
        *bound(&mut budget) = Some(9);
        child.action_budget = Some(budget);
        assert_eq!(check(&parent, &child), Ok(()));
    }
}

#[test]
fn extensions_and_streams_fail_closed_even_when_parent_has_same_binding() {
    use mvm_contract::protocol::extension_pack::*;
    let (mut parent, mut child) = plans();
    let extension = ExtensionPlanBinding {
        extension_id: ExtensionId::parse("example").unwrap(),
        version: ExtensionVersion::parse("1.0.0").unwrap(),
        pack_digest: [1; 32],
        contract_digest: [2; 32],
        placement: ExtensionPlacement::GuestWorkload,
        artifact: "worker".into(),
        entrypoint: "worker".into(),
        capabilities: vec![],
        budgets: ExtensionBudgets {
            cpu_millis: 1,
            memory_bytes: 1,
            duration_ms: 1,
            max_steps: 1,
            max_concurrency: 1,
            max_payload_bytes: 1,
            max_output_bytes: 1,
            max_artifact_bytes: 1,
        },
    };
    parent.extensions.push(extension.clone());
    child.extensions.push(extension);
    refused(&parent, &child, AuthorityDimension::Extensions);
    child.extensions.clear();
    let edge = mvm_contract::stream::StreamEdge::new("input");
    parent.stream_edges.push(edge.clone());
    child.stream_edges.push(edge);
    refused(&parent, &child, AuthorityDimension::Streams);
}
