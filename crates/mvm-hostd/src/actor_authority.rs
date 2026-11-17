//! Fail-closed attenuation for host-held actor templates, before ordinary admission.
//!
//! Inputs must come from authenticated host state, never a guest launch request.
//! This check neither admits a plan nor reserves aggregate workflow capacity.

use ed25519_dalek::VerifyingKey;
use mvm_contract::grants::{Grants, subset::grants_are_subset};
use mvm_contract::plan::execution_plan::ExecutionPlan;
use mvm_contract::plan::types::{NetworkMode, Resources};
use mvm_contract::policy::{
    action_budget::ActionBudget, network_policy::NetworkPolicy, resolver::EffectivePolicy,
};
use mvm_contract::protocol::agent_capability::CapabilityBinding;
use mvm_contract::protocol::mailbox::{MailboxGrant, MailboxOperation, SignedMailboxCapability};

/// Authenticated policy resolution for exactly one plan and broker registration.
///
/// The caller must verify that `resolved_digest` pins these resolved policies
/// and that the capability bindings are the ones registered for this boot.
#[derive(Debug, Clone, Copy)]
pub struct PolicyMaterial<'a> {
    pub resolved_digest: [u8; 32],
    pub network: &'a NetworkPolicy,
    pub effective: &'a EffectivePolicy,
    pub capabilities: &'a [CapabilityBinding],
}

/// Host-derived mailbox identity and signed operation authority for the child.
///
/// The caller derives `child_grant` from its admitted exact mailbox binding,
/// not from the submitted template. Issuer keys are trusted host inputs.
/// Revocation freshness and exact boot/subject binding remain ordinary mailbox
/// admission checks; signature validity alone is not mailbox admission.
#[derive(Debug, Clone, Copy)]
pub struct MailboxDerivation<'a> {
    pub child_grant: &'a MailboxGrant,
    pub parent_capability: &'a SignedMailboxCapability,
    pub child_capability: &'a SignedMailboxCapability,
    pub parent_issuer_key: &'a VerifyingKey,
    pub child_issuer_key: &'a VerifyingKey,
}

/// Independent authenticated ceilings; none are synthesized from guest input.
#[derive(Debug, Clone, Copy)]
pub struct ChildAuthorityContext<'a> {
    /// Effective per-child ceiling from controller/template/workflow/host policy.
    /// This is neither the parent's own allocation nor a remaining aggregate
    /// budget. The caller must additionally reserve aggregate capacity atomically.
    pub resource_ceiling: &'a Resources,
    pub parent_policy: PolicyMaterial<'a>,
    pub child_policy: PolicyMaterial<'a>,
    /// Required whenever the child has a mailbox; no inferred fallback.
    pub mailbox: Option<MailboxDerivation<'a>>,
}

/// Authority dimension that widened or lacked a comparable proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDimension {
    Identity,
    Policy,
    Network,
    Secrets,
    Filesystem,
    Resources,
    Grants,
    Services,
    AgentVerbs,
    Artifacts,
    Attestation,
    Lifetime,
    Extensions,
    Streams,
    Mailbox,
}

/// A refusal contains only the dimension, never policy, path, or secret bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("child authority is not bounded in {dimension:?}")]
pub struct ChildAuthorityError {
    pub dimension: AuthorityDimension,
}

fn require(condition: bool, dimension: AuthorityDimension) -> Result<(), ChildAuthorityError> {
    if condition {
        Ok(())
    } else {
        Err(ChildAuthorityError { dimension })
    }
}

fn subset<T: PartialEq>(child: &[T], parent: &[T]) -> bool {
    child.iter().all(|item| parent.contains(item))
}

fn optional_limit(child: Option<u64>, parent: Option<u64>) -> bool {
    parent.is_none_or(|max| child.is_some_and(|value| value <= max))
}

fn seconds(child: u32, parent: u32) -> bool {
    parent == 0 || (child != 0 && child <= parent)
}

/// Validate the exact host-held child template against authenticated authority.
///
/// Policy references and resolved content must both match: a matching display
/// name is not a policy identity. Unknown extension and stream authority is
/// refused rather than interpreted as a generic recursive JSON subset.
///
/// Workflow worker/non-delegation validation belongs to actor orchestration;
/// this function must only be called after that gate. Signing, replay,
/// admission, mailbox revocation, budget reservation, and launch remain required.
///
/// # Errors
/// Returns the first unproven authority dimension, without sensitive values.
pub fn validate_child_authority(
    parent: &ExecutionPlan,
    child: &ExecutionPlan,
    context: &ChildAuthorityContext<'_>,
) -> Result<(), ChildAuthorityError> {
    use AuthorityDimension as D;

    require(
        child.tenant == parent.tenant
            && child.schema_version == parent.schema_version
            && child.runtime_profile == parent.runtime_profile,
        D::Identity,
    )?;
    require(
        child.network_policy == parent.network_policy
            && child.fs_policy == parent.fs_policy
            && child.egress_policy == parent.egress_policy
            && child.admission_profile == parent.admission_profile
            && context.child_policy.resolved_digest == context.parent_policy.resolved_digest
            && context.child_policy.network == context.parent_policy.network
            && context.child_policy.effective == context.parent_policy.effective,
        D::Policy,
    )?;
    validate_network(parent, child)?;
    require(
        child.secrets.iter().all(|c| {
            parent.secrets.iter().any(|p| {
                c.name == p.name
                    && c.source == p.source
                    && (!p.approval_required || c.approval_required)
                    // Empty means the stored allowlist, not deny-all.
                    && (p.destinations.is_empty()
                        || (!c.destinations.is_empty()
                            && subset(&c.destinations, &p.destinations)))
            })
        }),
        D::Secrets,
    )?;
    require(
        child.shares.iter().all(|c| {
            parent.shares.iter().any(|p| {
                c.tag == p.tag
                    && c.host_path == p.host_path
                    && c.guest_path == p.guest_path
                    && c.kind == p.kind
                    && (!p.read_only || c.read_only)
                    && c.encrypted == p.encrypted
                    && c.content_sha256 == p.content_sha256
                    && subset(&c.include, &p.include)
                    && subset(&p.exclude, &c.exclude)
            })
        }) && (child.deps_volume.is_none() || child.deps_volume == parent.deps_volume)
            && child.protected_paths == parent.protected_paths,
        D::Filesystem,
    )?;
    let c = &child.resources;
    let ceiling = context.resource_ceiling;
    require(
        c.cpus > 0
            && c.mem_mib > 0
            && c.cpus <= ceiling.cpus
            && c.mem_mib <= ceiling.mem_mib
            && c.disk_mib <= ceiling.disk_mib
            && seconds(c.timeouts.boot_secs, ceiling.timeouts.boot_secs)
            && seconds(c.timeouts.exec_secs, ceiling.timeouts.exec_secs)
            && seconds(c.timeouts.exec_secs, parent.resources.timeouts.exec_secs),
        D::Resources,
    )?;
    require(
        grants_are_subset(
            child.grants.as_ref().unwrap_or(&Grants::default()),
            parent.grants.as_ref().unwrap_or(&Grants::default()),
        )
        .is_ok(),
        D::Grants,
    )?;
    require(
        subset(&child.services, &parent.services)
            && subset(
                context.child_policy.capabilities,
                context.parent_policy.capabilities,
            ),
        D::Services,
    )?;
    require(
        parent
            .agent_verbs
            .as_ref()
            .is_none_or(|p| child.agent_verbs.as_ref().is_some_and(|c| subset(c, p))),
        D::AgentVerbs,
    )?;
    require(
        subset(
            &child.artifact_policy.capture_paths,
            &parent.artifact_policy.capture_paths,
        ) && child.artifact_policy.retention_days <= parent.artifact_policy.retention_days
            && child.stream_retention == parent.stream_retention
            && child.validate_outputs().is_ok()
            && child.outputs.iter().all(|c| {
                parent.outputs.iter().any(|p| {
                    c.guest_path == p.guest_path
                        && c.host_path == p.host_path
                        && c.max_bytes <= p.max_bytes
                        && c.max_entries <= p.max_entries
                })
            }),
        D::Artifacts,
    )?;
    require(
        child.attestation == parent.attestation
            && child.key_rotation == parent.key_rotation
            && child.release_pin == parent.release_pin
            && child.environment == parent.environment
            && child.runtime_identity == parent.runtime_identity,
        D::Attestation,
    )?;
    require(
        child.valid_from >= parent.valid_from
            && child.valid_until <= parent.valid_until
            && child.valid_from < child.valid_until
            && child.post_run.destroy_on_exit
            && !child.post_run.snapshot_on_idle
            && child.snapshot_at.is_none()
            && budget_subset(child.action_budget, parent.action_budget),
        D::Lifetime,
    )?;
    require(child.extensions.is_empty(), D::Extensions)?;
    require(child.stream_edges.is_empty(), D::Streams)?;
    validate_mailbox(parent, child, context.mailbox)
}

fn validate_network(
    parent: &ExecutionPlan,
    child: &ExecutionPlan,
) -> Result<(), ChildAuthorityError> {
    let c = child.network_limits;
    let p = parent.network_limits;
    require(
        (child.network_mode == NetworkMode::None || child.network_mode == parent.network_mode)
            && c.validate().is_ok()
            && p.validate().is_ok()
            && c.max_tcp_flows <= p.max_tcp_flows
            && c.max_udp_associations <= p.max_udp_associations
            && c.max_dns_bindings <= p.max_dns_bindings
            && c.max_ingress_listeners <= p.max_ingress_listeners
            && c.max_stream_credit_bytes <= p.max_stream_credit_bytes
            && subset(&child.ingress, &parent.ingress)
            && child.validate_ingress().is_ok()
            && child.redaction == parent.redaction
            && child.reversible_replacement == parent.reversible_replacement,
        AuthorityDimension::Network,
    )
}

fn budget_subset(child: Option<ActionBudget>, parent: Option<ActionBudget>) -> bool {
    let c = child.unwrap_or_default();
    let p = parent.unwrap_or_default();
    [
        (c.max_egress_flows, p.max_egress_flows),
        (c.max_egress_bytes, p.max_egress_bytes),
        (c.max_dns_queries, p.max_dns_queries),
        (c.max_secret_substitutions, p.max_secret_substitutions),
        (c.max_stdin_grants, p.max_stdin_grants),
        (c.max_output_bytes, p.max_output_bytes),
        (c.max_output_entries, p.max_output_entries),
    ]
    .into_iter()
    .all(|(c, p)| optional_limit(c, p))
}

fn validate_mailbox(
    parent: &ExecutionPlan,
    child: &ExecutionPlan,
    proof: Option<MailboxDerivation<'_>>,
) -> Result<(), ChildAuthorityError> {
    use AuthorityDimension::Mailbox;
    let Some(c) = child.mailbox else {
        return Ok(());
    };
    let (Some(p), Some(proof)) = (parent.mailbox, proof) else {
        return require(false, Mailbox);
    };
    require(
        &c == proof.child_grant
            && c.mailbox != p.mailbox
            && c.epoch.get() == child.execution_epoch
            && p.epoch.get() == parent.execution_epoch
            && proof.parent_issuer_key.to_bytes() == p.authority_key
            && proof.child_issuer_key.to_bytes() == c.authority_key
            && mvm_core::mailbox::verify_capability_signature(
                proof.parent_capability,
                proof.parent_issuer_key,
            )
            .is_ok()
            && mvm_core::mailbox::verify_capability_signature(
                proof.child_capability,
                proof.child_issuer_key,
            )
            .is_ok()
            && c.report.is_none_or(|c| {
                p.report
                    .is_some_and(|p| c.max_payload_bytes() <= p.max_payload_bytes())
            })
            // Retention is a durability obligation, not simply a byte ceiling.
            && c.retention == p.retention,
        Mailbox,
    )?;
    let cc = &proof.child_capability.grant;
    let pc = &proof.parent_capability.grant;
    require(
        cc.address.mailbox == c.mailbox
            && pc.address.mailbox == p.mailbox
            && cc.address.tenant == pc.address.tenant
            && cc.address.authorization_domain == pc.address.authorization_domain
            && cc.minimum_execution_epoch == c.epoch
            && cc.maximum_execution_epoch == c.epoch
            && pc.minimum_execution_epoch <= p.epoch
            && pc.maximum_execution_epoch >= p.epoch
            && cc.policy_epoch == pc.policy_epoch
            && cc.delegation_depth == 0
            && cc.not_before_unix_ms >= pc.not_before_unix_ms
            && cc.expires_at_unix_ms <= pc.expires_at_unix_ms
            && cc.not_before_unix_ms >= child.valid_from.timestamp_millis()
            && cc.expires_at_unix_ms <= child.valid_until.timestamp_millis()
            && cc.max_payload_bytes <= pc.max_payload_bytes
            && cc.max_messages_per_minute <= pc.max_messages_per_minute
            && cc.max_outstanding_calls <= pc.max_outstanding_calls
            && cc.max_queue_contribution_bytes <= pc.max_queue_contribution_bytes
            && subset(&cc.message_kinds, &pc.message_kinds)
            && subset(&cc.content_types, &pc.content_types)
            && [
                MailboxOperation::Send,
                MailboxOperation::Receive,
                MailboxOperation::Reply,
                MailboxOperation::Monitor,
                MailboxOperation::Administer,
            ]
            .into_iter()
            .all(|operation| !cc.operations.allows(operation) || pc.operations.allows(operation)),
        Mailbox,
    )
}

#[cfg(test)]
#[path = "actor_authority/tests.rs"]
mod tests;
