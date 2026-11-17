//! Strict local operator input; admission and native ownership cannot be serialized.

use std::io::Read;

use anyhow::{Context, Result, ensure};
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::actor_budget::ActorBudget;
use mvm_contract::protocol::workload_actor::{ActorBindingId, MAX_ACTOR_TEMPLATES, WorkflowRole};
use serde::{Deserialize, Serialize};

use crate::actor_lifecycle::{
    ActorConstraints, ActorTemplate, ColdLaunch, ExactTemplateCatalog, TemplateDefinition,
};
use crate::actor_process::MAX_BOOTSTRAP_BYTES;

/// Actor-only subceilings cannot replace the operator's ordinary-workload budget.
pub(crate) fn require_host_budget(
    configured: &mvm_core::user_config::MvmConfig,
    actor: ActorBudget,
) -> Result<()> {
    let memory_mib = configured
        .host_budget_memory_mib
        .filter(|value| *value > 0)
        .context("actor launch requires a finite positive host_budget_memory_mib in the operator configuration; set it explicitly, leaving host safety headroom")?;
    let cpu = configured
        .host_budget_cpu_millicores
        .filter(|value| *value > 0)
        .context("actor launch requires a finite positive host_budget_cpu_millicores in the operator configuration; set it explicitly, leaving host safety headroom")?;
    let memory_bytes = memory_mib
        .checked_mul(1024 * 1024)
        .context("configured host memory ceiling exceeds byte accounting range")?;
    ensure!(
        actor.resources.memory_bytes <= memory_bytes,
        "actor memory subceiling exceeds configured global host memory budget"
    );
    ensure!(
        actor.resources.cpu_millicores <= u64::from(cpu),
        "actor CPU subceiling exceeds configured global host CPU budget"
    );
    Ok(())
}

/// A host-resolved exact template. The guest sees only the signed binding ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedActorTemplate {
    pub id: ActorBindingId,
    pub definition: TemplateDefinition,
}

/// Complete host-authored launch description. It contains no private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorBootstrap {
    pub version: u16,
    pub parent: ExecutionPlan,
    pub launch: ColdLaunch,
    pub templates: Vec<NamedActorTemplate>,
    pub constraints: ActorConstraints,
    pub host_budget: ActorBudget,
}

impl ActorBootstrap {
    /// Prepare the local mailbox endpoint with the existing host signing authority.
    ///
    /// This explicit authoring operation may initialize the ordinary protected
    /// host signer and installs the exact encrypted mailbox template. Only its
    /// public authority key enters the returned manifest; no private key is
    /// serialized. Call this before saving a newly authored local manifest.
    pub fn provision(mut self) -> Result<Self> {
        self.validate_names()?;
        self.launch.provision_sdk(&mut self.parent)?;
        for template in &mut self.templates {
            template
                .definition
                .launch
                .provision_sdk(&mut template.definition.plan)?;
        }
        let mut bootstrap = self.bind()?;
        let keys_dir = crate::audit::host_keypair::default_keys_dir()?;
        let _signer = crate::audit::host_keypair::load_or_init_at(&keys_dir)?;
        let digest = bootstrap.constraints.digest()?;
        let mut digest_bytes = [0u8; 32];
        hex::decode_to_slice(
            digest
                .as_str()
                .strip_prefix("sha256:")
                .context("invalid actor snapshot digest")?,
            &mut digest_bytes,
        )?;
        let mailboxes = crate::actor_lifecycle::local_mailboxes::LocalActorMailboxes::new(
            keys_dir,
            bootstrap.constraints.mailbox_policy.clone(),
            digest_bytes,
        )?;
        bootstrap.parent.mailbox = Some(mailboxes.install_controller(&bootstrap.parent)?);
        bootstrap.parent.plan_id = mvm_core::plan::compute_plan_id(&bootstrap.parent);
        bootstrap.validate()?;
        Ok(bootstrap)
    }

    /// Bind host-resolved template and constraint digests into an authored parent.
    ///
    /// The parent must already declare its workflow, finite lifecycle grant and
    /// fresh boot identity. This changes only those two digest bindings and the
    /// plan content address; it never signs, admits, starts, or promotes a plan.
    pub fn bind(mut self) -> Result<Self> {
        self.validate_names()?;
        let templates = self.exact_templates()?;
        let membership = self
            .parent
            .workflow
            .as_mut()
            .context("actor parent is a direct workload")?;
        let WorkflowRole::Controller { grant } = &mut membership.role else {
            anyhow::bail!("actor parent is not a controller");
        };
        grant.templates = templates
            .iter()
            .map(|template| template.binding().clone())
            .collect();
        membership.constraint_snapshot_digest = self.constraints.digest()?;
        self.parent.plan_id = mvm_core::plan::compute_plan_id(&self.parent);
        self.validate()?;
        Ok(self)
    }

    /// Read one bounded local manifest and reject trailing data and unknown fields.
    pub fn read(reader: impl Read) -> Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_BOOTSTRAP_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_BOOTSTRAP_BYTES,
            "actor bootstrap exceeds bound"
        );
        let bootstrap: Self = serde_json::from_slice(&bytes).context("invalid actor bootstrap")?;
        bootstrap.validate()?;
        Ok(bootstrap)
    }

    /// Verify all caller-authored cross-bindings before starting a controller process.
    pub fn validate(&self) -> Result<()> {
        self.validate_names()?;
        ensure!(self.version == 1, "unsupported actor bootstrap version");
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BOOTSTRAP_BYTES,
            "actor bootstrap exceeds bound"
        );
        mvm_core::plan::verify_plan_id(&self.parent)?;
        let workflow = self
            .parent
            .workflow
            .as_ref()
            .context("actor parent is a direct workload")?;
        workflow.validate()?;
        let WorkflowRole::Controller { grant } = &workflow.role else {
            anyhow::bail!("actor parent is not a controller");
        };
        ensure!(
            grant.controller.tenant == self.parent.tenant
                && grant.controller.workload == self.parent.workload
                && grant.controller.execution_epoch.get() == self.parent.execution_epoch
                && self.parent.image.name == self.parent.workload.0,
            "actor parent identity mismatch"
        );
        ensure!(
            self.parent
                .services
                .iter()
                .any(|service| service.as_str() == "host.actor.v1"),
            "actor parent lacks lifecycle service"
        );
        ensure!(
            self.parent.mailbox.is_some(),
            "actor parent requires mailbox"
        );
        ensure!(
            self.parent.image.entrypoint_present,
            "actor parent requires an immutable image entrypoint"
        );
        self.constraints.validate_parent_charge(&self.parent)?;
        ensure!(
            self.parent.secrets.is_empty()
                && self.parent.extensions.is_empty()
                && self.parent.ingress.is_empty()
                && self.parent.deps_volume.is_none()
                && self.parent.snapshot_at.is_none()
                && !self.parent.post_run.snapshot_on_idle
                && self.parent.post_run.destroy_on_exit,
            "actor parent requests unsupported retained resources"
        );
        // The cold-profile owner permits only its verified, digest-pinned SDK
        // attachment; a matching share tag alone never authorizes a host path.
        let _config = self.launch.config(&self.parent)?;
        ensure!(
            workflow.constraint_snapshot_digest == self.constraints.digest()?,
            "actor snapshot digest mismatch"
        );
        ensure!(
            self.launch.network_policy == self.constraints.network,
            "actor parent network differs from snapshot"
        );
        let templates = self.exact_templates()?;
        ensure!(
            templates.len() == grant.templates.len(),
            "actor catalog differs from grant"
        );
        let catalog = ExactTemplateCatalog::new(templates)?;
        for binding in &grant.templates {
            catalog.resolve(binding)?;
        }
        Ok(())
    }

    fn validate_names(&self) -> Result<()> {
        mvm_core::naming::validate_vm_name(&self.parent.workload.0)?;
        mvm_core::naming::validate_id(&self.parent.tenant.0, "tenant")?;
        Ok(())
    }

    pub(crate) fn exact_templates(&self) -> Result<Vec<ActorTemplate>> {
        ensure!(
            !self.templates.is_empty() && self.templates.len() <= MAX_ACTOR_TEMPLATES,
            "invalid actor catalog size"
        );
        self.templates
            .iter()
            .map(|template| ActorTemplate::new(template.id.clone(), template.definition.clone()))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod bounds_tests {
    use super::*;

    #[test]
    fn bootstrap_is_bounded_before_json_parsing() {
        let oversized = std::io::repeat(b' ').take((MAX_BOOTSTRAP_BYTES + 1) as u64);
        assert!(
            ActorBootstrap::read(oversized)
                .unwrap_err()
                .to_string()
                .contains("exceeds bound")
        );
    }

    #[test]
    fn no_guest_request_can_be_used_as_host_bootstrap() {
        let request = br#"{"version":1,"operation":{"operation":"launch","grant_id":"g","template_id":"t","idempotency_key":"i"}}"#;
        assert!(ActorBootstrap::read(request.as_slice()).is_err());
    }
}
