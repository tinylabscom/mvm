//! Exact host-authored cold launch definitions. Guests select only their binding.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use mvm_contract::grants::CpuGrant;
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::policy::resolver::EffectivePolicy;
use mvm_contract::protocol::actor_budget::ActorResources;
use mvm_contract::protocol::agent_capability::CapabilityBinding;
use mvm_contract::protocol::workload_actor::{
    ActorBindingId, MAX_ACTOR_TEMPLATES, TemplateBinding,
};
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::runtime_release::RuntimeLaunchBinding;
use mvm_core::vm_backend::{VmFile, VmStartConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The complete configurable surface of the initial cold actor launch profile.
///
/// Everything not represented here is fixed to the ordinary cold-start default;
/// in particular a template cannot request warm capacity, host endpoints, GPU,
/// caller registration, or a retained execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdLaunch {
    pub rootfs_path: String,
    pub kernel_path: Option<String>,
    pub runtime: RuntimeLaunchBinding,
    pub verity_path: Option<String>,
    pub roothash: Option<String>,
    pub config_files: Vec<TemplateFile>,
    pub network_policy: NetworkPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_sidecar: Option<mvm_runtime::sdk_sidecar::SdkSidecarPin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_source_checkout: Option<std::path::PathBuf>,
}

impl ColdLaunch {
    /// Resolve a supplied exact SDK pin before the host binds or signs this actor plan.
    ///
    /// This never chooses a version, guesses libc, builds source, or accepts user mounts.
    pub fn provision_sdk(&mut self, plan: &mut ExecutionPlan) -> Result<()> {
        ensure!(
            plan.sdk_uses_sidecar == self.sdk_sidecar.is_some(),
            "actor SDK delivery mode and sidecar pin disagree"
        );
        if let Some(pin) = &self.sdk_sidecar {
            let attachment = self.resolve_sidecar_pin(pin)?;
            if !plan.shares.is_empty() {
                ensure!(
                    plan.shares.len() == 1,
                    "actor SDK provisioning refuses user shares"
                );
                attachment.require_signed_grant(plan)?;
            }
            plan.shares = vec![attachment.grant];
        } else {
            ensure!(
                self.sdk_source_checkout.is_none(),
                "native actor cannot carry SDK source context"
            );
            ensure!(plan.shares.is_empty(), "actor profile refuses user shares");
        }
        Ok(())
    }

    /// Build the same bounded cold profile for a root or a derived child.
    pub fn config(&self, plan: &ExecutionPlan) -> Result<VmStartConfig> {
        let millicores = require_cpu_share(plan)?;
        let sdk_attachment = self.sdk_attachment(plan)?;
        ensure!(
            plan.image.entrypoint_present,
            "actor profile requires an immutable image entrypoint"
        );
        let mut config = VmStartConfig {
            name: plan.workload.0.clone(),
            rootfs_path: self.rootfs_path.clone(),
            kernel_path: self.kernel_path.clone(),
            verity_path: self.verity_path.clone(),
            roothash: self.roothash.clone(),
            cpus: plan.resources.cpus,
            cpu_grant: Some(CpuGrant::Share { millicores }),
            memory_mib: plan.resources.mem_mib.try_into()?,
            config_files: self
                .config_files
                .iter()
                .map(|file| VmFile {
                    name: file.name.clone(),
                    content: file.content.clone(),
                    mode: file.mode,
                })
                .collect(),
            network_policy: self.network_policy.clone(),
            ..Default::default()
        };
        self.runtime.apply_to_config(&mut config);
        if let Some(attachment) = sdk_attachment {
            config.volumes.push(attachment.volume);
        }
        Ok(config)
    }

    fn sdk_attachment(
        &self,
        plan: &ExecutionPlan,
    ) -> Result<Option<mvm_runtime::sdk_sidecar::SdkSidecarAttachment>> {
        ensure!(
            plan.sdk_uses_sidecar == self.sdk_sidecar.is_some(),
            "actor SDK delivery mode and sidecar pin disagree"
        );
        match &self.sdk_sidecar {
            None => {
                ensure!(
                    self.sdk_source_checkout.is_none(),
                    "native actor cannot carry SDK source context"
                );
                ensure!(plan.shares.is_empty(), "actor profile refuses user shares");
                Ok(None)
            }
            Some(pin) => {
                ensure!(
                    plan.shares.len() == 1,
                    "actor permits only its canonical SDK share"
                );
                let attachment = self.resolve_sidecar_pin(pin)?;
                attachment.require_signed_grant(plan)?;
                Ok(Some(attachment))
            }
        }
    }
    fn resolve_sidecar_pin(
        &self,
        pin: &mvm_runtime::sdk_sidecar::SdkSidecarPin,
    ) -> Result<mvm_runtime::sdk_sidecar::SdkSidecarAttachment> {
        let source_runtime = matches!(
            &self.runtime,
            RuntimeLaunchBinding::CliAssembly(
                mvm_core::protocol::runtime_release::CliRuntimeLaunchBinding {
                    provenance:
                        mvm_core::protocol::runtime_release::RuntimeBindingProvenance::Source { .. },
                    ..
                }
            )
        );
        ensure!(
            !source_runtime || self.sdk_source_checkout.is_some(),
            "source actor SDK requires an explicit checkout"
        );
        if let Some(source) = &self.sdk_source_checkout {
            ensure!(
                source.is_absolute(),
                "actor SDK source checkout must be absolute"
            );
        }
        pin.resolve_exact(
            std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
            self.sdk_source_checkout.as_deref(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFile {
    pub name: String,
    pub content: String,
    pub mode: u32,
}

/// Authenticated host template input, never decoded from the actor service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateDefinition {
    pub plan: ExecutionPlan,
    pub launch: ColdLaunch,
    pub effective_policy: EffectivePolicy,
    pub capabilities: Vec<CapabilityBinding>,
    pub charge: ActorResources,
}

/// Immutable executable template and the digest over every configurable input.
pub struct ActorTemplate {
    binding: TemplateBinding,
    definition: TemplateDefinition,
}

impl ActorTemplate {
    /// Freeze all launch inputs and derive the binding a controller plan must pin.
    pub fn new(id: ActorBindingId, definition: TemplateDefinition) -> Result<Self> {
        let plan = &definition.plan;
        ensure!(
            !plan
                .services
                .iter()
                .any(|service| service.as_str() == "host.actor.v1"),
            "worker template cannot expose lifecycle authority"
        );
        ensure!(
            definition.launch.kernel_path.is_none() || plan.environment.is_some(),
            "actor kernel requires an admitted content pin"
        );
        ensure!(
            plan.workflow.is_none(),
            "template must not carry delegation or parent lineage"
        );
        ensure!(
            plan.snapshot_at.is_none()
                && !plan.post_run.snapshot_on_idle
                && plan.post_run.destroy_on_exit,
            "actor must be destroyed"
        );
        ensure!(
            plan.extensions.is_empty() && plan.ingress.is_empty(),
            "actor profile does not support extensions or ingress"
        );
        ensure!(
            plan.secrets.is_empty(),
            "actor profile does not support secret file provisioning"
        );
        ensure!(
            plan.deps_volume.is_none(),
            "actor profile does not support dependency volumes"
        );
        let _sdk_attachment = definition.launch.sdk_attachment(plan)?;
        ensure!(plan.mailbox.is_some(), "actor requires a mailbox template");
        validate_charge(plan, definition.charge)?;
        let digest: [u8; 32] = Sha256::digest(serde_jcs::to_vec(&definition)?).into();
        let binding = TemplateBinding {
            id,
            digest: mvm_contract::assurance::Sha256Digest::from_bytes(&digest),
        };
        Ok(Self {
            binding,
            definition,
        })
    }

    pub fn binding(&self) -> &TemplateBinding {
        &self.binding
    }

    pub(super) fn definition(&self) -> &TemplateDefinition {
        &self.definition
    }

    pub(super) fn config(&self, child: &ExecutionPlan) -> Result<VmStartConfig> {
        self.definition.launch.config(child)
    }
}

fn validate_charge(plan: &ExecutionPlan, charge: ActorResources) -> Result<()> {
    ensure!(
        charge.live_vms == 1
            && charge.resident_vmms == 1
            && charge.concurrent_launches == 1
            && charge.controllers == 0
            && charge.warm_slots == 0
            && charge.parked_slots == 0
            && charge.checkpoint_slots == 0,
        "actor charge must describe one cold nondelegating child"
    );
    validate_resource_charge(plan, charge)
}

fn require_cpu_share(plan: &ExecutionPlan) -> Result<u32> {
    match plan.grants.as_ref().and_then(|grants| grants.cpu) {
        Some(CpuGrant::Share { millicores }) if millicores > 0 => Ok(millicores),
        Some(CpuGrant::Share { .. } | CpuGrant::Fuel { .. }) | None => {
            anyhow::bail!("actor profile requires an explicit nonzero CPU share")
        }
    }
}

pub(super) fn validate_resource_charge(plan: &ExecutionPlan, charge: ActorResources) -> Result<()> {
    let millicores = require_cpu_share(plan)?;
    let resources = &plan.resources;
    let memory = resources
        .mem_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("actor memory charge overflow"))?;
    let disk = resources
        .disk_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("actor disk charge overflow"))?;
    ensure!(
        charge.memory_bytes >= memory
            && charge.disk_bytes >= disk
            && charge.cpu_millicores >= u64::from(millicores)
            && charge.file_descriptors > 0
            && charge.host_sockets > 0
            && charge.vsock_channels > 0
            && charge.mailbox_bytes > 0,
        "actor template omits required resource charges"
    );
    Ok(())
}

/// Bounded exact lookup, with no fallback to tags, paths, or guest configuration.
pub struct ExactTemplateCatalog(BTreeMap<ActorBindingId, ActorTemplate>);

impl ExactTemplateCatalog {
    pub fn new(templates: Vec<ActorTemplate>) -> Result<Self> {
        ensure!(
            !templates.is_empty() && templates.len() <= MAX_ACTOR_TEMPLATES,
            "invalid actor catalog size"
        );
        let mut map = BTreeMap::new();
        for template in templates {
            ensure!(
                map.insert(template.binding.id.clone(), template).is_none(),
                "duplicate actor template"
            );
        }
        Ok(Self(map))
    }

    pub fn resolve(&self, binding: &TemplateBinding) -> Result<&ActorTemplate> {
        let template = self
            .0
            .get(&binding.id)
            .ok_or_else(|| anyhow::anyhow!("unknown actor template"))?;
        ensure!(
            template.binding == *binding,
            "actor template digest mismatch"
        );
        Ok(template)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxGrant, MailboxId};
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::protocol::runtime_release::{CliRuntimeLaunchBinding, RuntimeBindingProvenance};

    fn definition() -> TemplateDefinition {
        let plan = PlanFixture::new()
            .sdk_uses_sidecar(false)
            .grants(Some(mvm_contract::grants::Grants {
                cpu: Some(CpuGrant::Share { millicores: 1000 }),
                ..Default::default()
            }))
            .mailbox(MailboxGrant {
                mailbox: MailboxId::from_bytes([1; 32]),
                authority_key: [2; 32],
                epoch: ExecutionEpoch::new(1).unwrap(),
                report: None,
                retention: None,
                service_blind: None,
            })
            .build();
        let launch = ColdLaunch {
            rootfs_path: "/host/rootfs".into(),
            kernel_path: None,
            runtime: RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
                provenance: RuntimeBindingProvenance::Source {
                    version: "fixture".into(),
                    arch: mvm_core::arch::GuestArch::Aarch64,
                    archive_sha256: "a".repeat(64),
                },
                overlay_path: "/host/overlay".into(),
                overlay_verity_path: "/host/overlay.verity".into(),
                initramfs_path: "/host/initramfs".into(),
                overlay_roothash: "b".repeat(64),
            }),
            verity_path: None,
            roothash: None,
            config_files: Vec::new(),
            network_policy: NetworkPolicy::deny_all(),
            sdk_sidecar: None,
            sdk_source_checkout: None,
        };
        let charge = ActorResources {
            live_vms: 1,
            resident_vmms: 1,
            concurrent_launches: 1,
            memory_bytes: plan.resources.mem_mib * 1024 * 1024,
            cpu_millicores: u64::from(plan.resources.cpus) * 1000,
            disk_bytes: plan.resources.disk_mib * 1024 * 1024,
            mailbox_bytes: 4096,
            file_descriptors: 32,
            host_sockets: 8,
            vsock_channels: 8,
            ..Default::default()
        };
        TemplateDefinition {
            plan,
            launch,
            charge,
            effective_policy: EffectivePolicy::default(),
            capabilities: Vec::new(),
        }
    }

    #[test]
    fn exact_binding_changes_when_host_launch_configuration_changes() {
        let id = ActorBindingId::new("worker").unwrap();
        let original = ActorTemplate::new(id.clone(), definition()).unwrap();
        let binding = original.binding().clone();
        let catalog = ExactTemplateCatalog::new(vec![original]).unwrap();
        assert!(catalog.resolve(&binding).is_ok());
        let mut changed = definition();
        changed.launch.config_files.push(TemplateFile {
            name: "/etc/actor-config".into(),
            content: "different".into(),
            mode: 0o444,
        });
        let changed = ActorTemplate::new(id, changed).unwrap();
        assert!(catalog.resolve(changed.binding()).is_err());
    }

    #[test]
    fn undercharged_or_reusable_templates_are_refused() {
        let id = ActorBindingId::new("worker").unwrap();
        let mut input = definition();
        input.charge.memory_bytes = 0;
        assert!(ActorTemplate::new(id.clone(), input).is_err());
        let mut input = definition();
        input.plan.post_run.snapshot_on_idle = true;
        assert!(ActorTemplate::new(id, input).is_err());
    }

    #[test]
    fn actor_cpu_charge_requires_and_covers_the_enforced_share() {
        let id = ActorBindingId::new("worker").unwrap();
        for cpu in [
            None,
            Some(CpuGrant::Share { millicores: 0 }),
            Some(CpuGrant::Fuel { instructions: 1000 }),
        ] {
            let mut input = definition();
            input.plan.grants.as_mut().unwrap().cpu = cpu;
            assert!(input.launch.config(&input.plan).is_err());
            assert!(ActorTemplate::new(id.clone(), input).is_err());
        }
        let mut input = definition();
        input.plan.grants.as_mut().unwrap().cpu = Some(CpuGrant::Share { millicores: 2500 });
        input.charge.cpu_millicores = 2499;
        assert!(ActorTemplate::new(id.clone(), input.clone()).is_err());
        input.charge.cpu_millicores = 2500;
        assert!(ActorTemplate::new(id, input).is_ok());
    }

    #[test]
    fn native_actor_provisions_no_sdk_or_user_mounts() {
        let mut input = definition();
        input.launch.provision_sdk(&mut input.plan).unwrap();
        assert!(input.launch.config(&input.plan).unwrap().volumes.is_empty());
        input.plan.sdk_uses_sidecar = true;
        assert!(input.launch.provision_sdk(&mut input.plan).is_err());
        assert!(input.launch.config(&input.plan).is_err());
        input.plan.sdk_uses_sidecar = false;
        input.plan.shares.push(mvm_core::plan::HostShareGrant {
            tag: "user".into(),
            host_path: "/host/user".into(),
            guest_path: "/data".into(),
            kind: mvm_core::plan::ShareKind::Disk,
            read_only: true,
            encrypted: false,
            content_sha256: None,
            include: Vec::new(),
            exclude: Vec::new(),
        });
        assert!(input.launch.provision_sdk(&mut input.plan).is_err());
        assert!(input.launch.config(&input.plan).is_err());
    }

    #[test]
    fn source_actor_sdk_never_guesses_a_checkout() {
        let mut input = definition();
        input.plan.sdk_uses_sidecar = true;
        input.launch.sdk_sidecar = Some(mvm_runtime::sdk_sidecar::SdkSidecarPin {
            version: "fixture".into(),
            arch: mvm_core::arch::GuestArch::Aarch64,
            libc: mvm_contract::guest_libc::GuestLibc::Musl,
            image_sha256: mvm_contract::assurance::Sha256Digest::from_bytes(&[5; 32]),
        });
        let error = input.launch.provision_sdk(&mut input.plan).unwrap_err();
        assert!(error.to_string().contains("explicit checkout"));
        input.launch.sdk_source_checkout = Some("relative-checkout".into());
        let error = input.launch.provision_sdk(&mut input.plan).unwrap_err();
        assert!(error.to_string().contains("must be absolute"));
    }
}
