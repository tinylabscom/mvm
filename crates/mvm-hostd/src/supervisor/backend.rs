//! Backend launcher slot — what the supervisor calls to actually
//! start a VM once it's verified the plan.
//!
//! Plan 37 §3.1 specifies an open `BackendRegistry`; for Wave 1.4
//! we just need an abstraction so `Supervisor::launch(plan)` can
//! be tested without a real Firecracker. The registry + concrete
//! `FirecrackerBackend` / `AppleContainerBackend` impls land in
//! a follow-up that lifts today's `mvm/src/vm/backend.rs`
//! `AnyBackend` enum behind this trait.

use async_trait::async_trait;
use mvm_backend::base::config::VmSlot;
use mvm_backend::microvm::FlakeRunConfig;
use mvm_core::plan::{ExecutionPlan, PlanId};
use std::collections::BTreeMap;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend not wired (Noop slot)")]
    NotWired,

    #[error("backend launch failed: {0}")]
    LaunchFailed(String),

    #[error("backend launch preparation failed: {0}")]
    PrepareFailed(String),

    #[error("backend stop failed: {0}")]
    StopFailed(String),

    #[error("backend not aware of plan {plan_id:?}")]
    UnknownPlan { plan_id: PlanId },
}

/// Runtime metadata the backend owns before the supervisor installs
/// host-side policy. The VM slot is the canonical source for VM
/// identity and TAP allocation; callers must not synthesize those
/// names separately.
#[derive(Debug, Clone)]
pub struct BackendLaunchSpec {
    pub vm_slot: VmSlot,
}

impl BackendLaunchSpec {
    pub fn new(vm_slot: VmSlot) -> Self {
        Self { vm_slot }
    }
}

/// Async because real backends drive Firecracker's HTTP API or
/// Apple Container's vsock RPC, both of which the supervisor will
/// eventually pump from a tokio runtime.
#[async_trait]
pub trait BackendLauncher: Send + Sync {
    /// Reserve or derive runtime metadata needed before backend
    /// launch. This must not start tenant code. The supervisor uses
    /// the returned slot to install firewall policy before calling
    /// [`BackendLauncher::launch`].
    async fn prepare_launch(&self, plan: &ExecutionPlan)
    -> Result<BackendLaunchSpec, BackendError>;

    /// Issue the start request. Returns when the backend has
    /// accepted the request — not necessarily when the guest is
    /// ready. The supervisor's state machine separately transitions
    /// `Launched -> Running` after the guest agent pings (Wave 2).
    async fn launch(&self, plan: &ExecutionPlan) -> Result<(), BackendError>;

    /// Stop the workload identified by `plan_id`.
    async fn stop(&self, plan_id: &PlanId) -> Result<(), BackendError>;
}

/// Fail-closed default. A supervisor wired with `NoopBackendLauncher`
/// can't start any workload — the launch attempt errors with
/// `BackendError::NotWired` before the supervisor transitions to
/// `Launched`.
pub struct NoopBackendLauncher;

#[async_trait]
impl BackendLauncher for NoopBackendLauncher {
    async fn prepare_launch(
        &self,
        _plan: &ExecutionPlan,
    ) -> Result<BackendLaunchSpec, BackendError> {
        Err(BackendError::NotWired)
    }

    async fn launch(&self, _plan: &ExecutionPlan) -> Result<(), BackendError> {
        Err(BackendError::NotWired)
    }

    async fn stop(&self, _plan_id: &PlanId) -> Result<(), BackendError> {
        Err(BackendError::NotWired)
    }
}

/// Firecracker-backed launcher for an already-built runtime config.
///
/// `FlakeRunConfig` carries the canonical `VmSlot`, so this adapter
/// can satisfy the supervisor's firewall-before-launch contract
/// without allocating or synthesizing network identity in the
/// supervisor layer. `prepare_launch` only exposes metadata; tenant
/// code starts exclusively in `launch`.
pub struct FirecrackerRunConfigLauncher {
    config: FlakeRunConfig,
    launched: Mutex<BTreeMap<PlanId, String>>,
}

impl FirecrackerRunConfigLauncher {
    pub fn new(config: FlakeRunConfig) -> Result<Self, BackendError> {
        if config.name != config.slot.name {
            return Err(BackendError::PrepareFailed(format!(
                "run config name {:?} does not match slot name {:?}",
                config.name, config.slot.name
            )));
        }
        config
            .validate()
            .map_err(|e| BackendError::PrepareFailed(e.to_string()))?;
        Ok(Self {
            config,
            launched: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn config(&self) -> &FlakeRunConfig {
        &self.config
    }
}

#[async_trait]
impl BackendLauncher for FirecrackerRunConfigLauncher {
    async fn prepare_launch(
        &self,
        _plan: &ExecutionPlan,
    ) -> Result<BackendLaunchSpec, BackendError> {
        Ok(BackendLaunchSpec::new(self.config.slot.clone()))
    }

    async fn launch(&self, plan: &ExecutionPlan) -> Result<(), BackendError> {
        mvm_backend::microvm::run_from_build(&self.config)
            .map_err(|e| BackendError::LaunchFailed(e.to_string()))?;
        self.launched
            .lock()
            .expect("backend launch map mutex poisoned")
            .insert(plan.plan_id.clone(), self.config.name.clone());
        Ok(())
    }

    async fn stop(&self, plan_id: &PlanId) -> Result<(), BackendError> {
        let vm_name = self
            .launched
            .lock()
            .expect("backend launch map mutex poisoned")
            .get(plan_id)
            .cloned()
            .ok_or_else(|| BackendError::UnknownPlan {
                plan_id: plan_id.clone(),
            })?;
        mvm_backend::microvm::stop_vm(&vm_name)
            .map_err(|e| BackendError::StopFailed(e.to_string()))?;
        self.launched
            .lock()
            .expect("backend launch map mutex poisoned")
            .remove(plan_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_backend_launcher_is_constructable() {
        let _: Box<dyn BackendLauncher> = Box::new(NoopBackendLauncher);
    }

    fn sample_run_config() -> FlakeRunConfig {
        FlakeRunConfig {
            name: "vm1".to_string(),
            slot: VmSlot::new("vm1", 3),
            vmlinux_path: "/nix/store/kernel/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/nix/store/rootfs/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            revision_hash: "r".repeat(64),
            flake_ref: "github:example/workload".to_string(),
            profile: Some("worker".to_string()),
            cpus: 2,
            memory: 1024,
            mem_initial: None,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
            network_policy: mvm_core::network_policy::NetworkPolicy::default(),
        }
    }

    #[test]
    fn firecracker_launcher_constructor_rejects_slot_name_mismatch() {
        let mut config = sample_run_config();
        config.slot = VmSlot::new("other-vm", 3);

        let err = match FirecrackerRunConfigLauncher::new(config) {
            Ok(_) => panic!("mismatch must be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, BackendError::PrepareFailed(_)));
    }

    #[tokio::test]
    async fn firecracker_launcher_prepare_returns_configured_slot_without_launching() {
        let config = sample_run_config();
        let expected_slot = config.slot.clone();
        let launcher = FirecrackerRunConfigLauncher::new(config).expect("valid config");
        let plan = ExecutionPlan {
            schema_version: mvm_core::plan::SCHEMA_VERSION,
            plan_id: PlanId("01HXTEST0000000000000000".to_string()),
            plan_version: 1,
            tenant: mvm_core::plan::TenantId("tenant-a".to_string()),
            workload: mvm_core::plan::WorkloadId("workload-1".to_string()),
            runtime_profile: mvm_core::plan::RuntimeProfileRef("firecracker".to_string()),
            image: mvm_core::plan::SignedImageRef {
                name: "tenant-worker-aarch64".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: mvm_core::plan::Resources {
                cpus: 2,
                mem_mib: 1024,
                disk_mib: 4096,
                timeouts: mvm_core::plan::TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 600,
                },
            },
            admission_profile: mvm_core::plan::AdmissionProfile::local_default(
                "vm:boot",
                mvm_core::plan::PlanSeccompTier::Standard,
            ),
            network_policy: mvm_core::plan::PolicyRef("default-deny".to_string()),
            fs_policy: mvm_core::plan::FsPolicyRef("default".to_string()),
            secrets: vec![],
            egress_policy: mvm_core::plan::PolicyRef("agent-l7".to_string()),
            redaction: Default::default(),
            tool_policy: mvm_core::plan::PolicyRef("read-only".to_string()),
            artifact_policy: mvm_core::plan::ArtifactPolicy {
                capture_paths: vec!["/artifacts".to_string()],
                retention_days: 30,
            },
            audit_labels: BTreeMap::new(),
            key_rotation: mvm_core::plan::KeyRotationSpec { interval_days: 7 },
            attestation: mvm_core::plan::AttestationRequirement {
                mode: mvm_core::plan::AttestationMode::Noop,
            },
            release_pin: None,
            post_run: mvm_core::plan::PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: chrono::Utc::now(),
            valid_until: chrono::Utc::now(),
            nonce: mvm_core::plan::Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
        };

        let spec = launcher
            .prepare_launch(&plan)
            .await
            .expect("prepare succeeds");

        assert_eq!(spec.vm_slot.name, expected_slot.name);
        assert_eq!(spec.vm_slot.index, expected_slot.index);
        assert_eq!(spec.vm_slot.tap_dev, expected_slot.tap_dev);
    }
}
