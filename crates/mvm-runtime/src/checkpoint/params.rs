//! The grouped inputs each checkpoint entry point takes, and their builders.
//!
//! Extracted from the parent module so the capture/fork implementations stay
//! under the production-file-size gate: three builders is roughly four hundred
//! lines of setters that say nothing about how a checkpoint is taken.

use std::path::PathBuf;

use mvm_contract::builder::BuilderError;
use mvm_core::checkpoint::CheckpointId;

/// Inputs for an `fs_quick` capture. Grouped into a struct so the call site
/// reads clearly and we never thread a long positional argument list.
pub struct CaptureFsQuickParams {
    pub id: CheckpointId,
    pub vm_name: String,
    /// Absolute path to the VM's live rootfs image to clone.
    pub rootfs: PathBuf,
    pub supervisor_config_digest: String,
    pub runtime_overlay_version: Option<String>,
    pub tag: Option<String>,
    pub created_unix: u64,
    /// The caller asserts the VM is stopped or paused-and-synced. A non-quiesced
    /// capture is refused: an fs_quick checkpoint has no memory, so the rootfs
    /// must be in a clean, deterministic state.
    pub quiesced: bool,
    /// The permission set the captured VM was admitted under, sealed into the
    /// checkpoint's content-address so a restore has something to bound its
    /// child against. `None` records no bound and therefore permits any child
    /// CPU or wall clock — but still no egress, since an absent egress grant is
    /// deny-all.
    pub grants: Option<mvm_contract::grants::Grants>,
}

impl CaptureFsQuickParams {
    /// Start building a [`CaptureFsQuickParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> CaptureFsQuickParamsBuilder {
        CaptureFsQuickParamsBuilder::new()
    }
}

/// Builder for [`CaptureFsQuickParams`]. Required fields are checked by
/// [`CaptureFsQuickParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct CaptureFsQuickParamsBuilder {
    id: Option<CheckpointId>,
    vm_name: Option<String>,
    rootfs: Option<PathBuf>,
    supervisor_config_digest: Option<String>,
    runtime_overlay_version: Option<String>,
    tag: Option<String>,
    created_unix: Option<u64>,
    quiesced: Option<bool>,
    grants: Option<mvm_contract::grants::Grants>,
}

impl CaptureFsQuickParamsBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: None,
            vm_name: None,
            rootfs: None,
            supervisor_config_digest: None,
            runtime_overlay_version: None,
            tag: None,
            created_unix: None,
            quiesced: None,
            grants: None,
        }
    }

    /// Set `id`.
    #[must_use]
    pub fn id(mut self, id: CheckpointId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: String) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Set `rootfs`.
    #[must_use]
    pub fn rootfs(mut self, rootfs: PathBuf) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    /// Set `supervisor_config_digest`.
    #[must_use]
    pub fn supervisor_config_digest(mut self, supervisor_config_digest: String) -> Self {
        self.supervisor_config_digest = Some(supervisor_config_digest);
        self
    }

    /// Set `runtime_overlay_version`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn runtime_overlay_version(
        mut self,
        runtime_overlay_version: impl Into<Option<String>>,
    ) -> Self {
        self.runtime_overlay_version = runtime_overlay_version.into();
        self
    }

    /// Set `tag`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<Option<String>>) -> Self {
        self.tag = tag.into();
        self
    }

    /// Set `created_unix`.
    #[must_use]
    pub fn created_unix(mut self, created_unix: u64) -> Self {
        self.created_unix = Some(created_unix);
        self
    }

    /// Set `quiesced`.
    #[must_use]
    pub fn quiesced(mut self, quiesced: bool) -> Self {
        self.quiesced = Some(quiesced);
        self
    }

    /// Set `grants`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn grants(mut self, grants: impl Into<Option<mvm_contract::grants::Grants>>) -> Self {
        self.grants = grants.into();
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<CaptureFsQuickParams, BuilderError> {
        Ok(CaptureFsQuickParams {
            id: self
                .id
                .ok_or(BuilderError::missing("CaptureFsQuickParams", "id"))?,
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("CaptureFsQuickParams", "vm_name"))?,
            rootfs: self
                .rootfs
                .ok_or(BuilderError::missing("CaptureFsQuickParams", "rootfs"))?,
            supervisor_config_digest: self.supervisor_config_digest.ok_or(
                BuilderError::missing("CaptureFsQuickParams", "supervisor_config_digest"),
            )?,
            runtime_overlay_version: self.runtime_overlay_version,
            tag: self.tag,
            created_unix: self.created_unix.ok_or(BuilderError::missing(
                "CaptureFsQuickParams",
                "created_unix",
            ))?,
            quiesced: self
                .quiesced
                .ok_or(BuilderError::missing("CaptureFsQuickParams", "quiesced"))?,
            grants: self.grants,
        })
    }
}

impl Default for CaptureFsQuickParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a checkpoint fork may coexist with its captured parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkParentLiveness {
    /// The parent must be stopped before any child bytes are materialized.
    MustBeStopped,
    /// The backend has proved that the restored child cannot collide with the
    /// still-running parent.
    MayBeRunning,
}

/// Inputs for forking a child instance from a checkpoint.
pub struct ForkParams {
    pub checkpoint: CheckpointId,
    /// New checkpoint-id recording this fork's lineage.
    pub child_id: CheckpointId,
    pub child_vm_name: String,
    /// Where to materialize the child's rootfs (the new VM's state dir).
    pub dest_dir: PathBuf,
    pub created_unix: u64,
    /// Backend-specific parent coexistence policy for this restore.
    pub parent_liveness: ForkParentLiveness,
    /// Serialized `SignedExecutionPlan` JSON for the child's own claim-8
    /// admission. When `Some`, the spawner injects it into the child's
    /// `SupervisorConfig.plan` so the supervisor re-verifies it at start.
    /// `None` is accepted for fs_quick materialization and test-only paths;
    /// vm_full restore refuses it before starting the child VMM.
    pub child_plan_json: Option<String>,
    /// Tenant id for the admitted child plan (mirrors `child_plan_json`).
    /// The supervisor uses this to derive the audit-substrate paths.
    pub child_tenant_id: Option<String>,
}

impl ForkParams {
    /// Start building a [`ForkParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> ForkParamsBuilder {
        ForkParamsBuilder::new()
    }
}

/// Builder for [`ForkParams`]. Required fields are checked by
/// [`ForkParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct ForkParamsBuilder {
    checkpoint: Option<CheckpointId>,
    child_id: Option<CheckpointId>,
    child_vm_name: Option<String>,
    dest_dir: Option<PathBuf>,
    created_unix: Option<u64>,
    parent_liveness: ForkParentLiveness,
    child_plan_json: Option<String>,
    child_tenant_id: Option<String>,
}

impl ForkParamsBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkpoint: None,
            child_id: None,
            child_vm_name: None,
            dest_dir: None,
            created_unix: None,
            parent_liveness: ForkParentLiveness::MustBeStopped,
            child_plan_json: None,
            child_tenant_id: None,
        }
    }

    /// Set `checkpoint`.
    #[must_use]
    pub fn checkpoint(mut self, checkpoint: CheckpointId) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    /// Set `child_id`.
    #[must_use]
    pub fn child_id(mut self, child_id: CheckpointId) -> Self {
        self.child_id = Some(child_id);
        self
    }

    /// Set `child_vm_name`.
    #[must_use]
    pub fn child_vm_name(mut self, child_vm_name: String) -> Self {
        self.child_vm_name = Some(child_vm_name);
        self
    }

    /// Set `dest_dir`.
    #[must_use]
    pub fn dest_dir(mut self, dest_dir: PathBuf) -> Self {
        self.dest_dir = Some(dest_dir);
        self
    }

    /// Set `created_unix`.
    #[must_use]
    pub fn created_unix(mut self, created_unix: u64) -> Self {
        self.created_unix = Some(created_unix);
        self
    }

    /// Set the backend's live-parent coexistence policy.
    #[must_use]
    pub fn parent_liveness(mut self, parent_liveness: ForkParentLiveness) -> Self {
        self.parent_liveness = parent_liveness;
        self
    }

    /// Set `child_plan_json`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn child_plan_json(mut self, child_plan_json: impl Into<Option<String>>) -> Self {
        self.child_plan_json = child_plan_json.into();
        self
    }

    /// Set `child_tenant_id`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn child_tenant_id(mut self, child_tenant_id: impl Into<Option<String>>) -> Self {
        self.child_tenant_id = child_tenant_id.into();
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<ForkParams, BuilderError> {
        Ok(ForkParams {
            checkpoint: self
                .checkpoint
                .ok_or(BuilderError::missing("ForkParams", "checkpoint"))?,
            child_id: self
                .child_id
                .ok_or(BuilderError::missing("ForkParams", "child_id"))?,
            child_vm_name: self
                .child_vm_name
                .ok_or(BuilderError::missing("ForkParams", "child_vm_name"))?,
            dest_dir: self
                .dest_dir
                .ok_or(BuilderError::missing("ForkParams", "dest_dir"))?,
            created_unix: self
                .created_unix
                .ok_or(BuilderError::missing("ForkParams", "created_unix"))?,
            parent_liveness: self.parent_liveness,
            child_plan_json: self.child_plan_json,
            child_tenant_id: self.child_tenant_id,
        })
    }
}

impl Default for ForkParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CaptureVmFullParams {
    pub id: CheckpointId,
    pub vm_name: String,
    pub supervisor_config_digest: String,
    pub runtime_overlay_version: Option<String>,
    /// The live VM's persisted supervisor config, copied into the checkpoint so
    /// restore can rebuild the state dir (every stop reaps the live one).
    /// `None` for backends that do not persist a supervisor config (the
    /// blob is omitted from the checkpoint manifest and restore is handled
    /// differently by those backends).
    pub supervisor_config_src: Option<PathBuf>,
    pub tag: Option<String>,
    pub created_unix: u64,
    /// Whether the caller wants the source VM left paused after a successful
    /// capture. Only the warm pool does: for it the paused parent *is* the
    /// claim resource, and the checkpoint is an integrity witness beside it. A
    /// user checkpointing their own running VM wants it running afterwards, so
    /// this is `false` on the CLI path. Retention still requires the backend to
    /// support it — the two must agree.
    pub retain_paused: bool,
    /// The permission set the captured VM was admitted under. See
    /// [`CaptureFsQuickParams::grants`].
    pub grants: Option<mvm_contract::grants::Grants>,
}

impl CaptureVmFullParams {
    /// Start building a [`CaptureVmFullParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> CaptureVmFullParamsBuilder {
        CaptureVmFullParamsBuilder::new()
    }
}

/// Builder for [`CaptureVmFullParams`]. Required fields are checked by
/// [`CaptureVmFullParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct CaptureVmFullParamsBuilder {
    id: Option<CheckpointId>,
    vm_name: Option<String>,
    supervisor_config_digest: Option<String>,
    runtime_overlay_version: Option<String>,
    supervisor_config_src: Option<PathBuf>,
    tag: Option<String>,
    created_unix: Option<u64>,
    retain_paused: Option<bool>,
    grants: Option<mvm_contract::grants::Grants>,
}

impl CaptureVmFullParamsBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: None,
            vm_name: None,
            supervisor_config_digest: None,
            runtime_overlay_version: None,
            supervisor_config_src: None,
            tag: None,
            created_unix: None,
            retain_paused: None,
            grants: None,
        }
    }

    /// Set `id`.
    #[must_use]
    pub fn id(mut self, id: CheckpointId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set `vm_name`.
    #[must_use]
    pub fn vm_name(mut self, vm_name: String) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    /// Set `supervisor_config_digest`.
    #[must_use]
    pub fn supervisor_config_digest(mut self, supervisor_config_digest: String) -> Self {
        self.supervisor_config_digest = Some(supervisor_config_digest);
        self
    }

    /// Set `runtime_overlay_version`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn runtime_overlay_version(
        mut self,
        runtime_overlay_version: impl Into<Option<String>>,
    ) -> Self {
        self.runtime_overlay_version = runtime_overlay_version.into();
        self
    }

    /// Set `supervisor_config_src`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn supervisor_config_src(
        mut self,
        supervisor_config_src: impl Into<Option<PathBuf>>,
    ) -> Self {
        self.supervisor_config_src = supervisor_config_src.into();
        self
    }

    /// Set `tag`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<Option<String>>) -> Self {
        self.tag = tag.into();
        self
    }

    /// Set `created_unix`.
    #[must_use]
    pub fn created_unix(mut self, created_unix: u64) -> Self {
        self.created_unix = Some(created_unix);
        self
    }

    /// Set `retain_paused`.
    #[must_use]
    pub fn retain_paused(mut self, retain_paused: bool) -> Self {
        self.retain_paused = Some(retain_paused);
        self
    }

    /// Set `grants`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn grants(mut self, grants: impl Into<Option<mvm_contract::grants::Grants>>) -> Self {
        self.grants = grants.into();
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<CaptureVmFullParams, BuilderError> {
        Ok(CaptureVmFullParams {
            id: self
                .id
                .ok_or(BuilderError::missing("CaptureVmFullParams", "id"))?,
            vm_name: self
                .vm_name
                .ok_or(BuilderError::missing("CaptureVmFullParams", "vm_name"))?,
            supervisor_config_digest: self.supervisor_config_digest.ok_or(
                BuilderError::missing("CaptureVmFullParams", "supervisor_config_digest"),
            )?,
            runtime_overlay_version: self.runtime_overlay_version,
            supervisor_config_src: self.supervisor_config_src,
            tag: self.tag,
            created_unix: self
                .created_unix
                .ok_or(BuilderError::missing("CaptureVmFullParams", "created_unix"))?,
            retain_paused: self.retain_paused.ok_or(BuilderError::missing(
                "CaptureVmFullParams",
                "retain_paused",
            ))?,
            grants: self.grants,
        })
    }
}

impl Default for CaptureVmFullParamsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod capture_fs_quick_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = CaptureFsQuickParams::builder().build() else {
            panic!("an empty CaptureFsQuickParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("CaptureFsQuickParams", "id"));
    }
}

#[cfg(test)]
mod fork_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = ForkParams::builder().build() else {
            panic!("an empty ForkParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("ForkParams", "checkpoint"));
    }
}

#[cfg(test)]
mod capture_vm_full_params_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = CaptureVmFullParams::builder().build() else {
            panic!("an empty CaptureVmFullParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("CaptureVmFullParams", "id"));
    }
}
