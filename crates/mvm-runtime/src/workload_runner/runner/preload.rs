//! Saved-state child preparation before claim-time authorization.

use super::*;

impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Materialize and load one saved-state child while the pool is being
    /// refilled, leaving its VMM paused for a later claim. The child is not
    /// reachable by a workload yet: claim-time endpoint, broker, identity,
    /// and authenticated-vsock gates still run before resume.
    pub fn preload_standby_child(
        &self,
        ctx: &PreloadContext<'_>,
        handle: &mut StandbyHandle,
    ) -> std::result::Result<(), StandbyError> {
        if !self.driver.supports_preloaded_standby() {
            return Err(StandbyError::Unsupported {
                backend: self.driver.name().to_string(),
            });
        }
        if handle.preloaded_child_vm_name.is_some() {
            return Err(StandbyError::SpawnFailed(format!(
                "standby '{}' already owns a preloaded child",
                handle.id
            )));
        }
        let checkpoint = handle.parent_checkpoint.as_deref().ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "standby '{}' has no checkpoint for child preload",
                handle.id
            ))
        })?;
        let checkpoint_id = CheckpointId::new(checkpoint.to_string());
        let parent = ctx.checkpoints.read_meta(&checkpoint_id).map_err(|error| {
            StandbyError::SpawnFailed(format!("read preload checkpoint: {error:#}"))
        })?;
        crate::lineage::verify_record_against_chain(ctx.anchor, &parent).map_err(|error| {
            StandbyError::SpawnFailed(format!("authenticate preload checkpoint: {error:#}"))
        })?;
        if parent.class != mvm_core::checkpoint::CheckpointClass::VmFull {
            return Err(StandbyError::SpawnFailed(
                "warm memory preload requires a vm_full checkpoint".into(),
            ));
        }
        crate::checkpoint::verify_checkpoint_runtime(ctx.checkpoints, &parent).map_err(
            |error| StandbyError::SpawnFailed(format!("verify preload runtime: {error:#}")),
        )?;
        let runtime_digest = crate::checkpoint::metadata_blob_sha256(
            ctx.checkpoints,
            &parent,
            "runtime-artifacts.json",
        )
        .map_err(|error| StandbyError::SpawnFailed(error.to_string()))?;
        let anchors_digest = crate::checkpoint::metadata_blob_sha256(
            ctx.checkpoints,
            &parent,
            "device-anchors.json",
        )
        .map_err(|error| StandbyError::SpawnFailed(error.to_string()))?;
        let _registry_lock = acquire_registry_lock(ctx.registry_path)
            .map_err(|e| StandbyError::SpawnFailed(format!("acquire VM name registry: {e:#}")))?;
        let registry = VmNameRegistry::load(ctx.registry_path)
            .map_err(|e| StandbyError::SpawnFailed(format!("load VM name registry: {e:#}")))?;
        let (child_name, child_dir) = (0..MAX_CHILD_NAME_ATTEMPTS)
            .map(|_| generate_vm_name())
            .find_map(|name| {
                let dir = vm_state_dir(&name);
                (registry.lookup(&name).is_none() && !dir.exists()).then_some((name, dir))
            })
            .ok_or_else(|| {
                StandbyError::SpawnFailed("could not reserve a unique preloaded child name".into())
            })?;

        let materialized = if is_trusted_snapshot_id(checkpoint) {
            let backend = mvm_fs::trusted_snapshot::platform_backend(ctx.snapshots.root())
                .map_err(|e| {
                    StandbyError::SpawnFailed(format!("open trusted snapshot backend: {e:#}"))
                })?;
            materialize_child_from_trusted_parent(
                ctx.checkpoints,
                backend.as_ref(),
                &checkpoint_id,
                ctx.anchor,
                &child_dir,
            )
        } else {
            materialize_child_from_parent(
                ctx.checkpoints,
                ctx.snapshots,
                &checkpoint_id,
                ctx.anchor,
                &child_dir,
            )
        };
        if let Err(error) = materialized {
            let _ = std::fs::remove_dir_all(&child_dir);
            return Err(StandbyError::SpawnFailed(format!(
                "materialize preloaded child '{}': {error}",
                child_name
            )));
        }

        let loaded = self.driver.preload_standby_child(&PreloadChildRequest {
            child_vm_name: &child_name,
            child_dir: &child_dir,
            runtime_artifacts_sha256: Some(&runtime_digest),
            device_anchors_sha256: Some(&anchors_digest),
        });
        let loaded = match loaded {
            Ok(value) => value,
            Err(error) => {
                self.force_stop(&child_name, "failed preloaded standby child");
                let _ = std::fs::remove_dir_all(&child_dir);
                return Err(error);
            }
        };
        handle.preloaded_child_vm_name = Some(child_name);
        handle.pid = loaded.pid;
        handle.control_socket = loaded.control_socket;
        Ok(())
    }
}
