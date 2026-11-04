//! The ownership side of a transient launch: registering the volumes the
//! request declares under the attempt's receipt, recording its secret
//! references, and settling the receipt at cleanup.

use std::sync::Arc;

use mvm_core::client::{MvmError, Result};

use super::{
    AdmittedProfile, AttachmentRequest, LOCAL_TENANT, LaunchRequest, LaunchVolumeSpec,
    LocalBackend, LocalVolumeService, MachineSecretRef, SecretService, VolumeService as _,
    launch_volume_service, machine_state_root,
};

impl LocalBackend {
    /// [`Self::validate_and_record_secret_refs`] for a transient attempt: the
    /// sidecar is written under the lifecycle lock and its digest bound into
    /// the attempt's receipt, so cleanup removes only what this attempt wrote.
    pub(super) fn record_transient_secret_refs(
        &self,
        name: &str,
        refs: &[MachineSecretRef],
    ) -> Result<()> {
        let Some(service) = self.admit_secret_refs(refs)? else {
            return Ok(());
        };
        crate::volume::ownership::record_secret_refs(&self.session_root(), name, || {
            Ok(service.record_machine_references(name, refs)?)
        })
        .map_err(|e| crate::local::backend_err(format!("recording secret refs: {e:#}")))
    }

    /// Fail-closed validation of `refs`; the service to record them with, or
    /// `None` when there is nothing to record.
    pub(super) fn admit_secret_refs(
        &self,
        refs: &[MachineSecretRef],
    ) -> Result<Option<Arc<SecretService>>> {
        if refs.is_empty() {
            return Ok(None);
        }
        let service = self.secrets()?;
        service
            .validate_for_admission(LOCAL_TENANT, refs)
            .map_err(|e| MvmError::Rejected {
                reason: format!("secret reference admission refused: {e}"),
            })?;
        Ok(Some(service))
    }

    /// The attachments of `volumes` that `name` does not already hold.
    pub(super) fn unregistered_attachments(
        service: &LocalVolumeService,
        name: &str,
        volumes: &[LaunchVolumeSpec],
        profile: AdmittedProfile,
    ) -> Result<Vec<AttachmentRequest>> {
        if volumes.is_empty() {
            return Ok(Vec::new());
        }
        let existing = service
            .list_attachments(name)
            .map_err(|e| crate::local::backend_err(format!("listing attachments: {e:#}")))?;
        let mut missing = Vec::new();
        for spec in volumes {
            let identical = existing.iter().any(|a| {
                a.guest_path == spec.guest_path
                    && a.volume == spec.volume
                    && a.access == spec.access
            });
            if identical {
                continue;
            }
            if existing.iter().any(|a| a.guest_path == spec.guest_path) {
                return Err(MvmError::Conflict {
                    reason: format!(
                        "guest path {:?} is already attached with a different volume or \
                         access mode; detach it first",
                        spec.guest_path
                    ),
                });
            }
            missing.push(
                AttachmentRequest::builder(name, &spec.volume)
                    .and_then(|b| {
                        b.guest_path(&spec.guest_path)
                            .access(spec.access)
                            .profile(profile)
                            .build()
                    })
                    .map_err(|e| MvmError::InvalidSpec {
                        reason: format!("volume attachment {:?}: {e:#}", spec.volume),
                    })?,
            );
        }
        Ok(missing)
    }

    /// Directory the transient session receipt and secret sidecar live under:
    /// the secret service's configured machines root, else the default.
    pub(crate) fn session_root(&self) -> std::path::PathBuf {
        self.secret_service
            .as_ref()
            .map_or_else(machine_state_root, |service| {
                service.machines_root().to_path_buf()
            })
    }

    /// Register the volumes the request declares under the attempt's receipt. Registrations this attempt did not create
    /// are borrowed and never recorded for removal.
    pub(super) fn register_transient_volumes(
        &self,
        name: &str,
        request: &LaunchRequest,
    ) -> Result<()> {
        let root = self.session_root();
        let service = launch_volume_service();
        let missing = Self::unregistered_attachments(
            &service,
            name,
            &request.volumes,
            AdmittedProfile::from_profile_name(&request.profile),
        )?;
        service
            .register_session_volumes(name, &missing, &root)
            .map_err(|e| crate::local::backend_err(format!("attaching volumes: {e:#}")))
    }

    /// Settle a transient session through its receipt. Returns whether
    /// anything was retained.
    pub(super) fn release_transient_resources(&self, name: &str) -> Result<bool> {
        let release = LocalVolumeService::new()
            .release_session(name, &self.session_root())
            .map_err(|e| {
                crate::local::backend_err(format!("releasing session resources: {e:#}"))
            })?;
        crate::local::deregister_from_name_registry(name);
        match release {
            crate::volume::SessionRelease::Released => Ok(false),
            crate::volume::SessionRelease::Retained(reason) => {
                tracing::warn!(machine = name, %reason, "transient cleanup retained session resources");
                Ok(true)
            }
        }
    }

    /// Release the leases a stopped machine holds. A persistent machine owns
    /// every lease under its name; a transient one releases only those its
    /// session receipt recorded, and none when it has no receipt.
    pub(crate) fn release_stopped_leases(&self, name: &str) -> anyhow::Result<()> {
        use crate::volume::{LocalVolumeService, SessionRelease, VolumeService as _};
        let service = LocalVolumeService::new();
        if mvm_core::config::machine_spec_path(name).exists() {
            service.release_owner_leases(name)?;
        } else if let SessionRelease::Retained(reason) =
            service.release_session_leases(name, &self.session_root())?
        {
            tracing::warn!(machine = name, %reason, "stop retained volume leases");
        }
        Ok(())
    }
}
