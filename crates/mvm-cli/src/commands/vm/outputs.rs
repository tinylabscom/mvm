//! CLI parsing and presentation for grant-backed transient-run outputs.

use anyhow::Result;
use mvm_core::plan::OutputGrant;

use super::up::AdmissionContext;
use crate::ui;

pub(super) struct PreparedOutputs(mvm_client::output_audit::PreparedOutputs);

impl PreparedOutputs {
    pub(super) fn prepare(outputs: &[String], mounts: &[String]) -> Result<Self> {
        // Unrelated mount parsing belongs to the ordinary launch path.
        if outputs.is_empty() {
            return mvm_client::output_audit::PreparedOutputs::prepare(Vec::new(), &[]).map(Self);
        }
        let mount_guests = mounts
            .iter()
            .map(|raw| {
                super::shared::parse_volume_spec(raw).map(|spec| match spec {
                    super::shared::VolumeSpec::DirShare { guest_mount, .. } => guest_mount,
                    super::shared::VolumeSpec::Disk { guest, .. } => guest,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let grants = outputs
            .iter()
            .map(|raw| {
                let spec = super::shared::parse_output_spec(raw)?;
                let destination = super::shared::resolve_output_destination(&spec.host_dir)?;
                Ok(OutputGrant {
                    guest_path: spec.guest,
                    host_path: destination.to_string_lossy().into_owned(),
                    max_bytes: spec.max_bytes,
                    max_entries: spec.max_entries,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        mvm_client::output_audit::PreparedOutputs::prepare(grants, &mount_guests).map(Self)
    }

    pub(super) fn grants(&self) -> Vec<OutputGrant> {
        self.0.grants()
    }

    pub(super) fn attach(&self, mut request: crate::exec::ExecRequest) -> crate::exec::ExecRequest {
        request.disk_volumes.extend(self.0.volumes());
        request
    }

    pub(super) fn close_run<T>(
        &self,
        admitted: &std::cell::RefCell<Option<AdmissionContext>>,
        backend: &str,
        posture: mvm_client::admission::BootPosture,
        result: Result<T>,
    ) -> Result<T> {
        self.0
            .close_run(admitted, backend, strategy, result, &mut |collected| {
                ui::info(&format!(
                    "Collected {} entries ({} bytes) from {} into {}; manifest {} (sha256 {})",
                    collected.entry_count,
                    collected.total_bytes,
                    collected.guest_path,
                    collected.destination.display(),
                    collected.manifest_path.display(),
                    collected.manifest_sha256,
                ));
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_outputs_prepares_nothing() {
        let prepared = PreparedOutputs::prepare(&[], &["/h:/data".to_string()]).unwrap();
        assert!(prepared.grants().is_empty());
        assert!(prepared.0.volumes().is_empty());
    }

    #[test]
    fn an_output_overlapping_a_mount_is_refused_before_boot() {
        let dir = tempfile::tempdir().unwrap();
        let spec = format!("{}:/data/out", dir.path().join("r").display());
        let error = PreparedOutputs::prepare(&[spec], &["/h:/data".to_string()])
            .err()
            .expect("overlap refused");
        assert!(
            error.to_string().contains("overlaps the --mount"),
            "{error}"
        );
    }
}
