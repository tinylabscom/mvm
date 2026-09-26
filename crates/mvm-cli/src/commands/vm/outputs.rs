//! `--output HOST_DIR:/GUEST[:SIZE[:MAX_ENTRIES]]` on a transient run.
//!
//! Before boot, each output gets a fresh ext4 image in a private scratch
//! directory, attached writable at the guest path through the same disk-volume
//! path `--mount HOST:/GUEST:SIZE:rw` uses — so it is flushed before teardown
//! and named in the signed plan's host-fs grants like any other disk. The grant
//! itself (destination and bounds) rides in the plan's `outputs`.
//!
//! After the workload exits and its VM is gone, the host reads each image and
//! collects it under the bounds the *admitted plan* carries, then records the
//! result as a chain-signed `plan.outputs` entry. The guest is never asked for
//! anything: the image is the whole interface.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::plan::OutputGrant;
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
use mvm_hostd::audit::output_audit::{OutputOutcome, OutputRecord};

use super::up::AdmissionContext;
use crate::ui;

const MIB: u64 = 1024 * 1024;

/// Disk capacity for an output whose byte bound is `max_bytes`, in MiB.
///
/// ext4 spends part of any image on its own metadata, so a disk sized exactly
/// to the bound could not hold a workload that stays inside it. The headroom
/// means the byte bound — checked on the host, with a message naming it — is
/// what refuses an oversized result, rather than a full disk the workload may
/// or may not notice.
fn disk_capacity_mib(max_bytes: u64) -> u64 {
    let bound = max_bytes.div_ceil(MIB);
    bound + (bound / 4).max(16)
}

/// Whether two guest mount points would shadow one another.
fn guest_paths_overlap(a: &str, b: &str) -> bool {
    Path::new(a).starts_with(b) || Path::new(b).starts_with(a)
}

struct PreparedOutput {
    grant: OutputGrant,
    image: PathBuf,
}

/// The outputs one transient run grants, with their scratch images.
///
/// Dropping this removes the scratch directory and every image in it, which
/// is the only cleanup a collected or refused output needs.
pub(super) struct PreparedOutputs {
    outputs: Vec<PreparedOutput>,
    _scratch: Option<tempfile::TempDir>,
}

impl PreparedOutputs {
    /// Parse and check every `--output`, refusing before boot anything that
    /// could not be collected afterwards: a malformed spec, an unusable
    /// destination, two outputs sharing a destination, or a guest path that
    /// overlaps another output or a `--mount`.
    pub(super) fn prepare(outputs: &[String], mounts: &[String]) -> Result<Self> {
        if outputs.is_empty() {
            return Ok(Self {
                outputs: Vec::new(),
                _scratch: None,
            });
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

        let mut grants: Vec<OutputGrant> = Vec::with_capacity(outputs.len());
        for raw in outputs {
            let spec = super::shared::parse_output_spec(raw)?;
            if let Some(mount) = mount_guests
                .iter()
                .find(|mount| guest_paths_overlap(mount, &spec.guest))
            {
                anyhow::bail!(
                    "--output '{raw}' overlaps the --mount at {mount}; an output needs a guest \
                     directory of its own"
                );
            }
            let destination = super::shared::resolve_output_destination(&spec.host_dir)?;
            let host_path = destination.to_string_lossy().into_owned();
            for earlier in &grants {
                if guest_paths_overlap(&earlier.guest_path, &spec.guest) {
                    anyhow::bail!(
                        "--output '{raw}' overlaps the output at {}",
                        earlier.guest_path
                    );
                }
                if earlier.host_path == host_path {
                    anyhow::bail!("--output '{raw}' collects into {host_path} twice");
                }
            }
            grants.push(OutputGrant {
                guest_path: spec.guest,
                host_path,
                max_bytes: spec.max_bytes,
                max_entries: spec.max_entries,
            });
        }

        let parent = PathBuf::from(mvm_core::config::mvm_state_dir()).join("outputs");
        mvm_core::config::create_private_dir(&parent)
            .with_context(|| format!("creating output scratch root {}", parent.display()))?;
        let scratch = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(&parent)
            .with_context(|| format!("creating output scratch in {}", parent.display()))?;
        let scratch_path = std::fs::canonicalize(scratch.path())
            .with_context(|| format!("resolving {}", scratch.path().display()))?;
        let outputs = grants
            .into_iter()
            .enumerate()
            .map(|(index, grant)| PreparedOutput {
                image: scratch_path.join(format!("output-{index}.img")),
                grant,
            })
            .collect();
        Ok(Self {
            outputs,
            _scratch: Some(scratch),
        })
    }

    /// The grants to sign into the plan.
    pub(super) fn grants(&self) -> Vec<OutputGrant> {
        self.outputs.iter().map(|o| o.grant.clone()).collect()
    }

    /// Attach the writable disk backing each output to a launch request.
    pub(super) fn attach(&self, mut request: crate::exec::ExecRequest) -> crate::exec::ExecRequest {
        request.disk_volumes.extend(self.volumes());
        request
    }

    /// The writable disks backing each output.
    fn volumes(&self) -> Vec<VmVolume> {
        self.outputs
            .iter()
            .map(|output| VmVolume {
                materialized_image: None,
                volume_label: None,
                host: output.image.to_string_lossy().into_owned(),
                guest: output.grant.guest_path.clone(),
                size: format!("{}M", disk_capacity_mib(output.grant.max_bytes)),
                read_only: false,
                kind: VmVolumeKind::Disk,
                encrypted: false,
            })
            .collect()
    }

    /// Close a transient run: record how it ended against its admitted plan,
    /// collect its outputs, and surface the run's own failure ahead of a
    /// collection refusal.
    ///
    /// Outputs are collected whatever the workload's exit code — a failing
    /// job's partial results and logs are often exactly what the caller needs
    /// back. Only a run that did not complete is left uncollected.
    pub(super) fn close_run<T>(
        &self,
        admitted: &std::cell::RefCell<Option<AdmissionContext>>,
        backend: &str,
        strategy: mvm_build::run_image::RootStrategy,
        result: Result<T>,
    ) -> Result<T> {
        let admitted = admitted.borrow_mut().take();
        super::up::record_transient_outcome(admitted.as_ref(), backend, strategy, &result);
        let collected = self.collect(admitted.as_ref(), result.is_ok());
        let value = result?;
        collected?;
        Ok(value)
    }

    /// Collect every output after the run, record each in the audit chain,
    /// and fail when any collection was refused.
    ///
    /// Bounds and destinations come from the admitted plan, not from the
    /// flags: what is enforced is what was signed. A run that did not complete
    /// has no flushed disk to trust, so its outputs are recorded as refused
    /// and nothing is read.
    fn collect(&self, admitted: Option<&AdmissionContext>, run_completed: bool) -> Result<()> {
        if self.outputs.is_empty() {
            return Ok(());
        }
        let Some(admitted) = admitted else {
            anyhow::bail!(
                "outputs were not collected: the run has no admitted plan to record them against"
            );
        };
        let plan = admitted.admitted.plan();
        let mut refusals = Vec::new();
        for output in &self.outputs {
            let guest_path = output.grant.guest_path.as_str();
            let grant = plan
                .outputs
                .iter()
                .find(|grant| grant.guest_path == guest_path)
                .with_context(|| {
                    format!("the admitted plan carries no output grant for {guest_path}")
                })?;
            if !run_completed {
                record(
                    admitted,
                    guest_path,
                    OutputOutcome::Refused {
                        reason: "run_failed",
                    },
                )?;
                continue;
            }
            let destination = PathBuf::from(&grant.host_path);
            let protected = plan.protected_paths.matcher();
            let collected = mvm_fs::output::collect_from_ext4(&mvm_fs::output::OutputCollection {
                image: &output.image,
                destination: &destination,
                bounds: mvm_fs::output::OutputBounds {
                    max_bytes: grant.max_bytes,
                    max_entries: grant.max_entries,
                },
                protected: protected.as_ref(),
            });
            match collected {
                Ok(collected) => {
                    let tree_sha256 =
                        mvm_fs::hash::hash_source(&destination).with_context(|| {
                            format!("hashing collected outputs in {}", destination.display())
                        })?;
                    let manifest = &collected.manifest;
                    record(
                        admitted,
                        guest_path,
                        OutputOutcome::Collected {
                            manifest_sha256: &manifest.digest,
                            entry_count: manifest.entry_count,
                            total_bytes: manifest.total_bytes,
                            tree_sha256: &tree_sha256,
                        },
                    )?;
                    ui::info(&format!(
                        "Collected {} entries ({} bytes) from {guest_path} into {}; manifest {} (sha256 {})",
                        manifest.entry_count,
                        manifest.total_bytes,
                        destination.display(),
                        collected.manifest_path.display(),
                        manifest.digest,
                    ));
                }
                Err(refusal) => {
                    record(
                        admitted,
                        guest_path,
                        OutputOutcome::Refused {
                            reason: refusal.audit_tag(),
                        },
                    )?;
                    refusals.push(format!("{guest_path}: {refusal}"));
                }
            }
        }
        if !refusals.is_empty() {
            anyhow::bail!("output collection refused — {}", refusals.join("; "));
        }
        Ok(())
    }
}

fn record(admitted: &AdmissionContext, guest_path: &str, outcome: OutputOutcome<'_>) -> Result<()> {
    admitted
        .emitter
        .emit_outputs(
            admitted.admitted.plan(),
            &OutputRecord {
                guest_path,
                outcome,
            },
        )
        .with_context(|| format!("recording the output collection for {guest_path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_capacity_leaves_room_past_the_bound() {
        assert_eq!(disk_capacity_mib(MIB), 17);
        assert_eq!(disk_capacity_mib(64 * MIB), 80);
        assert_eq!(disk_capacity_mib(1024 * MIB), 1280);
        assert_eq!(disk_capacity_mib(MIB + 1), 18, "a partial MiB rounds up");
        for bound in [1, MIB, 7 * MIB + 3, 900 * MIB] {
            assert!(disk_capacity_mib(bound) * MIB > bound);
        }
    }

    #[test]
    fn overlap_is_by_path_component_not_by_prefix() {
        assert!(guest_paths_overlap("/data/out", "/data/out"));
        assert!(guest_paths_overlap("/data", "/data/out"));
        assert!(guest_paths_overlap("/data/out/x", "/data/out"));
        assert!(!guest_paths_overlap("/data/out", "/data/output"));
        assert!(!guest_paths_overlap("/work/a", "/data/a"));
    }

    #[test]
    fn no_outputs_prepares_nothing() {
        let prepared = PreparedOutputs::prepare(&[], &["/h:/data".to_string()]).unwrap();
        assert!(prepared.grants().is_empty());
        assert!(prepared.volumes().is_empty());
        prepared.collect(None, true).expect("nothing to collect");
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
