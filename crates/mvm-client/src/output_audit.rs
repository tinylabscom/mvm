//! Grant-backed file outputs for transient runs.
//!
//! The admitted plan owns destinations, bounds and protected paths. Scratch
//! images live until this handle is dropped, including on refusal or failure.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::plan::OutputGrant;
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
use mvm_hostd::audit::output_audit::{OutputOutcome, OutputRecord};

use crate::admission::AdmissionContext;

mod destination;
pub use destination::{protected_host_roots, resolve_output_destination};

const MIB: u64 = 1024 * 1024;

fn disk_capacity_mib(max_bytes: u64) -> u64 {
    let bound = max_bytes.div_ceil(MIB);
    bound + (bound / 4).max(16)
}

fn guest_paths_overlap(a: &str, b: &str) -> bool {
    Path::new(a).starts_with(b) || Path::new(b).starts_with(a)
}

struct PreparedOutput {
    grant: OutputGrant,
    image: PathBuf,
}

/// A successfully collected and audited output, ready for presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedOutput {
    pub guest_path: String,
    pub destination: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
    pub entry_count: u64,
    pub total_bytes: u64,
}

/// Owns one transient run's output images and their cleanup.
pub struct PreparedOutputs {
    outputs: Vec<PreparedOutput>,
    _scratch: Option<tempfile::TempDir>,
}

impl PreparedOutputs {
    /// Validate grants and host destinations before allocating private scratch.
    pub fn prepare(mut grants: Vec<OutputGrant>, mount_guests: &[String]) -> Result<Self> {
        for (index, grant) in grants.iter().enumerate() {
            for (label, path) in [("guest", &grant.guest_path), ("host", &grant.host_path)] {
                let path = Path::new(path);
                if !path.is_absolute()
                    || path.file_name().is_none()
                    || path
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                {
                    anyhow::bail!(
                        "output {label} path must name an absolute directory without '..'"
                    );
                }
            }
            if grant.max_bytes == 0 || grant.max_entries == 0 {
                anyhow::bail!("output bounds must be positive");
            }
            if let Some(mount) = mount_guests
                .iter()
                .find(|mount| guest_paths_overlap(mount, &grant.guest_path))
            {
                anyhow::bail!(
                    "output at {} overlaps the --mount at {mount}; an output needs a guest directory of its own",
                    grant.guest_path
                );
            }
            for earlier in &grants[..index] {
                if guest_paths_overlap(&earlier.guest_path, &grant.guest_path) {
                    anyhow::bail!(
                        "output at {} overlaps the output at {}",
                        grant.guest_path,
                        earlier.guest_path
                    );
                }
                if earlier.host_path == grant.host_path {
                    anyhow::bail!("output collects into {} twice", grant.host_path);
                }
            }
        }
        for index in 0..grants.len() {
            grants[index].host_path = resolve_output_destination(&grants[index].host_path)?
                .to_string_lossy()
                .into_owned();
            if grants[..index]
                .iter()
                .any(|earlier| earlier.host_path == grants[index].host_path)
            {
                anyhow::bail!("output collects into {} twice", grants[index].host_path);
            }
        }
        if grants.is_empty() {
            return Ok(Self {
                outputs: Vec::new(),
                _scratch: None,
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
    pub fn grants(&self) -> Vec<OutputGrant> {
        self.outputs.iter().map(|o| o.grant.clone()).collect()
    }

    /// Writable disks attached through the normal launch volume path.
    pub fn volumes(&self) -> Vec<VmVolume> {
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

    /// Record the run outcome and collect flushed images. The run's failure
    /// takes precedence over collection errors; a completed workload with a
    /// nonzero exit code still has useful outputs.
    pub fn close_run<T>(
        &self,
        admitted: &RefCell<Option<AdmissionContext>>,
        backend: &str,
        posture: crate::admission::BootPosture,
        result: Result<T>,
        observer: &mut dyn FnMut(CollectedOutput),
    ) -> Result<T> {
        let admitted = admitted.borrow_mut().take();
        if let Err(error) = self.validate_binding(admitted.as_ref()) {
            result?;
            return Err(error);
        }
        crate::admission::record_transient_outcome(admitted.as_ref(), backend, posture, &result);
        let collected = self.collect(admitted.as_ref(), result.is_ok(), observer);
        let value = result?;
        collected?;
        Ok(value)
    }

    fn validate_binding(&self, admitted: Option<&AdmissionContext>) -> Result<()> {
        if self.outputs.is_empty() {
            return Ok(());
        }
        let admitted = admitted.context(
            "outputs were not collected: the run has no admitted plan to record them against",
        )?;
        for output in &self.outputs {
            let grant = admitted
                .admitted
                .plan()
                .outputs
                .iter()
                .find(|grant| grant.guest_path == output.grant.guest_path)
                .with_context(|| {
                    format!(
                        "the admitted plan carries no output grant for {}",
                        output.grant.guest_path
                    )
                })?;
            anyhow::ensure!(
                grant.host_path == output.grant.host_path,
                "the admitted output destination does not match the prepared output at {}",
                output.grant.guest_path
            );
        }
        // Disk bytes are mutable run results, not identity. Bind every scratch
        // image to the signed host path, guest path, kind and access flags.
        crate::admission::enforce_shares(admitted, &self.volumes())?;
        for output in &self.outputs {
            destination::validate_protected_destination(Path::new(&output.grant.host_path))?;
        }
        Ok(())
    }

    fn collect(
        &self,
        admitted: Option<&AdmissionContext>,
        run_completed: bool,
        observer: &mut dyn FnMut(CollectedOutput),
    ) -> Result<()> {
        self.validate_binding(admitted)?;
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
                    observer(CollectedOutput {
                        guest_path: guest_path.to_owned(),
                        destination,
                        manifest_path: collected.manifest_path,
                        manifest_sha256: manifest.digest.clone(),
                        entry_count: manifest.entry_count,
                        total_bytes: manifest.total_bytes,
                    });
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
mod security_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(guest: &str, host: &str) -> OutputGrant {
        OutputGrant {
            guest_path: guest.into(),
            host_path: host.into(),
            max_bytes: MIB,
            max_entries: 10,
        }
    }

    #[test]
    fn overlapping_outputs_and_duplicate_destinations_are_refused_before_scratch() {
        for grants in [
            vec![grant("/out", "/a"), grant("/out/nested", "/b")],
            vec![grant("/out", "/a"), grant("/other", "/a")],
        ] {
            assert!(PreparedOutputs::prepare(grants, &[]).is_err());
        }
        assert!(PreparedOutputs::prepare(vec![grant("/out", "/a")], &["/out/x".into()]).is_err());
    }

    #[test]
    fn scratch_is_private_and_removed_on_drop() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let prepared = PreparedOutputs::prepare(vec![grant("/out", "/a")], &[]).unwrap();
        let image = prepared.outputs[0].image.clone();
        let scratch = image.parent().unwrap().to_owned();
        assert!(scratch.is_dir());
        let volumes = prepared.volumes();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].guest, "/out");
        assert!(!volumes[0].read_only);
        assert_eq!(volumes[0].size, "17M");
        std::fs::write(image, b"scratch").unwrap();
        drop(prepared);
        assert!(!scratch.exists());
    }

    #[test]
    fn invalid_grants_do_not_create_scratch_state() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut zero_bytes = grant("/out", "/a");
        zero_bytes.max_bytes = 0;
        let mut zero_entries = grant("/out", "/a");
        zero_entries.max_entries = 0;
        for invalid in [
            grant("relative", "/a"),
            grant("/out", "relative"),
            grant("/out/../other", "/a"),
            grant("/out", "/"),
            zero_bytes,
            zero_entries,
        ] {
            assert!(PreparedOutputs::prepare(vec![invalid], &[]).is_err());
        }
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_prepared_output_cannot_supply_its_own_authority() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let ctx = crate::admission::admit_plan_tests::admitted_into(
            &home.path().join("keys"),
            &home.path().join("audit"),
            "output-no-grant",
        );
        let prepared = PreparedOutputs {
            outputs: vec![PreparedOutput {
                grant: grant("/out", "/a"),
                image: "/unread.img".into(),
            }],
            _scratch: None,
        };
        let error = prepared
            .collect(Some(&ctx), true, &mut |_| panic!("no authority"))
            .unwrap_err();
        assert!(error.to_string().contains("no output grant"));
    }

    #[test]
    fn run_error_precedes_collection_error_and_completed_status_is_preserved() {
        let prepared = PreparedOutputs {
            outputs: vec![PreparedOutput {
                grant: grant("/out", "/a"),
                image: "/unread.img".into(),
            }],
            _scratch: None,
        };
        let error = prepared
            .close_run::<()>(
                &RefCell::new(None),
                "test",
                crate::admission::BootPosture::block(),
                Err(anyhow::anyhow!("original run failure")),
                &mut |_| panic!("not collected"),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "original run failure");
        let empty = PreparedOutputs::prepare(Vec::new(), &[]).unwrap();
        let exit = empty
            .close_run(
                &RefCell::new(None),
                "test",
                crate::admission::BootPosture::block(),
                Ok(7),
                &mut |_| panic!("no output"),
            )
            .unwrap();
        assert_eq!(exit, 7);
    }

    #[test]
    fn disk_capacity_leaves_room_past_the_bound() {
        assert_eq!(disk_capacity_mib(MIB), 17);
        assert_eq!(disk_capacity_mib(64 * MIB), 80);
        assert_eq!(disk_capacity_mib(1024 * MIB), 1280);
        assert_eq!(disk_capacity_mib(MIB + 1), 18);
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
        let prepared = PreparedOutputs::prepare(Vec::new(), &[]).unwrap();
        assert!(prepared.grants().is_empty());
        assert!(prepared.volumes().is_empty());
        prepared
            .collect(None, true, &mut |_| panic!("no output"))
            .unwrap();
    }

    #[test]
    fn missing_admission_never_reads_an_image() {
        let prepared = PreparedOutputs {
            outputs: vec![PreparedOutput {
                grant: OutputGrant {
                    guest_path: "/out".into(),
                    host_path: "/unread".into(),
                    max_bytes: 1,
                    max_entries: 1,
                },
                image: "/unread.img".into(),
            }],
            _scratch: None,
        };
        let error = prepared
            .collect(None, true, &mut |_| panic!("not collected"))
            .unwrap_err();
        assert!(error.to_string().contains("no admitted plan"));
    }
}
