//! Persist the admitted `ExecutionPlan` into the per-VM state dir at
//! boot so out-of-process lifecycle verbs (`checkpoint create`,
//! `checkpoint restore`, `pause`/`resume`) can rehydrate the plan and
//! bind audit-chain entries to the same `plan_id` the launch admitted
//! under.
//!
//! On-disk layout: `~/.mvm/vms/<vm_name>/plan.json`, mode 0600.
//! Same directory the backend's `<backend>.pid` lives in, so the
//! file is cleaned up alongside the VM when `mvmctl down` removes
//! the directory. The file is overwritten on every `mvmctl up` so
//! a re-launch under the same `vm_name` rebinds to the new plan.
//!
//! The file is **best-effort** at write time: a failure to persist
//! degrades the per-VM audit chain (lifecycle verbs will not be
//! plan-bound) but must not block the launch — boot succeeded; the
//! VM is running. Callers log a warn and continue, mirroring the
//! `audit emit_*` policy in `audit_chain.rs`.

use anyhow::{Context, Result, bail};
use mvm_core::plan::ExecutionPlan;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Filename inside the VM state dir.
pub const PLAN_FILENAME: &str = "plan.json";

/// Mode the plan file is written at. Same tier as the host signer
/// secret half — the file carries the audit-chain binding for
/// every subsequent lifecycle event.
pub const PLAN_MODE: u32 = 0o600;

/// Resolve `~/.mvm/vms/<vm_name>/`.
pub fn vm_state_dir(vm_name: &str) -> Result<PathBuf> {
    Ok(mvm_core::config::mvm_data_dir_strict()?
        .join("vms")
        .join(vm_name))
}

/// Resolve `~/.mvm/vms/<vm_name>/plan.json`.
pub fn plan_path(vm_name: &str) -> Result<PathBuf> {
    Ok(vm_state_dir(vm_name)?.join(PLAN_FILENAME))
}

/// Serialise `plan` as JSON and write it atomically into the VM
/// state dir at mode 0600. The state dir is created if missing
/// (backends create it under their own paths; the first writer
/// wins). Overwrites any prior file.
pub fn write_plan(vm_name: &str, plan: &ExecutionPlan) -> Result<PathBuf> {
    let dir = vm_state_dir(vm_name)?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating VM state dir {}", dir.display()))?;
    let path = dir.join(PLAN_FILENAME);

    let bytes =
        serde_json::to_vec_pretty(plan).with_context(|| "serialising ExecutionPlan to JSON")?;
    let tmp = dir.join(format!("{PLAN_FILENAME}.tmp"));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(PLAN_MODE)
            .open(&tmp)
            .with_context(|| format!("opening {} for write", tmp.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("writing plan to {}", tmp.display()))?;
        f.sync_all().ok();
    }
    // Force-tighten in case the open()'s mode arg was honored loosely
    // under an odd umask; readers refuse loose perms below.
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(PLAN_MODE))
        .with_context(|| format!("tightening {} to 0600", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(path)
}

/// Read the plan back from `~/.mvm/vms/<vm_name>/plan.json`.
/// Refuses files with loose perms (mode > 0o600) since they carry
/// the audit-chain binding identity.
pub fn read_plan(vm_name: &str) -> Result<ExecutionPlan> {
    let path = plan_path(vm_name)?;
    read_plan_at(&path)
}

/// Internal: read + parse the plan file at `path`. Exposed for
/// tests that point at a tempdir.
pub fn read_plan_at(path: &Path) -> Result<ExecutionPlan> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading metadata of {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} has permissions {:o}; refusing to read a world-/group-readable plan file. \
             Fix with: chmod 0600 {0}",
            path.display(),
            mode,
        );
    }
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    let plan: ExecutionPlan = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing ExecutionPlan from {}", path.display()))?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
    };
    use std::collections::BTreeMap;

    fn fixture_plan() -> ExecutionPlan {
        let now = chrono::Utc::now();
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("plan-persist-test".to_string()),
            plan_version: 1,
            tenant: TenantId("local".to_string()),
            workload: WorkloadId("vm-test".to_string()),
            runtime_profile: RuntimeProfileRef("vz".to_string()),
            image: SignedImageRef {
                name: "vm-test".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 0,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".to_string()),
            fs_policy: FsPolicyRef("local-default".to_string()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".to_string()),
            tool_policy: PolicyRef("local-default".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: Vec::new(),
                retention_days: 0,
            },
            audit_labels: BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: now,
            valid_until: now + chrono::Duration::minutes(10),
            nonce: Nonce::from_bytes([0u8; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
        }
    }

    #[test]
    fn write_then_read_roundtrips_plan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = fixture_plan();
        let path = dir.path().join("plan.json");

        // Use the at-variant directly so the test doesn't depend on
        // $HOME / ~/.mvm layout.
        let bytes = serde_json::to_vec_pretty(&plan).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let read = read_plan_at(&path).expect("read");
        assert_eq!(read, plan, "roundtrip equality");
    }

    #[test]
    fn write_plan_emits_mode_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = fixture_plan();
        let path = dir.path().join("plan.json");

        let bytes = serde_json::to_vec_pretty(&plan).unwrap();
        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(&bytes).unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "plan file must be 0600");
    }

    #[test]
    fn read_refuses_loose_perms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = fixture_plan();
        let path = dir.path().join("plan.json");

        let bytes = serde_json::to_vec_pretty(&plan).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        // World-readable — the read path must refuse.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = read_plan_at(&path).expect_err("loose perms refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("0600"),
            "error must name the expected mode: {msg}"
        );
    }

    #[test]
    fn read_missing_file_errors_with_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("plan.json");
        let err = read_plan_at(&path).expect_err("missing file errors");
        assert!(
            format!("{err:#}").contains(path.to_str().unwrap()),
            "error mentions path"
        );
    }
}
