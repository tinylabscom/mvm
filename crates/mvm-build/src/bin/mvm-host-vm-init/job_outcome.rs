//! The single-shot job's outcome: the `/job/result` the builder job contract
//! defines, the failure category it carries, the build logs mirrored beside
//! it, and the refusal of a job directory staged under another contract.
//!
//! Linux-only, like the PID-1 flow in `linux` that drives it.

use std::path::Path;

use mvm_build::builder_job_contract::{
    CLASSIFY_WINDOW_BYTES, FailureCategory, NIX_STDERR_LOG, NIX_STDOUT_LOG, RESULT_FILE,
    check_job_dir, classify_job_failure,
};

use crate::linux::{JOB_DIR, OUT_DIR, append_init_breadcrumb};

/// Write `/job/result`, the job outcome the builder job contract
/// defines, and mirror it into `/out`. Rendered by hand rather than with
/// `serde_json`, which the init binary's size budget keeps out.
pub(crate) fn write_result(
    exit_code: i32,
    failure: Option<FailureCategory>,
    stderr_tail: &str,
    build_ms: Option<u64>,
) {
    let body =
        crate::dispatch_response::job_outcome_json(exit_code, failure, stderr_tail, build_ms);
    let path = format!("{JOB_DIR}/{RESULT_FILE}");
    if let Err(e) = std::fs::write(&path, &body) {
        eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
    }
    mirror_host_visible_out_artifact(RESULT_FILE, &body);
}

/// A job that could not start because the boot around it failed. Nothing
/// the job asked for ran, so the failure is the builder's, not the build's.
pub(crate) fn write_setup_failure(detail: &str) {
    write_result(2, Some(FailureCategory::Internal), detail, None);
}

/// Classify a failed single-shot job from the build log `cmd.sh`
/// redirected Nix's stderr into, falling back to the script's own tail.
pub(crate) fn classify_failed_job(script_tail: &str) -> FailureCategory {
    let log = mvm_build::builder_vm_runtime::read_last_bytes_of(
        Path::new(&format!("{JOB_DIR}/{NIX_STDERR_LOG}")),
        CLASSIFY_WINDOW_BYTES as u64,
    )
    .ok();
    classify_job_failure(log.as_deref(), script_tail)
}

/// Copy the build's stdout and stderr captures into `/out` beside the
/// result, so the host finds the logs where it finds the artifacts on every
/// transport. The disk transport copies them again when it tars `/out`;
/// a virtio-fs `/out` is the host's directory, and this is the only copy.
pub(crate) fn mirror_build_logs() {
    for name in [NIX_STDERR_LOG, NIX_STDOUT_LOG] {
        let src = format!("{JOB_DIR}/{name}");
        if Path::new(&src).is_file() && Path::new(OUT_DIR).is_dir() {
            let _ = std::fs::copy(&src, format!("{OUT_DIR}/{name}"));
        }
    }
}

/// Refuse to run a job directory staged under a job contract this init
/// does not speak. Returns the refusal, logged and breadcrumbed, for the
/// caller to report as the job's outcome; `None` when the directory may run.
pub(crate) fn refuse_unless_contract(job_dir: &str) -> Option<String> {
    let refusal = check_job_dir(Path::new(job_dir)).err()?.to_string();
    append_init_breadcrumb("job_contract_refused", &refusal);
    eprintln!("mvm-host-vm-init: refusing {job_dir}: {refusal}");
    Some(refusal)
}

pub(crate) fn mirror_artifact_into_dir(dir: &Path, file_name: &str, body: &str) {
    if !dir.is_dir() {
        return;
    }
    let path = dir.join(file_name);
    if let Err(e) = std::fs::write(&path, body) {
        eprintln!(
            "mvm-host-vm-init: failed to mirror {} into {}: {e}",
            file_name,
            path.display()
        );
    }
}

pub(crate) fn mirror_host_visible_out_artifact(file_name: &str, body: &str) {
    mirror_artifact_into_dir(Path::new(OUT_DIR), file_name, body);
}
