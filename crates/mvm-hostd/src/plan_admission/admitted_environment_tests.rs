#![cfg(test)]

use super::admitted_environment::enforce_admitted_environment;
use mvm_core::plan::ExecutionPlan;

fn plan_pinning(kernel_sha256: Option<&str>) -> ExecutionPlan {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.environment = kernel_sha256.map(|k| mvm_core::plan::EnvironmentRef {
        kernel_sha256: k.to_string(),
    });
    plan
}

fn write_kernel(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join("vmlinux");
    std::fs::write(&p, bytes).expect("write kernel fixture");
    p
}

/// The pinned kernel is the one on disk: the boot proceeds.
#[test]
fn matching_kernel_digest_is_admitted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernel = write_kernel(tmp.path(), b"workload-kernel");
    let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
    enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(Some(&sha)))
        .expect("matching kernel must be admitted");
}

/// A different kernel than the plan pinned is refused: same plan, same
/// image, a kernel swapped underneath — a substitution that would be
/// invisible if nothing in the plan described the environment.
#[test]
fn substituted_kernel_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernel = write_kernel(tmp.path(), b"workload-kernel");
    let sha = mvm_core::crypto::image_verify::sha256_file(&kernel).expect("hash");
    std::fs::write(&kernel, b"a-general-purpose-kernel").expect("swap kernel");

    let err = enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(Some(&sha)))
        .expect_err("a substituted kernel must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("admitted-environment mismatch"),
        "error must name the mismatch, got: {msg}"
    );
}

/// Dropping the kernel path must not be a way around the pin.
#[test]
fn pinned_plan_with_no_kernel_path_is_refused() {
    let err = enforce_admitted_environment(None, &plan_pinning(Some(&"a".repeat(64))))
        .expect_err("a pinned plan with no kernel path must be refused");
    assert!(format!("{err:#}").contains("supplies no kernel path"));
}

/// Plans that pin nothing still boot — every plan written before the field
/// existed, and backends that carry their own bundled kernel.
#[test]
fn unpinned_plan_is_unaffected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kernel = write_kernel(tmp.path(), b"whatever");
    enforce_admitted_environment(Some(kernel.as_path()), &plan_pinning(None))
        .expect("an unpinned plan must be unaffected");
    enforce_admitted_environment(None, &plan_pinning(None))
        .expect("an unpinned plan with no kernel must be unaffected");
}
