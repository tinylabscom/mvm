use super::bootstrap;
use mvm_client::builder_images::capabilities::{
    assert_workload_kernel_supports_verity, workload_config_carries_dm_verity,
};
use mvm_client::builder_images::default_microvm::evict_incompatible_workload_kernel;

#[test]
fn workload_config_is_the_capability_witness() {
    let supported = "CONFIG_MD=y\nCONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n";
    assert_eq!(workload_config_carries_dm_verity(supported), Some(true));
    let builder = "# CONFIG_MD is not set\n# CONFIG_BLK_DEV_DM is not set\n";
    assert_eq!(workload_config_carries_dm_verity(builder), Some(false));
    assert_eq!(workload_config_carries_dm_verity(""), None);
    assert_eq!(
        workload_config_carries_dm_verity("not a kernel config"),
        None
    );
}

#[test]
fn assert_workload_kernel_supports_verity_rejects_an_explicit_non_verity_config() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("vmlinux");
    std::fs::write(&bad, b"valid raw ARM64 Image without KALLSYMS strings").unwrap();
    std::fs::write(
        tmp.path().join("config"),
        "# CONFIG_BLK_DEV_DM is not set\n",
    )
    .unwrap();
    let err = assert_workload_kernel_supports_verity(bad.to_str().unwrap()).unwrap_err();
    assert!(
        err.to_string().contains("CONFIG_DM_VERITY=y"),
        "unexpected error: {err}"
    );
}

#[test]
fn assert_workload_kernel_supports_verity_accepts_kallsyms_free_image_with_valid_config() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = tmp.path().join("vmlinux");
    std::fs::write(&kernel, b"raw ARM64 Image with no searchable dm symbols").unwrap();
    std::fs::write(
        tmp.path().join("config"),
        "CONFIG_MD=y\nCONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n",
    )
    .unwrap();
    assert_workload_kernel_supports_verity(kernel.to_str().unwrap()).unwrap();
}

#[test]
fn assert_workload_kernel_supports_verity_accepts_raw_image_without_optional_local_config() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = tmp.path().join("vmlinux");
    std::fs::write(
        &kernel,
        b"published raw ARM64 Image with no KALLSYMS strings",
    )
    .unwrap();
    assert_workload_kernel_supports_verity(kernel.to_str().unwrap()).unwrap();
}

#[test]
fn incompatible_cached_kernel_is_fully_evicted_for_automatic_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = mvm_build::kernel_fetch::cached_kernel_path(tmp.path(), "aarch64", "workload");
    std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
    std::fs::write(&kernel, b"builder kernel in workload slot").unwrap();
    std::fs::write(
        kernel.with_file_name("config"),
        "# CONFIG_BLK_DEV_DM is not set\n# CONFIG_DM_VERITY is not set\n",
    )
    .unwrap();
    mvm_build::kernel_fetch::record_kernel_digest(&kernel).unwrap();
    assert!(
        assert_workload_kernel_supports_verity(kernel.to_str().unwrap()).is_err(),
        "the explicit non-verity config must be rejected"
    );
    evict_incompatible_workload_kernel(&kernel).unwrap();
    assert!(!kernel.exists());
    assert!(!mvm_build::kernel_fetch::kernel_digest_sidecar(&kernel).exists());
    assert!(!kernel.with_file_name("config").exists());
    assert!(matches!(
        mvm_build::kernel_fetch::resolve_kernel(tmp.path(), "aarch64", "workload", true),
        mvm_build::kernel_fetch::KernelResolution::NeedsBuild(_)
    ));
}

#[test]
fn first_nameserver_from_resolv_conf_ignores_comments_and_invalid_lines() {
    let body = "\
# comment
search example.internal
nameserver invalid
nameserver 10.0.0.2
nameserver 10.0.0.3
";
    assert_eq!(
        bootstrap::first_nameserver_from_resolv_conf(body).as_deref(),
        Some("10.0.0.2")
    );
}

#[test]
fn first_nameserver_from_resolv_conf_none_when_absent() {
    let body = "search example.internal\noptions timeout:1\n";
    assert_eq!(bootstrap::first_nameserver_from_resolv_conf(body), None);
}
