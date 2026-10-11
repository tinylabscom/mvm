use super::*;

#[test]
fn no_default_microvm_kernel_is_ever_reused_as_the_workload_kernel() {
    for variant in ["dev", "prod"] {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp
            .path()
            .join(format!("default-microvm/{variant}/vmlinux"));
        std::fs::create_dir_all(kernel.parent().unwrap()).unwrap();
        std::fs::write(&kernel, b"default-kernel").unwrap();
        let resolved =
            mvm_build::kernel_fetch::resolve_kernel(tmp.path(), "x86_64", "workload", true);
        assert!(
            matches!(
                resolved,
                mvm_build::kernel_fetch::KernelResolution::NeedsBuild(_)
            ),
            "the {variant} default-microvm kernel must not stand in for the workload kernel"
        );
    }
}

#[test]
fn source_checkout_and_installed_binary_default_to_download() {
    assert_eq!(default_workload_kernel_source(true), KernelSource::Download);
    assert_eq!(
        default_workload_kernel_source(false),
        KernelSource::Download
    );
}

#[test]
fn official_release_defaults_to_download_even_inside_a_checkout() {
    assert_eq!(
        default_workload_kernel_source_for(
            mvm_build::artifact_acquisition::DistributionChannel::Release,
            true,
        ),
        KernelSource::Download
    );
}

#[test]
fn missing_workload_kernel_message_explains_automatic_and_manual_paths() {
    let msg = missing_workload_kernel_message("/cache/kernels/aarch64/workload/vmlinux");
    assert!(msg.contains("mvmctl kernel build --which workload"));
    assert!(msg.contains("just kernel::workload"));
    assert!(msg.contains("dm-verity-capable workload kernel"));
}

#[test]
fn prod_variant_targets_release_default_attr_with_verity_outputs() {
    assert_eq!(DefaultMicrovmVariant::Prod.attr(), "default");
    let prod = DefaultMicrovmVariant::Prod.required_outputs();
    for f in [
        "vmlinux",
        "rootfs.ext4",
        "mvm-meta.json",
        "rootfs.verity",
        "rootfs.roothash",
    ] {
        assert!(prod.contains(&f), "prod must emit {f}");
    }
}

#[test]
fn dev_variant_targets_dev_attr_without_verity() {
    assert_eq!(DefaultMicrovmVariant::Dev.attr(), "dev");
    let dev = DefaultMicrovmVariant::Dev.required_outputs();
    assert!(dev.contains(&"mvm-meta.json"));
    assert!(
        !dev.contains(&"rootfs.verity") && !dev.contains(&"rootfs.roothash"),
        "dev is accessible/unsealed — no verity sidecars",
    );
}
