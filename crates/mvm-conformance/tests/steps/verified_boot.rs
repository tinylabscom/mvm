//! Steps for verified-boot contracts shared by the workload runner and its
//! concrete VMM drivers. These exercise pure assembly/mapping seams and never
//! start a VM, so they run in the normal hermetic BDD gate.

use cucumber::{then, when};
use mvm_core::kernel_format::KernelFormat;
use mvm_core::vm_backend::{RuntimeSourcePolicy, VmStartConfig};
use mvm_runtime::driver::{
    ConsoleCapture, HvfDriver, KernelImage, LibkrunDriver, VmmDriver, VmmSpec,
};

use crate::world::CliWorld;

#[when(expr = "I assemble a sealed workload cmdline for {string}")]
fn assemble_sealed_cmdline(world: &mut CliWorld, backend: String) {
    let state = tempfile::tempdir().expect("create cmdline state dir");
    let config = VmStartConfig {
        name: format!("bdd-{backend}-sealed-boot"),
        rootfs_path: "/image/rootfs.ext4".to_string(),
        verity_path: Some("/image/rootfs.verity".to_string()),
        roothash: Some("a".repeat(64)),
        initrd_path: Some("/image/rootfs.initrd".to_string()),
        runtime_overlay_path: Some("/image/runtime.ext4".to_string()),
        runtime_overlay_verity_path: Some("/image/runtime.verity".to_string()),
        runtime_overlay_roothash: Some("b".repeat(64)),
        runtime_source_policy: RuntimeSourcePolicy::RequiredOverlay,
        ..Default::default()
    };
    let driver: Box<dyn VmmDriver> = match backend.as_str() {
        "libkrun" => Box::new(LibkrunDriver::new()),
        "hvf" => Box::new(HvfDriver::new()),
        _ => panic!("unsupported verified-boot BDD backend {backend:?}"),
    };
    world.workload_cmdline = Some(
        mvm_runtime::workload_runner::assemble_workload_cmdline_for_test(
            driver.as_ref(),
            &config,
            state.path(),
        ),
    );
}

#[then(expr = "the sealed workload cmdline contains {string}")]
fn sealed_cmdline_contains(world: &mut CliWorld, expected: String) {
    let cmdline = world
        .workload_cmdline
        .as_deref()
        .expect("a prior step must assemble the workload cmdline");
    assert!(
        cmdline.contains(&expected),
        "expected sealed workload cmdline to contain {expected:?}: {cmdline}"
    );
}

#[then(expr = "the sealed workload cmdline omits {string}")]
fn sealed_cmdline_omits(world: &mut CliWorld, unexpected: String) {
    let cmdline = world
        .workload_cmdline
        .as_deref()
        .expect("a prior step must assemble the workload cmdline");
    assert!(
        !cmdline.contains(&unexpected),
        "expected sealed workload cmdline to omit {unexpected:?}: {cmdline}"
    );
}

#[when("I map an existing ELF workload kernel through the libkrun driver")]
fn map_elf_kernel(world: &mut CliWorld) {
    let state = tempfile::tempdir().expect("create libkrun mapping state dir");
    let kernel = state.path().join("vmlinux");
    std::fs::write(&kernel, b"\x7fELFconformance-kernel").expect("write ELF kernel fixture");
    let spec = VmmSpec {
        name: "bdd-libkrun-kernel-format".to_string(),
        kernel: KernelImage::Path(kernel.clone()),
        initramfs: None,
        cmdline: String::new(),
        vcpus: 1,
        memory_mib: 128,
        mem_initial_mib: None,
        blocks: vec![],
        vsock: vec![],
        console: ConsoleCapture {
            log_path: state.path().join("console.log"),
        },
        trusted_builder: false,
    };
    let (mapped_path, format) =
        mvm_runtime::driver::libkrun::map_kernel_for_test(&spec, state.path())
            .expect("map libkrun kernel through supervisor config");
    assert_eq!(
        mapped_path.as_deref(),
        kernel.to_str(),
        "libkrun must preserve the mapped workload kernel path"
    );
    world.libkrun_kernel_format = Some(format);
}

#[then("the libkrun kernel format matches the current host architecture")]
fn kernel_format_matches_host(world: &mut CliWorld) {
    let format = world
        .libkrun_kernel_format
        .expect("a prior step must map the libkrun kernel");
    let expected = if cfg!(target_arch = "x86_64") {
        KernelFormat::Elf
    } else {
        KernelFormat::Raw
    };
    assert_eq!(format, expected);
}
