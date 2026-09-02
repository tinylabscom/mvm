//! Steps for verified-boot contracts shared by the workload runner and its
//! concrete VMM drivers. These exercise pure assembly/mapping seams and never
//! start a VM, so they run in the normal hermetic BDD gate.

use cucumber::{given, then, when};
use mvm_core::kernel_format::KernelFormat;
use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::backends::hvf::HvfDriver;
use mvm_runtime::driver::{ConsoleCapture, KernelImage, LibkrunDriver, VmmDriver, VmmSpec};

use crate::world::{CliWorld, MvmHomeGuard};

/// Materialize the universal initramfs this sealed boot attaches, and return its path.
///
/// The universal initramfs lives in the shared initramfs cache; its PID 1 is
/// handed roothashes and device slots over vsock. A legacy per-rootfs initrd
/// is no longer supported, so this fixture only produces the universal path.
fn sealed_initramfs_path(_flavor: &str) -> String {
    let dir = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("initramfs");
    std::fs::create_dir_all(&dir).expect("create initramfs cache dir");
    let image = dir.join("initramfs.cpio.gz");
    std::fs::write(&image, b"initramfs").expect("write initramfs");
    image.display().to_string()
}

#[when(expr = "I assemble a sealed workload cmdline for {string} booting the {string} initramfs")]
fn assemble_sealed_cmdline(world: &mut CliWorld, backend: String, flavor: String) {
    let state = tempfile::tempdir().expect("create cmdline state dir");
    let home = tempfile::tempdir().expect("create scenario home");
    // The universal flavor is recognized by its path under the cache root, and
    // the grant tokens read this home too, so both need it pointed at a tempdir.
    let _home_guard = MvmHomeGuard::new(home.path());
    let config = VmStartConfig {
        name: format!("bdd-{backend}-sealed-boot"),
        rootfs_path: "/image/rootfs.ext4".to_string(),
        verity_path: Some("/image/rootfs.verity".to_string()),
        roothash: Some("a".repeat(64)),
        initrd_path: Some(sealed_initramfs_path(&flavor)),
        runtime_overlay_path: Some("/image/runtime.ext4".to_string()),
        runtime_overlay_verity_path: Some("/image/runtime.verity".to_string()),
        runtime_overlay_roothash: Some("b".repeat(64)),
        ..Default::default()
    };
    let driver: Box<dyn VmmDriver> = match backend.as_str() {
        "libkrun" => Box::new(LibkrunDriver::new()),
        "hvf" => Box::new(HvfDriver::new()),
        _ => panic!("unsupported verified-boot BDD backend {backend:?}"),
    };
    let blocks = mvm_vmm::host::spec_map::workload_blocks(&config);
    world.sealed_runtime_overlay_attached = Some(
        config
            .runtime_overlay_roothash
            .as_deref()
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            && ["/image/runtime.ext4", "/image/runtime.verity"]
                .iter()
                .all(|path| {
                    blocks
                        .iter()
                        .any(|block| block.source == std::path::Path::new(path) && block.read_only)
                }),
    );
    world.workload_cmdline = Some(
        mvm_runtime::workload_runner::assemble_workload_cmdline_for_test(
            driver.as_ref(),
            &config,
            state.path(),
        ),
    );
}

#[then("the sealed workload attaches the verified runtime overlay")]
fn sealed_workload_attaches_verified_runtime_overlay(world: &mut CliWorld) {
    assert_eq!(
        world.sealed_runtime_overlay_attached,
        Some(true),
        "the complete runtime-overlay triple must map both the data and verity devices read-only"
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
        builder_egress_endpoint: None,
        name: "bdd-libkrun-kernel-format".to_string(),
        kernel: KernelImage::Path(kernel.clone()),
        initramfs: None,
        cmdline: String::new(),
        vcpus: 1,
        cpu_grant: None,
        memory_mib: 128,
        mem_initial_mib: None,
        blocks: vec![],
        vsock: vec![],
        console: ConsoleCapture {
            log_path: state.path().join("console.log"),
        },
        shares: Vec::new(),
        trusted_builder: false,
        plan_binding: None,
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

// ---------------------------------------------------------------------------
// Sealed-rootfs tamper refusal (MVM-SEC-03)
// ---------------------------------------------------------------------------

/// Build a minimal deterministic ext4 rootfs containing `/sbin/init`.
///
/// The image is produced by the same pure-Rust writer the OCI materializer
/// uses, so the witness exercises the real content-addressed bytes that
/// dm-verity would seal.
fn build_minimal_rootfs() -> Vec<u8> {
    let nodes = vec![
        mvm_fs::ext4::Node::Dir {
            path: "/sbin".to_string(),
            mode: 0o755,
            xattrs: vec![],
        },
        mvm_fs::ext4::Node::File {
            path: "/sbin/init".to_string(),
            mode: 0o755,
            data: b"#!/bin/sh\nexec /bin/sh\n".to_vec(),
            xattrs: vec![],
        },
    ];
    mvm_fs::ext4::build_image(nodes).expect("build minimal ext4 rootfs")
}

fn verity_root_hash(image: &[u8]) -> String {
    let salt = [0u8; 32];
    let hash = mvm_fs::ext4::verity::root_hash(image, &salt, 4096, 4096);
    mvm_fs::ext4::verity::to_hex(&hash)
}

#[given("a sealed ext4 rootfs with /sbin/init")]
fn given_sealed_rootfs(world: &mut CliWorld) {
    world.sealed_rootfs = Some(build_minimal_rootfs());
}

#[given("the rootfs verity root hash is recorded")]
fn record_rootfs_roothash(world: &mut CliWorld) {
    let image = world
        .sealed_rootfs
        .as_ref()
        .expect("rootfs must be built first");
    world.sealed_rootfs_roothash = Some(verity_root_hash(image));
}

#[when("a single byte in the rootfs data area is flipped")]
fn flip_rootfs_byte(world: &mut CliWorld) {
    let image = world
        .sealed_rootfs
        .as_mut()
        .expect("rootfs must be built first");
    // Flip a byte well inside the image, past the superblock, so the
    // tamper is in the data blocks dm-verity covers.
    let offset = image.len() / 2;
    image[offset] ^= 0xFF;
}

#[then("the tampered rootfs does not match the recorded verity root hash")]
fn tampered_rootfs_hash_mismatch(world: &mut CliWorld) {
    let image = world
        .sealed_rootfs
        .as_ref()
        .expect("rootfs must be built first");
    let recorded = world
        .sealed_rootfs_roothash
        .as_ref()
        .expect("root hash must be recorded first");
    let new_hash = verity_root_hash(image);
    assert_ne!(
        &new_hash, recorded,
        "tampered rootfs must have a different dm-verity root hash"
    );
}
