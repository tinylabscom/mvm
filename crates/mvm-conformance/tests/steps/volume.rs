//! Volume lifecycle, admission, backend-capability, and live guest witnesses.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cucumber::{given, then, when};
use mvm_build::guest_agent_build::{
    GuestBinarySource, GuestRuntimeBinaryPaths, RuntimeOverlayGuestLayout, guest_binary_source,
    install_into_cache, runtime_overlay_source_checkout_fingerprint,
};
use mvm_build::verity_initrd::install_verity_initrd_from_binary;
use mvm_core::arch::GuestArch;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
use mvm_runtime::vm::volume_registry::LocalVolumeCatalog;

use crate::world::CliWorld;

use super::cli::{mvmctl_command, workspace_root};
use mvm_conformance::IsolatedHome;

fn isolated_home(world: &CliWorld) -> &Path {
    world
        .isolated_home
        .as_ref()
        .expect("an isolated mvm home must be created first")
        .path()
}

fn managed_volume_path(world: &CliWorld, volume_name: &str) -> PathBuf {
    let mut guard = mvm_core::util::test_env::TestEnv::new();
    guard.set("MVM_HOME", isolated_home(world));
    PathBuf::from(
        LocalVolumeCatalog::load()
            .expect("load managed volume catalog")
            .get(volume_name)
            .unwrap_or_else(|| panic!("managed volume {volume_name:?} must exist"))
            .host_path
            .clone(),
    )
}

#[given("a cached live workload kernel")]
fn cached_live_workload_kernel(world: &mut CliWorld) {
    // The `@workload_kernel` gate guarantees this resolves before the scenario
    // is selected, so reaching here without one is a harness bug, not an
    // operator mistake.
    let source = crate::workload_kernel_path()
        .expect("`@workload_kernel` scenarios only run when a kernel resolves");
    let destination = isolated_home(world)
        .join("cache")
        .join("builder-vm")
        .join(std::env::consts::ARCH)
        .join("kernels")
        .join("workload")
        .join("vmlinux");
    fs::create_dir_all(
        destination
            .parent()
            .expect("workload kernel cache path has a parent"),
    )
    .expect("create isolated workload kernel cache");
    fs::copy(&source, &destination).unwrap_or_else(|error| {
        panic!("copy live workload kernel {source:?} to {destination:?}: {error}")
    });
    cache_live_guest_binaries(world);
}

fn cache_live_guest_binaries(world: &CliWorld) {
    let source_dir = PathBuf::from(
        std::env::var_os("MVM_BDD_GUEST_BIN_DIR")
            .expect("MVM_BDD_GUEST_BIN_DIR must name the prebuilt guest-runtime directory"),
    );
    assert!(
        source_dir.is_dir(),
        "MVM_BDD_GUEST_BIN_DIR does not name a directory: {source_dir:?}"
    );
    let source = guest_binary_source().expect("resolve guest-runtime cache generation");
    install_into_cache(
        GuestRuntimeBinaryPaths {
            agent: &source_dir.join("mvm-guest-agent"),
            netinit: &source_dir.join("mvm-guest-netinit"),
            egress_client: &source_dir.join("mvm-egress-client"),
            entrypoint_runner: &source_dir.join("mvm-oci-entrypoint"),
            verity_init: &source_dir.join("mvm-verity-init"),
        },
        &isolated_home(world).join("cache").join("oci"),
        source.cache_key(),
        GuestArch::host(),
    )
    .expect("seed isolated guest-runtime cache from prebuilt binaries");
    if let GuestBinarySource::SourceCheckout { workspace_root, .. } = source {
        let fingerprint = runtime_overlay_source_checkout_fingerprint(&workspace_root)
            .expect("fingerprint local runtime-overlay sources");
        install_verity_initrd_from_binary(
            &source_dir.join("mvm-verity-init"),
            &isolated_home(world).join("cache"),
            env!("CARGO_PKG_VERSION"),
            GuestArch::host(),
            Some(&fingerprint),
        )
        .expect("seed isolated verity initrd cache from the prebuilt runtime");
        cache_live_runtime_overlay(world, &source_dir, &fingerprint);
    }
}

fn cache_live_runtime_overlay(world: &CliWorld, source_dir: &Path, fingerprint: &str) {
    let layout = RuntimeOverlayGuestLayout::under(
        &isolated_home(world).join("cache"),
        env!("CARGO_PKG_VERSION"),
        GuestArch::host(),
        fingerprint,
    );
    fs::create_dir_all(&layout.dir).expect("create isolated runtime-overlay cache");
    for (source_name, destination) in [
        ("mvm-guest-agent", &layout.agent),
        ("mvm-guest-netinit", &layout.netinit),
        ("mvm-seccomp-apply", &layout.seccomp_apply),
        ("mvm-verity-init", &layout.verity_init),
        ("mvm-runner", &layout.runner),
        ("mvm-egress-client", &layout.egress_client),
        ("mvm-addon-dns", &layout.addon_dns),
        ("mvm-exit-report", &layout.exit_report),
        ("mvm-ping", &layout.ping),
        ("mvm-forward-proxy", &layout.forward_proxy),
    ] {
        let source = source_dir.join(source_name);
        fs::copy(&source, destination).unwrap_or_else(|error| {
            panic!("copy runtime-overlay binary {source:?} to {destination:?}: {error}")
        });
    }
}

#[when(expr = "I write byte {int} to the end of managed volume {string}")]
fn write_managed_volume_marker(world: &mut CliWorld, value: i64, volume_name: String) {
    let value = u8::try_from(value).expect("volume marker must fit in one byte");
    let path = managed_volume_path(world, &volume_name);
    let mut image = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("open materialized volume {path:?}: {error}"));
    image.seek(SeekFrom::End(-1)).expect("seek volume marker");
    image.write_all(&[value]).expect("write volume marker");
    image.sync_all().expect("sync volume marker");
}

#[then(expr = "managed volume {string} ends with byte {int}")]
fn managed_volume_has_marker(world: &mut CliWorld, volume_name: String, value: i64) {
    let expected = u8::try_from(value).expect("volume marker must fit in one byte");
    let path = managed_volume_path(world, &volume_name);
    let mut image = fs::File::open(&path)
        .unwrap_or_else(|error| panic!("open materialized volume {path:?}: {error}"));
    image.seek(SeekFrom::End(-1)).expect("seek volume marker");
    let mut actual = [0u8; 1];
    image.read_exact(&mut actual).expect("read volume marker");
    assert_eq!(actual[0], expected);
}

#[given("a signed execution plan with no admitted volume shares")]
fn plan_without_volume_shares(world: &mut CliWorld) {
    let plan = PlanFixture::new().build();
    let volume = VmVolume {
        host: "/private/unadmitted.ext4".to_string(),
        guest: "/data".to_string(),
        read_only: true,
        kind: VmVolumeKind::Disk,
        ..Default::default()
    };
    world.volume_admission_result = Some(
        mvm_hostd::plan_admission::enforce_admitted_shares(&[volume], &plan)
            .map_err(|error| error.to_string()),
    );
}

#[then("the unadmitted volume attachment is refused")]
fn unadmitted_volume_is_refused(world: &mut CliWorld) {
    let error = world
        .volume_admission_result
        .as_ref()
        .expect("the admission gate must run")
        .as_ref()
        .expect_err("an unadmitted volume must be refused");
    assert!(
        error.contains("not named in the signed ExecutionPlan"),
        "unexpected refusal: {error}"
    );
}

#[when("I run remote volume catalog without gateway configuration")]
fn remote_volume_catalog_without_configuration(world: &mut CliWorld) {
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["machine", "volume", "catalog", "--remote"])
        .env_remove("MVM_GATEWAY_URL")
        .env_remove("MVM_GATEWAY_TOKEN")
        .env_remove("MVM_TENANT_ID")
        .output()
        .expect("run remote volume catalog without gateway configuration");
    world.last_run = Some(output);
}

#[when(expr = "I execute shell command {string} in machine {string}")]
fn execute_machine_shell(world: &mut CliWorld, script: String, machine: String) {
    let home = isolated_home(world);
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["machine", "exec", &machine, "--", "/bin/sh", "-c", &script])
        .isolated_home(home)
        .output()
        .expect("execute command in live volume machine");
    world.last_run = Some(output);
}

#[when(expr = "I attempt a direct start of machine {string} with backend {string}")]
fn attempt_direct_start(world: &mut CliWorld, machine: String, backend: String) {
    let home = isolated_home(world);
    let fixture_dir = home.join("direct-boot-fixture");
    fs::create_dir_all(&fixture_dir).expect("create direct-boot fixture directory");
    let kernel = fixture_dir.join("vmlinux");
    let rootfs = fixture_dir.join("rootfs.ext4");
    fs::write(&kernel, b"not-a-kernel").expect("write direct-boot kernel fixture");
    fs::write(&rootfs, b"not-a-rootfs").expect("write direct-boot rootfs fixture");
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(["machine", "start", &machine, "--hypervisor", &backend])
        .isolated_home(home)
        .env("MVM_DIRECT_BOOT", "1")
        .env("MVM_KERNEL_PATH", &kernel)
        .env("MVM_ROOTFS_PATH", &rootfs)
        .output()
        .expect("attempt direct machine start");
    world.last_run = Some(output);
}

#[then("the local volume attachment lease catalog is empty")]
fn attachment_lease_catalog_is_empty(world: &mut CliWorld) {
    let path = isolated_home(world)
        .join("volumes")
        .join("attachments.json");
    if !path.exists() {
        return;
    }
    let value: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("read {path:?}: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse {path:?}: {error}"));
    let leases = value
        .get("leases")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("lease catalog {path:?} has no leases object"));
    assert!(leases.is_empty(), "failed start leaked leases: {leases:?}");
}
