//! Steps for the optional SDK-sidecar attachment workflow.
//!
//! These drive the real decision, resolution, attachment-shape, admission-gate,
//! and cmdline-assembly seams — no VM starts, so they run in the hermetic BDD
//! gate. The sidecar cache is staged in a per-scenario tempdir so a developer's
//! populated cache can never make a scenario pass for the wrong reason.

use cucumber::{given, then, when};
use mvm_build::guest_libc::GuestLibc;
use mvm_contract::protocol::broker::ServiceId;
use mvm_core::arch::GuestArch;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::vm_backend::{VmStartConfig, VmVolume, VmVolumeKind};
use mvm_fs::sdk_sidecar::{
    SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE, SdkSidecarLayout, SdkSidecarResolver,
};
use mvm_runtime::backends::hvf::HvfDriver;
use mvm_runtime::driver::VmmDriver;

use crate::world::CliWorld;

const FIXTURE_VERSION: &str = "1.2.3";

/// The variant these scenarios stage and resolve.
///
/// This scenario chooses glibc; the sibling musl acquisition path is covered by
/// the downloader's focused release-fixture regression.
const SCENARIO_LIBC: GuestLibc = GuestLibc::Glibc;

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// A sidecar ext4 carrying the one path the SDKs load, built with the in-repo
/// pure-Rust writer so the fixture needs no `mkfs`.
fn sidecar_ext4_bytes() -> Vec<u8> {
    use mvm_fs::ext4::Node;
    let nodes = vec![
        Node::Dir {
            path: "/lib".into(),
            mode: 0o555,
            xattrs: Vec::new(),
        },
        Node::File {
            path: "/lib/libmvm_host_services.so".into(),
            mode: 0o555,
            data: mvm_fs::elf::test_fixture::shared_object(&[
                "libgcc_s.so.1",
                SCENARIO_LIBC
                    .libc_soname()
                    .expect("a fixture names a real libc"),
            ]),
            xattrs: Vec::new(),
        },
    ];
    mvm_fs::ext4::build_image(nodes).expect("build the sidecar ext4 fixture")
}

fn cache_root(world: &mut CliWorld) -> std::path::PathBuf {
    world
        .sdk_sidecar_cache
        .get_or_insert_with(|| tempfile::tempdir().expect("create the sidecar cache dir"))
        .path()
        .to_path_buf()
}

fn layout(world: &mut CliWorld) -> SdkSidecarLayout {
    let root = cache_root(world);
    SdkSidecarLayout::under(
        &root,
        FIXTURE_VERSION,
        &GuestArch::host().to_string(),
        SCENARIO_LIBC,
    )
}

#[given(expr = "a verified SDK sidecar in the cache")]
fn verified_sidecar_in_cache(world: &mut CliWorld) {
    let layout = layout(world);
    std::fs::create_dir_all(&layout.artifact_dir).expect("create the artifact dir");
    let image = sidecar_ext4_bytes();
    let version_text = format!("{FIXTURE_VERSION}\n");
    std::fs::write(&layout.image, &image).expect("write the sidecar image");
    std::fs::write(&layout.version_file, &version_text).expect("write VERSION");
    std::fs::write(
        &layout.checksum_manifest_file,
        format!(
            "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
            sha256_hex(&image),
            sha256_hex(version_text.as_bytes()),
        ),
    )
    .expect("write the checksum manifest");
}

#[given(expr = "an empty SDK sidecar cache")]
fn empty_sidecar_cache(world: &mut CliWorld) {
    // Touch the cache root so the scenario is explicit about being cold rather
    // than relying on lazy creation later.
    let _ = cache_root(world);
}

#[given(expr = "the cached SDK sidecar image is byte-flipped")]
fn byte_flip_sidecar(world: &mut CliWorld) {
    let layout = layout(world);
    let mut image = std::fs::read(&layout.image).expect("read the staged sidecar image");
    let last = image.len() - 1;
    image[last] ^= 0xff;
    std::fs::write(&layout.image, &image).expect("write the tampered sidecar image");
}

/// Build the tarball the `sdk-sidecar-image` release job publishes: the ext4,
/// the VERSION marker, and the derivation's own manifest over both.
fn sidecar_release_archive() -> Vec<u8> {
    let image = sidecar_ext4_bytes();
    let version_text = format!("{FIXTURE_VERSION}\n").into_bytes();
    let manifest = format!(
        "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
        sha256_hex(&image),
        sha256_hex(&version_text),
    )
    .into_bytes();
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    for (name, bytes) in [
        (SDK_SIDECAR_IMAGE_FILE, image),
        (SDK_SIDECAR_VERSION_FILE, version_text),
        (mvm_fs::overlay::CHECKSUM_MANIFEST_FILE, manifest),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).expect("fixture member size"));
        header.set_cksum();
        tar.append_data(&mut header, name, bytes.as_slice())
            .expect("append the release archive member");
    }
    tar.into_inner()
        .expect("finish the tar stream")
        .finish()
        .expect("finish the gzip stream")
}

/// Stage the two assets a release publishes for this arch. `checksum_over`
/// picks which bytes the `.sha256` sidecar commits to, so a scenario can make
/// the recorded digest disagree with the shipped archive.
fn stage_release(world: &mut CliWorld, checksum_over: &[u8]) {
    let archive = sidecar_release_archive();
    let base = world
        .sdk_sidecar_release
        .get_or_insert_with(|| tempfile::tempdir().expect("create the release dir"))
        .path()
        .to_path_buf();
    let release_dir = base.join(format!("v{FIXTURE_VERSION}"));
    std::fs::create_dir_all(&release_dir).expect("create the versioned release dir");
    let names = mvm_build::sdk_sidecar::SdkSidecarArtifactNames::for_target(
        &GuestArch::host().to_string(),
        GuestLibc::Glibc,
    );
    std::fs::write(release_dir.join(&names.archive), &archive).expect("write the release archive");
    std::fs::write(
        release_dir.join(&names.archive_checksum),
        format!("{}  {}\n", sha256_hex(checksum_over), names.archive),
    )
    .expect("write the release archive checksum");
}

#[given(expr = "a published SDK sidecar release artifact")]
fn published_release_artifact(world: &mut CliWorld) {
    stage_release(world, &sidecar_release_archive());
}

#[given(expr = "a published SDK sidecar release artifact whose archive checksum does not match")]
fn published_release_artifact_with_drifted_checksum(world: &mut CliWorld) {
    stage_release(world, b"bytes the release never shipped");
}

/// Drive the acquire ladder an installed `mvmctl` runs on a cold cache: fetch
/// and verify the published artifact, then resolve the attachment from the
/// entry it installed. The release base URL is overridden to the staged fixture
/// for the duration of this step, so no scenario reaches the network.
#[when(expr = "the launch path acquires the SDK sidecar from the published release")]
fn acquire_sidecar_from_release(world: &mut CliWorld) {
    let cache = cache_root(world);
    let base = world
        .sdk_sidecar_release
        .as_ref()
        .expect("a prior step must stage the release")
        .path()
        .to_path_buf();
    let services = world.sdk_sidecar_services.clone();

    // `TestEnv` serializes process-wide env mutation and restores it on drop.
    // Nothing awaits inside this step, so the guard is held only for the
    // download and cannot stall a concurrently-running scenario.
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_OVERLAY_BASE_URL", format!("file://{}", base.display()));
    // The scenario is the acquire-and-boot workflow; a valid Sigstore
    // signature cannot be minted offline, so the signature rung is exercised
    // by `mvm_build::release_signature`'s own witnesses instead.
    env.set(mvm_build::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");

    world.sdk_sidecar_result = Some(
        mvm_build::sdk_sidecar::download_sdk_sidecar(
            FIXTURE_VERSION,
            GuestArch::host(),
            SCENARIO_LIBC,
            &cache,
        )
        .map_err(|e| format!("{e:#}"))
        .and_then(|_installed| {
            let resolver = SdkSidecarResolver::new(cache.clone(), FIXTURE_VERSION.to_string());
            mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
                &services,
                &resolver,
                GuestArch::host(),
                SCENARIO_LIBC,
            )
            .map_err(|e| format!("{e:#}"))
        }),
    );
}

#[then(expr = "the launch is refused and the SDK sidecar cache stays empty")]
fn launch_refused_cache_empty(world: &mut CliWorld) {
    let message = match resolved(world) {
        Err(message) => message.clone(),
        Ok(_) => panic!("expected the acquire to be refused"),
    };
    assert!(!message.is_empty(), "a refusal must carry a reason");
    let layout = layout(world);
    assert!(
        !layout.artifact_dir.exists(),
        "a refused acquire must leave no artifact dir at {}",
        layout.artifact_dir.display()
    );
}

#[given(expr = "a workload plan that binds no host service")]
fn plan_binds_nothing(world: &mut CliWorld) {
    world.sdk_sidecar_services = Vec::new();
    world.sdk_sidecar_plan = Some(PlanFixture::new().build());
}

#[given(expr = "a workload plan that binds host service {string}")]
fn plan_binds_service(world: &mut CliWorld, service: String) {
    let id = ServiceId::parse(service.as_str()).expect("a well-formed fixture service id");
    world.sdk_sidecar_services = vec![id.clone()];
    world.sdk_sidecar_plan = Some(PlanFixture::new().services(vec![id]).build());
}

#[given(expr = "a read-only directory mount at {string}")]
fn read_only_directory_mount(world: &mut CliWorld, guest_path: String) {
    world.sdk_sidecar_user_volumes.push(VmVolume {
        host: "/host/wheels".to_string(),
        guest: guest_path,
        size: String::new(),
        read_only: true,
        kind: VmVolumeKind::DirShare,
        encrypted: false,
        materialized_image: None,
        volume_label: None,
    });
}

#[when(expr = "the launch path resolves the SDK sidecar")]
fn resolve_sidecar(world: &mut CliWorld) {
    let root = cache_root(world);
    let resolver = SdkSidecarResolver::new(root, FIXTURE_VERSION.to_string());
    let services = world.sdk_sidecar_services.clone();
    world.sdk_sidecar_result = Some(
        mvm_runtime::sdk_sidecar::resolve_sdk_sidecar_attachment(
            &services,
            &resolver,
            GuestArch::host(),
            SCENARIO_LIBC,
        )
        .map_err(|e| format!("{e:#}")),
    );
}

#[when(expr = "the SDK sends a framed host time request to its bound broker")]
fn sdk_sends_host_time_request(world: &mut CliWorld) {
    use std::sync::Arc;
    use std::sync::mpsc;

    let state = tempfile::tempdir().expect("create broker state dir");
    let socket = state.path().join("broker.sock");
    let bindings = world.sdk_sidecar_services.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_socket = socket.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async move {
            let listener = tokio::net::UnixListener::bind(&server_socket)
                .map_err(|error| error.to_string())?;
            let mut registry = mvm_hostd::broker::registry::Registry::new();
            let _bound =
                mvm_hostd::broker::handlers::register_bound_handlers(&mut registry, &bindings);
            ready_tx.send(()).map_err(|error| error.to_string())?;
            tokio::select! {
                result = mvm_hostd::broker::server::serve_on_listener(
                    listener,
                    Arc::new(registry),
                    "bdd-workload".into(),
                    "bdd-tenant".into(),
                    65_536,
                ) => result.map_err(|error| error.to_string()),
                _ = stop_rx => Ok(()),
            }
        })
    });

    ready_rx
        .recv()
        .expect("broker must bind before the SDK dials");
    let result = std::os::unix::net::UnixStream::connect(&socket)
        .map_err(anyhow::Error::from)
        .and_then(|mut stream| {
            mvm_agentd::host_time::now_on(&mut stream).map_err(anyhow::Error::from)
        })
        .map(|response| response.wall_ms)
        .map_err(|error| format!("{error:#}"));
    let _ = stop_tx.send(());
    server
        .join()
        .expect("broker server thread must not panic")
        .expect("broker server must stop cleanly");
    world.sdk_host_time_result = Some(result);
}

#[then(expr = "the SDK receives a current host wall clock without a transport error")]
fn sdk_receives_host_time(world: &mut CliWorld) {
    let wall_ms = world
        .sdk_host_time_result
        .as_ref()
        .expect("a prior step must call host.time.v1")
        .as_ref()
        .unwrap_or_else(|error| panic!("host.time.v1 must cross the framed transport: {error}"));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("host clock must be after the Unix epoch")
        .as_millis();
    assert!(
        now_ms.saturating_sub(u128::from(*wall_ms)) < 5_000,
        "broker returned a stale wall clock: {wall_ms}"
    );
}

fn resolved(
    world: &CliWorld,
) -> &Result<Option<mvm_runtime::sdk_sidecar::SdkSidecarAttachment>, String> {
    world
        .sdk_sidecar_result
        .as_ref()
        .expect("a prior step must resolve the SDK sidecar")
}

#[then(expr = "no SDK sidecar is attached")]
fn no_sidecar_attached(world: &mut CliWorld) {
    match resolved(world) {
        Ok(None) => {}
        Ok(Some(a)) => panic!("expected no sidecar, got one at {}", a.volume.host),
        Err(e) => panic!("expected no sidecar, got an error: {e}"),
    }
}

#[then(expr = "the SDK sidecar is attached read-only at {string}")]
fn sidecar_attached_read_only(world: &mut CliWorld, guest_path: String) {
    let attached = resolved(world)
        .as_ref()
        .expect("resolution must succeed")
        .as_ref()
        .expect("a sidecar must be attached");
    assert_eq!(attached.volume.guest, guest_path);
    assert!(attached.volume.read_only, "the sidecar must be read-only");
    assert_eq!(
        attached.volume.kind,
        mvm_core::vm_backend::VmVolumeKind::Disk
    );
    // The plan grant must describe the same attachment, or the admission gate
    // below would refuse a launch the launch path built.
    assert_eq!(attached.grant.guest_path, attached.volume.guest);
    assert_eq!(attached.grant.host_path, attached.volume.host);
    assert!(attached.grant.read_only);
}

fn plan_of(world: &CliWorld) -> &mvm_core::plan::ExecutionPlan {
    world
        .sdk_sidecar_plan
        .as_ref()
        .expect("a prior step must build the workload plan")
}

fn attached_volumes(world: &CliWorld) -> Vec<mvm_core::vm_backend::VmVolume> {
    let mut volumes = world.sdk_sidecar_user_volumes.clone();
    if let Ok(Some(attachment)) = resolved(world) {
        volumes.push(attachment.volume.clone());
    }
    volumes
}

#[then(expr = "admission accepts the launch with no sidecar attachment")]
fn admission_accepts_without_sidecar(world: &mut CliWorld) {
    mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
        &[],
        plan_of(world),
        GuestLibc::Unknown,
    )
    .expect("a plan binding no SDK host service must admit with no sidecar");
}

#[then(expr = "admission accepts the launch with the sidecar attachment")]
fn admission_accepts_with_sidecar(world: &mut CliWorld) {
    let volumes = attached_volumes(world);
    assert!(!volumes.is_empty(), "no sidecar volume was resolved");
    mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
        &volumes,
        plan_of(world),
        SCENARIO_LIBC,
    )
    .expect("the resolved attachment must satisfy the admission gate");
}

#[then(expr = "wasm admission refuses the requested SDK host service before backend start")]
fn wasm_admission_refuses_sdk_host_service(world: &mut CliWorld) {
    let bound = world
        .sdk_sidecar_services
        .first()
        .expect("a prior step must bind an SDK host service")
        .as_str();
    let err = mvm_hostd::plan_admission::enforce_sdk_sidecar_backend_compatibility(
        mvm_core::vm_backend::BackendKind::Wasm,
        plan_of(world),
    )
    .expect_err("wasm must refuse the native SDK sidecar delivery mechanism");
    let message = err.to_string();
    assert!(message.contains(bound), "{message}");
    assert!(message.contains("wasm"), "{message}");
    assert!(message.contains("SDK host service"), "{message}");
    assert!(!message.contains("DiskVolumeNotSupported"), "{message}");
}

#[then(expr = "admission refuses a sidecar attachment for this plan")]
fn admission_refuses_sidecar(world: &mut CliWorld) {
    // Hand the gate a well-formed sidecar volume the plan never authorized.
    let smuggled = mvm_core::vm_backend::VmVolume {
        host: "/cache/sdk-sidecar/1.2.3/host/sdk.ext4".into(),
        guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
        size: String::new(),
        read_only: true,
        kind: mvm_core::vm_backend::VmVolumeKind::Disk,
        encrypted: false,
        materialized_image: None,
        volume_label: None,
    };
    let err = mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment(
        &[smuggled],
        plan_of(world),
        GuestLibc::Unknown,
    )
    .expect_err("an unauthorized sidecar must be refused");
    assert!(
        err.to_string().contains("binds no SDK host service"),
        "unexpected refusal reason: {err}"
    );
}

#[then(expr = "the launch is refused and the error names the binding that required it")]
fn launch_refused_naming_binding(world: &mut CliWorld) {
    let bound = world
        .sdk_sidecar_services
        .first()
        .expect("a prior step must bind a host service")
        .as_str()
        .to_string();
    let Err(message) = resolved(world) else {
        panic!("expected the launch to be refused");
    };
    assert!(
        message.contains(&bound),
        "the refusal must name the binding that required the sidecar: {message}"
    );
    assert!(
        message.contains(mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
        "the refusal must name the sidecar mount point: {message}"
    );
}

#[then(expr = "the launch is refused and the error reports an integrity mismatch")]
fn launch_refused_integrity(world: &mut CliWorld) {
    let Err(message) = resolved(world) else {
        panic!("expected the launch to be refused");
    };
    assert!(
        message.contains("integrity mismatch"),
        "the refusal must report the integrity mismatch: {message}"
    );
}

/// Build the launch config this scenario's resolution implies and assemble a
/// real sealed workload cmdline from it, so the guest-visible half of the
/// contract is asserted, not assumed.
fn assembled_cmdline(world: &mut CliWorld) -> String {
    let state = tempfile::tempdir().expect("create the cmdline state dir");
    let config = VmStartConfig {
        name: "bdd-sdk-sidecar".to_string(),
        rootfs_path: "/image/rootfs.ext4".to_string(),
        verity_path: Some("/image/rootfs.verity".to_string()),
        roothash: Some("a".repeat(64)),
        initrd_path: Some("/image/rootfs.initrd".to_string()),
        runtime_overlay_path: Some("/image/runtime.ext4".to_string()),
        runtime_overlay_verity_path: Some("/image/runtime.verity".to_string()),
        runtime_overlay_roothash: Some("b".repeat(64)),
        volumes: attached_volumes(world),
        ..Default::default()
    };
    let driver = HvfDriver::new();
    mvm_runtime::workload_runner::assemble_workload_cmdline_for_test(
        &driver as &dyn VmmDriver,
        &config,
        state.path(),
    )
}

#[then(expr = "the assembled workload cmdline names no SDK sidecar device")]
fn cmdline_names_no_sidecar(world: &mut CliWorld) {
    let cmdline = assembled_cmdline(world);
    assert!(
        !cmdline.contains("mvm.sdk_dev="),
        "a workload with no sidecar must carry no sidecar device token: {cmdline}"
    );
}

#[then(expr = "the assembled workload cmdline names the SDK sidecar device the backend attached")]
fn cmdline_names_sidecar(world: &mut CliWorld) {
    let volumes = attached_volumes(world);
    assert!(!volumes.is_empty(), "no sidecar volume was resolved");
    let cmdline = assembled_cmdline(world);
    // A sealed boot carries rootfs + verity + overlay pair, so the sidecar is
    // the fifth block device. Asserting the exact device — rather than just the
    // token's presence — is what proves the guest is told where to look.
    assert!(
        cmdline.contains("mvm.sdk_dev=/dev/vde"),
        "the cmdline must name the device the backend attached: {cmdline}"
    );
}

#[then(expr = "the user-volume manifest names {string} but not the SDK mount")]
fn user_volume_manifest_excludes_sidecar(world: &mut CliWorld, guest_path: String) {
    let cmdline = assembled_cmdline(world);
    let user_path = hex::encode(guest_path.as_bytes());
    let sdk_path = hex::encode(mvm_core::plan::SDK_SIDECAR_GUEST_PATH.as_bytes());
    let manifest = cmdline
        .split_ascii_whitespace()
        .find(|token| token.starts_with("mvm.uvols="))
        .expect("the ordinary directory mount must emit a user-volume manifest");

    assert!(
        manifest.contains(&format!("uvol0:{user_path}:ro:fs")),
        "the ordinary mount must remain in user-volume activation: {cmdline}"
    );
    assert!(
        !manifest.contains(&sdk_path),
        "the reserved SDK mount must bypass user-volume activation: {cmdline}"
    );
}
