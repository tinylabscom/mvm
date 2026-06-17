//! Plan 85 Phase B live smoke.
//!
//! Disabled by default. Set `MVM_OCI_IMAGE_RUNNER_SMOKE=1` on a host
//! with libkrun, `mvm-libkrun-supervisor`, and a populated builder-VM
//! image cache to pull Alpine, unpack it, materialize an ext4 rootfs
//! inside the builder VM, and boot it.

#![cfg(unix)]

use std::io::Cursor;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use libkrun_sys::{KrunContext, SupervisorConfig};
use mvm_build::rootfs::{MaterializeExt4Input, MaterializeExt4Options, materialize_ext4};
use mvm_oci::{
    LayerFetchOptions, LinuxPlatform, OciLayerFetcher, OciManifestFetcher, UnpackOptions,
    unpack_layer,
};
use tempfile::TempDir;

const ENABLE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_SMOKE";
const IMAGE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_REF";
const KERNEL_VAR: &str = "MVM_OCI_IMAGE_RUNNER_KERNEL";
const SUPERVISOR_VAR: &str = "MVM_OCI_IMAGE_RUNNER_SUPERVISOR";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";
const MARKER: &str = "oci-smoke: hi";

#[tokio::test(flavor = "multi_thread")]
async fn alpine_pull_unpack_materialize_and_boots() {
    if std::env::var(ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[oci_image_runner_smoke] skipped - set {ENABLE_VAR}=1 to pull Alpine, \
             materialize ext4 in the builder VM, and boot it with libkrun"
        );
        return;
    }

    let image_ref = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let image = image_ref.parse().expect("smoke image reference parses");
    let manifest_fetcher = OciManifestFetcher::new();
    let manifest = manifest_fetcher
        .fetch_linux_platform_manifest(&image, &LinuxPlatform::for_current_arch())
        .await
        .expect("fetch platform image manifest");
    let layers = manifest.layers().expect("platform manifest has layers");
    assert!(
        !layers.is_empty(),
        "smoke image must have at least one layer"
    );

    let tmp = TempDir::new().expect("tempdir");
    let unpacked_root = tmp.path().join("root");
    std::fs::create_dir_all(&unpacked_root).expect("create unpacked root");

    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    for layer in &layers {
        let mut compressed = Vec::new();
        layer_fetcher
            .fetch_layer(&image, layer, &mut compressed)
            .await
            .expect("fetch layer bytes");

        let report = if layer.media_type.ends_with("+gzip")
            || layer.media_type.ends_with(".gzip")
            || layer.media_type.contains("tar.gzip")
        {
            unpack_layer(
                GzDecoder::new(Cursor::new(compressed)),
                &unpacked_root,
                &UnpackOptions::default(),
            )
        } else {
            unpack_layer(
                Cursor::new(compressed),
                &unpacked_root,
                &UnpackOptions::default(),
            )
        }
        .expect("unpack layer");
        assert!(
            report.refused.is_empty(),
            "smoke layer unpack refused entries: {:?}",
            report.refused
        );
    }

    install_smoke_init(&unpacked_root);
    let uncompressed_size = unpacked_tree_size(&unpacked_root).expect("measure unpacked root size");

    let rootfs = tmp.path().join("rootfs.ext4");
    materialize_ext4(
        &MaterializeExt4Input::new(unpacked_root, rootfs.clone(), uncompressed_size),
        &MaterializeExt4Options::default(),
    )
    .expect("materialize Alpine rootfs.ext4 in builder VM");

    let kernel = kernel_path();
    let supervisor = supervisor_path();
    let console = tmp.path().join("console.log");
    let state_dir = tmp.path().join("vm-state");
    std::fs::create_dir_all(&state_dir).expect("create vm state dir");
    boot_with_libkrun(&supervisor, &kernel, &rootfs, &console, &state_dir);

    let console_text = std::fs::read_to_string(&console).expect("read console log");
    assert!(
        console_text.contains(MARKER),
        "guest console did not contain marker {MARKER:?}; console:\n{console_text}"
    );
}

fn install_smoke_init(root: &Path) {
    let init = root.join("init");
    std::fs::write(
        &init,
        format!(
            "#!/bin/sh\n/bin/sh -c 'echo {MARKER}; exit 0'\nstatus=$?\nsync\npoweroff -f\nexit $status\n"
        ),
    )
    .expect("write /init");
    let mut perms = std::fs::metadata(&init)
        .expect("init metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&init, perms).expect("chmod /init");
}

fn unpacked_tree_size(root: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn kernel_path() -> PathBuf {
    if let Some(path) = std::env::var_os(KERNEL_VAR).map(PathBuf::from) {
        assert!(
            path.is_file(),
            "{KERNEL_VAR}={} is not a file",
            path.display()
        );
        return path;
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let home = std::env::var("HOME").expect("HOME set");
    let path = Path::new(&home)
        .join(".cache/mvm/builder-vm")
        .join(arch)
        .join("vmlinux");
    assert!(
        path.is_file(),
        "{KERNEL_VAR} is unset and default builder-VM kernel is missing at {}",
        path.display()
    );
    path
}

fn supervisor_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SUPERVISOR_VAR).map(PathBuf::from) {
        assert!(
            path.is_file(),
            "{SUPERVISOR_VAR}={} is not a file",
            path.display()
        );
        return path;
    }
    which::which("mvm-libkrun-supervisor")
        .expect("mvm-libkrun-supervisor on PATH or MVM_OCI_IMAGE_RUNNER_SUPERVISOR set")
}

fn boot_with_libkrun(
    supervisor: &Path,
    kernel: &Path,
    rootfs: &Path,
    console: &Path,
    state_dir: &Path,
) {
    let vm_name = format!("oci-smoke-{}", std::process::id());
    let krun = KrunContext::new(
        &vm_name,
        kernel.to_string_lossy().into_owned(),
        rootfs.to_string_lossy().into_owned(),
    )
    .with_resources(1, 256)
    .with_cmdline("console=hvc0 root=/dev/vda rw init=/init")
    .with_console_output(console.to_string_lossy().into_owned())
    .with_vsock_socket_dir(state_dir.to_string_lossy().into_owned());
    let cfg = SupervisorConfig {
        krun,
        vm_state_dir: state_dir.to_string_lossy().into_owned(),
        pid_file_name: Some("oci-smoke.pid".to_string()),
        tenant_id: None,
        audit_dir: None,
        gateway_audit_socket: None,
        gateway_events_socket: None,
        signing_key_path: None,
        plan: None,
        bundle: None,
        network_policy: None,
        bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
    };
    let json = serde_json::to_string(&cfg).expect("serialize supervisor config");

    let mut child = Command::new(supervisor)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mvm-libkrun-supervisor");
    child
        .stdin
        .take()
        .expect("supervisor stdin")
        .write_all(json.as_bytes())
        .expect("write supervisor config");

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait().expect("poll supervisor") {
            assert!(
                status.success(),
                "supervisor exited with {status}; stderr={}",
                String::from_utf8_lossy(
                    &child
                        .wait_with_output()
                        .expect("collect supervisor output")
                        .stderr
                )
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!(
                "supervisor did not exit within 90s; console at {}",
                console.display()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
