//! Live end-to-end smoke for `mvmctl run --image <oci>`.
//!
//! Disabled by default. Set `MVM_OCI_IMAGE_RUNNER_SMOKE=1` on a host with
//! a working workload backend (Vz on macOS 26+, libkrun on macOS 13-25,
//! Firecracker on Linux/KVM), the matching supervisor/drainer helper
//! binaries built into the workspace `target/`, a populated builder-VM
//! image cache, and network access to the registry.
//!
//! Unlike a unit test, this drives the REAL CLI path so it exercises the
//! whole chain that only fails on a live boot:
//!
//! 1. OCI pull + hardened unpack,
//! 2. mvm-runtime injection (agent + netinit + `/init` + `/mvm/runtime`),
//! 3. ext4 materialize in the builder VM,
//! 4. the `admit_overlay_aware` admission gate (the injected rootfs must
//!    pass it — an un-injected OCI rootfs is refused),
//! 5. boot on the workload backend,
//! 6. a real in-guest agent round-trip: the agent runs the trailing
//!    command over vsock and streams its stdout back.
//!
//! The marker echoed by the in-guest command proves the command actually
//! ran inside the guest, not on the host.
//!
//! For source-checkout runs of the prod witness we explicitly force
//! `--kernel-source compile` so the test can prove the OCI prod path before the
//! version-matched published workload-kernel assets are available on GitHub
//! Releases. That override exercises the real CLI/kernel bootstrap path rather
//! than stubbing the kernel, while installed binaries still rely on the
//! published hash-verified downloads.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

const ENABLE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_SMOKE";
const IMAGE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_REF";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";
const PROD_ENABLE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_PROD_SMOKE";
const PROD_IMAGE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_PROD_REF";
const PROD_DEFAULT_POLICY_REGISTRY: &str = "cgr.dev";
const PROD_DEFAULT_POLICY_IDENTITY: &str =
    "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main";
const PROD_DEFAULT_POLICY_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Debug, Deserialize)]
struct OciCacheIndex {
    #[serde(default)]
    images: Vec<CachedOciImage>,
}

#[derive(Debug, Deserialize)]
struct CachedOciImage {
    resolved_digest: String,
    #[serde(default)]
    rootfs_path: Option<String>,
}

fn mvm_data_dir() -> PathBuf {
    std::env::var_os("MVM_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".mvm")))
        .expect("MVM_DATA_DIR or HOME must be set")
}

fn mvm_cache_dir() -> PathBuf {
    std::env::var_os("MVM_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache/mvm")))
        .expect("MVM_CACHE_DIR or HOME must be set")
}

fn mvmctl_with_target_path() -> Command {
    let mvmctl = env!("CARGO_BIN_EXE_mvmctl");
    let target_dir = Path::new(mvmctl)
        .parent()
        .expect("mvmctl binary has a parent dir")
        .to_path_buf();
    let path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{path}", target_dir.display());

    let mut cmd = Command::new(mvmctl);
    cmd.env("PATH", path);
    cmd
}

fn digest_from_reference(image_ref: &str) -> Option<&str> {
    image_ref.split_once('@').map(|(_, digest)| digest)
}

fn resolved_digest_from_run_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("[mvm] Using OCI image ") {
            return None;
        }
        let start = line.rfind('(')? + 1;
        let end = line.rfind(')')?;
        let digest = line.get(start..end)?.trim();
        digest.starts_with("sha256:").then(|| digest.to_string())
    })
}

fn prod_policy_path() -> PathBuf {
    std::env::var_os("MVM_OCI_POLICY")
        .map(PathBuf::from)
        .unwrap_or_else(|| mvm_data_dir().join("oci-policy.toml"))
}

fn default_prod_policy_text() -> String {
    format!(
        "allowed_registries = [\"{PROD_DEFAULT_POLICY_REGISTRY}\"]\n\n\
         [[cosign]]\n\
         certificate_identity = \"{PROD_DEFAULT_POLICY_IDENTITY}\"\n\
         certificate_oidc_issuer = \"{PROD_DEFAULT_POLICY_ISSUER}\"\n"
    )
}

fn ensure_prod_policy() -> PathBuf {
    let policy_path = prod_policy_path();
    if policy_path.is_file() {
        return policy_path;
    }

    let fallback = std::env::temp_dir().join(format!(
        "mvm-oci-prod-policy-{}-{}.toml",
        std::process::id(),
        std::thread::current().name().unwrap_or("smoke")
    ));
    std::fs::write(&fallback, default_prod_policy_text()).expect("write fallback prod OCI policy");
    fallback
}

fn prod_rootfs_path_for_digest(digest: &str) -> Option<PathBuf> {
    let index_path = mvm_cache_dir().join("oci/index.json");
    let index_bytes = std::fs::read(index_path).ok()?;
    let index: OciCacheIndex = serde_json::from_slice(&index_bytes).ok()?;
    let rel = index
        .images
        .iter()
        .find(|image| image.resolved_digest == digest)
        .and_then(|image| image.rootfs_path.as_deref())?;
    Some(mvm_cache_dir().join("oci").join(rel))
}

#[test]
fn run_image_boots_and_round_trips_the_agent() {
    if std::env::var(ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[oci_image_runner_smoke] skipped - set {ENABLE_VAR}=1 on a host with a workload \
             backend + builder-VM cache to pull an OCI image, inject the mvm runtime, boot it, \
             and round-trip the guest agent"
        );
        return;
    }

    let image_ref = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let marker = format!("oci-smoke-marker-{}", std::process::id());
    let output = mvmctl_with_target_path()
        .args(["run", "--image", &image_ref, "--", "/bin/echo", &marker])
        .output()
        .expect("spawn mvmctl run --image");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "mvmctl run --image exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains(&marker) || stderr.contains(&marker),
        "guest did not echo the marker {marker:?} - the agent round-trip did not run.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn run_image_prod_boots_with_cached_verity_sidecars() {
    if std::env::var(PROD_ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[oci_image_runner_prod_smoke] skipped - set {PROD_ENABLE_VAR}=1 on macOS with \
             a workload backend, builder-VM cache, cosign on PATH, and a signed digest-pinned \
             OCI ref in {PROD_IMAGE_VAR}"
        );
        return;
    }
    if which::which("cosign").is_err() {
        eprintln!("[oci_image_runner_prod_smoke] skipped - cosign is not on PATH");
        return;
    }
    let policy_path = ensure_prod_policy();

    let image_ref = match std::env::var(PROD_IMAGE_VAR) {
        Ok(value) => value,
        Err(_) => {
            eprintln!(
                "[oci_image_runner_prod_smoke] skipped - set {PROD_IMAGE_VAR} to a signed, \
                 digest-pinned registry ref; when the ref is a Chainguard image, this test can \
                 synthesize a temporary OCI policy if MVM_OCI_POLICY is unset"
            );
            return;
        }
    };
    let pinned_digest = digest_from_reference(&image_ref)
        .expect("prod OCI smoke requires a digest-pinned reference")
        .to_string();
    let marker = format!("oci-prod-smoke-marker-{}", std::process::id());

    let output = mvmctl_with_target_path()
        .env("MVM_OCI_POLICY", &policy_path)
        .args(["--kernel-source", "compile"])
        .args([
            "run",
            "--image",
            &image_ref,
            "--prod",
            "--",
            "/bin/echo",
            &marker,
        ])
        .output()
        .expect("spawn mvmctl run --image --prod");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "mvmctl run --image --prod exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains(&marker) || stderr.contains(&marker),
        "guest did not echo the prod marker {marker:?}.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let resolved_digest = resolved_digest_from_run_output(&stdout)
        .or_else(|| resolved_digest_from_run_output(&stderr))
        .unwrap_or(pinned_digest);
    let rootfs_path = prod_rootfs_path_for_digest(&resolved_digest)
        .expect("prod OCI cache must record a rootfs path");
    assert!(
        rootfs_path.is_file(),
        "prod OCI rootfs is missing at {}",
        rootfs_path.display()
    );
    let verity_path = rootfs_path.with_extension("verity");
    let roothash_path = rootfs_path.with_extension("roothash");
    assert!(
        verity_path.is_file(),
        "prod OCI verity sidecar missing at {}",
        verity_path.display()
    );
    assert!(
        roothash_path.is_file(),
        "prod OCI roothash missing at {}",
        roothash_path.display()
    );

    let roothash = std::fs::read_to_string(&roothash_path).expect("read prod roothash");
    let roothash = roothash.trim();
    assert_eq!(roothash.len(), 64, "prod roothash must be 64 lowercase hex");
    assert!(
        roothash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "prod roothash must be lowercase hex: {roothash}"
    );
}
