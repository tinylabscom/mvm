//! Live end-to-end smoke for `mvmctl run --image <oci>`.
//!
//! Disabled by default. Set `MVM_OCI_IMAGE_RUNNER_SMOKE=1` on a host with
//! a working workload backend, the matching supervisor/drainer helper
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
//! 6. a real in-guest agent round-trip over the repo's vsock-only control
//!    plane: the agent runs the trailing command and streams its stdout back.
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

use mvm_runtime::backend::AnyBackend;
#[cfg(target_os = "macos")]
use std::io::Write;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use serde::Deserialize;
#[cfg(target_os = "macos")]
use tempfile::TempDir;

const ENABLE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_SMOKE";
const REQUIRED_OVERLAY_ENABLE_VAR: &str = "MVM_OCI_REQUIRED_OVERLAY_SMOKE";
const VSOCK_EGRESS_ENABLE_VAR: &str = "MVM_OCI_VSOCK_EGRESS_SMOKE";
const BACKEND_VAR: &str = "MVM_OCI_IMAGE_RUNNER_HYPERVISOR";
const IMAGE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_REF";
const DEFAULT_IMAGE: &str = "docker.io/library/alpine:3.20";
#[cfg(target_os = "macos")]
const PROD_ENABLE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_PROD_SMOKE";
#[cfg(target_os = "macos")]
const PROD_IMAGE_VAR: &str = "MVM_OCI_IMAGE_RUNNER_PROD_REF";
#[cfg(target_os = "macos")]
const PROD_DEFAULT_POLICY_REGISTRY: &str = "cgr.dev";
#[cfg(target_os = "macos")]
const PROD_DEFAULT_POLICY_IDENTITY: &str =
    "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main";
#[cfg(target_os = "macos")]
const PROD_DEFAULT_POLICY_ISSUER: &str = "https://token.actions.githubusercontent.com";
#[cfg(target_os = "macos")]
const VERB_GRANT_ENABLE_VAR: &str = "MVM_AGENT_VERB_GRANT_SMOKE";
#[cfg(target_os = "macos")]
const HELLO_APP_ARGV: &str = "[[\"ari\"], {}]";
#[cfg(target_os = "macos")]
const VERB_GRANT_STAGED_MARKER: &str = "mvm-init: provisioned verb-grant";
#[cfg(target_os = "macos")]
const DENIED_VERB: &str = "update-idle-timeout";
#[cfg(target_os = "macos")]
const HELLO_APP_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/python/hello-app/app.py"
);

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct OciCacheIndex {
    #[serde(default)]
    images: Vec<CachedOciImage>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct CachedOciImage {
    resolved_digest: String,
    #[serde(default)]
    rootfs_path: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct SessionInfo {
    vm_name: String,
}

#[cfg(target_os = "macos")]
struct SessionCleanup {
    data_dir: PathBuf,
    session_id: Option<String>,
}

#[cfg(target_os = "macos")]
impl SessionCleanup {
    fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            session_id: None,
        }
    }

    fn arm(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }

    fn disarm(&mut self) {
        self.session_id = None;
    }
}

#[cfg(target_os = "macos")]
impl Drop for SessionCleanup {
    fn drop(&mut self) {
        let Some(session_id) = self.session_id.as_deref() else {
            return;
        };
        let _ = mvmctl_with_target_path()
            .env("HOME", &self.data_dir)
            .env("MVM_HOME", &self.data_dir)
            .args(["session", "kill", session_id])
            .output();
    }
}

#[cfg(target_os = "macos")]
fn mvm_home() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
}

#[cfg(target_os = "macos")]
fn mvm_cache_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir())
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

#[cfg(target_os = "macos")]
fn smoke_data_dir(sandbox: &TempDir) -> PathBuf {
    sandbox.path().join("mvm-state")
}

#[cfg(target_os = "macos")]
fn workload_audit_path(data_dir: &Path, vm_name: &str) -> PathBuf {
    data_dir
        .join("audit")
        .join(format!("local.{vm_name}.workload.jsonl"))
}

#[cfg(target_os = "macos")]
fn console_log_path(data_dir: &Path, vm_name: &str) -> PathBuf {
    data_dir.join("vms").join(vm_name).join("console.log")
}

#[cfg(target_os = "macos")]
fn kept_alive_session_id(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Session kept alive: ")
            .map(str::trim)
    })
}

#[cfg(target_os = "macos")]
fn wait_for_file_contains(path: &Path, needle: &str, timeout: Duration) -> String {
    let start = Instant::now();
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && contents.contains(needle)
        {
            return contents;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for {needle:?} in {}\nlast contents:\n{}",
            path.display(),
            std::fs::read_to_string(path).unwrap_or_else(|_| "<unreadable>".to_string())
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(target_os = "macos")]
fn run_with_stdin(cmd: &mut Command, stdin: &[u8], context: &str) -> std::process::Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{context}: spawn failed: {e}"));
    child
        .stdin
        .take()
        .expect("child stdin piped")
        .write_all(stdin)
        .unwrap_or_else(|e| panic!("{context}: write stdin failed: {e}"));
    child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("{context}: wait_with_output failed: {e}"))
}

#[cfg(target_os = "macos")]
fn digest_from_reference(image_ref: &str) -> Option<&str> {
    image_ref.split_once('@').map(|(_, digest)| digest)
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn prod_policy_path() -> PathBuf {
    std::env::var_os("MVM_OCI_POLICY")
        .map(PathBuf::from)
        .unwrap_or_else(|| mvm_home().join("oci-policy.toml"))
}

#[cfg(target_os = "macos")]
fn default_prod_policy_text() -> String {
    format!(
        "allowed_registries = [\"{PROD_DEFAULT_POLICY_REGISTRY}\"]\n\n\
         [[cosign]]\n\
         certificate_identity = \"{PROD_DEFAULT_POLICY_IDENTITY}\"\n\
         certificate_oidc_issuer = \"{PROD_DEFAULT_POLICY_ISSUER}\"\n"
    )
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

fn required_overlay_backend() -> String {
    std::env::var(BACKEND_VAR).unwrap_or_else(|_| {
        if cfg!(target_os = "linux") {
            "firecracker".to_string()
        } else {
            "hvf".to_string()
        }
    })
}

fn vsock_egress_backend() -> Option<String> {
    std::env::var(BACKEND_VAR).ok().or_else(|| {
        if cfg!(target_os = "macos") {
            Some("hvf".to_string())
        } else {
            None
        }
    })
}

fn backend_supports_image_vsock_egress(backend: &str) -> bool {
    let caps = AnyBackend::from_hypervisor(backend).capabilities();
    caps.vsock && caps.no_routable_guest_nic && caps.host_vsock_proxy
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
        .args([
            "--kernel-source",
            "compile",
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

#[test]
fn run_image_block_root_required_overlay_is_read_only_on_selected_backend() {
    if std::env::var(REQUIRED_OVERLAY_ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[oci_image_runner_smoke] skipped - set {REQUIRED_OVERLAY_ENABLE_VAR}=1 to prove the \
             block-backed OCI path boots with required-overlay and a read-only /mvm/runtime mount. \
             Optional: set {BACKEND_VAR}=firecracker|hvf|libkrun|qemu (default: firecracker on \
             Linux, hvf elsewhere)."
        );
        return;
    }

    let image_ref = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let mvmctl = env!("CARGO_BIN_EXE_mvmctl");
    let backend = required_overlay_backend();

    let target_dir = Path::new(mvmctl)
        .parent()
        .expect("mvmctl binary has a parent dir")
        .to_path_buf();
    let path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{path}", target_dir.display());

    let marker = format!("oci-required-overlay-{}", std::process::id());
    let guest_script = format!(
        "set -eu; \
         echo MARKER:{marker}; \
         grep ' /mvm/runtime ' /proc/mounts; \
         cat /proc/cmdline; \
         if touch /mvm/runtime/probe-write 2>/tmp/runtime-touch.err; then \
           echo UNEXPECTED_WRITE_SUCCESS; \
           exit 1; \
         fi; \
         cat /tmp/runtime-touch.err"
    );

    let output = Command::new(mvmctl)
        .env("PATH", path)
        .env("MVM_HYPERVISOR", &backend)
        .args([
            "run",
            "--image",
            &image_ref,
            "--",
            "/bin/sh",
            "-lc",
            &guest_script,
        ])
        .output()
        .expect("spawn mvmctl run --image required-overlay proof");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "mvmctl run --image required-overlay proof on backend {backend} exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code(),
    );
    assert!(
        combined.contains(&format!("MARKER:{marker}")),
        "guest command did not run inside the OCI VM.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        combined.contains(" /mvm/runtime ")
            && (combined.contains(" ro,") || combined.contains(" ro ")),
        "guest must report /mvm/runtime mounted read-only.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        combined.contains("Read-only file system"),
        "guest write attempt must fail with EROFS.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !combined.contains("UNEXPECTED_WRITE_SUCCESS"),
        "guest unexpectedly wrote to /mvm/runtime.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn run_image_uses_vsock_only_egress_contract_on_selected_backend() {
    if std::env::var(VSOCK_EGRESS_ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[oci_image_runner_smoke] skipped - set {VSOCK_EGRESS_ENABLE_VAR}=1 to prove the OCI \
             path uses the all-vsock egress contract on a backend that advertises \
             {{vsock,no_guest_nic,host_vsock_proxy}}. Optional: set {BACKEND_VAR}=hvf|... \
             (default: hvf on macOS)."
        );
        return;
    }

    let Some(backend) = vsock_egress_backend() else {
        eprintln!(
            "[oci_image_runner_smoke] skipped - no default all-vsock OCI egress backend is \
             declared for this host. Set {BACKEND_VAR} to a backend that advertises \
             {{vsock,no_guest_nic,host_vsock_proxy}}."
        );
        return;
    };
    assert!(
        backend_supports_image_vsock_egress(&backend),
        "backend {backend} does not advertise the all-vsock OCI egress contract \
         (requires vsock + no_guest_nic + host_vsock_proxy); this witness must not \
         run on a NIC-backed or otherwise non-vsock-proxy path"
    );

    let image_ref = std::env::var(IMAGE_VAR).unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let mvmctl = env!("CARGO_BIN_EXE_mvmctl");
    let target_dir = Path::new(mvmctl)
        .parent()
        .expect("mvmctl binary has a parent dir")
        .to_path_buf();
    let path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{path}", target_dir.display());
    let marker = format!("oci-vsock-egress-{}", std::process::id());
    let guest_script = format!(
        "set -eu; \
         echo MARKER:{marker}; \
         cat /proc/cmdline; \
         env | grep '^ALL_PROXY='"
    );

    let output = Command::new(mvmctl)
        .env("PATH", path)
        .env("MVM_HYPERVISOR", &backend)
        .args([
            "run",
            "--image",
            &image_ref,
            "--allow-host",
            "example.com",
            "--",
            "/bin/sh",
            "-lc",
            &guest_script,
        ])
        .output()
        .expect("spawn mvmctl run --image vsock egress proof");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "mvmctl run --image vsock egress proof on backend {backend} exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code(),
    );
    assert!(
        combined.contains(&format!("MARKER:{marker}")),
        "guest command did not run inside the OCI VM.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        combined.contains("mvm.vsock_egress=1"),
        "guest cmdline must opt into the vsock egress helper when outbound egress is allowed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        combined.contains("ALL_PROXY=socks5h://127.0.0.1:1080"),
        "guest env must receive the OCI SOCKS proxy contract for the vsock egress helper.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn prod_agent_verb_grant_hvf_witness_proves_staging_denial_and_audit() {
    if std::env::var(VERB_GRANT_ENABLE_VAR).as_deref() != Ok("1") {
        eprintln!(
            "[agent_verb_grant_smoke] skipped - set {VERB_GRANT_ENABLE_VAR}=1 on macOS with a working hvf workload path, builder VM access, and network/build prerequisites to capture the sealed grant-delivery witness"
        );
        return;
    }

    let sandbox = tempfile::tempdir().expect("create smoke sandbox");
    let data_dir = smoke_data_dir(&sandbox);
    std::fs::create_dir_all(&data_dir).expect("create smoke data dir");
    let mut cleanup = SessionCleanup::new(&data_dir);
    let compile_out = sandbox.path().join("hello-app");
    let app_path = Path::new(HELLO_APP_PATH);
    assert!(
        app_path.is_file(),
        "hello-app fixture missing at {}",
        app_path.display()
    );

    let compile = mvmctl_with_target_path()
        .env("HOME", &data_dir)
        .env("MVM_HOME", &data_dir)
        .args([
            "build",
            "compile",
            app_path.to_str().expect("hello-app path utf-8"),
            "--out",
            compile_out.to_str().expect("compile out utf-8"),
        ])
        .output()
        .expect("spawn mvmctl build compile hello-app");
    let compile_stdout = String::from_utf8_lossy(&compile.stdout);
    let compile_stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        compile.status.success(),
        "mvmctl build compile failed with {:?}\nstdout:\n{compile_stdout}\nstderr:\n{compile_stderr}",
        compile.status.code()
    );

    let run = run_with_stdin(
        mvmctl_with_target_path()
            .env("HOME", &data_dir)
            .env("MVM_HOME", &data_dir)
            .env("MVM_HYPERVISOR", "hvf")
            .args([
                "machine",
                "run",
                "--flake",
                compile_out.to_str().expect("compile out utf-8"),
                "--entrypoint",
                "-d",
                "--agent-verb",
                "ping",
                "--agent-verb",
                "run-entrypoint",
            ]),
        HELLO_APP_ARGV.as_bytes(),
        "spawn mvmctl machine run --entrypoint",
    );
    let run_stdout = String::from_utf8_lossy(&run.stdout);
    let run_stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "machine run --entrypoint failed with {:?}\nstdout:\n{run_stdout}\nstderr:\n{run_stderr}",
        run.status.code()
    );
    let run_combined = format!("{run_stdout}\n{run_stderr}");
    assert!(
        run_combined.contains("\"hello ari\""),
        "listed RunEntrypoint witness missing hello-app output.\nstdout:\n{run_stdout}\nstderr:\n{run_stderr}"
    );
    let session_id = kept_alive_session_id(&run_combined)
        .expect("machine run --entrypoint -d must print the kept-alive session id")
        .to_string();
    cleanup.arm(session_id.clone());

    let info = mvmctl_with_target_path()
        .env("HOME", &data_dir)
        .env("MVM_HOME", &data_dir)
        .args(["session", "info", &session_id])
        .output()
        .expect("spawn mvmctl session info");
    let info_stdout = String::from_utf8_lossy(&info.stdout);
    let info_stderr = String::from_utf8_lossy(&info.stderr);
    assert!(
        info.status.success(),
        "session info failed with {:?}\nstdout:\n{info_stdout}\nstderr:\n{info_stderr}",
        info.status.code()
    );
    let info_json: SessionInfo =
        serde_json::from_slice(&info.stdout).expect("parse session info json");
    let vm_name = info_json.vm_name;

    let console_log = console_log_path(&data_dir, &vm_name);
    let console = wait_for_file_contains(
        &console_log,
        VERB_GRANT_STAGED_MARKER,
        Duration::from_secs(30),
    );
    assert!(
        console.contains(VERB_GRANT_STAGED_MARKER),
        "console log missing grant staged marker {VERB_GRANT_STAGED_MARKER:?}\n{console}"
    );

    let denied = mvmctl_with_target_path()
        .env("HOME", &data_dir)
        .env("MVM_HOME", &data_dir)
        .env("MVM_HYPERVISOR", "hvf")
        .args(["machine", "set-timeout", &vm_name, "349"])
        .output()
        .expect("spawn mvmctl machine set-timeout");
    let denied_stdout = String::from_utf8_lossy(&denied.stdout);
    let denied_stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "unlisted ProdSafe verb should be denied.\nstdout:\n{denied_stdout}\nstderr:\n{denied_stderr}"
    );
    let denied_combined = format!("{denied_stdout}\n{denied_stderr}");
    assert!(
        denied_combined.contains(DENIED_VERB),
        "denial output must name the refused verb {DENIED_VERB:?}.\nstdout:\n{denied_stdout}\nstderr:\n{denied_stderr}"
    );

    let verify = mvmctl_with_target_path()
        .env("HOME", &data_dir)
        .env("MVM_HOME", &data_dir)
        .args(["trust", "audit", "verify", "--tenant", "local"])
        .output()
        .expect("spawn mvmctl trust audit verify");
    let verify_stdout = String::from_utf8_lossy(&verify.stdout);
    let verify_stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(
        verify.status.success(),
        "trust audit verify failed with {:?}\nstdout:\n{verify_stdout}\nstderr:\n{verify_stderr}",
        verify.status.code()
    );

    let workload_audit = workload_audit_path(&data_dir, &vm_name);
    let audit_contents =
        wait_for_file_contains(&workload_audit, "verb_denied", Duration::from_secs(15));
    assert!(
        audit_contents.contains(DENIED_VERB),
        "workload audit chain must carry the denied verb name.\n{audit_contents}"
    );

    let kill = mvmctl_with_target_path()
        .env("HOME", &data_dir)
        .env("MVM_HOME", &data_dir)
        .args(["session", "kill", &session_id])
        .output()
        .expect("spawn mvmctl session kill");
    assert!(
        kill.status.success(),
        "session kill cleanup failed: stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&kill.stdout),
        String::from_utf8_lossy(&kill.stderr)
    );
    cleanup.disarm();
}
