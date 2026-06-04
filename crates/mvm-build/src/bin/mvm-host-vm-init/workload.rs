//! Plan 107 A2.2 / A2.3 — spawn a workload microVM *inside* the
//! host VM on `WorkloadStart` dispatch.
//!
//! ## No VMM lock-in
//!
//! Everything VMM-specific (the config-file format, the binary
//! path, the spawn argv) lives behind the [`WorkloadVmm`] trait.
//! [`FirecrackerVmm`] is the only impl today and the only type that
//! names Firecracker; the dispatch loop, the wire protocol, and the
//! state-dir / process lifecycle are all VMM-agnostic. A second
//! backend (cloud-hypervisor, qemu-microvm) is a pure addition: a
//! new `WorkloadVmm` impl, no other changes. Mirrors the host-side
//! hypervisor-backend split in `mvm-backend/`.
//!
//! ## No serde
//!
//! Same rationale as [`crate::dispatch_response`] /
//! [`crate::builder_request`]: the Plan 72 §W3 ≤ 1.5 MiB budget
//! keeps `serde_json` out of the production rootfs, so
//! [`FirecrackerVmm::render_config`] hand-rolls the Firecracker
//! `--config-file` JSON. The `render_config_is_valid_json` test
//! parses the output with a dev-only `serde_json` to keep it honest.

use crate::dispatch_response::push_json_string;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Canonical base dir (inside the host VM) for per-workload state.
/// The host passes this as `WorkloadStart.vsock_socket_dir` in
/// production; the id-only `WorkloadStop` / `WorkloadStatus`
/// requests key off it (they carry no base). A4 formalises the
/// host→guest contract; A2 treats this const as the convention.
pub const WORKLOAD_STATE_BASE: &str = "/var/lib/mvm/workloads";

/// Path the Firecracker binary is baked at by the builder-vm flake
/// (Plan 107 A2.1 — `nix/images/builder-vm/flake.nix`).
pub const FIRECRACKER_BIN: &str = "/usr/bin/firecracker";

/// Base kernel cmdline every Firecracker workload boots with;
/// `kernel_cmdline_extras` (root=/init=/dm-verity roothash) is
/// appended by the host.
const FC_BASE_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 pci=off";

/// Guest CID the workload microVM's vsock is addressed at — mirrors
/// `mvm_guest::vsock::GUEST_CID` (hardcoded here because the guest
/// init deliberately doesn't depend on `mvm-guest`; see Cargo.toml).
const GUEST_CID: u32 = 3;

/// Generic (VMM-agnostic) spawn config — the post-parse form of
/// `mvm_build::builder_protocol::HostVmRequest::WorkloadStart`.
#[derive(Debug, Clone)]
pub struct WorkloadSpawnConfig {
    pub workload_id: String,
    pub kernel_path: String,
    pub rootfs_path: String,
    /// Base dir under which the per-workload state dir is created.
    pub vsock_socket_dir: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub kernel_cmdline_extras: String,
}

/// A VMM that can launch a workload microVM inside the host VM.
/// The swap seam that keeps mvm from being locked into Firecracker.
pub trait WorkloadVmm {
    /// Stable name for logs / status (e.g. `"firecracker"`).
    fn name(&self) -> &'static str;
    /// Render the VMM's config-file contents for this workload. The
    /// state dir supplies VMM-agnostic paths (vsock UDS, etc.).
    fn render_config(&self, cfg: &WorkloadSpawnConfig, state: &WorkloadStateDir) -> String;
    /// Build the spawn command (binary + args) given the written
    /// config-file path. `Command` is cross-platform, so this is
    /// assertable in tests without spawning.
    fn command(&self, config_path: &Path) -> Command;
}

/// Firecracker backend. The only type that names Firecracker.
#[derive(Debug, Clone, Copy, Default)]
pub struct FirecrackerVmm;

impl WorkloadVmm for FirecrackerVmm {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    fn render_config(&self, cfg: &WorkloadSpawnConfig, state: &WorkloadStateDir) -> String {
        let boot_args = if cfg.kernel_cmdline_extras.is_empty() {
            FC_BASE_CMDLINE.to_string()
        } else {
            format!("{FC_BASE_CMDLINE} {}", cfg.kernel_cmdline_extras)
        };
        let vsock_uds = state.vsock_path();
        let vsock_uds = vsock_uds.to_string_lossy();

        // Hand-rolled to mirror `mvm_build::firecracker`'s
        // `--config-file` shape: boot-source + a single root drive +
        // machine-config + vsock. Field order is cosmetic (the
        // Firecracker config parser is order-insensitive).
        let mut out = String::with_capacity(512);
        out.push_str(r#"{"boot-source":{"kernel_image_path":""#);
        push_json_string(&mut out, &cfg.kernel_path);
        out.push_str(r#"","boot_args":""#);
        push_json_string(&mut out, &boot_args);
        out.push_str(r#""},"drives":[{"drive_id":"rootfs","path_on_host":""#);
        push_json_string(&mut out, &cfg.rootfs_path);
        out.push_str(
            r#"","is_root_device":true,"is_read_only":false}],"machine-config":{"vcpu_count":"#,
        );
        out.push_str(&cfg.vcpus.to_string());
        out.push_str(r#","mem_size_mib":"#);
        out.push_str(&cfg.memory_mib.to_string());
        out.push_str(r#"},"vsock":{"vsock_id":"vsock0","guest_cid":"#);
        out.push_str(&GUEST_CID.to_string());
        out.push_str(r#","uds_path":""#);
        push_json_string(&mut out, &vsock_uds);
        out.push_str(r#""}}"#);
        out
    }

    fn command(&self, config_path: &Path) -> Command {
        let mut cmd = Command::new(FIRECRACKER_BIN);
        // `--no-api`: boot the microVM straight from the config file
        // and run without the HTTP API server. Without it, Firecracker
        // tries to bind its API socket at a default (privileged) path
        // and dies with EACCES before booting the guest. We never use
        // the API — lifecycle is the config-file boot + SIGTERM
        // (`stop_workload`), not API calls. A4 can add `--api-sock`
        // (mutually exclusive with `--no-api`) if it needs live
        // control.
        cmd.arg("--no-api").arg("--config-file").arg(config_path);
        cmd
    }
}

/// Per-workload state dir (Plan 107 A2.3):
/// `<base>/<workload_id>/` holding `config.json`, `fc.pid`,
/// `fc.stdout.log`, `fc.stderr.log`, and the `v.sock` vsock UDS.
///
/// On creation the leaf dir uses `create_dir` (not `create_dir_all`)
/// so a duplicate `workload_id` fails closed as a collision. The
/// `Drop` impl removes the dir so a panic mid-spawn doesn't leak;
/// [`WorkloadStateDir::persist`] disarms that once the workload is
/// successfully running and the dir must outlive this scope.
#[derive(Debug)]
pub struct WorkloadStateDir {
    path: PathBuf,
    cleanup_on_drop: bool,
}

impl WorkloadStateDir {
    /// Create `<base>/<workload_id>/`. Fails closed if the leaf
    /// already exists (workload-id collision).
    pub fn create(base: &Path, workload_id: &str) -> io::Result<Self> {
        fs::create_dir_all(base)?;
        let path = base.join(workload_id);
        // `create_dir` (not `_all`) so an existing dir → AlreadyExists.
        fs::create_dir(&path)?;
        Ok(Self {
            path,
            cleanup_on_drop: true,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn config_path(&self) -> PathBuf {
        self.path.join("config.json")
    }
    pub fn pid_path(&self) -> PathBuf {
        self.path.join("fc.pid")
    }
    pub fn stdout_path(&self) -> PathBuf {
        self.path.join("fc.stdout.log")
    }
    pub fn stderr_path(&self) -> PathBuf {
        self.path.join("fc.stderr.log")
    }
    pub fn vsock_path(&self) -> PathBuf {
        self.path.join("v.sock")
    }

    /// Disarm `Drop` cleanup — the workload spawned successfully, so
    /// the dir must persist for the host to reach `v.sock` / `fc.pid`.
    pub fn persist(mut self) -> PathBuf {
        self.cleanup_on_drop = false;
        self.path.clone()
    }
}

impl Drop for WorkloadStateDir {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Remove a per-workload state dir. Idempotent-ish: a missing dir is
/// not an error (already cleaned). Used by `WorkloadStop` and as the
/// final step of [`stop_workload`].
pub fn cleanup_state_dir(base: &Path, workload_id: &str) -> io::Result<()> {
    let dir = base.join(workload_id);
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Spawn a workload microVM via `vmm`, returning the spawned PID.
/// Creates the state dir, writes the rendered config, redirects the
/// VMM's stdout/stderr to log files, spawns, and records the PID.
/// On any failure the [`WorkloadStateDir`] `Drop` cleans up; on
/// success the dir is persisted for the host to reach.
pub fn start_workload(vmm: &dyn WorkloadVmm, cfg: &WorkloadSpawnConfig) -> io::Result<u32> {
    let base = PathBuf::from(&cfg.vsock_socket_dir);
    let state = WorkloadStateDir::create(&base, &cfg.workload_id)?;

    let config_json = vmm.render_config(cfg, &state);
    fs::write(state.config_path(), config_json)?;

    let stdout = fs::File::create(state.stdout_path())?;
    let stderr = fs::File::create(state.stderr_path())?;

    let config_path = state.config_path();
    let mut cmd = vmm.command(&config_path);
    cmd.stdin(std::process::Stdio::null())
        .stdout(stdout)
        .stderr(stderr);

    // spawn() returns immediately; the VMM runs as a long-lived
    // child of the dispatch loop. We never wait() on it — lifecycle
    // is tracked via the PID file + signals (stop_workload).
    let child = cmd.spawn()?;
    let pid = child.id();
    fs::write(state.pid_path(), pid.to_string())?;

    // Success — keep the state dir.
    let _ = state.persist();
    Ok(pid)
}

/// SIGTERM the workload's VMM, wait a short grace, fall back to
/// SIGKILL, then remove the state dir. Linux-only (signal syscalls).
#[cfg(target_os = "linux")]
pub fn stop_workload(base: &Path, workload_id: &str) -> io::Result<()> {
    use std::time::Duration;

    let pid_path = base.join(workload_id).join("fc.pid");
    if let Ok(pid) = fs::read_to_string(&pid_path).map(|s| s.trim().parse::<i32>()) {
        if let Ok(pid) = pid {
            // SIGTERM, then poll up to ~2s for the process to exit.
            unsafe { libc::kill(pid, libc::SIGTERM) };
            let mut exited = false;
            for _ in 0..40 {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    exited = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !exited {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
    cleanup_state_dir(base, workload_id)
}

/// Report a workload's lifecycle status: `"not_found"` (no state
/// dir), `"running"` (PID alive and vsock UDS present), or
/// `"stopped"`. Linux-only (PID liveness via `kill(pid, 0)`).
#[cfg(target_os = "linux")]
pub fn workload_status(base: &Path, workload_id: &str) -> &'static str {
    let dir = base.join(workload_id);
    if !dir.exists() {
        return "not_found";
    }
    let alive = fs::read_to_string(dir.join("fc.pid"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .map(|pid| unsafe { libc::kill(pid, 0) } == 0)
        .unwrap_or(false);
    if alive && dir.join("v.sock").exists() {
        "running"
    } else {
        "stopped"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cfg(base: &Path, id: &str) -> WorkloadSpawnConfig {
        WorkloadSpawnConfig {
            workload_id: id.to_string(),
            kernel_path: "/job/workload/vmlinux".to_string(),
            rootfs_path: "/job/workload/rootfs.ext4".to_string(),
            vsock_socket_dir: base.to_string_lossy().into_owned(),
            vcpus: 2,
            memory_mib: 1024,
            kernel_cmdline_extras: "root=/dev/vda ro init=/init".to_string(),
        }
    }

    #[test]
    fn render_config_is_valid_json_with_expected_values() {
        let tmp = tempfile::tempdir().unwrap();
        let state = WorkloadStateDir::create(tmp.path(), "wl1").unwrap();
        let cfg = sample_cfg(tmp.path(), "wl1");
        let json = FirecrackerVmm.render_config(&cfg, &state);

        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            v["boot-source"]["kernel_image_path"],
            "/job/workload/vmlinux"
        );
        assert_eq!(
            v["boot-source"]["boot_args"],
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/init"
        );
        assert_eq!(v["drives"][0]["path_on_host"], "/job/workload/rootfs.ext4");
        assert_eq!(v["drives"][0]["is_root_device"], true);
        assert_eq!(v["drives"][0]["is_read_only"], false);
        assert_eq!(v["machine-config"]["vcpu_count"], 2);
        assert_eq!(v["machine-config"]["mem_size_mib"], 1024);
        assert_eq!(v["vsock"]["guest_cid"], 3);
        assert_eq!(
            v["vsock"]["uds_path"],
            state.vsock_path().to_string_lossy().as_ref()
        );
    }

    #[test]
    fn render_config_base_cmdline_when_no_extras() {
        let tmp = tempfile::tempdir().unwrap();
        let state = WorkloadStateDir::create(tmp.path(), "wl1").unwrap();
        let mut cfg = sample_cfg(tmp.path(), "wl1");
        cfg.kernel_cmdline_extras = String::new();
        let json = FirecrackerVmm.render_config(&cfg, &state);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["boot-source"]["boot_args"],
            "console=ttyS0 reboot=k panic=1 pci=off"
        );
    }

    #[test]
    fn firecracker_command_is_config_file_invocation() {
        let cmd = FirecrackerVmm.command(Path::new("/some/config.json"));
        assert_eq!(cmd.get_program(), FIRECRACKER_BIN);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["--no-api", "--config-file", "/some/config.json"]);
        assert_eq!(FirecrackerVmm.name(), "firecracker");
    }

    #[test]
    fn state_dir_create_files_and_drop_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_path;
        {
            let state = WorkloadStateDir::create(tmp.path(), "wl1").unwrap();
            dir_path = state.path().to_path_buf();
            assert!(dir_path.is_dir());
            fs::write(state.config_path(), "{}").unwrap();
            assert!(state.config_path().exists());
            // state drops here without persist() → cleanup.
        }
        assert!(!dir_path.exists(), "Drop must remove the un-persisted dir");
    }

    #[test]
    fn state_dir_persist_disarms_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let state = WorkloadStateDir::create(tmp.path(), "wl1").unwrap();
        let path = state.persist();
        assert!(path.is_dir(), "persisted dir must survive the scope");
    }

    #[test]
    fn state_dir_create_detects_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let first = WorkloadStateDir::create(tmp.path(), "dup").unwrap();
        let second = WorkloadStateDir::create(tmp.path(), "dup");
        assert!(
            matches!(&second, Err(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "duplicate workload_id must fail closed, got {second:?}"
        );
        // The first guard must still own (and on drop clean) its dir;
        // the failed second create must not have removed it.
        assert!(first.path().is_dir());
    }

    #[test]
    fn cleanup_state_dir_is_ok_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        cleanup_state_dir(tmp.path(), "never-created").expect("missing dir is not an error");
    }

    /// Seam test — `start_workload` drives any `WorkloadVmm` without
    /// naming Firecracker. A fake VMM that spawns `/bin/true` (or a
    /// no-op on Windows) proves the lifecycle is VMM-agnostic.
    struct FakeVmm;
    impl WorkloadVmm for FakeVmm {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn render_config(&self, _cfg: &WorkloadSpawnConfig, _state: &WorkloadStateDir) -> String {
            r#"{"fake":true}"#.to_string()
        }
        fn command(&self, _config_path: &Path) -> Command {
            // A trivially-spawnable, immediately-exiting program,
            // resolved via PATH so it works on Linux and macOS
            // (`/bin/true` doesn't exist on macOS).
            if cfg!(windows) {
                let mut c = Command::new("cmd");
                c.args(["/C", "exit", "0"]);
                c
            } else {
                Command::new("true")
            }
        }
    }

    #[test]
    fn start_workload_drives_arbitrary_vmm() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = sample_cfg(tmp.path(), "wl-seam");
        let pid = start_workload(&FakeVmm, &cfg).expect("spawn fake vmm");
        assert!(pid > 0);

        let dir = tmp.path().join("wl-seam");
        assert!(dir.join("config.json").exists());
        assert_eq!(
            fs::read_to_string(dir.join("config.json")).unwrap(),
            r#"{"fake":true}"#
        );
        assert!(dir.join("fc.pid").exists());
        assert!(dir.join("fc.stdout.log").exists());
        assert!(dir.join("fc.stderr.log").exists());
        // Persisted on success — must outlive start_workload.
        assert!(dir.is_dir());
    }

    #[test]
    fn start_workload_cleans_up_on_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = sample_cfg(tmp.path(), "wl-dup");
        // Pre-create the leaf so create() collides.
        fs::create_dir_all(tmp.path().join("wl-dup")).unwrap();
        let err = start_workload(&FakeVmm, &cfg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    /// Plan 107 A2.4 — live nested-KVM smoke (runner-direct variant).
    ///
    /// Boots a **real** Firecracker workload microVM through the
    /// production [`start_workload`] + [`FirecrackerVmm`] path and
    /// asserts the kernel actually executed, then tears it down via
    /// [`stop_workload`]. This validates the A2.2/A2.3 spawn path
    /// end-to-end against a live VMM.
    ///
    /// **Scope:** the runner (or a container) stands in for the host
    /// VM, so Firecracker uses the runner's `/dev/kvm` directly (L1)
    /// — no nested KVM required, which is why it runs on a stock GHA
    /// `ubuntu-latest`. The genuine libkrun-host-VM *nesting* (L2,
    /// the no-`ptrace` trust uplift) is out of scope here and is
    /// validated by Plan 107 A4.5's live-KVM smoke on a nested-KVM
    /// runner.
    ///
    /// Inert unless `MVM_FC_BOOT_SMOKE=1` is set (so the normal
    /// `cargo test --workspace` lane skips it). The A2.4 CI lane
    /// installs `firecracker` at [`FIRECRACKER_BIN`], grants
    /// `/dev/kvm`, builds a workload kernel + rootfs, points
    /// `MVM_FC_SMOKE_KERNEL` / `MVM_FC_SMOKE_ROOTFS` at them, and
    /// sets the gate.
    ///
    /// Boot detection mirrors `mvm-backend`'s `ch-bootcheck`: poll
    /// the guest serial (Firecracker routes `ttyS0` to its stdout,
    /// which `start_workload` redirects to `fc.stdout.log`) for a
    /// kernel-boot marker. Reaching the kernel (even to a later
    /// rootfs/init failure) proves the VMM spawn path is viable; we
    /// don't require userspace.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_firecracker_boot_smoke() {
        use std::time::{Duration, Instant};

        if std::env::var("MVM_FC_BOOT_SMOKE").is_err() {
            eprintln!(
                "live_firecracker_boot_smoke: skipped (set MVM_FC_BOOT_SMOKE=1 + \
                 MVM_FC_SMOKE_KERNEL=<vmlinux> MVM_FC_SMOKE_ROOTFS=<rootfs.ext4> to run)"
            );
            return;
        }

        let kernel = std::env::var("MVM_FC_SMOKE_KERNEL")
            .expect("MVM_FC_SMOKE_KERNEL must point at a workload vmlinux");
        let rootfs = std::env::var("MVM_FC_SMOKE_ROOTFS")
            .expect("MVM_FC_SMOKE_ROOTFS must point at a workload rootfs.ext4");
        assert!(
            Path::new(&kernel).is_file(),
            "kernel artifact missing: {kernel}"
        );
        assert!(
            Path::new(&rootfs).is_file(),
            "rootfs artifact missing: {rootfs}"
        );
        assert!(
            Path::new(FIRECRACKER_BIN).exists(),
            "firecracker not installed at {FIRECRACKER_BIN}"
        );

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let workload_id = "live-smoke";
        let cfg = WorkloadSpawnConfig {
            workload_id: workload_id.to_string(),
            kernel_path: kernel,
            rootfs_path: rootfs,
            vsock_socket_dir: base.to_string_lossy().into_owned(),
            vcpus: 1,
            memory_mib: 256,
            // Mount the rootfs read-write so the kernel can at least
            // attempt to mount root; `panic=1` (in the base cmdline)
            // makes a no-init panic exit fast rather than hang.
            kernel_cmdline_extras: "root=/dev/vda rw loglevel=7".to_string(),
        };

        let pid =
            start_workload(&FirecrackerVmm, &cfg).expect("start_workload should spawn firecracker");
        eprintln!("[a2.4-smoke] spawned firecracker pid={pid}");

        let stdout_log = base.join(workload_id).join("fc.stdout.log");
        let stderr_log = base.join(workload_id).join("fc.stderr.log");

        // Poll the guest serial for a kernel-boot marker, ~30s budget.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut booted = false;
        while Instant::now() < deadline {
            let serial = fs::read_to_string(&stdout_log).unwrap_or_default();
            if serial.contains("Linux version")
                || serial.contains("Booting Linux")
                || serial.contains("Kernel panic")
                || serial.contains("Run /init as init process")
                || serial.contains("Run /sbin/init as init process")
            {
                booted = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }

        let serial_tail = {
            let s = fs::read_to_string(&stdout_log).unwrap_or_default();
            let fc_err = fs::read_to_string(&stderr_log).unwrap_or_default();
            eprintln!("──── fc.stderr ────\n{}\n──── end ────", fc_err.trim_end());
            let tail = if s.len() > 2048 {
                &s[s.len() - 2048..]
            } else {
                &s
            };
            tail.to_string()
        };
        eprintln!("──── guest serial tail ────\n{serial_tail}\n──── end ────");

        // Tear down before asserting so a failure doesn't leak the VM.
        let stop = stop_workload(base, workload_id);
        assert!(
            !base.join(workload_id).exists(),
            "stop_workload must remove the state dir"
        );
        stop.expect("stop_workload should succeed");

        assert!(
            booted,
            "no kernel-boot marker on guest serial within 30s — \
             firecracker rejected the config or never started the guest \
             (see fc.stderr above)"
        );
    }
}
