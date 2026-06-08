//! Plan 152 WS-B parity gate — Swift vs Rust `mvm-vz-supervisor`.
//!
//! The mandatory gate that must be green **before** the Swift supervisor
//! (`crates/mvm-vz-supervisor/`) is deleted: the Rust-native objc2 supervisor
//! must match the Swift one on boot, vsock round-trip, every control verb, and
//! save/restore. This file is authored independently of the supervisor
//! implementation (Plan 152 WS-B is built on a separate branch) — the gate is
//! deliberately written by a different hand than the code it judges.
//!
//! **Why this is a subprocess harness, not a linked one.** Both supervisors are
//! standalone binaries that read a [`SupervisorConfig`] JSON on stdin. We drive
//! them as child processes resolved by path, never linking
//! `Virtualization.framework` into the test binary itself. That keeps the gate
//! runnable on a normal dev Mac: a test binary that links VZ gets SIGKILL'd by
//! the macOS codesign/amfid path (see the `mvm-backend` test caveat), so this
//! harness lives in the VZ-free `mvm-build` crate and speaks to the supervisors
//! only over stdin + the per-VM unix sockets they expose.
//!
//! **Gating.** The live comparison needs two built+signed supervisor binaries
//! and a bootable kernel+rootfs. Those come from the environment so the test is
//! a no-op skip on a machine without them (a plain `cargo test` host, CI Linux,
//! GitHub macOS runners that lack Hypervisor.framework) and runs for real on the
//! self-hosted `vz-macos-26` runner or a dev Mac that exports them:
//!
//! ```text
//! MVM_VZ_PARITY_SWIFT_BIN=/abs/path/to/swift/mvm-vz-supervisor   # tools/build.sh output
//! MVM_VZ_PARITY_RUST_BIN=/abs/path/to/rust/mvm-vz-supervisor     # cargo --bin output, codesigned
//! MVM_VZ_PARITY_KERNEL=/abs/path/to/vmlinux                      # uncompressed
//! MVM_VZ_PARITY_ROOTFS=/abs/path/to/rootfs.ext4
//! ```
//!
//! Both supervisor binaries share the name `mvm-vz-supervisor`, so they are
//! addressed by explicit path, never by name resolution.
//!
//! Slice P1 (this file): boot + graceful-stop + exit-code parity, plus the pure
//! config/contract helpers. Control-verb parity (PAUSE/RESUME/STATUS/BALLOON)
//! and save/restore parity land as the supervisor grows those surfaces.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mvm_build::vz::{DiskConfig, KernelConfig, ResourceConfig, SupervisorConfig, VsockConfig};

const SWIFT_BIN: &str = "MVM_VZ_PARITY_SWIFT_BIN";
const RUST_BIN: &str = "MVM_VZ_PARITY_RUST_BIN";
const KERNEL: &str = "MVM_VZ_PARITY_KERNEL";
const ROOTFS: &str = "MVM_VZ_PARITY_ROOTFS";

/// Default workload kernel cmdline (ADR-056 §"Kernel-cmdline lockdown"). The
/// backend constructs this; we mirror it so the gate boots the same shape the
/// real launch path does.
const DEFAULT_CMDLINE: &str = "console=hvc0 root=/dev/vda rw init=/init";

/// Build the minimal bootable [`SupervisorConfig`] both supervisors must accept
/// identically: one rootfs disk, a vsock device, capture-only console, a control
/// socket, no network (the smallest config that still exercises the full boot
/// path). `state_dir` is the per-run scratch directory; all socket/pid/console
/// paths hang off it so two supervisors never collide.
fn build_boot_config(name: &str, kernel: &str, rootfs: &str, state_dir: &Path) -> SupervisorConfig {
    SupervisorConfig {
        name: name.to_string(),
        vm_state_dir: state_dir.to_string_lossy().into_owned(),
        pid_file_name: Some("vz.pid".to_string()),
        kernel: KernelConfig {
            path: kernel.to_string(),
            cmdline: DEFAULT_CMDLINE.to_string(),
            initrd_path: None,
        },
        resources: ResourceConfig {
            cpu_count: 1,
            memory_mib: 512,
        },
        disks: vec![DiskConfig {
            id: "rootfs".to_string(),
            path: rootfs.to_string(),
            read_only: false,
        }],
        virtio_fs: Vec::new(),
        vsock: VsockConfig {
            ports: vec![5252],
            socket_dir: state_dir.join("vsock").to_string_lossy().into_owned(),
        },
        console_output_path: Some(state_dir.join("console.log").to_string_lossy().into_owned()),
        network: None,
        balloon: None,
        control_socket_path: Some(
            state_dir
                .join("control.sock")
                .to_string_lossy()
                .into_owned(),
        ),
        startup_mode: Default::default(),
    }
}

/// One control-socket round-trip: write `verb\n`, read one line back. A
/// std-only reimplementation of `mvm_backend::vz_control::send_command` so this
/// VZ-free crate doesn't pull in `mvm-backend` (and its VZ link) just to talk to
/// a unix socket. Rejects an embedded newline before connecting — a verb with a
/// `\n` would be read as two commands.
fn send_command(socket: &Path, verb: &str) -> std::io::Result<String> {
    if verb.contains('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control verb must not contain a newline",
        ));
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(format!("{verb}\n").as_bytes())?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Observable outcome of booting one supervisor and asking it to stop. The two
/// supervisors must agree on every field.
#[derive(Debug, PartialEq, Eq)]
struct BootOutcome {
    /// The pid file appeared and the process stayed alive — boot reached the
    /// running state. Both supervisors write the pid file once running.
    reached_running: bool,
    /// Process exit code after a graceful SIGTERM (ACPI shutdown). `None` if it
    /// had to be SIGKILL'd (never stopped on its own).
    exit_code: Option<i32>,
}

fn wait_for_file(path: &Path, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Best-effort graceful stop, then reap. SIGTERM (both supervisors map it to a
/// guest ACPI shutdown) via `/bin/kill` so this crate needs no `libc` dep; if it
/// doesn't exit within `grace`, SIGKILL via `Child::kill` and report `None`.
fn stop_and_reap(child: &mut Child, grace: Duration) -> Option<i32> {
    let pid = child.id();
    let _ = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Spawn one supervisor against a freshly-built config, wait for boot, stop it.
fn probe_boot(bin: &Path, kernel: &str, rootfs: &str, label: &str) -> std::io::Result<BootOutcome> {
    let state_dir =
        std::env::temp_dir().join(format!("mvm-vz-parity-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&state_dir)?;
    let config = build_boot_config(label, kernel, rootfs, &state_dir);
    let json = config.to_json().expect("serialize SupervisorConfig");

    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("supervisor stdin piped")
        .write_all(json.as_bytes())?;

    let reached = wait_for_file(
        &config.resolved_pid_file(),
        Instant::now() + Duration::from_secs(30),
    );
    // If it never booted, it may still be flailing — stop it regardless.
    let exit_code = stop_and_reap(&mut child, Duration::from_secs(20));
    let _ = std::fs::remove_dir_all(&state_dir);

    Ok(BootOutcome {
        reached_running: reached,
        exit_code,
    })
}

/// Returns the four live-test paths, or `None` (with an explanatory skip note)
/// when any is unset — the live gate is opt-in via environment.
fn live_env() -> Option<(PathBuf, PathBuf, String, String)> {
    let swift = std::env::var_os(SWIFT_BIN)?;
    let rust = std::env::var_os(RUST_BIN)?;
    let kernel = std::env::var(KERNEL).ok()?;
    let rootfs = std::env::var(ROOTFS).ok()?;
    Some((PathBuf::from(swift), PathBuf::from(rust), kernel, rootfs))
}

// ---------------------------------------------------------------------------
// Always-on unit coverage of the pure harness pieces.
// ---------------------------------------------------------------------------

#[test]
fn boot_config_matches_the_decoded_contract() {
    let dir = Path::new("/tmp/mvm-parity-unit");
    let cfg = build_boot_config("smoke", "/k/vmlinux", "/r/rootfs.ext4", dir);
    let json = cfg.to_json().expect("serialize");

    // Round-trips through the same deny-unknown-fields decoder both supervisors
    // use, so a drift in the shared schema fails here, not at boot.
    let back: SupervisorConfig = serde_json::from_str(&json).expect("decode");
    assert_eq!(back.kernel.path, "/k/vmlinux");
    assert_eq!(back.kernel.cmdline, DEFAULT_CMDLINE);
    assert_eq!(back.disks.len(), 1);
    assert_eq!(back.disks[0].path, "/r/rootfs.ext4");
    assert_eq!(back.vsock.ports, vec![5252]);

    // Boot mode + no-network are the default-skipped shapes; both supervisors
    // must treat their absence as Boot / no NAT device.
    assert!(
        !json.contains("\"network\""),
        "no-network config must omit network"
    );
    assert!(
        !json.contains("\"startup_mode\""),
        "Boot is the default and is skipped"
    );
    assert!(json.contains("\"control_socket_path\""));
    assert_eq!(cfg.resolved_pid_file(), dir.join("vz.pid"));
}

#[test]
fn control_verb_rejects_embedded_newline() {
    // Mirror of the real client's guard: a newline would be framed as two verbs.
    let err = send_command(Path::new("/nonexistent.sock"), "PAUSE\nRESUME")
        .expect_err("newline must be rejected before connecting");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

// ---------------------------------------------------------------------------
// Live gate — skips unless both binaries + a boot artifact are exported.
// ---------------------------------------------------------------------------

#[test]
fn boot_parity_swift_vs_rust() {
    let Some((swift, rust, kernel, rootfs)) = live_env() else {
        eprintln!(
            "SKIP boot_parity_swift_vs_rust: set {SWIFT_BIN}, {RUST_BIN}, {KERNEL}, {ROOTFS} \
             to run the live Plan 152 WS-B parity gate (needs a VZ-capable host)."
        );
        return;
    };
    assert!(
        swift.is_file(),
        "{SWIFT_BIN} not a file: {}",
        swift.display()
    );
    assert!(rust.is_file(), "{RUST_BIN} not a file: {}", rust.display());

    let swift_outcome = probe_boot(&swift, &kernel, &rootfs, "swift").expect("swift probe");
    let rust_outcome = probe_boot(&rust, &kernel, &rootfs, "rust").expect("rust probe");

    assert!(
        swift_outcome.reached_running,
        "Swift supervisor failed to reach running — fix the fixture before judging parity"
    );
    assert_eq!(
        rust_outcome, swift_outcome,
        "Rust supervisor diverged from Swift on boot/exit: rust={rust_outcome:?} swift={swift_outcome:?}"
    );
}
