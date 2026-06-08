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
//! Slices: P1 boot + graceful-stop + exit-code parity; P2 vsock proxy round-trip
//! parity (identical request bytes → identical reply bytes through each
//! supervisor's per-port proxy); P3 control-verb parity (STATUS/PAUSE/RESUME
//! replies match step-for-step); P4 save/restore parity (`SAVE` a snapshot, then
//! restore it in a fresh supervisor). P3/P4 are staged ahead of the Rust control
//! socket + snapshot slices, so they report the gap until those land. Plus the
//! pure config/contract/round-trip/codec helpers. (BALLOON joins P3 once the
//! boot config carries a balloon device.)

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mvm_build::vz::{
    DiskConfig, KernelConfig, ResourceConfig, StartupMode, SupervisorConfig, VsockConfig,
};

const SWIFT_BIN: &str = "MVM_VZ_PARITY_SWIFT_BIN";
const RUST_BIN: &str = "MVM_VZ_PARITY_RUST_BIN";
const KERNEL: &str = "MVM_VZ_PARITY_KERNEL";
const ROOTFS: &str = "MVM_VZ_PARITY_ROOTFS";
/// Guest vsock port to round-trip through the proxy (default 5252, the agent).
const VSOCK_PORT: &str = "MVM_VZ_PARITY_VSOCK_PORT";
/// Path to a file of request bytes the guest answers on that port (e.g. a
/// captured agent ping). The gate stays protocol-agnostic — it asserts the two
/// supervisors return *identical* replies to identical bytes, not what the bytes
/// mean. Without it the vsock round-trip parity test skips.
const VSOCK_REQUEST: &str = "MVM_VZ_PARITY_VSOCK_REQUEST";

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

/// Connect to a host-side proxy unix socket, send `request`, and read the reply
/// until the peer closes or goes idle for `idle`. Returns the accumulated bytes.
/// Protocol-agnostic on purpose: vsock round-trip parity asserts identical bytes
/// out for identical bytes in under both supervisors, without encoding the agent
/// wire format (that's `mvm-guest`'s concern and would couple the gate to drift).
fn proxy_roundtrip(socket: &Path, request: &[u8], idle: Duration) -> std::io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(idle))?;
    stream.set_read_timeout(Some(idle))?;
    stream.write_all(request)?;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break, // peer closed
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            // Idle for `idle` (first byte never came, or the framed reply is
            // complete and the agent left the connection open) — return what we
            // have.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
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

/// Unique per-run scratch state dir for a supervisor under test.
fn make_state_dir(label: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("mvm-vz-parity-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Spawn a supervisor with `config` piped to stdin. stdout/stderr are silenced —
/// the gate judges observable side effects (pid file, sockets, exit code), not
/// logs.
fn spawn_with_config(bin: &Path, config: &SupervisorConfig) -> std::io::Result<Child> {
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
    Ok(child)
}

/// Copy the source rootfs into `state_dir` as a writable image and return its
/// path. Vz refuses a read-write disk attachment backed by a read-only file (the
/// cached artifacts are mode 0444 → "storage device attachment is invalid"), and
/// two supervisors must never share one mutable disk — so each probe boots from
/// its own copy.
fn writable_rootfs(state_dir: &Path, src: &str) -> std::io::Result<String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(state_dir)?;
    let dst = state_dir.join("rootfs.ext4");
    std::fs::copy(src, &dst)?;
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o644))?;
    Ok(dst.to_string_lossy().into_owned())
}

/// Poll the supervisor's control socket until STATUS reports the guest running,
/// or the deadline passes. Symmetric across supervisors (both bind the control
/// socket and answer STATUS) — unlike the pid file, whose write timing differs
/// (Swift writes it before start, the Rust supervisor after), which skews a
/// pid-based "reached running" signal on the failure path.
fn wait_for_running(control_sock: &Path, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if control_sock.exists()
            && let Ok(resp) = send_command(control_sock, "STATUS")
            && resp == "OK running"
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Spawn one supervisor against a freshly-built config, wait for boot, stop it.
fn probe_boot(bin: &Path, kernel: &str, rootfs: &str, label: &str) -> std::io::Result<BootOutcome> {
    let state_dir = make_state_dir(label)?;
    let rootfs_copy = writable_rootfs(&state_dir, rootfs)?;
    let config = build_boot_config(label, kernel, &rootfs_copy, &state_dir);
    let control_sock = config
        .control_socket_path
        .as_ref()
        .map(PathBuf::from)
        .expect("boot config sets a control socket path");
    let mut child = spawn_with_config(bin, &config)?;

    let reached = wait_for_running(&control_sock, Instant::now() + Duration::from_secs(30));
    // Stop regardless — if it never reached running it may still be flailing.
    let exit_code = stop_and_reap(&mut child, Duration::from_secs(20));
    let _ = std::fs::remove_dir_all(&state_dir);

    Ok(BootOutcome {
        reached_running: reached,
        exit_code,
    })
}

/// Boot one supervisor, wait for the per-port `vsock-<port>.sock` to appear,
/// dial it through the proxy, send `request`, read the guest's reply, then stop.
/// Returns the reply bytes, or `None` if the proxy socket never appeared or the
/// guest sent nothing — both parity failures the caller asserts on.
fn probe_vsock_roundtrip(
    bin: &Path,
    kernel: &str,
    rootfs: &str,
    port: u32,
    request: &[u8],
    label: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    let state_dir = make_state_dir(label)?;
    let rootfs_copy = writable_rootfs(&state_dir, rootfs)?;
    let config = build_boot_config(label, kernel, &rootfs_copy, &state_dir);
    let control_sock = config
        .control_socket_path
        .as_ref()
        .map(PathBuf::from)
        .expect("boot config sets a control socket path");
    let mut child = spawn_with_config(bin, &config)?;

    let booted = wait_for_running(&control_sock, Instant::now() + Duration::from_secs(30));
    let proxy_sock = Path::new(&config.vsock.socket_dir).join(format!("vsock-{port}.sock"));
    let proxy_ready =
        booted && wait_for_file(&proxy_sock, Instant::now() + Duration::from_secs(10));

    let reply = if proxy_ready {
        proxy_roundtrip(&proxy_sock, request, Duration::from_secs(5)).ok()
    } else {
        None
    };

    let _ = stop_and_reap(&mut child, Duration::from_secs(20));
    let _ = std::fs::remove_dir_all(&state_dir);
    Ok(reply.filter(|r| !r.is_empty()))
}

/// Boot one supervisor, wait for its control socket, send each verb in `verbs`
/// in order, and return the per-verb replies (`None` for a verb that errored, or
/// for a supervisor that never bound the control socket), then stop. Until the
/// Rust supervisor grows a control socket this returns all-`None` for it, so the
/// parity assertion correctly reports the divergence.
fn probe_control_verbs(
    bin: &Path,
    kernel: &str,
    rootfs: &str,
    verbs: &[&str],
    label: &str,
) -> std::io::Result<Vec<Option<String>>> {
    let state_dir = make_state_dir(label)?;
    let rootfs_copy = writable_rootfs(&state_dir, rootfs)?;
    let config = build_boot_config(label, kernel, &rootfs_copy, &state_dir);
    let control_sock = config
        .control_socket_path
        .as_ref()
        .map(PathBuf::from)
        .expect("boot config sets a control socket path");
    let mut child = spawn_with_config(bin, &config)?;

    let control_ready = wait_for_running(&control_sock, Instant::now() + Duration::from_secs(30));

    let replies = verbs
        .iter()
        .map(|verb| {
            if control_ready {
                send_command(&control_sock, verb).ok()
            } else {
                None
            }
        })
        .collect();

    let _ = stop_and_reap(&mut child, Duration::from_secs(20));
    let _ = std::fs::remove_dir_all(&state_dir);
    Ok(replies)
}

/// Observable outcome of a save→restore round-trip. Both supervisors must agree.
#[derive(Debug, PartialEq, Eq)]
struct SaveRestoreOutcome {
    /// Reply to `SAVE <path>` (`"OK"` on success), or `None` if the control
    /// socket never bound.
    save_reply: Option<String>,
    /// The snapshot blob materialized on disk.
    snapshot_written: bool,
    /// The `<snapshot>.machine-id` sidecar materialized (identity continuity).
    sidecar_written: bool,
    /// A fresh supervisor in `Restore` mode reached running from the snapshot.
    restore_reached_running: bool,
}

/// Save/restore parity: boot one supervisor, `SAVE` a snapshot, stop it, then
/// spawn a fresh supervisor in `Restore` mode against that snapshot and check it
/// reaches running. Contract per ADR-056 / `vz.rs`: `SAVE <path>` is a control
/// verb that also writes a `<path>.machine-id` sidecar; RESTORE is a *startup
/// mode*, not a verb. Staged ahead of the Rust snapshot slice → all-negative for
/// it until that lands, so the parity assertion reports the gap. The phases use
/// separate `boot/` and `restore/` state subdirs so their sockets/pid files
/// don't collide; the snapshot lives in the shared parent.
fn probe_save_restore(
    bin: &Path,
    kernel: &str,
    rootfs: &str,
    label: &str,
) -> std::io::Result<SaveRestoreOutcome> {
    let root = make_state_dir(label)?;
    let snapshot = root.join("snapshot.vzstate");
    let machine_id = root.join("snapshot.vzstate.machine-id");

    // Phase 1 — boot, SAVE, stop. Its writable rootfs copy is reused by the
    // restore phase so the restored memory state matches the disk it saw.
    let rootfs_copy = writable_rootfs(&root.join("boot"), rootfs)?;
    let boot_cfg = build_boot_config(label, kernel, &rootfs_copy, &root.join("boot"));
    let control_sock = boot_cfg
        .control_socket_path
        .as_ref()
        .map(PathBuf::from)
        .expect("boot config sets a control socket path");
    let mut child = spawn_with_config(bin, &boot_cfg)?;
    let control_ready = wait_for_running(&control_sock, Instant::now() + Duration::from_secs(30));
    let save_reply = if control_ready {
        send_command(&control_sock, &format!("SAVE {}", snapshot.display())).ok()
    } else {
        None
    };
    let _ = stop_and_reap(&mut child, Duration::from_secs(20));
    let snapshot_written = snapshot.exists();
    let sidecar_written = machine_id.exists();

    // Phase 2 — restore in a fresh supervisor against the same disk copy.
    let restore_reached_running = if snapshot_written {
        let restore_dir = root.join("restore");
        let mut restore_cfg = build_boot_config(label, kernel, &rootfs_copy, &restore_dir);
        restore_cfg.startup_mode = StartupMode::Restore {
            snapshot_path: snapshot.to_string_lossy().into_owned(),
            machine_id_path: Some(machine_id.to_string_lossy().into_owned()),
        };
        let restore_control = restore_cfg
            .control_socket_path
            .as_ref()
            .map(PathBuf::from)
            .expect("restore config sets a control socket path");
        let mut rchild = spawn_with_config(bin, &restore_cfg)?;
        let reached = wait_for_running(&restore_control, Instant::now() + Duration::from_secs(30));
        let _ = stop_and_reap(&mut rchild, Duration::from_secs(20));
        reached
    } else {
        false
    };

    let _ = std::fs::remove_dir_all(&root);
    Ok(SaveRestoreOutcome {
        save_reply,
        snapshot_written,
        sidecar_written,
        restore_reached_running,
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

#[test]
fn proxy_roundtrip_reads_the_peer_reply() {
    // Exercises the round-trip helper end-to-end against a fake peer (no VZ):
    // request goes out, the peer's reply comes back verbatim.
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("mvm-parity-rt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("echo.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut got = [0u8; 4];
            let _ = conn.read_exact(&mut got);
            let _ = conn.write_all(b"PONG");
            // drop closes the connection → the client's read returns 0.
        }
    });
    let reply = proxy_roundtrip(&sock, b"PING", Duration::from_secs(5)).unwrap();
    assert_eq!(reply, b"PONG");
    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn send_command_reads_one_newline_framed_reply() {
    // Validates the control-verb codec (write `verb\n`, read one line, strip the
    // newline) against a fake control server — the wire both supervisors speak.
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("mvm-parity-ctl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("control.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut b = [0u8; 1];
            while let Ok(1) = conn.read(&mut b) {
                if b[0] == b'\n' {
                    break;
                }
            }
            let _ = conn.write_all(b"OK running\n");
        }
    });
    let resp = send_command(&sock, "STATUS").unwrap();
    assert_eq!(resp, "OK running");
    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restore_config_round_trips_as_restore_mode() {
    // The Restore startup mode must survive the shared deny-unknown-fields
    // decoder both supervisors use — drift in the snapshot contract fails here.
    let dir = Path::new("/tmp/mvm-parity-restore-unit");
    let mut cfg = build_boot_config("snap", "/k/vmlinux", "/r/rootfs.ext4", dir);
    cfg.startup_mode = StartupMode::Restore {
        snapshot_path: "/abs/snap.vzstate".into(),
        machine_id_path: Some("/abs/snap.vzstate.machine-id".into()),
    };
    let json = cfg.to_json().expect("serialize");
    let back: SupervisorConfig = serde_json::from_str(&json).expect("decode");
    assert!(
        matches!(back.startup_mode, StartupMode::Restore { .. }),
        "restore config must decode as Restore mode"
    );
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

#[test]
fn vsock_roundtrip_parity_swift_vs_rust() {
    let Some((swift, rust, kernel, rootfs)) = live_env() else {
        eprintln!(
            "SKIP vsock_roundtrip_parity_swift_vs_rust: set {SWIFT_BIN}, {RUST_BIN}, {KERNEL}, \
             {ROOTFS} (+ {VSOCK_REQUEST}) to run the live vsock proxy parity gate."
        );
        return;
    };
    let Some(request_path) = std::env::var_os(VSOCK_REQUEST) else {
        eprintln!(
            "SKIP vsock_roundtrip_parity_swift_vs_rust: set {VSOCK_REQUEST} to a file of request \
             bytes the guest agent answers on the vsock port (e.g. a captured agent ping)."
        );
        return;
    };
    let request = std::fs::read(&request_path).expect("read vsock request fixture");
    let port: u32 = std::env::var(VSOCK_PORT)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5252);

    let swift_reply = probe_vsock_roundtrip(&swift, &kernel, &rootfs, port, &request, "swift")
        .expect("swift probe");
    let rust_reply =
        probe_vsock_roundtrip(&rust, &kernel, &rootfs, port, &request, "rust").expect("rust probe");

    assert!(
        swift_reply.is_some(),
        "Swift supervisor returned no vsock reply on port {port} — fix the fixture/agent before \
         judging parity"
    );
    assert_eq!(
        rust_reply, swift_reply,
        "Rust supervisor diverged from Swift on the vsock round-trip (port {port})"
    );
}

#[test]
fn control_verb_parity_swift_vs_rust() {
    let Some((swift, rust, kernel, rootfs)) = live_env() else {
        eprintln!(
            "SKIP control_verb_parity_swift_vs_rust: set {SWIFT_BIN}, {RUST_BIN}, {KERNEL}, \
             {ROOTFS} to run the live control-verb parity gate."
        );
        return;
    };
    // Stateful but symmetric: both supervisors get the same sequence, so the
    // replies must match step-for-step. BALLOON/SAVE/RESTORE join once the boot
    // config carries a balloon device and the save/restore slice lands.
    let verbs = ["STATUS", "PAUSE", "RESUME", "STATUS"];
    let swift_replies =
        probe_control_verbs(&swift, &kernel, &rootfs, &verbs, "swift").expect("swift probe");
    let rust_replies =
        probe_control_verbs(&rust, &kernel, &rootfs, &verbs, "rust").expect("rust probe");

    assert!(
        swift_replies.iter().any(Option::is_some),
        "Swift supervisor answered no control verbs — fix the fixture before judging parity"
    );
    assert_eq!(
        rust_replies, swift_replies,
        "Rust supervisor diverged from Swift on control verbs: rust={rust_replies:?} \
         swift={swift_replies:?}"
    );
}

#[test]
fn save_restore_parity_swift_vs_rust() {
    let Some((swift, rust, kernel, rootfs)) = live_env() else {
        eprintln!(
            "SKIP save_restore_parity_swift_vs_rust: set {SWIFT_BIN}, {RUST_BIN}, {KERNEL}, \
             {ROOTFS} to run the live save/restore parity gate (macOS 14+)."
        );
        return;
    };
    let swift_outcome = probe_save_restore(&swift, &kernel, &rootfs, "swift").expect("swift probe");
    let rust_outcome = probe_save_restore(&rust, &kernel, &rootfs, "rust").expect("rust probe");

    assert!(
        swift_outcome.snapshot_written && swift_outcome.restore_reached_running,
        "Swift supervisor could not save+restore — fix the fixture (macOS 14+?) before judging \
         parity: {swift_outcome:?}"
    );
    assert_eq!(
        rust_outcome, swift_outcome,
        "Rust supervisor diverged from Swift on save/restore: rust={rust_outcome:?} \
         swift={swift_outcome:?}"
    );
}
