//! Apple Container dev environment + bundled image fetching.
//!
//! Extracted from `commands/mod.rs` as a pure mechanical refactor —
//! no behavior changes.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use mvm::vsock_transport::{VsockProxyTransport, VsockTransport};

use super::super::vm::console::console_interactive;
use crate::ui;

// ============================================================================
// Apple Container dev environment
// ============================================================================

pub(super) const DEV_VM_NAME: &str = "mvm-dev";
const BUILDER_VM_SOURCE_FINGERPRINT_FILE: &str = ".mvm-source.sha256";
const BUILDER_VM_ARTIFACT_DIGEST_FILE: &str = ".mvm-artifacts.sha256";
const BUILDER_VM_PROVENANCE_FILE: &str = ".mvm-provenance.json";
/// Heuristic needle for `rootfs_contains_builder_init`. We used to scan
/// for the contiguous bytes `/sbin/mvm-host-vm-init`, but ext4 stores
/// each path component as a separate dirent — `sbin` and
/// `mvm-host-vm-init` are never adjacent in the raw image — so a
/// freshly-built rootfs that *has* the binary at `/sbin/mvm-host-vm-init`
/// would fail the check. The basename `mvm-host-vm-init` is what
/// actually appears in the dirent (one of the file's `/etc/.../...`
/// references is the embedded debug strings inside the Rust binary
/// itself). The dev-prebuilt seed image case continues to work because
/// the basename appears there too. False-positive risk is negligible:
/// nothing else in the rootfs is named exactly `mvm-host-vm-init`.
const HOST_VM_INIT_PATH: &[u8] = b"mvm-host-vm-init";

/// Check if the Apple Container dev VM is running *and* reachable
/// cross-process via the vsock proxy socket.
///
/// A live PID file alone is not enough — the daemon may have started but
/// failed to materialize the proxy socket, in which case `run_in_vm` calls
/// from other processes will fail. Treating that state as "not running"
/// keeps `dev status` honest with what `shell::run_in_vm` actually sees.
pub(in crate::commands) fn is_apple_container_dev_running() -> bool {
    let pid_running = mvm_providers::apple_container::list_ids()
        .iter()
        .any(|id| id == DEV_VM_NAME);
    if !pid_running {
        return false;
    }
    let proxy = mvm_providers::apple_container::vsock_proxy_path(DEV_VM_NAME);
    proxy.exists()
}

/// Boot the Apple Container dev VM, optionally opening an interactive console.
pub(super) fn cmd_dev_apple_container(cpus: u32, memory_gib: u32, open_shell: bool) -> Result<()> {
    let is_daemon = std::env::var("MVM_DEV_DAEMON").as_deref() == Ok("1");

    // When running as the daemon process, do the actual VM boot.
    if is_daemon {
        return cmd_dev_apple_container_daemon(cpus, memory_gib);
    }

    ui::progress("Starting dev environment via Apple Container...");

    if is_apple_container_dev_running() {
        if open_shell {
            ui::progress("Dev VM already running. Opening shell...");
            return console_interactive(DEV_VM_NAME);
        }
        ui::progress("Dev VM already running.");
        return Ok(());
    }

    // Clean up stale state from a previous process that died.
    cleanup_stale_dev_vm();

    // Ensure dev image exists (build if needed — this runs in the CLI process)
    let (kernel, rootfs) = ensure_dev_image()?;

    // ADR-002 W1.5: lock ~/.mvm and ~/.cache/mvm to 0700 on every
    // `dev up`. Idempotent — a fresh install creates them locked-
    // down, and a host that pre-dates this change gets chmod'd on
    // the first `dev up` after the upgrade.
    mvm_core::config::ensure_data_dir().with_context(|| "locking down data dir to mode 0700")?;
    mvm_core::config::ensure_cache_dir().with_context(|| "locking down cache dir to mode 0700")?;

    // Launch a background daemon process that keeps the VM alive.
    let exe = std::env::current_exe().context("cannot find current executable")?;
    let log_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&log_dir)?;

    // Truncate previous-run daemon logs. launchd doesn't rotate, and
    // the daemon writes every guest-agent stdout/stderr there, so
    // these grow without bound. Each `dev up` is a logical session
    // boundary — losing prior logs is fine; preserving them forever
    // is the wrong default.
    //
    // ADR-002 W1.4: the daemon logs capture guest output the same way
    // console.log does — they are mode 0600 so a same-host other user
    // can't tail them. The truncate-on-each-up cadence is unchanged.
    use std::os::unix::fs::OpenOptionsExt as _;
    for name in ["daemon-stdout.log", "daemon-stderr.log"] {
        let path = format!("{log_dir}/{name}");
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .mode(0o600)
            .open(&path);
    }

    // Sign the binary BEFORE launching via launchd. The daemon runs with
    // MVM_SIGNED=1 so it won't re-exec (which would lose launchd context).
    mvm_providers::apple_container::ensure_signed();

    // The host-backed Nix store is a sparse ext4 file at a stable
    // path. Apple Container attaches it as /dev/vdb; the guest's init
    // mkfs's it once and uses it as overlayfs upper over the rootfs's
    // /nix. Persisted under the data dir (not the cache dir) so
    // `dev down --reset` doesn't wipe it — populated build cache
    // survives image rebuilds, since image staleness and store
    // staleness are independent concerns.
    //
    // The parent process only ensures the parent dir exists; the
    // sparse file itself is created in start_vm if missing.
    let nix_store_disk = nix_store_disk_path();
    if let Some(parent) = std::path::Path::new(&nix_store_disk).parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("creating host-backed Nix store parent {}", parent.display())
        })?;
    }
    maybe_gc_host_nix_disk(&nix_store_disk);

    ui::info(&format!(
        "Booting dev VM ({} vCPUs, {} GiB memory)...",
        cpus, memory_gib
    ));

    // Install a launchd agent to run the daemon. This is a proper macOS
    // service that is cleanly unloaded by `dev down`.
    install_dev_launchd_agent(&exe, &kernel, &rootfs, cpus, memory_gib, &log_dir)?;

    // Wait for the VM to become ready (vsock proxy socket + guest agent reachable)
    let proxy_path = dev_vsock_proxy_path();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "Dev VM did not start within 60 seconds.\n\
                           Check logs: {log_dir}/daemon-stderr.log"
            );
        }
        if std::path::Path::new(&proxy_path).exists()
            && VsockProxyTransport::new(proxy_path.clone())
                .connect(mvm_guest::vsock::GUEST_AGENT_PORT)
                .is_ok()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    ui::success("Dev VM ready.");
    ui::info("  Shell:      mvmctl dev shell");
    ui::info("  Stop VM:    mvmctl dev down");

    if open_shell {
        ui::info("");
        let _ = console_interactive(DEV_VM_NAME);
    }

    Ok(())
}

/// Path for the vsock proxy Unix socket.
pub(in crate::commands) fn dev_vsock_proxy_path() -> String {
    mvm_providers::apple_container::vsock_proxy_path(DEV_VM_NAME)
        .to_string_lossy()
        .into_owned()
}

/// Daemon mode: boot the VM (which also publishes the vsock proxy socket)
/// and block forever so the in-process VZVirtualMachine stays alive.
fn cmd_dev_apple_container_daemon(cpus: u32, memory_gib: u32) -> Result<()> {
    let kernel = std::env::var("MVM_DEV_KERNEL")
        .unwrap_or_else(|_| format!("{}/dev/vmlinux", mvm_core::config::mvm_cache_dir()));
    let rootfs = std::env::var("MVM_DEV_ROOTFS")
        .unwrap_or_else(|_| format!("{}/dev/rootfs.ext4", mvm_core::config::mvm_cache_dir()));

    let memory_mib = (memory_gib as u64) * 1024;
    mvm_providers::apple_container::start(DEV_VM_NAME, &kernel, &rootfs, cpus, memory_mib)
        .map_err(|e| anyhow::anyhow!("Failed to start dev VM: {e}"))?;

    // Block forever — the VM lives in this process.
    loop {
        std::thread::park();
    }
}

/// Path to the sparse ext4 file that backs the dev VM's Nix store
/// upper layer. Lives outside the cache dir so `dev down --reset`
/// doesn't churn it.
fn nix_store_disk_path() -> String {
    format!("{}/dev/nix-store.img", mvm_core::config::mvm_data_dir())
}

/// Threshold above which `dev up` invokes the in-VM GC before booting.
/// We compare against the sparse file's *materialised* (allocated) size
/// on the host, not its logical size — the file is provisioned at 64
/// GiB but only consumes blocks for actual writes. 20 GiB allocated is
/// comfortably above a typical Rust/Python toolchain closure (~3-6 GiB)
/// and well below the point where the host disk feels strained.
const NIX_STORE_GC_THRESHOLD_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// Run `nix-collect-garbage --delete-older-than 14d` *inside* the dev
/// VM when the backing sparse file's allocated size crosses the
/// threshold. Running the GC inside the VM matters: the in-VM nix
/// owns the database and knows the GC roots; running on the host with
/// `NIX_STORE_DIR` pointed at the upper layer would skip locks and
/// could corrupt the store mid-build. Best-effort — failure is logged
/// and the boot proceeds.
fn maybe_gc_host_nix_disk(disk_path: &str) {
    let Ok(meta) = std::fs::metadata(disk_path) else {
        return;
    };
    let allocated = file_allocated_bytes(&meta);
    if allocated < NIX_STORE_GC_THRESHOLD_BYTES {
        return;
    }
    let gib = allocated as f64 / (1024.0 * 1024.0 * 1024.0);
    ui::info(&format!(
        "Host-backed Nix store ({disk_path}) using {gib:.1} GiB; \
         next dev VM boot will run nix-collect-garbage."
    ));
    // Drop a sentinel the daemon's first-build hook can spot. The
    // actual GC runs inside the VM via the dev_build pipeline; we
    // can't run it from the host (would race the in-VM nix daemon
    // and skip locks). The sentinel approach keeps the host side
    // declarative and pushes the work to where it can be done safely.
    let sentinel = format!(
        "{}/dev/nix-store-needs-gc",
        mvm_core::config::mvm_data_dir()
    );
    let _ = std::fs::write(&sentinel, "");
}

/// Allocated (st_blocks * 512) bytes of a file, which for a sparse
/// file is the *materialised* size — much smaller than the logical
/// length until the file gets written into. Falls back to logical
/// length on platforms without st_blocks.
#[cfg(unix)]
fn file_allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    meta.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn file_allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

const DEV_LAUNCHD_LABEL: &str = "com.mvm.dev";

fn dev_launchd_plist_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(format!(
        "{home}/Library/LaunchAgents/{DEV_LAUNCHD_LABEL}.plist"
    ))
}

fn install_dev_launchd_agent(
    exe: &std::path::Path,
    kernel: &str,
    rootfs: &str,
    cpus: u32,
    memory_gib: u32,
    log_dir: &str,
) -> Result<()> {
    // Unload any previous agent first
    unload_dev_launchd_agent();

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{DEV_LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>dev</string>
        <string>up</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MVM_DEV_DAEMON</key>
        <string>1</string>
        <key>MVM_DEV_KERNEL</key>
        <string>{kernel}</string>
        <key>MVM_DEV_ROOTFS</key>
        <string>{rootfs}</string>
        <key>MVM_DEV_CPUS</key>
        <string>{cpus}</string>
        <key>MVM_DEV_MEM_GIB</key>
        <string>{memory_gib}</string>
        <key>MVM_HOST_WORKDIR</key>
        <string>{host_workdir}</string>
        <key>MVM_HOST_DATADIR</key>
        <string>{host_datadir}</string>
        <key>MVM_NIX_STORE_DISK</key>
        <string>{nix_store_disk}</string>
        <key>MVM_SIGNED</key>
        <string>0</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{log_dir}/daemon-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/daemon-stderr.log</string>
</dict>
</plist>"#,
        exe = exe.display(),
        // Capture the user's CWD here (parent CLI process). The daemon
        // is spawned by launchd with `current_dir() == /`, so it can't
        // recover this on its own — `start_vm()` reads this env var to
        // decide where to bind-mount the virtiofs share inside the VM.
        host_workdir = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        // Persistent host-backed Nix store, sparse ext4 file. Lives
        // outside the cache dir for the dev image (which `dev down
        // --reset` blows away) so populated build cache survives image
        // rebuilds. The file is created on first VM start; the guest
        // mkfs's it the first time it sees /dev/vdb.
        nix_store_disk = nix_store_disk_path(),
        // The mvm data dir on the host ($HOME/.mvm/...). The VM
        // mounts it at the same absolute path so paths the dev_build
        // pipeline emits (e.g. ~/.mvm/dev/builds/<hash>/) resolve to
        // the same files on both sides of the VM boundary.
        host_datadir = mvm_core::config::mvm_data_dir(),
    );

    let plist_path = dev_launchd_plist_path();
    let agents_dir = plist_path.parent().expect("plist path must have parent");
    std::fs::create_dir_all(agents_dir)?;
    std::fs::write(&plist_path, &plist)?;

    let output = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap_or("")])
        .output()
        .context("Failed to run launchctl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchctl load failed: {stderr}");
    }

    Ok(())
}

fn unload_dev_launchd_agent() {
    let plist_path = dev_launchd_plist_path();
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap_or("")])
            .output();
        let _ = std::fs::remove_file(&plist_path);
    }
}

/// Kill the process that owns the dev VM and clean up its state.
fn stop_dev_vm_owner() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let vm_dir = std::path::PathBuf::from(format!("{home}/.mvm/vms/{DEV_VM_NAME}"));
    let pid_file = vm_dir.join("pid");

    if let Ok(pid_str) = std::fs::read_to_string(&pid_file)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        // Don't kill ourselves
        if pid as u32 != std::process::id() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            // Wait briefly for it to exit
            for _ in 0..20 {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let _ = std::fs::remove_dir_all(&vm_dir);
}

/// Clean up stale persisted state from a dead dev VM process.
fn cleanup_stale_dev_vm() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let vm_dir = std::path::PathBuf::from(format!("{home}/.mvm/vms/{DEV_VM_NAME}"));
    let pid_file = vm_dir.join("pid");

    if !pid_file.exists() {
        return;
    }

    let pid_str = match std::fs::read_to_string(&pid_file) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return,
    };
    let pid: i32 = match pid_str.parse() {
        Ok(p) => p,
        Err(_) => return,
    };

    // Check if the process is still alive (signal 0 = existence check)
    let alive = unsafe { libc::kill(pid, 0) } == 0;
    if alive {
        return; // process still running, not stale
    }

    ui::info("Cleaning up stale dev VM state from a previous session...");
    let _ = std::fs::remove_dir_all(&vm_dir);
}

/// Stop the Apple Container dev VM.
pub(super) fn cmd_dev_apple_container_down() -> Result<()> {
    let was_running = is_apple_container_dev_running() || dev_launchd_plist_path().exists();

    // Unload the launchd agent (stops the daemon process)
    unload_dev_launchd_agent();
    // Kill any lingering daemon process
    stop_dev_vm_owner();
    // Clean up state files
    cleanup_stale_dev_vm();
    let _ = std::fs::remove_file(dev_vsock_proxy_path());

    if was_running {
        ui::success("Dev VM stopped.");
    } else {
        ui::info("Dev VM is not running.");
    }
    Ok(())
}

/// Show Apple Container dev VM status.
pub(super) fn cmd_dev_apple_container_status() -> Result<()> {
    let running = is_apple_container_dev_running();
    ui::info("Backend:  Apple Container (Virtualization.framework)");
    ui::info(&format!("Dev VM:   {DEV_VM_NAME}"));
    ui::info(&format!(
        "Status:   {}",
        if running { "running" } else { "stopped" }
    ));

    if running
        && let Ok(mut stream) = mvm_providers::apple_container::vsock_connect_any(
            DEV_VM_NAME,
            mvm_guest::vsock::GUEST_AGENT_PORT,
        )
    {
        let req = mvm_guest::vsock::GuestRequest::Exec {
            command: "uname -r".to_string(),
            stdin: None,
            timeout_secs: Some(5),
        };
        // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit.
        super::super::shared::emit_vsock_rpc_audit(DEV_VM_NAME, &req);
        if let Ok(mvm_guest::vsock::GuestResponse::ExecResult { stdout, .. }) =
            mvm_guest::vsock::send_request(&mut stream, &req)
        {
            ui::info(&format!("  Kernel:  {}", stdout.trim()));
        }
    }

    if let Some(image) = resolve_dev_status_image() {
        ui::info("  Image:   cached");
        if let Some(kernel_path) = image.kernel_path {
            ui::info(&format!("  Kernel:  {kernel_path}"));
        }
        ui::info(&format!("  Rootfs:  {}", image.rootfs_path));
    } else {
        ui::info("  Image:   not built");
    }

    let builder_cache = resolve_builder_vm_cache_status_summary();
    ui::info(&format!(
        "  Builder: {} cache {} (reason: {})",
        builder_cache.cache_kind,
        builder_cache.state.label(),
        builder_cache.reason_code
    ));

    Ok(())
}

/// Inspect dev caches without booting, rebuilding, or exposing local
/// artifact paths/digests.
pub(super) fn cmd_dev_cache_inspect(json: bool) -> Result<()> {
    let summary = resolve_dev_cache_inspect_summary();
    if json {
        println!("{}", dev_cache_inspect_json(&summary)?);
        return Ok(());
    }

    ui::info("Dev cache:");
    ui::info(&format!(
        "  Dev image: {} (kernel: {}, rootfs: {})",
        summary.dev_image.state, summary.dev_image.kernel, summary.dev_image.rootfs
    ));
    ui::info(&format!(
        "  Builder:   {} cache {} (reason: {})",
        summary.builder_cache.cache_kind,
        summary.builder_cache.state.label(),
        summary.builder_cache.reason_code
    ));
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct DevStatusImage {
    kernel_path: Option<String>,
    rootfs_path: String,
}

fn resolve_dev_status_image() -> Option<DevStatusImage> {
    if let Some(image) = dev_launchd_image_paths()
        && std::path::Path::new(&image.rootfs_path).exists()
    {
        return Some(image);
    }

    let version = env!("CARGO_PKG_VERSION");
    for dir in [
        format!("{}/dev/current", mvm_core::config::mvm_data_dir()),
        format!(
            "{}/dev/prebuilt/v{version}",
            mvm_core::config::mvm_data_dir()
        ),
        format!("{}/dev", mvm_core::config::mvm_cache_dir()),
    ] {
        let rootfs_path = format!("{dir}/rootfs.ext4");
        if !std::path::Path::new(&rootfs_path).exists() {
            continue;
        }
        let kernel_path = format!("{dir}/vmlinux");
        return Some(DevStatusImage {
            kernel_path: std::path::Path::new(&kernel_path)
                .exists()
                .then_some(kernel_path),
            rootfs_path,
        });
    }

    None
}

fn dev_launchd_image_paths() -> Option<DevStatusImage> {
    let plist = std::fs::read_to_string(dev_launchd_plist_path()).ok()?;
    Some(DevStatusImage {
        kernel_path: plist_env_string_value(&plist, "MVM_DEV_KERNEL"),
        rootfs_path: plist_env_string_value(&plist, "MVM_DEV_ROOTFS")?,
    })
}

fn plist_env_string_value(plist: &str, key: &str) -> Option<String> {
    let expected_key = format!("<key>{key}</key>");
    let mut lines = plist.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line != expected_key {
            continue;
        }
        let value = lines.next()?.trim();
        return value
            .strip_prefix("<string>")?
            .strip_suffix("</string>")
            .map(str::to_string);
    }
    None
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BuilderVmCacheState {
    Ready,
    Stale,
}

impl BuilderVmCacheState {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct BuilderVmCacheStatusSummary {
    cache_kind: &'static str,
    state: BuilderVmCacheState,
    reason_code: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DevImageCacheSummary {
    state: &'static str,
    kernel: &'static str,
    rootfs: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DevCacheInspectSummary {
    dev_image: DevImageCacheSummary,
    builder_cache: BuilderVmCacheStatusSummary,
}

#[derive(Debug, Serialize)]
struct DevCacheInspectJson {
    schema_version: u8,
    dev_image: DevImageCacheJson,
    builder_cache: BuilderVmCacheJson,
}

#[derive(Debug, Serialize)]
struct DevImageCacheJson {
    state: &'static str,
    kernel: &'static str,
    rootfs: &'static str,
}

#[derive(Debug, Serialize)]
struct BuilderVmCacheJson {
    kind: &'static str,
    state: &'static str,
    reason_code: &'static str,
}

fn resolve_dev_cache_inspect_summary() -> DevCacheInspectSummary {
    DevCacheInspectSummary {
        dev_image: dev_image_cache_summary(resolve_dev_status_image().as_ref()),
        builder_cache: resolve_builder_vm_cache_status_summary(),
    }
}

fn dev_image_cache_summary(image: Option<&DevStatusImage>) -> DevImageCacheSummary {
    match image {
        Some(image) => DevImageCacheSummary {
            state: "cached",
            kernel: if image.kernel_path.is_some() {
                "present"
            } else {
                "missing"
            },
            rootfs: "present",
        },
        None => DevImageCacheSummary {
            state: "missing",
            kernel: "missing",
            rootfs: "missing",
        },
    }
}

fn dev_cache_inspect_json(summary: &DevCacheInspectSummary) -> Result<String> {
    let output = DevCacheInspectJson {
        schema_version: 1,
        dev_image: DevImageCacheJson {
            state: summary.dev_image.state,
            kernel: summary.dev_image.kernel,
            rootfs: summary.dev_image.rootfs,
        },
        builder_cache: BuilderVmCacheJson {
            kind: summary.builder_cache.cache_kind,
            state: summary.builder_cache.state.label(),
            reason_code: summary.builder_cache.reason_code,
        },
    };
    serde_json::to_string_pretty(&output).context("serializing dev cache inspection JSON")
}

fn resolve_builder_vm_cache_status_summary() -> BuilderVmCacheStatusSummary {
    builder_vm_cache_status_summary(
        find_builder_vm_flake(),
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        builder_vm_host_arch(),
    )
}

fn builder_vm_cache_status_summary(
    builder_flake: Result<String>,
    cache_root: &std::path::Path,
    arch: &str,
) -> BuilderVmCacheStatusSummary {
    let cache_dir = cache_root.join("builder-vm").join(arch);
    let Ok(flake_dir) = builder_flake else {
        return release_builder_vm_cache_status_summary(&cache_dir);
    };
    let Ok(fingerprint) = builder_vm_source_fingerprint(&flake_dir) else {
        return BuilderVmCacheStatusSummary {
            cache_kind: "source",
            state: BuilderVmCacheState::Stale,
            reason_code: "source_fingerprint_error",
        };
    };
    let status = builder_vm_source_cache_status(&cache_dir, &fingerprint);
    BuilderVmCacheStatusSummary {
        cache_kind: "source",
        state: if status.is_ready() {
            BuilderVmCacheState::Ready
        } else {
            BuilderVmCacheState::Stale
        },
        reason_code: status.reason_code(),
    }
}

fn release_builder_vm_cache_status_summary(
    cache_dir: &std::path::Path,
) -> BuilderVmCacheStatusSummary {
    if validate_builder_vm_stage0_artifacts(cache_dir).is_ok() {
        return BuilderVmCacheStatusSummary {
            cache_kind: "release",
            state: BuilderVmCacheState::Ready,
            reason_code: "hit",
        };
    }
    BuilderVmCacheStatusSummary {
        cache_kind: "release",
        state: BuilderVmCacheState::Stale,
        reason_code: "missing_or_invalid_artifacts",
    }
}

/// Prepare `~/.mvm/dev/current/` for a fresh dev-image build.
///
/// Replaces a stale symlink (the nix-darwin `linux-builder` legacy
/// pointed `current` at a root-owned `/nix/store/…-mvm-dev` path)
/// with a real, writable directory. `create_dir_all` is a no-op
/// against an existing symlink, so without this the libkrun
/// virtio-fs `/out` mount lands on the read-only Nix store path
/// and Apple Container fails with EACCES.
///
/// Only reachable under the libkrun-dispatch branch of `ensure_dev_image`,
/// which itself is gated on `builder-vm`.
#[cfg(feature = "builder-vm")]
fn prepare_dev_image_out_dir(out_dir: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(out_dir).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating dev-image out parent {}", parent.display()))?;
    }
    if std::path::Path::new(out_dir)
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        std::fs::remove_file(out_dir)
            .with_context(|| format!("removing stale dev-image symlink at {out_dir}"))?;
    }
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating dev-image out dir {out_dir}"))?;
    Ok(())
}

/// Resolve the dev image (kernel + rootfs) to absolute paths.
///
/// In a source checkout: uses the libkrun-backed builder VM
/// (Plan 72 W4/W5 — `LibkrunBuilderVm` runs `nix build` against the
/// dev-shell flake from inside a microVM with a persistent 64 GiB
/// `/nix` store). Libkrun isn't installed → loud error pointing at
/// the install command; **no libkrun fallback for the dev-shell
/// image** (Plan 72 W5.C — the dev-shell rustc closure overflows
/// libkrun's 4 GiB overlay anyway, so a fallback that would
/// just disk-out is worse than an actionable error).
///
/// Outside a source checkout: falls back to the GitHub-release
/// download of a pre-built image.
///
/// Failures of the local build are surfaced loudly — never silently
/// substituted with the prebuilt, since the prebuilt would mask local
/// rootfs changes.
pub(super) fn ensure_dev_image() -> Result<(String, String)> {
    // Plan 115 / ADR-065: source-checkout dispatch.
    //
    // The dev-shell image now comes from `packages.<sys>.dev` in
    // `nix/images/builder-vm/flake.nix` (the same flake as the
    // headless builder VM). The old separate `nix/images/builder/`
    // flake has been deleted. `find_builder_vm_flake()` detects a
    // source checkout; when present, `build_image_via_libkrun` is
    // invoked against the `dev` attr of the consolidated flake.
    #[cfg(feature = "builder-vm")]
    if find_builder_vm_flake().is_ok() {
        let out_dir = format!("{}/dev/current", mvm_core::config::mvm_data_dir());
        prepare_dev_image_out_dir(&out_dir)?;

        return build_image_via_libkrun(&out_dir);
    }

    // No local source checkout — download the published prebuilt.
    // Cache key = mvmctl's version: each version owns a sibling
    // directory under .../dev/prebuilt/, and bumping the binary
    // automatically invalidates older caches. We sweep older version
    // dirs on every miss so disk usage tracks the *current* version,
    // not the union of every version ever installed.
    ui::info("No local builder-vm flake found; downloading published prebuilt.");
    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_root = format!("{}/dev/prebuilt", mvm_core::config::mvm_data_dir());
    let prebuilt_dir = format!("{prebuilt_root}/v{version}");
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    let kernel_path = format!("{prebuilt_dir}/vmlinux");
    let rootfs_path = format!("{prebuilt_dir}/rootfs.ext4");
    // Cache hit on the current version's dir — fast path. Validate
    // first; if either file is below the size floor or the rootfs
    // lacks the ext4 magic, treat the cache as poisoned and delete it
    // so the cascade below can re-populate from a healthy source. The
    // typical poisoning vector is an earlier copy from a stub or
    // half-downloaded source — the size floor catches the stub case
    // (~12 B vs. ~16 MiB minimum), and the magic check catches a
    // wrong-format file at the right size.
    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        match validate_dev_image_artifacts(&kernel_path, &rootfs_path) {
            Ok(()) => {
                prune_old_prebuilts(&prebuilt_root, version);
                return Ok((kernel_path, rootfs_path));
            }
            Err(e) => {
                ui::warn(&format!(
                    "Cached dev image at {prebuilt_dir} failed sanity check ({e}); \
                     deleting and rebuilding."
                ));
                let _ = std::fs::remove_file(&kernel_path);
                let _ = std::fs::remove_file(&rootfs_path);
            }
        }
    }
    // Source-checkout-first. When the binary was compiled out of an
    // mvm source tree that has `nix/images/dev-prebuilt/<arch>/`
    // populated, that's the authoritative dev image for this build —
    // skip GitHub entirely. The helper returns `None` for installed
    // binaries (their `CARGO_MANIFEST_DIR` resolves into
    // `~/.cargo/registry/` where the directory will never exist) and
    // for source checkouts that haven't vendored anything yet, in
    // which case we fall through to the published prebuilt as before.
    if let Some((src_kernel, src_rootfs, source_label)) = find_vendored_dev_image() {
        validate_dev_image_artifacts(&src_kernel, &src_rootfs).with_context(|| {
            format!(
                "vendored dev image at {source_label} failed sanity check — \
                 refusing to copy garbage into the prebuilt cache"
            )
        })?;
        ui::info(&format!(
            "Using vendored dev image from source checkout ({source_label})."
        ));
        std::fs::copy(&src_kernel, &kernel_path)
            .with_context(|| format!("copying vendored kernel {src_kernel:?} → {kernel_path}"))?;
        std::fs::copy(&src_rootfs, &rootfs_path)
            .with_context(|| format!("copying vendored rootfs {src_rootfs:?} → {rootfs_path}"))?;
        // No prune — vendored is the source of truth for this binary,
        // not a download; leaving older `v*/` dirs around lets
        // installed-binary users keep their offline-fallback cache.
        return Ok((kernel_path, rootfs_path));
    }
    // Try the published prebuilt. Defer the prune until *after* a
    // successful download — old `~/.mvm/dev/prebuilt/v*/` dirs and
    // historical `~/.mvm/dev/builds/<hash>/` artifacts are our last-
    // resort fallback when the release page lacks v{version} assets.
    match download_dev_image(&kernel_path, &rootfs_path) {
        Ok(result) => {
            prune_old_prebuilts(&prebuilt_root, version);
            Ok(result)
        }
        Err(download_err) => {
            ui::warn(&format!(
                "Could not download dev image for v{version}: {download_err}\n\
                 Searching for a local fallback under ~/.mvm/dev/."
            ));
            if let Some((src_kernel, src_rootfs, source_label)) = find_local_fallback_image() {
                ui::warn(&format!(
                    "Using local fallback from {source_label}. \
                     This is not the published v{version} image — boot it knowing the \
                     versions differ. Publish v{version} assets or restore the local \
                     builder flake to make this go away."
                ));
                std::fs::copy(&src_kernel, &kernel_path).with_context(|| {
                    format!("copying fallback kernel {src_kernel:?} → {kernel_path}")
                })?;
                std::fs::copy(&src_rootfs, &rootfs_path).with_context(|| {
                    format!("copying fallback rootfs {src_rootfs:?} → {rootfs_path}")
                })?;
                Ok((kernel_path, rootfs_path))
            } else {
                Err(download_err.context(
                    "no local fallback found under ~/.mvm/dev/current/, \
                     ~/.mvm/dev/prebuilt/v*/, or ~/.mvm/dev/builds/*/",
                ))
            }
        }
    }
}

/// Search for any locally-cached dev image as a fallback when the
/// published-prebuilt download fails or as a Stage 0 seed when the
/// builder VM cache is empty. Looks under, in order of precedence
/// when mtimes tie:
///
/// - `~/.mvm/dev/current/{vmlinux,rootfs.ext4}` — the canonical
///   "live" dev image written by `build_image_via_libkrun` and read
///   by `resolve_dev_status_image`. Present whenever `mvmctl dev up`
///   has succeeded at least once on this host; survives a manual
///   delete of `~/.cache/mvm/builder-vm/`. This is the load-bearing
///   seed for Plan 77 Stage 0 — without it, a contributor who blew
///   away the builder VM cache would have no path back.
/// - `~/.mvm/dev/prebuilt/v*/{vmlinux,rootfs.ext4}` — previously
///   downloaded prebuilts for earlier versions.
/// - `~/.mvm/dev/builds/<hash>/{vmlinux,rootfs.ext4}` — historical
///   nix-darwin `linux-builder` outputs from the pre-libkrun era.
///
/// Returns the most-recently-modified pair so a user with a recent
/// successful build/download keeps booting, with a short label
/// (e.g. `current`, `prebuilt/v0.13.0`, or `builds/abcdef…`) for the
/// warning surface. `None` means nothing usable was found.
fn find_local_fallback_image() -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    find_local_fallback_image_with(|_| true)
}

fn find_local_fallback_image_with(
    accepts_rootfs: impl Fn(&std::path::Path) -> bool,
) -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    let dev_root = format!("{}/dev", mvm_core::config::mvm_data_dir());

    let mut candidates: Vec<(std::time::SystemTime, std::path::PathBuf, String)> = Vec::new();
    // Silently skip cache entries that look corrupt (stub bytes from
    // a botched earlier copy, half-written downloads, stale symlinks
    // from the legacy nix-darwin `current/` layout). The auto-discover
    // path is best-effort — surfacing every bad candidate as a warning
    // would spam the boot path; the cascade just falls through to a
    // healthier candidate or to the next layer.
    let mut consider = |dir: std::path::PathBuf, label: String| {
        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        if !kernel.is_file() || !rootfs.is_file() {
            return;
        }
        if validate_dev_image_artifacts(&kernel, &rootfs).is_err() {
            return;
        }
        if !accepts_rootfs(&rootfs) {
            return;
        }
        let mtime = std::fs::metadata(&rootfs)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        candidates.push((mtime, dir, label));
    };

    consider(
        std::path::Path::new(&dev_root).join("current"),
        "current".to_string(),
    );
    for sub in ["prebuilt", "builds"] {
        let parent = std::path::Path::new(&dev_root).join(sub);
        let Ok(entries) = std::fs::read_dir(&parent) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let label = format!("{sub}/{}", entry.file_name().to_string_lossy());
            consider(dir, label);
        }
    }

    candidates.sort_by_key(|(mtime, ..)| *mtime);
    let (_, dir, label) = candidates.into_iter().next_back()?;
    Some((dir.join("vmlinux"), dir.join("rootfs.ext4"), label))
}

fn rootfs_contains_builder_init(rootfs: &std::path::Path) -> Result<bool> {
    file_contains_bytes(rootfs, HOST_VM_INIT_PATH)
        .with_context(|| format!("scanning {} for /sbin/mvm-host-vm-init", rootfs.display()))
}

fn file_contains_bytes(path: &std::path::Path, needle: &[u8]) -> Result<bool> {
    if needle.is_empty() {
        return Ok(true);
    }
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut carry = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            return Ok(false);
        }
        let mut window = Vec::with_capacity(carry.len() + n);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buf[..n]);
        if window.windows(needle.len()).any(|w| w == needle) {
            return Ok(true);
        }
        let keep = needle.len().saturating_sub(1).min(window.len());
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }
}

/// Sanity-check that a `(vmlinux, rootfs.ext4)` pair looks like a real
/// dev image. Fast-fails before copying or returning the artifacts as
/// usable, so a stub or truncated file can't poison the prebuilt cache.
///
/// Two checks per file:
///
/// - **Size floor.** A real `vmlinux` is several MiB (typical ARM64
///   Image is 15–20 MiB); a real `rootfs.ext4` is ~700 MiB. Reject
///   anything under a conservative floor (1 MiB / 4 MiB respectively)
///   to catch the stub-file case (~12 B from a botched test, ~0 B
///   from a torn-down download).
/// - **Ext4 magic.** The ext4 superblock starts at byte 1024; the
///   `s_magic` field is at byte 1080 (offset 56 inside the
///   superblock) and equals `0xEF53` little-endian. Only the rootfs
///   gets this check — `vmlinux` formats vary by arch (ARM64
///   `Image`, x86 bzImage, etc.) so there's no portable magic to
///   match.
fn validate_dev_image_artifacts(
    kernel: impl AsRef<std::path::Path>,
    rootfs: impl AsRef<std::path::Path>,
) -> Result<()> {
    const KERNEL_MIN_BYTES: u64 = 1024 * 1024;
    const ROOTFS_MIN_BYTES: u64 = 4 * 1024 * 1024;
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 56;
    const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

    let kernel = kernel.as_ref();
    let rootfs = rootfs.as_ref();

    let kernel_size = std::fs::metadata(kernel)
        .with_context(|| format!("stat {}", kernel.display()))?
        .len();
    if kernel_size < KERNEL_MIN_BYTES {
        anyhow::bail!(
            "kernel at {} is only {} bytes (expected ≥ {})",
            kernel.display(),
            kernel_size,
            KERNEL_MIN_BYTES,
        );
    }

    let rootfs_size = std::fs::metadata(rootfs)
        .with_context(|| format!("stat {}", rootfs.display()))?
        .len();
    if rootfs_size < ROOTFS_MIN_BYTES {
        anyhow::bail!(
            "rootfs at {} is only {} bytes (expected ≥ {})",
            rootfs.display(),
            rootfs_size,
            ROOTFS_MIN_BYTES,
        );
    }

    use std::io::{Read, Seek, SeekFrom};
    let mut f =
        std::fs::File::open(rootfs).with_context(|| format!("open {}", rootfs.display()))?;
    f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET))
        .with_context(|| format!("seek to ext4 magic in {}", rootfs.display()))?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)
        .with_context(|| format!("read ext4 magic from {}", rootfs.display()))?;
    if magic != EXT4_MAGIC {
        anyhow::bail!(
            "rootfs at {} does not have ext4 magic at offset {} (got {magic:02x?})",
            rootfs.display(),
            EXT4_MAGIC_OFFSET,
        );
    }

    Ok(())
}

/// Look for a vendored dev image inside the source checkout the mvmctl
/// binary was compiled from: `{workspace_root}/nix/images/dev-prebuilt/
/// <arch>/{vmlinux, rootfs.ext4}`. The path is checked last in the
/// fallback cascade — it's the most predictable source ("what the
/// repo ships") but only useful when `mvmctl` runs out of its source
/// checkout: `CARGO_MANIFEST_DIR` is baked at compile time and points
/// into `~/.cargo/registry/` for `cargo install`-ed builds, where the
/// directory will reliably be missing. That's fine — for installed
/// binaries the `~/.mvm/dev/` auto-discover path covers the offline
/// case.
///
/// `arch` mirrors the matrix used by `download_dev_image`: `aarch64`
/// on Apple Silicon / aarch64-linux, `x86_64` everywhere else.
fn find_vendored_dev_image() -> Option<(std::path::PathBuf, std::path::PathBuf, String)> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir).parent()?.parent()?;
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let dir = workspace_root
        .join("nix")
        .join("images")
        .join("dev-prebuilt")
        .join(arch);
    let kernel = dir.join("vmlinux");
    let rootfs = dir.join("rootfs.ext4");
    if !kernel.is_file() || !rootfs.is_file() {
        return None;
    }
    let label = format!("vendored {}", dir.display());
    Some((kernel, rootfs, label))
}

/// Drop every direct child of `prebuilt_root` except the one for the
/// currently-running version. Best-effort — failure is logged.
fn prune_old_prebuilts(prebuilt_root: &str, current_version: &str) {
    let current = format!("v{current_version}");
    let Ok(entries) = std::fs::read_dir(prebuilt_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == current {
            continue;
        }
        let path = entry.path();
        match std::fs::remove_dir_all(&path) {
            Ok(()) => ui::info(&format!("Pruned stale prebuilt cache: {name_str}")),
            Err(e) => tracing::warn!("Could not prune {}: {e}", path.display()),
        }
    }
}

/// Download a pre-built dev image (kernel + rootfs) from GitHub releases.
///
/// Plan 36 / ADR 005 trust chain:
///
/// 1. Try the cosign-keyless-signed manifest first
///    (`dev-image-{arch}.manifest.json` + `.bundle`). If present,
///    `mvm-security::image_verify::verify_manifest` validates the
///    Sigstore bundle against the project's release-workflow OIDC
///    identity, parses the manifest, and we use *its* artifact
///    digests as the source of truth.
///
/// 2. If the manifest is 404 (older release predating plan 36) or
///    its companion bundle is missing, fall back to the W5.1
///    unsigned-checksum path with a loud deprecation warning. This
///    keeps mvmctl pointing at older releases working through the
///    rollout, and the deprecation banner sets the stage for making
///    the manifest mandatory in a future major version.
///
/// 3. Either way, every downloaded artifact gets streaming SHA-256
///    verification (W5.1) against the expected digest.
///
/// Escape hatches (both print loud warnings):
///   - `MVM_SKIP_HASH_VERIFY=1` — skip SHA-256 step (existing W5.1).
///   - `MVM_SKIP_COSIGN_VERIFY=1` — skip cosign signature check on
///     the manifest body but still parse and use it. Only for
///     emergency Sigstore-side rotation; SHA-256 still applies.
fn download_dev_image(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    // Wrap the verification pipeline so every exit path — success or
    // failure — emits the verify_duration gauge and bumps the
    // appropriate outcome counter. Plan 36 §Layer 4 step 11.
    let verify_start = std::time::Instant::now();
    let result = download_dev_image_inner(kernel_path, rootfs_path);
    let elapsed_ms = verify_start.elapsed().as_millis() as u64;
    let metrics = mvm_core::observability::metrics::global();
    metrics
        .dev_image_verify_duration_ms
        .store(elapsed_ms, std::sync::atomic::Ordering::Relaxed);
    if result.is_ok() {
        metrics
            .dev_image_verify_ok
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    result
}

fn download_dev_image_inner(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    // Detect host arch to download the right image.
    // Apple Silicon (aarch64-darwin) needs aarch64-linux image.
    // Intel Mac (x86_64-darwin) needs x86_64-linux image.
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let kernel_name = format!("dev-vmlinux-{arch}");
    let rootfs_name = format!("dev-rootfs-{arch}.ext4");
    let kernel_url = format!("{base_url}/{kernel_name}");
    let rootfs_url = format!("{base_url}/{rootfs_name}");

    ui::info(&format!("Downloading dev image (v{version})..."));

    // Plan 36 PR-C.2: prefer the cosign-signed manifest. Falls back
    // to the W5.1 unsigned checksum file when the manifest is 404
    // (older release).
    let expected = match try_fetch_signed_manifest(&base_url, version, arch, "dev")? {
        Some(manifest) => {
            ui::success(&format!(
                "  ✓ cosign-verified manifest for v{} (built {} UTC, valid until {} UTC)",
                manifest.version,
                manifest.built_at.format("%Y-%m-%d"),
                manifest.not_after.format("%Y-%m-%d"),
            ));
            manifest
                .artifacts
                .iter()
                .map(|a| (a.name.clone(), a.sha256.to_ascii_lowercase()))
                .collect::<std::collections::HashMap<_, _>>()
        }
        None => {
            ui::warn(&format!(
                "No cosign-signed manifest found for v{version}. Falling back to \
                 unsigned checksum file (legacy path predating plan 36 / ADR 005). \
                 Future releases will require the signed manifest."
            ));
            let checksums_name = format!("dev-image-{arch}-checksums-sha256.txt");
            let checksums_url = format!("{base_url}/{checksums_name}");
            fetch_expected_hashes(&checksums_url, &[&kernel_name, &rootfs_name])?
        }
    };

    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!("Failed to download kernel from {kernel_url}"))
    })?;
    verify_artifact_hash(
        kernel_path,
        &kernel_name,
        expected.get(kernel_name.as_str()),
    )?;

    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!("Failed to download rootfs from {rootfs_url}"))
    })?;
    verify_artifact_hash(
        rootfs_path,
        &rootfs_name,
        expected.get(rootfs_name.as_str()),
    )?;

    ui::success("Dev image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

/// Probe for and verify the cosign-signed manifest at
/// `{base_url}/{variant}-image-{arch}.manifest.json{,.bundle}`.
///
/// Returns:
/// - `Ok(Some(manifest))` — manifest + bundle present, signature verified,
///   version pinned to runtime, max-age window not yet exceeded.
/// - `Ok(None)` — manifest URL 404. This is the legacy fallback for
///   older releases that predate plan 36; caller can fall back to the
///   W5.1 unsigned-checksum path with a deprecation warning.
/// - `Err(_)` — manifest fetched but verification or parsing failed.
///   Hard error; never silently fall through. `MVM_SKIP_COSIGN_VERIFY=1`
///   downgrades signature failures to a parse-only path.
fn try_fetch_signed_manifest(
    base_url: &str,
    version: &str,
    arch: &str,
    variant: &str,
) -> Result<Option<mvm_security::image_verify::SignedManifest>> {
    use mvm_security::image_verify;

    let manifest_name = format!("{variant}-image-{arch}.manifest.json");
    let manifest_url = format!("{base_url}/{manifest_name}");
    let bundle_url = format!("{manifest_url}.bundle");

    // HEAD-probe the manifest URL. If absent (older release without
    // plan-36 signing), fall back gracefully.
    if !url_exists(&manifest_url)? {
        return Ok(None);
    }

    let manifest_tmp = tempfile::NamedTempFile::new().context("creating manifest tempfile")?;
    let bundle_tmp = tempfile::NamedTempFile::new().context("creating bundle tempfile")?;
    let manifest_path = manifest_tmp.path().to_string_lossy().into_owned();
    let bundle_path = bundle_tmp.path().to_string_lossy().into_owned();

    download_file(&manifest_url, &manifest_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download signed manifest from {manifest_url}"
        ))
    })?;
    download_file(&bundle_url, &bundle_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download cosign bundle from {bundle_url}. The release \
             pipeline requires a manifest's signature to be present alongside \
             the manifest body — refusing to trust an unsigned manifest."
        ))
    })?;

    let manifest_bytes =
        std::fs::read(&manifest_path).context("reading downloaded manifest body")?;
    let bundle_bytes = std::fs::read(&bundle_path).context("reading downloaded cosign bundle")?;

    // GitHub Actions keyless OIDC: the SAN encodes the workflow URL
    // bound to the tag, and the issuer is GitHub's token endpoint.
    let expected_identity = format!(
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"
    );
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        tracing::warn!(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest body. \
             This is an emergency-rotation escape hatch only."
        );
        image_verify::parse_manifest(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("manifest parse failed: {e}"))?
    } else {
        image_verify::verify_manifest(
            &manifest_bytes,
            &bundle_bytes,
            &expected_identity,
            expected_issuer,
        )
        .map_err(|e| {
            bump_verify_outcome("sig_invalid");
            anyhow::anyhow!(
                "Cosign verification failed for {manifest_name}: {e}\n\
                 \n\
                 Plan 36 / ADR 005 requires every dev image manifest to be cosign-keyless\n\
                 signed against the release workflow's OIDC identity. Refusing to use this\n\
                 image. Possible causes:\n\
                 - account/CDN compromise (open a security issue);\n\
                 - the release was published without going through the signing job;\n\
                 - clock skew (manifest expired); check `date -u`.\n\
                 \n\
                 Emergency rotation: set MVM_SKIP_COSIGN_VERIFY=1 to bypass the signature\n\
                 check while keeping SHA-256 verification active."
            )
        })?
    };

    // Pin the manifest's claimed version to mvmctl's own version. A
    // mismatch means someone is feeding us a different release's
    // manifest — refuse.
    image_verify::check_version_pin(&manifest, version).map_err(|e| {
        bump_verify_outcome("version_skew");
        anyhow::anyhow!("manifest version pin failed: {e}")
    })?;

    // Enforce max-age (default 90d). mvmctl warns and proceeds; mvmd
    // refuses (different risk tolerance — handled in mvmd plan 23).
    let now = chrono::Utc::now();
    if let Err(e) = image_verify::check_not_after(&manifest, now) {
        bump_verify_outcome("expired");
        ui::warn(&format!(
            "Dev image manifest is past its max-age ({e}). Consider upgrading \
             mvmctl — older signed images are still cryptographically valid but \
             may carry unpatched vulnerabilities."
        ));
    }

    // Plan 36 §Layer 4 step 4: consult the cosign-signed revocation
    // list. Cached up to 24h; tolerated up to 7d offline. A signed
    // image whose version is on the list hard-fails — recall is the
    // primary mechanism for "we know this build is bad."
    if let Some(revocations) = try_fetch_revocation_list()? {
        image_verify::check_revocation(&manifest, &revocations).map_err(|e| {
            bump_verify_outcome("revoked");
            anyhow::anyhow!(
                "Dev image manifest is on the project's revocation list: {e}\n\
                 \n\
                 Plan 36 / ADR 005: a published `revocations` release entry has\n\
                 marked v{version} unsafe to run. Refusing to use this image.\n\
                 Upgrade mvmctl to a non-revoked release."
            )
        })?;
    }

    Ok(Some(manifest))
}

/// Fetch + verify the project's signed revocation list, caching it
/// under `~/.cache/mvm/revocations/`.
///
/// Plan 36 §Layer 4 step 4. The revocation list lives at a stable
/// `revocations` release tag whose only assets are
/// `revoked-versions.json` and its cosign bundle. Append-only across
/// releases; updated by cutting a new entry on that tag.
///
/// Cache policy:
///   - Refresh from upstream if the cached file is >24h old.
///   - Tolerate up to 7d of cached staleness when the network is
///     unavailable; surface a warning rather than blocking.
///   - 404 on the upstream URL is treated as "no recalls today" —
///     bootstrap state until the project publishes its first
///     revocations entry. Returns Ok(None).
///
/// Returns Ok(None) when the list isn't available *and* we have no
/// cached copy — caller proceeds without revocation enforcement (with
/// a warning). Returns Err on signature verification failure.
fn try_fetch_revocation_list() -> Result<Option<mvm_security::image_verify::RevocationList>> {
    use mvm_security::image_verify;
    use std::time::{Duration, SystemTime};

    let cache_dir = format!("{}/revocations", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating revocations cache dir {cache_dir}"))?;
    let cache_json = format!("{cache_dir}/revoked-versions.json");
    let cache_bundle = format!("{cache_dir}/revoked-versions.json.bundle");

    let cache_age = std::fs::metadata(&cache_json)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or(Duration::from_secs(u64::MAX));

    let twenty_four_hours = Duration::from_secs(24 * 60 * 60);
    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);

    // Refresh if cache is stale (or absent).
    if cache_age > twenty_four_hours {
        let base = "https://github.com/tinylabscom/mvm/releases/download/revocations";
        let json_url = format!("{base}/revoked-versions.json");
        let bundle_url = format!("{base}/revoked-versions.json.bundle");

        match url_exists(&json_url) {
            Ok(true) => {
                let tmp_json =
                    tempfile::NamedTempFile::new().context("creating revocations tempfile")?;
                let tmp_bundle = tempfile::NamedTempFile::new()
                    .context("creating revocations bundle tempfile")?;
                let tmp_json_path = tmp_json.path().to_string_lossy().into_owned();
                let tmp_bundle_path = tmp_bundle.path().to_string_lossy().into_owned();
                let download_result = download_file(&json_url, &tmp_json_path)
                    .and_then(|()| download_file(&bundle_url, &tmp_bundle_path));
                match download_result {
                    Ok(()) => {
                        std::fs::copy(&tmp_json_path, &cache_json)
                            .context("caching revoked-versions.json")?;
                        std::fs::copy(&tmp_bundle_path, &cache_bundle)
                            .context("caching revoked-versions.json.bundle")?;
                    }
                    Err(e) if cache_age <= seven_days => {
                        ui::warn(&format!(
                            "Could not refresh revocation list ({e}); using cached copy \
                             (last refreshed {} hours ago).",
                            cache_age.as_secs() / 3600
                        ));
                    }
                    Err(e) => {
                        ui::warn(&format!(
                            "Could not refresh revocation list ({e}) and no fresh cache \
                             is available; proceeding without recall enforcement."
                        ));
                        return Ok(None);
                    }
                }
            }
            Ok(false) => {
                // 404: the project hasn't published a revocations
                // release yet. Bootstrap state — no recalls means
                // nothing to enforce. Don't cache this; a future
                // refresh should pick up the first published list.
                return Ok(None);
            }
            Err(e) if cache_age <= seven_days => {
                ui::warn(&format!(
                    "Could not probe revocation list ({e}); using cached copy."
                ));
            }
            Err(e) => {
                ui::warn(&format!(
                    "Could not probe revocation list ({e}) and no fresh cache \
                     is available; proceeding without recall enforcement."
                ));
                return Ok(None);
            }
        }
    }

    // No cached file → nothing to enforce.
    if !std::path::Path::new(&cache_json).exists() {
        return Ok(None);
    }

    let json_bytes = std::fs::read(&cache_json).context("reading cached revocations.json")?;
    let bundle_bytes =
        std::fs::read(&cache_bundle).context("reading cached revocations.json.bundle")?;

    // The revocations tag is signed by a dedicated revocations
    // workflow's OIDC identity, not the per-release workflow. A
    // separate identity ensures a leaked image-signing cert can't
    // fabricate a permissive revocation list (and vice versa).
    let expected_identity = "https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocations";
    let expected_issuer = "https://token.actions.githubusercontent.com";

    if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        // The same MVM_SKIP_COSIGN_VERIFY emergency-rotation escape
        // hatch covers both the manifest and the revocation list.
        // SHA-256 of artifacts still applies separately at the
        // verify_artifact_hash callsite.
        let list: image_verify::RevocationList = serde_json::from_slice(&json_bytes)
            .context("parsing revocations JSON without signature verification")?;
        return Ok(Some(list));
    }

    image_verify::verify_signed_payload(
        &json_bytes,
        &bundle_bytes,
        expected_identity,
        expected_issuer,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "Revocation list signature verification failed: {e}. Refusing to \
             trust an unverified recall."
        )
    })?;
    let list: image_verify::RevocationList =
        serde_json::from_slice(&json_bytes).context("parsing verified revocations JSON")?;
    Ok(Some(list))
}

/// `mvmctl dev import-image` — sideload a verified dev image from local files.
///
/// Plan 36 PR-D.2 / §"Air-gapped install path". Runs the same
/// cosign + SHA-256 + version-pin + max-age + revocation pipeline
/// as `download_dev_image`, but against operator-provided local
/// files instead of the GitHub Releases URL. On success the verified
/// artifacts are copied into the version-namespaced cache so the next
/// `mvmctl dev up` boots from them with no further verification or
/// network round-trip.
///
/// The intended user is anyone running mvmctl in a regulated /
/// gov / air-gapped environment that can't reach github.com but
/// that legitimately wants the supply-chain check. Without this
/// path the only option for these users was MVM_SKIP_HASH_VERIFY=1,
/// which disables verification entirely — exactly the unsafe escape
/// plan 36 exists to discourage.
pub fn cmd_dev_import_image(
    manifest_path: &str,
    bundle_path: &str,
    vmlinux_path: &str,
    rootfs_path: &str,
) -> Result<()> {
    use mvm_security::image_verify;

    let version = env!("CARGO_PKG_VERSION");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    ui::info(&format!(
        "Importing dev image (v{version}, {arch}) from local files..."
    ));

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("reading manifest file at {manifest_path}"))?;
    let bundle_bytes = std::fs::read(bundle_path)
        .with_context(|| format!("reading cosign bundle at {bundle_path}"))?;

    let expected_identity = format!(
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"
    );
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        ui::warn(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest. \
             This is an emergency-rotation escape only.",
        );
        image_verify::parse_manifest(&manifest_bytes)
            .map_err(|e| anyhow::anyhow!("manifest parse failed: {e}"))?
    } else {
        image_verify::verify_manifest(
            &manifest_bytes,
            &bundle_bytes,
            &expected_identity,
            expected_issuer,
        )
        .map_err(|e| {
            bump_verify_outcome("sig_invalid");
            anyhow::anyhow!(
                "Cosign verification failed for the imported manifest: {e}\n\
                 \n\
                 Plan 36 / ADR 005: a sideloaded manifest must carry the\n\
                 same release-workflow OIDC signature as the network path.\n\
                 \n\
                 Common causes:\n\
                 - mismatched manifest + bundle pair (re-export both as a set);\n\
                 - manifest belongs to a different mvmctl version (check `mvmctl --version`);\n\
                 - clock skew (signature time-window).\n\
                 \n\
                 Emergency rotation: MVM_SKIP_COSIGN_VERIFY=1 keeps SHA-256\n\
                 verification active while bypassing the signature step."
            )
        })?
    };

    image_verify::check_version_pin(&manifest, version).map_err(|e| {
        bump_verify_outcome("version_skew");
        anyhow::anyhow!(
            "Imported manifest is for a different mvmctl version: {e}\n\
             \n\
             Plan 36 pins manifest.version == mvmctl version exactly. Re-export\n\
             the manifest from a release matching v{version}, or upgrade mvmctl."
        )
    })?;

    let now = chrono::Utc::now();
    if let Err(e) = image_verify::check_not_after(&manifest, now) {
        bump_verify_outcome("expired");
        ui::warn(&format!(
            "Imported manifest is past its max-age ({e}). Sideloaded images \
             from older releases remain cryptographically valid but may \
             carry unpatched vulnerabilities."
        ));
    }

    if let Some(revocations) = try_fetch_revocation_list()? {
        image_verify::check_revocation(&manifest, &revocations).map_err(|e| {
            bump_verify_outcome("revoked");
            anyhow::anyhow!(
                "Imported manifest is on the project's revocation list: {e}\n\
                 \n\
                 Plan 36: a `revocations` release entry has marked v{version} \
                 unsafe to run. Refusing to import."
            )
        })?;
    }

    if manifest.arch != arch {
        anyhow::bail!(
            "Manifest is for arch {} but this host is {arch}. Wrong-arch image \
             would not boot. Re-export the manifest for the correct arch.",
            manifest.arch
        );
    }

    let kernel_name = format!("dev-vmlinux-{arch}");
    let rootfs_name = format!("dev-rootfs-{arch}.{}", manifest.rootfs_format);

    let kernel_digest = manifest
        .artifact(&kernel_name)
        .ok_or_else(|| anyhow::anyhow!("manifest does not list {kernel_name}"))?;
    let rootfs_digest = manifest
        .artifact(&rootfs_name)
        .ok_or_else(|| anyhow::anyhow!("manifest does not list {rootfs_name}"))?;

    image_verify::verify_artifact(std::path::Path::new(vmlinux_path), kernel_digest).map_err(
        |e| {
            bump_verify_outcome("digest_mismatch");
            anyhow::anyhow!("kernel SHA-256 mismatch: {e}")
        },
    )?;
    image_verify::verify_artifact(std::path::Path::new(rootfs_path), rootfs_digest).map_err(
        |e| {
            bump_verify_outcome("digest_mismatch");
            anyhow::anyhow!("rootfs SHA-256 mismatch: {e}")
        },
    )?;

    // Copy the verified artifacts into the version-namespaced cache.
    // The next `mvmctl dev up` picks them up without re-running
    // verification (the cache hit precedes download_dev_image).
    let prebuilt_dir = format!(
        "{}/dev/prebuilt/v{version}",
        mvm_core::config::mvm_data_dir()
    );
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    let target_kernel = format!("{prebuilt_dir}/vmlinux");
    let target_rootfs = format!("{prebuilt_dir}/rootfs.ext4");
    std::fs::copy(vmlinux_path, &target_kernel)
        .with_context(|| format!("copying kernel to {target_kernel}"))?;
    std::fs::copy(rootfs_path, &target_rootfs)
        .with_context(|| format!("copying rootfs to {target_rootfs}"))?;

    mvm_core::observability::metrics::global()
        .dev_image_verify_ok
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    ui::success(&format!(
        "Imported and verified dev image v{version} into {prebuilt_dir}. \
         Run `mvmctl dev up` to boot the dev VM from the cached artifacts."
    ));
    Ok(())
}

/// Bump the dev_image_verify_<outcome> counter. Plan 36 §Layer 4 step 11.
///
/// Caller passes the outcome name; centralising the lookup keeps the
/// counter set discoverable in one place. mvmd plan 23's
/// reconciliation loop will alert on attack-shaped spikes
/// (sig_invalid, digest_mismatch, revoked).
///
/// Security-relevant outcomes (everything except `network`, which is
/// operational) also emit a `LocalAuditKind::ImageVerifyFailed` event
/// so `mvmctl audit tail` shows the rejection. The counter is the
/// alerting channel; the audit line is the forensics channel.
fn bump_verify_outcome(outcome: &str) {
    let m = mvm_core::observability::metrics::global();
    let counter = match outcome {
        "sig_invalid" => &m.dev_image_verify_sig_invalid,
        "digest_mismatch" => &m.dev_image_verify_digest_mismatch,
        "version_skew" => &m.dev_image_verify_version_skew,
        "revoked" => &m.dev_image_verify_revoked,
        "expired" => &m.dev_image_verify_expired,
        "network" => &m.dev_image_verify_network,
        // Defensive: an unknown outcome is itself a bug worth surfacing
        // — log a warning rather than silently swallowing the metric.
        _ => {
            tracing::warn!("bump_verify_outcome: unknown outcome '{outcome}'");
            return;
        }
    };
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if outcome != "network" {
        let mvmctl_version = env!("CARGO_PKG_VERSION");
        mvm_core::audit_emit!(
            ImageVerifyFailed,
            "outcome={outcome} mvmctl_version={mvmctl_version}"
        );
    }
}

/// HEAD-probe a URL. Returns Ok(true) when the resource is reachable
/// (HTTP 2xx), Ok(false) on 404, Err for transient failures.
fn url_exists(url: &str) -> Result<bool> {
    let output = std::process::Command::new("curl")
        .args(["-fSI", "-o", "/dev/null", "-w", "%{http_code}", url])
        .output()
        .context("Failed to run curl HEAD probe")?;
    let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
    match code.as_str() {
        "200" | "302" => Ok(true),
        "404" => Ok(false),
        _ => {
            // Other status (5xx, network error, redirect chain failure)
            // — don't silently fall through to the unsigned path.
            anyhow::bail!(
                "HEAD probe of {url} returned status {code}; refusing to guess \
                 whether the signed manifest is missing or transiently unavailable. \
                 Retry, or investigate."
            )
        }
    }
}

/// Download the per-release `sha256sum`-format checksum file and parse it
/// into a `name -> hex-digest` map for the artifacts we plan to download.
///
/// The checksum file is the trust anchor for ADR-002 §W5.1. It is fetched
/// from the same GitHub release URL as the artifacts, over TLS. Anyone
/// who can swap the artifact can also swap the checksum file, so the
/// real defence is end-to-end signing (cosign on the .tar.gz / SBOM
/// today, on the checksum file itself in a future iteration). What we
/// gain *now* is detection of mid-flight corruption and operator-error
/// substitution at the URL level — both of which are ruled out by a
/// matching hash.
///
/// Returns only entries for the artifacts in `wanted`; missing names
/// short-circuit to a clear error.
fn fetch_expected_hashes(
    checksums_url: &str,
    wanted: &[&str],
) -> Result<std::collections::HashMap<String, String>> {
    let tmp = tempfile::NamedTempFile::new().context("Failed to create temp file")?;
    let tmp_path = tmp.path().to_string_lossy().to_string();
    download_file(checksums_url, &tmp_path).with_context(|| {
        format!(
            "Failed to download checksum manifest from {checksums_url}.\n\
             ADR-002 §W5.1 requires a hash-verified download; refusing to\n\
             proceed without the checksum file. To bypass for an emergency\n\
             rotation, set MVM_SKIP_HASH_VERIFY=1."
        )
    })?;
    let body = std::fs::read_to_string(&tmp_path)
        .with_context(|| format!("Failed to read checksum file at {tmp_path}"))?;

    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        // `sha256sum` output: `<64-hex>  <filename>`. Two-space gap is
        // canonical; a single space marks "text mode" but we accept
        // either rather than be picky about emitter conventions.
        let mut iter = line.splitn(2, char::is_whitespace);
        let Some(hash) = iter.next() else { continue };
        let Some(rest) = iter.next() else { continue };
        let name = rest.trim().trim_start_matches('*').to_string();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            map.insert(name, hash.to_ascii_lowercase());
        }
    }

    for w in wanted {
        if !map.contains_key(*w) {
            anyhow::bail!(
                "Checksum manifest at {checksums_url} did not include\n\
                 an entry for '{w}'. Refusing to download an unverifiable\n\
                 artifact. ADR-002 §W5.1."
            );
        }
    }
    Ok(map)
}

/// Stream `path` through SHA-256 and compare to `expected` (lowercase
/// hex). On mismatch, delete the file and bail with a clear message.
/// On `MVM_SKIP_HASH_VERIFY=1`, log a warning and accept — the env-var
/// is the documented escape hatch for emergency-rotation scenarios per
/// plan 29.
fn verify_artifact_hash(path: &str, name: &str, expected: Option<&String>) -> Result<()> {
    if std::env::var_os("MVM_SKIP_HASH_VERIFY").is_some() {
        tracing::warn!(
            "MVM_SKIP_HASH_VERIFY set — skipping integrity check on {name}. \
             ADR-002 §W5.1 documents this as an emergency-rotation escape hatch."
        );
        return Ok(());
    }
    let Some(expected) = expected else {
        // fetch_expected_hashes already enforced presence, but defend
        // against a refactor that decouples the steps.
        anyhow::bail!("internal: no expected hash recorded for {name}");
    };

    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open downloaded artifact at {path}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("Failed to hash downloaded artifact at {path}"))?;
    let actual = format!("{:x}", hasher.finalize());

    if actual != *expected {
        let _ = std::fs::remove_file(path);
        bump_verify_outcome("digest_mismatch");
        anyhow::bail!(
            "Integrity check failed for {name}.\n\
             expected sha256: {expected}\n\
             actual   sha256: {actual}\n\
             \n\
             The downloaded artifact does not match the published checksum.\n\
             Refusing to use it. Possible causes:\n\
             - mid-flight corruption (retry the download);\n\
             - mirror/CDN cache poisoning (open an issue);\n\
             - the release was re-uploaded and the manifest is stale.\n\
             ADR-002 §W5.1."
        );
    }
    ui::info(&format!("  ✓ verified {name} sha256={}", &actual[..12]));
    Ok(())
}

/// Download a file from a URL using curl.
fn download_file(url: &str, dest: &str) -> Result<()> {
    let status = std::process::Command::new("curl")
        .args(["-fSL", "--progress-bar", "-o", dest, url])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run curl")?;

    if !status.success() {
        // Clean up partial download
        let _ = std::fs::remove_file(dest);
        anyhow::bail!(
            "Download failed. Pre-built images for v{version} may not yet be\n\
             published — release tags are pushed before the artifact-build\n\
             matrix completes, so a 404 here often just means the build is\n\
             still in flight. Check the release page or retry in a few\n\
             minutes:\n\
             \n\
             \x20   https://github.com/tinylabscom/mvm/releases/tag/v{version}\n\
             \n\
             To build locally instead, set up a Nix Linux builder:\n\
             \n\
             \x20 Option 1 — Temporary (run in another terminal):\n\
             \x20   nix run 'nixpkgs#darwin.linux-builder'\n\
             \n\
             \x20 Option 2 — Permanent (add to /etc/nix/nix.conf):\n\
             \x20   builders = ssh-ng://builder@linux-builder aarch64-linux /etc/nix/builder_ed25519 4 1 kvm,big-parallel - -\n\
             \x20   builders-use-substitutes = true",
            version = env!("CARGO_PKG_VERSION")
        );
    }
    Ok(())
}

/// Locate the builder-VM flake at `nix/images/builder-vm/flake.nix`.
///
/// Plan 115 / ADR-065: the consolidated flake produces both the
/// headless builder VM (`packages.<sys>.default`) and the interactive
/// dev-shell image (`packages.<sys>.dev`). Used by `ensure_dev_image`
/// to detect a source checkout, and by `bootstrap_builder_vm_image`
/// to locate Layer 1. Returns `Err` when not in a source checkout,
/// signalling the caller to fall back to the published prebuilt.
fn find_builder_vm_flake() -> Result<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root.join("nix").join("images").join("builder-vm");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }

    anyhow::bail!("Builder VM flake not found. Expected at nix/images/builder-vm/flake.nix.")
}

/// Plan 72 W5 — ensure `~/.cache/mvm/builder-vm/<arch>/` contains
/// `vmlinux` + `rootfs.ext4` before launching the libkrun builder.
///
/// `LibkrunBuilderVm::run_build` reads from this cache; this
/// function is what fills it. The two-layer artifact rule from
/// ADR-046 in action:
///
/// - Layer 1 (this function): ensure the **builder VM image** is
///   available in the local cache.
/// - Layer 2: use the Layer 1 image plus libkrun to build the
///   **dev shell image** with the large rustc closure.
///
/// Acquisition policy:
///
/// - Source checkout: a cache hit is allowed, but a cache miss fails
///   closed. The builder VM image must come from the in-repo
///   `nix/images/builder-vm/flake.nix` path; downloading a published
///   artifact would hide local builder-image changes.
/// - Installed binary: a cache hit is allowed; a cache miss may fetch
///   the published artifact for the running release version.
///
/// W5.B wired this into `ensure_dev_image`; Plan 72 W5's "Layer 1
/// outside source checkout — download the published prebuilt"
/// follow-up landed here.
///
/// `allow(dead_code)`: same justification as
/// [`find_builder_vm_flake`] — only called when
/// `builder-vm` is on.
#[allow(dead_code)]
fn bootstrap_builder_vm_image() -> Result<()> {
    let arch = builder_vm_host_arch();
    let out_dir = format!("{}/builder-vm/{arch}", mvm_core::config::mvm_cache_dir());
    let out_dir_path = std::path::Path::new(&out_dir);
    let builder_flake = find_builder_vm_flake();
    let source_fingerprint = builder_flake
        .as_ref()
        .ok()
        .map(|flake_dir| builder_vm_source_fingerprint(flake_dir))
        .transpose()?;
    let cache_ready = match source_fingerprint.as_deref() {
        Some(fingerprint) => {
            let status = builder_vm_source_cache_status(out_dir_path, fingerprint);
            ui::progress(&format!(
                "Builder VM source cache decision: {}",
                status.reason_code()
            ));
            status.is_ready()
        }
        None => validate_builder_vm_stage0_artifacts(out_dir_path).is_ok(),
    };

    match resolve_builder_vm_bootstrap_action(builder_flake, cache_ready)? {
        BuilderVmBootstrapAction::UseCached => {
            ui::info(&format!("Builder VM image already cached at {out_dir}."));
            Ok(())
        }
        BuilderVmBootstrapAction::BuildFromSource { flake_dir } => {
            #[cfg(feature = "builder-vm")]
            let source_fingerprint = source_fingerprint.ok_or_else(|| {
                anyhow::anyhow!("builder VM source fingerprint was not computed for {flake_dir}")
            })?;
            ui::info(&format!(
                "Builder VM image not in cache; building locally from {flake_dir}..."
            ));

            // Plan 115 / ADR-065: the Alpine root-dir Stage 0 is the
            // only bootstrap path. The dev-image Stage 0 path
            // (bootstrap_builder_vm_image_via_dev_image_stage0) has been
            // removed; `nix/images/builder/flake.nix` is deleted.
            #[cfg(feature = "builder-vm")]
            {
                bootstrap_builder_vm_image_via_root_dir_stage0(
                    &flake_dir,
                    &out_dir,
                    &source_fingerprint,
                )
                .context("building the source-checkout builder VM image via root-dir Stage 0")
            }

            #[cfg(not(feature = "builder-vm"))]
            {
                let _ = (&flake_dir, &out_dir, &source_fingerprint, arch);
                anyhow::bail!(
                    "Stage 0 needs the `builder-vm` cargo feature to be enabled \
                     for this `mvmctl` build."
                )
            }
        }
        BuilderVmBootstrapAction::DownloadPublished => {
            perform_builder_vm_download_published(arch, &out_dir)
        }
    }
}

fn builder_vm_host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// Plan 77 W4: the only call site that can invoke the published-prebuilt
/// download path. Gated behind `release-artifact-bootstrap`. Contributor
/// builds (the default) hit the `cfg(not(...))` arm and bail structurally
/// — even if the resolver routed here, the function refuses to touch the
/// network. End-user-binary release builds opt in at compile time.
///
/// Extracted from [`bootstrap_builder_vm_image`] specifically so the
/// fail-closed shape is unit-testable.
fn perform_builder_vm_download_published(arch: &str, out_dir: &str) -> Result<()> {
    #[cfg(feature = "release-artifact-bootstrap")]
    {
        ui::info(&format!(
            "Builder VM image not in cache; downloading published prebuilt for v{}...",
            env!("CARGO_PKG_VERSION")
        ));
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("creating builder-vm cache dir {out_dir}"))?;
        download_builder_vm_image(arch, out_dir).context("downloading the builder VM image")
    }
    #[cfg(not(feature = "release-artifact-bootstrap"))]
    {
        let _ = (arch, out_dir);
        anyhow::bail!(
            "Builder VM image is missing and no in-repo builder VM flake \
             was found. This `mvmctl` binary was built without the \
             `release-artifact-bootstrap` feature, so it cannot pull a \
             published prebuilt from GitHub releases (per Plan 77 W4 and \
             the AGENTS.md / CLAUDE.md invariant). \
             Run from a source checkout that has \
             `nix/images/builder-vm/flake.nix`, or rebuild `mvmctl` with \
             `--features release-artifact-bootstrap` (release-cut binaries only)."
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum BuilderVmBootstrapAction {
    UseCached,
    BuildFromSource { flake_dir: String },
    DownloadPublished,
}

fn resolve_builder_vm_bootstrap_action(
    builder_flake: Result<String>,
    cache_ready: bool,
) -> Result<BuilderVmBootstrapAction> {
    if cache_ready {
        return Ok(BuilderVmBootstrapAction::UseCached);
    }

    match builder_flake {
        Ok(flake_dir) => Ok(BuilderVmBootstrapAction::BuildFromSource { flake_dir }),
        Err(_) => Ok(BuilderVmBootstrapAction::DownloadPublished),
    }
}

/// Stage 0 bootstrap via libkrun's `krun_set_root` mode — extract
/// Alpine Linux's official minirootfs (hash + PGP-verified against
/// the embedded Alpine release key in mvm source) into a host
/// directory, layer our `/init` on top, and hand the directory to
/// libkrun. libkrun mounts it as the guest root via virtiofs
/// against libkrunfw's bundled TSI-patched kernel. The init script
/// runs `apk add nix`, builds the in-repo `nix/images/builder-vm`
/// flake against `/work`, and writes the steady-state artifacts
/// (`vmlinux`, `rootfs.ext4`, `cmdline.txt`) to `/out`, then
/// powers off.
///
/// Replaces the previous initramfs-cpio dispatch shape: libkrunfw's
/// kernel ships with `CONFIG_BLK_DEV_INITRD=n`, so cpio initramfs
/// cannot unpack. `set_root` mode is libkrun's intended container
/// boot path and uses the same kernel without modification. Plan 91
/// further replaced the `nix-portable` bootstrap (which served a
/// macOS Mach-O binary under the `aarch64` name upstream) with the
/// Alpine path.
#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_via_root_dir_stage0(
    builder_flake_dir: &str,
    out_dir: &str,
    source_fingerprint: &str,
) -> Result<()> {
    use mvm_build::libkrun_builder::BuilderVmImage;

    let _stage0_guard = acquire_stage0_lock(out_dir)?;

    // Plan 93 Phase 3: time each host-visible Stage 0 step and print a
    // one-line `[mvm] <step> … <secs>s` so perceived speed matches the
    // actual per-step wall-clock.
    let fetch_started = std::time::Instant::now();
    let stage0_assets = mvm_build::stage0::assets_for_host_arch();
    let vendor_reports = mvm_build::stage0::prepare_assets(stage0_assets)
        .context("preparing Stage 0 bootstrap assets (Alpine minirootfs + signature)")?;
    ui::timed_step("Fetching Stage 0 bootstrap assets", fetch_started.elapsed());
    // One VendorBlobFetched audit entry per vendored blob (covers both
    // fresh fetch and cache revalidation), so every supply-chain trust
    // decision in the no-prebuilt-download path is auditable. The emit
    // lives here (the host caller) so `mvm-build` stays audit-free.
    for report in &vendor_reports {
        mvm_core::policy::audit::emit(
            mvm_core::policy::audit::LocalAuditKind::VendorBlobFetched,
            None,
            Some(&report.audit_detail()),
        );
    }

    // Materialize the guest root tree (Alpine minirootfs + /init +
    // stubs) under a stable per-host location. libkrun mounts this
    // directory as the guest root via virtiofs.
    let root_dir = mvm_build::stage0::stage0_cache_dir().join("root");
    if root_dir.exists() {
        std::fs::remove_dir_all(&root_dir).with_context(|| {
            format!("clearing previous Stage 0 root dir {}", root_dir.display())
        })?;
    }
    let materialize_started = std::time::Instant::now();
    mvm_build::stage0::materialize_root_dir(&root_dir)
        .with_context(|| format!("materializing Stage 0 root at {}", root_dir.display()))?;
    ui::timed_step(
        "Materializing Stage 0 root dir",
        materialize_started.elapsed(),
    );

    // Workspace root = three dirs above the flake.nix
    // (nix/images/builder-vm/flake.nix → repo root).
    let workspace_root = std::path::Path::new(builder_flake_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake_dir}"))?
        .to_path_buf();

    let out_dir_path = std::path::Path::new(out_dir);
    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let started = std::time::Instant::now();
    let fingerprint_prefix = stage0_fingerprint_prefix(source_fingerprint);
    mvm_core::audit_emit!(
        Stage0Boot,
        "seed=root-dir fingerprint_prefix={fingerprint_prefix} flavor={flavor}",
        flavor = STAGE0_FLAVOR_CURRENT,
    );

    // ADR-065: extract the embedded host-vm binaries so the Stage 0 nix
    // build can install them from /mvm-bins instead of building them with
    // the guest's nix. Same cache dir the steady-state job path uses.
    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir =
        crate::host_binaries::extract::ensure_extracted(std::path::Path::new(&host_bins_cache))
            .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    let image = BuilderVmImage::new_root_dir(root_dir.clone(), "/init");
    let result = run_stage0_root_dir(
        &staging_dir,
        &workspace_root,
        image,
        &host_bin_dir,
        source_fingerprint,
    );
    let duration_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(()) => {
            promote_builder_vm_stage0_cache(&staging_dir, out_dir_path, source_fingerprint)
                .context("promoting Stage 0 artifacts into the builder VM cache")?;
            mvm_core::audit_emit!(
                Stage0CachePromoted,
                "cache={cache} fingerprint_prefix={fingerprint_prefix} duration_ms={duration_ms} flavor={flavor}",
                cache = out_dir_path.display(),
                flavor = STAGE0_FLAVOR_CURRENT,
            );
            Ok(())
        }
        Err((stage, e)) => {
            let _ = std::fs::remove_dir_all(&staging_dir);
            let reason = stage0_failure_reason_summary(&e);
            mvm_core::audit_emit!(
                Stage0Failed,
                "stage={stage} duration_ms={duration_ms} reason={reason}"
            );
            Err(e)
        }
    }
}

/// Boot the Stage 0 VM with the supplied `RootDir` image, mounting
/// `workspace_root` as `/work` and `staging_dir` as `/out`. On
/// clean exit, write the cache-validation sidecars next to the
/// emitted artifacts so the outer caller can promote them into the
/// per-arch builder VM cache.
#[cfg(feature = "builder-vm")]
fn run_stage0_root_dir(
    staging_dir: &std::path::Path,
    workspace_root: &std::path::Path,
    image: mvm_build::libkrun_builder::BuilderVmImage,
    host_bin_dir: &std::path::Path,
    source_fingerprint: &str,
) -> std::result::Result<(), (Stage0FailureStage, anyhow::Error)> {
    use mvm_build::libkrun_builder::LibkrunBuilderVm;

    LibkrunBuilderVm::default()
        .run_stage0(image, workspace_root, staging_dir, host_bin_dir)
        .map_err(|e| {
            (
                Stage0FailureStage::Build,
                anyhow::anyhow!("Stage 0 root-dir build: {e}"),
            )
        })?;

    write_builder_vm_source_fingerprint(staging_dir, source_fingerprint)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;
    write_builder_vm_artifact_digest_manifest(staging_dir)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;
    write_builder_vm_source_cache_provenance(staging_dir, source_fingerprint)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;

    Ok(())
}

/// Plan 93 Phase 0: which Stage 0 bootstrap variant this build runs.
///
/// The `flavor=` field on `Stage0Boot` / `Stage0CachePromoted` audit
/// detail strings carries this value so a future per-variant identifier
/// (e.g. Plan 91's Alpine bootstrap, an experimental seed image) only
/// needs to flip this single constant — not every emit site. Today
/// there is one variant, so the value is the literal `"current"`.
#[cfg(feature = "builder-vm")]
const STAGE0_FLAVOR_CURRENT: &str = "current";

/// Plan 77 W3: which phase of Stage 0 failed. Each variant maps to a
/// `stage=...` value in the `Stage0Failed` audit detail so a dashboard
/// can break down "Stage 0 reliability" by failure phase. String
/// representations are stable wire format.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy)]
enum Stage0FailureStage {
    Build,
    Validate,
}

#[cfg(feature = "builder-vm")]
impl Stage0FailureStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Validate => "validate",
        }
    }
}

#[cfg(feature = "builder-vm")]
impl std::fmt::Display for Stage0FailureStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extract libkrunfw's bundled TSI-patched kernel into the host cache
/// and return the on-disk path. Only available when `libkrun-sys` is
/// compiled in (the default on macOS + Linux libkrun hosts) — without
/// that feature the FFI is dead code and the caller falls back.
///
/// Currently unused on the main path; reserved for the follow-up
/// PR that wires the initramfs Stage 0 dispatch (the initramfs
/// path needs a kernel and libkrunfw is where we get it).
#[cfg(all(feature = "builder-vm", feature = "libkrun-sys"))]
#[allow(dead_code)]
fn extract_libkrunfw_kernel() -> Result<std::path::PathBuf> {
    let cache_dir =
        std::path::PathBuf::from(format!("{}/libkrunfw", mvm_core::config::mvm_cache_dir()));
    let target = cache_dir.join("vmlinux");
    let bundled = mvm_libkrun::extract_bundled_kernel(&target)
        .map_err(|e| anyhow::anyhow!("libkrunfw kernel extraction: {e}"))?;
    ui::info(&format!(
        "Extracted libkrunfw kernel ({} bytes) to {}",
        bundled.size,
        bundled.path.display()
    ));
    Ok(bundled.path)
}

#[cfg(all(feature = "builder-vm", not(feature = "libkrun-sys")))]
#[allow(dead_code)]
fn extract_libkrunfw_kernel() -> Result<std::path::PathBuf> {
    anyhow::bail!(
        "libkrunfw kernel extraction requires the `libkrun-sys` feature; \
         rebuild `mvmctl` with `--features libkrun-sys` on a host with libkrun installed."
    )
}

/// Plan 77 W3: short prefix of the source fingerprint for audit
/// `fingerprint_prefix=` field. 8 hex chars are enough to disambiguate
/// against unrelated `dev up` runs without exposing the full digest.
#[cfg(feature = "builder-vm")]
fn stage0_fingerprint_prefix(source_fingerprint: &str) -> String {
    source_fingerprint.chars().take(8).collect::<String>()
}

/// Plan 77 W3: condense an `anyhow::Error` into the short single-line
/// `reason=` field for `Stage0Failed`. The full chain is on stderr
/// already; the audit field is for "what broke at a glance". Capped
/// at 160 chars and stripped of newlines / commas / spaces around
/// `=`-signs so the space-separated `key=value` detail format stays
/// parseable.
#[cfg(feature = "builder-vm")]
fn stage0_failure_reason_summary(err: &anyhow::Error) -> String {
    let raw = err.to_string();
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            // Audit detail is space-separated `key=value` pairs; any
            // bare `=` in the reason text would confuse a downstream
            // parser, so map them to `~` (visibly distinct from `=`).
            '=' => '~',
            _ => c,
        })
        .collect();
    let truncated: String = cleaned.chars().take(160).collect();
    truncated
}

/// Plan 77 W2 — RAII advisory lock at
/// `~/.cache/mvm/builder-vm/stage0.lock` (one directory above the
/// per-arch cache). `try_acquire` is non-blocking, so a concurrent
/// invocation bails fast with a clear message instead of silently
/// queuing for minutes behind a libkrun-builder VM that's already
/// busy holding the shared `nix-store-<arch>.img` volume.
///
/// `out_dir` is the per-arch cache dir (e.g. `.../builder-vm/aarch64`);
/// the lock anchor is its sibling `stage0` (so `FileLock::try_acquire`
/// produces `stage0.lock`).
#[cfg(any(feature = "builder-vm", test))]
fn acquire_stage0_lock(out_dir: &str) -> Result<mvm_core::atomic_io::FileLock> {
    use mvm_core::atomic_io::FileLock;

    let parent = std::path::Path::new(out_dir)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("builder VM cache path has no parent: {out_dir}"))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let lock_anchor = parent.join("stage0");

    match FileLock::try_acquire(&lock_anchor) {
        Ok(Some(guard)) => Ok(guard),
        Ok(None) => anyhow::bail!(
            "another `mvmctl dev up` (or any caller of Stage 0) is already bootstrapping the \
             builder VM image on this host (lock held at {}.lock). Wait for it to finish, or — \
             only if you are sure no other invocation is running, e.g. after a crash — delete the \
             lock file and retry.",
            lock_anchor.display()
        ),
        Err(e) => Err(e.context("acquiring Stage 0 advisory lock")),
    }
}

#[cfg(any(feature = "builder-vm", test))]
fn unique_builder_vm_stage0_staging_dir(final_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let parent = final_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "builder VM cache path has no parent: {}",
            final_dir.display()
        )
    })?;
    let name = final_dir
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "builder VM cache path has no UTF-8 basename: {}",
                final_dir.display()
            )
        })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating builder-vm cache parent {}", parent.display()))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Ok(parent.join(format!(".{name}.stage0-{}-{nonce}", std::process::id())))
}

fn validate_builder_vm_stage0_artifacts(dir: &std::path::Path) -> Result<()> {
    let rootfs = dir.join("rootfs.ext4");
    validate_dev_image_artifacts(dir.join("vmlinux"), &rootfs).with_context(|| {
        format!(
            "validating Stage 0 builder VM artifacts in {}",
            dir.display()
        )
    })?;
    if !rootfs_contains_builder_init(&rootfs)? {
        anyhow::bail!(
            "Stage 0 builder VM artifact {} is missing /sbin/mvm-host-vm-init",
            rootfs.display()
        );
    }
    Ok(())
}

/// Plan 77 W2 — outcome of [`sweep_orphaned_stage0_staging_dirs`]:
/// either the sweep ran (with counts) or the Stage 0 advisory lock was
/// already held so the sweep was skipped to avoid racing a live
/// bootstrap. The pruner uses the variant to decide what to print.
pub(in crate::commands) enum Stage0SweepOutcome {
    Swept { removed: u64, freed_bytes: u64 },
    SkippedLockHeld,
}

/// Plan 77 W2 — remove staging directories from a crashed Stage 0
/// bootstrap. Only safe to run when no Stage 0 is currently in progress;
/// the function tries the same advisory lock the live bootstrap uses
/// and bails (returns `SkippedLockHeld`) on contention rather than
/// racing it. Called from `mvmctl cache prune` so the cleanup ships
/// with the existing "clean everything" verb.
///
/// "Orphan" means the staging dir was left behind by a crashed run;
/// successful Stage 0 runs `rename(2)` the staging dir into the live
/// cache, so any staging dir on disk is by definition orphaned. Format
/// matches [`unique_builder_vm_stage0_staging_dir`]
/// (`.<arch>.stage0-<pid>-<nonce>`); we also recognise the legacy
/// `<arch>-staging[-...]` shape from pre-W1 builds on the same host.
pub(in crate::commands) fn sweep_orphaned_stage0_staging_dirs(
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    let builder_vm_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm");
    sweep_orphaned_stage0_staging_dirs_at(&builder_vm_root, dry_run)
}

/// Inner form of [`sweep_orphaned_stage0_staging_dirs`] that takes an
/// explicit root path. Exists so unit tests can exercise the sweep
/// against a tempdir without mutating `MVM_CACHE_DIR` or any other
/// process-wide env var.
fn sweep_orphaned_stage0_staging_dirs_at(
    builder_vm_root: &std::path::Path,
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    use mvm_core::atomic_io::FileLock;

    if !builder_vm_root.is_dir() {
        return Ok(Stage0SweepOutcome::Swept {
            removed: 0,
            freed_bytes: 0,
        });
    }

    // Try the Stage 0 advisory lock. The lock anchor is shared with the
    // live `acquire_stage0_lock` callsite — when a `dev up` is in
    // progress, we want the pruner to skip the staging sweep rather
    // than race it. RAII drop releases the lock when this function
    // returns.
    let lock_anchor = builder_vm_root.join("stage0");
    let _guard = match FileLock::try_acquire(&lock_anchor) {
        Ok(Some(guard)) => guard,
        Ok(None) => return Ok(Stage0SweepOutcome::SkippedLockHeld),
        Err(e) => {
            // I/O failure on the lock path is rare (e.g. parent disappeared
            // mid-prune). Treat it as "skip with a warning" rather than
            // failing the whole prune verb — the staging sweep is a best-
            // effort hygiene step.
            tracing::warn!(err = %e, "could not acquire Stage 0 lock for sweep; skipping");
            return Ok(Stage0SweepOutcome::SkippedLockHeld);
        }
    };

    let mut removed = 0u64;
    let mut freed_bytes = 0u64;
    let entries = match std::fs::read_dir(builder_vm_root) {
        Ok(e) => e,
        Err(_) => {
            return Ok(Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            });
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_orphan_stage0_staging_dir_name(&name) || !path.is_dir() {
            continue;
        }
        let size = stage0_dir_size_bytes(&path);
        if dry_run {
            println!(
                "Would remove orphan Stage 0 staging dir: {} ({} bytes)",
                path.display(),
                size,
            );
        } else if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!(path = %path.display(), err = %e, "could not remove orphan staging dir");
            continue;
        }
        removed += 1;
        freed_bytes += size;
    }
    Ok(Stage0SweepOutcome::Swept {
        removed,
        freed_bytes,
    })
}

/// Plan 95 §FU-1 — outcome of [`reap_orphaned_vm_helpers`]. Counts
/// orphaned helper PIDs that were signalled and per-VM cache dirs
/// removed, plus the bytes freed by removing those dirs. Pruner-side
/// caller uses this to print a clean one-line summary.
pub(in crate::commands) struct ReapOutcome {
    pub killed: u64,
    pub removed_dirs: u64,
    pub freed_bytes: u64,
}

/// Plan 95 §FU-1 — reap orphaned per-VM helpers left behind by killed
/// `mvmctl dev up` runs. Covers both backends: libkrun (`mvm-libkrun-
/// supervisor` + `gvproxy`) and Vz (`mvm-vz-supervisor`).
///
/// mvmctl spawns the active backend's supervisor binary, which in turn
/// spawns its networking helper (gvproxy for libkrun). If mvmctl exits
/// abnormally (^C, SIGKILL, crash), supervisor + helpers are reparented
/// to launchd PID 1 and outlive mvmctl indefinitely (Plan 95 doc
/// §Follow-ups FU-2/FU-3 cover the "prevent" side; this is the "clean
/// up after the fact" side — FU-1).
///
/// The dir traversal below is **prefix-agnostic**: it iterates every
/// subdirectory of `~/.cache/mvm/builder-vm/vms/`, so both
/// `mvm-builder-vm-<job_id>` (libkrun) and `mvm-builder-vz-<job_id>`
/// (Vz) state dirs are picked up by the same loop, and the sidecar PID
/// names (`builder.pid` / `stage0.pid`) are shared across backends. The
/// `reap_picks_up_orphaned_vz_builder_state_dir` test pins this — a
/// future refactor that narrows the traversal or renames the sidecar
/// must update that test. See Plan 97 Phase C and Plan 99 PR-1.
///
/// Two scans per VM dir:
///
/// 1. **Sidecar PID scan.** Each dir carries a `{builder.pid,
///    stage0.pid}` sidecar with the supervisor's PID. (Earlier
///    versions of this function looked for the wrong names
///    (`supervisor.pid`/`gvproxy.pid`); the actual sidecar names
///    are `builder.pid` for steady-state and `stage0.pid` for
///    Stage 0 — fixed after smoke-testing on accumulated state
///    showed `0` PIDs killed despite live orphans.)
/// 2. **Argv scan.** `gvproxy` is the supervisor's GRANDCHILD and
///    writes no sidecar of its own — its argv references the VM
///    dir's `gvproxy.sock`. The argv scan catches those grandchildren
///    even after the supervisor is gone. Same for `tail -F` readers
///    of `console.log`.
///
/// For each PID found by either scan:
/// - dead → ignore
/// - alive with a non-launchd parent → in-flight dev up; mark dir
///   as "has a live owner", skip dir removal
/// - alive with launchd as parent → SIGTERM and count
///
/// Then if no helper in the dir had a live non-launchd parent, the
/// dir is removed. This avoids the over-aggressive `rm -rf $vm/`
/// of the prototype `/tmp/plan95/reap.sh`, which during validation
/// nuked a live mvmctl's state dir.
pub(in crate::commands) fn reap_orphaned_vm_helpers(dry_run: bool) -> Result<ReapOutcome> {
    let vms_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm/vms");
    reap_orphaned_vm_helpers_at(&vms_root, dry_run)
}

/// Inner form taking an explicit `vms_root`. Exists for tests against
/// a tempdir without mutating `MVM_CACHE_DIR`.
fn reap_orphaned_vm_helpers_at(vms_root: &std::path::Path, dry_run: bool) -> Result<ReapOutcome> {
    let mut outcome = ReapOutcome {
        killed: 0,
        removed_dirs: 0,
        freed_bytes: 0,
    };
    if !vms_root.is_dir() {
        return Ok(outcome);
    }

    for entry in std::fs::read_dir(vms_root)?.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }

        let mut dir_has_live_owner = false;
        let mut killed_in_dir = 0u64;
        let mut seen_pids: std::collections::HashSet<i32> = std::collections::HashSet::new();

        // Scan 1 — sidecar files. Steady-state builder VMs write
        // `builder.pid`; Stage 0 writes `stage0.pid`.
        for sidecar in ["builder.pid", "stage0.pid"] {
            let pid_file = dir.join(sidecar);
            let Some(pid) = read_pid_file(&pid_file) else {
                continue;
            };
            if !seen_pids.insert(pid) {
                continue;
            }
            match classify_pid(pid) {
                PidClassification::Dead => {}
                PidClassification::LiveOwned => dir_has_live_owner = true,
                PidClassification::Orphan => {
                    if !dry_run {
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                    }
                    killed_in_dir += 1;
                }
            }
        }

        // Scan 2 — argv scan for grandchildren (gvproxy, tail -F …
        // console.log). They don't write sidecars but their argv
        // contains the VM dir basename (the `mvm-stage0-…` or
        // `mvm-builder-vm-…` id), which is unique on this host.
        let dir_basename = match dir.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        for pid in pids_referencing(&dir_basename) {
            if !seen_pids.insert(pid) {
                continue;
            }
            match classify_pid(pid) {
                PidClassification::Dead => {}
                PidClassification::LiveOwned => dir_has_live_owner = true,
                PidClassification::Orphan => {
                    if !dry_run {
                        unsafe {
                            libc::kill(pid, libc::SIGTERM);
                        }
                    }
                    killed_in_dir += 1;
                }
            }
        }

        outcome.killed += killed_in_dir;
        if dir_has_live_owner {
            continue;
        }

        let size = dir_size_bytes(&dir);
        if !dry_run {
            let _ = std::fs::remove_dir_all(&dir);
        }
        outcome.removed_dirs += 1;
        outcome.freed_bytes += size;
    }

    Ok(outcome)
}

enum PidClassification {
    Dead,
    LiveOwned, // alive, parent is something other than launchd → in-flight
    Orphan,    // alive, parent is launchd PID 1 → SIGTERM-able
}

fn classify_pid(pid: i32) -> PidClassification {
    if !pid_is_alive(pid) {
        return PidClassification::Dead;
    }
    match pid_parent(pid) {
        Some(1) => PidClassification::Orphan,
        _ => PidClassification::LiveOwned,
    }
}

/// Find all PIDs whose argv contains `needle`. Used by the argv-scan
/// pass to catch grandchildren (gvproxy, console-tail) that don't
/// write a sidecar file. macOS has no `/proc`, so the portable path
/// is `pgrep -f <needle>` — argv-substring match.
fn pids_referencing(needle: &str) -> Vec<i32> {
    let out = match std::process::Command::new("pgrep")
        .args(["-f", needle])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|s| s.trim().parse::<i32>().ok())
        .filter(|&p| p > 1)
        .collect()
}

fn read_pid_file(path: &std::path::Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 1)
}

fn pid_is_alive(pid: i32) -> bool {
    // Signal 0 = existence check, doesn't deliver a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Returns the parent PID, or `None` if the process is gone or its
/// PPID can't be read. macOS has no `/proc`; the portable path is
/// `ps -o ppid= -p <pid>`. Shelling out adds ~5 ms per call, which
/// is acceptable for a pruner that runs a handful of times per
/// session (and not on a hot path).
fn pid_parent(pid: i32) -> Option<i32> {
    let out = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<i32>()
        .ok()
}

fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return total;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            total += p.metadata().map(|m| m.len()).unwrap_or(0);
        } else if p.is_dir() {
            total += dir_size_bytes(&p);
        }
    }
    total
}

/// Predicate matching the staging-dir basenames left by Stage 0.
/// Two shapes are recognised:
/// - Current (W1+): `.<arch>.stage0-<pid>-<nonce>` (hidden, see
///   [`unique_builder_vm_stage0_staging_dir`]).
/// - Legacy (pre-W1): `<arch>-staging` or `<arch>-staging-<suffix>`
///   left behind by earlier Stage 0 prototypes that were observed on
///   contributor hosts; harmless when they exist but the pruner is
///   the obvious place to clean them up.
fn is_orphan_stage0_staging_dir_name(name: &str) -> bool {
    let is_known_arch = |arch: &str| arch == "aarch64" || arch == "x86_64";

    // Current hidden form.
    if let Some(rest) = name.strip_prefix('.')
        && let Some((arch, tail)) = rest.split_once('.')
        && is_known_arch(arch)
        && tail.starts_with("stage0-")
    {
        return true;
    }
    // Legacy `<arch>-staging` / `<arch>-staging-<suffix>`.
    if let Some((arch, tail)) = name.split_once('-')
        && is_known_arch(arch)
        && (tail == "staging" || tail.starts_with("staging"))
    {
        return true;
    }
    false
}

/// Total byte size of a directory tree. Best-effort — failures stat-ing
/// individual entries are skipped silently because the caller only uses
/// this for the "bytes freed" UI counter, never for correctness.
fn stage0_dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(entry_path),
                Ok(_) => {
                    if let Ok(meta) = entry_path.metadata() {
                        total = total.saturating_add(meta.len());
                    }
                }
                Err(_) => {}
            }
        }
    }
    total
}

/// Fingerprint the full set of source inputs that determine the
/// builder-VM rootfs.
///
/// The builder-VM rootfs is built by `nix/images/builder-vm/flake.nix`
/// from three categories of source input:
///
/// 1. The flake itself (`flake.nix` + `flake.lock`) — controls
///    which `nixpkgs` rev, which `mkGuest` shape, which `microvm.nix`,
///    which packages get installed.
/// 2. The workspace `Cargo.lock` — `rustPlatform.buildRustPackage`
///    consumes it for the dep closure of every Rust binary baked
///    into the rootfs (`mvm-host-vm-init`, `mvm-egress-proxy`).
/// 3. The Rust sources of the in-VM binaries (`crates/mvm-host-vm-init/`,
///    `crates/mvm-egress-proxy/`) — these are the actual PID-1 +
///    egress-proxy binaries the rootfs runs.
///
/// Pre-2026-05 this function only hashed (1), with the result that
/// contributor edits to `crates/mvm-host-vm-init/src/main.rs` (or
/// any other Rust source baked into the rootfs) silently reused the
/// cached `rootfs.ext4`. The bug burned the PR #420 dev-loop
/// repeatedly: every test required manually `rm -rf
/// ~/.cache/mvm/builder-vm/aarch64/` to force a Stage 0 rebuild.
/// This version closes that hole.
///
/// ## Scope and tradeoffs
///
/// We don't hash the entire workspace. A change to `mvm-cli` doesn't
/// affect the rootfs and shouldn't invalidate the cache. The two
/// crates listed match the `rustPlatform.buildRustPackage` calls in
/// `nix/images/builder-vm/flake.nix` (`mvmBuilderInitFor` +
/// `mvmEgressProxyFor`); a future flake change that bakes a third
/// Rust binary into the rootfs needs to add that crate to the list
/// here.
///
/// ## Hash discipline
///
/// Same shape as the original flake-only hash:
/// `{name}\0{u64-length-LE}\0{contents}\0`, repeated for each input.
/// The `name` is the relative path keyed off the workspace, so
/// renaming a file or moving it across crates changes the fingerprint.
/// Files within a directory are visited in lexicographic order
/// regardless of filesystem read order so the hash is deterministic
/// across HFS+, APFS, and ext4.
fn builder_vm_source_fingerprint(builder_flake_dir: &str) -> Result<String> {
    let flake_dir = std::path::Path::new(builder_flake_dir);
    let workspace_root = workspace_root_for_builder_flake(flake_dir)?;
    let mut hasher = Sha256::new();

    // Layer 1: flake-local inputs.
    for name in ["flake.nix", "flake.lock"] {
        let path = flake_dir.join(name);
        if !path.exists() {
            if name == "flake.nix" {
                anyhow::bail!("builder VM source fingerprint missing {}", path.display());
            }
            continue;
        }
        hash_named_file(&mut hasher, name, &path)?;
    }

    // Layer 2: workspace Cargo.lock. `rustPlatform.buildRustPackage`
    // consumes it for every Rust binary baked into the rootfs.
    let cargo_lock = workspace_root.join("Cargo.lock");
    if !cargo_lock.is_file() {
        anyhow::bail!(
            "builder VM source fingerprint missing {} \
             (workspace root resolved from flake dir as {})",
            cargo_lock.display(),
            workspace_root.display()
        );
    }
    hash_named_file(&mut hasher, "Cargo.lock", &cargo_lock)?;

    // Layer 3: in-VM binary sources. Each crate listed here
    // corresponds to a `rustPlatform.buildRustPackage` call in
    // `nix/images/builder-vm/flake.nix`. Add to this list when a
    // new Rust binary gets baked into the rootfs.
    //
    // Only `Cargo.toml` and the recursive `src/` tree enter the
    // closure `rustc` actually sees. `README.md`, `CHANGELOG.md`,
    // and other crate-root files don't influence the baked binary,
    // so they don't bust the Stage 0 cache (Plan 93 Phase 0).
    for crate_name in ["mvm-host-vm-init", "mvm-egress-proxy"] {
        let crate_dir = workspace_root.join("crates").join(crate_name);
        if !crate_dir.is_dir() {
            anyhow::bail!(
                "builder VM source fingerprint missing crate dir {}",
                crate_dir.display()
            );
        }

        let cargo_toml = crate_dir.join("Cargo.toml");
        if !cargo_toml.is_file() {
            anyhow::bail!(
                "builder VM source fingerprint missing {}",
                cargo_toml.display()
            );
        }
        hash_named_file(
            &mut hasher,
            &format!("crates/{crate_name}/Cargo.toml"),
            &cargo_toml,
        )?;

        let src_dir = crate_dir.join("src");
        if !src_dir.is_dir() {
            anyhow::bail!(
                "builder VM source fingerprint missing crate src dir {}",
                src_dir.display()
            );
        }
        hash_dir_recursive(&mut hasher, &format!("crates/{crate_name}/src"), &src_dir)?;
    }

    // Layer 4: the embedded host-binary identity. These bytes are what
    // actually get baked into the rootfs, so their SHA captures anything
    // the crate-src hash above can miss — chiefly the cross-compile
    // toolchain (a gnu→musl target switch produces different binaries
    // from identical source). Without this a toolchain change would
    // silently reuse a stale cached image.
    for bin in crate::host_binaries::embedded::EMBEDDED.iter() {
        hasher.update(b"host-bin\0");
        hasher.update(bin.name.as_bytes());
        hasher.update(b"\0");
        hasher.update(bin.sha256_hex.as_bytes());
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Resolve the workspace root from the builder-VM flake dir.
///
/// `find_builder_vm_flake` computes the flake path as
/// `<workspace>/nix/images/builder-vm`, so walking three parents up
/// lands on the workspace. Splitting this out for the fingerprint
/// tests to call without going through `find_builder_vm_flake`'s
/// `CARGO_MANIFEST_DIR` lookup.
fn workspace_root_for_builder_flake(flake_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    flake_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot resolve workspace root from builder-vm flake dir {} \
                 (expected <workspace>/nix/images/builder-vm)",
                flake_dir.display()
            )
        })
}

/// Feed a single named file into the hasher using the original
/// flake-fingerprint discipline: `{name}\0{u64-length-LE}\0{contents}\0`.
fn hash_named_file(hasher: &mut Sha256, name: &str, path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading builder VM source input {}", path.display()))?;
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(b"\0");
    hasher.update(&bytes);
    hasher.update(b"\0");
    Ok(())
}

/// Hash every regular file under `dir` recursively, keyed by
/// `<prefix>/<relative-path>` so the fingerprint reflects directory
/// structure. Skips hidden entries and `target/` — neither is an
/// input to `rustPlatform.buildRustPackage`.
fn hash_dir_recursive(hasher: &mut Sha256, prefix: &str, dir: &std::path::Path) -> Result<()> {
    let files = walk_source_dir_sorted(dir)
        .with_context(|| format!("walking builder VM source dir {}", dir.display()))?;
    for path in &files {
        let rel = path.strip_prefix(dir).map_err(|e| {
            anyhow::anyhow!(
                "strip_prefix {} from {}: {e}",
                dir.display(),
                path.display()
            )
        })?;
        let key = format!("{prefix}/{}", rel.display());
        hash_named_file(hasher, &key, path)?;
    }
    Ok(())
}

/// Walk every regular file under `dir`, skipping hidden entries
/// (`.git/`, `.DS_Store`, …), editor swap files (`*.swp`), and
/// `target/` (cargo build output). Paths are returned
/// lexicographically sorted so the hash is deterministic regardless
/// of filesystem read order.
fn walk_source_dir_sorted(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).with_context(|| format!("read_dir {}", d.display()))?;
        for e in entries {
            let e = e.with_context(|| format!("read_dir entry in {}", d.display()))?;
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with('.') || name_str == "target" || name_str.ends_with(".swp") {
                continue;
            }
            let path = e.path();
            let ft = e
                .file_type()
                .with_context(|| format!("file_type {}", path.display()))?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BuilderVmSourceCacheStatus {
    Hit,
    MissingArtifact,
    InvalidStage0Artifacts,
    MissingFingerprint,
    FingerprintMismatch,
    MissingArtifactDigestManifest,
    ArtifactDigestMismatch,
    MissingProvenance,
    ProvenanceMismatch,
}

impl BuilderVmSourceCacheStatus {
    fn is_ready(self) -> bool {
        self == Self::Hit
    }

    fn reason_code(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::MissingArtifact => "missing_artifact",
            Self::InvalidStage0Artifacts => "invalid_stage0_artifacts",
            Self::MissingFingerprint => "missing_fingerprint",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::MissingArtifactDigestManifest => "missing_artifact_digest_manifest",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::MissingProvenance => "missing_provenance",
            Self::ProvenanceMismatch => "provenance_mismatch",
        }
    }
}

fn builder_vm_source_cache_status(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> BuilderVmSourceCacheStatus {
    if !dir.join("vmlinux").exists() || !dir.join("rootfs.ext4").exists() {
        return BuilderVmSourceCacheStatus::MissingArtifact;
    }
    if validate_builder_vm_stage0_artifacts(dir).is_err() {
        return BuilderVmSourceCacheStatus::InvalidStage0Artifacts;
    }

    let fingerprint_path = dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE);
    let Ok(actual_fingerprint) = std::fs::read_to_string(fingerprint_path) else {
        return BuilderVmSourceCacheStatus::MissingFingerprint;
    };
    if actual_fingerprint.trim() != expected_fingerprint {
        return BuilderVmSourceCacheStatus::FingerprintMismatch;
    }

    let digest_path = dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE);
    if !digest_path.exists() {
        return BuilderVmSourceCacheStatus::MissingArtifactDigestManifest;
    }
    if !builder_vm_artifact_digest_manifest_matches(dir) {
        return BuilderVmSourceCacheStatus::ArtifactDigestMismatch;
    }

    let provenance_path = dir.join(BUILDER_VM_PROVENANCE_FILE);
    if !provenance_path.exists() {
        return BuilderVmSourceCacheStatus::MissingProvenance;
    }
    if !builder_vm_source_cache_provenance_matches(dir, expected_fingerprint) {
        return BuilderVmSourceCacheStatus::ProvenanceMismatch;
    }

    BuilderVmSourceCacheStatus::Hit
}

#[cfg(any(feature = "builder-vm", test))]
fn builder_vm_source_cache_ready(dir: &std::path::Path, expected_fingerprint: &str) -> bool {
    builder_vm_source_cache_status(dir, expected_fingerprint).is_ready()
}

#[cfg(any(feature = "builder-vm", test))]
fn builder_vm_source_fingerprint_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    std::fs::read_to_string(dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE))
        .map(|actual| actual.trim() == expected_fingerprint)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_source_fingerprint(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    std::fs::write(
        dir.join(BUILDER_VM_SOURCE_FINGERPRINT_FILE),
        format!("{source_fingerprint}\n"),
    )
    .with_context(|| format!("writing builder VM source fingerprint in {}", dir.display()))
}

fn builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<String> {
    let mut lines = Vec::new();
    for name in ["vmlinux", "rootfs.ext4", "cmdline.txt"] {
        let path = dir.join(name);
        if !path.exists() {
            if name == "cmdline.txt" {
                continue;
            }
            anyhow::bail!("builder VM artifact digest missing {}", path.display());
        }
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading builder VM artifact {}", path.display()))?;
        lines.push(format!("{:x}  {name}", Sha256::digest(&bytes)));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn builder_vm_artifact_digest_manifest_matches(dir: &std::path::Path) -> bool {
    let expected = match builder_vm_artifact_digest_manifest(dir) {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    std::fs::read_to_string(dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE))
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_artifact_digest_manifest(dir: &std::path::Path) -> Result<()> {
    let manifest = builder_vm_artifact_digest_manifest(dir)?;
    std::fs::write(dir.join(BUILDER_VM_ARTIFACT_DIGEST_FILE), manifest)
        .with_context(|| format!("writing builder VM artifact digests in {}", dir.display()))
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct BuilderVmSourceCacheProvenance {
    schema_version: u32,
    source_kind: String,
    source_fingerprint: String,
    artifacts: Vec<String>,
}

fn builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<BuilderVmSourceCacheProvenance> {
    Ok(BuilderVmSourceCacheProvenance {
        schema_version: 1,
        source_kind: "source_checkout_stage0".to_string(),
        source_fingerprint: source_fingerprint.to_string(),
        artifacts: builder_vm_artifact_names_present(dir)?,
    })
}

fn builder_vm_artifact_names_present(dir: &std::path::Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in ["vmlinux", "rootfs.ext4", "cmdline.txt"] {
        let path = dir.join(name);
        if !path.exists() {
            if name == "cmdline.txt" {
                continue;
            }
            anyhow::bail!("builder VM provenance missing artifact {}", path.display());
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn builder_vm_source_cache_provenance_matches(
    dir: &std::path::Path,
    expected_fingerprint: &str,
) -> bool {
    let expected = match builder_vm_source_cache_provenance(dir, expected_fingerprint) {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    std::fs::read_to_string(dir.join(BUILDER_VM_PROVENANCE_FILE))
        .ok()
        .and_then(|actual| serde_json::from_str::<BuilderVmSourceCacheProvenance>(&actual).ok())
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

#[cfg(any(feature = "builder-vm", test))]
fn write_builder_vm_source_cache_provenance(
    dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    let provenance = builder_vm_source_cache_provenance(dir, source_fingerprint)?;
    let json = serde_json::to_string_pretty(&provenance)
        .context("serializing builder VM source cache provenance")?;
    std::fs::write(dir.join(BUILDER_VM_PROVENANCE_FILE), format!("{json}\n"))
        .with_context(|| format!("writing builder VM provenance in {}", dir.display()))
}

#[cfg(any(feature = "builder-vm", test))]
fn promote_builder_vm_stage0_cache(
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    source_fingerprint: &str,
) -> Result<()> {
    validate_builder_vm_stage0_artifacts(staging_dir)?;
    if !builder_vm_source_fingerprint_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing the expected source fingerprint",
            staging_dir.display()
        );
    }
    if !builder_vm_artifact_digest_manifest_matches(staging_dir) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing matching artifact digests",
            staging_dir.display()
        );
    }
    if !builder_vm_source_cache_provenance_matches(staging_dir, source_fingerprint) {
        anyhow::bail!(
            "Stage 0 builder VM staging dir {} is missing matching provenance metadata",
            staging_dir.display()
        );
    }

    if final_dir.exists() {
        if builder_vm_source_cache_ready(final_dir, source_fingerprint) {
            std::fs::remove_dir_all(staging_dir).with_context(|| {
                format!(
                    "removing redundant Stage 0 staging dir {}",
                    staging_dir.display()
                )
            })?;
            return Ok(());
        }
        std::fs::remove_dir_all(final_dir).with_context(|| {
            format!("removing partial builder VM cache {}", final_dir.display())
        })?;
    }

    std::fs::rename(staging_dir, final_dir).with_context(|| {
        format!(
            "promoting Stage 0 builder VM cache {} to {}",
            staging_dir.display(),
            final_dir.display()
        )
    })?;
    if !builder_vm_source_cache_ready(final_dir, source_fingerprint) {
        anyhow::bail!(
            "promoted Stage 0 builder VM cache {} failed source-cache validation",
            final_dir.display()
        );
    }
    Ok(())
}

/// Download the per-arch Layer 1 builder VM artifacts published by the
/// `builder-vm-image` release-workflow job into the local cache dir,
/// SHA-256-verified per ADR-002 §W5.1.
///
/// Mirrors `download_dev_image_inner` for the dev-shell image, minus
/// cosign signing (Plan 36 ADR-005 extends to builder-vm artifacts as
/// a follow-up). The required artifacts are `vmlinux` + `rootfs.ext4`;
/// `cmdline.txt` and `manifest.json` sidecars are best-effort
/// downloads with a fallback at the `mvm-build` consumer
/// (`ensure_builder_vm_image` uses the canonical Plan 72 §W2 cmdline
/// when `cmdline.txt` is missing).
///
/// Plan 77 W4: gated behind `release-artifact-bootstrap`. Contributor
/// builds (default) never compile this in, so the "no flake + cache
/// miss" branch in [`bootstrap_builder_vm_image`] has no escape hatch
/// and surfaces a hard error. End-user-binary release builds opt in
/// at compile time via `--features release-artifact-bootstrap`.
#[cfg(feature = "release-artifact-bootstrap")]
fn download_builder_vm_image(arch: &str, cache_dir: &str) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let names = builder_vm_artifact_names(arch);
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let kernel_url = format!("{base_url}/{}", names.kernel);
    let rootfs_url = format!("{base_url}/{}", names.rootfs);
    let cmdline_url = format!("{base_url}/{}", names.cmdline);
    let manifest_url = format!("{base_url}/{}", names.manifest);
    let checksums_url = format!("{base_url}/{}", names.checksums);

    // Required artifacts only; sidecars get best-effort treatment
    // below. `fetch_expected_hashes` enforces that the checksum file
    // contains entries for everything in `wanted` before any download
    // starts.
    let expected = fetch_expected_hashes(&checksums_url, &[&names.kernel, &names.rootfs])?;

    ui::info("  Fetching kernel...");
    let kernel_path = format!("{cache_dir}/vmlinux");
    download_file(&kernel_url, &kernel_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM kernel from {kernel_url}"
        ))
    })?;
    verify_artifact_hash(&kernel_path, &names.kernel, expected.get(&names.kernel))?;

    ui::info("  Fetching rootfs...");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    download_file(&rootfs_url, &rootfs_path).map_err(|e| {
        bump_verify_outcome("network");
        e.context(format!(
            "Failed to download builder VM rootfs from {rootfs_url}"
        ))
    })?;
    verify_artifact_hash(&rootfs_path, &names.rootfs, expected.get(&names.rootfs))?;

    // Sidecars — best-effort. `cmdline.txt` has a documented fallback
    // in `mvm-build::libkrun_builder::ensure_builder_vm_image`;
    // `manifest.json` is informational. A 404 on either is fine; a
    // hash mismatch when the file IS present is still a hard fail.
    if let Some(expected_cmdline) = expected.get(&names.cmdline) {
        let cmdline_path = format!("{cache_dir}/cmdline.txt");
        if download_file(&cmdline_url, &cmdline_path).is_ok() {
            verify_artifact_hash(&cmdline_path, &names.cmdline, Some(expected_cmdline))?;
        }
    }
    if let Some(expected_manifest) = expected.get(&names.manifest) {
        let manifest_path = format!("{cache_dir}/manifest.json");
        if download_file(&manifest_url, &manifest_path).is_ok() {
            verify_artifact_hash(&manifest_path, &names.manifest, Some(expected_manifest))?;
        }
    }

    ui::success(&format!(
        "Builder VM image downloaded, hash-verified, and cached at {cache_dir}."
    ));
    Ok(())
}

/// Per-arch artifact filenames the release workflow's
/// `builder-vm-image` job uploads. Pure function — no I/O, no
/// network — so the unit test can verify naming matches the
/// release.yml side without touching the network. Gated together
/// with [`download_builder_vm_image`] (Plan 77 W4).
#[cfg(any(feature = "release-artifact-bootstrap", test))]
struct BuilderVmArtifactNames {
    kernel: String,
    rootfs: String,
    cmdline: String,
    manifest: String,
    checksums: String,
}

#[cfg(any(feature = "release-artifact-bootstrap", test))]
fn builder_vm_artifact_names(arch: &str) -> BuilderVmArtifactNames {
    BuilderVmArtifactNames {
        kernel: format!("builder-vm-vmlinux-{arch}"),
        rootfs: format!("builder-vm-rootfs-{arch}.ext4"),
        cmdline: format!("builder-vm-{arch}.cmdline.txt"),
        manifest: format!("builder-vm-{arch}.manifest.json"),
        checksums: format!("builder-vm-{arch}-checksums-sha256.txt"),
    }
}

/// Plan 72 W5.B — build the dev-shell image via the libkrun-backed
/// builder VM.
///
/// Layer 1 (the builder VM image at `~/.cache/mvm/builder-vm/<arch>/`)
/// is fetched via [`bootstrap_builder_vm_image`] on cache miss. The
/// dev-shell image the user boots into via `mvmctl dev up` is built by
/// `LibkrunBuilderVm::run_build` against the in-repo
/// `nix/images/builder/` flake, inside a libkrun guest that mounts the
/// workspace at `/work` and writes its artifacts back through a
/// virtio-fs `/out` share.
///
/// On success returns the host-side paths to the produced `vmlinux`
/// and `rootfs.ext4` in `out_dir`.
///
/// Caller is expected to have:
///   - confirmed `mvm_libkrun::is_available()` true,
///   - confirmed `find_builder_vm_flake().is_ok()` (Layer 1 source is
///     present in the workspace),
///   - run [`prepare_dev_image_out_dir`] on `out_dir`.
// Gated only on `builder-vm`.
#[cfg(feature = "builder-vm")]
fn build_image_via_libkrun(out_dir: &str) -> Result<(String, String)> {
    use mvm_build::builder_backend_select::{resolve_builder_backend, resolve_choice};
    use mvm_build::builder_vm::{BuilderJob, BuilderMounts, host_system_linux};

    // Ensure Layer 1 (the builder VM image) is in
    // `~/.cache/mvm/builder-vm/<arch>/`.
    bootstrap_builder_vm_image()
        .context("Stage 0 builder-VM image bootstrap (precondition for libkrun dispatch)")?;

    // Workspace root for the `/work` virtio-fs share. `find_builder_vm_flake()`
    // returns `<workspace>/nix/images/builder-vm`; the workspace itself is
    // three levels up. The consolidated flake reads `MVM_WORKSPACE_PATH=/work`
    // (set in the guest's `cmd.sh` by `LibkrunBuilderVm`) under
    // `--impure`, so the flake's `builtins.path` import lands on the
    // mount rather than the store-copied flake dir. Plan 115 / ADR-065
    // collapsed `nix/images/builder/` into `nix/images/builder-vm/`;
    // the interactive dev-shell image is now `packages.<sys>.dev`.
    let builder_flake = find_builder_vm_flake().context(
        "builder-vm flake missing at nix/images/builder-vm/flake.nix; libkrun dispatch needs it as Layer 2 source",
    )?;
    let workspace_root = std::path::Path::new(&builder_flake)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake}"))?
        .to_path_buf();

    // Inside the guest, `/work` is the workspace mount. The builder-vm
    // flake lives at `/work/nix/images/builder-vm` from the cmd.sh's
    // perspective. `path:` forces Nix's filesystem flake fetcher (not
    // the git fetcher, which would discover `/work/.git` and trip on
    // worktree files whose `gitdir:` redirects point outside the
    // mount). `packages.<sys>.dev` is the interactive (dev-shell) attr
    // added by Plan 115 / ADR-065.
    // Plan 115 / ADR-065: extract the embedded host-vm binaries to the
    // host-bins cache dir and mount them at /mvm-bins inside the builder VM.
    // The builder-vm flake's cmd.sh reads MVM_HOST_BIN_DIR=/mvm-bins to
    // install the correct cross-compiled binaries into the rootfs.
    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let host_bin_dir =
        crate::host_binaries::extract::ensure_extracted(std::path::Path::new(&host_bins_cache))
            .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;

    let job = BuilderJob::Flake {
        flake_ref: "path:/work/nix/images/builder-vm".to_string(),
        attr_path: format!("packages.{}.dev", host_system_linux()),
    };
    let mounts = BuilderMounts {
        flake_src: workspace_root,
        // libkrun keeps `/nix` on a persistent virtio-blk; no host
        // bind-mount of `/nix/store` is used or wanted (would be a
        // Darwin-x-Linux closure mismatch on macOS anyway).
        host_nix_store: None,
        artifact_out: std::path::PathBuf::from(out_dir),
        host_bin_dir,
    };

    // Plan 97 Phase C: `MVM_BUILDER_BACKEND=vz` flips the dispatch
    // to `VzBuilderVm` without touching the rest of the pipeline.
    // The resolver defaults to libkrun when the env var is unset,
    // preserving the historical behaviour for every existing caller.
    let backend_name = resolve_choice().name();
    let backend = resolve_builder_backend();
    backend
        .run_build(&job, &mounts)
        .map_err(|e| anyhow::anyhow!("{backend_name} builder VM: {e}"))?;

    // run_build wrote vmlinux + rootfs.ext4 into out_dir via the
    // virtio-fs `/out` mount; the same files mvm-cli is about to
    // hand back to the dev-up path.
    let kernel = format!("{out_dir}/vmlinux");
    let rootfs = format!("{out_dir}/rootfs.ext4");
    if !std::path::Path::new(&kernel).exists() {
        anyhow::bail!("{backend_name} builder VM exited cleanly but did not produce {kernel}");
    }
    if !std::path::Path::new(&rootfs).exists() {
        anyhow::bail!("{backend_name} builder VM exited cleanly but did not produce {rootfs}");
    }
    Ok((kernel, rootfs))
}

/// Ensure the bundled default microVM image (kernel + rootfs) is in the cache.
///
/// Used by any image-taking command when no `--flake` or `--manifest` was
/// supplied. Returns `(kernel_path, rootfs_path)`.
///
/// Downloads a pre-built image from the matching GitHub release when
/// the local cache is empty.
pub(crate) fn ensure_default_microvm_image() -> Result<(String, String)> {
    let cache_dir = format!("{}/default-microvm", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)?;

    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");

    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        return Ok((kernel_path, rootfs_path));
    }

    download_default_microvm_image(&kernel_path, &rootfs_path)
}

/// Download a pre-built default microVM image (kernel + rootfs) from the
/// matching GitHub release. Mirrors `download_dev_image`, including the
/// ADR-002 §W5.1 hash-verify path.
fn download_default_microvm_image(
    kernel_path: &str,
    rootfs_path: &str,
) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let kernel_name = format!("default-microvm-vmlinux-{arch}");
    let rootfs_name = format!("default-microvm-rootfs-{arch}.ext4");
    let checksums_name = format!("default-microvm-{arch}-checksums-sha256.txt");
    let kernel_url = format!("{base_url}/{kernel_name}");
    let rootfs_url = format!("{base_url}/{rootfs_name}");
    let checksums_url = format!("{base_url}/{checksums_name}");

    ui::info(&format!(
        "Downloading default microVM image (v{version})..."
    ));

    let expected = fetch_expected_hashes(&checksums_url, &[&kernel_name, &rootfs_name])?;

    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path)
        .with_context(|| format!("Failed to download kernel from {kernel_url}"))?;
    verify_artifact_hash(
        kernel_path,
        &kernel_name,
        expected.get(kernel_name.as_str()),
    )?;

    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path)
        .with_context(|| format!("Failed to download rootfs from {rootfs_url}"))?;
    verify_artifact_hash(
        rootfs_path,
        &rootfs_name,
        expected.get(rootfs_name.as_str()),
    )?;

    ui::success("Default microVM image downloaded, hash-verified, and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

#[cfg(test)]
mod dev_status_image_tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        home: Option<String>,
        data_dir: Option<String>,
        cache_dir: Option<String>,
    }

    impl EnvGuard {
        fn set(
            home: &std::path::Path,
            data_dir: &std::path::Path,
            cache_dir: &std::path::Path,
        ) -> Self {
            let guard = Self {
                home: std::env::var("HOME").ok(),
                data_dir: std::env::var("MVM_DATA_DIR").ok(),
                cache_dir: std::env::var("MVM_CACHE_DIR").ok(),
            };
            unsafe {
                std::env::set_var("HOME", home);
                std::env::set_var("MVM_DATA_DIR", data_dir);
                std::env::set_var("MVM_CACHE_DIR", cache_dir);
            }
            guard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.home {
                    Some(value) => std::env::set_var("HOME", value),
                    None => std::env::remove_var("HOME"),
                }
                match &self.data_dir {
                    Some(value) => std::env::set_var("MVM_DATA_DIR", value),
                    None => std::env::remove_var("MVM_DATA_DIR"),
                }
                match &self.cache_dir {
                    Some(value) => std::env::set_var("MVM_CACHE_DIR", value),
                    None => std::env::remove_var("MVM_CACHE_DIR"),
                }
            }
        }
    }

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().expect("test path must have parent")).unwrap();
        std::fs::write(path, b"test").unwrap();
    }

    fn write_valid_builder_cache_artifacts(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).expect("mkdir artifact dir");
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        let init_offset = rootfs.len() - HOST_VM_INIT_PATH.len() - 1;
        rootfs[init_offset..init_offset + HOST_VM_INIT_PATH.len()]
            .copy_from_slice(HOST_VM_INIT_PATH);
        std::fs::write(dir.join("rootfs.ext4"), rootfs).expect("write rootfs");
    }

    fn write_builder_vm_flake(dir: &std::path::Path) {
        std::fs::create_dir_all(dir).expect("mkdir flake dir");
        std::fs::write(dir.join("flake.nix"), "{ outputs = _: {}; }").expect("write flake");
        std::fs::write(dir.join("flake.lock"), "{\"nodes\":{}}").expect("write lock");
    }

    /// Stage the workspace prerequisites that `builder_vm_source_fingerprint`
    /// (post-PR #422) reads in addition to the flake dir itself:
    /// `Cargo.lock` at the workspace root + stub `mvm-host-vm-init` and
    /// `mvm-egress-proxy` crate dirs. Without this, any test that calls
    /// the fingerprint helper against a fresh tempdir-rooted flake at
    /// `<tmp>/nix/images/builder-vm` blows up with
    /// `builder VM source fingerprint missing <tmp>/Cargo.lock`.
    ///
    /// Matches `builder_vm_bootstrap_tests::write_builder_vm_workspace`
    /// in shape; lives here as well because the two test mods are
    /// independent and we don't want to plumb a cross-mod helper just
    /// for two callers.
    fn write_builder_vm_workspace_prereqs(workspace_root: &std::path::Path) {
        std::fs::write(workspace_root.join("Cargo.lock"), "# stub Cargo.lock\n")
            .expect("write Cargo.lock");
        for crate_name in ["mvm-host-vm-init", "mvm-egress-proxy"] {
            let src = workspace_root.join("crates").join(crate_name).join("src");
            std::fs::create_dir_all(&src).expect("mkdir crate src");
            std::fs::write(
                src.parent().unwrap().join("Cargo.toml"),
                format!("[package]\nname = \"{crate_name}\"\nversion = \"0.0.0\"\n"),
            )
            .expect("write Cargo.toml");
            std::fs::write(src.join("main.rs"), "fn main() {}\n").expect("write main.rs");
        }
    }

    #[test]
    fn status_image_prefers_launchd_image_paths() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let data_dir = tmp.path().join("data");
        let cache_dir = tmp.path().join("cache");
        let _env = EnvGuard::set(&home, &data_dir, &cache_dir);

        let launchd_kernel = tmp.path().join("daemon/vmlinux");
        let launchd_rootfs = tmp.path().join("daemon/rootfs.ext4");
        touch(&launchd_kernel);
        touch(&launchd_rootfs);
        touch(&data_dir.join("dev/current/vmlinux"));
        touch(&data_dir.join("dev/current/rootfs.ext4"));

        let plist_path = dev_launchd_plist_path();
        std::fs::create_dir_all(plist_path.parent().unwrap()).unwrap();
        std::fs::write(
            plist_path,
            format!(
                r#"<plist version="1.0">
<dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MVM_DEV_KERNEL</key>
        <string>{}</string>
        <key>MVM_DEV_ROOTFS</key>
        <string>{}</string>
    </dict>
</dict>
</plist>"#,
                launchd_kernel.display(),
                launchd_rootfs.display()
            ),
        )
        .unwrap();

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: Some(launchd_kernel.to_string_lossy().into_owned()),
                rootfs_path: launchd_rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_reports_current_data_dir_image() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );
        let kernel = tmp.path().join("data/dev/current/vmlinux");
        let rootfs = tmp.path().join("data/dev/current/rootfs.ext4");
        touch(&kernel);
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: Some(kernel.to_string_lossy().into_owned()),
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_reports_versioned_prebuilt_when_current_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );
        let dir = data_dir
            .join("dev/prebuilt")
            .join(format!("v{}", env!("CARGO_PKG_VERSION")));
        let rootfs = dir.join("rootfs.ext4");
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: None,
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_falls_back_to_legacy_cache_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path().join("cache");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &cache_dir,
        );
        let rootfs = cache_dir.join("dev/rootfs.ext4");
        touch(&rootfs);

        assert_eq!(
            resolve_dev_status_image(),
            Some(DevStatusImage {
                kernel_path: None,
                rootfs_path: rootfs.to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn status_image_is_none_when_no_rootfs_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        assert_eq!(resolve_dev_status_image(), None);
    }

    /// Write a `(vmlinux, rootfs.ext4)` pair that satisfies
    /// `validate_dev_image_artifacts` (size floor + ext4 magic).
    fn write_valid_dev_image(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).unwrap();
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        let init_offset = rootfs.len() - HOST_VM_INIT_PATH.len() - 1;
        rootfs[init_offset..init_offset + HOST_VM_INIT_PATH.len()]
            .copy_from_slice(HOST_VM_INIT_PATH);
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
    }

    /// Plan 77 W1 — `~/.mvm/dev/current/` is the load-bearing seed for
    /// Stage 0 when the builder VM cache is empty but a dev image was
    /// previously built on this host. Closes the gap where a contributor
    /// who deleted `~/.cache/mvm/builder-vm/<arch>/` got a hard error
    /// even though a valid seed was sitting at `dev/current/`.
    #[test]
    fn fallback_image_finds_dev_current() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );

        let current = data_dir.join("dev/current");
        write_valid_dev_image(&current);

        let (kernel, rootfs, label) =
            find_local_fallback_image().expect("dev/current/ pair must be discovered");
        assert_eq!(kernel, current.join("vmlinux"));
        assert_eq!(rootfs, current.join("rootfs.ext4"));
        assert_eq!(label, "current");
    }

    /// When multiple candidates exist, the most-recently-modified one
    /// wins. Guards against a stale `prebuilt/` entry hiding a fresh
    /// `current/` image (or vice versa).
    #[test]
    fn fallback_image_prefers_most_recent_candidate() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &data_dir,
            &tmp.path().join("cache"),
        );

        let prebuilt = data_dir.join("dev/prebuilt/v0.0.1");
        let current = data_dir.join("dev/current");
        write_valid_dev_image(&prebuilt);
        write_valid_dev_image(&current);
        // Force `current/` to be strictly newer than `prebuilt/` —
        // coarse-mtime filesystems (HFS+, some tmpfs) can otherwise
        // collide two writes into the same second.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::OpenOptions::new()
            .write(true)
            .open(current.join("rootfs.ext4"))
            .unwrap()
            .set_modified(later)
            .unwrap();

        let (_, _, label) = find_local_fallback_image().expect("a candidate must be discovered");
        assert_eq!(label, "current");
    }

    /// No candidates anywhere → `None`. Smoke-test for the empty case.
    #[test]
    fn fallback_image_is_none_when_no_pair_exists() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _env = EnvGuard::set(
            &tmp.path().join("home"),
            &tmp.path().join("data"),
            &tmp.path().join("cache"),
        );

        assert!(find_local_fallback_image().is_none());
    }

    #[test]
    fn builder_cache_status_reports_source_cache_hit_without_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("nix/images/builder-vm");
        let cache_root = tmp.path().join("cache");
        let cache = cache_root.join("builder-vm/testarch");
        write_builder_vm_flake(&flake);
        write_builder_vm_workspace_prereqs(tmp.path());
        write_valid_builder_cache_artifacts(&cache);
        let fingerprint = builder_vm_source_fingerprint(flake.to_str().unwrap()).unwrap();
        write_builder_vm_source_fingerprint(&cache, &fingerprint).unwrap();
        write_builder_vm_artifact_digest_manifest(&cache).unwrap();
        write_builder_vm_source_cache_provenance(&cache, &fingerprint).unwrap();

        assert_eq!(
            builder_vm_cache_status_summary(
                Ok(flake.to_string_lossy().into_owned()),
                &cache_root,
                "testarch"
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            }
        );
    }

    #[test]
    fn builder_cache_status_reports_source_provenance_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("nix/images/builder-vm");
        let cache_root = tmp.path().join("cache");
        let cache = cache_root.join("builder-vm/testarch");
        write_builder_vm_flake(&flake);
        write_builder_vm_workspace_prereqs(tmp.path());
        write_valid_builder_cache_artifacts(&cache);
        let fingerprint = builder_vm_source_fingerprint(flake.to_str().unwrap()).unwrap();
        write_builder_vm_source_fingerprint(&cache, &fingerprint).unwrap();
        write_builder_vm_artifact_digest_manifest(&cache).unwrap();

        assert_eq!(
            builder_vm_cache_status_summary(
                Ok(flake.to_string_lossy().into_owned()),
                &cache_root,
                "testarch"
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Stale,
                reason_code: "missing_provenance",
            }
        );
    }

    #[test]
    fn builder_cache_status_reports_release_cache_without_source_flake() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");

        assert_eq!(
            builder_vm_cache_status_summary(
                Err(anyhow::anyhow!("missing source flake")),
                &cache_root,
                "testarch",
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "release",
                state: BuilderVmCacheState::Stale,
                reason_code: "missing_or_invalid_artifacts",
            }
        );

        write_valid_builder_cache_artifacts(&cache_root.join("builder-vm/testarch"));
        assert_eq!(
            builder_vm_cache_status_summary(
                Err(anyhow::anyhow!("missing source flake")),
                &cache_root,
                "testarch",
            ),
            BuilderVmCacheStatusSummary {
                cache_kind: "release",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            }
        );
    }

    #[test]
    fn dev_image_cache_summary_never_includes_paths() {
        let image = DevStatusImage {
            kernel_path: Some("/private/tmp/mvm/vmlinux".to_string()),
            rootfs_path: "/private/tmp/mvm/rootfs.ext4".to_string(),
        };

        assert_eq!(
            dev_image_cache_summary(Some(&image)),
            DevImageCacheSummary {
                state: "cached",
                kernel: "present",
                rootfs: "present",
            }
        );
        assert_eq!(
            dev_image_cache_summary(None),
            DevImageCacheSummary {
                state: "missing",
                kernel: "missing",
                rootfs: "missing",
            }
        );
    }

    #[test]
    fn dev_cache_inspect_json_omits_paths_and_digests() {
        let summary = DevCacheInspectSummary {
            dev_image: DevImageCacheSummary {
                state: "cached",
                kernel: "present",
                rootfs: "present",
            },
            builder_cache: BuilderVmCacheStatusSummary {
                cache_kind: "source",
                state: BuilderVmCacheState::Ready,
                reason_code: "hit",
            },
        };

        let json = dev_cache_inspect_json(&summary).expect("serialize JSON");
        assert!(json.contains("\"schema_version\": 1"));
        assert!(json.contains("\"builder_cache\""));
        assert!(json.contains("\"reason_code\": \"hit\""));
        assert!(!json.contains("/private/tmp"));
        assert!(!json.contains("sha256"));
        assert!(!json.contains("rootfs.ext4"));
        assert!(!json.contains("vmlinux"));
    }
}

#[cfg(test)]
mod reap_orphans_tests {
    use super::*;

    #[test]
    fn missing_vms_root_is_empty_outcome() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("does-not-exist");
        let out = reap_orphaned_vm_helpers_at(&vms_root, false).expect("reap");
        assert_eq!(out.killed, 0);
        assert_eq!(out.removed_dirs, 0);
        assert_eq!(out.freed_bytes, 0);
    }

    #[test]
    fn dead_pids_get_their_dirs_swept() {
        // A VM dir whose `builder.pid` references a long-dead PID
        // (we use `1` and skip it via read_pid_file's `> 1` guard, so
        // instead use a PID that's very unlikely to be alive). The
        // reaper should remove the dir and count `removed_dirs += 1`
        // without trying to kill anyone.
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-99999-1234567890");
        std::fs::create_dir_all(&vm).expect("mkdir");
        // pick a PID guaranteed not to exist: 2^31-2 (one less than i32::MAX,
        // outside normal kernel allocation range on macOS/Linux)
        std::fs::write(vm.join("builder.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 1024]).expect("write payload");

        let out = reap_orphaned_vm_helpers_at(&vms_root, false).expect("reap");
        assert_eq!(out.killed, 0, "no live PID, so nothing to kill");
        assert_eq!(out.removed_dirs, 1, "dir should be removed");
        assert!(out.freed_bytes >= 1024, "payload size counted");
        assert!(!vm.exists(), "dir should be gone");
    }

    #[test]
    fn live_owner_preserves_dir_in_dry_run_and_real() {
        // A VM dir whose `builder.pid` references THIS test's PID.
        // The test process's parent is cargo/test runner, not launchd
        // PID 1, so `pid_parent != Some(1)` → reaper marks the dir as
        // "has a live owner" and leaves it alone.
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-pid-of-self");
        std::fs::create_dir_all(&vm).expect("mkdir");
        let my_pid = std::process::id() as i32;
        std::fs::write(vm.join("builder.pid"), format!("{my_pid}\n")).expect("write pid");

        let out = reap_orphaned_vm_helpers_at(&vms_root, false).expect("reap");
        assert_eq!(out.killed, 0, "live owner should not be killed");
        assert_eq!(out.removed_dirs, 0, "dir preserved while owner alive");
        assert!(vm.exists(), "dir should still be on disk");
    }

    #[test]
    fn dry_run_does_not_mutate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vms_root = dir.path().join("vms");
        let vm = vms_root.join("mvm-stage0-dryrun-test");
        std::fs::create_dir_all(&vm).expect("mkdir");
        std::fs::write(vm.join("builder.pid"), "2147483646\n").expect("write pid");
        std::fs::write(vm.join("payload"), vec![0u8; 256]).expect("write payload");

        let out = reap_orphaned_vm_helpers_at(&vms_root, true).expect("dry-run reap");
        // Dry-run still *counts* what it would do, but doesn't mutate.
        assert_eq!(out.removed_dirs, 1);
        assert!(vm.exists(), "dry-run must not remove the dir");
        assert!(vm.join("builder.pid").exists(), "pid file untouched");
    }
}

#[cfg(test)]
mod hash_verify_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::sync::Mutex;

    /// Cargo test runs tests in parallel within a single binary. Two
    /// of these tests touch `MVM_SKIP_HASH_VERIFY` (the global env-var
    /// escape hatch from ADR-002 §W5.1), so they have to be serialised
    /// against each other and against any other test that hashes a
    /// real artifact. Static mutex held for the test's lifetime.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Compute the canonical lowercase-hex SHA-256 of a byte slice. Tests
    /// use this to derive matching expected values without rebuilding
    /// the production hash path.
    fn hex_sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn verify_hash_accepts_matching_artifact() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        let bytes = b"hello world\n";
        std::fs::write(&path, bytes).unwrap();
        let expected = hex_sha256(bytes);
        let result = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&expected));
        assert!(
            result.is_ok(),
            "matching hash should be accepted: {result:?}"
        );
        // File must still exist on success.
        assert!(
            path.exists(),
            "verified file must not be deleted on success"
        );
    }

    #[test]
    fn verify_hash_rejects_mismatched_artifact_and_deletes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"actual contents").unwrap();
        let expected = hex_sha256(b"different contents");
        let err = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&expected))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Integrity check failed"),
            "expected integrity-check error, got: {err}"
        );
        assert!(
            !path.exists(),
            "tampered file must be deleted to prevent reuse"
        );
    }

    #[test]
    fn verify_hash_skip_env_var_bypasses_check() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Ensure the file exists even though we'll set a "wrong" hash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"contents").unwrap();
        let wrong = hex_sha256(b"definitely not the contents");

        // SAFETY: ENV_LOCK serialises every test that touches this env
        // var, so no concurrent reader observes a half-set value. The
        // unsafe block is only required by edition-2024's set_var /
        // remove_var signatures; behaviour is unchanged.
        unsafe {
            std::env::set_var("MVM_SKIP_HASH_VERIFY", "1");
        }
        let result = verify_artifact_hash(path.to_str().unwrap(), "artifact", Some(&wrong));
        unsafe {
            std::env::remove_var("MVM_SKIP_HASH_VERIFY");
        }
        assert!(result.is_ok(), "skip-env should bypass check: {result:?}");
    }

    #[test]
    fn fetch_expected_hashes_parses_sha256sum_format() {
        // Run a tiny in-process HTTP server? Overkill — the function
        // takes a URL and shells out to curl. Instead, we test the
        // parser by exercising it directly via a file:// URL: curl
        // accepts file:// and just copies the bytes.
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("checksums.txt");
        let mut f = std::fs::File::create(&manifest_path).unwrap();
        // Two-space gap is canonical sha256sum output. Mix in a leading
        // '*' on one line (binary mode) to confirm we strip it.
        writeln!(f, "{}  dev-vmlinux-x86_64", "a".repeat(64)).unwrap();
        writeln!(f, "{} *dev-rootfs-x86_64.ext4", "b".repeat(64)).unwrap();
        writeln!(f, "garbage line that is not a hash").unwrap();
        drop(f);

        let url = format!("file://{}", manifest_path.display());
        let map = fetch_expected_hashes(&url, &["dev-vmlinux-x86_64", "dev-rootfs-x86_64.ext4"])
            .expect("manifest should parse");
        assert_eq!(map.get("dev-vmlinux-x86_64").unwrap(), &"a".repeat(64));
        assert_eq!(map.get("dev-rootfs-x86_64.ext4").unwrap(), &"b".repeat(64));
    }

    #[test]
    fn fetch_expected_hashes_errors_when_artifact_missing_from_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("checksums.txt");
        std::fs::write(
            &manifest_path,
            format!("{}  some-other-file\n", "c".repeat(64)),
        )
        .unwrap();

        let url = format!("file://{}", manifest_path.display());
        let err = fetch_expected_hashes(&url, &["dev-vmlinux-x86_64"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("did not include") && err.contains("dev-vmlinux-x86_64"),
            "expected missing-entry error, got: {err}"
        );
    }
}

#[cfg(test)]
mod builder_vm_bootstrap_tests {
    //! Plan 72 W5 — `find_builder_vm_flake` + `bootstrap_builder_vm_image`.
    use super::*;
    use std::io::Write;

    #[test]
    fn find_builder_vm_flake_resolves_to_in_repo_path() {
        // From a source checkout, the helper must find the W2
        // flake at <workspace>/nix/images/builder-vm/flake.nix.
        // `env!("CARGO_MANIFEST_DIR")` is baked at compile time
        // and points at the workspace's mvm-cli crate dir, so
        // this assertion is robust across `cargo test` and
        // `cargo nextest`.
        let path = find_builder_vm_flake().expect("expected builder-vm flake present in repo");
        assert!(
            path.ends_with("nix/images/builder-vm"),
            "unexpected flake path: {path}"
        );
        // The flake file itself must be readable.
        assert!(
            std::path::Path::new(&path).join("flake.nix").is_file(),
            "flake.nix missing under {path}"
        );
    }

    /// Per-arch artifact filenames must match what the release
    /// workflow's `builder-vm-image` job uploads. Pure function —
    /// asserts the contract between `builder_vm_artifact_names()`
    /// (the consumer side that constructs download URLs) and the
    /// `cp "$STORE_PATH/..." "staging/builder-vm-..."` lines in
    /// `.github/workflows/release.yml` (the producer side).
    #[test]
    fn builder_vm_artifact_names_match_release_workflow() {
        let n = builder_vm_artifact_names("aarch64");
        assert_eq!(n.kernel, "builder-vm-vmlinux-aarch64");
        assert_eq!(n.rootfs, "builder-vm-rootfs-aarch64.ext4");
        assert_eq!(n.cmdline, "builder-vm-aarch64.cmdline.txt");
        assert_eq!(n.manifest, "builder-vm-aarch64.manifest.json");
        assert_eq!(n.checksums, "builder-vm-aarch64-checksums-sha256.txt");

        let n = builder_vm_artifact_names("x86_64");
        assert_eq!(n.kernel, "builder-vm-vmlinux-x86_64");
        assert_eq!(n.rootfs, "builder-vm-rootfs-x86_64.ext4");
        assert_eq!(n.cmdline, "builder-vm-x86_64.cmdline.txt");
        assert_eq!(n.manifest, "builder-vm-x86_64.manifest.json");
        assert_eq!(n.checksums, "builder-vm-x86_64-checksums-sha256.txt");
    }

    #[test]
    fn builder_vm_bootstrap_uses_cache_even_in_source_checkout() {
        let action = resolve_builder_vm_bootstrap_action(
            Ok("/repo/nix/images/builder-vm".to_string()),
            true,
        )
        .expect("cache hit should be usable in a source checkout");

        assert_eq!(action, BuilderVmBootstrapAction::UseCached);
    }

    #[test]
    fn builder_vm_bootstrap_source_checkout_builds_from_source_on_cache_miss() {
        let action = resolve_builder_vm_bootstrap_action(
            Ok("/repo/nix/images/builder-vm".to_string()),
            false,
        )
        .expect("source checkout cache miss should route to local source build");

        assert_eq!(
            action,
            BuilderVmBootstrapAction::BuildFromSource {
                flake_dir: "/repo/nix/images/builder-vm".to_string()
            }
        );
    }

    #[test]
    fn builder_vm_bootstrap_installed_binary_may_download_on_cache_miss() {
        let action =
            resolve_builder_vm_bootstrap_action(Err(anyhow::anyhow!("no source flake")), false)
                .expect("installed binaries may use published prebuilts");

        assert_eq!(action, BuilderVmBootstrapAction::DownloadPublished);
    }

    /// Plan 77 W4: even when the resolver routes to `DownloadPublished`,
    /// a contributor build (no `release-artifact-bootstrap` feature) must
    /// refuse to invoke the download path and surface a clear structural
    /// error. This locks the AGENTS.md / CLAUDE.md "no prebuilt builder
    /// VM artifact" invariant into the type system rather than runtime
    /// branch order. The companion sibling under
    /// `#[cfg(feature = "release-artifact-bootstrap")]` would need a
    /// network mock; we cover the structural-failure side here because
    /// it's the one contributors hit.
    #[cfg(not(feature = "release-artifact-bootstrap"))]
    #[test]
    fn perform_builder_vm_download_published_bails_without_feature() {
        let err = perform_builder_vm_download_published("aarch64", "/tmp/mvm-w4-test-out")
            .expect_err("download must refuse without release-artifact-bootstrap");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("release-artifact-bootstrap"),
            "error must name the feature flag: {msg}"
        );
        assert!(
            msg.contains("nix/images/builder-vm/flake.nix"),
            "error must point at the source-checkout remediation: {msg}"
        );
        // Critically: the bail must happen before any directory creation.
        // Otherwise a contributor running on a shared host could pollute
        // `/tmp/...` even when the gate is "closed".
        assert!(
            !std::path::Path::new("/tmp/mvm-w4-test-out").exists(),
            "structural failure must not touch the filesystem"
        );
    }

    fn write_valid_builder_vm_artifacts(dir: &std::path::Path) {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        std::fs::create_dir_all(dir).expect("mkdir artifact dir");
        std::fs::write(dir.join("vmlinux"), vec![0x7f; 1024 * 1024 + 1]).expect("write kernel");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        let init_offset = rootfs.len() - HOST_VM_INIT_PATH.len() - 1;
        rootfs[init_offset..init_offset + HOST_VM_INIT_PATH.len()]
            .copy_from_slice(HOST_VM_INIT_PATH);
        std::fs::write(dir.join("rootfs.ext4"), rootfs).expect("write rootfs");
    }

    fn write_builder_vm_flake(dir: &std::path::Path, flake: &str, lock: Option<&str>) {
        std::fs::create_dir_all(dir).expect("mkdir flake dir");
        std::fs::write(dir.join("flake.nix"), flake).expect("write flake");
        if let Some(lock) = lock {
            std::fs::write(dir.join("flake.lock"), lock).expect("write lock");
        }
    }

    fn write_builder_vm_source_cache_metadata(dir: &std::path::Path, fingerprint: &str) {
        write_builder_vm_source_fingerprint(dir, fingerprint).expect("write fingerprint");
        write_builder_vm_artifact_digest_manifest(dir).expect("write artifact digest manifest");
        write_builder_vm_source_cache_provenance(dir, fingerprint).expect("write provenance");
    }

    /// Plan 77 W2 — `acquire_stage0_lock` is an advisory `flock(2)`
    /// guard at `<cache_parent>/stage0.lock`. The first acquisition
    /// succeeds; a second concurrent attempt while the first guard is
    /// still in scope fails fast with a recognizable message; once the
    /// first guard drops, the lock becomes available again.
    #[test]
    fn stage0_lock_refuses_concurrent_acquisition() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out_dir = tmp.path().join("aarch64");
        let out_dir_str = out_dir.to_str().expect("utf-8 out_dir");

        let first = acquire_stage0_lock(out_dir_str).expect("first acquisition should succeed");
        // Lock file lives one directory above out_dir, named `stage0.lock`.
        assert!(
            tmp.path().join("stage0.lock").exists(),
            "stage0.lock should be created on first acquisition"
        );

        let err = match acquire_stage0_lock(out_dir_str) {
            Err(e) => e,
            Ok(_) => panic!("second acquisition must refuse while first is held"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already bootstrapping the builder VM image"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("stage0.lock"),
            "error should name the lock file path: {msg}"
        );

        drop(first);

        // Now reachable again — guards must not leak past their scope.
        let _second =
            acquire_stage0_lock(out_dir_str).expect("acquisition should succeed after drop");
    }

    /// Lock setup must not fail when the parent cache directory does
    /// not yet exist on disk (fresh contributor host). `acquire_stage0_lock`
    /// is responsible for creating it.
    #[test]
    fn stage0_lock_creates_missing_cache_parent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("nested/builder-vm/aarch64");
        let nested_str = nested.to_str().expect("utf-8 nested");

        let _guard =
            acquire_stage0_lock(nested_str).expect("acquisition should create missing parent dir");
        assert!(
            tmp.path().join("nested/builder-vm/stage0.lock").exists(),
            "lock file must be created at the constructed parent path"
        );
    }

    /// Plan 77 W2 — name predicate must match both the current hidden
    /// `.<arch>.stage0-<pid>-<nonce>` form and the legacy
    /// `<arch>-staging[-...]` form, and reject everything else that
    /// lives alongside under `~/.cache/mvm/builder-vm/` (live cache
    /// dirs `aarch64/` / `x86_64/`, the `nix-store-<arch>.img` blob,
    /// `jobs/`, `vms/`, `stage0.lock`, sundry dotfiles).
    #[test]
    fn is_orphan_stage0_staging_dir_name_matches_known_shapes() {
        // Current hidden form (matches `unique_builder_vm_stage0_staging_dir`).
        assert!(is_orphan_stage0_staging_dir_name(
            ".aarch64.stage0-12345-1700000000000000000"
        ));
        assert!(is_orphan_stage0_staging_dir_name(
            ".x86_64.stage0-99999-1700000000000000000"
        ));
        // Legacy plain form.
        assert!(is_orphan_stage0_staging_dir_name("aarch64-staging"));
        assert!(is_orphan_stage0_staging_dir_name("x86_64-staging-foo"));

        // Negatives: everything that legitimately lives next to
        // staging dirs must be left alone.
        assert!(!is_orphan_stage0_staging_dir_name("aarch64"));
        assert!(!is_orphan_stage0_staging_dir_name("x86_64"));
        assert!(!is_orphan_stage0_staging_dir_name("jobs"));
        assert!(!is_orphan_stage0_staging_dir_name("vms"));
        assert!(!is_orphan_stage0_staging_dir_name("stage0.lock"));
        assert!(!is_orphan_stage0_staging_dir_name("nix-store-aarch64.img"));
        assert!(!is_orphan_stage0_staging_dir_name("nix-store-x86_64.img"));
        // Dotfile that isn't a staging dir.
        assert!(!is_orphan_stage0_staging_dir_name(".DS_Store"));
        // Unknown arch suffixes are conservative-deny.
        assert!(!is_orphan_stage0_staging_dir_name(".riscv64.stage0-1-2"));
        assert!(!is_orphan_stage0_staging_dir_name("riscv64-staging"));
    }

    /// Plan 77 W2 — sweep removes a staging dir of the current form,
    /// reports the byte count, leaves the live cache and unrelated
    /// siblings intact, and the dry-run variant is purely observational
    /// (no fs mutation).
    #[test]
    fn sweep_removes_orphan_staging_dir_and_leaves_siblings() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();

        // Build a representative layout under <root>.
        let orphan = root.join(".aarch64.stage0-12345-1700000000000000000");
        std::fs::create_dir_all(orphan.join("nested")).unwrap();
        std::fs::write(orphan.join("a"), b"hello world").unwrap(); // 11 bytes
        std::fs::write(orphan.join("nested/b"), vec![0u8; 7]).unwrap();

        let live_cache = root.join("aarch64");
        std::fs::create_dir_all(&live_cache).unwrap();
        std::fs::write(live_cache.join("rootfs.ext4"), b"do-not-delete").unwrap();

        let nix_store = root.join("nix-store-aarch64.img");
        std::fs::write(&nix_store, b"sparse").unwrap();

        // Dry-run: nothing should move.
        match sweep_orphaned_stage0_staging_dirs_at(&root, true)
            .expect("dry-run sweep should succeed")
        {
            Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            } => {
                assert_eq!(removed, 1, "dry-run reports the orphan");
                assert_eq!(freed_bytes, 18, "dry-run reports the orphan's byte total");
            }
            Stage0SweepOutcome::SkippedLockHeld => panic!("dry-run must not skip"),
        }
        assert!(orphan.is_dir(), "dry-run must not remove the orphan");
        assert!(live_cache.is_dir(), "dry-run must not touch the live cache");

        // Real run: orphan goes, siblings stay.
        match sweep_orphaned_stage0_staging_dirs_at(&root, false).expect("sweep should succeed") {
            Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            } => {
                assert_eq!(removed, 1);
                assert_eq!(freed_bytes, 18);
            }
            Stage0SweepOutcome::SkippedLockHeld => panic!("must not skip on uncontended lock"),
        }
        assert!(!orphan.exists(), "orphan must be removed");
        assert!(
            live_cache.join("rootfs.ext4").is_file(),
            "live cache must be untouched"
        );
        assert!(nix_store.is_file(), "nix-store image must be untouched");
    }

    /// Plan 77 W2 — when a live Stage 0 is in progress and holds the
    /// advisory lock, the sweep must skip rather than race the
    /// staging dir the live run is about to promote.
    #[test]
    fn sweep_skips_when_stage0_lock_is_held() {
        use mvm_core::atomic_io::FileLock;

        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        std::fs::create_dir_all(&root).unwrap();

        // Hold the lock as a "live" Stage 0 would.
        let _live = FileLock::try_acquire(&root.join("stage0"))
            .expect("first acquisition should not fail")
            .expect("first acquisition should succeed");

        // Stage an orphan to confirm the sweep would have something to do.
        let orphan = root.join(".aarch64.stage0-12345-1700000000000000000");
        std::fs::create_dir_all(&orphan).unwrap();

        match sweep_orphaned_stage0_staging_dirs_at(&root, false)
            .expect("sweep should succeed even when skipping")
        {
            Stage0SweepOutcome::SkippedLockHeld => {}
            Stage0SweepOutcome::Swept { .. } => {
                panic!("sweep must skip while the Stage 0 lock is held")
            }
        }
        assert!(
            orphan.is_dir(),
            "skipped sweep must not touch the would-be orphan"
        );
    }

    /// Plan 77 W2 — sweep on a non-existent root is a no-op. Exercises
    /// the early-return for fresh hosts that have never run `dev up`.
    #[test]
    fn sweep_is_noop_when_root_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("never-existed");

        match sweep_orphaned_stage0_staging_dirs_at(&missing, false)
            .expect("sweep on missing root should succeed")
        {
            Stage0SweepOutcome::Swept {
                removed,
                freed_bytes,
            } => {
                assert_eq!(removed, 0);
                assert_eq!(freed_bytes, 0);
            }
            Stage0SweepOutcome::SkippedLockHeld => {
                panic!("missing root must not look like lock contention")
            }
        }
    }

    /// Plan 97 Phase C / Plan 99 PR-1 — pin that the orphan reaper
    /// covers `mvm-builder-vz-<job_id>` dirs the same way it covers
    /// `mvm-builder-vm-<job_id>`. The traversal in
    /// `reap_orphaned_vm_helpers_at` is prefix-agnostic and
    /// `VzBuilderVm` writes a `builder.pid` sidecar under the shared
    /// `~/.cache/mvm/builder-vm/vms/` tree; this test guards against
    /// a future refactor narrowing either invariant.
    #[test]
    fn reap_picks_up_orphaned_vz_builder_state_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vms = tmp.path();
        let vz_dir = vms.join("mvm-builder-vz-abc12345");
        std::fs::create_dir_all(&vz_dir).unwrap();
        // `i32::MAX` is guaranteed not to be a live process on any
        // supported host — classify_pid → Dead, so the dir has no
        // live owner and is eligible for removal.
        std::fs::write(vz_dir.join("builder.pid"), format!("{}\n", i32::MAX)).unwrap();

        let outcome =
            reap_orphaned_vm_helpers_at(vms, /* dry_run = */ false).expect("reap should succeed");

        assert_eq!(
            outcome.removed_dirs, 1,
            "vz builder state dir should be reaped"
        );
        assert!(
            !vz_dir.exists(),
            "vz builder state dir should be gone on disk"
        );
    }

    #[test]
    fn builder_vm_stage0_staging_dir_is_hidden_sibling() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let final_dir = tmp.path().join("builder-vm").join("aarch64");
        let staging = unique_builder_vm_stage0_staging_dir(&final_dir)
            .expect("valid final dir should produce staging dir");

        assert_eq!(staging.parent(), final_dir.parent());
        let name = staging
            .file_name()
            .and_then(|s| s.to_str())
            .expect("staging basename should be utf-8");
        assert!(
            name.starts_with(".aarch64.stage0-"),
            "unexpected staging dir name: {name}"
        );
    }

    #[test]
    fn builder_vm_stage0_promotion_rejects_invalid_artifacts_without_live_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        std::fs::create_dir_all(&staging).expect("mkdir staging");
        std::fs::write(staging.join("vmlinux"), b"stub").expect("write stub kernel");
        std::fs::write(staging.join("rootfs.ext4"), b"stub").expect("write stub rootfs");
        write_builder_vm_source_cache_metadata(&staging, "fingerprint");
        let final_dir = tmp.path().join("aarch64");

        let err = promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
            .expect_err("stub artifacts must not be promoted");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validating Stage 0 builder VM artifacts"),
            "{msg}"
        );
        assert!(!final_dir.exists(), "invalid cache must not go live");
    }

    #[test]
    fn builder_vm_stage0_promotion_validates_then_promotes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        let final_dir = tmp.path().join("aarch64");
        write_valid_builder_vm_artifacts(&staging);
        write_builder_vm_source_cache_metadata(&staging, "fingerprint");

        promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
            .expect("valid artifacts should promote");

        assert!(!staging.exists(), "staging dir should be moved away");
        validate_builder_vm_stage0_artifacts(&final_dir).expect("final cache should validate");
        assert!(builder_vm_source_cache_ready(&final_dir, "fingerprint"));
    }

    #[test]
    fn builder_vm_stage0_promotion_keeps_existing_valid_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        let final_dir = tmp.path().join("aarch64");
        write_valid_builder_vm_artifacts(&staging);
        write_builder_vm_source_cache_metadata(&staging, "fingerprint");
        write_valid_builder_vm_artifacts(&final_dir);
        write_builder_vm_source_cache_metadata(&final_dir, "fingerprint");

        promote_builder_vm_stage0_cache(&staging, &final_dir, "fingerprint")
            .expect("existing valid cache should win the race");

        assert!(!staging.exists(), "redundant staging dir should be removed");
        validate_builder_vm_stage0_artifacts(&final_dir)
            .expect("existing cache should remain valid");
    }

    /// Lay out a synthetic mvm workspace under `tmp` that the
    /// expanded `builder_vm_source_fingerprint` will accept:
    ///
    /// ```text
    /// tmp/
    ///   Cargo.lock
    ///   crates/
    ///     mvm-host-vm-init/{Cargo.toml,src/main.rs}
    ///     mvm-egress-proxy/{Cargo.toml,src/main.rs}
    ///   nix/images/builder-vm/{flake.nix,flake.lock}
    /// ```
    ///
    /// Returns the path of the `nix/images/builder-vm/` dir — the
    /// argument the fingerprint function expects.
    fn write_builder_vm_workspace(tmp: &std::path::Path) -> std::path::PathBuf {
        std::fs::write(tmp.join("Cargo.lock"), "# stub Cargo.lock\n").expect("write Cargo.lock");

        for crate_name in ["mvm-host-vm-init", "mvm-egress-proxy"] {
            let src = tmp.join("crates").join(crate_name).join("src");
            std::fs::create_dir_all(&src).expect("mkdir crate src");
            std::fs::write(
                src.parent().unwrap().join("Cargo.toml"),
                format!("[package]\nname = \"{crate_name}\"\nversion = \"0.0.0\"\n"),
            )
            .expect("write Cargo.toml");
            std::fs::write(src.join("main.rs"), "fn main() {}\n").expect("write main.rs");
        }

        let flake = tmp.join("nix/images/builder-vm");
        write_builder_vm_flake(&flake, "{ outputs = _: {}; }", Some("{\"nodes\":{}}"));
        flake
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_with_flake_inputs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        write_builder_vm_flake(
            &flake,
            "{ outputs = _: { changed = true; }; }",
            Some("{\"nodes\":{}}"),
        );
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(first, second);
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_with_cargo_lock() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        // Mutating Cargo.lock simulates a `cargo update` that bumps
        // a transitive crate version. The dep closure of every
        // rootfs Rust binary changes → rootfs must rebuild.
        std::fs::write(
            tmp.path().join("Cargo.lock"),
            "# stub Cargo.lock — updated\n",
        )
        .expect("rewrite Cargo.lock");
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(
            first, second,
            "Cargo.lock edit must invalidate the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_with_mvm_host_vm_init_source() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        // The bug this whole expansion fixes: a contributor edits
        // the PID-1 binary source and `mvmctl dev up` silently
        // serves the stale cached rootfs.
        std::fs::write(
            tmp.path().join("crates/mvm-host-vm-init/src/main.rs"),
            "fn main() { println!(\"hello from edited builder-init\"); }\n",
        )
        .expect("rewrite main.rs");
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(
            first, second,
            "edit to mvm-host-vm-init source must invalidate the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_with_mvm_egress_proxy_source() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        std::fs::write(
            tmp.path().join("crates/mvm-egress-proxy/src/main.rs"),
            "fn main() { println!(\"updated proxy\"); }\n",
        )
        .expect("rewrite main.rs");
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(
            first, second,
            "edit to mvm-egress-proxy source must invalidate the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_does_not_change_with_readme_edit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let baseline =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

        // Plan 93 Phase 0: only `Cargo.toml` + `src/**` enter the
        // closure rustc sees. README, CHANGELOG, LICENSE, and other
        // crate-root files don't influence the baked binary, so they
        // must NOT bust the Stage 0 cache — a contributor tweaking
        // docs shouldn't eat a 10-30 minute rebuild.
        std::fs::write(
            tmp.path().join("crates/mvm-host-vm-init/README.md"),
            "# mvm-host-vm-init\n\nAdded docs.\n",
        )
        .expect("write README");
        std::fs::write(
            tmp.path().join("crates/mvm-egress-proxy/CHANGELOG.md"),
            "# changelog\n",
        )
        .expect("write CHANGELOG");

        let after =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

        assert_eq!(
            baseline, after,
            "non-src crate-root files must not affect the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_with_cargo_toml_edit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        // A dep bump or a feature-flag change in Cargo.toml shifts
        // what rustPlatform.buildRustPackage produces, so the
        // fingerprint must pick it up.
        std::fs::write(
            tmp.path().join("crates/mvm-host-vm-init/Cargo.toml"),
            "[package]\nname = \"mvm-host-vm-init\"\nversion = \"0.0.1\"\n",
        )
        .expect("rewrite Cargo.toml");
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(
            first, second,
            "Cargo.toml edit must invalidate the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_errors_when_cargo_toml_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        std::fs::remove_file(tmp.path().join("crates/mvm-host-vm-init/Cargo.toml"))
            .expect("rm Cargo.toml");

        let err = builder_vm_source_fingerprint(flake.to_str().unwrap())
            .expect_err("missing Cargo.toml must be a hard error");
        assert!(
            err.to_string().contains("Cargo.toml"),
            "error must name the missing path: {err}"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_changes_when_new_file_added_to_crate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let first = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        // A `git add` of a new module file under the crate also
        // changes the closure rustc sees, so the fingerprint must
        // reflect new files, not just modifications of existing ones.
        std::fs::write(
            tmp.path().join("crates/mvm-host-vm-init/src/new_module.rs"),
            "pub fn whatever() {}\n",
        )
        .expect("write new_module.rs");
        let second = builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("fingerprint");

        assert_ne!(
            first, second,
            "new file in mvm-host-vm-init must invalidate the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_is_deterministic_for_identical_workspace() {
        let tmp1 = tempfile::tempdir().expect("tempdir 1");
        let tmp2 = tempfile::tempdir().expect("tempdir 2");
        let flake1 = write_builder_vm_workspace(tmp1.path());
        let flake2 = write_builder_vm_workspace(tmp2.path());

        let a = builder_vm_source_fingerprint(flake1.to_str().unwrap()).expect("fingerprint 1");
        let b = builder_vm_source_fingerprint(flake2.to_str().unwrap()).expect("fingerprint 2");

        // Same inputs → same fingerprint regardless of where they
        // live on disk. (The hash discipline keys off relative
        // paths, never absolute, so this must hold.)
        assert_eq!(
            a, b,
            "identical workspace layouts must produce identical fingerprints"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_ignores_target_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let baseline =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

        // cargo build artifacts under `target/` are not flake inputs.
        // Adding multi-MB junk there must not change the fingerprint
        // (otherwise every `cargo build` would invalidate the cache).
        // Place a `target/` both at the crate root (outside the
        // narrowed walk) and inside `src/` (inside the walk, exercising
        // the explicit skip).
        let crate_target = tmp.path().join("crates/mvm-host-vm-init/target/debug");
        std::fs::create_dir_all(&crate_target).expect("mkdir crate target");
        std::fs::write(crate_target.join("garbage.rlib"), vec![0u8; 4096])
            .expect("write crate target garbage");
        let src_target = tmp.path().join("crates/mvm-host-vm-init/src/target/debug");
        std::fs::create_dir_all(&src_target).expect("mkdir src/target");
        std::fs::write(src_target.join("junk.rlib"), vec![0u8; 4096])
            .expect("write src/target garbage");

        let after =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

        assert_eq!(
            baseline, after,
            "target/ contents must not affect the builder-vm cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_ignores_hidden_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        let baseline =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("baseline fingerprint");

        // `.git/HEAD`, editor swap files (`.swp`, `foo.rs.swp`),
        // `.DS_Store`, etc. — none are flake inputs and editing them
        // shouldn't bust the cache. Place each both at the crate root
        // (outside the narrowed walk) and inside `src/` (inside the
        // walk, exercising the explicit skip).
        for path in [
            "crates/mvm-host-vm-init/.swp",
            "crates/mvm-host-vm-init/.DS_Store",
            "crates/mvm-host-vm-init/src/.DS_Store",
            "crates/mvm-host-vm-init/src/main.rs.swp",
        ] {
            std::fs::write(tmp.path().join(path), b"junk").expect("write hidden");
        }

        let after =
            builder_vm_source_fingerprint(flake.to_str().unwrap()).expect("after fingerprint");

        assert_eq!(
            baseline, after,
            "hidden entries / swap files must not affect the cache key"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_errors_when_cargo_lock_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        std::fs::remove_file(tmp.path().join("Cargo.lock")).expect("rm Cargo.lock");

        let err = builder_vm_source_fingerprint(flake.to_str().unwrap())
            .expect_err("missing Cargo.lock must be a hard error");
        assert!(
            err.to_string().contains("Cargo.lock"),
            "error must name the missing path: {err}"
        );
    }

    #[test]
    fn builder_vm_source_fingerprint_errors_when_in_vm_crate_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let flake = write_builder_vm_workspace(tmp.path());
        std::fs::remove_dir_all(tmp.path().join("crates/mvm-host-vm-init")).expect("rm crate dir");

        let err = builder_vm_source_fingerprint(flake.to_str().unwrap())
            .expect_err("missing in-VM crate dir must be a hard error");
        assert!(
            err.to_string().contains("mvm-host-vm-init"),
            "error must name the missing crate: {err}"
        );
    }

    #[test]
    fn builder_vm_source_cache_requires_matching_fingerprint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);

        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "valid artifacts without a source marker must not satisfy source checkout cache"
        );
        write_builder_vm_source_cache_metadata(&cache, "other");
        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "stale source marker must not satisfy source checkout cache"
        );
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");
        assert!(builder_vm_source_cache_ready(&cache, "fingerprint"));
    }

    #[test]
    fn builder_vm_source_cache_status_reports_safe_reason_codes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");

        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_artifact"
        );

        std::fs::create_dir_all(&cache).expect("mkdir cache");
        std::fs::write(cache.join("vmlinux"), b"stub").expect("write stub kernel");
        std::fs::write(cache.join("rootfs.ext4"), b"stub").expect("write stub rootfs");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "invalid_stage0_artifacts"
        );

        write_valid_builder_vm_artifacts(&cache);
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_fingerprint"
        );

        write_builder_vm_source_fingerprint(&cache, "other").expect("write fingerprint");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "fingerprint_mismatch"
        );

        write_builder_vm_source_fingerprint(&cache, "fingerprint").expect("write fingerprint");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_artifact_digest_manifest"
        );

        write_builder_vm_artifact_digest_manifest(&cache).expect("write digest manifest");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "missing_provenance"
        );

        write_builder_vm_source_cache_provenance(&cache, "other").expect("write provenance");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "provenance_mismatch"
        );

        write_builder_vm_source_cache_provenance(&cache, "fingerprint").expect("write provenance");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "hit"
        );

        write_builder_vm_artifact_digest_manifest(&cache).expect("rewrite digest manifest");
        std::fs::OpenOptions::new()
            .append(true)
            .open(cache.join("vmlinux"))
            .expect("open kernel")
            .write_all(b"tamper")
            .expect("tamper kernel");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "artifact_digest_mismatch"
        );

        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");
        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "hit"
        );
    }

    #[test]
    fn builder_vm_source_cache_provenance_omits_local_paths_and_artifact_digests() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");

        let json = std::fs::read_to_string(cache.join(BUILDER_VM_PROVENANCE_FILE))
            .expect("read provenance");
        assert!(json.contains("\"source_kind\": \"source_checkout_stage0\""));
        assert!(json.contains("\"source_fingerprint\": \"fingerprint\""));
        assert!(json.contains("\"vmlinux\""));
        assert!(json.contains("\"rootfs.ext4\""));
        assert!(
            !json.contains(&cache.display().to_string()),
            "provenance must not store local cache paths: {json}"
        );
        assert!(
            !json.contains("sha256"),
            "artifact digests belong in the separate digest manifest, not provenance: {json}"
        );
    }

    #[test]
    fn builder_vm_source_cache_rejects_tampered_provenance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");

        let tampered = serde_json::json!({
            "schema_version": 1,
            "source_kind": "source_checkout_stage0",
            "source_fingerprint": "other",
            "artifacts": ["vmlinux", "rootfs.ext4"]
        });
        std::fs::write(
            cache.join(BUILDER_VM_PROVENANCE_FILE),
            serde_json::to_string_pretty(&tampered).expect("json"),
        )
        .expect("write tampered provenance");

        assert_eq!(
            builder_vm_source_cache_status(&cache, "fingerprint").reason_code(),
            "provenance_mismatch"
        );
        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "provenance drift must force a source-checkout rebuild"
        );
    }

    #[test]
    fn builder_vm_source_cache_rejects_tampered_artifact_after_metadata() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cache = tmp.path().join("builder-vm").join("aarch64");
        write_valid_builder_vm_artifacts(&cache);
        write_builder_vm_source_cache_metadata(&cache, "fingerprint");

        std::fs::OpenOptions::new()
            .append(true)
            .open(cache.join("vmlinux"))
            .expect("open kernel")
            .write_all(b"tamper")
            .expect("tamper kernel");

        assert!(
            !builder_vm_source_cache_ready(&cache, "fingerprint"),
            "artifact digest drift must force a source-checkout rebuild"
        );
    }

    #[test]
    fn builder_vm_stage0_promotion_replaces_stale_valid_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join(".aarch64.stage0-test");
        let final_dir = tmp.path().join("aarch64");
        write_valid_builder_vm_artifacts(&staging);
        write_builder_vm_source_cache_metadata(&staging, "new");
        write_valid_builder_vm_artifacts(&final_dir);
        write_builder_vm_source_cache_metadata(&final_dir, "old");

        promote_builder_vm_stage0_cache(&staging, &final_dir, "new")
            .expect("stale valid cache should be replaced");

        assert!(!staging.exists(), "staging dir should be moved away");
        assert!(builder_vm_source_cache_ready(&final_dir, "new"));
    }

    // -------------------------------------------------------------------
    // Plan 77 W3 — Stage 0 audit-emit helpers.
    //
    // Tests below pin the *details* of the audit emits (which strings
    // the macro will write into `kind`, `detail`) so that the
    // downstream log shippers don't break on a typo, plus a structural
    // test for the failure-summary truncation rule.
    // -------------------------------------------------------------------

    #[test]
    fn stage0_fingerprint_prefix_truncates_to_eight_chars() {
        let full = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let prefix = stage0_fingerprint_prefix(full);
        assert_eq!(prefix, "01234567");
        assert_eq!(prefix.len(), 8);
    }

    #[test]
    fn stage0_fingerprint_prefix_handles_short_input() {
        // Defensive: source_fingerprint should always be 64 hex chars,
        // but if a future caller hands us a short string the helper
        // must not panic.
        let prefix = stage0_fingerprint_prefix("abc");
        assert_eq!(prefix, "abc");
    }

    #[test]
    fn stage0_failure_reason_summary_strips_newlines_and_caps_length() {
        let err = anyhow::anyhow!("first line\nsecond line\twith tab");
        let summary = stage0_failure_reason_summary(&err);
        assert!(!summary.contains('\n'));
        assert!(!summary.contains('\r'));
        assert!(!summary.contains('\t'));

        // 200-char input → 160-char output.
        let long_err = anyhow::anyhow!("{}", "x".repeat(200));
        let summary = stage0_failure_reason_summary(&long_err);
        assert_eq!(summary.chars().count(), 160);
    }

    #[test]
    fn stage0_failure_reason_summary_escapes_equals() {
        // The audit detail format is space-separated `key=value` pairs.
        // A bare `=` in the reason text would confuse downstream
        // parsers; the helper maps them to `~`.
        let err = anyhow::anyhow!("expected x=1 got y=2");
        let summary = stage0_failure_reason_summary(&err);
        assert!(!summary.contains('='), "got {summary}");
        assert!(summary.contains('~'));
    }

    #[test]
    fn stage0_failure_stage_wire_format_is_stable() {
        // The `stage=` value lands in audit details that downstream
        // dashboards filter on. Pinning the casing here keeps a future
        // refactor from accidentally renaming the variant.
        assert_eq!(Stage0FailureStage::Build.as_str(), "build");
        assert_eq!(Stage0FailureStage::Validate.as_str(), "validate");
        assert_eq!(format!("{}", Stage0FailureStage::Build), "build");
    }

    #[test]
    fn stage0_flavor_current_wire_format_is_stable() {
        // Plan 93 Phase 0 — the `flavor=` value emitted on every
        // `Stage0Boot` / `Stage0CachePromoted` audit line. Today there
        // is one variant (`"current"`); a future Plan 91 follow-up may
        // introduce additional variants (e.g. `"alpine"`). Pinning the
        // current literal here so a rename surfaces immediately.
        assert_eq!(STAGE0_FLAVOR_CURRENT, "current");
    }
}
