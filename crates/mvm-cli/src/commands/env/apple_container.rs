//! Apple Container dev environment + bundled image fetching.
//!
//! Extracted from `commands/mod.rs` as a pure mechanical refactor —
//! no behavior changes.

use anyhow::{Context, Result};

use mvm_runtime::vsock_transport::{VsockProxyTransport, VsockTransport};

use super::super::vm::console::console_interactive;
use crate::ui;

// ============================================================================
// Apple Container dev environment
// ============================================================================

pub(super) const DEV_VM_NAME: &str = "mvm-dev";

/// Check if the Apple Container dev VM is running *and* reachable
/// cross-process via the vsock proxy socket.
///
/// A live PID file alone is not enough — the daemon may have started but
/// failed to materialize the proxy socket, in which case `run_in_vm` calls
/// from other processes will fail. Treating that state as "not running"
/// keeps `dev status` honest with what `shell::run_in_vm` actually sees.
pub(in crate::commands) fn is_apple_container_dev_running() -> bool {
    let pid_running = mvm_apple_container::list_ids()
        .iter()
        .any(|id| id == DEV_VM_NAME);
    if !pid_running {
        return false;
    }
    let proxy = mvm_apple_container::vsock_proxy_path(DEV_VM_NAME);
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
    mvm_apple_container::ensure_signed();

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
    mvm_apple_container::vsock_proxy_path(DEV_VM_NAME)
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
    mvm_apple_container::start(DEV_VM_NAME, &kernel, &rootfs, cpus, memory_mib)
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
        && let Ok(mut stream) =
            mvm_apple_container::vsock_connect_any(DEV_VM_NAME, mvm_guest::vsock::GUEST_AGENT_PORT)
        && let Ok(mvm_guest::vsock::GuestResponse::ExecResult { stdout, .. }) =
            mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::Exec {
                    command: "uname -r".to_string(),
                    stdin: None,
                    timeout_secs: Some(5),
                },
            )
    {
        ui::info(&format!("  Kernel:  {}", stdout.trim()));
    }

    // Show dev image info
    let cache_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    ui::info(&format!(
        "  Image:   {}",
        if std::path::Path::new(&rootfs_path).exists() {
            "cached"
        } else {
            "not built"
        }
    ));
    if std::path::Path::new(&kernel_path).exists() {
        ui::info(&format!("  Kernel:  {kernel_path}"));
    }
    if std::path::Path::new(&rootfs_path).exists() {
        ui::info(&format!("  Rootfs:  {rootfs_path}"));
    }

    Ok(())
}

/// Ensure the Nix linux-builder VM is running, SSH is configured, and
/// nix-daemon knows about it.
///
/// `nix run 'nixpkgs#darwin.linux-builder'` starts a QEMU VM on port 31022
/// and writes `/etc/nix/builder_ed25519`, but does NOT create the SSH config
/// that maps `linux-builder` → `localhost:31022`. It also does not add the
/// `builders` line to nix.conf. This function handles all three pieces:
/// 1. Start the builder VM in the background if not already running
/// 2. Write the SSH host alias so nix-daemon can connect
/// 3. Add the `builders` line to nix.custom.conf
///
/// Returns `true` if the builder appears reachable after any fixup.
fn ensure_linux_builder_ssh_config() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        false
    }

    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        use std::net::TcpStream;
        use std::time::Duration;

        let key_path = "/etc/nix/builder_ed25519";
        let builder_port: u16 = 31022;

        let builder_listening = || {
            TcpStream::connect_timeout(
                &format!("127.0.0.1:{builder_port}")
                    .parse()
                    .expect("valid socket address literal"),
                Duration::from_secs(2),
            )
            .is_ok()
        };

        // If builder is not listening, try to start it automatically
        if !builder_listening() {
            let nix_bin = find_nix_binary();
            ui::info("  Starting Nix linux-builder VM in the background...");

            // Launch as a background process. The builder writes
            // /etc/nix/builder_ed25519 on first run (needs sudo).
            // Redirect output to a log file so it doesn't clutter the terminal.
            let log_path = format!("{}/linux-builder.log", mvm_core::config::mvm_cache_dir());
            let log_file = std::fs::File::create(&log_path)
                .or_else(|_| std::fs::File::create("/dev/null"))
                .expect("failed to open /dev/null");
            let stderr_file = log_file
                .try_clone()
                .or_else(|_| std::fs::File::create("/dev/null"))
                .expect("failed to open /dev/null");

            let child = std::process::Command::new(&nix_bin)
                .args(["run", "nixpkgs#darwin.linux-builder"])
                .stdout(log_file)
                .stderr(stderr_file)
                .stdin(std::process::Stdio::null())
                .spawn();

            if child.is_err() {
                return false;
            }

            // Wait for the builder to become ready (port 31022 + key file).
            // First boot can take a while as it downloads the builder VM.
            ui::info(
                "  Waiting for linux-builder to become ready (this may take a minute on first run)...",
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            loop {
                if std::time::Instant::now() > deadline {
                    ui::warn("  Timed out waiting for linux-builder to start.");
                    return false;
                }
                if std::path::Path::new(key_path).exists() && builder_listening() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }

        // Key must exist (created by the linux-builder on first run)
        if !std::path::Path::new(key_path).exists() {
            return false;
        }

        // --- SSH config ---
        // Check that the SSH config exists AND uses the correct user ("builder",
        // not "root"). Older versions wrote "User root" which doesn't work.
        let ssh_config_dir = std::path::Path::new("/etc/ssh/ssh_config.d");
        let config_path = ssh_config_dir.join("200-linux-builder.conf");

        let expected_config = format!(
            "Host linux-builder\n\
             \x20 HostName localhost\n\
             \x20 Port {builder_port}\n\
             \x20 User builder\n\
             \x20 IdentityFile {key_path}\n\
             \x20 IdentitiesOnly yes\n\
             \x20 StrictHostKeyChecking no\n\
             \x20 UserKnownHostsFile /dev/null\n\
             \x20 LogLevel ERROR\n"
        );

        let ssh_needs_write = if config_path.exists() {
            // Re-write if the existing config has wrong user
            std::fs::read_to_string(&config_path)
                .map(|c| !c.contains("User builder"))
                .unwrap_or(true)
        } else {
            // Also check via ssh -G whether some other config provides
            // a correct mapping (e.g. user's own ~/.ssh/config)
            let ssh_check = std::process::Command::new("ssh")
                .args(["-G", "linux-builder"])
                .output();
            if let Ok(out) = ssh_check {
                let cfg = String::from_utf8_lossy(&out.stdout);
                let has_host = cfg.lines().any(|l| {
                    l.strip_prefix("hostname ")
                        .is_some_and(|h| h.trim() != "linux-builder")
                });
                let has_user = cfg.lines().any(|l| {
                    l.strip_prefix("user ")
                        .is_some_and(|u| u.trim() == "builder")
                });
                !has_host || !has_user
            } else {
                true
            }
        };

        let mut ssh_ok = !ssh_needs_write;
        if ssh_needs_write {
            let tmp_path = "/tmp/mvm-linux-builder-ssh.conf";
            if let Ok(mut f) = std::fs::File::create(tmp_path)
                && f.write_all(expected_config.as_bytes()).is_ok()
            {
                let status = std::process::Command::new("sudo")
                    .args(["cp", tmp_path, config_path.to_str().unwrap_or_default()])
                    .status();
                let _ = std::fs::remove_file(tmp_path);
                ssh_ok = matches!(status, Ok(s) if s.success());
            }
        }

        if !ssh_ok {
            return false;
        }

        // --- nix.conf builders line ---
        // nix-daemon needs a `builders` entry pointing at the linux-builder.
        // Determinate Nix uses nix.custom.conf (included from nix.conf).
        // Also fix stale configs that used the wrong SSH user.
        let builders_line = format!(
            "builders = ssh-ng://builder@linux-builder aarch64-linux {key_path} 4 1 kvm,big-parallel - -"
        );

        let nix_custom = std::path::Path::new("/etc/nix/nix.custom.conf");
        let nix_conf = std::path::Path::new("/etc/nix/nix.conf");

        let nix_needs_write = {
            let has_correct = [nix_custom, nix_conf].iter().any(|path| {
                std::fs::read_to_string(path)
                    .map(|c| {
                        c.lines().any(|l| {
                            l.trim_start().starts_with("builders")
                                && l.contains("builder@linux-builder")
                        })
                    })
                    .unwrap_or(false)
            });
            !has_correct
        };

        if nix_needs_write {
            ui::info("  Configuring nix-daemon to use the linux-builder...");

            // Read existing content, strip any old mvmctl builder block, append fresh one
            let existing = std::fs::read_to_string(nix_custom).unwrap_or_default();
            let cleaned: String = {
                let mut skip = false;
                let mut lines = Vec::new();
                for line in existing.lines() {
                    if line.contains("Added by mvmctl for darwin.linux-builder") {
                        skip = true;
                        continue;
                    }
                    if skip {
                        // Skip the builders and builders-use-substitutes lines
                        if line.trim_start().starts_with("builders") {
                            continue;
                        }
                        // Blank line after the block — skip it too, then stop skipping
                        if line.trim().is_empty() {
                            skip = false;
                            continue;
                        }
                        skip = false;
                    }
                    lines.push(line);
                }
                lines.join("\n")
            };

            let new_content = format!(
                "{cleaned}\n\
                 # Added by mvmctl for darwin.linux-builder\n\
                 {builders_line}\n\
                 builders-use-substitutes = true\n"
            );

            let tmp_path = "/tmp/mvm-nix-custom-append.conf";
            if let Ok(mut f) = std::fs::File::create(tmp_path)
                && f.write_all(new_content.as_bytes()).is_ok()
            {
                let status = std::process::Command::new("sudo")
                    .args(["cp", tmp_path, nix_custom.to_str().unwrap_or_default()])
                    .status();
                let _ = std::fs::remove_file(tmp_path);
                if !matches!(status, Ok(s) if s.success()) {
                    return false;
                }

                // Restart nix-daemon so it picks up the new config.
                let restarted = std::process::Command::new("sudo")
                    .args([
                        "launchctl",
                        "kickstart",
                        "-k",
                        "system/systems.determinate.nix-daemon",
                    ])
                    .status()
                    .is_ok_and(|s| s.success());
                if !restarted {
                    let _ = std::process::Command::new("sudo")
                        .args([
                            "launchctl",
                            "kickstart",
                            "-k",
                            "system/org.nixos.nix-daemon",
                        ])
                        .status();
                }
            }
        }

        true
    }
}

/// Resolve the dev image (kernel + rootfs) to absolute paths.
///
/// Builds the dev-image flake via Nix if needed, otherwise relies on
/// Nix's content-addressed cache (rebuild is a no-op when source is
/// unchanged). Updates a GC-root symlink at `~/.mvm/dev/current` so
/// `nix-collect-garbage` won't reap the live image while it's in use.
///
/// Returns paths under the GC-root symlink rather than into /nix/store
/// directly — this keeps the launchd plist and user-facing logs stable
/// across rebuilds (the symlink target moves, the symlink path doesn't).
fn ensure_dev_image() -> Result<(String, String)> {
    // Resolution policy:
    //   * In a source checkout (find_dev_image_flake() Ok): always
    //     run nix build. Nix dedupes content-addressed builds, so a
    //     no-op rebuild is fast; an actual change is picked up
    //     automatically without a manual cache wipe.
    //   * Outside a source checkout (find_dev_image_flake() Err):
    //     fall back to the GitHub-release download.
    //
    // Failures of the local build are surfaced loudly — never silently
    // substituted with the prebuilt, since the prebuilt would mask
    // local rootfs changes.
    let plat = mvm_core::platform::current();
    let local_flake = find_dev_image_flake().ok();
    let host_nix = plat.has_host_nix();

    if let Some(flake_dir) = &local_flake
        && host_nix
    {
        ui::info(&format!(
            "Resolving dev image via Nix from local checkout: {flake_dir}"
        ));
        let nix_bin = find_nix_binary();

        // On macOS, ensure the linux-builder SSH config exists so nix-daemon
        // can reach the builder VM on localhost:31022.
        if cfg!(target_os = "macos") && ensure_linux_builder_ssh_config() {
            ui::info("  Linux builder detected and SSH configured.");
        }

        // Build into a Nix-managed indirect GC root at ~/.mvm/dev/current.
        // `nix build --out-link` materialises a symlink that survives
        // garbage collection. The symlink path is stable; its target
        // moves each time the source closure changes. Builds against
        // unchanged source resolve in milliseconds via Nix's content
        // cache — no separate filesystem cache, no manual reset.
        let gc_root = format!("{}/dev/current", mvm_core::config::mvm_data_dir());
        if let Some(parent) = std::path::Path::new(&gc_root).parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("creating dev-image GC root parent {}", parent.display())
            })?;
        }

        let mut child = std::process::Command::new(&nix_bin)
            .args([
                "build",
                &format!(
                    "{flake_dir}#packages.{}.default",
                    mvm_build::dev_build::linux_system()
                ),
                "--out-link",
                &gc_root,
                "--print-out-paths",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .context("Failed to run nix build")?;

        let stdout = {
            let mut buf = String::new();
            if let Some(mut out) = child.stdout.take() {
                use std::io::Read;
                let _ = out.read_to_string(&mut buf);
            }
            buf
        };
        let status = child.wait().context("nix build process failed")?;

        if status.success() {
            let store_path = stdout.trim().to_string();
            let ks = format!("{gc_root}/vmlinux");
            let rs = format!("{gc_root}/rootfs.ext4");
            if std::path::Path::new(&ks).exists() && std::path::Path::new(&rs).exists() {
                ui::success(&format!("Dev image ready (store path: {store_path})."));
                return Ok((ks, rs));
            }
        }

        // Local nix build failed. Re-run with --dry-run to capture stderr
        // (the first run streamed stderr to the terminal for user visibility).
        let diag = std::process::Command::new(&nix_bin)
            .args([
                "build",
                &format!(
                    "{flake_dir}#packages.{}.default",
                    mvm_build::dev_build::linux_system()
                ),
                "--no-link",
                "--dry-run",
            ])
            .output()
            .ok();
        let stderr = diag
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            .unwrap_or_default();
        let hint = if stderr.contains("required system or feature not available") {
            "\n\nNix cannot cross-compile Linux images on this Mac.\n\
             No Linux builder detected. Either:\n\
             \x20 1. Run in another terminal (keeps running):\n\
             \x20    nix run 'nixpkgs#darwin.linux-builder'\n\
             \x20 2. Or add to /etc/nix/nix.conf (permanent):\n\
             \x20    builders = ssh-ng://builder@linux-builder aarch64-linux /etc/nix/builder_ed25519 4 1 kvm,big-parallel - -\n\
             \x20    builders-use-substitutes = true"
                .to_string()
        } else {
            String::new()
        };
        anyhow::bail!(
            "Local dev image build failed (running from source checkout: {flake_dir}).\n\
             {stderr}{hint}\n\n\
             Refusing to fall back to the published prebuilt because it would mask\n\
             local rootfs changes. To force the prebuilt anyway, move or delete\n\
             nix/images/builder/flake.nix so the source-checkout heuristic stops matching."
        );
    }

    // No local source checkout — download the published prebuilt.
    // Cache key = mvmctl's version: each version owns a sibling
    // directory under .../dev/prebuilt/, and bumping the binary
    // automatically invalidates older caches. We sweep older version
    // dirs on every miss so disk usage tracks the *current* version,
    // not the union of every version ever installed.
    if local_flake.is_none() {
        ui::info("No local dev-image flake found; downloading published prebuilt.");
    } else if !host_nix {
        ui::info("No `nix` binary on host; downloading published prebuilt instead of local build.");
    }
    let version = env!("CARGO_PKG_VERSION");
    let prebuilt_root = format!("{}/dev/prebuilt", mvm_core::config::mvm_data_dir());
    let prebuilt_dir = format!("{prebuilt_root}/v{version}");
    std::fs::create_dir_all(&prebuilt_dir)
        .with_context(|| format!("creating prebuilt dir {prebuilt_dir}"))?;
    prune_old_prebuilts(&prebuilt_root, version);
    let kernel_path = format!("{prebuilt_dir}/vmlinux");
    let rootfs_path = format!("{prebuilt_dir}/rootfs.ext4");
    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        return Ok((kernel_path, rootfs_path));
    }
    download_dev_image(&kernel_path, &rootfs_path)
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
    let base_url = format!("https://github.com/auser/mvm/releases/download/v{version}");
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
            "Failed to download cosign bundle from {bundle_url}. Plan 36 \
             requires a manifest's signature to be present alongside the \
             manifest body — refusing to trust an unsigned manifest."
        ))
    })?;

    let manifest_bytes =
        std::fs::read(&manifest_path).context("reading downloaded manifest body")?;
    let bundle_bytes = std::fs::read(&bundle_path).context("reading downloaded cosign bundle")?;

    // GitHub Actions keyless OIDC: the SAN encodes the workflow URL
    // bound to the tag, and the issuer is GitHub's token endpoint.
    let expected_identity =
        format!("https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/v{version}");
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        tracing::warn!(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest body. \
             Plan 36 documents this as an emergency-rotation escape hatch only."
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
        let base = "https://github.com/auser/mvm/releases/download/revocations";
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
                             is available; proceeding without recall enforcement. \
                             Plan 36 §Layer 4."
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
    let expected_identity =
        "https://github.com/auser/mvm/.github/workflows/revocations.yml@refs/tags/revocations";
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
             trust an unverified recall. Plan 36 §Layer 4."
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

    let expected_identity =
        format!("https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/v{version}");
    let expected_issuer = "https://token.actions.githubusercontent.com";

    let manifest = if std::env::var_os("MVM_SKIP_COSIGN_VERIFY").is_some() {
        ui::warn(
            "MVM_SKIP_COSIGN_VERIFY set — accepting unverified manifest. \
             Plan 36 documents this as an emergency-rotation escape only.",
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
             \x20   https://github.com/auser/mvm/releases/tag/v{version}\n\
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

/// Find the `nix` binary, checking PATH and common install locations.
fn find_nix_binary() -> String {
    if which::which("nix").is_ok() {
        return "nix".to_string();
    }
    for path in &[
        "/nix/var/nix/profiles/default/bin/nix",
        "/run/current-system/sw/bin/nix",
    ] {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    "nix".to_string() // fall back to PATH, let the error happen naturally
}

/// Find the dev-image Nix flake directory.
fn find_dev_image_flake() -> Result<String> {
    // Check in the source tree
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root.join("nix").join("images").join("builder");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }

    // Fall back to the parent flake's minimal profile
    let parent = workspace_root.join("nix");
    if parent.join("flake.nix").exists() {
        return Ok(parent.to_str().unwrap_or(".").to_string());
    }

    anyhow::bail!(
        "Dev image flake not found. Expected at nix/images/builder/flake.nix\n\
         or nix/flake.nix"
    )
}

/// Locate the bundled `nix/images/default-tenant/` flake.
///
/// This is the fallback used by image-taking commands (`mvmctl exec`,
/// `mvmctl up`) when neither `--flake` nor `--manifest` is supplied.
/// (Was `nix/default-microvm/` before W7.3.)
fn find_default_microvm_flake() -> Result<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root
        .join("nix")
        .join("images")
        .join("default-tenant");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }
    anyhow::bail!(
        "Default microVM image flake not found. Expected at nix/images/default-tenant/flake.nix"
    )
}

/// Ensure the bundled default microVM image (kernel + rootfs) is in the cache.
///
/// Used by any image-taking command when no `--flake` or `--manifest` was
/// supplied. Builds via Nix on first use and caches under
/// `~/.cache/mvm/default-microvm/`. Returns `(kernel_path, rootfs_path)`.
///
/// On hosts without Nix (or where the local Nix build fails — e.g. macOS
/// without a Linux builder configured), falls back to downloading a
/// pre-built image from the matching GitHub release.
pub(crate) fn ensure_default_microvm_image() -> Result<(String, String)> {
    let cache_dir = format!("{}/default-microvm", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)?;

    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");

    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        return Ok((kernel_path, rootfs_path));
    }

    let plat = mvm_core::platform::current();
    if plat.has_host_nix()
        && let Ok(flake_dir) = find_default_microvm_flake()
    {
        let nix_bin = find_nix_binary();

        if cfg!(target_os = "macos") && ensure_linux_builder_ssh_config() {
            ui::info("  Linux builder detected and SSH configured.");
        }

        ui::info("Building default microVM image via Nix (first time only)...");
        let mut child = std::process::Command::new(&nix_bin)
            .args([
                "build",
                &format!(
                    "{flake_dir}#packages.{}.default",
                    mvm_build::dev_build::linux_system()
                ),
                "--no-link",
                "--print-out-paths",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .context("Failed to run nix build")?;

        let stdout = {
            let mut buf = String::new();
            if let Some(mut out) = child.stdout.take() {
                use std::io::Read;
                let _ = out.read_to_string(&mut buf);
            }
            buf
        };
        let status = child.wait().context("nix build process failed")?;

        if status.success() {
            let store_path = stdout.trim().to_string();
            let ks = format!("{store_path}/vmlinux");
            let rs = format!("{store_path}/rootfs.ext4");
            if std::path::Path::new(&ks).exists() && std::path::Path::new(&rs).exists() {
                std::fs::copy(&ks, &kernel_path)?;
                std::fs::copy(&rs, &rootfs_path)?;
                ui::success("Default microVM image built and cached.");
                return Ok((kernel_path, rootfs_path));
            }
        }

        ui::warn("Local Nix build failed; falling back to pre-built download.");
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
    let base_url = format!("https://github.com/auser/mvm/releases/download/v{version}");
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
