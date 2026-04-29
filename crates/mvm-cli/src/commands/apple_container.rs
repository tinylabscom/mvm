//! Apple Container dev environment + bundled image fetching.
//!
//! Extracted from `commands/mod.rs` as a pure mechanical refactor —
//! no behavior changes.

use anyhow::{Context, Result};

use super::console::{console_interactive, vsock_proxy_connect};
use crate::ui;

// ============================================================================
// Apple Container dev environment
// ============================================================================

pub(super) const DEV_VM_NAME: &str = "mvm-dev";

/// Check if the Apple Container dev VM is running.
/// Checks both in-process VM tracking (PID file) and launchd agent.
pub(super) fn is_apple_container_dev_running() -> bool {
    // Check persisted PID file (also checks if process is alive)
    let pid_running = mvm_apple_container::list_ids()
        .iter()
        .any(|id| id == DEV_VM_NAME);
    if pid_running {
        return true;
    }
    // Check if launchd agent is installed and loaded
    if dev_launchd_plist_path().exists() {
        let output = std::process::Command::new("launchctl")
            .args(["list", DEV_LAUNCHD_LABEL])
            .output();
        if let Ok(o) = output
            && o.status.success()
        {
            return true;
        }
    }
    false
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

    // Launch a background daemon process that keeps the VM alive.
    let exe = std::env::current_exe().context("cannot find current executable")?;
    let log_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&log_dir)?;

    // Sign the binary BEFORE launching via launchd. The daemon runs with
    // MVM_SIGNED=1 so it won't re-exec (which would lose launchd context).
    mvm_apple_container::ensure_signed();

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
            && vsock_proxy_connect(&proxy_path, mvm_guest::vsock::GUEST_AGENT_PORT).is_ok()
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
pub(super) fn dev_vsock_proxy_path() -> String {
    mvm_apple_container::vsock_proxy_path(DEV_VM_NAME)
        .to_string_lossy()
        .into_owned()
}

/// Daemon mode: boot the VM, expose a vsock proxy socket, and block forever.
fn cmd_dev_apple_container_daemon(cpus: u32, memory_gib: u32) -> Result<()> {
    let kernel = std::env::var("MVM_DEV_KERNEL")
        .unwrap_or_else(|_| format!("{}/dev/vmlinux", mvm_core::config::mvm_cache_dir()));
    let rootfs = std::env::var("MVM_DEV_ROOTFS")
        .unwrap_or_else(|_| format!("{}/dev/rootfs.ext4", mvm_core::config::mvm_cache_dir()));

    let memory_mib = (memory_gib as u64) * 1024;
    mvm_apple_container::start(DEV_VM_NAME, &kernel, &rootfs, cpus, memory_mib)
        .map_err(|e| anyhow::anyhow!("Failed to start dev VM: {e}"))?;

    // Start a vsock proxy: listen on a Unix socket and proxy each
    // connection to the guest agent's vsock port. This lets `dev shell`
    // from another process connect to the VM.
    let proxy_path = dev_vsock_proxy_path();
    let _ = std::fs::remove_file(&proxy_path);
    start_vsock_proxy(&proxy_path);

    // Block forever — the VM lives in this process.
    loop {
        std::thread::park();
    }
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

/// Listen on a Unix socket and proxy each connection to the VM's vsock.
fn start_vsock_proxy(socket_path: &str) {
    use std::os::unix::net::UnixListener;

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Failed to start vsock proxy: {e}");
            return;
        }
    };

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Each connection: read the target vsock port from the first 4 bytes,
            // then proxy bidirectionally to that vsock port.
            std::thread::spawn(move || {
                use std::io::Read;
                let mut client = stream;
                let mut port_buf = [0u8; 4];
                if client.read_exact(&mut port_buf).is_err() {
                    return;
                }
                let port = u32::from_le_bytes(port_buf);

                let vsock = match mvm_apple_container::vsock_connect(DEV_VM_NAME, port) {
                    Ok(s) => s,
                    Err(_) => return,
                };

                // Bidirectional proxy
                let mut vsock_read = match vsock.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut client_write = match client.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let h = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut vsock_read, &mut client_write);
                });
                let mut vsock_write = vsock;
                let _ = std::io::copy(&mut client, &mut vsock_write);
                let _ = h.join();
            });
        }
    });
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

/// Ensure the dev image (kernel + rootfs) exists in the cache.
///
/// Returns (kernel_path, rootfs_path). Builds from the dev-image Nix flake
/// if not cached.
fn ensure_dev_image() -> Result<(String, String)> {
    let cache_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)?;

    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");

    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        return Ok((kernel_path, rootfs_path));
    }

    // Try Nix build first (works if Linux builder is configured)
    let plat = mvm_core::platform::current();
    if plat.has_host_nix()
        && let Ok(flake_dir) = find_dev_image_flake()
    {
        ui::info("Building dev image via Nix (first time only)...");
        let nix_bin = find_nix_binary();

        // On macOS, ensure the linux-builder SSH config exists so nix-daemon
        // can reach the builder VM on localhost:31022.
        if cfg!(target_os = "macos") && ensure_linux_builder_ssh_config() {
            ui::info("  Linux builder detected and SSH configured.");
        }

        // Stream stderr to the terminal so the user sees build progress,
        // while capturing stdout (which contains the store path).
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
                ui::success("Dev image built and cached.");
                return Ok((kernel_path, rootfs_path));
            }
        }

        // nix build failed. Re-run with captured stderr to detect the error type
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
        if stderr.contains("required system or feature not available") {
            ui::warn(
                "Nix cannot cross-compile Linux images on this Mac.\n\
                 No Linux builder detected. To fix this, either:\n\n\
                 \x20 1. Run in another terminal (keeps running):\n\
                 \x20    nix run 'nixpkgs#darwin.linux-builder'\n\n\
                 \x20 2. Or add to /etc/nix/nix.conf (permanent):\n\
                 \x20    builders = ssh-ng://builder@linux-builder aarch64-linux /etc/nix/builder_ed25519 4 1 kvm,big-parallel - -\n\
                 \x20    builders-use-substitutes = true\n\n\
                 Falling back to downloading a pre-built dev image...",
            );
        } else {
            ui::warn(&format!("Nix build failed, trying download:\n{stderr}"));
        }
    }

    // Fallback: download pre-built dev image from GitHub release
    download_dev_image(&kernel_path, &rootfs_path)
}

/// Download a pre-built dev image (kernel + rootfs) from GitHub releases.
fn download_dev_image(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
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
    let kernel_url = format!("{base_url}/dev-vmlinux-{arch}");
    let rootfs_url = format!("{base_url}/dev-rootfs-{arch}.ext4");

    ui::info(&format!("Downloading dev image (v{version})..."));

    // Download kernel
    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path)
        .with_context(|| format!("Failed to download kernel from {kernel_url}"))?;

    // Download rootfs
    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path)
        .with_context(|| format!("Failed to download rootfs from {rootfs_url}"))?;

    ui::success("Dev image downloaded and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
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

    let candidate = workspace_root.join("nix").join("dev-image");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }

    // Fall back to the guest-lib minimal profile
    let guest_lib = workspace_root.join("nix").join("guest-lib");
    if guest_lib.join("flake.nix").exists() {
        return Ok(guest_lib.to_str().unwrap_or(".").to_string());
    }

    anyhow::bail!(
        "Dev image flake not found. Expected at nix/dev-image/flake.nix\n\
         or nix/guest-lib/flake.nix"
    )
}

/// Locate the bundled `nix/default-microvm/` flake.
///
/// This is the fallback used by image-taking commands (`mvmctl exec`,
/// `mvmctl up`/`run`/`start`) when neither `--flake` nor `--template` is
/// supplied.
fn find_default_microvm_flake() -> Result<String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root.join("nix").join("default-microvm");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }
    anyhow::bail!(
        "Default microVM image flake not found. Expected at nix/default-microvm/flake.nix"
    )
}

/// Ensure the bundled default microVM image (kernel + rootfs) is in the cache.
///
/// Used by any image-taking command when no `--flake` or `--template` was
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
/// matching GitHub release. Mirrors `download_dev_image`.
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
    let kernel_url = format!("{base_url}/default-microvm-vmlinux-{arch}");
    let rootfs_url = format!("{base_url}/default-microvm-rootfs-{arch}.ext4");

    ui::info(&format!(
        "Downloading default microVM image (v{version})..."
    ));

    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path)
        .with_context(|| format!("Failed to download kernel from {kernel_url}"))?;

    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path)
        .with_context(|| format!("Failed to download rootfs from {rootfs_url}"))?;

    ui::success("Default microVM image downloaded and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}
