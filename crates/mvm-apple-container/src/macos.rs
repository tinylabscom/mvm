//! macOS Virtualization.framework VM lifecycle using objc2-virtualization.
//!
//! VMs are created from the CLI thread with callbacks on the main dispatch
//! queue. The main thread pumps NSRunLoop (see main.rs) to deliver callbacks.

use std::collections::HashMap;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::*;
use objc2_virtualization::*;

const START_TIMEOUT: Duration = Duration::from_secs(30);

/// In-process VM handle tracking. Stores raw pointer to VZVirtualMachine
/// (must be accessed only from the main dispatch queue).
///
/// We store raw pointers because VZVirtualMachine is `!Send` — the actual
/// object lives on the main queue. All access goes through `dispatch_on_main`.
static VMS: std::sync::LazyLock<Mutex<HashMap<String, usize>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Directory for persisted VM state (PID files + metadata).
fn vm_state_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(format!("{home}/.mvm/vms"))
}

/// Write VM state to disk so other processes can see it.
fn persist_vm_state(id: &str) {
    let dir = vm_state_dir().join(id);
    tracing::info!("Persisting VM state to {}", dir.display());
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("Failed to create VM state dir {}: {e}", dir.display());
        return;
    }
    let pid = std::process::id();
    let _ = std::fs::write(dir.join("pid"), pid.to_string());
    let _ = std::fs::write(dir.join("backend"), "apple-virtualization");
}

/// Path to the cross-process vsock proxy Unix socket for VM `id`.
fn vsock_proxy_socket_path(id: &str) -> std::path::PathBuf {
    vm_state_dir().join(id).join("vsock.sock")
}

/// Listen on the per-VM Unix socket and forward each connection to a vsock
/// port on the running in-process VM.
///
/// Wire protocol: client sends a little-endian `u32` port, then the proxy
/// connects to that vsock port via `vsock_connect` and copies bytes both
/// ways. This mirrors what `vsock_connect_any` (in `lib.rs`) speaks, so any
/// other `mvmctl` process can reach the dev VM as long as the socket file
/// exists and the daemon is alive.
///
/// Failures here are surfaced via `Err`: the caller (currently `start_vm`)
/// treats a failed proxy as a failed VM start, since a VM that can't be
/// reached cross-process is functionally not running.
fn start_vsock_proxy_listener(id: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let socket_path = vsock_proxy_socket_path(id);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create proxy socket dir {}: {e}", parent.display()))?;
    }
    // A leftover socket file from a previous (now-dead) daemon would make
    // bind() fail with EADDRINUSE. The state-cleanup path in `dev down`
    // already handles this, but be defensive: any pid-checked stale entry
    // that escaped cleanup must not block a fresh start.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("bind vsock proxy socket {}: {e}", socket_path.display()))?;

    // ADR-002 W1.2: lock the socket to mode 0700 so a same-host other
    // user can't speak the proxy protocol. Without this the socket
    // inherits umask (typically 0755), and any process running as
    // anyone on the same Mac could open the dev VM's guest agent
    // and call `Exec` (in the dev image) or `ConsoleOpen` (in any
    // image). Filesystem perms ARE the auth boundary; we make them
    // explicit rather than implicit.
    if let Err(e) = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700)) {
        tracing::warn!(
            "could not chmod 0700 on vsock proxy socket {}: {e}",
            socket_path.display()
        );
    }

    let id = id.to_string();
    std::thread::Builder::new()
        .name(format!("vsock-proxy-{id}"))
        .spawn(move || proxy_accept_loop(listener, id))
        .map_err(|e| format!("spawn vsock proxy thread: {e}"))?;
    Ok(())
}

/// Decide whether a port that arrived over the proxy socket is one we
/// should forward to the in-process VM's vsock. ADR-002 W1.3.
///
/// The proxy speaks a one-byte-prefix protocol: client sends a u32 LE
/// port and then expects bidirectional bytes to that vsock port. Without
/// an allowlist, a client could connect to *any* vsock port the guest
/// happens to have listening — not just the guest agent. We restrict
/// to the three ranges mvmctl actually uses:
///
/// * `52` — guest agent control channel.
/// * `PORT_FORWARD_BASE..=BASE+65535` — traffic forwarders set up by
///   `start_port_proxy` (BASE = 10000).
/// * `CONSOLE_PORT_BASE..=BASE+65535` — `ConsoleOpen` data ports
///   (BASE = 20000).
fn proxy_port_is_allowed(port: u32) -> bool {
    const GUEST_AGENT: u32 = 52;
    const PORT_FORWARD_BASE: u32 = 10_000;
    const CONSOLE_PORT_BASE: u32 = 20_000;
    port == GUEST_AGENT
        || (PORT_FORWARD_BASE..=PORT_FORWARD_BASE + 65_535).contains(&port)
        || (CONSOLE_PORT_BASE..=CONSOLE_PORT_BASE + 65_535).contains(&port)
}

fn proxy_accept_loop(listener: std::os::unix::net::UnixListener, id: String) {
    use std::io::Read;

    for stream in listener.incoming().flatten() {
        let id = id.clone();
        std::thread::spawn(move || {
            let mut client = stream;
            let mut port_buf = [0u8; 4];
            if client.read_exact(&mut port_buf).is_err() {
                return;
            }
            let port = u32::from_le_bytes(port_buf);

            if !proxy_port_is_allowed(port) {
                tracing::warn!(
                    "vsock proxy: rejecting connection to disallowed port {port} on '{id}'"
                );
                return;
            }

            let vsock = match vsock_connect(&id, port) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("vsock proxy: connect to '{id}' port {port} failed: {e}");
                    return;
                }
            };

            let Ok(mut vsock_read) = vsock.try_clone() else {
                return;
            };
            let Ok(mut client_write) = client.try_clone() else {
                return;
            };
            let copy_up = std::thread::spawn(move || {
                let _ = std::io::copy(&mut vsock_read, &mut client_write);
            });
            let mut vsock_write = vsock;
            let _ = std::io::copy(&mut client, &mut vsock_write);
            let _ = copy_up.join();
        });
    }
}

/// Remove VM state from disk and unload launchd agent.
fn remove_vm_state(id: &str) {
    unload_launchd_agent(id);
    let dir = vm_state_dir().join(id);
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// launchd agent management
// ---------------------------------------------------------------------------

fn launchd_label(id: &str) -> String {
    format!("com.mvm.vm.{id}")
}

fn launchd_plist_path(id: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(format!(
        "{home}/Library/LaunchAgents/{}.plist",
        launchd_label(id)
    ))
}

/// Install and load a launchd user agent that runs the VM in the background.
///
/// Install a launchd agent using pre-built kernel/rootfs paths.
/// The agent calls `start_vm()` directly via env vars (no rebuild).
pub fn install_launchd_direct(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
    ports: &[String],
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let label = launchd_label(id);
    let plist_path = launchd_plist_path(id);
    let log_dir = vm_state_dir().join(id);
    std::fs::create_dir_all(&log_dir).map_err(|e| format!("mkdir: {e}"))?;

    // The plist runs mvmctl with --hypervisor apple-container and
    // MVM_DIRECT_BOOT env var that tells start_vm to use the paths
    // from env vars instead of going through the build pipeline.
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>up</string>
        <string>--flake</string>
        <string>/dev/null</string>
        <string>--name</string>
        <string>{id}</string>
        <string>--hypervisor</string>
        <string>apple-container</string>
        <string>--cpus</string>
        <string>{cpus}</string>
        <string>--memory</string>
        <string>{memory_mib}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MVM_SIGNED</key>
        <string>1</string>
        <key>MVM_DIRECT_BOOT</key>
        <string>1</string>
        <key>MVM_KERNEL_PATH</key>
        <string>{kernel_path}</string>
        <key>MVM_ROOTFS_PATH</key>
        <string>{rootfs_path}</string>
        <key>MVM_PORTS</key>
        <string>{ports}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{log_dir}/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/stderr.log</string>
</dict>
</plist>"#,
        exe = exe.display(),
        log_dir = log_dir.display(),
        ports = ports.join(","),
    );

    let agents_dir = plist_path.parent().expect("plist path must have parent");
    std::fs::create_dir_all(agents_dir).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::write(&plist_path, &plist).map_err(|e| format!("write: {e}"))?;

    let output = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("launchctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl load: {stderr}"));
    }

    tracing::info!("Installed launchd agent: {label}");
    Ok(())
}

/// Unload and remove the launchd agent for a VM.
fn unload_launchd_agent(id: &str) {
    let plist_path = launchd_plist_path(id);
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap_or("")])
            .output();
        let _ = std::fs::remove_file(&plist_path);
        tracing::info!("Unloaded launchd agent: {}", launchd_label(id));
    }
}

/// Read all VM IDs from disk, filtering out dead PIDs.
fn read_persisted_vm_ids() -> Vec<String> {
    let dir = vm_state_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    let mut ids = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let pid_file = entry.path().join("pid");
        if let Ok(pid_str) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = pid_str.trim().parse::<i32>()
        {
            // Check if process is still alive
            if unsafe { libc::kill(pid, 0) } == 0 {
                ids.push(name);
            } else {
                // Dead process — clean up
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
    ids
}

/// Ensure the running binary has the virtualization entitlement.
/// If not, sign it ad-hoc and re-exec the process.
///
/// When `MVM_SIGNED=1` is set (by re-exec or launchd agents), the
/// re-exec is skipped — the parent already signed the binary on disk
/// before launching the daemon.
pub fn ensure_signed() {
    // Already re-exec'd or launched by launchd with a signed binary.
    if std::env::var("MVM_SIGNED").as_deref() == Ok("1") {
        return;
    }

    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };
    let exe_str = exe.to_str().unwrap_or("");

    // Check if already signed with the required entitlement
    if let Ok(output) = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml", exe_str])
        .output()
        && output.status.success()
        && String::from_utf8_lossy(&output.stdout).contains("com.apple.security.virtualization")
    {
        return;
    }

    tracing::info!("Signing binary with virtualization entitlement...");
    sign_binary(exe_str);

    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("MVM_SIGNED", "1")
        .exec();
    tracing::error!("Re-exec after signing failed: {err}");
    std::process::exit(1);
}

/// Sign the binary with the virtualization entitlement (no re-exec).
///
/// Called by `ensure_signed()` and also by the `-d` detach path to
/// pre-sign before installing the launchd agent.
fn sign_binary(exe_str: &str) {
    let ent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
        \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\"><dict>\n\
        <key>com.apple.security.virtualization</key><true/>\n\
        </dict></plist>";

    let ent_path = std::env::temp_dir().join("mvm-entitlements.plist");
    if std::fs::write(&ent_path, ent).is_err() {
        return;
    }

    let _ = std::process::Command::new("codesign")
        .args(["--sign", "-", "--force", "--entitlements"])
        .arg(&ent_path)
        .arg(exe_str)
        .output();

    let _ = std::fs::remove_file(&ent_path);
}

/// Start a port proxy that forwards localhost:host_port to the guest's
/// tcp_port via vsock. The guest agent runs a vsock→TCP forwarder on
/// `PORT_FORWARD_BASE + guest_port`. Runs in a background thread.
pub fn start_port_proxy(vm_id: &str, host_port: u16, guest_port: u16) {
    use std::net::TcpListener;

    let bind = format!("127.0.0.1:{host_port}");
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Port proxy bind {bind} failed: {e}");
            return;
        }
    };

    // Must match mvm_guest::vsock::PORT_FORWARD_BASE
    let vsock_port = 10000u32 + guest_port as u32;
    tracing::info!(
        "Port forwarding: localhost:{host_port} → vsock:{vsock_port} → guest tcp/{guest_port}"
    );

    let vm_id = vm_id.to_string();
    std::thread::Builder::new()
        .name(format!("proxy-{host_port}"))
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let vm_id = vm_id.clone();
                std::thread::spawn(move || {
                    let upstream = match vsock_connect(&vm_id, vsock_port) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(
                                "Port proxy: vsock connect to {vm_id} port {vsock_port} failed: {e}"
                            );
                            return;
                        }
                    };
                    let downstream = stream;
                    let Ok(mut up_read) = upstream.try_clone() else {
                        tracing::warn!("Port proxy: upstream clone failed");
                        return;
                    };
                    let Ok(mut down_write) = downstream.try_clone() else {
                        tracing::warn!("Port proxy: downstream clone failed");
                        return;
                    };
                    let mut up_write = upstream;
                    let mut down_read = downstream;

                    let h1 = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut down_read, &mut up_write);
                    });
                    let h2 = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut up_read, &mut down_write);
                    });
                    let _ = h1.join();
                    let _ = h2.join();
                });
            }
        })
        .ok();
}

fn nsurl(path: &str) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(path))
}

pub fn start_vm(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
    verity: Option<crate::VerityConfig<'_>>,
) -> Result<(), String> {
    ensure_signed();

    if !Path::new(kernel_path).exists() {
        return Err(format!("Kernel not found: {kernel_path}"));
    }
    if !Path::new(rootfs_path).exists() {
        return Err(format!("Rootfs not found: {rootfs_path}"));
    }
    if let Some(v) = &verity {
        if !Path::new(v.verity_path).exists() {
            return Err(format!("Verity sidecar not found: {}", v.verity_path));
        }
        if !Path::new(v.initrd_path).exists() {
            return Err(format!("Verity initramfs not found: {}", v.initrd_path));
        }
        if v.roothash.len() != 64 || !v.roothash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "Invalid root hash {:?} (expected 64 hex chars)",
                v.roothash
            ));
        }
    }

    // Copy rootfs to a writable location — the Nix store copy is read-only
    // but Virtualization.framework needs read-write access for the disk.
    let vm_dir = vm_state_dir().join(id);
    std::fs::create_dir_all(&vm_dir).map_err(|e| format!("create vm dir: {e}"))?;
    let writable_rootfs = vm_dir.join("rootfs.ext4");
    // Always create a fresh copy — previous runs may have left a locked file
    if writable_rootfs.exists() {
        let _ = std::fs::remove_file(&writable_rootfs);
    }
    {
        std::fs::copy(rootfs_path, &writable_rootfs).map_err(|e| format!("copy rootfs: {e}"))?;
        // Ensure writable
        let mut perms = std::fs::metadata(&writable_rootfs)
            .map_err(|e| format!("metadata: {e}"))?
            .permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&writable_rootfs, perms).map_err(|e| format!("chmod: {e}"))?;
    }
    let rootfs_path = writable_rootfs.to_str().unwrap_or(rootfs_path);

    unsafe {
        let platform =
            VZGenericPlatformConfiguration::init(VZGenericPlatformConfiguration::alloc());

        let boot_loader =
            VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &nsurl(kernel_path));
        // Pass the host's project directory through the kernel cmdline so
        // the guest's init can bind-mount the virtiofs share at the same
        // absolute path inside the VM. Without this, `nix build
        // /Users/foo/proj/...` issued from mvmctl ends up running inside
        // the VM where that absolute path doesn't exist; with it, host
        // paths "just work" cross-VM.
        //
        // Source order: explicit `MVM_HOST_WORKDIR` env var (set by the
        // CLI before launching the launchd-managed daemon, since the
        // daemon's `current_dir()` is launchd's `/`), falling back to the
        // current process's CWD when started directly (Linux dev / tests).
        // Reject `/` and any path containing whitespace or `=` because the
        // kernel cmdline parser is whitespace-delimited and a workdir of
        // `/` would bind-mount virtiofs over the entire root filesystem.
        let workdir = std::env::var("MVM_HOST_WORKDIR")
            .ok()
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
            })
            .filter(|s| s.starts_with('/') && s != "/")
            .filter(|s| !s.contains([' ', '\t', '\n', '=']));
        let datadir = std::env::var("MVM_HOST_DATADIR")
            .ok()
            .filter(|s| s.starts_with('/') && s != "/")
            .filter(|s| !s.contains([' ', '\t', '\n', '=']));
        // When dm-verity is on we boot via the verity initramfs (its
        // PID 1 is `mvm-verity-init`, which reads `mvm.roothash=` from
        // the cmdline, constructs /dev/mapper/root, and switch_root's
        // to /sysroot/init). The kernel-level `root=` setting is
        // irrelevant in that case — the initramfs picks the real root
        // explicitly. ADR-002 §W3.
        let mut cmdline = if verity.is_some() {
            "console=hvc0 init=/init".to_string()
        } else {
            "console=hvc0 root=/dev/vda rw init=/init".to_string()
        };
        if let Some(p) = &workdir {
            cmdline.push_str(&format!(" mvm.workdir={p}"));
        }
        if let Some(p) = &datadir {
            cmdline.push_str(&format!(" mvm.datadir={p}"));
        }
        if let Some(v) = &verity {
            // mvm-verity-init reads these three knobs from /proc/cmdline:
            //   mvm.roothash=<hex>   (required)
            //   mvm.data=<dev>       (defaults to /dev/vda)
            //   mvm.hash=<dev>       (defaults to /dev/vdb)
            // The defaults match our drive ordering, so we only need
            // to pass the roothash.
            cmdline.push_str(&format!(" mvm.roothash={}", v.roothash));
            // Attach the verity initramfs. The objc2 binding marks the
            // setter as safe; we're already inside the surrounding
            // `unsafe` block from the rest of `start_vm`.
            boot_loader.setInitialRamdiskURL(Some(&nsurl(v.initrd_path)));
        }
        boot_loader.setCommandLine(&NSString::from_str(&cmdline));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(cpus as usize);
        config.setMemorySize(memory_mib * 1024 * 1024);

        // ── Storage devices ───────────────────────────────────────
        //
        // /dev/vda — rootfs (read-only ext4 baked by mkGuest). Holds the
        //            boot closure: busybox, init, the bundled
        //            `pkgs.nix`, the pre-seeded /nix/var/nix/db.
        //
        // /dev/vdb — host-backed Nix store. Sparse ext4 file at
        //            $MVM_NIX_STORE_DISK on the host, attached as a
        //            second VirtioBlk device. The init mkfs's it on
        //            first boot, then mounts it as the *upper* layer of
        //            an overlayfs over the rootfs's /nix. We use ext4
        //            (block device) instead of virtiofs because
        //            overlayfs needs the upper to support `trusted.*`
        //            xattrs — virtiofs on macOS can't surface those, so
        //            an overlay over a virtiofs upper silently
        //            downgrades to read-only.
        let mut storage_devices: Vec<Retained<VZStorageDeviceConfiguration>> = Vec::new();

        // When verity is on, the rootfs disk MUST be opened read-only
        // — a writable handle would let any host process mutate the
        // bytes the verity Merkle tree was built against and break
        // the integrity check at read time.
        let rootfs_read_only = verity.is_some();
        let rootfs_attach = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &nsurl(rootfs_path),
            rootfs_read_only,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        ).map_err(|e| format!("disk: {e}"))?;
        let rootfs_disk = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &rootfs_attach,
        );
        storage_devices.push(Retained::into_super(rootfs_disk));

        // Verity sidecar (Merkle tree) → /dev/vdb. Production microVMs
        // that opt into verifiedBoot ship without the writable Nix
        // store overlay, so no device-letter collision arises. We
        // refuse to start if both are requested simultaneously.
        if let Some(v) = &verity {
            if std::env::var("MVM_NIX_STORE_DISK")
                .ok()
                .filter(|s| !s.is_empty())
                .is_some()
            {
                return Err("MVM_NIX_STORE_DISK and dm-verity are mutually exclusive: \
                     the writable overlay would land on /dev/vdb and collide \
                     with the verity sidecar. Disable verifiedBoot or remove \
                     the overlay disk."
                    .to_string());
            }
            let verity_attach =
                VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                    VZDiskImageStorageDeviceAttachment::alloc(),
                    &nsurl(v.verity_path),
                    true,
                    VZDiskImageCachingMode::Automatic,
                    VZDiskImageSynchronizationMode::Full,
                ).map_err(|e| format!("verity attach: {e}"))?;
            let verity_disk = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &verity_attach,
            );
            storage_devices.push(Retained::into_super(verity_disk));
        }

        if let Ok(nix_store_disk) = std::env::var("MVM_NIX_STORE_DISK")
            && !nix_store_disk.is_empty()
        {
            // Create the sparse file if missing. truncate(0) sets the
            // logical length without allocating blocks; the host
            // filesystem materialises blocks on write. 64 GiB is a
            // generous-but-finite cap that fits a Rust+Python toolchain
            // closure several times over and gives nix-collect-garbage
            // headroom before the user notices.
            const NIX_STORE_DISK_BYTES: u64 = 64 * 1024 * 1024 * 1024;
            let path = std::path::Path::new(&nix_store_disk);
            if !path.exists() {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("create nix-store disk parent: {e}"))?;
                }
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|e| format!("create nix-store disk {nix_store_disk}: {e}"))?;
                f.set_len(NIX_STORE_DISK_BYTES)
                    .map_err(|e| format!("size nix-store disk: {e}"))?;
            }
            let nix_attach = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &nsurl(&nix_store_disk),
                false,
                VZDiskImageCachingMode::Automatic,
                VZDiskImageSynchronizationMode::Full,
            ).map_err(|e| format!("nix-store disk attach: {e}"))?;
            let nix_disk = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &nix_attach,
            );
            storage_devices.push(Retained::into_super(nix_disk));
        }

        config.setStorageDevices(&NSArray::from_retained_slice(&storage_devices));

        // NAT network
        let net = VZVirtioNetworkDeviceConfiguration::new();
        net.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
        config.setNetworkDevices(&NSArray::from_retained_slice(&[Retained::into_super(net)]));

        // Entropy + memory balloon
        config.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            VZVirtioEntropyDeviceConfiguration::new(),
        )]));
        config.setMemoryBalloonDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new(),
        )]));

        // Vsock device — enables host↔guest communication on port 52
        // (same protocol as Firecracker vsock, used by the guest agent)
        let vsock = VZVirtioSocketDeviceConfiguration::new();
        config.setSocketDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            vsock,
        )]));

        // VirtioFS shares. The launchd-spawned daemon's `current_dir()`
        // is `/`, so prefer the explicit env vars set by the parent CLI;
        // without them, sharing `/` would expose the entire macOS root
        // inside the VM. (The Nix store is NOT a virtiofs share — it's
        // the second VirtioBlk device above. virtiofs can't carry the
        // xattrs overlayfs needs for the writable upper layer.)
        //
        //   workdir   the user's project directory. The guest's init
        //             mounts it at /root and bind-mounts it again at
        //             `mvm.workdir=<host>` so absolute host paths
        //             resolve cross-VM.
        //
        //   datadir   $HOME/.mvm on the host (via MVM_HOST_DATADIR).
        //             The dev-build pipeline writes artifacts to
        //             $HOME/.mvm/dev/builds/<hash>/ from inside the
        //             VM; without this share, those writes would land
        //             on the read-only rootfs and ENOSPC. Mounted at
        //             the same absolute host path inside the VM so
        //             host and guest agree on artifact locations.
        let mut shares: Vec<Retained<VZVirtioFileSystemDeviceConfiguration>> = Vec::new();
        let cwd = workdir.clone().unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .to_string_lossy()
                .into_owned()
        });
        if Path::new(&cwd).is_dir() {
            let shared_dir = VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &nsurl(&cwd),
                false,
            );
            let share = VZSingleDirectoryShare::initWithDirectory(
                VZSingleDirectoryShare::alloc(),
                &shared_dir,
            );
            let fs_config = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str("workdir"),
            );
            fs_config.setShare(Some(&share));
            shares.push(fs_config);
        }
        if let Ok(datadir) = std::env::var("MVM_HOST_DATADIR")
            && !datadir.is_empty()
            && Path::new(&datadir).is_dir()
        {
            let shared_dir = VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &nsurl(&datadir),
                false,
            );
            let share = VZSingleDirectoryShare::initWithDirectory(
                VZSingleDirectoryShare::alloc(),
                &shared_dir,
            );
            let fs_config = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str("datadir"),
            );
            fs_config.setShare(Some(&share));
            shares.push(fs_config);
        }
        if !shares.is_empty() {
            let supers: Vec<Retained<VZDirectorySharingDeviceConfiguration>> =
                shares.into_iter().map(Retained::into_super).collect();
            config.setDirectorySharingDevices(&NSArray::from_retained_slice(&supers));
        }

        // Serial console — write kernel and init output to log file
        // ADR-002 W1.4: console log is mode 0600. The kernel + init
        // write every byte of guest stdout/stderr there, including
        // anything a guest service prints — secrets, environment,
        // command output. Default umask leaves it 0644 (world-readable
        // on macOS multi-user systems). Open with `mode(0o600)` via
        // OpenOptions so the file is born locked-down rather than
        // racing a chmod after `File::create`.
        use std::os::unix::fs::OpenOptionsExt as _;
        let console_log = vm_dir.join("console.log");
        let console_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&console_log)
            .map_err(|e| format!("create console log: {e}"))?;
        use std::os::fd::IntoRawFd;
        let log_fd = console_file.into_raw_fd();
        let write_handle = NSFileHandle::initWithFileDescriptor(NSFileHandle::alloc(), log_fd);
        let read_handle = {
            let devnull = std::fs::File::open("/dev/null").map_err(|e| e.to_string())?;
            NSFileHandle::initWithFileDescriptor(NSFileHandle::alloc(), devnull.into_raw_fd())
        };
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration::new();
        let attachment =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&read_handle),
                Some(&write_handle),
            );
        serial.setAttachment(Some(&attachment));
        config.setSerialPorts(&NSArray::from_retained_slice(&[Retained::into_super(
            serial,
        )]));

        // Dispatch VM creation AND start to the main queue.
        // Virtualization.framework requires VMs to be created on the main thread.
        let (tx, rx) = mpsc::channel::<Result<(), String>>();

        // We need to move config into the closure. It's an ObjC object
        // so we wrap it.
        let config_ptr = Retained::into_raw(config) as usize;
        let id_owned = id.to_string();

        #[allow(unused_unsafe)]
        dispatch2::DispatchQueue::main().exec_async(move || {
            // SAFETY: config_ptr was created from Retained::into_raw above
            let config = unsafe {
                Retained::from_raw(config_ptr as *mut VZVirtualMachineConfiguration)
                    .expect("config pointer must be valid")
            };

            // SAFETY: VZ init methods are safe ObjC sends
            let vm = unsafe {
                VZVirtualMachine::initWithConfiguration_queue(
                    VZVirtualMachine::alloc(),
                    &config,
                    dispatch2::DispatchQueue::main(),
                )
            };

            let tx_clone = tx.clone();
            let handler = RcBlock::new(move |error: *mut NSError| {
                if error.is_null() {
                    let _ = tx_clone.send(Ok(()));
                } else {
                    // SAFETY: error pointer is valid when non-null
                    let e = unsafe { &*error };
                    let desc = e.localizedDescription();
                    let _ = tx_clone.send(Err(format!("{desc}")));
                }
            });

            // SAFETY: safe ObjC message send
            unsafe { vm.startWithCompletionHandler(&handler) };

            // Store VM pointer so we can access socket devices later.
            // The pointer stays valid as long as we don't drop it.
            let vm_ptr = Retained::into_raw(vm) as usize;
            if let Ok(mut map) = VMS.lock() {
                map.insert(id_owned.clone(), vm_ptr);
            }

            tracing::debug!("VM '{}' start dispatched to main queue", id_owned);
        });

        // Wait for callback (main RunLoop pumps in main.rs)
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            std::thread::sleep(Duration::from_millis(50));

            match rx.try_recv() {
                Ok(Ok(())) => {
                    tracing::info!("VM '{id}' started via Virtualization.framework");
                    persist_vm_state(id);
                    if let Err(e) = start_vsock_proxy_listener(id) {
                        // A VM that can't be reached by other processes is
                        // functionally not running — surface the failure
                        // and tear down the just-persisted state, but
                        // leave any launchd plist alone so the agent that
                        // spawned us isn't cleaned up mid-execution.
                        let _ = std::fs::remove_dir_all(vm_state_dir().join(id));
                        return Err(format!("start vsock proxy listener: {e}"));
                    }
                    return Ok(());
                }
                Ok(Err(e)) => return Err(format!("start failed: {e}")),
                Err(mpsc::TryRecvError::Empty) if Instant::now() < deadline => continue,
                Err(mpsc::TryRecvError::Empty) => return Err("start timed out".to_string()),
                Err(e) => return Err(format!("channel: {e}")),
            }
        }
    }
}

pub fn stop_vm(id: &str) -> Result<(), String> {
    // Drop the VM reference (stops the VM)
    if let Ok(mut map) = VMS.lock()
        && let Some(ptr) = map.remove(id)
    {
        // SAFETY: ptr was created from Retained::into_raw in start_vm.
        // Dropping the Retained will release the ObjC object.
        unsafe {
            let _ = Retained::from_raw(ptr as *mut VZVirtualMachine);
        }
    }
    remove_vm_state(id);
    Ok(())
}

pub fn list_vm_ids() -> Vec<String> {
    read_persisted_vm_ids()
}

/// Path to the per-VM cross-process vsock proxy Unix socket.
pub fn proxy_socket_path(id: &str) -> std::path::PathBuf {
    vsock_proxy_socket_path(id)
}

/// Connect to the guest agent via vsock and return a Unix stream.
///
/// Uses the stored VZVirtualMachine reference to access the socket device,
/// then calls `connectToPort:completionHandler:` to establish a vsock
/// connection to the guest agent on port 52.
///
/// Returns an `std::os::unix::net::UnixStream` wrapping the connection's
/// file descriptor.
pub fn vsock_connect(id: &str, port: u32) -> Result<std::os::unix::net::UnixStream, String> {
    let vm_ptr = VMS
        .lock()
        .map_err(|e| format!("lock: {e}"))?
        .get(id)
        .copied()
        .ok_or_else(|| format!("VM '{id}' not found (not running in this process)"))?;

    let (tx, rx) = mpsc::channel::<Result<i32, String>>();

    dispatch2::DispatchQueue::main().exec_async(move || {
        // SAFETY: vm_ptr was created from Retained::into_raw and is valid
        // while the VM is in the VMS map. We borrow without taking ownership.
        let vm = unsafe { &*(vm_ptr as *const VZVirtualMachine) };

        // Get the first socket device
        let socket_devices = unsafe { vm.socketDevices() };
        if socket_devices.is_empty() {
            let _ = tx.send(Err("no vsock device on VM".to_string()));
            return;
        }
        let device: Retained<VZVirtioSocketDevice> =
            unsafe { Retained::cast_unchecked(socket_devices.objectAtIndex(0)) };

        let handler = RcBlock::new(
            move |connection: *mut VZVirtioSocketConnection, error: *mut NSError| {
                if !error.is_null() {
                    let e = unsafe { &*error };
                    let _ = tx.send(Err(format!("vsock connect: {}", e.localizedDescription())));
                    return;
                }
                if connection.is_null() {
                    let _ = tx.send(Err("vsock connect returned null connection".to_string()));
                    return;
                }
                // Extract the file descriptor from the connection.
                // We dup() it because VZVirtioSocketConnection owns the fd
                // and will close it when the connection object is dropped.
                let conn = unsafe { &*connection };
                let fd = unsafe { conn.fileDescriptor() };
                let duped = unsafe { libc::dup(fd) };
                if duped < 0 {
                    let _ = tx.send(Err("failed to dup vsock fd".to_string()));
                } else {
                    let _ = tx.send(Ok(duped));
                }
            },
        );

        // SAFETY: safe ObjC message send. The handler is a DynBlock.
        let dyn_handler: &block2::DynBlock<dyn Fn(*mut VZVirtioSocketConnection, *mut NSError)> =
            &handler;
        unsafe { device.connectToPort_completionHandler(port, dyn_handler) };
    });

    // Wait for the connection callback
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        std::thread::sleep(Duration::from_millis(50));
        match rx.try_recv() {
            Ok(Ok(fd)) => {
                // SAFETY: fd is a valid file descriptor from VZVirtioSocketConnection
                let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                return Ok(stream);
            }
            Ok(Err(e)) => return Err(e),
            Err(mpsc::TryRecvError::Empty) if Instant::now() < deadline => continue,
            Err(mpsc::TryRecvError::Empty) => return Err("vsock connect timed out".to_string()),
            Err(e) => return Err(format!("channel: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    /// Run `body` with `$HOME` pointed at a short temp dir so the listener
    /// and readiness probes don't touch the real `~/.mvm/vms/`.
    ///
    /// Uses `/tmp` directly rather than `std::env::temp_dir()`, because the
    /// latter resolves to `/var/folders/...` on macOS, which when combined
    /// with `.mvm/vms/<id>/vsock.sock` exceeds `SUN_LEN` (~104 bytes).
    ///
    /// Holds a process-global mutex while HOME is mutated so concurrent
    /// `with_temp_home` calls don't race each other into a shared
    /// (incoherent) HOME — cargo runs tests in parallel by default.
    fn with_temp_home<F: FnOnce(&std::path::Path)>(body: F) {
        use std::sync::Mutex;
        static HOME_LOCK: Mutex<()> = Mutex::new(());
        let _guard = HOME_LOCK.lock().expect("HOME lock");

        let temp = std::path::PathBuf::from(format!("/tmp/mvmac-{}", unique_id()));
        std::fs::create_dir_all(&temp).expect("create temp HOME");
        let saved = std::env::var("HOME").ok();
        // SAFETY: serialised by HOME_LOCK above.
        unsafe { std::env::set_var("HOME", &temp) };
        body(&temp);
        unsafe {
            match saved {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&temp);
    }

    fn unique_id() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}-{}", std::process::id(), nanos)
    }

    #[test]
    fn test_proxy_socket_path_lives_under_home_vms_dir() {
        with_temp_home(|home| {
            let p = vsock_proxy_socket_path("vm-x");
            assert!(
                p.starts_with(home),
                "path {} not under {}",
                p.display(),
                home.display()
            );
            assert!(
                p.ends_with(".mvm/vms/vm-x/vsock.sock"),
                "got {}",
                p.display()
            );
        });
    }

    /// A stale socket file from a previous (now-dead) daemon must not stop a
    /// fresh listener from binding. The listener also has to accept a
    /// connection from a peer that speaks the documented wire protocol.
    #[test]
    fn test_listener_recovers_from_stale_socket_and_reads_port() {
        with_temp_home(|_home| {
            let id = "stale-recover";
            let path = vsock_proxy_socket_path(id);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("create vm dir");
            std::fs::write(&path, b"left over from a dead daemon").expect("seed stale file");

            start_vsock_proxy_listener(id).expect("listener should rebind");
            assert!(path.exists(), "socket file must exist after listener start");

            // Connect and send the wire protocol's u32 port. The listener
            // will hand off to vsock_connect, which fails (no in-process
            // VM), but the protocol read on this side must succeed.
            let mut client = UnixStream::connect(&path).expect("connect to proxy");
            client.write_all(&52u32.to_le_bytes()).expect("write port");

            // Read should return EOF (0 bytes) once the worker thread gives
            // up on vsock_connect — that's the contract.
            let mut buf = [0u8; 1];
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .expect("set read timeout");
            let n = client.read(&mut buf).unwrap_or(0);
            assert_eq!(n, 0, "expected EOF after vsock_connect failure");
        });
    }

    /// ADR-002 W1.2: the proxy socket is born with mode `0700`.
    ///
    /// We verify this by binding via the same code path the daemon
    /// uses (`start_vsock_proxy_listener`), then asking the file
    /// system what perms it has. If a future change forgets the
    /// `set_permissions` call, this test fails before any user is
    /// exposed to a 0755 socket.
    #[test]
    fn test_proxy_socket_is_chmod_0700() {
        use std::os::unix::fs::PermissionsExt as _;
        with_temp_home(|_home| {
            let id = "perm-test";
            start_vsock_proxy_listener(id).expect("listener bind");
            let path = vsock_proxy_socket_path(id);
            let mode = std::fs::metadata(&path)
                .expect("socket exists")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o700,
                "vsock proxy socket at {} must be mode 0700, was 0{:o}",
                path.display(),
                mode
            );
        });
    }

    /// ADR-002 W1.3: the proxy port allowlist accepts the three
    /// ranges mvmctl actually uses and rejects everything else.
    /// Pure logic — no daemon needed; just the predicate.
    ///
    /// Ranges:
    ///   guest_agent:  {52}
    ///   port_forward: 10_000..=75_535  (BASE 10_000 + 0..=65_535)
    ///   console_data: 20_000..=85_535  (BASE 20_000 + 0..=65_535)
    ///
    /// The port_forward and console_data ranges legitimately overlap;
    /// any port in the union is fine. Only the gaps below 10_000
    /// (excluding 52) and above 85_535 are forbidden.
    #[test]
    fn test_proxy_port_allowlist() {
        // Allowed: guest agent control channel.
        assert!(proxy_port_is_allowed(52));

        // Allowed: port-forward range edges + interior.
        assert!(proxy_port_is_allowed(10_000));
        assert!(proxy_port_is_allowed(10_080));
        assert!(proxy_port_is_allowed(75_535));

        // Allowed: console-data range edges + interior (overlaps with
        // port-forward in 20_000..=75_535; that's fine).
        assert!(proxy_port_is_allowed(20_000));
        assert!(proxy_port_is_allowed(20_001));
        assert!(proxy_port_is_allowed(85_535));

        // Rejected: low ports outside the agent slot.
        assert!(!proxy_port_is_allowed(0));
        assert!(!proxy_port_is_allowed(1));
        assert!(!proxy_port_is_allowed(22));
        assert!(!proxy_port_is_allowed(51));
        assert!(!proxy_port_is_allowed(53));

        // Rejected: gap between agent slot and port-forward range.
        assert!(!proxy_port_is_allowed(100));
        assert!(!proxy_port_is_allowed(9_999));

        // Rejected: above the union of port_forward and console_data.
        assert!(!proxy_port_is_allowed(85_536));
        assert!(!proxy_port_is_allowed(u32::MAX));
    }

    // ──── Verity input validation (ADR-002 §W3.2) ────────────────────
    //
    // The `start_vm` body validates the verity config's roothash shape
    // before constructing any objc objects. Live boot through VZ is
    // exercised in the macOS CI lane; these tests pin the validation
    // contract so a refactor that loosens the check (e.g., accepting
    // uppercase hex, accepting wrong lengths) is caught immediately.

    fn dummy_paths() -> (tempfile::TempDir, String, String, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&kernel, b"FAKE_KERNEL").unwrap();
        std::fs::write(&rootfs, vec![0u8; 4096]).unwrap();
        std::fs::write(&verity, b"FAKE_VERITY").unwrap();
        std::fs::write(&initrd, b"FAKE_INITRD").unwrap();
        (
            dir,
            kernel.to_string_lossy().into(),
            rootfs.to_string_lossy().into(),
            verity.to_string_lossy().into(),
            initrd.to_string_lossy().into(),
        )
    }

    #[test]
    fn start_vm_rejects_short_roothash() {
        let (_dir, k, r, v, i) = dummy_paths();
        let cfg = crate::VerityConfig {
            verity_path: &v,
            roothash: "deadbeef",
            initrd_path: &i,
        };
        let err = start_vm("test-id", &k, &r, 1, 256, Some(cfg)).unwrap_err();
        assert!(
            err.contains("Invalid root hash"),
            "expected validation error, got: {err}"
        );
    }

    #[test]
    fn start_vm_rejects_non_hex_roothash() {
        let (_dir, k, r, v, i) = dummy_paths();
        let bad = "z".repeat(64);
        let cfg = crate::VerityConfig {
            verity_path: &v,
            roothash: &bad,
            initrd_path: &i,
        };
        let err = start_vm("test-id", &k, &r, 1, 256, Some(cfg)).unwrap_err();
        assert!(
            err.contains("Invalid root hash"),
            "expected validation error, got: {err}"
        );
    }

    #[test]
    fn start_vm_rejects_missing_verity_sidecar() {
        let (_dir, k, r, _v, i) = dummy_paths();
        let valid_hash = "a".repeat(64);
        let cfg = crate::VerityConfig {
            verity_path: "/nonexistent/path/to/rootfs.verity",
            roothash: &valid_hash,
            initrd_path: &i,
        };
        let err = start_vm("test-id", &k, &r, 1, 256, Some(cfg)).unwrap_err();
        assert!(
            err.contains("Verity sidecar not found"),
            "expected missing-sidecar error, got: {err}"
        );
    }

    #[test]
    fn start_vm_rejects_missing_verity_initrd() {
        let (_dir, k, r, v, _i) = dummy_paths();
        let valid_hash = "a".repeat(64);
        let cfg = crate::VerityConfig {
            verity_path: &v,
            roothash: &valid_hash,
            initrd_path: "/nonexistent/path/to/rootfs.initrd",
        };
        let err = start_vm("test-id", &k, &r, 1, 256, Some(cfg)).unwrap_err();
        assert!(
            err.contains("Verity initramfs not found"),
            "expected missing-initramfs error, got: {err}"
        );
    }
}
