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
pub fn ensure_signed() {
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

    let ok = std::process::Command::new("codesign")
        .args(["--sign", "-", "--force", "--entitlements"])
        .arg(&ent_path)
        .arg(exe_str)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let _ = std::fs::remove_file(&ent_path);

    if ok {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&exe)
            .args(std::env::args_os().skip(1))
            .env("MVM_SIGNED", "1")
            .exec();
        tracing::error!("Re-exec after signing failed: {err}");
        std::process::exit(1);
    }
}

/// Discover the guest's IP by scanning ARP for recent entries on bridge interfaces.
/// Waits up to `timeout` for a new IP to appear.
pub fn discover_guest_ip(timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(output) = std::process::Command::new("arp").arg("-a").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // Look for non-permanent, non-incomplete entries on bridge interfaces
                if line.contains("bridge")
                    && !line.contains("permanent")
                    && !line.contains("incomplete")
                    && !line.contains("ff:ff:ff:ff")
                {
                    // Extract IP: "? (192.168.64.9) at ba:b3:..."
                    if let Some(start) = line.find('(')
                        && let Some(end) = line.find(')')
                    {
                        let ip = &line[start + 1..end];
                        // Skip bridge gateway IPs (end in .0 or .1)
                        if !ip.ends_with(".0") && !ip.ends_with(".1") {
                            return Some(ip.to_string());
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

/// Start a TCP proxy that forwards localhost:host_port to guest_ip:guest_port.
/// Runs in a background thread. Returns immediately.
pub fn start_port_proxy(host_port: u16, guest_ip: &str, guest_port: u16) {
    use std::net::{TcpListener, TcpStream};

    let target = format!("{guest_ip}:{guest_port}");
    let bind = format!("127.0.0.1:{host_port}");

    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Port proxy bind {bind} failed: {e}");
            return;
        }
    };
    tracing::info!("Port forwarding: localhost:{host_port} → {target}");

    std::thread::Builder::new()
        .name(format!("proxy-{host_port}"))
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                let target = target.clone();
                std::thread::spawn(move || {
                    let Ok(upstream) = TcpStream::connect(&target) else {
                        return;
                    };
                    let downstream = stream;
                    let Ok(mut up_read) = upstream.try_clone() else {
                        return;
                    };
                    let Ok(mut down_write) = downstream.try_clone() else {
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
) -> Result<(), String> {
    ensure_signed();

    if !Path::new(kernel_path).exists() {
        return Err(format!("Kernel not found: {kernel_path}"));
    }
    if !Path::new(rootfs_path).exists() {
        return Err(format!("Rootfs not found: {rootfs_path}"));
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
        boot_loader.setCommandLine(&NSString::from_str(
            "console=hvc0 root=/dev/vda rw init=/init",
        ));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(cpus as usize);
        config.setMemorySize(memory_mib * 1024 * 1024);

        // Rootfs disk
        let disk_attach = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &nsurl(rootfs_path),
            false,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        ).map_err(|e| format!("disk: {e}"))?;

        let disk = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attach,
        );
        config.setStorageDevices(&NSArray::from_retained_slice(&[Retained::into_super(disk)]));

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

        // Serial console — write kernel and init output to log file
        let console_log = vm_dir.join("console.log");
        let console_file =
            std::fs::File::create(&console_log).map_err(|e| format!("create console log: {e}"))?;
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
