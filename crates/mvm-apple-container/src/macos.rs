//! macOS Virtualization.framework VM lifecycle using objc2-virtualization.
//!
//! VMs are created from the CLI thread with callbacks on the main dispatch
//! queue. The main thread pumps NSRunLoop (see main.rs) to deliver callbacks.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::*;
use objc2_virtualization::*;

const START_TIMEOUT: Duration = Duration::from_secs(30);

/// In-process VM handle tracking.
static VM_IDS: std::sync::LazyLock<Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

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
/// Takes the original CLI args (minus -d) and replays them via launchd.
/// The agent runs as a proper macOS user service with its own RunLoop.
pub fn install_launchd_agent(id: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let label = launchd_label(id);
    let plist_path = launchd_plist_path(id);
    let log_dir = vm_state_dir().join(id);
    std::fs::create_dir_all(&log_dir).map_err(|e| format!("mkdir: {e}"))?;

    // Replay the original args without -d/--detach
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "-d" && a != "--detach")
        .collect();

    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{a}</string>"))
        .collect::<Vec<_>>()
        .join("\n");

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
{args_xml}
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MVM_SIGNED</key>
        <string>1</string>
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
    );

    // Write plist
    let agents_dir = plist_path.parent().expect("plist path must have parent");
    std::fs::create_dir_all(agents_dir).map_err(|e| format!("mkdir LaunchAgents: {e}"))?;
    std::fs::write(&plist_path, &plist).map_err(|e| format!("write plist: {e}"))?;

    // Load agent
    let output = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("launchctl load: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl load failed: {stderr}"));
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
            "console=hvc0 root=/dev/vda rw init=/init quiet",
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

            // Leak VM to keep it alive
            std::mem::forget(vm);

            tracing::debug!("VM '{}' start dispatched to main queue", id_owned);
        });

        // Wait for callback (main RunLoop pumps in main.rs)
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            std::thread::sleep(Duration::from_millis(50));

            match rx.try_recv() {
                Ok(Ok(())) => {
                    tracing::info!("VM '{id}' started via Virtualization.framework");
                    VM_IDS
                        .lock()
                        .map_err(|e| e.to_string())?
                        .insert(id.to_string());
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
    VM_IDS.lock().map_err(|e| e.to_string())?.remove(id);
    remove_vm_state(id);
    Ok(())
}

pub fn list_vm_ids() -> Vec<String> {
    read_persisted_vm_ids()
}
