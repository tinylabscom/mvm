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

/// Remove VM state from disk.
fn remove_vm_state(id: &str) {
    let dir = vm_state_dir().join(id);
    let _ = std::fs::remove_dir_all(dir);
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
    if !Path::new(kernel_path).exists() {
        return Err(format!("Kernel not found: {kernel_path}"));
    }
    if !Path::new(rootfs_path).exists() {
        return Err(format!("Rootfs not found: {rootfs_path}"));
    }

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
