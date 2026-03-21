//! macOS Virtualization.framework VM lifecycle using objc2-virtualization.
//!
//! All VZ operations run on a dedicated background thread that owns a
//! RunLoop. The caller communicates via channels — no VZ objects cross
//! thread boundaries.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::*;
use objc2_virtualization::*;

const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Track running VM names (VZ objects stay on the VM thread).
static VM_IDS: std::sync::LazyLock<Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

fn nsurl(path: &str) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(path))
}

/// Start a VM on a dedicated thread.
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

    let id = id.to_string();
    let kernel = kernel_path.to_string();
    let rootfs = rootfs_path.to_string();

    let (tx, rx) = mpsc::channel::<Result<(), String>>();

    // Spawn a dedicated thread for this VM — VZ objects must stay on one thread.
    let id_clone = id.clone();
    thread::Builder::new()
        .name(format!("mvm-vz-{id}"))
        .spawn(move || {
            vm_thread_main(&id_clone, &kernel, &rootfs, cpus, memory_mib, tx);
        })
        .map_err(|e| format!("spawn VM thread: {e}"))?;

    // Wait for the VM to start (or fail)
    rx.recv().map_err(|e| format!("VM thread error: {e}"))?
}

/// VM thread main — creates and starts the VM, sends result on channel,
/// then pumps the RunLoop to keep the VM alive until stop is requested.
fn vm_thread_main(
    id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    cpus: u32,
    memory_mib: u64,
    started_tx: mpsc::Sender<Result<(), String>>,
) {
    unsafe {
        // Build configuration
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
        let disk_attach = match VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &nsurl(rootfs_path),
            false,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        ) {
            Ok(a) => a,
            Err(e) => {
                let _ = started_tx.send(Err(format!("disk: {e}")));
                return;
            }
        };

        let disk = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attach,
        );
        config.setStorageDevices(&NSArray::from_retained_slice(&[Retained::into_super(disk)]));

        // NAT network
        let net = VZVirtioNetworkDeviceConfiguration::new();
        net.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
        config.setNetworkDevices(&NSArray::from_retained_slice(&[Retained::into_super(net)]));

        // Entropy
        config.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            VZVirtioEntropyDeviceConfiguration::new(),
        )]));

        // Memory balloon
        config.setMemoryBalloonDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new(),
        )]));

        // Create VM with a dispatch queue for this thread.
        // Virtualization.framework requires a dispatch queue for callbacks.
        // Use the main dispatch queue — Virtualization.framework delivers
        // callbacks on this queue, and we pump mainRunLoop to process them.
        let vm = VZVirtualMachine::initWithConfiguration_queue(
            VZVirtualMachine::alloc(),
            &config,
            dispatch2::DispatchQueue::main(),
        );

        // Start
        let (start_tx, start_rx) = mpsc::channel::<Result<(), String>>();
        let handler = RcBlock::new(move |error: *mut NSError| {
            if error.is_null() {
                let _ = start_tx.send(Ok(()));
            } else {
                let e = &*error;
                let _ = start_tx.send(Err(format!("{}", e.localizedDescription())));
            }
        });
        vm.startWithCompletionHandler(&handler);

        // Pump RunLoop until started
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.05),
            );

            match start_rx.try_recv() {
                Ok(Ok(())) => {
                    tracing::info!("VM '{id}' started");
                    if let Ok(mut ids) = VM_IDS.lock() {
                        ids.insert(id.to_string());
                    }
                    let _ = started_tx.send(Ok(()));
                    break;
                }
                Ok(Err(e)) => {
                    let _ = started_tx.send(Err(format!("start failed: {e}")));
                    return;
                }
                Err(mpsc::TryRecvError::Empty) if Instant::now() < deadline => continue,
                Err(mpsc::TryRecvError::Empty) => {
                    let _ = started_tx.send(Err("start timed out".to_string()));
                    return;
                }
                Err(e) => {
                    let _ = started_tx.send(Err(format!("channel: {e}")));
                    return;
                }
            }
        }

        // Keep pumping RunLoop to keep the VM alive.
        // The VM runs until the guest shuts down or we're interrupted.
        loop {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(1.0),
            );

            // Check if we've been removed from the registry (stop was called)
            if !VM_IDS.lock().map(|ids| ids.contains(id)).unwrap_or(false) {
                tracing::info!("VM '{id}' stop requested");
                let (stop_tx, stop_rx) = mpsc::channel::<()>();
                let stop_handler = RcBlock::new(move |_error: *mut NSError| {
                    let _ = stop_tx.send(());
                });
                vm.stopWithCompletionHandler(&stop_handler);

                let stop_deadline = Instant::now() + Duration::from_secs(5);
                while Instant::now() < stop_deadline {
                    NSRunLoop::mainRunLoop().runMode_beforeDate(
                        NSDefaultRunLoopMode,
                        &NSDate::dateWithTimeIntervalSinceNow(0.05),
                    );
                    if stop_rx.try_recv().is_ok() {
                        break;
                    }
                }
                tracing::info!("VM '{id}' stopped");
                break;
            }
        }
    }
}

/// Stop a running VM by removing it from the registry.
/// The VM thread detects this and calls stopWithCompletionHandler.
pub fn stop_vm(id: &str) -> Result<(), String> {
    let removed = VM_IDS.lock().map_err(|e| e.to_string())?.remove(id);

    if removed {
        Ok(())
    } else {
        Err(format!("VM '{id}' not found"))
    }
}

/// List running VM IDs.
pub fn list_vm_ids() -> Vec<String> {
    VM_IDS
        .lock()
        .map(|ids| ids.iter().cloned().collect())
        .unwrap_or_default()
}
