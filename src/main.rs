use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> anyhow::Result<()> {
    // On macOS, Virtualization.framework requires the main thread to pump
    // NSRunLoop for VM lifecycle callbacks. Run the CLI on a background
    // thread and keep the main thread available for the RunLoop.
    #[cfg(target_os = "macos")]
    {
        main_macos()
    }

    #[cfg(not(target_os = "macos"))]
    {
        mvm_cli::run()
    }
}

#[cfg(target_os = "macos")]
fn main_macos() -> anyhow::Result<()> {
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();

    thread::Builder::new()
        .name("mvm-cli".into())
        .spawn(move || {
            let result = mvm_cli::run();
            let _ = tx.send(result);
        })
        .expect("Failed to spawn CLI thread");

    // Pump the main RunLoop until the CLI thread finishes.
    // This allows Virtualization.framework callbacks to fire on the
    // main dispatch queue.
    loop {
        // Process RunLoop events (VM callbacks arrive here)
        let _running = unsafe {
            let pool = objc2_foundation::NSAutoreleasePool::new();
            let ran = objc2_foundation::NSRunLoop::mainRunLoop().runMode_beforeDate(
                objc2_foundation::NSDefaultRunLoopMode,
                &objc2_foundation::NSDate::dateWithTimeIntervalSinceNow(0.1),
            );
            drop(pool);
            ran
        };

        // Check if CLI thread is done
        match rx.try_recv() {
            Ok(result) => return result,
            Err(mpsc::TryRecvError::Empty) => continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                anyhow::bail!("CLI thread exited unexpectedly");
            }
        }
    }
}
