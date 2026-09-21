//! The per-VM host GPU endpoint.
//!
//! One of these runs per GPU-enabled guest (spawned by the workload
//! runner, reaped with the VM). It listens on the host end of the guest's
//! GPU vsock channel and serves the guest shim's RPCs against the real
//! driver when one is present, or the deterministic stub otherwise.

use mvm_gpu::server::{parse_listen_addr, run};
use mvm_gpu::{GpuBackend, native, stub};
use std::process::exit;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!(
        "usage: mvm-gpu-endpoint --listen unix:/path|tcp:HOST:PORT|vsock:PORT \\
          --backend auto|native|stub [--vm NAME]"
    );
    exit(2);
}

fn main() {
    let mut listen: Option<String> = None;
    let mut backend_mode = "auto".to_string();
    let mut vm_name: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--backend" => backend_mode = args.next().unwrap_or_else(|| usage()),
            "--vm" => vm_name = args.next(),
            "--help" | "-h" => usage(),
            other => {
                eprintln!("mvm-gpu-endpoint: unknown argument {other:?}");
                usage();
            }
        }
    }
    let Some(listen) = listen else {
        usage();
    };
    let addr = match parse_listen_addr(&listen) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("mvm-gpu-endpoint: {e}");
            exit(2);
        }
    };

    let make_backend: Arc<dyn Fn() -> Box<dyn GpuBackend> + Send + Sync> =
        match backend_mode.as_str() {
            "stub" => Arc::new(|| Box::new(stub::StubBackend::new())),
            "native" => {
                if native::probe().is_none() {
                    eprintln!("mvm-gpu-endpoint: --backend native but no usable driver library");
                    exit(1);
                }
                // Each connection rebuilds from the loaded driver rather than
                // sharing one backend: a shared backend would let two guests
                // share handle tables. cuInit is documented idempotent.
                Arc::new(|| match native::probe() {
                    Some(backend) => Box::new(backend),
                    None => Box::new(stub::StubBackend::new()),
                })
            }
            "auto" => match native::probe() {
                Some(_) => Arc::new(|| match native::probe() {
                    Some(backend) => Box::new(backend),
                    // A driver that vanished between probe and serve answers
                    // as the stub rather than refusing the guest outright.
                    None => Box::new(stub::StubBackend::new()),
                }),
                None => Arc::new(|| Box::new(stub::StubBackend::new())),
            },
            other => {
                eprintln!("mvm-gpu-endpoint: unknown --backend {other:?}");
                exit(2);
            }
        };

    let vm = vm_name.as_deref().unwrap_or("<unnamed>");
    eprintln!("mvm-gpu-endpoint: vm={vm} backend={backend_mode} listening on {addr}");

    // SIGTERM/SIGINT flip the stop flag: the runner reaps this process
    // with the VM, and the flag unblocks the accept loop for a clean exit.
    stop_flag::arm();

    if let Err(e) = run(&addr, move || make_backend(), stop_flag::flag()) {
        eprintln!("mvm-gpu-endpoint: serve {addr}: {e}");
        exit(1);
    }
}

/// One static stop flag + a libc signal arm. Self-contained on purpose:
/// this process is spawned per VM and keeps its dependency surface minimal.
mod stop_flag {
    use std::sync::atomic::{AtomicBool, Ordering};

    static STOP: AtomicBool = AtomicBool::new(false);

    /// Arm SIGINT/SIGTERM to set the flag. Idempotent.
    pub(super) fn arm() {
        // SAFETY: `handler` has the C ABI signal-handler shape; `signal`
        // installs it for the process, and the flag is a 'static atomic.
        unsafe {
            let handler = handler as *const () as libc::sighandler_t;
            libc::signal(libc::SIGINT, handler);
            libc::signal(libc::SIGTERM, handler);
        }
    }

    /// The stop flag the accept loop polls.
    pub(super) fn flag() -> &'static AtomicBool {
        &STOP
    }

    extern "C" fn handler(_sig: i32) {
        STOP.store(true, Ordering::Relaxed);
    }
}
