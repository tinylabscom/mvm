//! The per-VM host GPU endpoint.
//!
//! One of these runs per GPU-enabled guest (spawned by the workload
//! runner, reaped with the VM). It listens on the host end of the guest's
//! GPU vsock channel and serves the guest shim's RPCs against the real
//! driver when one is present, or the deterministic stub otherwise.

use mvm_gpu::server::{parse_listen_addr, run};
use mvm_gpu::{GpuBackend, native, stub};
use std::io;
use std::process::exit;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!(
        "usage: mvm-gpu-endpoint --listen unix:/path|tcp:HOST:PORT|vsock:PORT \\
          --backend auto|native|stub [--device ORDINAL] [--vm NAME]"
    );
    exit(2);
}

fn main() {
    // The workload runner resolves this helper through
    // `mvm_vmm::host::aux_bin::resolve_verified`, which probes the binary
    // for the host-helper contract version before every spawn. Answer
    // before anything else, exactly like the other helpers.
    mvm_vmm::host::helper_contract::exit_with_probe_answer_if_requested("mvm-gpu-endpoint");

    let mut listen: Option<String> = None;
    let mut backend_mode = "auto".to_string();
    let mut device_ordinal: Option<u32> = None;
    let mut vm_name: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next(),
            "--backend" => backend_mode = args.next().unwrap_or_else(|| usage()),
            "--device" => {
                let Some(raw) = args.next() else {
                    usage();
                };
                device_ordinal = match raw.parse() {
                    Ok(ordinal) => Some(ordinal),
                    Err(error) => {
                        eprintln!("mvm-gpu-endpoint: invalid device ordinal {raw:?}: {error}");
                        exit(2);
                    }
                };
            }
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

    let make_backend: Arc<dyn Fn() -> io::Result<Box<dyn GpuBackend>> + Send + Sync> =
        match backend_mode.as_str() {
            "stub" => Arc::new(move || Ok(Box::new(stub_backend(device_ordinal)))),
            "native" => {
                if native::probe().is_none() {
                    eprintln!("mvm-gpu-endpoint: --backend native but no usable driver library");
                    exit(1);
                }
                // Each connection rebuilds from the loaded driver rather than
                // sharing one backend: a shared backend would let two guests
                // share handle tables. cuInit is documented idempotent.
                Arc::new(move || {
                    select_backend(
                        false,
                        || native_backend(device_ordinal),
                        || stub_backend(device_ordinal),
                    )
                })
            }
            "auto" => match native::probe() {
                Some(_) => Arc::new(move || {
                    select_backend(
                        true,
                        || native_backend(device_ordinal),
                        || stub_backend(device_ordinal),
                    )
                }),
                None => Arc::new(move || Ok(Box::new(stub_backend(device_ordinal)))),
            },
            other => {
                eprintln!("mvm-gpu-endpoint: unknown --backend {other:?}");
                exit(2);
            }
        };

    if let Some(ordinal) = device_ordinal {
        let mut backend = make_backend().unwrap_or_else(|error| {
            eprintln!("mvm-gpu-endpoint: {error}");
            exit(1);
        });
        match mvm_gpu::handle_request(&mut *backend, &mvm_gpu::GpuRequest::DeviceGetCount) {
            mvm_gpu::GpuResponse::DeviceCount { count: 1 } => {}
            mvm_gpu::GpuResponse::Err(error) => {
                eprintln!(
                    "mvm-gpu-endpoint: refusing host GPU ordinal {ordinal}: {}",
                    error.message
                );
                exit(1);
            }
            response => {
                eprintln!(
                    "mvm-gpu-endpoint: refusing host GPU ordinal {ordinal}: unexpected validation response {response:?}"
                );
                exit(1);
            }
        }
    }

    let vm = vm_name.as_deref().unwrap_or("<unnamed>");
    // SIGTERM/SIGINT flip the stop flag: the runner reaps this process
    // with the VM, and the flag unblocks the accept loop for a clean exit.
    stop_flag::arm();

    // Logged once the socket is bound, so the line doubles as a readiness signal.
    let announce =
        || eprintln!("mvm-gpu-endpoint: vm={vm} backend={backend_mode} listening on {addr}");
    if let Err(e) = run(&addr, move || make_backend(), stop_flag::flag(), announce) {
        eprintln!("mvm-gpu-endpoint: serve {addr}: {e}");
        exit(1);
    }
}

fn stub_backend(device_ordinal: Option<u32>) -> stub::StubBackend {
    match device_ordinal {
        Some(ordinal) => stub::StubBackend::new().with_device_ordinal(ordinal),
        None => stub::StubBackend::new(),
    }
}

fn native_backend(device_ordinal: Option<u32>) -> Option<native::NativeCudaBackend> {
    native::probe().map(|backend| match device_ordinal {
        Some(ordinal) => backend.with_device_ordinal(ordinal),
        None => backend,
    })
}

fn select_backend<N: GpuBackend + 'static, S: GpuBackend + 'static>(
    allow_stub: bool,
    native: impl FnOnce() -> Option<N>,
    stub: impl FnOnce() -> S,
) -> io::Result<Box<dyn GpuBackend>> {
    if let Some(backend) = native() {
        Ok(Box::new(backend))
    } else if allow_stub {
        Ok(Box::new(stub()))
    } else {
        Err(io::Error::other(
            "--backend native: driver initialization failed; refusing stub fallback",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_native_refuses_lost_driver_without_constructing_stub() {
        let result = select_backend(
            false,
            || None::<stub::StubBackend>,
            || -> stub::StubBackend { panic!("native must never construct a stub") },
        );
        let error = result
            .err()
            .expect("native initialization must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("--backend native"));
        assert!(error.to_string().contains("refusing stub fallback"));
    }

    #[test]
    fn auto_keeps_gpu_free_stub_fallback() {
        let mut backend =
            select_backend(true, || None::<stub::StubBackend>, stub::StubBackend::new)
                .expect("auto can fall back");
        assert_eq!(backend.device_count().unwrap(), 2);
    }

    #[test]
    fn successful_native_selection_does_not_construct_stub() {
        for allow_stub in [false, true] {
            let mut backend = select_backend(
                allow_stub,
                || Some(stub::StubBackend::new()),
                || -> stub::StubBackend { panic!("successful selection must not fall back") },
            )
            .expect("selected backend");
            assert_eq!(backend.device_count().unwrap(), 2);
        }
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
