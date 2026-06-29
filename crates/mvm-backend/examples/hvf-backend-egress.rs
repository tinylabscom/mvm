//! Prove the end-to-end policy-driven vsock egress through the HVF backend +
//! supervisor (ADR-100): a VM started with an allow-list `NetworkPolicy` reaches
//! the admitted destination over vsock; the supervisor resolves the host pin,
//! projects the gate, and proxies. macOS / Apple-silicon.
//!
//! Uses this host's LAN IP (RFC1918 — not mandatory-deny) with a local echo
//! server, so the test is deterministic and offline.
//!
//! ```sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-init-echo/initramfs.cpio \
//!   MVM_HVF_EGRESS_HOST=192.168.4.23 MVM_HVF_EGRESS_PORT=19099 \
//!   ./target/debug/examples/hvf-backend-egress
//! ```

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf_backend::HvfBackend;
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::vm_backend::{VmBackend, VmStartConfig, VmStatus};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        // Bound the run so the demo always terminates (this echo guest doesn't
        // report a workload-exit), then observe via status/logs.
        // SAFETY: single-threaded test setup.
        unsafe { std::env::set_var("MVM_HVF_TIMEOUT", "8") };

        let host = std::env::var("MVM_HVF_EGRESS_HOST").unwrap_or_else(|_| "192.168.4.23".into());
        let port: u16 = std::env::var("MVM_HVF_EGRESS_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(19099);

        // One-shot local echo server at the admitted destination.
        let listener = TcpListener::bind((host.as_str(), port)).expect("bind echo server");
        let echo = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = c.read(&mut buf) {
                    let _ = c.write_all(&buf[..n]);
                }
            }
        });

        let backend = HvfBackend;
        let cfg = VmStartConfig {
            name: "hvf-egress-policy-demo".to_string(),
            kernel_path: Some(
                std::env::var("MVM_HVF_KERNEL")
                    .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image".into()),
            ),
            initrd_path: std::env::var("MVM_HVF_INITRD").ok(),
            // Policy-driven: admit exactly the echo destination over vsock.
            network_policy: NetworkPolicy::allow_list(vec![HostPort {
                host: host.clone(),
                port,
            }]),
            ..Default::default()
        };

        let id = backend.start(&cfg).expect("start");
        // Poll until the (bounded) supervisor stops, then read the captured console.
        for _ in 0..150 {
            if backend.status(&id).unwrap() == VmStatus::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = echo.join();
        let logs = backend.logs(&id, 0, false).unwrap_or_default();
        let ok = logs.contains("egress reply over vsock: ping");
        println!("policy: allow-list [{host}:{port}] | egress reply received: {ok}");
        if ok {
            println!(
                "PROOF: a VM started with an allow-list NetworkPolicy reached {host}:{port} over \
                 vsock — the supervisor resolved the pin, projected the claim-10 gate, and proxied \
                 the bytes (no guest NIC)."
            );
        } else {
            eprintln!("no proxied reply; console:\n{logs}");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-backend-egress: only on macOS / Apple silicon");
}
