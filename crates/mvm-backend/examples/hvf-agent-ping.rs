//! Live proof (macOS / Apple-silicon): a host process reaches the guest agent
//! over the in-house HVF vsock bridge. Boots a real mkGuest workload, then pings
//! the guest agent on `GUEST_AGENT_PORT` through the host agent socket the
//! `AgentBridge` exposes (`MVM_HVF_AGENT_SOCKET`). Exit 0 iff the agent answered.
//!
//! ```sh
//! cargo build -p mvm-vm-host --bin mvm-hvf-supervisor
//! cargo build -p mvm-backend --example hvf-agent-ping
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_HVF_KERNEL=/tmp/hvf-real/Image MVM_HVF_DISK=/tmp/hvf-real/rootfs.ext4 \
//!   MVM_HVF_TIMEOUT=60 MVM_HVF_AGENT_SOCKET=/tmp/hvf-agent.sock \
//!   ./target/debug/examples/hvf-agent-ping
//! ```

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf_backend::HvfBackend;
        use mvm_core::vm_backend::{VmBackend, VmStartConfig};
        use std::time::Duration;

        let sock = std::env::var("MVM_HVF_AGENT_SOCKET")
            .unwrap_or_else(|_| "/tmp/hvf-agent.sock".to_string());
        // The detached supervisor inherits our env, so kernel_boot binds this path.
        unsafe { std::env::set_var("MVM_HVF_AGENT_SOCKET", &sock) };
        let _ = std::fs::remove_file(&sock);

        let backend = HvfBackend;
        let cfg = VmStartConfig {
            name: "hvf-agent-ping".to_string(),
            kernel_path: Some(std::env::var("MVM_HVF_KERNEL").expect("MVM_HVF_KERNEL")),
            rootfs_path: std::env::var("MVM_HVF_DISK").expect("MVM_HVF_DISK"),
            ..Default::default()
        };

        let id = backend.start(&cfg).expect("HvfBackend::start");
        println!("started {id:?}; agent socket = {sock}");

        // The agent comes up after /init's Stage 2.5 (a few seconds post-boot). Poll
        // ping until it answers or the VM's timeout window closes. Each ping is a
        // fresh host connection: while the agent isn't listening the guest RSTs the
        // stream and we retry; once it's up the bridge relays the Ping/Pong.
        let mut ok = false;
        for i in 0..120 {
            if let Ok(true) = mvm_guest::vsock::ping_at(&sock) {
                println!("PING answered after ~{}ms", i * 500);
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        println!("guest agent reachable over HVF vsock bridge: {ok}");
        let _ = backend.stop(&id);
        std::process::exit(if ok { 0 } else { 1 });
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        eprintln!("hvf-agent-ping requires macOS / Apple silicon");
        std::process::exit(2);
    }
}
