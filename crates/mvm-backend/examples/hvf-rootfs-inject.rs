//! Self-hosting builder-rootfs bootstrap (Plan 214, Option B): inject the freshly
//! cross-compiled `mvm-host-vm-init` into a builder rootfs using ONLY the in-house
//! VMM — no vz, no legacy builder. Boots `kernel + inject-initramfs + a writable
//! copy of the rootfs`; the `mvm-rootfs-patcher` init mounts the rootfs RW, copies
//! the new binary to `/sbin/mvm-host-vm-init`, and powers off. Output: a patched
//! rootfs at `$OUT` (default `/tmp/mvm-patched-rootfs.ext4`).
//!
//! Prereqs — cross-compile the two static binaries first:
//! ```sh
//! RUSTC=$(rustup which rustc) RUSTUP_TOOLCHAIN=stable-aarch64-apple-darwin \
//!   cargo zigbuild -p mvm-build --bin mvm-rootfs-patcher --bin mvm-host-vm-init \
//!   --target aarch64-unknown-linux-musl --release
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   cargo run -p mvm-backend --example hvf-rootfs-inject
//! ```

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use mvm_build::hvf_supervisor::{HvfDisk, HvfSupervisorConfig};
    use mvm_build::rootfs_inject::{InjectBinary, build_inject_initramfs};

    let home = std::env::var("HOME").unwrap();
    let dev = format!("{home}/.mvm/dev/current");
    let kernel = PathBuf::from(format!("{dev}/vmlinux"));
    let src_rootfs = PathBuf::from(format!("{dev}/rootfs.ext4"));
    let musl = "target/aarch64-unknown-linux-musl/release";
    let patcher = PathBuf::from(format!("{musl}/mvm-rootfs-patcher"));
    let new_init = PathBuf::from(format!("{musl}/mvm-host-vm-init"));
    for (what, p) in [
        ("kernel", &kernel),
        ("rootfs", &src_rootfs),
        ("patcher", &patcher),
        ("new init", &new_init),
    ] {
        assert!(
            p.exists(),
            "missing {what} at {} (cross-compile first)",
            p.display()
        );
    }

    // Build the inject initramfs: patcher as /init + the new host init as payload.
    let initramfs = build_inject_initramfs(
        &std::fs::read(&patcher).unwrap(),
        &[InjectBinary {
            name: "mvm-host-vm-init",
            install_path: "/sbin/mvm-host-vm-init",
            bytes: std::fs::read(&new_init).unwrap(),
        }],
    );
    let initramfs_path = std::env::temp_dir().join("mvm-inject-initramfs.cpio");
    std::fs::write(&initramfs_path, &initramfs).unwrap();
    println!("built inject initramfs ({} bytes)", initramfs.len());

    // A writable copy of the rootfs the patcher mounts + edits (never touches the
    // source image).
    let out = PathBuf::from(
        std::env::var("OUT").unwrap_or_else(|_| "/tmp/mvm-patched-rootfs.ext4".into()),
    );
    std::fs::copy(&src_rootfs, &out).unwrap();
    println!("copied rootfs -> {}", out.display());

    // Drive the supervisor directly: kernel + initramfs + the rootfs copy as a
    // writable virtio-blk disk. Default cmdline runs the initramfs /init (patcher).
    let console_log = std::env::temp_dir().join("mvm-inject-console.log");
    let cfg = HvfSupervisorConfig {
        kernel: kernel.clone(),
        cmdline: None,
        // The patcher just mounts + copies; the default RAM is plenty.
        memory_mib: 0,
        initramfs: Some(initramfs_path.clone()),
        disks: vec![HvfDisk {
            path: out.clone(),
            read_only: false,
            ephemeral: false,
        }],
        vsock: false,
        console_log: console_log.clone(),
        pid_file: std::env::temp_dir().join("mvm-inject.pid"),
        workload_exit: std::env::temp_dir().join("mvm-inject.exit"),
        timeout_secs: 60,
        agent_socket: None,
        substitution_socket: None,
        egress_relay_socket: None,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let supervisor = std::env::var("MVM_HVF_SUPERVISOR_PATH")
        .unwrap_or_else(|_| "target/debug/mvm-hvf-supervisor".into());

    println!("booting inject VM via {supervisor}…");
    let mut child = Command::new(&supervisor)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn supervisor");
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json.as_bytes())
        .unwrap();
    let status = child.wait().expect("wait supervisor");
    println!("inject VM exited: {status}");

    // Verify the patcher ran + injected the init from its console log.
    let console = std::fs::read_to_string(&console_log).unwrap_or_default();
    let injected =
        console.contains("injected /payload/mvm-host-vm-init -> /mnt/sbin/mvm-host-vm-init");
    println!("--- patcher console lines ---");
    for line in console.lines().filter(|l| l.contains("mvm-rootfs-patcher")) {
        println!("  {line}");
    }
    if injected {
        println!(
            "PROOF: the in-house VMM patched a builder rootfs with the current \
             mvm-host-vm-init — no vz, no legacy builder. Patched rootfs: {}",
            out.display()
        );
    } else {
        eprintln!(
            "FAILED: patcher did not report injecting the init; see {}",
            console_log.display()
        );
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    println!("hvf-rootfs-inject: only on macOS / Apple silicon");
}
