//! Self-hosting builder-rootfs bootstrap: inject the freshly
//! cross-compiled `mvm-host-vm-init` into a builder rootfs using ONLY the hvf
//! VMM — no vz, no legacy builder. Thin driver over
//! `mvm_runtime::builder_runner::inject_host_binaries`. Output: a patched rootfs
//! at `$OUT` (default `/tmp/mvm-patched-rootfs.ext4`).
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

    use mvm_build::rootfs_inject::InjectBinary;
    use mvm_runtime::builder_runner::{
        InjectRequest, default_inject_work_dir, inject_host_binaries,
    };

    let home = std::env::var("HOME").unwrap();
    let dev = format!("{home}/.mvm/dev/current");
    let kernel = PathBuf::from(
        std::env::var("MVM_INJECT_KERNEL").unwrap_or_else(|_| format!("{dev}/vmlinux")),
    );
    let src_rootfs = PathBuf::from(
        std::env::var("MVM_INJECT_SRC_ROOTFS").unwrap_or_else(|_| format!("{dev}/rootfs.ext4")),
    );
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

    let out = PathBuf::from(
        std::env::var("OUT").unwrap_or_else(|_| "/tmp/mvm-patched-rootfs.ext4".into()),
    );
    let new_init_bytes = std::fs::read(&new_init).unwrap();
    println!("injecting the current mvm-host-vm-init into a rootfs copy via the hvf VMM…");
    inject_host_binaries(&InjectRequest {
        kernel: &kernel,
        base_rootfs: &src_rootfs,
        out_rootfs: &out,
        work_dir: &default_inject_work_dir("example"),
        patcher: &std::fs::read(&patcher).unwrap(),
        binaries: &[InjectBinary {
            name: "mvm-host-vm-init",
            install_path: "/sbin/mvm-host-vm-init",
            bytes: new_init_bytes,
        }],
    })
    .expect("inject");

    println!(
        "PROOF: the hvf VMM patched a builder rootfs with the current \
         mvm-host-vm-init — no vz, no legacy builder. Patched rootfs: {}",
        out.display()
    );
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    println!("hvf-rootfs-inject: only on macOS / Apple silicon");
}
