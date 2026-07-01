//! Step 1 of the builder-on-HVF capstone: live-prove the disk-only job/artifact
//! transport end to end, with NO nix and NO egress. Drives the real
//! `BuilderRunner<InHouseDriver>` with a trivial `cmd.sh`, so a green run means
//! the guest init's disk-transport fallback (extract input disk → run cmd.sh →
//! tar /out onto the output disk) works on the in-house HVF VMM.
//!
//! Needs a built dev image at `~/.mvm/dev/current` (kernel + builder rootfs).
//!
//! ```sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   cargo run -p mvm-backend --example hvf-builder-transport
//! ```

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use std::path::PathBuf;

    use mvm_backend::builder_runner::{BuilderBuild, BuilderRunner};
    use mvm_backend::driver::InHouseDriver;
    use mvm_build::builder_disk_transport::create_output_disk;

    let home = std::env::var("HOME").unwrap();
    let dev = format!("{home}/.mvm/dev/current");
    let kernel = PathBuf::from(format!("{dev}/vmlinux"));
    // MVM_BUILDER_ROOTFS points at a rootfs with the current mvm-host-vm-init
    // baked in (e.g. the self-hosted-inject output); default is the dev image.
    let rootfs = PathBuf::from(
        std::env::var("MVM_BUILDER_ROOTFS").unwrap_or_else(|_| format!("{dev}/rootfs.ext4")),
    );
    assert!(
        kernel.exists() && rootfs.exists(),
        "need a kernel at {dev} and a builder rootfs (set MVM_BUILDER_ROOTFS)"
    );

    // Scratch job / work / mvm-bins trees the transport carries into the guest.
    let scratch = std::env::temp_dir().join("mvm-builder-step1");
    let _ = std::fs::remove_dir_all(&scratch);
    let job = scratch.join("job");
    let work = scratch.join("work");
    let bins = scratch.join("bins");
    for d in [&job, &work, &bins] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(work.join("marker"), b"HELLO-FROM-WORK").unwrap();
    std::fs::write(bins.join("placeholder"), b"bin").unwrap();
    // Trivial job — no nix. Prove the transport moves data both ways: read an
    // input from /work, write an artifact to /out. write_result drops /job/result;
    // the guest folds both into the output tar.
    std::fs::write(
        job.join("cmd.sh"),
        b"#!/bin/sh\nset -eu\n\
          echo \"STEP1-OK marker=$(cat /work/marker)\" > /out/rootfs.ext4\n\
          echo \"work-listing:\" >> /out/rootfs.ext4\n\
          ls /work >> /out/rootfs.ext4\n\
          echo \"mvm-bins-listing:\" >> /out/rootfs.ext4\n\
          ls /mvm-bins >> /out/rootfs.ext4\n",
    )
    .unwrap();

    // Empty nix-store scratch — the guest formats + seeds it at boot.
    let nix_store = scratch.join("nix-store.img");
    create_output_disk(&nix_store, 8 << 30).expect("size nix-store scratch"); // 8 GiB sparse

    // The builder powers off on its own after the job; this only backstops a hang.
    // SAFETY: single-threaded example setup.
    unsafe { std::env::set_var("MVM_HVF_TIMEOUT", "180") };

    println!("booting the builder VM on HVF (disk transport, no nix)…");
    let runner = BuilderRunner::new(InHouseDriver::new());
    let outcome = runner
        .build(&BuilderBuild {
            name: "hvf-builder-step1",
            kernel: &kernel,
            rootfs: &rootfs,
            nix_store: &nix_store,
            job_dir: &job,
            work_src: &work,
            host_bin_dir: &bins,
            output_size: 64 << 20,
            vcpus: 2,
            // Builder-appropriate RAM (a real nix build OOMs at 512 MiB);
            // overridable to exercise the configurable-RAM path.
            memory_mib: std::env::var("MVM_BUILDER_MEM_MIB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8192),
        })
        .expect("builder build");

    println!(
        "stopped={} output_dir={}",
        outcome.stopped,
        outcome.output_dir.display()
    );
    println!("--- output dir listing ---");
    if let Ok(rd) = std::fs::read_dir(&outcome.output_dir) {
        for e in rd.flatten() {
            println!("  {}", e.file_name().to_string_lossy());
        }
    }

    let rootfs_out = outcome.output_dir.join("rootfs.ext4");
    if !rootfs_out.exists() {
        eprintln!("FAILED: no rootfs.ext4 in the guest's output tar");
        std::process::exit(1);
    }
    let body = std::fs::read_to_string(&rootfs_out).unwrap_or_default();
    println!("--- /out/rootfs.ext4 (written by the guest cmd.sh) ---\n{body}");
    if let Ok(r) = std::fs::read_to_string(outcome.output_dir.join("result")) {
        println!("--- result ---\n{r}");
    }
    if body.contains("STEP1-OK marker=HELLO-FROM-WORK") {
        println!(
            "PROOF: the disk transport round-tripped on HVF — the input disk reached \
             the guest, cmd.sh read /work and wrote /out, and the output tar came \
             back to the host. No vz, no virtio-fs, no nix."
        );
    } else {
        eprintln!("FAILED: output present but the expected marker is missing");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    println!("hvf-builder-transport: only on macOS / Apple silicon");
}
