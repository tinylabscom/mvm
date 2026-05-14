//! `mvm-builder-init` entry point. Plan 71 W3.
//!
//! On Linux the binary is `init=` for the libkrun builder VM —
//! mounts, fsck/format, network, run, write result, poweroff.
//! On other targets the binary builds to a stub that prints a
//! message and exits 1 so `cargo build -p mvm-builder-init` keeps
//! working on macOS dev hosts (the real cross-compile lands via
//! mkGuest's `buildPackages.mvm-builder-init` against
//! aarch64-linux).
//!
//! W3 ships only the skeleton: the Linux body lays out the boot
//! steps with `todo!()` and typed `unreachable!()` markers so the
//! W3-real PR knows exactly where each syscall goes. Per the plan's
//! W3 acceptance, the boot-in-qemu / boot-to-poweroff timing
//! validation runs *after* W2 lands a real builder VM image.

#![allow(clippy::needless_doctest_main)]

#[cfg(target_os = "linux")]
fn main() -> ! {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // The crate's *binary* is meaningful only as `init=` inside the
    // libkrun builder VM (Linux). On macOS / other hosts we still
    // want `cargo build -p mvm-builder-init` to succeed so the
    // workspace stays uniformly compilable; print a clear message
    // and exit nonzero. CI runs unit tests via the library crate
    // (cross-platform) — the binary stub is just here to keep
    // `cargo build` honest.
    eprintln!(
        "mvm-builder-init: binary is Linux-only (init=/sbin/mvm-builder-init for the libkrun builder VM). \
         Build via mkGuest's buildPackages.mvm-builder-init for aarch64-linux."
    );
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use mvm_builder_init::{BuilderCmdline, JobResult};

    /// The path the host stages the job script at.
    pub const JOB_CMD_PATH: &str = "/job/cmd.sh";
    /// Where the result line gets written before poweroff.
    pub const JOB_RESULT_PATH: &str = "/job/result";
    /// Persistent /nix store virtio-blk.
    pub const NIX_STORE_BLK: &str = "/dev/vdb";
    /// Mount point for the persistent /nix store before the bind
    /// onto `/nix`.
    pub const NIX_STORE_MOUNT: &str = "/nix-store";
    /// Final mount the user processes see.
    pub const NIX_FINAL: &str = "/nix";

    pub fn run() -> ! {
        // Steps below are the boot order the W3-real PR fills in.
        // Each one bottoms out in `todo_init` so a partial build
        // can't accidentally boot a half-initialized VM that loses
        // job output.

        if let Err(e) = mount_essentials() {
            write_result_and_poweroff(JobResult::mount_essentials_failed(e));
        }

        // /proc must be mounted before we can read /proc/cmdline.
        let _cmdline = read_cmdline();

        if let Err(e) = mount_persistent_nix_store() {
            write_result_and_poweroff(JobResult::mount_nix_store_failed(e));
        }

        // Network bring-up is skipped under `mvm.builder.offline=1`;
        // the W4 PR threads that through to here.
        if let Err(e) = bring_up_network() {
            write_result_and_poweroff(JobResult::network_failed(e));
        }

        let result = run_job();
        write_result_and_poweroff(result);
    }

    fn mount_essentials() -> Result<(), String> {
        // mount /proc /sys /dev /tmp via libc::mount. Filled in by
        // the W3-real PR. Returning Err with the syscall errno
        // string lets the result file carry actionable context.
        todo_init("mount_essentials")
    }

    fn read_cmdline() -> BuilderCmdline {
        match std::fs::read_to_string("/proc/cmdline") {
            Ok(s) => BuilderCmdline::parse(&s),
            // /proc not mounted, or read failed. Fall through with
            // defaults — the init's other steps are robust to a
            // missing cmdline.
            Err(_) => BuilderCmdline::default(),
        }
    }

    fn mount_persistent_nix_store() -> Result<(), String> {
        // fsck/format /dev/vdb, mount at /nix-store, bind to /nix.
        // First-boot path also copies the seed /nix from the
        // rootfs (~150 MiB).
        let _ = (NIX_STORE_BLK, NIX_STORE_MOUNT, NIX_FINAL);
        todo_init("mount_persistent_nix_store")
    }

    fn bring_up_network() -> Result<(), String> {
        // exec udhcpc -i eth0 -n -q. Honor `mvm.builder.offline=1`
        // from BuilderCmdline (read in run()) — the W4 PR threads
        // the flag here.
        todo_init("bring_up_network")
    }

    fn run_job() -> JobResult {
        // exec /bin/sh -eu /job/cmd.sh; tee stderr to a capture
        // buffer truncated to STDERR_TAIL_MAX_BYTES; return
        // JobResult { code, stderr_tail }.
        let _ = JOB_CMD_PATH;
        // Return a typed placeholder until the W3-real PR fills in
        // the exec path. Reserved code 254 lets the host detect a
        // skeleton-build accidentally shipped to production.
        JobResult::new(254, "mvm-builder-init: run_job skeleton stub")
    }

    fn write_result_and_poweroff(r: JobResult) -> ! {
        // Best-effort write; if the result file is unwritable we
        // still poweroff so the host doesn't hang on its launch-side
        // timeout.
        let line = r.to_json_line();
        let _ = std::fs::write(JOB_RESULT_PATH, line);

        // SAFETY: `libc::sync()` and `libc::reboot()` are the only
        // way to cleanly power off a libkrun guest. Both are
        // syscall wrappers; the unsafe block names them
        // explicitly so reviewers see what's happening.
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }

        // reboot() never returns on success. If it did (e.g.,
        // wrong magic constants on this arch), spin so the host's
        // wall-clock timeout takes over.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    fn todo_init(step: &'static str) -> Result<(), String> {
        // Marker for the W3-real PR. Returning Err — *not* panic —
        // means the skeleton-built init still writes a result file
        // on the way out, so the host doesn't think it crashed.
        Err(format!(
            "mvm-builder-init: skeleton {step}() not yet implemented; see plan 71 W3"
        ))
    }
}
