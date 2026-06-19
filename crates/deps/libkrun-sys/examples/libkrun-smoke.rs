//! Smoke test — boot a Nix-built kernel + ext4 rootfs via libkrun on
//! macOS Apple Silicon and observe the result.
//!
//! Build:
//!   cargo build --example libkrun-smoke -p mvm-libkrun --features libkrun-sys
//!
//! Run (defaults pull from `~/.mvm/dev/current/`, the dev-VM artifacts
//! shipped by `mvmctl dev up`):
//!   target/debug/examples/libkrun-smoke
//!
//! Override any path:
//!   libkrun-smoke \
//!     --kernel /path/to/vmlinux \
//!     --rootfs /path/to/rootfs.ext4 \
//!     --data-disk /path/to/nix-store.img \
//!     --cmdline 'console=hvc0 root=/dev/vda rw init=/init' \
//!     --console-output /tmp/mvm-libkrun-smoke.log
//!
//! ## What it proves
//!
//! libkrun's macOS Apple Silicon (Hypervisor.framework) path can load
//! a Nix-built ARM64 kernel and attach an ext4 rootfs as `/dev/vda`.
//! `krun_start_enter` blocks until the guest exits; the smoke test
//! process becomes the guest. On success libkrun calls `exit()` with
//! the guest's exit code — there is no "after". A boot failure
//! surfaces as a libkrun error code returned from `start_enter`.
//!
//! ## Hard-coded for this iteration
//!
//! - `--cmdline` defaults to the same line Apple Container uses on
//!   macOS (`console=hvc0 root=/dev/vda rw init=/init`), because both
//!   backends drive `Hypervisor.framework` and share the virtio-console
//!   wiring. The Firecracker `console=ttyS0` cmdline is wrong here.
//! - Kernel format is `KrunContext`'s default (Raw). ARM64 Linux
//!   "Image" files use the raw format; ELF kernels would need
//!   `KernelFormat::Elf`.
//! - The default vsock port (`GUEST_AGENT_PORT`) is configured so the
//!   guest-agent listener has a host-side socket to bind to; the
//!   actual health-check ping is a follow-on and is *not* run from
//!   this binary (the calling process becomes the guest, so there is
//!   no opportunity to dial the socket from here).
//!
//! ## Not yet wired
//!
//! - Boot timing / health-check ping over vsock — needs a separate
//!   host process or a fork(); the smoke binary is single-process and
//!   inherits the process-exits-on-success contract of
//!   `krun_start_enter`. That wiring is a follow-on.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use libkrun_sys::{KernelFormat, KrunContext, LogLevel, set_log_level, start_enter};

fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}\n");
            eprintln!("{HELP}");
            return ExitCode::from(2);
        }
    };

    if args.help {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    // macOS Hypervisor.framework rejects any process that lacks the
    // `com.apple.security.hypervisor` entitlement (the joint VZ +
    // Hypervisor entitlement set). `ensure_signed`
    // ad-hoc codesigns the current binary on first run and re-spawns
    // with `MVM_SIGNED=1`; subsequent runs are silent. Without this
    // call, `krun_start_enter` fails at VM creation with rc -22.
    mvm_backend::codesign::ensure_signed();

    // Sanity-check every path that has to exist before we hand it to
    // libkrun. The C wrapper would fail later anyway, but failing here
    // gives a clearer error.
    for (label, path) in [("kernel", &args.kernel), ("rootfs", &args.rootfs)] {
        if !Path::new(path).is_file() {
            eprintln!("error: {label} path does not exist or is not a file: {path}");
            return ExitCode::from(2);
        }
    }
    if let Some(dd) = &args.data_disk
        && !Path::new(dd).is_file()
    {
        eprintln!("error: data-disk path does not exist or is not a file: {dd}");
        return ExitCode::from(2);
    }

    eprintln!("plan 57 W3 — libkrun boot smoke");
    eprintln!("  kernel:   {}", args.kernel);
    eprintln!("  format:   {:?}", args.kernel_format);
    eprintln!("  rootfs:   {}", args.rootfs);
    if let Some(dd) = &args.data_disk {
        eprintln!("  data:     {dd} (as /dev/vdb)");
    }
    eprintln!("  cmdline:  {}", args.cmdline);
    eprintln!("  vcpus:    {}", args.vcpus);
    eprintln!("  mem MiB:  {}", args.mem_mib);
    if let Some(co) = &args.console_output {
        eprintln!("  console → {co}");
    } else {
        eprintln!("  console → (process stdout)");
    }
    eprintln!();
    eprintln!("krun_start_enter blocks until the guest exits, then calls");
    eprintln!("exit() with the guest's status. ^C kills the host process,");
    eprintln!("which tears the guest down with it.");
    eprintln!();

    // Crank libkrun's own log level so a boot failure surfaces with
    // some context rather than a bare errno.
    if let Err(e) = set_log_level(LogLevel::Debug) {
        eprintln!("warn: krun_set_log_level failed: {e}");
    }

    // Per-VM vsock socket dir. The smoke binary doesn't run a sibling
    // listener (it becomes the guest), so any AF_VSOCK connect inside
    // the guest will fail with ECONNREFUSED — that's expected for the
    // spike. The supervisor adds the host-side listener.
    let socket_dir = format!("{}/.mvm/vms/mvm-libkrun-smoke", args.home);
    if let Err(e) = std::fs::create_dir_all(&socket_dir) {
        eprintln!("warn: create_dir_all {socket_dir}: {e}");
    }

    let mut ctx = KrunContext::new("mvm-libkrun-smoke", &args.kernel, &args.rootfs)
        .with_kernel_format(args.kernel_format)
        .with_resources(args.vcpus, args.mem_mib)
        .with_cmdline(&args.cmdline)
        .with_vsock_socket_dir(&socket_dir)
        .add_vsock_port(mvm_guest::vsock::GUEST_AGENT_PORT);
    if let Some(dd) = args.data_disk {
        ctx = ctx.add_disk("data", dd, false);
    }
    if let Some(co) = args.console_output {
        ctx = ctx.with_console_output(co);
    }

    match start_enter(&ctx) {
        // `start_enter` returns `Result<Infallible, _>`; on success the
        // process is already gone, so the Ok arm is unreachable in
        // practice and the match is over `Err` only.
        Err(e) => {
            eprintln!("\nlibkrun start_enter failed: {e}");
            ExitCode::from(1)
        }
    }
}

const HELP: &str = "\
plan 57 W3 — libkrun boot smoke

Boots a Nix-built kernel + ext4 rootfs through libkrun on macOS Apple
Silicon and blocks until the guest exits. Defaults target the dev-VM
artifacts under ~/.mvm/dev/current/.

USAGE:
    libkrun-smoke [OPTIONS]

OPTIONS:
    --kernel <PATH>           kernel image (ARM64 'Image' / raw format)
                              [default: ~/.mvm/dev/current/vmlinux]
    --kernel-format <FORMAT>  kernel format: raw, elf, image_gz, image_bz2,
                              image_zstd, or pe_gz [default: raw]
    --rootfs <PATH>           ext4 root filesystem image
                              [default: ~/.mvm/dev/current/rootfs.ext4]
    --data-disk <PATH>        optional second virtio-blk device (/dev/vdb)
                              [default: ~/.mvm/dev/nix-store.img if it exists]
    --cmdline <STRING>        kernel command line
                              [default: 'console=hvc0 root=/dev/vda rw init=/init']
    --console-output <PATH>   route hvc0 console to a file
                              [default: inherit calling process's stdout]
    --vcpus <N>               vCPU count [default: 1]
    --mem <MIB>               guest RAM in MiB [default: 512]
    -h, --help                show this help
";

struct Args {
    kernel: String,
    kernel_format: KernelFormat,
    rootfs: String,
    data_disk: Option<String>,
    cmdline: String,
    console_output: Option<String>,
    vcpus: u8,
    mem_mib: u32,
    home: String,
    help: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        let default_kernel = format!("{home}/.mvm/dev/current/vmlinux");
        let default_rootfs = format!("{home}/.mvm/dev/current/rootfs.ext4");
        let default_data = format!("{home}/.mvm/dev/nix-store.img");
        let auto_data = PathBuf::from(&default_data)
            .is_file()
            .then_some(default_data);

        let mut kernel = default_kernel;
        let mut kernel_format = KernelFormat::Raw;
        let mut rootfs = default_rootfs;
        let mut data_disk = auto_data;
        let mut cmdline = "console=hvc0 root=/dev/vda rw init=/init".to_string();
        let mut console_output: Option<String> = None;
        let mut vcpus: u8 = 1;
        let mut mem_mib: u32 = 512;
        let mut help = false;

        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-h" | "--help" => help = true,
                "--kernel" => kernel = next_value(&mut it, "--kernel")?,
                "--kernel-format" => {
                    kernel_format = parse_kernel_format(&next_value(&mut it, "--kernel-format")?)?
                }
                "--rootfs" => rootfs = next_value(&mut it, "--rootfs")?,
                "--data-disk" => data_disk = Some(next_value(&mut it, "--data-disk")?),
                "--no-data-disk" => data_disk = None,
                "--cmdline" => cmdline = next_value(&mut it, "--cmdline")?,
                "--console-output" => {
                    console_output = Some(next_value(&mut it, "--console-output")?)
                }
                "--vcpus" => {
                    let v = next_value(&mut it, "--vcpus")?;
                    vcpus = v.parse().map_err(|e| format!("--vcpus: {e}"))?;
                }
                "--mem" => {
                    let v = next_value(&mut it, "--mem")?;
                    mem_mib = v.parse().map_err(|e| format!("--mem: {e}"))?;
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }

        Ok(Args {
            kernel,
            kernel_format,
            rootfs,
            data_disk,
            cmdline,
            console_output,
            vcpus,
            mem_mib,
            home,
            help,
        })
    }
}

fn parse_kernel_format(value: &str) -> Result<KernelFormat, String> {
    match value {
        "raw" => Ok(KernelFormat::Raw),
        "elf" => Ok(KernelFormat::Elf),
        "image_gz" => Ok(KernelFormat::ImageGz),
        "image_bz2" => Ok(KernelFormat::ImageBz2),
        "image_zstd" => Ok(KernelFormat::ImageZstd),
        "pe_gz" => Ok(KernelFormat::PeGz),
        other => Err(format!(
            "unsupported --kernel-format {other:?}; expected raw, elf, image_gz, image_bz2, image_zstd, or pe_gz"
        )),
    }
}

fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}
