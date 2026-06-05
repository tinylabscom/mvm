//! PID 1 of the Stage 0 bootstrap VM — **nix-tarball seed** variant
//! (plan 160). Replaces the Alpine `init.sh`.
//!
//! libkrun mounts the materialized seed rootfs (the official Nix release
//! tarball's `/nix/store` + this binary as `/init`) as the guest root over
//! virtiofs (`krun_set_root`) and boots libkrunfw's bundled kernel; the
//! seed carries `nix` + `bash` + `curl` + `xz` + `nss-cacert` (CA certs) in
//! its closure — no Alpine, no apk, no external busybox.
//!
//! Networking is **not** our job: Stage 0's libkrun launch sets
//! `NET_FLAG_DHCP_CLIENT` (`libkrun_builder::apply_networking_mode` →
//! `configure_with_gateway`), so the guest comes up with a fully-configured
//! eth0 + DHCP + DNS. We only: mount the pseudo-filesystems + the host
//! virtiofs shares, make `/nix` writable (overlay the read-only seed store
//! with a tmpfs upper — plan 160 0a; the persistent ext4 disk is a later
//! refinement that needs mkfs, which the seed gets from `nix build
//! e2fsprogs` once this path is proven), then run `nix build` of the
//! in-repo builder-VM flake, copy the artifacts to `/out`, and power off.
//!
//! Mirrors the contract of `crates/mvm-build/src/stage0/init.sh` (the
//! Alpine variant) minus apk/networking; the host (`stage0::run_stage0`)
//! drives both behind `MVM_STAGE0_SEED`.

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The seed init only ever runs inside the Linux Stage 0 guest. The
        // crate still compiles on macOS/Windows contributor hosts (the bin
        // is cross-compiled to aarch64-musl + embedded by mvm-cli/build.rs,
        // ADR-065) so workspace builds stay green.
        eprintln!("stage0-init: only runs as PID 1 inside the Linux Stage 0 guest");
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};

    /// Read-only seed store (the nix tarball's `/nix`) — the overlay lower.
    const NIX_TARGET: &str = "/nix";
    /// tmpfs that backs the overlay upper + work on first boot (no mkfs;
    /// the persistent ext4 disk replaces this in a follow-up — plan 160).
    const NIX_UPPER_TMPFS: &str = "/run/nix-upper";
    const NIX_OVERLAY_UPPER: &str = "/run/nix-upper/upper";
    const NIX_OVERLAY_WORK: &str = "/run/nix-upper/work";
    const NIX_OVERLAY_MERGED: &str = "/run/nix-merged";

    pub fn run() -> ExitCode {
        if let Err(e) = setup() {
            eprintln!("stage0-init: FATAL: {e}");
            // Best-effort power off so the host sees the VM exit rather than
            // hang; the absence of /out artifacts is the failure signal.
            return power_off();
        }
        match build_and_copy() {
            Ok(()) => {
                eprintln!("stage0-init: done; halting");
                power_off()
            }
            Err(e) => {
                eprintln!("stage0-init: build failed: {e}");
                power_off()
            }
        }
    }

    /// Mounts + a writable `/nix`. Order mirrors `init.sh` minus apk/net.
    fn setup() -> Result<(), String> {
        mount_pseudofs()?;
        // `/dev/null` insurance — some libkrun set_root boots reach
        // userspace without it, which then masks every `2>/dev/null`
        // downstream (see init.sh's note). `|| Ok` it: devtmpfs usually
        // creates it.
        if !Path::new("/dev/null").exists() {
            mknod_null();
        }

        // Host virtio-fs shares. Tags match `add_virtio_fs(tag, ...)` in
        // `LibkrunBuilderVm::run_stage0`.
        for (tag, target, required) in [
            ("work", "/work", true),
            ("out", "/out", true),
            ("mvm-bins", "/mvm-bins", true),
        ] {
            std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
            mount_fs(tag, target, "virtiofs")?;
            if required && !is_mountpoint(target) {
                return Err(format!("{target} virtiofs mount did not take"));
            }
        }

        setup_nix_overlay()?;
        Ok(())
    }

    /// Standard PID-1 pseudo-filesystems. libkrun's kernel pre-mounts some;
    /// `mount_fs_idempotent` treats EBUSY as success.
    fn mount_pseudofs() -> Result<(), String> {
        mount_fs_idempotent("proc", "/proc", "proc")?;
        mount_fs_idempotent("sysfs", "/sys", "sysfs")?;
        mount_fs_idempotent("devtmpfs", "/dev", "devtmpfs")?;
        mount_fs_idempotent("tmpfs", "/tmp", "tmpfs")?;
        mount_fs_idempotent("tmpfs", "/run", "tmpfs")?;
        let _ = std::fs::create_dir_all("/dev/shm");
        mount_fs_idempotent("tmpfs", "/dev/shm", "tmpfs")?;
        // nix's build sandbox opens /dev/ptmx → needs devpts at /dev/pts.
        let _ = std::fs::create_dir_all("/dev/pts");
        mount_fs_idempotent("devpts", "/dev/pts", "devpts")?;
        Ok(())
    }

    /// Make `/nix` writable: overlay the read-only seed store (lower) with a
    /// tmpfs upper. nix sees its own closure from the lower and writes new
    /// store paths to the upper. (init.sh's persistent ext4 `/dev/vda` is
    /// the production upper; that needs mkfs, which the seed lacks until
    /// `nix build e2fsprogs` — a plan-160 follow-up. tmpfs is case-sensitive
    /// like ext4, so substituters that fail on case-insensitive APFS work.)
    fn setup_nix_overlay() -> Result<(), String> {
        mount_fs("tmpfs", NIX_UPPER_TMPFS, "tmpfs")?;
        for d in [NIX_OVERLAY_UPPER, NIX_OVERLAY_WORK, NIX_OVERLAY_MERGED] {
            std::fs::create_dir_all(d).map_err(|e| format!("create {d}: {e}"))?;
        }
        let data = format!(
            "lowerdir={NIX_TARGET},upperdir={NIX_OVERLAY_UPPER},workdir={NIX_OVERLAY_WORK}"
        );
        {
            use nix::mount::{MsFlags, mount};
            mount(
                Some("mvm-nix"),
                NIX_OVERLAY_MERGED,
                Some("overlay"),
                MsFlags::empty(),
                Some(data.as_str()),
            )
            .map_err(|e| format!("mount overlay {NIX_OVERLAY_MERGED}: {e}"))?;
        }
        bind_mount(NIX_OVERLAY_MERGED, NIX_TARGET)
    }

    /// `nix build` the builder-VM flake, then copy kernel + rootfs to /out.
    /// Invocation matches init.sh (the Alpine variant) byte-for-byte so the
    /// host-side contract (`/out/stage0-build.conf`, output modes) is
    /// unchanged.
    fn build_and_copy() -> Result<(), String> {
        let nix = find_seed_bin("nix")?;
        let cacert = find_seed_cacert()?;

        // Env (init.sh §"export HOME / MVM_WORKSPACE_PATH / MVM_HOST_BIN_DIR").
        std::fs::create_dir_all("/root").ok();
        let nix_path = nix
            .parent()
            .map(|bindir| {
                let path = std::env::var("PATH").unwrap_or_default();
                format!("{}:{path}", bindir.display())
            })
            .unwrap_or_default();
        // SAFETY: this is PID 1, single-threaded at this point — no other
        // thread can observe a torn environment. `set_var` is `unsafe` in
        // edition 2024 only for that thread-safety reason.
        // CA bundle = HTTPS trust for cache.nixos.org / flake inputs (libkrun
        // gives us DNS; `nss-cacert` from the seed gives the trust roots).
        // PATH = the seed nix's own bin dir (curl/xz/etc. live beside `nix`).
        unsafe {
            std::env::set_var("HOME", "/root");
            std::env::set_var("MVM_WORKSPACE_PATH", "/work");
            std::env::set_var("MVM_HOST_BIN_DIR", "/mvm-bins");
            std::env::set_var("NIX_SSL_CERT_FILE", &cacert);
            if !nix_path.is_empty() {
                std::env::set_var("PATH", nix_path);
            }
        }

        // Optional host-dropped build config (single-attr / kernel-only
        // modes). Mirrors init.sh's `. /out/stage0-build.conf` + defaults.
        let conf = read_build_conf("/out/stage0-build.conf");
        let attr = conf
            .get("MVM_STAGE0_BUILD_ATTR")
            .cloned()
            .unwrap_or_else(|| "default".into());
        let mode = conf
            .get("MVM_STAGE0_OUTPUT_MODE")
            .cloned()
            .unwrap_or_else(|| "image".into());
        let arch = machine_arch()?;
        let flake_ref = format!("path:/work/nix/images/builder-vm#packages.{arch}-linux.{attr}");

        eprintln!("stage0-init: building {flake_ref} (output_mode={mode})");
        let out = Command::new(&nix)
            .args([
                "build",
                &flake_ref,
                "--extra-experimental-features",
                "nix-command flakes",
                "--option",
                "connect-timeout",
                "30",
                "--max-jobs",
                "1",
                "--no-link",
                "--no-write-lock-file",
                "--impure",
                "--print-out-paths",
                "--print-build-logs",
            ])
            .output()
            .map_err(|e| format!("spawn nix build: {e}"))?;
        // nix's --print-build-logs go to stderr; surface them to the console.
        std::io::Write::write_all(&mut std::io::stderr(), &out.stderr).ok();
        // Persist the full log to /out for host-side post-mortem (init.sh
        // writes /out/nix-stderr.log).
        let _ = std::fs::write("/out/nix-stderr.log", &out.stderr);
        if !out.status.success() {
            return Err(format!(
                "nix build exit {}",
                out.status.code().unwrap_or(-1)
            ));
        }
        let store_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if store_path.is_empty() {
            return Err("nix build emitted no /nix/store path".into());
        }
        copy_artifacts(Path::new(&store_path), &mode)
    }

    /// Output by mode (matches init.sh): image = kernel + rootfs.ext4 +
    /// cmdline; kernel = kernel only; rootfs = rootfs + cmdline only.
    fn copy_artifacts(out: &Path, mode: &str) -> Result<(), String> {
        if mode != "rootfs" {
            let kernel = ["vmlinux", "Image", "bzImage"]
                .iter()
                .map(|n| out.join(n))
                .find(|p| p.is_file())
                .ok_or_else(|| format!("no kernel in {}", out.display()))?;
            copy_deref(&kernel, Path::new("/out/vmlinux"))?;
        }
        if mode != "kernel" {
            let rootfs = out.join("rootfs.ext4");
            if !rootfs.is_file() {
                return Err(format!("no rootfs.ext4 in {}", out.display()));
            }
            copy_deref(&rootfs, Path::new("/out/rootfs.ext4"))?;
            let cmdline = out.join("cmdline.txt");
            if cmdline.is_file() {
                let _ = copy_deref(&cmdline, Path::new("/out/cmdline.txt"));
            }
        }
        Ok(())
    }

    // ---- helpers ----------------------------------------------------------

    fn mount_fs(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some(source),
            target,
            Some(fstype),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount {source} -> {target} ({fstype}): {e}"))
    }

    fn mount_fs_idempotent(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        match mount_fs(source, target, fstype) {
            Ok(()) => Ok(()),
            Err(e) if e.contains("EBUSY") => {
                eprintln!("stage0-init: {target} ({fstype}) already mounted (EBUSY) — continuing");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn bind_mount(source: &str, target: &str) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind {source} -> {target}: {e}"))
    }

    fn is_mountpoint(target: &str) -> bool {
        // A path is a mountpoint when its st_dev differs from its parent's.
        let (Ok(here), Some(parent)) = (std::fs::metadata(target), Path::new(target).parent())
        else {
            return false;
        };
        let Ok(up) = std::fs::metadata(parent) else {
            return false;
        };
        use std::os::unix::fs::MetadataExt;
        here.dev() != up.dev()
    }

    fn mknod_null() {
        // mknod /dev/null c 1 3; ignore errors (libkrun may already have it).
        use std::ffi::CString;
        if let Ok(path) = CString::new("/dev/null") {
            // SAFETY: standard char-device node, fixed major/minor 1/3.
            unsafe {
                libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(1, 3));
            }
        }
    }

    /// Glob the seed store for a `*-<pkg>-*/bin/<bin>` executable. Store
    /// paths are hash-prefixed, so we discover rather than hardcode.
    fn find_seed_bin(bin: &str) -> Result<PathBuf, String> {
        let store = Path::new("/nix/store");
        let entries = std::fs::read_dir(store).map_err(|e| format!("read /nix/store: {e}"))?;
        for e in entries.flatten() {
            let cand = e.path().join("bin").join(bin);
            if cand.is_file() {
                return Ok(cand);
            }
        }
        Err(format!(
            "seed store has no bin/{bin} (is the nix tarball seed intact?)"
        ))
    }

    /// Find the seed's CA bundle (`nss-cacert`) for `NIX_SSL_CERT_FILE`.
    fn find_seed_cacert() -> Result<PathBuf, String> {
        let store = Path::new("/nix/store");
        let entries = std::fs::read_dir(store).map_err(|e| format!("read /nix/store: {e}"))?;
        for e in entries.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().contains("nss-cacert") {
                let bundle = e.path().join("etc/ssl/certs/ca-bundle.crt");
                if bundle.is_file() {
                    return Ok(bundle);
                }
            }
        }
        Err("seed store has no nss-cacert ca-bundle.crt".into())
    }

    /// `uname -m` via libc (no coreutils in the seed). aarch64 / x86_64.
    fn machine_arch() -> Result<String, String> {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: uname writes into the provided utsname struct.
        if unsafe { libc::uname(&mut uts) } != 0 {
            return Err("uname() failed".into());
        }
        let bytes: Vec<u8> = uts
            .machine
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Minimal `KEY=VALUE` / `KEY="VALUE"` reader for the optional
    /// host-dropped build conf (init.sh sourced it as shell; we only ever
    /// set two plain assignments there).
    fn read_build_conf(path: &str) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        let Ok(text) = std::fs::read_to_string(path) else {
            return map;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                map.insert(k.trim().to_string(), v.to_string());
            }
        }
        map
    }

    fn copy_deref(src: &Path, dst: &Path) -> Result<(), String> {
        // `cp -L`: follow the store symlink and copy the real file.
        std::fs::copy(src, dst)
            .map(|_| ())
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))
    }

    fn power_off() -> ExitCode {
        use nix::sys::reboot::{RebootMode, reboot};
        // SAFETY: sync() takes no args and cannot fail.
        unsafe {
            libc::sync();
        }
        match reboot(RebootMode::RB_POWER_OFF) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("stage0-init: reboot syscall failed: {e}");
                ExitCode::FAILURE
            }
        }
    }
}
