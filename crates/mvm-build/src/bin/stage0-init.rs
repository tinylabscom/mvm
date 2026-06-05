//! PID 1 of the Stage 0 bootstrap VM — the **nix-tarball seed** (plan 160).
//!
//! libkrun mounts the materialized seed rootfs (the official Nix release
//! tarball's `/nix/store` + this binary as `/init`) as the guest root over
//! virtiofs (`krun_set_root`) and boots libkrunfw's bundled kernel; the
//! seed carries `nix` + `bash` + `curl` + `xz` + `nss-cacert` (CA certs) in
//! its closure — no Alpine, no apk, no external busybox.
//!
//! What it does: mount the pseudo-filesystems + the host virtio-fs shares;
//! make `/nix` a writable, non-virtiofs store (copy the seed closure into a
//! tmpfs and bind it over `/nix` — overlayfs-over-virtiofs writes fail in
//! libkrun, and nix needs a writable store); write `/etc/resolv.conf`
//! (libkrun's `NET_FLAG_DHCP_CLIENT` brings up eth0 but NOT DNS, so point it
//! at gvproxy's gateway); then `nix build` the in-repo builder-VM flake,
//! copy the artifacts to `/out`, and power off. (Proven end-to-end on
//! aarch64; the persistent ext4 store is an optional RAM optimization —
//! plan 160 0b/follow-up.)
//!
//! The host side (`stage0::materialize_root_dir`) lays down the seed and
//! writes this binary as `/init`; libkrun's launch supplies eth0 + DHCP.

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

    /// Where nix runs from (its store paths are absolute `/nix/store/...`).
    const NIX_TARGET: &str = "/nix";
    /// Bind of the original (virtiofs) seed `/nix` so we can still read the
    /// seed store after mounting a fresh tmpfs over `/nix`.
    const NIX_SEED_RO: &str = "/nix-seed-ro";

    pub fn run() -> ExitCode {
        // libkrunfw's bundled kernel hands PID 1 a low RLIMIT_NOFILE on some
        // arches (x86_64 hit EMFILE copying the seed store to tmpfs). As PID 1
        // / root we can raise both soft and hard limits; do it before any
        // fd-heavy work.
        raise_fd_limit();
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

    /// Raise `RLIMIT_NOFILE` so the recursive seed-store copy (and `nix`
    /// itself) don't hit `EMFILE` under the bundled kernel's low default.
    /// Best-effort: as PID 1/root we can lift the hard limit, but a kernel
    /// ceiling below 65536 just clamps — we then take whatever the hard
    /// limit allows. Never fatal.
    fn raise_fd_limit() {
        // SAFETY: getrlimit/setrlimit with a valid resource id + struct ptr.
        unsafe {
            let want = libc::rlimit {
                rlim_cur: 65536,
                rlim_max: 65536,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                return;
            }
            // Hard ceiling below 65536: raise the soft limit to the hard limit.
            let mut cur = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) == 0 {
                cur.rlim_cur = cur.rlim_max;
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &cur);
            }
        }
    }

    /// Mounts the pseudo-filesystems + the virtio-fs shares, then makes
    /// `/nix` a writable store. No apk, no networking (libkrun supplies eth0).
    fn setup() -> Result<(), String> {
        mount_pseudofs()?;
        // `/dev/null` insurance — some libkrun set_root boots reach
        // userspace without it, which then masks every `2>/dev/null`
        // downstream. `|| Ok` it: devtmpfs usually creates it.
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

        setup_nix_store()?;
        configure_nix_runtime()?;
        Ok(())
    }

    /// DNS + nix store state the seed rootfs doesn't ship. libkrun's
    /// `NET_FLAG_DHCP_CLIENT` brings eth0 up but doesn't write
    /// `/etc/resolv.conf`, so point it at gvproxy's default gateway/DNS
    /// (`192.168.127.1`); nix needs it to reach cache.nixos.org. Also seed
    /// the local store dirs so nix runs single-user (no daemon).
    fn configure_nix_runtime() -> Result<(), String> {
        std::fs::create_dir_all("/etc").map_err(|e| format!("create /etc: {e}"))?;
        std::fs::write("/etc/resolv.conf", b"nameserver 192.168.127.1\n")
            .map_err(|e| format!("write /etc/resolv.conf: {e}"))?;
        for d in ["/nix/var", "/nix/var/nix", "/nix/var/log/nix"] {
            std::fs::create_dir_all(d).map_err(|e| format!("create {d}: {e}"))?;
        }
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

    /// Make `/nix` a writable, non-virtiofs store. The seed `/nix` arrives on
    /// the libkrun virtiofs RootDir; overlayfs-over-virtiofs writes fail
    /// (`nix build` → `creating /nix/store/.links: ECONNRESET` — a FUSE
    /// backend error). So instead: bind the original (virtiofs) `/nix` aside,
    /// mount a fresh **tmpfs** at `/nix`, and copy the seed closure into it.
    /// nix then runs entirely on tmpfs (case-sensitive, writable, no FUSE).
    ///
    /// First cut for the boot proof: a full-tmpfs store can exhaust RAM on
    /// the full builder-VM build — the persistent ext4 `/dev/vda` (bootstrap
    /// e2fsprogs via nix, mkfs, copy the store onto it) is the production
    /// follow-up (plan 160).
    fn setup_nix_store() -> Result<(), String> {
        // Copy BEFORE hiding the seed: mount a tmpfs at NIX_SEED_RO, copy the
        // seed `/nix/store` (still directly readable on the virtiofs root)
        // into it, then bind it over `/nix`. nix then runs from the tmpfs.
        std::fs::create_dir_all(NIX_SEED_RO).map_err(|e| format!("create {NIX_SEED_RO}: {e}"))?;
        mount_fs("tmpfs", NIX_SEED_RO, "tmpfs")?;
        let seed_store = Path::new(NIX_TARGET).join("store");
        let dst_store = Path::new(NIX_SEED_RO).join("store");
        std::fs::create_dir_all(&dst_store)
            .map_err(|e| format!("create {}: {e}", dst_store.display()))?;
        let n_src = std::fs::read_dir(&seed_store)
            .map(|d| d.count())
            .unwrap_or(0);
        copy_tree(&seed_store, &dst_store)
            .map_err(|e| format!("copying seed nix store to tmpfs: {e}"))?;
        let n_dst = std::fs::read_dir(&dst_store)
            .map(|d| d.count())
            .unwrap_or(0);
        eprintln!("stage0-init: copied seed store: {n_src} -> {n_dst} entries");
        // Now make the tmpfs copy be `/nix`.
        bind_mount(NIX_SEED_RO, NIX_TARGET)?;
        Ok(())
    }

    /// Recursively copy `src` -> `dst` preserving symlinks + file modes
    /// (the seed has no `cp`). Iterative to avoid deep-tree recursion limits.
    /// Hardlinks degrade to copies — fine for a one-shot bootstrap store.
    fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
        let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
        while let Some((from_dir, to_dir)) = stack.pop() {
            std::fs::create_dir_all(&to_dir)?;
            for entry in std::fs::read_dir(&from_dir)? {
                let entry = entry?;
                let ft = entry.file_type()?;
                let from = entry.path();
                let to = to_dir.join(entry.file_name());
                if ft.is_symlink() {
                    let target = std::fs::read_link(&from)?;
                    let _ = std::fs::remove_file(&to);
                    std::os::unix::fs::symlink(&target, &to)?;
                } else if ft.is_dir() {
                    stack.push((from, to));
                } else {
                    std::fs::copy(&from, &to)?; // preserves permissions
                }
            }
        }
        Ok(())
    }

    /// `nix build` the builder-VM flake, then copy kernel + rootfs to /out.
    /// The host-side contract (`/out/stage0-build.conf`, output modes) is the
    /// same one `dev up` / `kernel build` write.
    fn build_and_copy() -> Result<(), String> {
        let nix = find_seed_bin("nix")?;
        let cacert = find_seed_cacert()?;

        // Env: HOME / MVM_WORKSPACE_PATH / MVM_HOST_BIN_DIR for the nix build.
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
            // Force single-user (local store) — the seed has no nix-daemon;
            // an empty NIX_REMOTE makes nix build directly as root.
            std::env::set_var("NIX_REMOTE", "");
            if !nix_path.is_empty() {
                std::env::set_var("PATH", nix_path);
            }
        }

        // Console diagnostics (the console.log persists across the power-off;
        // /out gets cleaned up on failure). Confirms the seed nix is runnable
        // before the long build.
        eprintln!("stage0-init: nix = {}", nix.display());
        match Command::new(&nix).arg("--version").output() {
            Ok(o) => eprintln!(
                "stage0-init: nix --version: {}{}",
                String::from_utf8_lossy(&o.stdout).trim(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => eprintln!("stage0-init: nix --version failed to spawn: {e}"),
        }

        // Optional host-dropped build config (single-attr / kernel-only
        // modes); absent it, build the full image.
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
                // Single-user root bootstrap: the seed has no `nixbld` build
                // users + no daemon, so build directly as root (empty
                // build-users-group). Keep the DEFAULT sandbox — it gives
                // each build a clean env (its own /bin/sh + toolchain),
                // independent of the minimal seed rootfs; disabling it makes
                // builds fail on the seed's missing `/bin`, `gcc`, etc.
                "--option",
                "build-users-group",
                "",
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
        // Persist the full log to /out (a virtio-fs share) for host-side
        // post-mortem at ~/.cache/mvm/builder-vm/.../nix-stderr.log.
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

    /// Output by mode: image = kernel + rootfs.ext4 + cmdline; kernel =
    /// kernel only; rootfs = rootfs + cmdline only.
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
        // The nix seed rootfs is minimal (no /tmp, /run, …) and `mount(2)`
        // needs the target dir to exist — create it first.
        let _ = std::fs::create_dir_all(target);
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
    /// host-dropped build conf — the host only ever writes two plain
    /// assignments (`MVM_STAGE0_BUILD_ATTR`, `MVM_STAGE0_OUTPUT_MODE`).
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
