//! PID 1 of the Stage 0 bootstrap VM — the **nix-tarball seed**.
//! Boots under **two** builder backends (selected by the `mvm.backend=qemu`
//! kernel cmdline marker), carrying the official Nix release tarball's
//! `/nix/store` + this binary as `/init` — no Alpine, no apk, no busybox.
//!
//! **libkrun** (macOS/aarch64): the seed root arrives over virtiofs
//! (`krun_set_root`) on libkrunfw's bundled kernel; `/out` and `/mvm-bins`
//! stay virtio-fs, while `/work` prefers an ext4 disk identified by volume
//! label (`nix build` reading a large workspace tree through
//! virtio-fs-over-FUSE exhausts libkrun's virtio-fs handle pool — "Too many
//! open files" — so the host packs it onto a block device instead; falls
//! back to the old `"work"` virtio-fs tag when no such disk is attached); we
//! copy the seed `/nix/store` into a tmpfs and bind it over `/nix` (virtiofs
//! writes fail under FUSE); outbound fetches go through the shared vsock
//! egress proxy. Proven E2E on aarch64.
//!
//! **QEMU** (Linux/x86_64): the stock distro kernel +
//! initramfs mount the seed as an **ext4** root (`/dev/vda`, writable — so
//! `/nix` needs no tmpfs copy), shares are ext4 block disks (`vdb`/`vdc`/`vdd`),
//! and outbound fetches go through the same vsock egress proxy as every other
//! backend. Proven E2E on x86_64 (kernel built + copied to `/out`).
//!
//! Either way: `nix build` the in-repo builder-VM flake, copy the artifacts to
//! `/out`, and power off. The host side (`stage0::materialize_root_dir` /
//! `qemu_builder`) lays down the seed and writes this binary as `/init`.

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
        // is cross-compiled to aarch64-musl + embedded by
        // mvm-cli/build.rs) so workspace builds stay green.
        eprintln!("stage0-init: only runs as PID 1 inside the Linux Stage 0 guest");
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use sha2::{Digest, Sha256};
    use std::net::{SocketAddr, TcpStream};
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    const VSOCK_EGRESS_PROXY_URL: &str = mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_URL;
    const VSOCK_EGRESS_NO_PROXY: &str = "127.0.0.1,localhost";
    const VSOCK_EGRESS_PROXY_LISTEN_ADDR: &str = mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN;
    const VSOCK_EGRESS_PROXY_READY_TIMEOUT: Duration = Duration::from_secs(5);
    const VSOCK_EGRESS_PORT_ENV: &str = "MVM_EGRESS_VSOCK_PORT";
    /// Marks a store error the tmpfs fallback must not swallow.
    const FATAL_STORE_PREFIX: &str = "FATAL-STORE: ";
    const VSOCK_EGRESS_PORT_TOKEN_PREFIX: &str = "mvm.vsock_egress_port=";
    const QEMU_STAGE0_VSOCK_MODULES: &[&str] = &[
        "/mvm-bins/vsock-modules/vsock.ko",
        "/mvm-bins/vsock-modules/vmw_vsock_virtio_transport_common.ko",
        "/mvm-bins/vsock-modules/vmw_vsock_virtio_transport.ko",
    ];

    /// Where nix runs from (its store paths are absolute `/nix/store/...`).
    const NIX_TARGET: &str = "/nix";
    /// Bind of the original (virtiofs) seed `/nix` so we can still read the
    /// seed store after mounting a fresh tmpfs over `/nix`.
    const NIX_SEED_RO: &str = "/nix-seed-ro";
    /// Stage 0's dedicated persistent Nix-store block device. The libkrun
    /// launcher attaches this before the virtio-fs shares, so it enumerates as
    /// `/dev/vda`. QEMU uses `/dev/vda` as the rootfs, so this is libkrun-only.
    const LIBKRUN_STAGE0_NIX_STORE_DEV: &str = "/dev/vda";
    /// QEMU attaches seed, work, output, and host binaries first, then the
    /// read-only FlowMux identity. The persistent store follows as `/dev/vdf`.
    const QEMU_STAGE0_NIX_STORE_DEV: &str = "/dev/vdf";
    /// Mount point for the persistent Stage 0 Nix store before binding it over
    /// `/nix`.
    const STAGE0_NIX_STORE_MOUNT: &str = "/nix-stage0-store";
    /// Marker written next to `store/` and `var/` on the persistent Stage 0
    /// store. It binds reuse to the seed store fingerprint, not to mutable Nix
    /// build output added later.
    const STAGE0_NIX_STORE_MARKER: &str = "/nix-stage0-store/.mvm-stage0-nix-store";
    const STAGE0_NIX_STORE_MARKER_SCHEMA_VERSION: u32 = 1;

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
        match build_and_copy().and_then(|()| finalize_persistent_nix_store()) {
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

    /// True when stage0-init runs under the **QEMU** builder backend
    /// (Linux) vs **libkrun**. The QEMU launcher passes `mvm.backend=qemu`
    /// on the kernel cmdline; libkrun does not. This drives the remaining
    /// host-vs-VMM differences: share transport (ext4 block disks vs virtiofs)
    /// and the nix store layout (writable ext4 root vs tmpfs copy).
    fn is_qemu() -> bool {
        std::fs::read_to_string("/proc/cmdline")
            .map(|c| c.contains("mvm.backend=qemu"))
            .unwrap_or(false)
    }

    fn should_enable_vsock_egress(qemu: bool, cmdline: &str) -> bool {
        !qemu
            || cmdline
                .split_whitespace()
                .any(|tok| tok == "mvm.vsock_egress=1")
    }

    fn vsock_egress_port_from_cmdline(cmdline: &str) -> Option<u32> {
        cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(VSOCK_EGRESS_PORT_TOKEN_PREFIX))
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|port| *port > 0)
    }

    fn apply_vsock_egress_proxy_env(cmd: &mut Command) {
        cmd.env("ALL_PROXY", VSOCK_EGRESS_PROXY_URL)
            .env("HTTP_PROXY", VSOCK_EGRESS_PROXY_URL)
            .env("HTTPS_PROXY", VSOCK_EGRESS_PROXY_URL)
            .env("http_proxy", VSOCK_EGRESS_PROXY_URL)
            .env("https_proxy", VSOCK_EGRESS_PROXY_URL)
            .env("NO_PROXY", VSOCK_EGRESS_NO_PROXY)
            .env("no_proxy", VSOCK_EGRESS_NO_PROXY);
    }

    fn stage0_nix_config() -> String {
        "experimental-features = nix-command flakes\n\
         sandbox = false\n\
         build-users-group =\n\
         max-jobs = 1\n\
         cores = 0\n\
         connect-timeout = 30\n"
            .to_string()
    }

    fn best_effort_raise_loopback() {
        match mvm_agentd::guest_net::bring_iface_up("lo") {
            Ok(mvm_agentd::guest_net::GuestNetwork::Configured) => {
                eprintln!("stage0-init: brought loopback interface up")
            }
            // Unlike eth0 on a workload guest, a kernel with no `lo` is not a
            // tier — it is a kernel built without loopback. Say which it is
            // rather than reporting a generic bring-up failure.
            Ok(mvm_agentd::guest_net::GuestNetwork::NoInterface) => {
                eprintln!("stage0-init: no loopback interface exists in this guest")
            }
            Err(e) => eprintln!("stage0-init: bring_iface_up lo failed: {e}"),
        }
        let busybox = Path::new("/mvm-bins/busybox");
        if !busybox.is_file() {
            eprintln!(
                "stage0-init: {} missing; skipping loopback address helper",
                busybox.display()
            );
            return;
        }
        let ip_link_status = Command::new(busybox)
            .args(["ip", "link", "set", "lo", "up"])
            .status();
        if let Ok(status) = &ip_link_status
            && !status.success()
        {
            eprintln!(
                "stage0-init: busybox ip link set lo up exited {}",
                status.code().unwrap_or(-1)
            );
        }
        let _ = Command::new(busybox)
            .args(["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])
            .status();
    }

    fn af_vsock_available() -> bool {
        const AF_VSOCK: libc::c_int = 40;
        // SAFETY: socket(2) returns -1 on error or a valid fd we close immediately.
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return false;
        }
        // SAFETY: `fd` came from `socket` above and is still owned here.
        unsafe {
            libc::close(fd);
        }
        true
    }

    fn best_effort_load_qemu_vsock_modules() {
        if af_vsock_available() {
            eprintln!("stage0-init: AF_VSOCK already available");
            return;
        }
        for module in QEMU_STAGE0_VSOCK_MODULES {
            if !Path::new(module).is_file() {
                eprintln!("stage0-init: guest vsock module missing at {module}");
                continue;
            }
            match std::fs::OpenOptions::new().read(true).open(module) {
                Ok(file) => {
                    // SAFETY: `finit_module(2)` reads the owned module fd and never
                    // outlives `file`; flags=0, empty params string.
                    let rc = unsafe {
                        libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), c"".as_ptr(), 0)
                    };
                    if rc == 0 {
                        eprintln!("stage0-init: loaded guest vsock module {module}");
                    } else {
                        eprintln!(
                            "stage0-init: finit_module {module} failed: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
                Err(e) => eprintln!("stage0-init: open {module} for finit_module failed: {e}"),
            }
        }
        if af_vsock_available() {
            eprintln!("stage0-init: AF_VSOCK became available after loading guest modules");
        } else {
            eprintln!("stage0-init: AF_VSOCK still unavailable after loading guest modules");
        }
    }

    fn dump_vsock_egress_diagnostics() {
        if let Ok(state) = std::fs::read_to_string("/sys/class/net/lo/operstate") {
            eprintln!("stage0-init: lo operstate = {}", state.trim());
        }
        if let Ok(flags) = std::fs::read_to_string("/sys/class/net/lo/flags") {
            eprintln!("stage0-init: lo flags = {}", flags.trim());
        }
        if let Ok(net_dev) = std::fs::read_to_string("/proc/net/dev")
            && let Some(lo_line) = net_dev.lines().find(|line| line.contains("lo:"))
        {
            eprintln!("stage0-init: /proc/net/dev {}", lo_line.trim());
        }
        if let Ok(tcp_table) = std::fs::read_to_string("/proc/net/tcp") {
            let mut matched = false;
            for line in tcp_table.lines().filter(|line| line.contains(":0438")) {
                matched = true;
                eprintln!("stage0-init: /proc/net/tcp {line}");
            }
            if !matched {
                eprintln!("stage0-init: /proc/net/tcp has no listener/flow for :0438");
            }
        }
    }

    /// Fork the guest-local egress proxy. `Err` carries the probe the readiness
    /// decision will refuse on, so a client that never started and one that
    /// started and died reach the same single decision point.
    fn fork_vsock_egress_client(cmdline: &str) -> Result<Child, EgressProbe> {
        let egress_client = Path::new("/mvm-bins/mvm-egress-client");
        if !egress_client.is_file() {
            return Err(EgressProbe::ClientMissing(
                egress_client.display().to_string(),
            ));
        }
        if is_qemu() {
            best_effort_load_qemu_vsock_modules();
        }
        let mut cmd = Command::new(egress_client);
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        if let Some(port) = vsock_egress_port_from_cmdline(cmdline) {
            cmd.env(VSOCK_EGRESS_PORT_ENV, port.to_string());
        }
        match cmd.spawn() {
            Ok(child) => {
                eprintln!(
                    "stage0-init: forked mvm-egress-client pid={} from {}",
                    child.id(),
                    egress_client.display()
                );
                Ok(child)
            }
            Err(e) => Err(EgressProbe::ClientExited(format!("spawn failed: {e}"))),
        }
    }

    fn egress_child_exit_message(status: ExitStatus) -> String {
        if let Some(code) = status.code() {
            return format!("exit code {code}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return format!("signal {signal}");
            }
        }
        "unknown termination".to_string()
    }

    use mvm_build::egress_readiness::{EgressProbe, egress_readiness_outcome};

    fn probe_vsock_egress_proxy(mut child: Option<&mut Child>) -> EgressProbe {
        let Ok(proxy_addr) = VSOCK_EGRESS_PROXY_LISTEN_ADDR.parse::<SocketAddr>() else {
            return EgressProbe::BadListenAddr(VSOCK_EGRESS_PROXY_LISTEN_ADDR.to_string());
        };
        let deadline = Instant::now() + VSOCK_EGRESS_PROXY_READY_TIMEOUT;
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&proxy_addr, Duration::from_millis(200)).is_ok() {
                return EgressProbe::Ready;
            }
            if let Some(child) = child.as_deref_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return EgressProbe::ClientExited(egress_child_exit_message(status));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("stage0-init: could not poll mvm-egress-client readiness: {e}")
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        EgressProbe::TimedOut
    }

    /// Start the egress proxy and refuse to build without it. The returned
    /// child is kept alive by the caller for the rest of the boot.
    fn start_vsock_egress_if_requested(cmdline: &str) -> Result<Option<Child>, String> {
        if !should_enable_vsock_egress(is_qemu(), cmdline) {
            return Ok(None);
        }
        // The identity must be in /run/mvm before the client starts: it loads
        // both keys before it binds, so a missing drive surfaces as a proxy
        // that never came up rather than as anything naming the drive.
        if let Err(e) = mvm_agentd::flowmux_drive::provision_identity_from_drive() {
            let why = egress_readiness_outcome(EgressProbe::IdentityMissing(e.to_string()))
                .expect_err("IdentityMissing is a refusing probe");
            eprintln!("stage0-init: {why}");
            return Err(why);
        }
        let (child, probe) = match fork_vsock_egress_client(cmdline) {
            Ok(mut child) => {
                let probe = probe_vsock_egress_proxy(Some(&mut child));
                (Some(child), probe)
            }
            Err(probe) => (None, probe),
        };
        match egress_readiness_outcome(probe) {
            Ok(()) => {
                eprintln!(
                    "stage0-init: local vsock egress proxy ready at {}",
                    VSOCK_EGRESS_PROXY_LISTEN_ADDR
                );
                Ok(child)
            }
            Err(why) => {
                eprintln!("stage0-init: {why}");
                dump_vsock_egress_diagnostics();
                Err(why)
            }
        }
    }

    /// Mounts the pseudo-filesystems + the host shares, then makes `/nix` a
    /// writable store.
    fn setup() -> Result<(), String> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        sync_clock_from_host_epoch(&cmdline)?;
        mount_pseudofs()?;
        // `/dev/null` insurance — some libkrun set_root boots reach
        // userspace without it, which then masks every `2>/dev/null`
        // downstream. `|| Ok` it: devtmpfs usually creates it.
        if !Path::new("/dev/null").exists() {
            mknod_null();
        }

        let qemu = is_qemu();
        eprintln!(
            "stage0-init: backend = {}",
            if qemu { "qemu" } else { "libkrun" }
        );

        // Host shares. QEMU presents all three as ext4 block disks (the
        // initramfs already loaded virtio_blk for the ext4 root, so
        // vdb/vdc/vdd enumerate with no extra modules — no virtiofsd, no
        // 9p); order matches the device order on the QEMU cmdline (vda=seed
        // root, then work/out/mvm-bins). libkrun presents `/out` and
        // `/mvm-bins` over virtio-fs by tag; `/work` prefers an ext4 disk
        // too (`mount_libkrun_work_share`) — a large workspace read through
        // virtio-fs-over-FUSE exhausts libkrun's virtio-fs handle pool
        // (`nix build` fails with "Too many open files"), so the host packs
        // it onto a block device whenever it attaches one.
        if qemu {
            mount_shares(&[
                ("/dev/vdb", "/work", "ext4"),
                ("/dev/vdc", "/out", "ext4"),
                ("/dev/vdd", "/mvm-bins", "ext4"),
            ])?;
        } else {
            mount_libkrun_work_share()?;
            mount_shares(&[
                ("out", "/out", "virtiofs"),
                ("mvm-bins", "/mvm-bins", "virtiofs"),
            ])?;
        }

        setup_nix_store(qemu)?;
        if should_enable_vsock_egress(qemu, &cmdline) {
            best_effort_raise_loopback();
            mvm_agentd::guest_net::seed_loopback_resolver()
                .map_err(|e| format!("seed loopback DNS resolver: {e}"))?;
        }
        // Held for the rest of the boot: dropping the handle would not kill the
        // proxy, but keeping it lets a later reaper see the same child.
        let _egress_child = start_vsock_egress_if_requested(&cmdline)?;
        configure_nix_runtime()?;
        Ok(())
    }

    /// Seed the RTC-less Stage 0 guest clock before starting the egress client
    /// or Nix. Without this, TLS validation observes 1970 and every fresh
    /// bootstrap download fails with a misleading certificate error.
    fn sync_clock_from_host_epoch(cmdline: &str) -> Result<(), String> {
        let Some(epoch_seconds) =
            mvm_vmm::host::boot_config::builder_hostepoch_from_cmdline(cmdline)
        else {
            return Ok(());
        };
        mvm_agentd::restore_clock::resync(epoch_seconds)
            .map_err(|error| format!("set wall clock from host epoch: {error}"))?;
        eprintln!("stage0-init: wall clock set from host epoch {epoch_seconds}");
        Ok(())
    }

    /// Seed the local Nix store directories the bootstrap rootfs doesn't ship.
    fn configure_nix_runtime() -> Result<(), String> {
        std::fs::create_dir_all("/etc").map_err(|e| format!("create /etc: {e}"))?;
        for d in ["/nix/var", "/nix/var/nix", "/nix/var/log/nix"] {
            std::fs::create_dir_all(d).map_err(|e| format!("create {d}: {e}"))?;
        }
        ensure_bin_sh_from_seed()?;
        Ok(())
    }

    fn ensure_bin_sh_from_seed() -> Result<(), String> {
        if Path::new("/bin/sh").exists() {
            return Ok(());
        }
        std::fs::create_dir_all("/bin").map_err(|e| format!("create /bin: {e}"))?;
        let seed_sh = find_seed_bin("sh").or_else(|_| find_seed_bin("bash"))?;
        std::os::unix::fs::symlink(&seed_sh, "/bin/sh")
            .map_err(|e| format!("symlink /bin/sh -> {}: {e}", seed_sh.display()))?;
        eprintln!(
            "stage0-init: installed /bin/sh shim from {}",
            seed_sh.display()
        );
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
    /// backend error).
    ///
    /// Fast path: mount the dedicated persistent ext4 `/dev/vda`, seed it once
    /// from the verified RootDir store, then bind it over `/nix` on every later
    /// boot. If the current seed lacks `mkfs.ext4` and the disk is still blank,
    /// fall back to the old tmpfs copy so the bootstrap remains functional.
    fn setup_nix_store(qemu: bool) -> Result<(), String> {
        match setup_persistent_nix_store(qemu) {
            Ok(()) => return Ok(()),
            // A fatal store fault is not something to degrade around: the tmpfs
            // is sized by guest RAM, so continuing turns a nameable disk problem
            // into an out-of-space error far from its cause.
            Err(e) if e.starts_with(FATAL_STORE_PREFIX) => {
                return Err(e.trim_start_matches(FATAL_STORE_PREFIX).to_string());
            }
            Err(e) => eprintln!(
                "stage0-init: persistent Stage 0 /nix store unavailable ({e}); falling back to tmpfs seed copy"
            ),
        }

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

    fn stage0_nix_store_device(qemu: bool) -> &'static str {
        if qemu {
            QEMU_STAGE0_NIX_STORE_DEV
        } else {
            LIBKRUN_STAGE0_NIX_STORE_DEV
        }
    }

    /// Size of a block device in bytes, via its sysfs 512-byte block count.
    ///
    /// Read from sysfs rather than by seeking the device: a seek would need the
    /// device open, and the point of this check is to refuse it before trusting
    /// it enough to mount.
    fn block_device_bytes(device: &str) -> Option<u64> {
        let name = Path::new(device).file_name()?.to_str()?;
        let raw = std::fs::read_to_string(format!("/sys/class/block/{name}/size")).ok()?;
        raw.trim().parse::<u64>().ok().map(|blocks| blocks * 512)
    }

    fn setup_persistent_nix_store(qemu: bool) -> Result<(), String> {
        // Prefer the ext4 label. The device letter is a function of how many
        // block devices the backend attached ahead of this one, so adding a
        // drive silently re-letters every disk behind it — which is how this
        // guest came to mount a 32 KiB identity image as its Nix store, fail,
        // and fall back to a tmpfs too small for a kernel source tree. The
        // letter stays as a fallback for a store image formatted before it
        // carried a label.
        let label = mvm_build::rootfs::STAGE0_NIX_STORE_EXT4_LABEL;
        // Every attached virtio disk, not a fixed prefix of them. The QEMU path
        // attaches seed, work, out, mvm-bins and the FlowMux identity ahead of
        // the store, so a four-entry list stopped two devices short of the disk
        // it was looking for — the lookup could never succeed there, fell back
        // to enumeration order, and picked the 32 KiB identity image.
        let by_label = find_labeled_ext4_disk_among(virtio_block_devices(), label)
            .map(|d| d.to_string_lossy().into_owned());
        let device: &str = match by_label.as_deref() {
            Some(dev) => {
                eprintln!("stage0-init: Stage 0 Nix store is {dev} (label {label:?})");
                dev
            }
            None => {
                let dev = stage0_nix_store_device(qemu);
                eprintln!(
                    "stage0-init: no disk carries the ext4 label {label:?}; \
                     falling back to {dev} by enumeration order"
                );
                dev
            }
        };
        if !Path::new(device).exists() {
            return Err(format!("{device} is not present"));
        }

        // A device that is present but far too small is a misidentified disk,
        // not an empty store. Refuse it here rather than letting the caller
        // degrade to a RAM-sized tmpfs whose exhaustion surfaces thousands of
        // lines later as an unrelated-looking build error.
        if let Some(bytes) = block_device_bytes(device)
            && bytes < mvm_build::store_readiness::MIN_PLAUSIBLE_STORE_BYTES
        {
            return Err(FATAL_STORE_PREFIX.to_string()
                + &mvm_build::store_readiness::store_readiness_outcome(
                    mvm_build::store_readiness::StoreProbe::ImplausiblySmall {
                        device: device.to_string(),
                        bytes,
                    },
                )
                .expect_err("an undersized store device must refuse"));
        }

        std::fs::create_dir_all(STAGE0_NIX_STORE_MOUNT)
            .map_err(|e| format!("create {STAGE0_NIX_STORE_MOUNT}: {e}"))?;
        mount_stage0_nix_store(device)?;

        let seed_store = Path::new(NIX_TARGET).join("store");
        let expected_marker = stage0_nix_store_marker(&seed_store)?;
        if persistent_nix_store_matches(&expected_marker)? {
            eprintln!("stage0-init: reusing persistent Stage 0 Nix store at {device}");
            bind_mount(STAGE0_NIX_STORE_MOUNT, NIX_TARGET)?;
            return Ok(());
        }
        if persistent_nix_store_matches_seed(&seed_store)? {
            std::fs::write(STAGE0_NIX_STORE_MARKER, expected_marker)
                .map_err(|e| format!("write {STAGE0_NIX_STORE_MARKER}: {e}"))?;
            eprintln!("stage0-init: adopting host-prepopulated Stage 0 Nix store at {device}");
            bind_mount(STAGE0_NIX_STORE_MOUNT, NIX_TARGET)?;
            return Ok(());
        }

        eprintln!("stage0-init: initializing persistent Stage 0 Nix store at {device}");
        clear_dir_children(Path::new(STAGE0_NIX_STORE_MOUNT))
            .map_err(|e| format!("clearing {STAGE0_NIX_STORE_MOUNT}: {e}"))?;
        let dst_store = Path::new(STAGE0_NIX_STORE_MOUNT).join("store");
        std::fs::create_dir_all(&dst_store)
            .map_err(|e| format!("create {}: {e}", dst_store.display()))?;
        let n_src = std::fs::read_dir(&seed_store)
            .map(|d| d.count())
            .unwrap_or(0);
        copy_tree(&seed_store, &dst_store)
            .map_err(|e| format!("copying seed nix store to persistent disk: {e}"))?;
        let n_dst = std::fs::read_dir(&dst_store)
            .map(|d| d.count())
            .unwrap_or(0);
        std::fs::write(STAGE0_NIX_STORE_MARKER, expected_marker)
            .map_err(|e| format!("write {STAGE0_NIX_STORE_MARKER}: {e}"))?;
        eprintln!("stage0-init: seeded persistent store: {n_src} -> {n_dst} entries");
        bind_mount(STAGE0_NIX_STORE_MOUNT, NIX_TARGET)?;
        Ok(())
    }

    /// Flush and cleanly unmount the persistent store before reporting Stage 0
    /// success. `reboot(RB_POWER_OFF)` alone can surface delayed ext4 failures
    /// only after the success marker has reached the console, which makes the
    /// host accept a corrupt cache. The explicit unmount moves all filesystem
    /// writeback ahead of that marker and makes kernel error accounting part of
    /// the guest result.
    fn finalize_persistent_nix_store() -> Result<(), String> {
        if !persistent_store_finalization_required(is_qemu(), is_mountpoint(STAGE0_NIX_STORE_MOUNT))
        {
            return Ok(());
        }

        // SAFETY: sync() takes no arguments and only flushes filesystem state.
        unsafe {
            libc::sync();
        }
        reject_ext4_errors(Path::new("/sys/fs/ext4/vda/errors_count"))?;
        unmount(NIX_TARGET)?;
        unmount(STAGE0_NIX_STORE_MOUNT)?;
        Ok(())
    }

    fn persistent_store_finalization_required(qemu: bool, persistent_mounted: bool) -> bool {
        !qemu && persistent_mounted
    }

    fn reject_ext4_errors(errors_count_path: &Path) -> Result<(), String> {
        let raw = std::fs::read_to_string(errors_count_path)
            .map_err(|e| format!("read {}: {e}", errors_count_path.display()))?;
        let count = raw.trim().parse::<u64>().map_err(|e| {
            format!(
                "parse {} value {raw:?} as an ext4 error count: {e}",
                errors_count_path.display()
            )
        })?;
        if count == 0 {
            Ok(())
        } else {
            Err(format!(
                "persistent Stage 0 ext4 store reported {count} filesystem error(s)"
            ))
        }
    }

    fn mount_stage0_nix_store(device: &str) -> Result<(), String> {
        match mount_fs(device, STAGE0_NIX_STORE_MOUNT, "ext4") {
            Ok(()) => return Ok(()),
            Err(first_mount_err) => {
                let Some(mkfs) = find_mkfs_ext4() else {
                    return Err(format!(
                        "{first_mount_err}; mkfs.ext4 not available in seed"
                    ));
                };
                eprintln!(
                    "stage0-init: formatting {device} for persistent Stage 0 store ({first_mount_err})"
                );
                format_ext4_with(&mkfs, device)?;
            }
        }
        mount_fs(device, STAGE0_NIX_STORE_MOUNT, "ext4")
    }

    fn find_mkfs_ext4() -> Option<PathBuf> {
        [
            "/sbin/mkfs.ext4",
            "/bin/mkfs.ext4",
            "/usr/sbin/mkfs.ext4",
            "/usr/bin/mkfs.ext4",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
    }

    fn format_ext4_with(mkfs: &Path, dev: &str) -> Result<(), String> {
        let blocks_4k = device_size_4k_blocks(dev)?;
        let status = ext4_format_command(mkfs, dev, blocks_4k)
            .status()
            .map_err(|e| format!("spawn {}: {e}", mkfs.display()))?;
        if !status.success() {
            return Err(format!(
                "{} exit {}",
                mkfs.display(),
                status.code().unwrap_or(-1)
            ));
        }
        Ok(())
    }

    fn ext4_format_command(mkfs: &Path, dev: &str, blocks_4k: u64) -> Command {
        let mut command = Command::new(mkfs);
        command
            .args(["-F", "-q", "-b", "4096", "-L"])
            .arg(mvm_build::rootfs::STAGE0_NIX_STORE_EXT4_LABEL)
            .arg(dev)
            .arg(blocks_4k.to_string());
        command
    }

    fn device_size_4k_blocks(dev: &str) -> Result<u64, String> {
        let basename = Path::new(dev)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("device path {dev} has no basename"))?;
        let sys_path = format!("/sys/class/block/{basename}/size");
        let sectors_str =
            std::fs::read_to_string(&sys_path).map_err(|e| format!("read {sys_path}: {e}"))?;
        let sectors: u64 = sectors_str
            .trim()
            .parse()
            .map_err(|e| format!("parse {sys_path} = {sectors_str:?}: {e}"))?;
        Ok(sectors / 8)
    }

    fn persistent_nix_store_matches(expected_marker: &str) -> Result<bool, String> {
        let mounted_store = Path::new(STAGE0_NIX_STORE_MOUNT).join("store");
        if !mounted_store.is_dir() {
            return Ok(false);
        }
        if !std::fs::read_to_string(STAGE0_NIX_STORE_MARKER)
            .is_ok_and(|marker| marker == expected_marker)
        {
            return Ok(false);
        }
        if !seed_store_has_required_runtime(&mounted_store)? {
            eprintln!(
                "stage0-init: persistent Stage 0 store marker matches but the reused seed \
                 runtime is incomplete; re-seeding the store"
            );
            return Ok(false);
        }
        Ok(true)
    }

    fn persistent_nix_store_matches_seed(seed_store: &Path) -> Result<bool, String> {
        let mounted_store = Path::new(STAGE0_NIX_STORE_MOUNT).join("store");
        if !mounted_store.is_dir() {
            return Ok(false);
        }
        Ok(seed_store_entries_hash(&mounted_store)? == seed_store_entries_hash(seed_store)?)
    }

    fn stage0_nix_store_marker(seed_store: &Path) -> Result<String, String> {
        Ok(format!(
            "schema_version={STAGE0_NIX_STORE_MARKER_SCHEMA_VERSION}\nseed_store_entries_sha256={}\n",
            seed_store_entries_hash(seed_store)?
        ))
    }

    fn seed_store_entries_hash(seed_store: &Path) -> Result<String, String> {
        let mut entries = std::fs::read_dir(seed_store)
            .map_err(|e| format!("read {}: {e}", seed_store.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .map_err(|e| format!("read entry under {}: {e}", seed_store.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_unstable();

        let mut hasher = Sha256::new();
        for entry in entries {
            hasher.update(entry.as_bytes());
            hasher.update(b"\n");
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn clear_dir_children(dir: &Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                std::fs::remove_dir_all(path)?;
            } else {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    /// Nix builds unsandboxed inside the Stage 0 guest (no user namespaces
    /// available), so it uses `/homeless-shelter` as the builder's HOME and
    /// **refuses to run** if that directory already exists — its no-sandbox
    /// purity check. A build that was interrupted mid-flight (power-off, OOM, a
    /// store fault) leaves the dir behind on the persistent guest root, and
    /// because the root is reused across boots whenever its seed marker matches,
    /// every later bootstrap then fails with
    /// `error: home directory "/homeless-shelter" exists`. Remove a stale one
    /// before invoking nix so a crashed prior run self-heals instead of wedging
    /// the bootstrap. `root` is the filesystem root (`/` in the guest; a tempdir
    /// under test). A `NotFound` is the normal clean-boot case, not an error.
    fn purge_stale_nix_builder_home(root: &Path) -> std::io::Result<()> {
        let home = root.join("homeless-shelter");
        match std::fs::remove_dir_all(&home) {
            Ok(()) => {
                eprintln!(
                    "stage0-init: removed stale nix builder home {}",
                    home.display()
                );
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
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
    /// same one `mvmctl bootstrap` / `kernel build` write.
    fn build_and_copy() -> Result<(), String> {
        let nix = find_seed_bin("nix")?;
        let cacert = find_seed_cacert()?;
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();

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
            // The Stage 0 VM is already the isolation boundary. Disabling the
            // in-guest Nix sandbox keeps fixed-output fetchers on the same
            // proxy-aware environment as the top-level `nix build`, instead of
            // dropping the egress proxy vars inside sandboxed derivations.
            std::env::set_var("NIX_CONFIG", stage0_nix_config());
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

        // Clear a `/homeless-shelter` left by a crashed prior build before nix's
        // unsandboxed purity check trips on it and wedges the bootstrap.
        purge_stale_nix_builder_home(Path::new("/"))
            .map_err(|e| format!("clearing stale nix builder home: {e}"))?;

        eprintln!("stage0-init: building {flake_ref} (output_mode={mode})");
        let mut cmd = Command::new(&nix);
        cmd.args([
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
        ]);
        if should_enable_vsock_egress(is_qemu(), &cmdline) {
            apply_vsock_egress_proxy_env(&mut cmd);
        }
        // Echo nix's `--print-build-logs` to the guest's own stderr, which the
        // host captures to `console.log` live — that's what makes the otherwise-
        // silent multi-minute build tailable from the host.
        let (status, stderr_log, stdout) =
            run_streaming(cmd, &mut std::io::stderr()).map_err(|e| format!("nix build: {e}"))?;

        // Persist the full log to /out (a virtio-fs share) for host-side
        // post-mortem at ~/.mvm/cache/builder-vm/.../nix-stderr.log.
        let _ = std::fs::write("/out/nix-stderr.log", &stderr_log);
        if !status.success() {
            return Err(format!("nix build exit {}", status.code().unwrap_or(-1)));
        }
        let store_path = stdout.trim().to_string();
        if store_path.is_empty() {
            return Err("nix build emitted no /nix/store path".into());
        }
        copy_artifacts(Path::new(&store_path), &mode)?;

        // Best-effort: also emit the resolved `.config` so the host can report
        // the `=y` symbol count without a CI round-trip. The configfile is a
        // cached build dep of the kernel just built, so this realises instantly.
        // A failure here never fails the kernel build — the kernel is the
        // artifact that matters.
        if mode == "kernel"
            && let Some(config_attr) = conf.get("MVM_STAGE0_CONFIG_ATTR")
            && let Err(e) = emit_resolved_config(&nix, &arch, config_attr)
        {
            eprintln!("stage0-init: skipping kernel-config emit: {e}");
        }
        Ok(())
    }

    /// Realise the resolved-`.config` flake attr and copy it to
    /// `/out/mvm-kernel.config`. Cheap — it's a cached dependency of the
    /// kernel just built.
    fn emit_resolved_config(nix: &Path, arch: &str, config_attr: &str) -> Result<(), String> {
        let flake_ref =
            format!("path:/work/nix/images/builder-vm#packages.{arch}-linux.{config_attr}");
        let mut cmd = Command::new(nix);
        cmd.args([
            "build",
            &flake_ref,
            "--extra-experimental-features",
            "nix-command flakes",
            "--option",
            "build-users-group",
            "",
            "--max-jobs",
            "1",
            "--no-link",
            "--no-write-lock-file",
            "--impure",
            "--print-out-paths",
        ]);
        let out = cmd.output().map_err(|e| format!("nix build config: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nix build config exit {}",
                out.status.code().unwrap_or(-1)
            ));
        }
        let store_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if store_path.is_empty() {
            return Err("config build emitted no /nix/store path".into());
        }
        copy_deref(Path::new(&store_path), Path::new("/out/mvm-kernel.config"))
    }

    /// Spawn `cmd`, streaming its stderr line-by-line to `live` (flushed per
    /// line so a host tailing the console sees progress as it arrives) while
    /// accumulating the full stderr for a post-mortem log, and capturing stdout
    /// (nix's single trailing out-path). Returns `(status, stderr_log, stdout)`.
    ///
    /// Draining stderr to EOF before reading stdout can't deadlock here: nix
    /// writes only the short out-path to stdout (well under the pipe buffer), so
    /// it never blocks waiting for us to read it.
    fn run_streaming(
        mut cmd: Command,
        live: &mut dyn std::io::Write,
    ) -> Result<(std::process::ExitStatus, Vec<u8>, String), String> {
        use std::io::{BufRead, Read};
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;

        let mut stderr_log: Vec<u8> = Vec::new();
        if let Some(child_stderr) = child.stderr.take() {
            let reader = std::io::BufReader::new(child_stderr);
            for chunk in reader.split(b'\n') {
                let Ok(mut chunk) = chunk else { break };
                chunk.push(b'\n');
                let _ = live.write_all(&chunk);
                let _ = live.flush();
                stderr_log.extend_from_slice(&chunk);
            }
        }
        let mut stdout = String::new();
        if let Some(mut child_stdout) = child.stdout.take() {
            let _ = child_stdout.read_to_string(&mut stdout);
        }
        let status = child.wait().map_err(|e| format!("wait: {e}"))?;
        Ok((status, stderr_log, stdout))
    }

    /// Output by mode: image = kernel + rootfs.ext4 + cmdline + manifest;
    /// kernel = kernel only; rootfs = rootfs + cmdline (+ manifest when
    /// present); sdk-sidecar = the resolver's three-file sidecar contract.
    fn copy_artifacts(out: &Path, mode: &str) -> Result<(), String> {
        copy_artifacts_into(out, mode, Path::new("/out"))
    }

    fn copy_artifacts_into(out: &Path, mode: &str, out_root: &Path) -> Result<(), String> {
        if mode == "sdk-sidecar" {
            for name in [
                mvm_fs::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE,
                mvm_fs::sdk_sidecar::SDK_SIDECAR_VERSION_FILE,
                mvm_fs::overlay::CHECKSUM_MANIFEST_FILE,
            ] {
                let source = out.join(name);
                if !source.is_file() {
                    return Err(format!(
                        "SDK sidecar output {} is missing {name}",
                        out.display()
                    ));
                }
                copy_deref(&source, &out_root.join(name))?;
            }
            return Ok(());
        }
        if mode != "rootfs" {
            let kernel = ["vmlinux", "Image", "bzImage"]
                .iter()
                .map(|n| out.join(n))
                .find(|p| p.is_file())
                .ok_or_else(|| format!("no kernel in {}", out.display()))?;
            copy_deref(&kernel, &out_root.join("vmlinux"))?;
        }
        if mode != "kernel" {
            let rootfs = out.join("rootfs.ext4");
            if !rootfs.is_file() {
                return Err(format!("no rootfs.ext4 in {}", out.display()));
            }
            copy_deref(&rootfs, &out_root.join("rootfs.ext4"))?;
            let cmdline = out.join("cmdline.txt");
            if cmdline.is_file() {
                let _ = copy_deref(&cmdline, &out_root.join("cmdline.txt"));
            }
            let manifest = out.join("manifest.json");
            if manifest.is_file() {
                let _ = copy_deref(&manifest, &out_root.join("manifest.json"));
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

    /// Like [`mount_fs`], but read-only. The host attaches the `/work` ext4
    /// disk read-only at the libkrun layer (`krun_add_disk`'s `read_only`
    /// flag), and a Linux block device that reports itself read-only refuses
    /// a plain read-write mount — so this must pass `MS_RDONLY` rather than
    /// reusing `mount_fs`. Mirrors the existing read-only virtio-fs mounts
    /// the steady-state builder guest already does for the same `/work`
    /// share (`mvm-host-vm-init`'s `virtiofs_mount_flags`).
    fn mount_fs_ro(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some(source),
            target,
            Some(fstype),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("mount {source} -> {target} ({fstype}) read-only: {e}"))
    }

    // The ext4 label probe is shared with every other guest init through
    // `mvm_agentd::flowmux_drive`: Stage 0 mounts `/work` by label and the
    // identity drive by label, and a second copy of the superblock layout is
    // exactly the kind of duplicate that drifts.
    use mvm_agentd::flowmux_drive::{find_labeled_ext4_disk_among, virtio_block_devices};

    /// Mounts `/work` for the libkrun backend. Prefers the ext4 disk
    /// carrying [`mvm_build::rootfs::STAGE0_WORK_EXT4_LABEL`] — the host
    /// packs the workspace onto a block device because `nix build` reading
    /// a large tree through virtio-fs-over-FUSE exhausts libkrun's
    /// virtio-fs handle pool ("Too many open files"). Falls back to the
    /// `"work"` virtio-fs tag when no such disk is attached, the shape
    /// every caller used before this disk existed.
    fn mount_libkrun_work_share() -> Result<(), String> {
        std::fs::create_dir_all("/work").map_err(|e| format!("create /work: {e}"))?;
        let label = mvm_build::rootfs::STAGE0_WORK_EXT4_LABEL;
        // Same enumeration as the store lookup, for the same reason: a fixed
        // prefix of device letters is the positional assumption the label
        // removes, and /work is not guaranteed to land inside it either.
        match find_labeled_ext4_disk_among(virtio_block_devices(), label) {
            Some(dev) => {
                let dev = dev.to_string_lossy().into_owned();
                mount_fs_ro(&dev, "/work", "ext4")?;
                eprintln!("stage0-init: mounted /work from ext4 disk {dev} (label {label:?})");
            }
            None => {
                mount_fs("work", "/work", "virtiofs")?;
                eprintln!("stage0-init: mounted /work from virtiofs (no {label:?} disk attached)");
            }
        }
        if !is_mountpoint("/work") {
            return Err("/work (ext4-or-virtiofs) mount did not take".to_string());
        }
        Ok(())
    }

    /// Create + mount each `(source, target, fstype)` share in order,
    /// verifying the mount took. Shared by the QEMU shares (all ext4) and
    /// the libkrun `/out` + `/mvm-bins` shares (virtio-fs); `/work` on
    /// libkrun goes through [`mount_libkrun_work_share`] instead, since it
    /// picks its own source/fstype/flags.
    fn mount_shares(shares: &[(&str, &str, &str)]) -> Result<(), String> {
        for (source, target, fstype) in shares {
            std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
            mount_fs(source, target, fstype)?;
            if !is_mountpoint(target) {
                return Err(format!("{target} ({fstype}) mount did not take"));
            }
        }
        Ok(())
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

    fn unmount(target: &str) -> Result<(), String> {
        nix::mount::umount(target).map_err(|e| format!("unmount {target}: {e}"))
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
    fn find_seed_bin_in(store: &Path, bin: &str) -> Result<PathBuf, String> {
        let entries =
            std::fs::read_dir(store).map_err(|e| format!("read {}: {e}", store.display()))?;
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

    fn find_seed_bin(bin: &str) -> Result<PathBuf, String> {
        find_seed_bin_in(Path::new("/nix/store"), bin)
    }

    /// Find the seed's CA bundle (`nss-cacert`) for `NIX_SSL_CERT_FILE`.
    fn find_seed_cacert_in(store: &Path) -> Result<PathBuf, String> {
        let entries =
            std::fs::read_dir(store).map_err(|e| format!("read {}: {e}", store.display()))?;
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

    fn find_seed_cacert() -> Result<PathBuf, String> {
        find_seed_cacert_in(Path::new("/nix/store"))
    }

    fn seed_store_has_required_runtime(store: &Path) -> Result<bool, String> {
        Ok(find_seed_bin_in(store, "nix").is_ok() && find_seed_cacert_in(store).is_ok())
    }

    fn nul_terminated_c_chars(chars: &[libc::c_char]) -> Vec<u8> {
        chars
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| u8::from_ne_bytes(c.to_ne_bytes()))
            .collect()
    }

    /// `uname -m` via libc (no coreutils in the seed). aarch64 / x86_64.
    fn machine_arch() -> Result<String, String> {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: uname writes into the provided utsname struct.
        if unsafe { libc::uname(&mut uts) } != 0 {
            return Err("uname() failed".into());
        }
        let bytes = nul_terminated_c_chars(&uts.machine);
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Minimal `KEY=VALUE` / `KEY="VALUE"` reader for the optional
    /// host-dropped build conf — the host writes a small fixed set of plain
    /// `MVM_STAGE0_*` assignments after validating every value as a token.
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
        mvm_build::stage0::copy_nonempty_file(src, dst)
            .map(|_| ())
            .map_err(|error| error.to_string())
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

    #[cfg(test)]
    mod tests {
        use super::{
            VSOCK_EGRESS_NO_PROXY, VSOCK_EGRESS_PROXY_URL, copy_artifacts_into, run_streaming,
            stage0_nix_store_device,
        };
        use std::os::unix::fs::symlink;
        use std::process::Command;

        #[test]
        fn stage0_nix_store_device_matches_backend_disk_order() {
            assert_eq!(stage0_nix_store_device(false), "/dev/vda");
            assert_eq!(stage0_nix_store_device(true), "/dev/vdf");
        }

        #[test]
        fn c_char_bytes_preserve_bytes_and_stop_at_nul() {
            let chars: [libc::c_char; 5] = [109, 118, 109, 0, 120];
            assert_eq!(super::nul_terminated_c_chars(&chars), b"mvm");
        }

        #[test]
        fn guest_ext4_format_pins_stage0_store_label_and_block_count() {
            let command = super::ext4_format_command(
                std::path::Path::new("/sbin/mkfs.ext4"),
                "/dev/vda",
                4096,
            );
            assert_eq!(command.get_program(), "/sbin/mkfs.ext4");
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                [
                    "-F",
                    "-q",
                    "-b",
                    "4096",
                    "-L",
                    mvm_build::rootfs::STAGE0_NIX_STORE_EXT4_LABEL,
                    "/dev/vda",
                    "4096",
                ]
            );
        }

        #[test]
        fn purge_stale_nix_builder_home_removes_leftover_and_tolerates_absence() {
            let root = tempfile::tempdir().expect("tempdir");
            // Clean boot: no `/homeless-shelter` present — a no-op, never an error.
            super::purge_stale_nix_builder_home(root.path()).expect("absent home is ok");
            // Crashed prior build: a populated leftover must be removed wholesale
            // so nix's unsandboxed purity check doesn't wedge the next build.
            let home = root.path().join("homeless-shelter");
            std::fs::create_dir_all(home.join(".cargo")).expect("seed leftover tree");
            std::fs::write(home.join(".cargo/config"), b"stale").expect("seed leftover file");
            super::purge_stale_nix_builder_home(root.path()).expect("removes leftover");
            assert!(!home.exists(), "stale nix builder home must be gone");
        }

        #[test]
        fn ext4_error_count_must_be_zero_before_success() {
            let root = tempfile::tempdir().expect("tempdir");
            let errors = root.path().join("errors_count");
            std::fs::write(&errors, "0\n").expect("write zero count");
            super::reject_ext4_errors(&errors).expect("zero errors are clean");

            std::fs::write(&errors, "7\n").expect("write nonzero count");
            let error = super::reject_ext4_errors(&errors).expect_err("errors must fail");
            assert!(error.contains("7 filesystem error(s)"), "{error}");
        }

        #[test]
        fn ext4_finalization_applies_only_to_a_mounted_libkrun_store() {
            assert!(super::persistent_store_finalization_required(false, true));
            assert!(!super::persistent_store_finalization_required(false, false));
            assert!(!super::persistent_store_finalization_required(true, true));
            assert!(!super::persistent_store_finalization_required(true, false));
        }

        #[test]
        fn streams_stderr_live_keeps_full_log_and_captures_stdout() {
            // Mimic nix: build logs to stderr, the out-path to stdout.
            let mut cmd = Command::new("sh");
            cmd.args([
                "-c",
                "printf 'log1\\nlog2\\n' >&2; printf '/nix/store/abc\\n'",
            ]);
            let mut live: Vec<u8> = Vec::new();
            let (status, stderr_log, stdout) = run_streaming(cmd, &mut live).unwrap();
            assert!(status.success());
            // Echoed live to the console sink…
            assert_eq!(live, b"log1\nlog2\n");
            // …and accumulated for the post-mortem log.
            assert_eq!(stderr_log, b"log1\nlog2\n");
            // out-path captured from stdout.
            assert_eq!(stdout.trim(), "/nix/store/abc");
        }

        #[test]
        fn propagates_nonzero_exit_with_log() {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", "echo boom >&2; exit 7"]);
            let mut live: Vec<u8> = Vec::new();
            let (status, stderr_log, _stdout) = run_streaming(cmd, &mut live).unwrap();
            assert_eq!(status.code(), Some(7));
            assert_eq!(stderr_log, b"boom\n");
        }

        #[test]
        fn should_enable_vsock_egress_honors_qemu_cmdline_token() {
            assert!(super::should_enable_vsock_egress(
                true,
                "console=hvc0 mvm.vsock_egress=1 root=/dev/vda"
            ));
            assert!(!super::should_enable_vsock_egress(
                true,
                "console=hvc0 mvm.vsock_egress=0 root=/dev/vda"
            ));
        }

        #[test]
        fn should_enable_vsock_egress_always_on_for_libkrun_stage0() {
            assert!(super::should_enable_vsock_egress(
                false,
                "console=hvc0 root=/dev/vda"
            ));
        }

        #[test]
        fn vsock_egress_port_from_cmdline_reads_positive_port() {
            assert_eq!(
                super::vsock_egress_port_from_cmdline(
                    "console=hvc0 mvm.vsock_egress=1 mvm.vsock_egress_port=45253 root=/dev/vda"
                ),
                Some(45253)
            );
            assert_eq!(
                super::vsock_egress_port_from_cmdline(
                    "console=hvc0 mvm.vsock_egress_port=0 root=/dev/vda"
                ),
                None
            );
        }

        #[test]
        fn apply_vsock_egress_proxy_env_sets_proxy_contract() {
            let mut cmd = Command::new("env");
            super::apply_vsock_egress_proxy_env(&mut cmd);
            let envs: std::collections::HashMap<_, _> = cmd
                .get_envs()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.expect("proxy vars are always set")
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
                .collect();
            assert_eq!(
                envs.get("ALL_PROXY").map(String::as_str),
                Some(VSOCK_EGRESS_PROXY_URL)
            );
            assert_eq!(
                envs.get("HTTP_PROXY").map(String::as_str),
                Some(VSOCK_EGRESS_PROXY_URL)
            );
            assert_eq!(
                envs.get("HTTPS_PROXY").map(String::as_str),
                Some(VSOCK_EGRESS_PROXY_URL)
            );
            assert_eq!(
                envs.get("NO_PROXY").map(String::as_str),
                Some(VSOCK_EGRESS_NO_PROXY)
            );
        }

        #[test]
        fn stage0_nix_config_disables_in_guest_sandbox() {
            let cfg = super::stage0_nix_config();
            assert!(cfg.contains("experimental-features = nix-command flakes"));
            assert!(cfg.contains("sandbox = false"));
            assert!(cfg.contains("build-users-group ="));
            assert!(cfg.contains("max-jobs = 1"));
            assert!(cfg.contains("connect-timeout = 30"));
        }

        #[test]
        fn egress_child_exit_message_reports_exit_code() {
            let status = Command::new("sh")
                .args(["-c", "exit 7"])
                .status()
                .expect("spawn shell");
            assert_eq!(super::egress_child_exit_message(status), "exit code 7");
        }

        #[test]
        fn copy_artifacts_promotes_manifest_for_image_outputs() {
            let temp = tempfile::tempdir().expect("tempdir");
            let out = temp.path().join("builder-out");
            let copied = temp.path().join("copied");
            std::fs::create_dir_all(&out).expect("create out dir");
            std::fs::create_dir_all(&copied).expect("create copied dir");
            std::fs::write(out.join("vmlinux.real"), b"kernel").expect("write kernel");
            symlink(out.join("vmlinux.real"), out.join("vmlinux")).expect("symlink kernel");
            std::fs::write(out.join("rootfs.ext4"), b"rootfs").expect("write rootfs");
            std::fs::write(out.join("cmdline.txt"), b"console=hvc0\n").expect("write cmdline");
            std::fs::write(
                out.join("manifest.json"),
                br#"{"cache_contract_version":2,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#,
            )
            .expect("write manifest");

            copy_artifacts_into(&out, "image", &copied).expect("copy image outputs");

            assert_eq!(
                std::fs::read(copied.join("manifest.json")).expect("read copied manifest"),
                std::fs::read(out.join("manifest.json")).expect("read source manifest")
            );
        }

        #[test]
        fn copy_artifacts_promotes_only_the_sdk_sidecar_contract() {
            let temp = tempfile::tempdir().expect("tempdir");
            let out = temp.path().join("sidecar-out");
            let copied = temp.path().join("copied");
            std::fs::create_dir_all(&out).expect("create out dir");
            std::fs::create_dir_all(&copied).expect("create copied dir");
            std::fs::write(out.join("sdk.ext4"), b"sidecar").expect("write sidecar image");
            std::fs::write(out.join("VERSION"), b"0.18.0\n").expect("write version");
            std::fs::write(
                out.join("checksums-sha256.txt"),
                b"digest  sdk.ext4\ndigest  VERSION\n",
            )
            .expect("write checksum manifest");
            std::fs::write(out.join("rootfs.ext4"), b"must not copy")
                .expect("write unrelated rootfs");

            copy_artifacts_into(&out, "sdk-sidecar", &copied).expect("copy SDK sidecar outputs");

            assert_eq!(std::fs::read(copied.join("sdk.ext4")).unwrap(), b"sidecar");
            assert_eq!(std::fs::read(copied.join("VERSION")).unwrap(), b"0.18.0\n");
            assert!(copied.join("checksums-sha256.txt").is_file());
            assert!(!copied.join("vmlinux").exists());
            assert!(!copied.join("rootfs.ext4").exists());
        }

        #[test]
        fn seed_store_runtime_check_requires_nix_and_cacert() {
            let root = tempfile::tempdir().expect("tempdir");
            let store = root.path().join("store");
            std::fs::create_dir_all(store.join("abc-nix/bin")).expect("seed nix dir");
            std::fs::write(store.join("abc-nix/bin/nix"), b"#!/bin/sh\n").expect("seed nix bin");
            std::fs::create_dir_all(store.join("def-nss-cacert/etc/ssl/certs"))
                .expect("seed cacert dir");
            std::fs::write(
                store.join("def-nss-cacert/etc/ssl/certs/ca-bundle.crt"),
                b"dummy cert",
            )
            .expect("seed cacert bundle");
            assert!(
                super::seed_store_has_required_runtime(&store).expect("runtime check"),
                "store with nix + cacert should be reusable"
            );

            std::fs::remove_file(store.join("abc-nix/bin/nix")).expect("remove nix");
            assert!(
                !super::seed_store_has_required_runtime(&store).expect("runtime check"),
                "store missing nix must be re-seeded"
            );
        }
    }
}
