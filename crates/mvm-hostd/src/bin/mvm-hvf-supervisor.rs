//! `mvm-hvf-supervisor` — one process per raw-HVF guest.
//!
//! Reads an [`mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig`] JSON document on
//! stdin (written by `mvm_runtime::backends::hvf`), self-signs the `hypervisor`
//! entitlement, boots the guest via `mvm_runtime::backends::hvf::boot_kernel` (which drives
//! the unified `vmm::run` loop), captures its console to the configured log, and
//! writes/removes a PID file so the backend can confirm launch and stop/status
//! the VM. macOS / Apple-silicon only; a stub elsewhere so the workspace links.

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    mvm_vmm::host::helper_contract::exit_with_probe_answer_if_requested("mvm-hvf-supervisor");
    eprintln!(
        "mvm-hvf-supervisor runs only on macOS / Apple silicon (Hypervisor.framework); \
         this is a stub build"
    );
    std::process::exit(1);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CONFIG_LIMIT: usize = 8 * 1024 * 1024;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const REPLAY_HINT: &str = "MVM_HVF_LEGACY_CONFIG_REPLAY";

/// Mapping only; the descriptor remains independently owned.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ConfigMapping {
    address: *mut libc::c_void,
    len: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ConfigMapping {
    fn map(fd: i32, len: usize, protection: i32) -> std::io::Result<Self> {
        // SAFETY: no fixed address; caller checked positive bounded length and
        // owns/borrows a descriptor supporting the requested access.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                protection,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { address, len })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for ConfigMapping {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns this successful mapping.
        unsafe {
            libc::munmap(self.address, self.len);
        }
    }
}

/// Only an EMPTY shared-memory name can exist; all writes follow unlink.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct EmptyReplayName(Option<std::ffi::CString>);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for EmptyReplayName {
    fn drop(&mut self) {
        // SAFETY: own exclusive random name; unlink never follows a disk path.
        if let Some(name) = &self.0 {
            unsafe {
                libc::shm_unlink(name.as_ptr());
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn legacy_replay(raw: &[u8]) -> anyhow::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    anyhow::ensure!(
        !raw.is_empty() && raw.len() <= CONFIG_LIMIT,
        "config exceeds replay bound"
    );
    let name = std::ffi::CString::new(format!("/mvm-cfg-{:016x}", rand::random::<u64>()))?;
    // SAFETY: exclusive EMPTY object; no configuration has been written.
    let writable = unsafe {
        libc::shm_open(
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    anyhow::ensure!(writable >= 0, "could not create anonymous config replay");
    let mut name = EmptyReplayName(Some(name));
    // SAFETY: newly created descriptor has no other Rust owner.
    let writable = unsafe { std::fs::File::from_raw_fd(writable) };
    // SAFETY: acquire the read-only handle while the exclusively owned name is EMPTY.
    let readonly = unsafe {
        libc::shm_open(
            name.0.as_ref().expect("owned empty name").as_ptr(),
            libc::O_RDONLY,
            0,
        )
    };
    anyhow::ensure!(readonly >= 0, "could not open read-only config replay");
    // SAFETY: successful shm_open transferred this descriptor exclusively.
    let readonly = unsafe { std::fs::File::from_raw_fd(readonly) };
    // SAFETY: the name is ours; failure occurs BEFORE any secret bytes are written.
    anyhow::ensure!(
        unsafe { libc::shm_unlink(name.0.as_ref().expect("owned empty name").as_ptr()) } == 0,
        "could not unlink empty config replay"
    );
    // Disarm immediately: never unlink a later unrelated object at that name.
    name.0.take();
    drop(name);
    writable.set_len(u64::try_from(raw.len())?)?;
    let mapping = ConfigMapping::map(
        writable.as_raw_fd(),
        raw.len(),
        libc::PROT_READ | libc::PROT_WRITE,
    )?;
    // SAFETY: live writable mapping exactly raw.len(); buffers do not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(raw.as_ptr(), mapping.address.cast::<u8>(), raw.len());
    }
    drop(mapping);
    drop(writable);
    // POSIX shm descriptors start CLOEXEC; explicitly enforce it for this temporary.
    // SAFETY: the read-only descriptor is live and owned.
    anyhow::ensure!(
        unsafe { libc::fcntl(readonly.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "could not protect config replay descriptor"
    );
    Ok(readonly)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn read_config_input(fd: i32, hint: Option<&std::ffi::OsStr>) -> anyhow::Result<String> {
    use anyhow::Context;
    if let Some(hint) = hint {
        let text = hint
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid config replay hint"))?;
        let length = text
            .strip_prefix("shm-v1:")
            .ok_or_else(|| anyhow::anyhow!("invalid config replay format"))?;
        let len: usize = length
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid config replay length"))?;
        anyhow::ensure!(
            len > 0 && len <= CONFIG_LIMIT && length == len.to_string(),
            "invalid config replay bound"
        );
        // SAFETY: metadata and access inspection only; no ownership conversion.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: caller supplies a live borrowed input descriptor.
        let flags = unsafe {
            if libc::fstat(fd, &mut stat) != 0 {
                -1
            } else {
                libc::fcntl(fd, libc::F_GETFL)
            }
        };
        // Darwin pshm_stat has permission bits, no S_IFREG file type, and no
        // links. The hint remains untrusted; normal JSON/admission checks follow.
        // SAFETY: sysconf/geteuid only inspect process/platform state.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
        anyhow::ensure!(page > 0, "invalid config replay page size");
        let rounded = len
            .checked_add(page - 1)
            .context("config replay size overflow")?
            / page
            * page;
        anyhow::ensure!(
            flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && stat.st_mode & libc::S_IFMT == 0
                && stat.st_mode & 0o777 == 0o600
                && stat.st_nlink == 0
                && stat.st_uid == unsafe { libc::geteuid() }
                && usize::try_from(stat.st_size)? == rounded,
            "invalid anonymous config replay descriptor"
        );
        let mapping = ConfigMapping::map(fd, len, libc::PROT_READ)?;
        // SAFETY: read-only mapping remains live for this bounded copy.
        let bytes = unsafe { std::slice::from_raw_parts(mapping.address.cast::<u8>(), len) };
        return String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("config replay is not UTF-8"));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 65536];
    loop {
        let available = (CONFIG_LIMIT + 1 - bytes.len()).min(buffer.len());
        // SAFETY: borrowed descriptor; output is a live, exclusive buffer.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), available) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..usize::try_from(count)?]);
        anyhow::ensure!(
            bytes.len() <= CONFIG_LIMIT,
            "supervisor config exceeds 8 MiB"
        );
    }
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("supervisor config is not UTF-8"))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
enum StartupMode {
    Legacy,
    Checked,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn startup_mode(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> anyhow::Result<StartupMode> {
    if cfg.boot_image_fds.is_some() || cfg.kernel_fd.is_some() || cfg.caller_registration.is_some()
    {
        anyhow::ensure!(
            cfg.boot_image_fds.is_some()
                && cfg.kernel_fd.is_some()
                && cfg.caller_registration.is_some(),
            "incomplete checked boot cannot use legacy startup"
        );
        Ok(StartupMode::Checked)
    } else {
        Ok(StartupMode::Legacy)
    }
}

/// Ad-hoc entitlement applied at first launch — `Hypervisor.framework` rejects an
/// unsigned process. Hypervisor-only — no virtualization entitlement.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HVF_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
    \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
    <plist version=\"1.0\"><dict>\n\
    <key>com.apple.security.hypervisor</key><true/>\n\
    </dict></plist>";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exe_has_hypervisor_entitlement(exe: &std::path::Path) -> bool {
    mvm_core::env_hygiene::helper_command("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(exe)
        .output()
        .map(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout).contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn signed_marker_path(exe: &std::path::Path) -> std::path::PathBuf {
    let mut marker = exe.as_os_str().to_os_string();
    marker.push(".mvm-hvf-signed");
    std::path::PathBuf::from(marker)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn executable_fingerprint(exe: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(exe).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(format!(
        "{}:{}:{}:{}",
        metadata.ino(),
        metadata.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn signed_marker_matches(exe: &std::path::Path) -> bool {
    let Some(fingerprint) = executable_fingerprint(exe) else {
        return false;
    };
    std::fs::read_to_string(signed_marker_path(exe))
        .map(|cached| cached.trim() == fingerprint)
        .unwrap_or(false)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn record_signed_marker(exe: &std::path::Path) {
    if let Some(fingerprint) = executable_fingerprint(exe) {
        let _ = std::fs::write(signed_marker_path(exe), fingerprint);
    }
}

/// Self-sign ad-hoc with the hypervisor entitlement, then re-exec. We ship the
/// bin unsigned and HVF rejects it otherwise. `MVM_HVF_SIGNED` breaks the exec
/// loop; `exec()` preserves the pid + the stdin config pipe. A file lock
/// serializes concurrent launches (codesign --force rewrites the shared binary
/// in place). Mirrors the libkrun supervisor's `ensure_self_signed`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_self_signed(diagnostics: &mut mvm_vmm::host::hvf_supervisor::StartupReporter) {
    use mvm_vmm::host::hvf_supervisor::StartupStage;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    diagnostics.stage(StartupStage::SignCheck);
    if std::env::var("MVM_HVF_SIGNED").as_deref() == Ok("1") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    // The helper is stable between builds. Avoid spawning `codesign` for every
    // short-lived workload by caching only metadata observed after a successful
    // entitlement check or signing operation. Hypervisor.framework remains the
    // final authority and still rejects an unsigned helper.
    if signed_marker_matches(&exe) {
        return;
    }
    if exe_has_hypervisor_entitlement(&exe) {
        record_signed_marker(&exe);
        return;
    }

    diagnostics.stage(StartupStage::SigningLock);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(std::env::temp_dir().join("mvm-hvf-supervisor.codesign.lock"))
        .ok();
    if let Some(f) = &lock {
        // SAFETY: flock on a valid fd; LOCK_EX blocks until exclusive.
        unsafe {
            libc::flock(f.as_raw_fd(), libc::LOCK_EX);
        }
    }

    if !exe_has_hypervisor_entitlement(&exe) {
        diagnostics.stage(StartupStage::Signing);
        let ent = std::env::temp_dir().join("mvm-hvf-supervisor-entitlements.plist");
        if std::fs::write(&ent, HVF_ENTITLEMENTS_PLIST).is_err() {
            return;
        }
        let output = mvm_core::env_hygiene::helper_command("codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&ent)
            .arg(&exe)
            .output();
        let signed = output.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !signed {
            eprintln!("mvm-hvf-supervisor: ad-hoc codesign failed; VM start may be rejected");
            if let Ok(o) = &output {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stderr = stderr.trim_end();
                if !stderr.is_empty() {
                    eprintln!("{stderr}");
                }
            }
            return;
        }
        record_signed_marker(&exe);
    }
    drop(lock);

    diagnostics.stage(StartupStage::Reexec);
    let mut command = mvm_core::env_hygiene::helper_command(&exe);
    command
        .args(std::env::args_os().skip(1))
        .env("MVM_HVF_SIGNED", "1");
    diagnostics.configure_reexec(&mut command);
    let err = command.exec();
    eprintln!("mvm-hvf-supervisor: re-exec after signing failed: {err}");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::{record_signed_marker, signed_marker_matches};
    use std::io::Write;

    #[test]
    fn legacy_replay_maps_exact_bytes_readonly_without_touching_stdin() {
        use std::os::fd::AsRawFd;
        let raw = b" {\"nonnative\":\"fixture\"}\n";
        let replay = super::legacy_replay(raw).unwrap();
        let fd = replay.as_raw_fd();
        // SAFETY: inspect the private unit-owned descriptor, never global FD0.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let hint = std::ffi::OsString::from(format!("shm-v1:{}", raw.len()));
        assert_eq!(
            super::read_config_input(fd, Some(&hint))
                .unwrap()
                .as_bytes(),
            raw
        );
        assert!(replay.set_len(0).is_err());
        assert!(
            super::ConfigMapping::map(fd, raw.len(), libc::PROT_READ | libc::PROT_WRITE).is_err()
        );
        assert_eq!(
            super::read_config_input(fd, Some(&hint))
                .unwrap()
                .as_bytes(),
            raw
        );
        // Omitted hint must fail, not pretend POSIX shm supports ordinary read.
        assert!(super::read_config_input(fd, None).is_err());
    }

    #[test]
    fn replay_hints_and_partial_checked_configs_fail_closed() {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStringExt;
        let replay = super::legacy_replay(b"{}").unwrap();
        for hint in [
            "",
            "2",
            "shm-v1:0",
            "shm-v1:02",
            "shm-v1:8388609",
            "shm-v2:2",
        ] {
            assert!(
                super::read_config_input(replay.as_raw_fd(), Some(std::ffi::OsStr::new(hint)))
                    .is_err()
            );
        }
        assert!(
            super::read_config_input(
                replay.as_raw_fd(),
                Some(&std::ffi::OsString::from_vec(vec![0xff]))
            )
            .is_err()
        );
        assert!(super::legacy_replay(&[]).is_err());
        assert!(super::legacy_replay(&vec![0; super::CONFIG_LIMIT + 1]).is_err());
        let mut cfg: mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig =
            serde_json::from_value(serde_json::json!({
                "console_capture":"encrypted", "vm_name":"shape-only", "kernel":"/unused",
                "timeout_secs":0,
                "console_log":"/unused", "pid_file":"/unused", "workload_exit":"/unused"
            }))
            .unwrap();
        assert!(matches!(
            super::startup_mode(&cfg).unwrap(),
            super::StartupMode::Legacy
        ));
        cfg.kernel_fd = Some(9);
        assert!(super::startup_mode(&cfg).is_err());
        cfg.boot_image_fds = Some(mvm_vmm::host::hvf_supervisor::BootImageFds {
            rootfs: 10,
            verity: 11,
            metadata: 12,
            root_hash: 13,
        });
        assert!(
            super::startup_mode(&cfg).is_err(),
            "missing actual registration cannot downgrade"
        );
        cfg.kernel_fd = None;
        assert!(super::startup_mode(&cfg).is_err());
        // Raw config shape only: no original caller/VM/checked owner is minted.
    }

    #[test]
    fn signed_marker_is_bound_to_the_executable_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("mvm-hvf-supervisor");
        let mut file = std::fs::File::create(&exe).expect("create executable");
        file.write_all(b"signed helper").expect("write executable");
        file.flush().expect("flush executable");

        assert!(!signed_marker_matches(&exe));
        record_signed_marker(&exe);
        assert!(signed_marker_matches(&exe));

        std::fs::write(&exe, b"replacement helper with different size")
            .expect("replace executable");
        assert!(!signed_marker_matches(&exe));
    }
}

/// Set by the SIGTERM/SIGINT handler; `boot_kernel_until`'s watchdog polls it and
/// force-exits the guest so a stop flushes the console + drops the PID file
/// cleanly (vs the kernel being killed mid-run).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set/cleared by the SIGUSR1/SIGUSR2 handlers; `boot_kernel_until` parks the
/// guest vCPU out of execution (RAM + devices intact) while this is true, so
/// `HvfBackend::pause`/`resume` freeze and thaw the guest in place.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_pause_signal(_: libc::c_int) {
    PAUSED.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_resume_signal(_: libc::c_int) {
    PAUSED.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// The verified saved state the launcher handed over, when this boot is a
/// restore.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn restore_image_from(
    cfg: &mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig,
) -> anyhow::Result<Option<mvm_runtime::backends::hvf::snapshot::RestoreImage>> {
    use mvm_vmm::host::restore_image::adopt_inherited;
    let Some(fds) = cfg.restore_descriptors()? else {
        return Ok(None);
    };
    Ok(Some(mvm_runtime::backends::hvf::snapshot::RestoreImage {
        ram: adopt_inherited(fds.ram)?,
        frame: adopt_inherited(fds.frame)?,
    }))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use anyhow::Context;
    use mvm_vmm::host::hvf_supervisor::{
        HvfShutdownTimingRecord, HvfSupervisorConfig, StartupReporter, StartupStage,
    };

    // No opens or descriptor ownership conversions precede bounded parsing.
    // A replay hint selects only input mechanics, NEVER startup authority.
    let replay_hint = std::env::var_os(REPLAY_HINT);
    let raw = read_config_input(libc::STDIN_FILENO, replay_hint.as_deref())?;
    if raw.is_empty() && replay_hint.is_none() {
        mvm_vmm::host::helper_contract::exit_with_probe_answer_if_requested("mvm-hvf-supervisor");
    }
    anyhow::ensure!(
        !mvm_vmm::host::helper_contract::probe_requested(std::env::args()),
        "a contract probe cannot carry boot configuration"
    );
    let cfg: HvfSupervisorConfig =
        serde_json::from_str(&raw).context("parse HvfSupervisorConfig JSON from stdin")?;
    let mode = startup_mode(&cfg)?;
    let mut diagnostics;
    let files = match mode {
        StartupMode::Checked => {
            // Complete preflight precedes FIRST ownership conversion.
            let files = mvm_hostd::supervisor::caller_registration::adopt_startup_files(&cfg)?;
            // SAFETY: preflight established the distinct inherited diagnostics
            // pipe; its sole ownership is transferred by the actual launcher.
            diagnostics = unsafe { StartupReporter::inherited() };
            mvm_vmm::host::codesign::try_ensure_signed().map_err(anyhow::Error::msg)?;
            files
        }
        StartupMode::Legacy => {
            if replay_hint.is_none() {
                let replay = legacy_replay(raw.as_bytes())?;
                // SAFETY: single-threaded startup replaces only standard input.
                anyhow::ensure!(
                    unsafe { libc::dup2(replay.as_raw_fd(), libc::STDIN_FILENO) } >= 0,
                    "could not install read-only config replay"
                );
                drop(replay);
                // SAFETY: no worker threads or foreign runtime have started.
                // The inherited value is a locator/length only, never a secret.
                unsafe {
                    std::env::set_var(REPLAY_HINT, format!("shm-v1:{}", raw.len()));
                }
            }
            // SAFETY: unchanged legacy launcher diagnostics ownership contract.
            diagnostics = unsafe { StartupReporter::inherited() };
            // Body unchanged: only legacy can sign/reexec with RAM-backed FD0.
            ensure_self_signed(&mut diagnostics);
            mvm_hostd::supervisor::caller_registration::adopt_startup_files(&cfg)?
        }
    };

    // Graceful stop: SIGTERM/SIGINT set STOP, which the boot watchdog observes and
    // force-exits the guest (then we flush the console + drop the PID file).
    // Pause/resume: SIGUSR1 sets PAUSED (park the vCPU out of guest execution),
    // SIGUSR2 clears it (thaw and re-enter the guest).
    // SAFETY: installing trivial async-signal-safe handlers (each an atomic store).
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
        let pause_h = on_pause_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGUSR1, pause_h);
        let resume_h = on_resume_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGUSR2, resume_h);
    }

    diagnostics.stage(StartupStage::ConfigRead);
    diagnostics.stage(StartupStage::ConfigParse);
    let registered_startup = mvm_hostd::supervisor::caller_registration::prepare_startup(&cfg)?;
    let (held_kernel, mut checked_images, registered_startup) = match mode {
        StartupMode::Checked => {
            let startup =
                registered_startup.context("checked boot requires actual consumed caller")?;
            let (launch, kernel, images) = files.bind(startup.launch, &cfg)?.into_startup();
            (
                Some(kernel),
                Some(images),
                Some(
                    mvm_hostd::supervisor::caller_registration::PreparedCallerStartup {
                        launch,
                        initramfs: startup.initramfs,
                    },
                ),
            )
        }
        StartupMode::Legacy => (files.into_legacy_kernel()?, None, registered_startup),
    };
    anyhow::ensure!(
        held_kernel.is_none() || cfg.restore_descriptors()?.is_none(),
        "canonical kernel descriptor cannot enter a restore/warm boot"
    );
    use mvm_vmm::host::hvf_supervisor::ProtectedSupervisorStatus as CaptureStatus;
    let state_dir = cfg
        .pid_file
        .parent()
        .context("supervisor state directory missing")?;
    mvm_core::naming::validate_vm_name(&cfg.vm_name)?;
    anyhow::ensure!(
        state_dir == mvm_core::config::vm_state_dir(&cfg.vm_name),
        "supervisor instance does not match its managed state directory"
    );
    // Only a planless resident standby may be reassigned. An admitted
    // workload already has bounds tied to its original owner.
    if cfg.handoff_socket.is_some() && (cfg.plan.is_some() || !cfg.vsock) {
        anyhow::bail!("protected handoff requires a planless vsock standby");
    }

    diagnostics.stage(StartupStage::StartupInputs);
    // Adopt the verified saved state before anything else can open a file, so
    // no descriptor number is reused out from under it.
    let restore = restore_image_from(&cfg)?;
    let ready_marker = restore
        .as_ref()
        .and(cfg.pid_file.parent())
        .map(mvm_vmm::host::hvf_supervisor::restore_ready_path);
    let stop_control = mvm_hostd::supervisor::hvf_stop::StopControl::start(&cfg.vm_name, &STOP)?;
    let _ = std::fs::remove_file(mvm_vmm::host::hvf_supervisor::shutdown_timing_path(
        state_dir,
    ));
    diagnostics.stage(StartupStage::StatusPublish);
    CaptureStatus::Starting.publish(state_dir)?;
    if let Some(path) = &cfg.pause_state {
        let _ = std::fs::remove_file(path);
    }

    let (registered_launch, initramfs) = match registered_startup {
        Some(startup) => (Some(startup.launch), startup.initramfs),
        None => (
            None,
            mvm_hostd::supervisor::caller_registration::load_boot_inputs(&cfg)?,
        ),
    };
    // A VM that outlives its launcher owns its egress endpoint *here*, because
    // the endpoint self-reaps when orphaned and this process is the only one
    // whose life is the VM's. It has to run before the disks below: the
    // identity drive it writes is one of them, and the guest refuses to boot if
    // its egress proxy is unbound.
    let mut builder_endpoint = match cfg.builder_egress_endpoint.as_ref() {
        Some(endpoint) => match spawn_owned_builder_endpoint(endpoint) {
            Ok(owner) => Some(owner),
            Err(error) => {
                // The typed spawn error retains any uncertain Child. Dropping
                // it attempts bounded owned cleanup but removes no evidence.
                drop(error);
                eprintln!("supervisor: HVF_BUILDER_ENDPOINT_SETUP_FAILED");
                std::process::exit(8);
            }
        },
        None => None,
    };

    // Build the virtio-blk backings in `/dev/vda`… order. A read-only disk is
    // file-served (hypervisor-enforced RO, no RAM cost); a read-write disk is
    // file-served and persists writes; an ephemeral disk is loaded into RAM and
    // its writes are dropped on exit (a workload rootfs that must not mutate its
    // shared base image).
    let mut disks = Vec::with_capacity(cfg.disks.len());
    let mut observed_disks = Vec::new();
    for (index, d) in cfg.disks.iter().enumerate() {
        let held = checked_images
            .as_mut()
            .map(|images| images.take_disk(index))
            .transpose()?
            .flatten();
        let img = if let Some(file) = held {
            mvm_runtime::backends::hvf::DiskImage::readonly_file(file)?
        } else if d.read_only {
            mvm_runtime::backends::hvf::DiskImage::open(&d.path, true)
                .with_context(|| format!("open read-only disk {}", d.path.display()))?
        } else if d.ephemeral {
            let bytes = std::fs::read(&d.path)
                .with_context(|| format!("read ephemeral disk {}", d.path.display()))?;
            mvm_runtime::backends::hvf::DiskImage::mem(bytes)
        } else {
            mvm_runtime::backends::hvf::DiskImage::open(&d.path, false)
                .with_context(|| format!("open read-write disk {}", d.path.display()))?
        };
        if let Some(artifact) =
            mvm_vmm::runtime_artifacts::RuntimeArtifact::disk(d.path.clone(), &img)?
        {
            observed_disks.push(artifact);
        }
        disks.push(img);
    }
    // The loader replaces initramfs/cmdline evidence on restore using only
    // the authenticated inherited frame, after checking selected identity.
    let runtime_artifacts = Some(mvm_vmm::runtime_artifacts::RuntimeArtifacts {
        kernel: None,
        initramfs: cfg
            .initramfs
            .clone()
            .zip(initramfs.as_deref())
            .map(|(path, bytes)| mvm_vmm::runtime_artifacts::RuntimeArtifact::loaded(path, bytes))
            .transpose()?,
        disks: observed_disks,
        kernel_cmdline: String::new(),
        firecracker_drives: None,
    });
    let runtime_observer = mvm_vmm::runtime_artifacts::Observer::bind(
        cfg.pid_file
            .parent()
            .context("supervisor state directory missing")?,
        runtime_artifacts,
    )?;
    // Take the exclusive store-image lock before the guest can attach the
    // image, and hold it for this process's life — which, for the persistent
    // builder that sets this, is the VM's life. A named binding, not `_`:
    // `let _ = ...` drops the file here and silently unlocks the image while
    // the VM runs. Failure is fatal; booting anyway would attach an image
    // another VM is writing, which is the corruption the lock prevents.
    let _image_lock = match cfg.exclusive_image_lock.as_ref() {
        None => None,
        Some(lock_path) => Some(
            mvm_build::builder_vm_runtime::hold_image_lock(
                lock_path,
                mvm_build::builder_vm_runtime::LockWait::from_env(),
            )
            .with_context(|| {
                format!(
                    "mvm-hvf-supervisor refusing to boot without the exclusive \
                     store-image lock at {}",
                    lock_path.display()
                )
            })?,
        ),
    };

    // timeout_secs == 0 ⇒ persistent: run until stopped (SIGTERM). A multi-year
    // cap backstops a stuck guest. Otherwise it's a bounded run.
    let timeout = if cfg.timeout_secs == 0 {
        Duration::from_secs(10 * 365 * 24 * 60 * 60)
    } else {
        Duration::from_secs(cfg.timeout_secs)
    };

    // The wall-clock bound the plan was admitted under, distinct from the
    // backstop above. This process owns the guest for its whole life, so a
    // timer here is the one that can still fire when `mvmctl` is long gone.
    // Held to the end of the scope: dropping the guard stands the timer down.
    // Mirrors `mvm-libkrun-supervisor`, including its refusal — a bounded
    // workload whose kill could not be audited must not boot.
    // The timer records its timeout exit code beside the pid file. A plan-
    // bearing boot with nowhere to record it is refused rather than booted
    // unbounded — same fail-closed posture as an unauditable kill.
    let _wall_clock = match cfg.pid_file.parent() {
        Some(vm_state_dir) => {
            let timer_inputs = mvm_hostd::supervisor::wall_clock::SupervisorTimerInputs {
                plan_json: cfg.plan.as_ref(),
                audit_dir: cfg.audit_dir.as_deref(),
                signing_key_path: cfg.signing_key_path.as_deref(),
                vm_state_dir,
                pid_file: &cfg.pid_file,
            };
            let guard = match mvm_hostd::supervisor::wall_clock::arm_for_supervisor(
                timer_inputs,
                Box::new(timer_inputs.preserving_exit_killer()),
            ) {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!(
                        "supervisor: refusing to boot a bounded workload it cannot audit: {e}"
                    );
                    std::process::exit(7);
                }
            };
            // A session's idle timeout, for the same reason as the wall clock:
            // no client is left to enforce it once the one that started the
            // session has exited.
            mvm_hostd::supervisor::session_expiry::arm_for_supervisor(
                &timer_inputs,
                Box::new(timer_inputs.preserving_exit_killer()),
            );
            guard
        }
        None if cfg.plan.is_some() => {
            eprintln!(
                "supervisor: refusing to boot a plan-bearing workload whose pid file {} has no \
                 parent directory to record a wall-clock timeout in",
                cfg.pid_file.display()
            );
            std::process::exit(7);
        }
        None => None,
    };

    // Egress over vsock is a pure relay to the per-VM endpoint, which owns the
    // whole egress decision (claim-10 default-deny + secret substitution). The
    // supervisor only wires the relay socket paths through.
    diagnostics.stage(StartupStage::CapturePolicy);
    use mvm_hostd::stream::protected::{CaptureAuthority, CaptureParams};
    let admitted_plan = cfg
        .plan
        .as_ref()
        .map(mvm_hostd::supervisor::wall_clock::decode_admitted_plan)
        .transpose()
        .map_err(|_| anyhow::anyhow!("invalid admitted capture policy"))?;
    let redaction = admitted_plan
        .as_ref()
        .map(|plan| plan.redaction.clone())
        .unwrap_or_default();
    let authority = if let Some(launch) = registered_launch {
        CaptureAuthority::CallerRegistered(launch)
    } else {
        match admitted_plan.as_ref() {
            Some(plan) => CaptureAuthority::Admitted(plan),
            None if cfg.trusted_builder_egress || cfg.handoff_socket.is_some() => {
                CaptureAuthority::OperationalLiveOnly
            }
            None => anyhow::bail!("workload protected capture requires an admitted plan"),
        }
    };
    diagnostics.stage(StartupStage::CaptureSetup);
    let (capture_owner, console_sink) =
        match mvm_hostd::stream::protected::CaptureOwner::start(CaptureParams {
            vm: &cfg.vm_name,
            authority,
            redaction: &redaction,
        }) {
            Ok(capture) => capture,
            Err(_) => {
                let _ = CaptureStatus::CaptureSetupFailed.publish(state_dir);
                anyhow::bail!("required protected console owner could not be provisioned");
            }
        };
    let capture_owner = mvm_hostd::supervisor::protected_handoff::CaptureRoute::start(
        capture_owner,
        cfg.pid_file.clone(),
        &STOP,
        stop_control.authority(),
    )?;
    let capture_control = cfg.handoff_socket.as_ref().map(|_| capture_owner.control());
    // Only a provisioned capture owner may announce this boot.
    diagnostics.stage(StartupStage::StatusPublish);
    CaptureStatus::Running.publish(state_dir)?;
    diagnostics.stage(StartupStage::PidPublish);
    std::fs::write(&cfg.pid_file, std::process::id().to_string())
        .context("publish protected supervisor PID")?;
    diagnostics.stage(StartupStage::PidPublished);
    drop(diagnostics);
    let kernel_boot = match held_kernel.as_ref() {
        Some(kernel) => mvm_runtime::backends::hvf::KernelBootUntilParams::builder_descriptor(
            kernel,
            &cfg.kernel,
            timeout,
        ),
        None => {
            mvm_runtime::backends::hvf::KernelBootUntilParams::builder_file(&cfg.kernel, timeout)
        }
    };
    let kernel_boot = match &checked_images {
        Some(images) => kernel_boot.literal_bootargs(images.cmdline())?,
        None => kernel_boot,
    };
    let result = mvm_runtime::backends::hvf::boot_kernel_until(
        kernel_boot
            .initramfs(initramfs.as_deref())
            .disks(disks)
            .vsock(cfg.vsock)
            .stop(&STOP)
            .paused(&PAUSED)
            .cpu_millicores(cfg.cpu_millicores)
            .quota_record(cfg.quota_record.clone())
            .channels(mvm_runtime::backends::hvf::HostChannels {
                agent_socket: cfg.agent_socket.clone(),
                substitution_socket: cfg.substitution_socket.clone(),
                egress_relay: cfg.egress_relay_socket.clone(),
                trusted_builder_egress: cfg.trusted_builder_egress,
                broker_socket: cfg.broker_socket.clone(),
                display_socket: cfg.display_socket.clone(),
                gpu_socket: cfg.gpu_socket.clone(),
                console_data_sockets: cfg
                    .console_data_sockets
                    .iter()
                    .map(|c| (c.guest_port, c.host_socket.clone()))
                    .collect(),
                builder_control_sockets: cfg
                    .builder_control_sockets
                    .iter()
                    .map(|c| (c.guest_port, c.host_socket.clone()))
                    .collect(),
                cmdline: cfg.cmdline.clone(),
                mem_mib: cfg.memory_mib,
                vcpus: cfg.vcpus,
                runtime_observer: Some(runtime_observer),
                console_log: None,
                console_sink: Some(Box::new(console_sink)),
                pause_state: cfg.pause_state.clone(),
                snapshot_request: cfg.snapshot_request.clone(),
                snapshot_ram: cfg.snapshot_ram.clone(),
                snapshot_frame: cfg.snapshot_frame.clone(),
                restore,
                ready_marker,
                handoff_socket: cfg.handoff_socket.clone(),
                handoff_root: cfg.handoff_root.clone(),
                handoff_verify_key: cfg.handoff_verify_key.clone(),
                handoff_accepted: None,
                capture_control,
            })
            .build(),
    );

    // The UART was dropped (and its final line enqueued) on both success and
    // error. Drain and seal before announcing stop; never rewrite raw console.
    let console_write_started = std::time::Instant::now();
    let complete = capture_owner.finish();
    let console_write = console_write_started.elapsed();
    let endpoint_stopped = builder_endpoint
        .as_mut()
        .map(mvm_vmm::host::network_endpoint_spawn::OwnedEndpoint::shutdown)
        .transpose();
    let status = if !complete {
        CaptureStatus::CaptureFailed
    } else if result.is_err() || endpoint_stopped.is_err() {
        CaptureStatus::BootFailed
    } else {
        CaptureStatus::Stopped
    };
    stop_control.publish_terminal_status(status)?;
    anyhow::ensure!(
        complete,
        "HVF capture finalization failed; retain runtime evidence"
    );
    endpoint_stopped.context("HVF_BUILDER_ENDPOINT_SHUTDOWN_UNCONFIRMED")?;
    let r = match result {
        Ok(result) => result,
        Err(_) => {
            anyhow::bail!("HVF boot failed; inspect protected supervisor status");
        }
    };
    // Transient run-to-exit: persist the workload exit code (the backend's `wait`
    // reads this) so it is durable before "stopped" is observable.
    let workload_exit_write_started = std::time::Instant::now();
    if let Some(code) = r.workload_exit_code {
        mvm_core::atomic_io::atomic_write_durable(&cfg.workload_exit, code.to_string().as_bytes())?;
    }
    let workload_exit_write = r
        .workload_exit_code
        .map(|_| workload_exit_write_started.elapsed())
        .unwrap_or_default();
    // What the machine consumed, beside the exit code it consumed it producing.
    // The run measured it from inside — vCPU CPU time is only readable while
    // those threads are alive — and this is where the VM's state directory is
    // known, which is the directory the host reads the sidecar back from.
    //
    // Best-effort by contract: a workload that already ran must not lose its
    // exit over a missing piece of evidence, so a write failure is swallowed
    // exactly as the console and exit-code writes above swallow theirs.
    if let Some(state_dir) = cfg.pid_file.parent() {
        let _ = mvm_core::usage_capture::write_captured(state_dir, &r.usage);
    }
    if let Some(timing) = r.shutdown_timing
        && let Some(state_dir) = cfg.pid_file.parent()
    {
        let record = HvfShutdownTimingRecord {
            schema_version: 1,
            watchdog_to_vcpu_exit_micros: duration_micros(timing.watchdog_to_vcpu_exit),
            watchdog_join_micros: duration_micros(timing.watchdog_join),
            io_thread_join_micros: duration_micros(timing.io_thread_join),
            vcpu_destroy_micros: duration_micros(timing.vcpu_destroy),
            vm_destroy_micros: duration_micros(timing.vm_destroy),
            console_write_micros: duration_micros(console_write),
            workload_exit_write_micros: duration_micros(workload_exit_write),
        };
        if let Ok(json) = serde_json::to_vec(&record) {
            let path = mvm_vmm::host::hvf_supervisor::shutdown_timing_path(state_dir);
            let _ = std::fs::write(path, json);
        }
    }
    match stop_control.publish_finalized()? {
        mvm_hostd::supervisor::hvf_stop::FinalizationPublication::Durable => {}
        mvm_hostd::supervisor::hvf_stop::FinalizationPublication::PublishedDurabilityUnconfirmed(
            _,
        ) => {
            anyhow::bail!("HVF_CONTROL_PUBLICATION_DURABILITY_UNCONFIRMED");
        }
    }
    if let Some(code) = r.workload_exit_code {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Mint this boot's FlowMux identity, write the drive the guest reads it off,
/// and spawn the trusted builder's egress endpoint as a child of this process.
///
/// The identity is minted **here** rather than handed over: the endpoint's
/// config carries the host signer by value, and this supervisor's own config is
/// persisted to disk beside the VM, so passing it through would put a signing
/// key on disk. `mint_from_host_signer` reads the same
/// `~/.mvm/keys/host-signer.ed25519` the config already names by path
/// elsewhere, so nothing new becomes reachable — the key just never travels.
///
/// The policy and secret set are fixed at this call site, not taken from the
/// wire: a trusted builder gets `trusted_build_egress` and no secrets, and no
/// field on `BuilderEgressEndpoint` can widen either.
fn spawn_owned_builder_endpoint(
    endpoint: &mvm_vmm::host::hvf_supervisor::BuilderEgressEndpoint,
) -> anyhow::Result<mvm_vmm::host::network_endpoint_spawn::OwnedEndpoint> {
    use anyhow::Context;

    let identity = mvm_vmm::host::flowmux_identity::FlowMuxIdentityMaterial::mint_from_host_signer(
        endpoint.vm_name.clone(),
    )
    .context("minting the builder's FlowMux identity")?;
    identity
        .write_drive(&endpoint.identity_drive)
        .with_context(|| {
            format!(
                "writing the builder's FlowMux identity drive {}",
                endpoint.identity_drive.display()
            )
        })?;

    let policy = mvm_core::policy::network_policy::NetworkPolicy::trusted_build_egress();
    mvm_vmm::host::network_endpoint_spawn::spawn_network_endpoint_owned(
        mvm_vmm::host::network_endpoint_spawn::SubstitutionSpawnParams {
            // The builder VM's endpoint never collects telemetry: the
            // builder boots with no `mvm.telemetry=1` assertion, so there is
            // no guest listener for a collector to dial.
            telemetry: false,
            vm_name: &endpoint.vm_name,
            state_dir: &endpoint.state_dir,
            // This supervisor is the builder VM, so its own life is the VM's.
            lifetime: mvm_vmm::host::network_endpoint_spawn::EndpointLifetime::Launcher,
            tenant: "builder",
            secrets: &[],
            redaction: &mvm_core::policy::RedactionPolicy::default(),
            tools: None,
            transport: mvm_vmm::host::network_endpoint_spawn::EndpointTransport::Uds {
                path: endpoint.socket.clone(),
            },
            egress_proxy: None,
            tls_intermediate: None,
            network_policy: Some(&policy),
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: Some(identity.spawn_config().clone()),
            session_marker: None,
        },
    )
    .context("spawning the builder's egress endpoint")
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn duration_micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
