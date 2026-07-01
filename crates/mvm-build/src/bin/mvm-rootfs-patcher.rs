//! `mvm-rootfs-patcher` — PID 1 of the self-hosting builder-rootfs bootstrap.
//!
//! Booted from an initramfs on the in-house VMM (`kernel + initramfs + the
//! target rootfs as a writable virtio-blk disk`). It mounts the rootfs
//! read-write and copies each binary in `/payload` to its install path per
//! `/payload/manifest` (built by `mvm_build::rootfs_inject`), then powers off.
//! The result is a rootfs with the current mvm host binaries baked in, produced
//! with no legacy (vz/libkrun) builder — the primitive that breaks the builder
//! bootstrap chicken-and-egg.
//!
//! Linux-only (mount/reboot syscalls). Cross-compiled to static aarch64-musl; a
//! stub elsewhere so the workspace links on a dev host.

/// One `/payload/manifest` line: `<payload-name> <install-path> <octal-mode>`.
/// Returns `(name, install_path, mode)`; the mode defaults to `0755` if missing
/// or unparseable. `None` for a blank/comment line.
#[cfg(any(target_os = "linux", test))]
fn parse_manifest_line(line: &str) -> Option<(String, String, u32)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut f = line.split_whitespace();
    let name = f.next()?.to_string();
    let install = f.next()?.to_string();
    let mode = f
        .next()
        .and_then(|m| u32::from_str_radix(m, 8).ok())
        .unwrap_or(0o755);
    Some((name, install, mode))
}

#[cfg(target_os = "linux")]
fn main() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    use nix::mount::{MsFlags, mount};

    // Pseudo-fs first: devtmpfs gives us /dev/console (for logging) and /dev/vd*.
    let _ = mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    );
    let _ = mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    );
    let mut console = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/console")
        .ok();
    macro_rules! log {
        ($($a:tt)*) => {{
            if let Some(c) = console.as_mut() { let _ = writeln!(c, $($a)*); }
        }};
    }
    log!("mvm-rootfs-patcher: starting");

    let poweroff = || -> ! {
        // SAFETY: sync + power off; the in-house VMM services the PSCI SYSTEM_OFF
        // this reboot syscall lowers to.
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_POWER_OFF);
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    };

    // Target rootfs device (default /dev/vda; overridable on the cmdline).
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let target = cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("mvm.patch_target="))
        .unwrap_or("/dev/vda")
        .to_string();

    if let Err(e) = mount(
        Some(target.as_str()),
        "/mnt",
        Some("ext4"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        log!("mvm-rootfs-patcher: mount {target} -> /mnt failed: {e}");
        poweroff();
    }
    log!("mvm-rootfs-patcher: mounted {target} read-write at /mnt");

    let manifest = std::fs::read_to_string("/payload/manifest").unwrap_or_default();
    let mut injected = 0u32;
    for line in manifest.lines() {
        let Some((name, install, mode)) = parse_manifest_line(line) else {
            continue;
        };
        let src = format!("/payload/{name}");
        let dst = format!("/mnt{install}");
        if let Some(parent) = std::path::Path::new(&dst).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::copy(&src, &dst) {
            Ok(_) => {
                let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode));
                log!("mvm-rootfs-patcher: injected {src} -> {dst} (mode {mode:o})");
                injected += 1;
            }
            Err(e) => log!("mvm-rootfs-patcher: copy {src} -> {dst} failed: {e}"),
        }
    }

    log!("mvm-rootfs-patcher: injected {injected} binaries; unmounting + powering off");
    let _ = nix::mount::umount("/mnt");
    poweroff();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "mvm-rootfs-patcher is Linux-only (initramfs PID 1 for the self-hosting \
         builder-rootfs bootstrap). On a dev host this binary is a no-op; it is \
         cross-compiled for <arch>-unknown-linux-musl."
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::parse_manifest_line;

    #[test]
    fn parses_a_manifest_line_with_explicit_mode() {
        assert_eq!(
            parse_manifest_line("mvm-host-vm-init /sbin/mvm-host-vm-init 0755"),
            Some((
                "mvm-host-vm-init".to_string(),
                "/sbin/mvm-host-vm-init".to_string(),
                0o755
            ))
        );
    }

    #[test]
    fn defaults_mode_when_absent_and_skips_blanks_and_comments() {
        assert_eq!(
            parse_manifest_line("x /sbin/x"),
            Some(("x".to_string(), "/sbin/x".to_string(), 0o755))
        );
        assert_eq!(parse_manifest_line("   "), None);
        assert_eq!(parse_manifest_line("# comment"), None);
    }
}
