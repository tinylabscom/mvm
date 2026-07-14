//! PID 1 injected into arbitrary OCI rootfs trees.
//!
//! This binary must not depend on `/bin/sh`, busybox, coreutils, or a distro
//! init system. It is statically linked and baked at `/init` so scratch,
//! distroless, Alpine, Debian, and language-base images all get the same mvm
//! vsock control plane.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{CString, OsStr};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const AGENT_FALLBACK: &str = "/usr/local/bin/mvm-guest-agent";
    const AGENT_OVERLAY: &str = "/mvm/runtime/agent";
    const AGENT_OVERLAY_DEV_SHELL: &str = "/mvm/runtime/agent-dev-shell";
    const NETINIT_FALLBACK: &str = "/usr/local/bin/mvm-guest-netinit";
    const NETINIT_OVERLAY: &str = "/mvm/runtime/netinit";
    const EGRESS_CLIENT: &str = "/usr/local/bin/mvm-egress-client";

    pub fn main() {
        mount_pseudofs();
        ensure_runtime_dirs();
        mount_user_volumes();
        provision_egress_ca();
        provision_verb_grant();
        provision_host_signer_pub();
        run_one(resolve_exec([NETINIT_OVERLAY, NETINIT_FALLBACK]), "netinit");
        if cmdline_has_flag("mvm.vsock_egress=1") {
            bring_loopback_up();
            spawn_one(Path::new(EGRESS_CLIENT), "egress-client");
        }
        // The guest agent is the mvm vsock control plane — the whole reason this
        // init exists (scratch/distroless/Alpine all get it from the overlay).
        // Fail closed if it can't be resolved: idling on agent-less would leave
        // the host waiting out its agent-readiness timeout on a silently dead VM.
        // PID 1 exiting panics the kernel (panic=-1 -> reboot), so the boot fails
        // loudly instead.
        let Some(agent) = resolve_guest_agent() else {
            eprintln!(
                "mvm-oci-init: no guest agent resolved from /mvm/runtime and no baked \
                 fallback — refusing to boot without the mvm control plane"
            );
            std::process::exit(1);
        };
        spawn_one(&agent, "guest-agent");
        idle_forever();
    }

    fn mount_pseudofs() {
        mount_fs("proc", "/proc", "proc", 0, None);
        mount_fs("sysfs", "/sys", "sysfs", 0, None);
        mount_fs("devtmpfs", "/dev", "devtmpfs", 0, None);
        mount_fs("devpts", "/dev/pts", "devpts", 0, None);
        mount_fs(
            "tmpfs",
            "/run",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            None,
        );
        mount_fs(
            "tmpfs",
            "/tmp",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            None,
        );
    }

    fn ensure_runtime_dirs() {
        for path in [
            "/proc",
            "/sys",
            "/dev",
            "/dev/pts",
            "/dev/shm",
            "/run",
            "/run/mvm",
            "/tmp",
            "/mvm/runtime",
        ] {
            if let Err(e) = fs::create_dir_all(path) {
                eprintln!("mvm-oci-init: mkdir {path}: {e}");
            }
        }
    }

    fn mount_user_volumes() {
        let Some(encoded) = cmdline_value("mvm.uvols") else {
            return;
        };
        for item in encoded.split(';').filter(|s| !s.is_empty()) {
            let mut parts = item.splitn(4, ':');
            let (Some(tag), Some(path_hex), Some(mode), Some(kind)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                eprintln!("mvm-oci-init: malformed user volume token");
                continue;
            };
            let Ok(path_bytes) = hex_decode(path_hex) else {
                eprintln!("mvm-oci-init: malformed user volume path");
                continue;
            };
            let upath = PathBuf::from(OsStr::from_bytes(&path_bytes));
            if kind == "blk" {
                eprintln!(
                    "mvm-oci-init: user disk volume for '{}' attached; guest auto-mount not wired",
                    upath.display()
                );
                continue;
            }
            if let Err(e) = fs::create_dir_all(&upath) {
                eprintln!("mvm-oci-init: mkdir user volume {}: {e}", upath.display());
                continue;
            }
            let flags = if mode == "ro" { libc::MS_RDONLY } else { 0 };
            mount_fs(tag, &upath, "virtiofs", flags, None);
        }
    }

    fn provision_egress_ca() {
        let Some(hex) = cmdline_value("mvm.egress_ca") else {
            return;
        };
        let Ok(cert) = hex_decode(&hex) else {
            eprintln!("mvm-oci-init: malformed egress CA token");
            return;
        };
        let _ = fs::create_dir_all("/run/mvm");
        if let Err(e) = fs::write("/run/mvm/egress-ca.crt", &cert) {
            eprintln!("mvm-oci-init: write egress CA: {e}");
            return;
        }
        let mut bundle = Vec::new();
        for candidate in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-bundle.crt",
        ] {
            if let Ok(bytes) = fs::read(candidate) {
                bundle.extend_from_slice(&bytes);
                if !bundle.ends_with(b"\n") {
                    bundle.push(b'\n');
                }
                break;
            }
        }
        bundle.extend_from_slice(&cert);
        if let Err(e) = fs::write("/run/mvm/ca-bundle.crt", bundle) {
            eprintln!("mvm-oci-init: write CA bundle: {e}");
        }
    }

    fn provision_verb_grant() {
        let Some(hex) = cmdline_value("mvm.verb_grant") else {
            return;
        };
        let Ok(grant) = hex_decode(&hex) else {
            eprintln!("mvm-oci-init: malformed verb-grant token");
            return;
        };
        let _ = fs::create_dir_all("/run/mvm");
        if let Err(e) = fs::write("/run/mvm/verb-grant.json", grant) {
            eprintln!("mvm-oci-init: write verb grant: {e}");
        }
    }

    /// Provision the out-of-band host-signer trust anchor delivered on the kernel
    /// cmdline. Block backends copy this key off the config drive; a vsock-only
    /// guest has no config drive, so the launcher rides the 32-byte public key on
    /// `mvm.host_signer_pub=<hex>` and the agent verifies the grant against it.
    fn provision_host_signer_pub() {
        let Some(hex) = cmdline_value("mvm.host_signer_pub") else {
            return;
        };
        if let Err(e) = write_host_signer_pub(Path::new("/"), &hex) {
            eprintln!("mvm-oci-init: {e}");
        }
    }

    /// Decode the hex host-signer pubkey token and write the raw key bytes to
    /// `<root>/run/mvm/host-signer.pub` with mode 0644. `root` is a seam for
    /// tests; production passes `/`.
    fn write_host_signer_pub(root: &Path, hex: &str) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let bytes =
            hex_decode(hex).map_err(|()| "malformed host-signer pubkey token".to_string())?;
        let dir = root.join("run/mvm");
        fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        let path = dir.join("host-signer.pub");
        fs::write(&path, &bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
        Ok(())
    }

    fn mount_fs(
        source: impl AsRef<OsStr>,
        target: impl AsRef<Path>,
        fstype: &str,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) {
        let source = match cstring_os(source.as_ref()) {
            Some(s) => s,
            None => return,
        };
        let target_path = target.as_ref();
        if let Err(e) = fs::create_dir_all(target_path) {
            eprintln!(
                "mvm-oci-init: mkdir mount target {}: {e}",
                target_path.display()
            );
            return;
        }
        let Some(target) = cstring_os(target_path.as_os_str()) else {
            return;
        };
        let Some(fstype) = cstring_str(fstype) else {
            return;
        };
        let data_c = data.and_then(cstring_str);
        let data_ptr = data_c
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr().cast::<libc::c_void>());
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags,
                data_ptr,
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EBUSY) {
                eprintln!("mvm-oci-init: mount {}: {e}", target_path.display());
            }
        }
    }

    fn resolve_exec<const N: usize>(candidates: [&str; N]) -> Option<PathBuf> {
        candidates
            .into_iter()
            .map(PathBuf::from)
            .find(|p| is_executable(p))
    }

    fn runtime_source_policy() -> mvm_core::vm_backend::RuntimeSourcePolicy {
        cmdline_value("mvm.runtime_source_policy")
            .as_deref()
            .and_then(mvm_core::vm_backend::RuntimeSourcePolicy::from_cmdline_value)
            .unwrap_or(mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay)
    }

    fn guest_security_profile() -> mvm_core::security::AgentProfile {
        mvm_guest::builder_agent::load_security_policy()
            .ok()
            .flatten()
            .map(|policy| policy.profile)
            .unwrap_or_else(|| mvm_core::security::SecurityPolicy::dev_defaults().profile)
    }

    fn resolve_guest_agent() -> Option<PathBuf> {
        resolve_guest_agent_for(
            runtime_source_policy(),
            guest_security_profile(),
            is_executable,
        )
    }

    fn resolve_guest_agent_for(
        runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
        profile: mvm_core::security::AgentProfile,
        is_exec: impl Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        let candidates: &[&str] = match (runtime_source_policy, profile) {
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::Dev,
            ) => &[AGENT_OVERLAY_DEV_SHELL],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_OVERLAY],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                mvm_core::security::AgentProfile::Dev,
            ) => &[AGENT_OVERLAY_DEV_SHELL, AGENT_OVERLAY, AGENT_FALLBACK],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_OVERLAY, AGENT_FALLBACK],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
                mvm_core::security::AgentProfile::Dev
                | mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_FALLBACK],
        };
        candidates
            .iter()
            .map(Path::new)
            .find(|path| is_exec(path))
            .map(Path::to_path_buf)
    }

    fn is_executable(path: &Path) -> bool {
        path.is_file()
            && fs::metadata(path)
                .map(|m| {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o111 != 0
                })
                .unwrap_or(false)
    }

    fn run_one(path: Option<PathBuf>, label: &str) {
        let Some(path) = path else {
            return;
        };
        match Command::new(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => eprintln!("mvm-oci-init: {label} exited {status}"),
            Err(e) => eprintln!("mvm-oci-init: run {label} at {}: {e}", path.display()),
        }
    }

    fn spawn_one(path: &Path, label: &str) {
        if !is_executable(path) {
            eprintln!("mvm-oci-init: no executable {label} at {}", path.display());
            return;
        }
        match Command::new(path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => eprintln!("mvm-oci-init: spawned {label} pid={}", child.id()),
            Err(e) => eprintln!("mvm-oci-init: spawn {label} at {}: {e}", path.display()),
        }
    }

    fn cmdline() -> String {
        fs::read_to_string("/proc/cmdline").unwrap_or_default()
    }

    fn cmdline_value(key: &str) -> Option<String> {
        let prefix = format!("{key}=");
        cmdline()
            .split_whitespace()
            .find_map(|part| part.strip_prefix(&prefix).map(ToOwned::to_owned))
    }

    fn cmdline_has_flag(flag: &str) -> bool {
        cmdline().split_whitespace().any(|part| part == flag)
    }

    fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
        let bytes = input.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            return Err(());
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            let hi = hex_val(pair[0])?;
            let lo = hex_val(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    fn hex_val(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }

    fn bring_loopback_up() {
        if let Err(e) = mvm_guest::guest_net::bring_iface_up("lo") {
            eprintln!("mvm-oci-init: bring loopback up: {e}");
        }
        if loopback_is_up() {
            return;
        }
        if bring_loopback_up_with_busybox() {
            if loopback_is_up() {
                return;
            }
            eprintln!("mvm-oci-init: busybox loopback fallback ran, but lo is still down");
            return;
        }
        eprintln!("mvm-oci-init: loopback remains down (no working busybox ip/ifconfig fallback)");
    }

    fn loopback_is_up() -> bool {
        let Ok(flags) = fs::read_to_string("/sys/class/net/lo/flags") else {
            return false;
        };
        loopback_flags_indicate_up(&flags)
    }

    fn loopback_flags_indicate_up(flags: &str) -> bool {
        let Some(hex) = flags.trim().strip_prefix("0x") else {
            return false;
        };
        u32::from_str_radix(hex, 16)
            .map(|bits| bits & (libc::IFF_UP as u32) != 0)
            .unwrap_or(false)
    }

    fn bring_loopback_up_with_busybox() -> bool {
        let busybox = Path::new("/bin/busybox");
        if !is_executable(busybox) {
            return false;
        }
        let ip_ok = Command::new(busybox)
            .args(["ip", "link", "set", "lo", "up"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if ip_ok {
            return true;
        }
        Command::new(busybox)
            .args(["ifconfig", "lo", "up"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn idle_forever() -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(2_147_483_647));
        }
    }

    fn cstring_str(s: &str) -> Option<CString> {
        CString::new(s)
            .map_err(|_| eprintln!("mvm-oci-init: string contains NUL"))
            .ok()
    }

    fn cstring_os(s: &OsStr) -> Option<CString> {
        CString::new(s.as_bytes())
            .map_err(|_| eprintln!("mvm-oci-init: path contains NUL"))
            .ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hex_decode_accepts_lower_upper_and_rejects_bad_input() {
            assert_eq!(hex_decode("2f62696e").unwrap(), b"/bin");
            assert_eq!(hex_decode("2F").unwrap(), b"/");
            assert!(hex_decode("0").is_err());
            assert!(hex_decode("zz").is_err());
        }

        #[test]
        fn loopback_flags_indicate_up_reads_hex_flags() {
            assert!(!loopback_flags_indicate_up("0x8\n"));
            assert!(loopback_flags_indicate_up("0x9\n"));
            assert!(!loopback_flags_indicate_up("garbage"));
        }

        #[test]
        fn write_host_signer_pub_writes_bytes_mode_0644() {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let pubkey = [0xABu8; 32];
            let hex: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();

            write_host_signer_pub(dir.path(), &hex).unwrap();

            let path = dir.path().join("run/mvm/host-signer.pub");
            let written = fs::read(&path).unwrap();
            assert_eq!(written, pubkey.to_vec(), "raw key bytes must round-trip");
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "host-signer.pub must be mode 0644");
        }

        #[test]
        fn write_host_signer_pub_rejects_malformed_hex() {
            let dir = tempfile::tempdir().unwrap();
            assert!(write_host_signer_pub(dir.path(), "zz").is_err());
            assert!(
                !dir.path().join("run/mvm/host-signer.pub").exists(),
                "no file written on malformed input"
            );
        }

        #[test]
        fn resolve_guest_agent_for_dev_required_overlay_prefers_dev_shell_overlay() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::Dev,
                |path| path == Path::new(AGENT_OVERLAY_DEV_SHELL),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_OVERLAY_DEV_SHELL)));
        }

        #[test]
        fn resolve_guest_agent_for_prod_required_overlay_uses_plain_overlay_agent() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd,
                |path| path == Path::new(AGENT_OVERLAY),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_OVERLAY)));
        }

        #[test]
        fn resolve_guest_agent_for_rootfs_only_dev_falls_back_to_baked_agent() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
                mvm_core::security::AgentProfile::Dev,
                |path| path == Path::new(AGENT_FALLBACK),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_FALLBACK)));
        }

        #[test]
        fn resolve_guest_agent_for_required_overlay_returns_none_when_overlay_missing() {
            // No executable candidate -> None, which main() treats as fatal
            // (fail closed) rather than booting agent-less.
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd,
                |_path| false,
            );
            assert_eq!(got, None);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-oci-init is Linux-only");
}
