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
    const NETINIT_FALLBACK: &str = "/usr/local/bin/mvm-guest-netinit";
    const NETINIT_OVERLAY: &str = "/mvm/runtime/netinit";
    const EGRESS_CLIENT: &str = "/usr/local/bin/mvm-egress-client";

    pub fn main() {
        mount_pseudofs();
        ensure_runtime_dirs();
        mount_user_volumes();
        provision_egress_ca();
        provision_verb_grant();
        run_one(resolve_exec([NETINIT_OVERLAY, NETINIT_FALLBACK]), "netinit");
        if cmdline_has_flag("mvm.vsock_egress=1") {
            bring_loopback_up();
            spawn_one(Path::new(EGRESS_CLIENT), "egress-client");
        }
        spawn_one(
            &resolve_exec([AGENT_OVERLAY, AGENT_FALLBACK])
                .unwrap_or_else(|| PathBuf::from(AGENT_FALLBACK)),
            "guest-agent",
        );
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
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if sock < 0 {
            eprintln!(
                "mvm-oci-init: socket for loopback setup: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // libc's ioctl request type differs per target (c_ulong on gnu,
        // c_int on musl) — `as _` defers to whichever this libc declares.
        let get_flags = libc::SIOCGIFFLAGS as _;
        let set_flags = libc::SIOCSIFFLAGS as _;
        let mut ifr = IfReq::for_name("lo");
        let get_rc = unsafe { libc::ioctl(sock, get_flags, &mut ifr) };
        if get_rc == 0 {
            ifr.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            let set_rc = unsafe { libc::ioctl(sock, set_flags, &ifr) };
            if set_rc != 0 {
                eprintln!(
                    "mvm-oci-init: bring loopback up: {}",
                    std::io::Error::last_os_error()
                );
            }
        } else {
            eprintln!(
                "mvm-oci-init: read loopback flags: {}",
                std::io::Error::last_os_error()
            );
        }
        unsafe {
            libc::close(sock);
        }
    }

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        pad: [u8; 24],
    }

    impl IfReq {
        fn for_name(name: &str) -> Self {
            let mut ifr = Self {
                name: [0; libc::IFNAMSIZ],
                flags: 0,
                pad: [0; 24],
            };
            for (dst, src) in ifr.name.iter_mut().zip(name.as_bytes()) {
                *dst = *src as libc::c_char;
            }
            ifr
        }
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
        fn ifreq_name_is_nul_padded() {
            let ifr = IfReq::for_name("lo");
            assert_eq!(ifr.name[0], b'l' as libc::c_char);
            assert_eq!(ifr.name[1], b'o' as libc::c_char);
            assert_eq!(ifr.name[2], 0);
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
