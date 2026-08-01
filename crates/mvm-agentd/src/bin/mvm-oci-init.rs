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
    const AGENT_OVERLAY_INTERACTIVE: &str = "/mvm/runtime/agent-interactive";
    const NETINIT_FALLBACK: &str = "/usr/local/bin/mvm-guest-netinit";
    const NETINIT_OVERLAY: &str = "/mvm/runtime/netinit";
    const EGRESS_CLIENT: &str = "/usr/local/bin/mvm-egress-client";
    const EGRESS_CLIENT_OVERLAY: &str = "/mvm/runtime/egress-client";

    /// Tools the image ships that cannot work in this guest, and the overlay
    /// binary that stands in for each.
    ///
    /// A NIC-less guest has no route and no raw socket, so the image's own
    /// `ping` fails at `socket()` before a packet exists. The replacement is
    /// bind-mounted over it rather than written into the image: the rootfs keeps
    /// exactly the bytes the registry served (which is what the recorded OCI
    /// provenance refers to), `/proc/mounts` records the substitution for anyone
    /// who wonders, and the original stays underneath. It also reaches a caller
    /// that runs `/bin/ping` outright, which no `PATH` order does.
    const MEDIATED_TOOLS: &[(&str, &str)] = &[("/mvm/runtime/ping", "/bin/ping")];

    pub fn main() {
        mount_pseudofs();
        ensure_runtime_dirs();
        mount_user_volumes();
        mount_mediated_tools();
        provision_egress_ca();
        provision_verb_grant();
        provision_host_signer_pub();
        run_one(resolve_exec([NETINIT_OVERLAY, NETINIT_FALLBACK]), "netinit");
        if cmdline_has_flag("mvm.vsock_egress=1") {
            bring_loopback_up();
            if let Err(error) = mvm_agentd::guest_net::seed_loopback_resolver() {
                // Non-fatal: a read-only image rootfs may have no writable
                // /etc/resolv.conf to repoint, but the workload still reaches its
                // admitted egress through the loopback proxy. Log and continue —
                // panicking PID 1 here would fail an otherwise-bootable VM.
                eprintln!(
                    "mvm-oci-init: could not point resolv.conf at the loopback DNS stub \
                     (continuing; proxy egress is unaffected): {error}"
                );
            }
            // Egress is required when this flag is set; the client is the only guest
            // path to the admitted network. Resolve overlay-first (respecting the
            // runtime-source policy) and fail closed rather than boot a workload that
            // silently cannot reach its allow-listed egress.
            let Some(egress_client) = resolve_egress_client() else {
                eprintln!(
                    "mvm-oci-init: mvm.vsock_egress=1 but no egress client resolved from \
                     /mvm/runtime and no baked fallback — refusing to boot a workload that \
                     cannot reach its admitted egress"
                );
                std::process::exit(1);
            };
            spawn_one(&egress_client, "egress-client");
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

    /// Bind-mount each mediated tool over the image's own copy.
    ///
    /// Skipped silently when either side is absent: an image that ships no
    /// `ping` has nothing to mount over (and the rootfs is read-only under
    /// verity, so one cannot be created), and a launch shape with no runtime
    /// overlay has no replacement to offer. In both cases the image behaves as
    /// it would have without mvm, which is the honest outcome.
    fn mount_mediated_tools() {
        for (source, target) in MEDIATED_TOOLS {
            if !Path::new(source).is_file() || !Path::new(target).exists() {
                continue;
            }
            bind_mount_file(source, target);
        }
    }

    /// `mount(source, target, NULL, MS_BIND, NULL)` over an existing file.
    ///
    /// Distinct from [`mount_fs`], which creates its target as a directory: the
    /// target here is a file that must already exist, and creating it is exactly
    /// what we are avoiding.
    fn bind_mount_file(source: &str, target: &str) {
        let (Some(source_c), Some(target_c)) = (cstring_str(source), cstring_str(target)) else {
            return;
        };
        // SAFETY: both paths are NUL-terminated and live for the call; MS_BIND
        // with a null fstype/data is the documented file-bind form.
        let rc = unsafe {
            libc::mount(
                source_c.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            // Non-fatal: the workload keeps the image's own tool, which simply
            // does not work here. Failing PID 1 over a `ping` would be worse.
            eprintln!(
                "mvm-oci-init: bind {source} over {target}: {}",
                std::io::Error::last_os_error()
            );
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
        let Some(b64) = cmdline_value("mvm.verb_grant") else {
            return;
        };
        // base64, not hex: the envelope is the largest cmdline token and the
        // kernel silently truncates past COMMAND_LINE_SIZE.
        let Ok(grant) = base64_decode(&b64) else {
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
        let cmdline = cmdline();
        let Some(hex) = mvm_agentd::vsock::host_signer_pub_token(&cmdline) else {
            return;
        };
        if let Err(e) = mvm_agentd::vsock::write_host_signer_anchor(Path::new("/"), hex) {
            eprintln!("mvm-oci-init: host-signer anchor not provisioned: {e}");
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

    fn runtime_source_policy() -> mvm_core::vm_backend::RuntimeSourcePolicy {
        cmdline_value("mvm.runtime_source_policy")
            .as_deref()
            .and_then(mvm_core::vm_backend::RuntimeSourcePolicy::from_cmdline_value)
            .unwrap_or(mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay)
    }

    fn guest_security_profile() -> mvm_core::security::AgentProfile {
        mvm_agentd::builder_agent::load_security_policy()
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
            ) => &[AGENT_OVERLAY_INTERACTIVE],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::SealedProd
                | mvm_core::security::AgentProfile::Builder,
            ) => &[AGENT_OVERLAY],
            (
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                mvm_core::security::AgentProfile::Dev,
            ) => &[AGENT_OVERLAY_INTERACTIVE, AGENT_OVERLAY, AGENT_FALLBACK],
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

    fn resolve_egress_client() -> Option<PathBuf> {
        resolve_egress_client_for(runtime_source_policy(), is_executable)
    }

    fn resolve_egress_client_for(
        runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
        is_exec: impl Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        let candidates: &[&str] = match runtime_source_policy {
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay => &[EGRESS_CLIENT_OVERLAY],
            mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay => {
                &[EGRESS_CLIENT_OVERLAY, EGRESS_CLIENT]
            }
            mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly => &[EGRESS_CLIENT],
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

    /// Standard-alphabet base64 decode, hand-rolled to keep this PID 1 free of
    /// external crates (see the module doc). Rejects a character after padding,
    /// a trailing partial character, and non-zero padding bits.
    fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
        let mut acc: u32 = 0;
        let mut nbits: u32 = 0;
        let mut seen_pad = false;
        let mut out = Vec::with_capacity(input.len() / 4 * 3);
        for &b in input.as_bytes() {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'=' {
                seen_pad = true;
                continue;
            }
            if seen_pad {
                return Err(());
            }
            acc = (acc << 6) | u32::from(base64_val(b)?);
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push(((acc >> nbits) & 0xff) as u8);
            }
        }
        // A lone trailing character carries 6 unusable bits, and whatever bits
        // remain must be the encoder's zero padding.
        if nbits >= 6 || acc & ((1u32 << nbits) - 1) != 0 {
            return Err(());
        }
        Ok(out)
    }

    fn base64_val(b: u8) -> Result<u8, ()> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(()),
        }
    }

    fn bring_loopback_up() {
        if let Err(e) = mvm_agentd::guest_net::bring_iface_up("lo") {
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
        fn base64_decode_round_trips_each_padding_length() {
            // 0, 1 and 2 bytes of padding respectively.
            assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
            assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
            assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
            assert_eq!(base64_decode("").unwrap(), b"");
            // Both non-alphanumeric alphabet characters.
            assert_eq!(base64_decode("+/8=").unwrap(), [0xfb, 0xff]);
        }

        #[test]
        fn base64_decode_rejects_malformed_input() {
            assert!(base64_decode("Zm9v!mFy").is_err(), "invalid character");
            assert!(base64_decode("Zm9vYmFyZ").is_err(), "trailing partial char");
            assert!(base64_decode("Zm9v=YmFy").is_err(), "data after padding");
            // Non-zero bits under the padding.
            assert!(base64_decode("Zm9vYh==").is_err(), "dirty padding bits");
        }

        #[test]
        fn loopback_flags_indicate_up_reads_hex_flags() {
            assert!(!loopback_flags_indicate_up("0x8\n"));
            assert!(loopback_flags_indicate_up("0x9\n"));
            assert!(!loopback_flags_indicate_up("garbage"));
        }

        // The anchor writer moved to `mvm_agentd::vsock::write_host_signer_anchor`
        // so both inits share one implementation; its byte layout, 0644 mode and
        // malformed-token refusal are covered there rather than duplicated here.

        #[test]
        fn resolve_guest_agent_for_dev_required_overlay_prefers_interactive_overlay() {
            let got = resolve_guest_agent_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                mvm_core::security::AgentProfile::Dev,
                |path| path == Path::new(AGENT_OVERLAY_INTERACTIVE),
            );
            assert_eq!(got, Some(PathBuf::from(AGENT_OVERLAY_INTERACTIVE)));
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

        #[test]
        fn resolve_egress_client_for_required_overlay_resolves_overlay() {
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                |path| path == Path::new(EGRESS_CLIENT_OVERLAY),
            );
            assert_eq!(got, Some(PathBuf::from(EGRESS_CLIENT_OVERLAY)));
        }

        #[test]
        fn resolve_egress_client_for_required_overlay_returns_none_when_nothing_executable() {
            // No executable candidate -> None, which main() treats as fatal
            // (fail closed) rather than booting a workload with no egress path.
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                |_path| false,
            );
            assert_eq!(got, None);
        }

        #[test]
        fn resolve_egress_client_for_required_overlay_does_not_fall_back_to_baked() {
            // Only the baked path is executable; required-overlay must not accept it.
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                |path| path == Path::new(EGRESS_CLIENT),
            );
            assert_eq!(got, None);
        }

        #[test]
        fn resolve_egress_client_for_prefer_overlay_prefers_overlay_when_both_present() {
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                |_path| true,
            );
            assert_eq!(got, Some(PathBuf::from(EGRESS_CLIENT_OVERLAY)));
        }

        #[test]
        fn resolve_egress_client_for_prefer_overlay_falls_back_to_baked() {
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                |path| path == Path::new(EGRESS_CLIENT),
            );
            assert_eq!(got, Some(PathBuf::from(EGRESS_CLIENT)));
        }

        #[test]
        fn resolve_egress_client_for_rootfs_only_ignores_overlay_and_uses_baked() {
            // Overlay executable but policy is rootfs-only -> only the baked
            // candidate is considered, so it wins.
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
                |path| path == Path::new(EGRESS_CLIENT_OVERLAY) || path == Path::new(EGRESS_CLIENT),
            );
            assert_eq!(got, Some(PathBuf::from(EGRESS_CLIENT)));
        }

        #[test]
        fn resolve_egress_client_for_rootfs_only_returns_none_when_baked_missing() {
            let got = resolve_egress_client_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
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
