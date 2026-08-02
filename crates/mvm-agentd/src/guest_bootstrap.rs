//! Guest environment setup shared by the two guest inits.
//!
//! Both entry points reach the same workload environment: `mvm-oci-init` as PID 1
//! on the legacy per-rootfs initrd, and the guest agent's activation path when the
//! universal initramfs boots it as PID 1. Keeping the steps here means neither can
//! quietly acquire — or lose — one of them.

use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The egress client could not be resolved while egress was required.
///
/// Fail-closed: a workload that boots without it silently cannot reach the
/// network its plan admitted, which reads as a policy denial rather than a
/// missing binary.
#[derive(Debug, PartialEq, Eq)]
pub struct EgressClientMissing;

/// Run every post-mount setup step the workload environment depends on.
///
/// Callers must invoke this after the rootfs is in place and while still
/// privileged: the mounts, `/run/mvm` writes and interface changes all need root.
pub fn provision_guest_environment() -> Result<(), EgressClientMissing> {
    ensure_runtime_dirs();
    mount_mediated_tools();
    provision_egress_ca();
    provision_verb_grant();
    run_one(resolve_exec([NETINIT_OVERLAY, NETINIT_FALLBACK]), "netinit");
    if cmdline_has_flag("mvm.vsock_egress=1") {
        start_vsock_egress()?;
    }
    Ok(())
}

fn start_vsock_egress() -> Result<(), EgressClientMissing> {
    bring_loopback_up();
    if let Err(error) = crate::guest_net::seed_loopback_resolver() {
        // Non-fatal: a read-only image rootfs may have no writable
        // /etc/resolv.conf to repoint, but the workload still reaches its
        // admitted egress through the loopback proxy.
        eprintln!(
            "mvm-guest-init: could not point resolv.conf at the loopback DNS stub \
             (continuing; proxy egress is unaffected): {error}"
        );
    }
    let Some(egress_client) = resolve_egress_client() else {
        eprintln!(
            "mvm-guest-init: mvm.vsock_egress=1 but no egress client resolved from \
             /mvm/runtime and no baked fallback — refusing to boot a workload that \
             cannot reach its admitted egress"
        );
        return Err(EgressClientMissing);
    };
    spawn_one(&egress_client, "egress-client");
    Ok(())
}

pub const NETINIT_FALLBACK: &str = "/usr/local/bin/mvm-guest-netinit";

pub const NETINIT_OVERLAY: &str = "/mvm/runtime/netinit";

pub const EGRESS_CLIENT: &str = "/usr/local/bin/mvm-egress-client";

pub const EGRESS_CLIENT_OVERLAY: &str = "/mvm/runtime/egress-client";

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
pub const MEDIATED_TOOLS: &[(&str, &str)] = &[("/mvm/runtime/ping", "/bin/ping")];

pub fn ensure_runtime_dirs() {
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
            eprintln!("mvm-guest-init: mkdir {path}: {e}");
        }
    }
}

/// Bind-mount each mediated tool over the image's own copy.
///
/// Skipped silently when either side is absent: an image that ships no
/// `ping` has nothing to mount over (and the rootfs is read-only under
/// verity, so one cannot be created), and a launch shape with no runtime
/// overlay has no replacement to offer. In both cases the image behaves as
/// it would have without mvm, which is the honest outcome.
pub fn mount_mediated_tools() {
    for (source, target) in MEDIATED_TOOLS {
        if !Path::new(source).is_file() || !Path::new(target).exists() {
            continue;
        }
        bind_mount_file(source, target);
    }
}

/// Convert to a NUL-terminated C string for the raw mount syscalls.
pub fn cstring_str(s: &str) -> Option<CString> {
    CString::new(s)
        .map_err(|_| eprintln!("mvm-guest-init: string contains NUL"))
        .ok()
}

/// Make `target` a plain file so a later bind mount lands on it and nothing else.
///
/// `MS_BIND` resolves the target path, so mounting onto a symlink lands on
/// whatever it points at. Busybox images link every applet at one binary —
/// `/bin/ping` and `/bin/sh` both point at `/bin/busybox` — so mounting over the
/// link would replace the shell along with the tool. Swap the link for an empty
/// regular file first, staging then renaming so a failure leaves the image as it was.
pub fn replace_symlink_target(target: &Path) -> Result<(), String> {
    match fs::symlink_metadata(target) {
        Ok(meta) if meta.file_type().is_symlink() => {}
        // A regular file is already an exclusive path: a bind mount over one
        // hardlink does not disturb its siblings.
        Ok(_) => return Ok(()),
        Err(e) => return Err(format!("stat {}: {e}", target.display())),
    }
    let staged = target.with_extension("mvm-mediated");
    fs::File::create(&staged).map_err(|e| format!("create {}: {e}", staged.display()))?;
    fs::rename(&staged, target).map_err(|e| {
        let _ = fs::remove_file(&staged);
        format!("replace symlink {}: {e}", target.display())
    })
}

/// `mount(source, target, NULL, MS_BIND, NULL)` over an existing file.
///
/// The target must already exist as a file; creating one is exactly what this
/// avoids, so the image keeps the bytes the registry served.
pub fn bind_mount_file(source: &str, target: &str) {
    if let Err(e) = replace_symlink_target(Path::new(target)) {
        // Non-fatal, and deliberately before the mount: leaving the image's own
        // tool in place is far better than mounting through a link.
        eprintln!("mvm-guest-init: not substituting {target}: {e}");
        return;
    }
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
            "mvm-guest-init: bind {source} over {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

pub fn provision_egress_ca() {
    let Some(hex) = cmdline_value("mvm.egress_ca") else {
        return;
    };
    let Some(cert) = hex_decode(&hex) else {
        eprintln!("mvm-guest-init: malformed egress CA token");
        return;
    };
    let _ = fs::create_dir_all("/run/mvm");
    if let Err(e) = fs::write("/run/mvm/egress-ca.crt", &cert) {
        eprintln!("mvm-guest-init: write egress CA: {e}");
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
        eprintln!("mvm-guest-init: write CA bundle: {e}");
    }
}

pub fn provision_verb_grant() {
    let Some(b64) = cmdline_value("mvm.verb_grant") else {
        return;
    };
    // base64, not hex: the envelope is the largest cmdline token and the
    // kernel silently truncates past COMMAND_LINE_SIZE.
    let Some(grant) = base64_decode(&b64) else {
        eprintln!("mvm-guest-init: malformed verb-grant token");
        return;
    };
    let _ = fs::create_dir_all("/run/mvm");
    if let Err(e) = fs::write("/run/mvm/verb-grant.json", grant) {
        eprintln!("mvm-guest-init: write verb grant: {e}");
    }
}

pub fn resolve_exec<const N: usize>(candidates: [&str; N]) -> Option<PathBuf> {
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|p| is_executable(p))
}

pub fn runtime_source_policy() -> mvm_core::vm_backend::RuntimeSourcePolicy {
    cmdline_value("mvm.runtime_source_policy")
        .as_deref()
        .and_then(mvm_core::vm_backend::RuntimeSourcePolicy::from_cmdline_value)
        .unwrap_or(mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay)
}

pub fn resolve_egress_client() -> Option<PathBuf> {
    resolve_egress_client_for(runtime_source_policy(), is_executable)
}

pub fn resolve_egress_client_for(
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

pub fn is_executable(path: &Path) -> bool {
    path.is_file()
        && fs::metadata(path)
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            })
            .unwrap_or(false)
}

pub fn run_one(path: Option<PathBuf>, label: &str) {
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
        Ok(status) => eprintln!("mvm-guest-init: {label} exited {status}"),
        Err(e) => eprintln!("mvm-guest-init: run {label} at {}: {e}", path.display()),
    }
}

pub fn spawn_one(path: &Path, label: &str) {
    if !is_executable(path) {
        eprintln!(
            "mvm-guest-init: no executable {label} at {}",
            path.display()
        );
        return;
    }
    match Command::new(path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => eprintln!("mvm-guest-init: spawned {label} pid={}", child.id()),
        Err(e) => eprintln!("mvm-guest-init: spawn {label} at {}: {e}", path.display()),
    }
}

pub fn cmdline() -> String {
    fs::read_to_string("/proc/cmdline").unwrap_or_default()
}

pub fn cmdline_value(key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    cmdline()
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix).map(ToOwned::to_owned))
}

pub fn cmdline_has_flag(flag: &str) -> bool {
    cmdline().split_whitespace().any(|part| part == flag)
}

pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Standard-alphabet base64 decode, hand-rolled to keep this PID 1 free of
/// external crates (see the module doc). Rejects a character after padding,
/// a trailing partial character, and non-zero padding bits.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
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
            return None;
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
        return None;
    }
    Some(out)
}

fn base64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn bring_loopback_up() {
    if let Err(e) = crate::guest_net::bring_iface_up("lo") {
        eprintln!("mvm-guest-init: bring loopback up: {e}");
    }
    if loopback_is_up() {
        return;
    }
    if bring_loopback_up_with_busybox() {
        if loopback_is_up() {
            return;
        }
        eprintln!("mvm-guest-init: busybox loopback fallback ran, but lo is still down");
        return;
    }
    eprintln!("mvm-guest-init: loopback remains down (no working busybox ip/ifconfig fallback)");
}

pub fn loopback_is_up() -> bool {
    let Ok(flags) = fs::read_to_string("/sys/class/net/lo/flags") else {
        return false;
    };
    loopback_flags_indicate_up(&flags)
}

pub fn loopback_flags_indicate_up(flags: &str) -> bool {
    let Some(hex) = flags.trim().strip_prefix("0x") else {
        return false;
    };
    u32::from_str_radix(hex, 16)
        .map(|bits| bits & (libc::IFF_UP as u32) != 0)
        .unwrap_or(false)
}

pub fn bring_loopback_up_with_busybox() -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_accepts_lower_upper_and_rejects_bad_input() {
        assert_eq!(hex_decode("2f62696e").unwrap(), b"/bin");
        assert_eq!(hex_decode("2F").unwrap(), b"/");
        assert!(hex_decode("0").is_none());
        assert!(hex_decode("zz").is_none());
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
        assert!(base64_decode("Zm9v!mFy").is_none(), "invalid character");
        assert!(
            base64_decode("Zm9vYmFyZ").is_none(),
            "trailing partial char"
        );
        assert!(base64_decode("Zm9v=YmFy").is_none(), "data after padding");
        // Non-zero bits under the padding.
        assert!(base64_decode("Zm9vYh==").is_none(), "dirty padding bits");
    }

    #[test]
    fn loopback_flags_indicate_up_reads_hex_flags() {
        assert!(!loopback_flags_indicate_up("0x8\n"));
        assert!(loopback_flags_indicate_up("0x9\n"));
        assert!(!loopback_flags_indicate_up("garbage"));
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

    #[test]
    fn replace_symlink_target_swaps_a_symlink_for_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let busybox = dir.path().join("busybox");
        fs::write(&busybox, b"multi-call binary").unwrap();
        let ping = dir.path().join("ping");
        std::os::unix::fs::symlink(&busybox, &ping).unwrap();

        replace_symlink_target(&ping).unwrap();

        // The link is gone, so a bind mount here cannot reach busybox...
        assert!(
            !fs::symlink_metadata(&ping)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // ...and busybox itself is untouched, which is what keeps `sh` working.
        assert_eq!(fs::read(&busybox).unwrap(), b"multi-call binary");
    }

    #[test]
    fn replace_symlink_target_leaves_a_regular_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let ping = dir.path().join("ping");
        fs::write(&ping, b"real ping").unwrap();

        replace_symlink_target(&ping).unwrap();

        assert_eq!(fs::read(&ping).unwrap(), b"real ping");
    }

    #[test]
    fn replace_symlink_target_reports_a_missing_target() {
        let dir = tempfile::tempdir().unwrap();
        let err = replace_symlink_target(&dir.path().join("absent")).unwrap_err();
        assert!(err.contains("stat"), "unexpected error: {err}");
    }

    #[test]
    fn replace_symlink_target_leaves_no_staging_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ping");
        std::os::unix::fs::symlink(dir.path().join("busybox"), &target).unwrap();

        replace_symlink_target(&target).unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().contains("mvm-mediated"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "staging file left behind: {leftovers:?}"
        );
    }
}
