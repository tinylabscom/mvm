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
/// Whether `/` is mounted read-only.
///
/// Read from `/proc/mounts` once rather than inferred from each failure,
/// because it is a property of the image and not of any one step: a sealed prod
/// rootfs takes no writes at all, and every optional provisioning step below
/// fails against it identically. Probing the mount is also type-independent —
/// these steps return `MountError`, `io::Error` and `String` between them, so
/// classifying per-error would need every path to preserve an errno, and one
/// that stopped doing so would silently go back to shouting.
fn rootfs_is_read_only() -> bool {
    // Actually once, not once per step. Every optional step consults this, so
    // the un-cached version read the file six times on exactly the sealed boot
    // this exists to quieten, and the doc above claimed otherwise. The mount
    // cannot change under a running init, so caching costs nothing.
    static READ_ONLY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *READ_ONLY.get_or_init(|| {
        let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
            // Unreadable /proc: assume writable, which keeps every failure loud.
            // The wrong guess here costs noise, and the other one costs silence.
            return false;
        };
        root_is_read_only_in(&mounts)
    })
}

/// The `/proc/mounts` half of [`rootfs_is_read_only`], split out so it can be
/// tested against real mount tables without a guest.
fn root_is_read_only_in(mounts: &str) -> bool {
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (Some(_dev), Some(target), Some(_fstype), Some(opts)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        // Exactly `ro`, never a prefix: `rootflags`, `rootcontext` and
        // `relatime` all begin with the same two letters, and matching a
        // substring would silence every failure on a writable rootfs.
        target == "/" && opts.split(',').any(|o| o == "ro")
    })
}

/// Steps that were skipped because the rootfs takes no writes.
static READ_ONLY_SKIPS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Report an optional provisioning step that did not run.
///
/// Every caller is optional by construction — see `provision_workload_identity`
/// — and the workload runs without any of them. On a read-only rootfs none of
/// them *can* run, so reporting each separately described a healthy sealed
/// image as six distinct failures on every boot. Collect those and state the
/// one fact behind them; anything else stays at full volume.
fn note_optional_step(step: &str, detail: &dyn std::fmt::Display) {
    if rootfs_is_read_only() {
        if let Ok(mut skips) = READ_ONLY_SKIPS.lock() {
            skips.push(step.to_string());
        }
        return;
    }
    eprintln!("mvm-guest-init: {step}: {detail}");
}

/// Say once what the collected steps have in common.
fn report_read_only_skips() {
    let Ok(skips) = READ_ONLY_SKIPS.lock() else {
        return;
    };
    if skips.is_empty() {
        return;
    }
    eprintln!(
        "mvm-guest-init: rootfs is mounted read-only, so these optional steps were \
         skipped: {}. The workload runs without them.",
        skips.join(", ")
    );
}

pub fn provision_guest_environment() -> Result<(), EgressClientMissing> {
    provision_hostname();
    ensure_runtime_dirs();
    provision_workload_identity();
    mount_mediated_tools();
    provision_egress_ca();
    provision_verb_grant();
    provision_flowmux_identity();
    start_forward_proxy();
    run_one(resolve_exec([NETINIT_OVERLAY, NETINIT_FALLBACK]), "netinit");
    if cmdline_has_flag("mvm.vsock_egress=1") {
        start_vsock_egress()?;
    }
    report_read_only_skips();
    Ok(())
}

/// Give the workload a home it owns and a name for its uid.
///
/// Both are cosmetic-until-they-aren't: without the home the shell starts in a
/// directory it cannot write, and without the `/etc/passwd` entry `whoami`
/// exits nonzero and `getpwuid()` returns `NULL` to any library that asks.
/// Neither failure is worth refusing to boot over.
///
/// The home comes from a tmpfs laid over a mount point the image carries,
/// which needs no write to the root and so works on the read-only roots every
/// workload actually boots with. The account entries are baked in at image
/// materialization for the same reason; the writable-root branch below is the
/// fallback for a root mvm did not materialize, and calls the same
/// `provision_in` the materializer does.
fn provision_workload_identity() {
    if let Err(error) = crate::guest_mount::mount_workload_home() {
        // Deliberately not routed through `note_optional_step`: that bucket
        // means "the read-only root explains this", and mounting over a
        // directory needs no write to the root. A failure here is its own
        // fact and stays at full volume.
        eprintln!(
            "mvm-guest-init: could not mount a writable home at {} \
             (continuing with {} as $HOME): {error}",
            crate::guest_mount::WORKLOAD_HOME,
            crate::guest_mount::WORKLOAD_HOME_FALLBACK
        );
    }
    if !crate::guest_mount::optional_image_writes_allowed(rootfs_is_read_only()) {
        return;
    }
    if let Err(error) = crate::guest_mount::ensure_workload_home() {
        note_optional_step(
            &format!(
                "workload home {} (falling back to {})",
                crate::guest_mount::WORKLOAD_HOME,
                crate::guest_mount::WORKLOAD_HOME_FALLBACK
            ),
            &error,
        );
    }
    if let Err(error) = crate::workload_identity::provision() {
        note_optional_step(
            &format!(
                "naming uid {} in /etc/passwd (whoami and getpwuid will not resolve it)",
                crate::guest_mount::WORKLOAD_UID
            ),
            &error,
        );
    }
}

/// Start the loopback forward proxy the substitution path relays through.
///
/// Here, as a privileged child, rather than inside the guest agent: relaying
/// opens an authenticated FlowMux session, which reads the guest signing key,
/// and the key is root-only precisely so the workload — whose uid the agent
/// shares — cannot authenticate as its own guest. Served from the agent, every
/// relay failed on that read and the workload got a `502`.
///
/// Unconditional, and not gated on `mvm.vsock_egress=1` in particular: that
/// token is *off* for exactly the launches that need this. A secret-bearing
/// workload's egress goes through the host substitution endpoint, so its guest
/// deliberately starts no vsock egress client, and this listener is the whole
/// of its egress. A workload with no placeholders has no `HTTP_PROXY` pointed
/// here and the listener simply sees no connections.
///
/// Non-fatal if it cannot be resolved. Unlike the egress client, whose absence
/// means an admitted network is silently unreachable, this one is used only by
/// a launch that minted placeholders — and that launch fails loudly on its
/// first request rather than quietly reaching the network unsubstituted.
fn start_forward_proxy() {
    let Some(proxy) = resolve_forward_proxy() else {
        note_optional_step(
            "loopback forward proxy (secret-bearing egress will have nothing to relay through)",
            &"no executable at /mvm/runtime/forward-proxy or /usr/local/bin/mvm-forward-proxy",
        );
        return;
    };
    spawn_one(&proxy, "forward-proxy");
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

pub const FORWARD_PROXY: &str = "/usr/local/bin/mvm-forward-proxy";

pub const FORWARD_PROXY_OVERLAY: &str = "/mvm/runtime/forward-proxy";

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
            note_optional_step(&format!("mkdir {path}"), &e);
        }
    }
    // The workload runs unprivileged, so the two world-writable scratch
    // directories have to actually be world-writable. An image that ships them
    // already has them at 1777; one that does not (`scratch`, distroless) gets
    // whatever `create_dir_all` chose, which is root-owned 0755 — and every
    // tempfile the workload opens then fails with EACCES.
    for path in ["/tmp", "/dev/shm"] {
        if let Err(e) = fs::set_permissions(
            path,
            std::os::unix::fs::PermissionsExt::from_mode(SCRATCH_DIR_MODE),
        ) {
            note_optional_step(&format!("chmod 1777 {path}"), &e);
        }
    }
}

/// `drwxrwxrwt` — world-writable with the sticky bit, so one workload process
/// cannot delete another's files.
const SCRATCH_DIR_MODE: u32 = 0o1777;

/// Deliver each mediated tool, by both routes available.
///
/// A launch shape with no runtime overlay has no replacement to offer, and
/// that case is skipped silently — the image behaves as it would have without
/// mvm, which is the honest outcome.
pub fn mount_mediated_tools() {
    for (source, target) in MEDIATED_TOOLS {
        if !Path::new(source).is_file() {
            continue;
        }
        // Always reachable by name, even when the image ships no copy to mount
        // over and even when the rootfs is sealed against the mount.
        install_mediated_tool(source, target);
        if !Path::new(target).exists() {
            continue;
        }
        let Err(first) = substitute_in_place(source, target) else {
            continue;
        };
        // The image's copy is a symlink and the rootfs will not take the write
        // that replaces it. Make just its directory writable and retry, so a
        // caller running the tool by absolute path reaches the stand-in too.
        match overlay_parent_for_write(Path::new(target)) {
            Ok(()) => {
                if let Err(second) = substitute_in_place(source, target) {
                    eprintln!("mvm-guest-init: {target} not substituted after overlay: {second}");
                }
            }
            Err(e) => note_optional_step(
                &format!("substituting {target}, left as the image shipped it ({first})"),
                &e,
            ),
        }
    }
}

/// Make `dir` writable in place by stacking a tmpfs over it.
///
/// The verified image is the lower layer and stays exactly as the registry
/// served it — dm-verity still covers those blocks, and nothing writes through
/// to them. Only the substitution lands in the upper, which is root-owned on
/// the `/run` tmpfs, so the workload's unprivileged uid cannot reach it either.
/// Scoped to the one directory holding a mediated tool rather than the whole
/// root, so every other path keeps resolving straight to the sealed image.
fn overlay_parent_for_write(target: &Path) -> Result<(), String> {
    let dir = target
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", target.display()))?;
    let (upper, work) = overlay_dirs_for(dir);
    for path in [&upper, &work] {
        fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }
    // overlayfs requires upper and work on one filesystem; both are on /run.
    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        dir.display(),
        upper.display(),
        work.display()
    );
    mount_overlay(dir, &options)
}

/// Where a directory's overlay upper and work dirs live.
///
/// Mirrors the directory under one root so two mediated tools in different
/// directories cannot collide on the same upper.
fn overlay_dirs_for(dir: &Path) -> (PathBuf, PathBuf) {
    let base = Path::new("/run/mvm/overlay").join(dir.strip_prefix("/").unwrap_or(dir));
    (base.join("upper"), base.join("work"))
}

fn mount_overlay(target: &Path, options: &str) -> Result<(), String> {
    let target_str = target
        .to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", target.display()))?;
    let (Some(source_c), Some(target_c), Some(fstype_c), Some(options_c)) = (
        cstring_str("overlay"),
        cstring_str(target_str),
        cstring_str("overlay"),
        cstring_str(options),
    ) else {
        return Err("mount arguments contain NUL".to_string());
    };
    // SAFETY: every pointer is NUL-terminated and outlives the call.
    let rc = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            fstype_c.as_ptr(),
            0,
            options_c.as_ptr().cast::<libc::c_void>(),
        )
    };
    if rc != 0 {
        return Err(format!(
            "mount overlay on {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Replace the image's copy of a tool with the stand-in, in place.
fn substitute_in_place(source: &str, target: &str) -> Result<(), String> {
    replace_symlink_target(Path::new(target))?;
    bind_mount_file(source, target)
}

/// Link a stand-in into the mediated-tool directory so `PATH` finds it.
///
/// The bind mount is the stronger delivery — it reaches a caller that runs
/// `/bin/ping` outright, which no `PATH` order does — but it cannot apply to a
/// symlink on a read-only rootfs. This route always applies: `/run` is a tmpfs
/// the init just mounted.
pub fn install_mediated_tool(source: &str, target: &str) {
    install_mediated_tool_in(
        Path::new(mvm_core::guest_netd::MEDIATED_TOOLS_BIN),
        source,
        target,
    );
}

fn install_mediated_tool_in(dir: &Path, source: &str, target: &str) {
    let Some(name) = Path::new(target).file_name() else {
        return;
    };
    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("mvm-guest-init: mkdir {}: {e}", dir.display());
        return;
    }
    let link = dir.join(name);
    // Replace rather than fail: activation can retry, and a stale link from a
    // previous boot would shadow the current overlay.
    let _ = fs::remove_file(&link);
    if let Err(e) = std::os::unix::fs::symlink(source, &link) {
        eprintln!("mvm-guest-init: link {source} to {}: {e}", link.display());
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
/// The target must already exist as a regular file — creating one is exactly
/// what this avoids, so the image keeps the bytes the registry served.
/// [`substitute_in_place`] is responsible for getting it there.
pub fn bind_mount_file(source: &str, target: &str) -> Result<(), String> {
    let (Some(source_c), Some(target_c)) = (cstring_str(source), cstring_str(target)) else {
        return Err("mount arguments contain NUL".to_string());
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
        return Err(format!(
            "bind {source} over {target}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
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

/// Copy this boot's FlowMux identity out of the host-attached drive into
/// `/run/mvm`, so the egress client can authenticate its session.
///
/// Best-effort here, deliberately: this runs on every guest boot, including
/// ones whose policy admits no egress and which therefore get no identity
/// drive. The refusal belongs where egress is actually required — the egress
/// client itself will not bind without the keys, and the builder inits turn
/// that into a named refusal. Making it fatal here would refuse boots that
/// never wanted networking.
pub fn provision_flowmux_identity() {
    #[cfg(target_os = "linux")]
    if let Err(error) = crate::flowmux_drive::provision_identity_from_drive()
        && let Some(warning) = error.boot_warning()
    {
        eprintln!("mvm-init: FlowMux identity not provisioned: {warning}");
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
    resolve_runtime_binary_for(
        runtime_source_policy,
        EGRESS_CLIENT_OVERLAY,
        EGRESS_CLIENT,
        is_exec,
    )
}

pub fn resolve_forward_proxy() -> Option<PathBuf> {
    resolve_forward_proxy_for(runtime_source_policy(), is_executable)
}

pub fn resolve_forward_proxy_for(
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
    is_exec: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    resolve_runtime_binary_for(
        runtime_source_policy,
        FORWARD_PROXY_OVERLAY,
        FORWARD_PROXY,
        is_exec,
    )
}

/// Pick the overlay or the baked copy of one helper, per the boot's declared
/// runtime-source policy.
///
/// One rule for every helper. A required-overlay boot is a statement about
/// where *all* of the runtime came from, so a helper that quietly fell back to
/// a baked copy would be the one binary in the guest the declaration did not
/// cover — and it would take a reader comparing two ladders to notice.
fn resolve_runtime_binary_for(
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
    overlay: &'static str,
    baked: &'static str,
    is_exec: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let candidates: &[&str] = match runtime_source_policy {
        mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay => &[overlay],
        mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay => &[overlay, baked],
        mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly => &[baked],
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

/// Spawn a helper the way `spawn_one` does, but as an unprivileged user.
///
/// The guest agent is started this way because it serves the verbs that run
/// workload code, and every one of those spawn sites inherits the agent's
/// identity rather than setting its own. On the pid-1 boot path the agent
/// drops privilege itself once its mounts are done; on this path the init
/// owns the mounts, so the agent never needs root and is handed the workload
/// identity from the start. Both paths converge on the same posture: nothing
/// that executes workload code runs as uid 0.
#[cfg(target_os = "linux")]
pub fn spawn_one_as(path: &Path, label: &str, uid: u32, gid: u32) {
    use std::os::unix::process::CommandExt;

    if !is_executable(path) {
        eprintln!(
            "mvm-guest-init: no executable {label} at {}",
            path.display()
        );
        return;
    }
    let mut cmd = Command::new(path);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // SAFETY: the hook runs in the forked child before exec. It calls only
    // async-signal-safe syscalls and allocates nothing, which is what
    // `drop_guest_agent_privilege_raw` exists to guarantee.
    unsafe {
        cmd.pre_exec(move || crate::guest_mount::drop_guest_agent_privilege_raw(uid, gid));
    }
    match cmd.spawn() {
        Ok(child) => eprintln!(
            "mvm-guest-init: spawned {label} pid={} uid={uid} gid={gid}",
            child.id()
        ),
        Err(e) => eprintln!("mvm-guest-init: spawn {label} at {}: {e}", path.display()),
    }
}

pub fn cmdline() -> String {
    fs::read_to_string("/proc/cmdline").unwrap_or_default()
}

pub fn cmdline_value(key: &str) -> Option<String> {
    crate::guest_hostname::cmdline_value_from(&cmdline(), key).map(ToOwned::to_owned)
}

fn provision_hostname() {
    match crate::guest_hostname::provision_from(
        &cmdline(),
        crate::guest_hostname::set_kernel_hostname,
    ) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("mvm-guest-init: no mvm.hostname token; keeping the kernel hostname")
        }
        Err(error) => eprintln!("mvm-guest-init: could not set guest hostname: {error}"),
    }
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
    if let Err(e) = crate::guest_net::configure_loopback() {
        eprintln!("mvm-guest-init: configure loopback: {e}");
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

    /// The forward proxy follows the same declaration the egress client does.
    /// A required-overlay boot that ran a baked copy would be one binary the
    /// declaration did not actually cover.
    #[test]
    fn resolve_forward_proxy_for_required_overlay_does_not_fall_back_to_baked() {
        assert_eq!(
            resolve_forward_proxy_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                |path| path == Path::new(FORWARD_PROXY),
            ),
            None
        );
        assert_eq!(
            resolve_forward_proxy_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
                |path| path == Path::new(FORWARD_PROXY_OVERLAY),
            ),
            Some(PathBuf::from(FORWARD_PROXY_OVERLAY))
        );
    }

    #[test]
    fn resolve_forward_proxy_for_prefers_the_overlay_and_falls_back_when_allowed() {
        assert_eq!(
            resolve_forward_proxy_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                |_| true
            ),
            Some(PathBuf::from(FORWARD_PROXY_OVERLAY))
        );
        assert_eq!(
            resolve_forward_proxy_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
                |path| path == Path::new(FORWARD_PROXY),
            ),
            Some(PathBuf::from(FORWARD_PROXY))
        );
        assert_eq!(
            resolve_forward_proxy_for(
                mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
                |_| true
            ),
            Some(PathBuf::from(FORWARD_PROXY))
        );
    }

    /// The two helpers must not drift apart: they are the same decision about
    /// where the runtime came from, and the shared rule is what keeps them one.
    #[test]
    fn the_egress_client_and_the_forward_proxy_resolve_by_the_same_rule() {
        for policy in [
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
        ] {
            let only_baked = |overlay: &'static str, baked: &'static str| {
                (
                    resolve_runtime_binary_for(policy, overlay, baked, |p| p == Path::new(baked)),
                    baked,
                )
            };
            let (egress, egress_baked) = only_baked(EGRESS_CLIENT_OVERLAY, EGRESS_CLIENT);
            let (proxy, proxy_baked) = only_baked(FORWARD_PROXY_OVERLAY, FORWARD_PROXY);
            assert_eq!(
                egress.map(|p| p == Path::new(egress_baked)),
                proxy.map(|p| p == Path::new(proxy_baked)),
                "{policy:?} treated the two helpers differently"
            );
        }
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

    /// The delivery that still works when the rootfs is sealed: a link in the
    /// mediated-tool dir, which `PATH` finds even though the bind mount cannot
    /// apply to a symlink on a read-only filesystem.
    #[test]
    fn install_mediated_tool_links_the_stand_in_under_its_target_name() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");

        install_mediated_tool_in(&bin, "/mvm/runtime/ping", "/bin/ping");

        // Named for the tool it stands in for, so `ping` on PATH finds it.
        let link = bin.join("ping");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new("/mvm/runtime/ping")
        );
    }

    #[test]
    fn install_mediated_tool_replaces_a_stale_link_from_a_previous_boot() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink("/stale/ping", bin.join("ping")).unwrap();

        install_mediated_tool_in(&bin, "/mvm/runtime/ping", "/bin/ping");

        assert_eq!(
            fs::read_link(bin.join("ping")).unwrap(),
            Path::new("/mvm/runtime/ping")
        );
    }

    #[test]
    fn overlay_dirs_mirror_the_directory_under_one_root() {
        let (upper, work) = overlay_dirs_for(Path::new("/bin"));
        assert_eq!(upper, Path::new("/run/mvm/overlay/bin/upper"));
        assert_eq!(work, Path::new("/run/mvm/overlay/bin/work"));
    }

    /// Two tools in different directories must not share an upper, or the
    /// second overlay would inherit the first's substitution.
    #[test]
    fn overlay_dirs_do_not_collide_across_directories() {
        let (bin_upper, _) = overlay_dirs_for(Path::new("/bin"));
        let (sbin_upper, _) = overlay_dirs_for(Path::new("/usr/sbin"));
        assert_ne!(bin_upper, sbin_upper);
        assert_eq!(sbin_upper, Path::new("/run/mvm/overlay/usr/sbin/upper"));
    }

    /// upperdir and workdir must sit on one filesystem for overlayfs to mount;
    /// both live under the /run tmpfs the init already mounted.
    #[test]
    fn overlay_upper_and_work_share_a_filesystem() {
        let (upper, work) = overlay_dirs_for(Path::new("/bin"));
        assert!(upper.starts_with("/run"));
        assert!(work.starts_with("/run"));
        assert_eq!(upper.parent(), work.parent());
    }

    #[test]
    fn mediated_tools_bin_is_an_absolute_guest_path() {
        assert!(Path::new(mvm_core::guest_netd::MEDIATED_TOOLS_BIN).is_absolute());
    }

    #[test]
    fn mediated_tools_name_the_target_binary() {
        for (source, target) in MEDIATED_TOOLS {
            assert!(target.starts_with('/'), "{target} must be absolute");
            assert!(
                source.starts_with("/mvm/runtime/"),
                "{source} is an overlay path"
            );
            assert!(
                Path::new(target).file_name().is_some(),
                "{target} must name a binary for the PATH route"
            );
        }
    }
}

#[cfg(test)]
mod read_only_rootfs_tests {
    use super::root_is_read_only_in;

    /// A sealed prod guest: `/` carries `ro`, so the optional provisioning
    /// steps below cannot run and should be reported once rather than six
    /// times.
    #[test]
    fn a_read_only_root_is_recognised() {
        let mounts = "\
/dev/vda / ext4 ro,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
";
        assert!(root_is_read_only_in(mounts));
    }

    /// A dev guest, and the case that must stay loud: every failure on a
    /// writable rootfs is a real failure worth printing.
    #[test]
    fn a_writable_root_is_not() {
        let mounts = "\
/dev/vda / ext4 rw,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
";
        assert!(!root_is_read_only_in(mounts));
    }

    /// The substring trap. `rootflags`, `rootcontext` and `relatime` all start
    /// with `r`, and `errors=remount-ro` ends with `ro`; matching anything but
    /// the whole option would silence real failures on a writable image.
    #[test]
    fn an_option_that_merely_contains_ro_is_not_a_read_only_mount() {
        let mounts = "/dev/vda / ext4 rw,relatime,errors=remount-ro 0 0\n";
        assert!(
            !root_is_read_only_in(mounts),
            "`errors=remount-ro` is not `ro`"
        );
    }

    /// Only `/` counts. A read-only mount somewhere else says nothing about
    /// whether these steps can run.
    #[test]
    fn a_read_only_mount_elsewhere_does_not_count() {
        let mounts = "\
/dev/vda / ext4 rw,relatime 0 0
/dev/vdb /mvm/runtime ext4 ro,relatime 0 0
";
        assert!(!root_is_read_only_in(mounts));
    }

    /// A short or blank line must not panic or match.
    #[test]
    fn malformed_lines_are_ignored() {
        assert!(!root_is_read_only_in("\n/ ro\ngarbage\n"));
    }
}
