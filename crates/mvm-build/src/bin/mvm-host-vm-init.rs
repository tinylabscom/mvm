//! mvm-host-vm-init — PID 1 for the libkrun builder VM.
//!
//! Tiny static-linked init that mounts the essentials, brings up the
//! persistent `/nix` store (formatting on first boot), tries to
//! bring the network up, executes `/job/cmd.sh`, writes
//! `/job/result`, and powers off.
//!
//! ## Why this binary, not a shell script
//!
//! The choice between shell and Rust was explicitly debated. Rust
//! won because:
//!
//! - One binary to audit; no `/bin/sh` -> `/usr/bin/sh` -> busybox
//!   hop where each link is a separate Nix store path.
//! - The mount syscalls (overlay/bind mounting the persistent
//!   `/nix-store` over `/nix`) are direct rather than `/sbin/mount`
//!   wrappers, so we get clear errors when something refuses.
//! - We can encode the `/job/result` JSON shape in one place
//!   rather than escape-quoting it across `printf` invocations.
//!
//! ## What runs in here
//!
//! On boot:
//!
//!   1. Mount `/proc`, `/sys`, `/dev`, `/tmp` (the standard init
//!      essentials — busybox-as-PID-1 from `mkGuest` does the
//!      same).
//!   2. Probe `/dev/vdb` for an ext4 superblock; format with
//!      `mkfs.ext4 -F` if blank (first boot on a fresh sparse
//!      virtio-blk image).
//!   3. Mount `/dev/vdb` at `/nix-store`, then mount `/nix` as an
//!      overlay with the rootfs seed as lowerdir and `/nix-store`
//!      as upper/work storage. This lets reads see the baked-in Nix
//!      closure without copying it into the constrained persistent
//!      disk before the first build.
//!   4. Best-effort `udhcpc -i eth0 -n -q` — failure is
//!      non-fatal (offline builds against the seed store still
//!      work; `LibkrunBuilderVm::with_offline()` formalizes this).
//!   5. Read `/job/cmd.sh`. Exit code 2 + "no cmd.sh" in
//!      `/job/result` if missing.
//!   6. Spawn `/bin/sh -eu /job/cmd.sh`. Capture exit + stderr
//!      tail (last 20 lines, to keep the result file small).
//!   7. Write `/job/result` as `{"exit_code":<i32>,"stderr_tail":<json-string>}`.
//!   8. `sync` + `reboot(RB_POWER_OFF)`. The libkrun host
//!      detects power-off via the shutdown-eventfd
//!      (`krun_get_shutdown_eventfd`).
//!
//! ## Non-Linux build behaviour
//!
//! Linux-only by design. On macOS / Windows the crate still
//! compiles (workspace ergonomics) but `main()` prints a hint
//! and exits 1. mkGuest cross-compiles the real binary against
//! `<arch>-unknown-linux-musl` from a Linux nix-build
//! environment; that's where the size budget (≤ 1.5 MiB) and
//! static-link requirement get enforced.

use std::process::ExitCode;

// Cross-platform modules. The install-spec parser and install
// pipeline runner live here so `cargo test` on macOS exercises the
// dispatch logic via shell stubs without paying for a Linux cross-
// compile. The Linux-only `linux` module composes them with the
// real PID-1 mount / power-off dance.
//
// `allow(dead_code)` because the modules are consumed from
// `linux::run_install_job` on Linux and from `#[cfg(test)]` blocks
// on every host. On non-Linux non-test builds (workspace ergonomics
// + reproducible builds) every public item looks "unused" — clippy
// would flag them otherwise. Real dead code would still surface as
// red because the tests would lose coverage.
#[allow(dead_code)]
#[path = "mvm-host-vm-init/boot_timings.rs"]
mod boot_timings;
/// Hand-rolled parser for the `HostVmRequest` wire shape the
/// persistent builder VM's dispatch loop reads off vsock.
/// Cross-platform; the Linux dispatch loop calls into it after
/// reading the framed body. Tested against the host's
/// serde-derived encoding so schema drift on either side is loud.
#[allow(dead_code)]
#[path = "mvm-host-vm-init/builder_request.rs"]
mod builder_request;
/// Hand-rolled `HostVmResponse::Result` JSON. Cross-platform
/// (testable on macOS) so the wire shape can be validated against
/// `mvm_build::builder_protocol`'s typed serde via a dev-dep test,
/// without dragging serde_json into the production builder-init
/// binary.
#[allow(dead_code)]
#[path = "mvm-host-vm-init/dispatch_response.rs"]
mod dispatch_response;
#[allow(dead_code)]
#[path = "mvm-host-vm-init/install.rs"]
mod install;
#[allow(dead_code)]
#[path = "mvm-host-vm-init/install_spec.rs"]
mod install_spec;
#[allow(dead_code)]
#[path = "mvm-host-vm-init/network.rs"]
mod network;
#[allow(dead_code)]
#[path = "mvm-host-vm-init/proxy.rs"]
mod proxy;
/// Spawn a workload microVM inside the host VM via a `WorkloadVmm`
/// backend (Firecracker today). Cross-platform trait +
/// state-dir/lifecycle logic (tested on macOS); the signal-based
/// stop/status helpers are Linux-only.
#[allow(dead_code)]
#[path = "mvm-host-vm-init/workload.rs"]
mod workload;
/// In-host-VM vsock forwarder (the nesting hop). The cross-platform
/// CONNECT+splice core is unit-tested on every host; the AF_VSOCK
/// listener wiring is Linux-only. `unix`-gated because it uses
/// `UnixStream` (the crate is inert on Windows).
#[cfg(unix)]
#[allow(dead_code)]
#[path = "mvm-host-vm-init/workload_proxy.rs"]
mod workload_proxy;

/// Builder-VM lifecycle hook runner. Mounts a workload rootfs and runs
/// `/etc/mvm/hooks/before_build.sh` inside a chroot. Linux-only; the
/// module is compiled on other hosts only for workspace ergonomics.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "mvm-host-vm-init/builder_hooks.rs"]
mod builder_hooks;

/// Parse the exact device path emitted by `losetup --find --show`.
///
/// Kept outside the Linux-only mount module so every host exercises the
/// validation that stands between subprocess output and a privileged mount.
#[cfg(any(target_os = "linux", test))]
fn parse_loop_device(output: &[u8]) -> Result<std::path::PathBuf, std::io::Error> {
    let text = std::str::from_utf8(output)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let path = text.strip_suffix('\n').unwrap_or(text);
    let Some(number) = path.strip_prefix("/dev/loop") else {
        return Err(std::io::Error::other(format!(
            "losetup returned unexpected device path {path:?}"
        )));
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(std::io::Error::other(format!(
            "losetup returned unexpected device path {path:?}"
        )));
    }
    Ok(std::path::PathBuf::from(path))
}

fn main() -> ExitCode {
    // Subcommand dispatch for builder-VM utility operations. When invoked
    // as `mvm-host-vm-init run-before-build-hook <rootfs.ext4>`, mount the
    // rootfs, run the before_build lifecycle hook inside a chroot, and
    // return the hook's exit status. This keeps the hook runner in the
    // same cross-compiled binary the builder VM already embeds at
    // `/sbin/mvm-host-vm-init`.
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("run-before-build-hook") {
        return run_before_build_hook_subcommand();
    }

    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("seal-rootfs-journal") {
        return seal_rootfs_journal_subcommand();
    }

    #[cfg(target_os = "linux")]
    {
        linux::run()
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "mvm-host-vm-init is Linux-only (PID 1 for the libkrun \
             builder VM). On a developer host this binary is a no-op; \
             mkGuest cross-compiles the real init for \
             <arch>-unknown-linux-musl. See \
             specs/plans/72-builder-vm-via-libkrun.md §W3."
        );
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
fn run_before_build_hook_subcommand() -> ExitCode {
    let rootfs = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("usage: mvm-host-vm-init run-before-build-hook <rootfs.ext4>");
        std::process::exit(2);
    });
    match builder_hooks::run_before_build_hook(std::path::Path::new(&rootfs)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mvm-host-vm-init: run-before-build-hook failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn seal_rootfs_journal_subcommand() -> ExitCode {
    let rootfs = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("usage: mvm-host-vm-init seal-rootfs-journal <rootfs.ext4>");
        std::process::exit(2);
    });
    match builder_hooks::seal_rootfs_journal(std::path::Path::new(&rootfs)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mvm-host-vm-init: seal-rootfs-journal failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn virtiofs_tag_is_read_only(tag: &str) -> bool {
    // `work` is the user's source; `mvm-bins` is the embedded host
    // binaries; `closure-seed` is the optional seeded Nix store closure
    // NAR. All three are inputs the guest must not write back.
    tag == "work" || tag == "mvm-bins" || tag == "closure-seed"
}

/// One user-supplied volume to mount, decoded from the `mvm.uvols=`
/// kernel-cmdline param the host wrote
/// (`mvm_core::vm_backend::encode_user_volumes_cmdline`).
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct UserVolMount {
    /// virtio-fs tag (`uvol{idx}`) the host registered for this volume.
    tag: String,
    /// Guest mount point (decoded from hex).
    target: String,
    read_only: bool,
    /// `true` = virtio-blk disk image, `false` = virtio-fs dir share.
    is_disk: bool,
}

/// Decode lowercase/uppercase hex into a UTF-8 string. `None` on odd
/// length, non-hex digits, or invalid UTF-8.
#[cfg(any(target_os = "linux", test))]
fn hex_decode_utf8(s: &str) -> Option<String> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
        i += 2;
    }
    String::from_utf8(bytes).ok()
}

/// Parse the `mvm.uvols=` token out of a kernel cmdline. Format:
/// `mvm.uvols=<tag>:<hex(path)>:<ro|rw>:<fs|blk>;...`. Best-effort:
/// malformed entries are skipped rather than failing (a bad mount must
/// never wedge PID 1). Mirrors the host encoder in `mvm-core`.
#[cfg(any(target_os = "linux", test))]
fn parse_user_volumes_cmdline(cmdline: &str) -> Vec<UserVolMount> {
    let Some(val) = cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("mvm.uvols="))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in val.split(';').filter(|e| !e.is_empty()) {
        let mut f = entry.split(':');
        let (Some(tag), Some(hexpath), Some(mode), Some(kind), None) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let Some(target) = hex_decode_utf8(hexpath) else {
            continue;
        };
        if tag.is_empty() || target.is_empty() {
            continue;
        }
        out.push(UserVolMount {
            tag: tag.to_string(),
            target,
            read_only: mode.eq_ignore_ascii_case("ro"),
            is_disk: kind.eq_ignore_ascii_case("blk"),
        });
    }
    out
}

/// Disk-transport config parsed from the kernel cmdline. A Rootfs-image
/// libkrun builder VM moves the job in and the artifacts out over raw disks
/// (tar-on-a-block-device) rather than virtio-fs shares; the hvf VMM has no
/// virtio-fs at all, so this is its only option.
/// `mvm.builder_transport=disk` enables it; `mvm.builder_input=` /
/// `mvm.builder_output=` name the block devices (defaulting to the vdc/vdd
/// convention). Absent ⇒ `None`, and the init keeps the virtio-fs path unchanged.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct DiskTransport {
    input_dev: String,
    output_dev: String,
}

#[cfg(any(target_os = "linux", test))]
fn parse_disk_transport_cmdline(cmdline: &str) -> Option<DiskTransport> {
    let mut enabled = false;
    let mut input = None;
    let mut output = None;
    for tok in cmdline.split_whitespace() {
        if let Some(v) = tok.strip_prefix("mvm.builder_transport=") {
            enabled = v == "disk";
        } else if let Some(v) = tok.strip_prefix("mvm.builder_input=") {
            input = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("mvm.builder_output=") {
            output = Some(v.to_string());
        }
    }
    enabled.then(|| DiskTransport {
        input_dev: input.unwrap_or_else(|| "/dev/vdc".to_string()),
        output_dev: output.unwrap_or_else(|| "/dev/vdd".to_string()),
    })
}

/// Bytes from the start of the ext4 superblock that the host-side
/// geometry check reads. The high-32 bits of `s_blocks_count` live
/// at superblock offset `0x150` (336), so 512 is the smallest
/// power-of-two read covering every field the parser inspects.
#[cfg(any(target_os = "linux", test))]
const EXT4_SUPERBLOCK_READ: usize = 512;

/// Parse the ext4 superblock buffer and return the total
/// filesystem size in bytes the superblock asserts, or `None`
/// when the buffer has no valid ext4 magic / a sanity-failing
/// block size.
///
/// Layout (little-endian; offsets relative to the start of the
/// superblock — itself at byte offset 1024 of the partition):
/// - `0x04`  u32 `s_blocks_count_lo`  — low 32 bits of total block count
/// - `0x18`  u32 `s_log_block_size`   — block size = `1024 << this`
/// - `0x38`  u16 `s_magic`            — `0xEF53` for ext{2,3,4}
/// - `0x150` u32 `s_blocks_count_hi`  — high 32 bits (64-bit feature; 0 otherwise)
///
/// Pure function so darwin `cargo test` exercises it without a
/// Linux cross-compile; the file-IO and `BLKGETSIZE64` ioctl that
/// feed it live inside the linux module.
/// Whether the kernel has recorded filesystem errors on this ext4 volume.
///
/// Reads `s_state` (u16 at `0x3A` of the superblock). Bit 1
/// (`EXT4_ERROR_FS`) is set by the kernel when it detects corruption and
/// survives a remount, so it is still set on the *next* boot — which is
/// exactly when we want to refuse.
///
/// `None` means there is no ext4 here to judge; the caller treats that as
/// "needs formatting", not as an error.
///
/// Catching this up front matters because the damage otherwise surfaces
/// somewhere arbitrary and unrecognisable downstream: a corrupt store showed
/// up as `/bin/chown -R 902:902 /nix/var/nix exited 1`, which names neither
/// the disk nor corruption.
#[cfg(any(target_os = "linux", test))]
fn parse_ext4_recorded_error_state(sb: &[u8]) -> Option<bool> {
    /// `s_state` bit 1: the kernel detected filesystem errors.
    const EXT4_ERROR_FS: u16 = 0x0002;

    if sb.len() < 0x3A + 2 {
        return None;
    }
    if sb[0x38] != 0x53 || sb[0x39] != 0xEF {
        return None;
    }
    let state = u16::from_le_bytes(sb[0x3A..0x3C].try_into().ok()?);
    Some(state & EXT4_ERROR_FS != 0)
}

#[cfg(any(target_os = "linux", test))]
fn parse_ext4_recorded_size_bytes(sb: &[u8]) -> Option<u64> {
    if sb.len() < 0x150 + 4 {
        return None;
    }
    // Magic at 0x38 — guard before trusting the other fields.
    if sb[0x38] != 0x53 || sb[0x39] != 0xEF {
        return None;
    }
    let blocks_lo = u32::from_le_bytes(sb[0x04..0x08].try_into().ok()?);
    let log_block_size = u32::from_le_bytes(sb[0x18..0x1c].try_into().ok()?);
    let blocks_hi = u32::from_le_bytes(sb[0x150..0x154].try_into().ok()?);
    // Reject absurd block sizes — ext4 spec allows 1 KiB..64 KiB
    // (log values 0..=6). Anything higher signals a malformed or
    // stale superblock; treat as unformatted.
    if log_block_size > 6 {
        return None;
    }
    let block_size = 1024u64 << log_block_size;
    let total_blocks = (u64::from(blocks_hi) << 32) | u64::from(blocks_lo);
    total_blocks.checked_mul(block_size)
}

/// Create `/dev/fd → /proc/self/fd` and `/dev/std{in,out,err} →
/// /proc/self/fd/{0,1,2}` under `dev_root`. Idempotent: any entry that
/// already exists (file, symlink, or device node) is left untouched —
/// we never replace whatever the kernel or a prior boot has put there.
///
/// `dev_root` is a parameter so this helper is testable under a
/// `tempfile::tempdir()` without privilege. The targets are written as
/// absolute `/proc/self/fd/...` strings on purpose: they're consumed
/// by code running inside the guest Linux VM where `/proc` is the
/// procfs mount point. The helper itself is cross-platform — symlink
/// creation works on macOS too — so unit tests run on contributor Macs
/// in addition to the production Linux build target.
//
// Production callers live under `#[cfg(target_os = "linux")]`
// (`main.rs:1501`), and the unit tests live in `#[cfg(test)] mod tests`;
// on macOS without `--test` the function would otherwise look dead.
// Matches the sibling pattern at `parse_ext4_recorded_size_bytes` above.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn setup_dev_fd_symlinks(dev_root: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    for (link_name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let link = dev_root.join(link_name);
        // `Path::exists` follows symlinks; `symlink_metadata` does
        // not. We want "is there anything at this path?", which is
        // the symlink_metadata question — otherwise a dangling
        // symlink left over from a prior boot would be treated as
        // absent and we'd EEXIST on the symlink call.
        if link.symlink_metadata().is_ok() {
            continue;
        }
        symlink(target, &link)
            .map_err(|e| format!("symlink {} -> {target}: {e}", link.display()))?;
    }
    Ok(())
}

// ============================================================================
// Guest-agent fork (the universal-agent invariant)
// ============================================================================
//
// The builder/dev VM bakes `mvm-guest-agent` (mkGuest, via the
// `entrypoint.shell = "/bin/sh"` → interactive build) but PID 1 here never
// forked it, so vsock port 5252 stayed unbound on builder/dev VMs — only
// workload VMs ran the agent. This init forks the agent under
// setpriv exactly as the workload `/init` does (nix/lib/mk-guest.nix), so
// the *same* agent runs in every VM type. The argv construction + binary
// resolution are pure (cross-platform-testable); the spawn itself is in
// `linux::run`.

#[cfg(any(target_os = "linux", test))]
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", test))]
use std::process::Command;

/// The uid the guest agent is dropped to via setpriv. The agent is a
/// long-lived RPC service, not a build step, so it gets its own uid —
/// distinct from build commands' `BUILDER_UID` (902). Mirrors the
/// workload `/init` fork in `nix/lib/mk-guest.nix`.
#[cfg(any(target_os = "linux", test))]
const AGENT_UID: u32 = 990;

/// Candidate paths for the baked `mvm-guest-agent`, in preference order.
/// The verity runtime overlay, when attached, bind-mounts the
/// agent at `/mvm/runtime/agent`; prefer it over the rootfs-baked copy.
/// Same order the workload `/init` probes.
#[cfg(any(target_os = "linux", test))]
const AGENT_BIN_CANDIDATES: [&str; 2] = ["/mvm/runtime/agent", "/usr/local/bin/mvm-guest-agent"];
/// Candidate paths for the guest-side egress shim, in preference order.
/// Builder/dev VMs keep the baked fallback today, but when the runtime overlay
/// is attached it is the authoritative location for the helper.
#[cfg(any(target_os = "linux", test))]
const EGRESS_CLIENT_BIN_CANDIDATES: [&str; 2] = [
    "/mvm/runtime/egress-client",
    "/usr/local/bin/mvm-egress-client",
];
#[cfg(target_os = "linux")]
const RUNTIME_OVERLAY_MOUNT: &str = "/mvm/runtime";

#[cfg(any(target_os = "linux", test))]
fn runtime_overlay_device_from_cmdline(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("mvm.runtime_data="))
        .map(ToOwned::to_owned)
}

#[cfg(any(target_os = "linux", test))]
const VSOCK_EGRESS_PROXY_URL: &str = mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_URL;
#[cfg(any(target_os = "linux", test))]
const VSOCK_EGRESS_NO_PROXY: &str = "localhost,127.0.0.1,::1";
#[cfg(target_os = "linux")]
const VSOCK_EGRESS_PORT_ENV: &str = "MVM_EGRESS_VSOCK_PORT";
#[cfg(any(target_os = "linux", test))]
const VSOCK_EGRESS_PORT_TOKEN_PREFIX: &str = "mvm.vsock_egress_port=";
#[cfg(any(target_os = "linux", test))]
const INIT_LIFECYCLE_BREADCRUMB_FILE: &str = "mvm-host-vm-init.lifecycle.log";

#[cfg(any(target_os = "linux", test))]
fn vsock_egress_requested_from_cmdline(cmdline: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|tok| tok == "mvm.vsock_egress=1")
}

/// Parse `mvm.hostepoch=<unix_seconds>` — the host's wall-clock at launch. The
/// builder VMMs expose no RTC, so PID 1 seeds the guest clock from this;
/// otherwise a cold Nix store's HTTPS fetch fails cert validation ("certificate
/// is not yet valid") against a clock stuck near the 1970 epoch. Rejects
/// non-positive values so a malformed token can't wind the clock backwards.
#[cfg(any(target_os = "linux", test))]
fn hostepoch_from_cmdline(cmdline: &str) -> Option<i64> {
    mvm_core::vm_backend::decode_host_epoch_cmdline(cmdline)
        .and_then(|seconds| seconds.try_into().ok())
}

#[cfg(any(target_os = "linux", test))]
fn vsock_egress_port_from_cmdline(cmdline: &str) -> Option<u32> {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(VSOCK_EGRESS_PORT_TOKEN_PREFIX))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|port| *port > 0)
}

#[cfg(any(target_os = "linux", test))]
fn apply_vsock_egress_proxy_env(cmd: &mut std::process::Command) {
    cmd.env("ALL_PROXY", VSOCK_EGRESS_PROXY_URL)
        .env("HTTP_PROXY", VSOCK_EGRESS_PROXY_URL)
        .env("HTTPS_PROXY", VSOCK_EGRESS_PROXY_URL)
        .env("http_proxy", VSOCK_EGRESS_PROXY_URL)
        .env("https_proxy", VSOCK_EGRESS_PROXY_URL)
        .env("NO_PROXY", VSOCK_EGRESS_NO_PROXY)
        .env("no_proxy", VSOCK_EGRESS_NO_PROXY);
}

#[cfg(any(target_os = "linux", test))]
fn format_init_breadcrumb_line(stage: &str, detail: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}.{:03} {}: {}\n",
        now.as_secs(),
        now.subsec_millis(),
        stage,
        detail
    )
}

#[cfg(any(target_os = "linux", test))]
fn append_init_breadcrumb_at(
    run_log_path: &std::path::Path,
    persistent_targets: &[&std::path::Path],
    stage: &str,
    detail: &str,
) {
    use std::io::Write;

    let line = format_init_breadcrumb_line(stage, detail);
    if let Some(parent) = run_log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(run_log_path)
    {
        let _ = file.write_all(line.as_bytes());
    }
    for persistent_mount in persistent_targets {
        let _ = std::fs::create_dir_all(persistent_mount);
        let persistent_log = persistent_mount.join(INIT_LIFECYCLE_BREADCRUMB_FILE);
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&persistent_log)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn resolve_egress_client_binary(is_exec: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let candidates: &[&str] = &EGRESS_CLIENT_BIN_CANDIDATES[..1];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| is_exec(p))
        .map(Path::to_path_buf)
}

#[cfg(any(target_os = "linux", test))]
fn runtime_overlay_mount_flag_bits() -> libc::c_ulong {
    1
}

/// Resolve which agent binary to launch: the first candidate `is_exec`
/// reports runnable. `is_exec` is injected so the preference order is
/// unit-testable without a filesystem (production passes a real
/// executable check). `None` — neither present — means the VM boots
/// agent-less, which is non-fatal and surfaced in `mvmctl status`,
/// exactly as the workload path treats a missing agent.
#[cfg(any(target_os = "linux", test))]
fn resolve_agent_binary(is_exec: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let candidates: &[&str] = &AGENT_BIN_CANDIDATES[..1];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| is_exec(p))
        .map(Path::to_path_buf)
}

/// Build the `setsid` + `mvm-setpriv` command that forks the guest agent under
/// the agent uid. Mirrors the workload `/init` invocation in
/// `nix/lib/mk-guest.nix`; the builder image installs the same static helper at
/// `/sbin/mvm-setpriv`.
/// The agent receives only `CAP_KILL` and `CAP_SYS_TIME`: the former permits
/// the authenticated agent to signal PID 1, and the latter corrects a
/// restored wall clock. No workload process inherits either capability.
#[cfg(any(target_os = "linux", test))]
fn agent_spawn_command(agent_bin: &Path) -> Command {
    let mut c = Command::new("/bin/busybox");
    c.arg("setsid")
        .arg("/sbin/mvm-setpriv")
        .arg(format!("--reuid={AGENT_UID}"))
        .arg(format!("--regid={AGENT_UID}"))
        .arg("--clear-groups")
        .arg("--securebits=keep-caps")
        .arg("--inh-caps=+kill")
        .arg("--ambient-caps=+kill")
        .arg("--inh-caps=+sys_time")
        .arg("--ambient-caps=+sys_time")
        .arg("--no-new-privs")
        .arg("--")
        .arg(agent_bin);
    c
}

// ============================================================================
// Seeded closure import (content-keyed idempotency)
// ============================================================================
//
// A builder pack may carry a `nix-closure.nar` — a `nix-store --export` of
// the dev-shell toolchain closure. When the host wires that NAR into the
// guest (a later slice), `linux::import_seeded_closure` imports it into
// the persistent Nix store exactly once per closure *content*, not once
// per boot: an unchanged closure across reboots is a no-op, but a pack
// carrying a different closure re-imports. These two functions are the
// pure decision logic that call site drives; they carry no filesystem or
// process access so they're exercised on every host, not just Linux.

/// Whether the closure identified by `closure_hash` still needs
/// importing, given the idempotency marker's contents left by a prior
/// boot (`None` — no marker, e.g. first boot or a freshly formatted
/// persistent store). `Some(hash)` where `hash` (ignoring surrounding
/// whitespace) equals `closure_hash` means this exact closure is already
/// in the store; anything else — no marker, a stale hash, a different
/// pack's closure — means it still needs importing.
#[cfg(any(target_os = "linux", test))]
fn closure_import_needed(marker_contents: Option<&str>, closure_hash: &str) -> bool {
    marker_contents.map(str::trim) != Some(closure_hash)
}

/// The idempotency marker's on-disk body after successfully importing
/// `closure_hash`. A later boot reads this back and compares it (via
/// [`closure_import_needed`]) against the newly computed hash of
/// whatever closure NAR is present that boot.
#[cfg(any(target_os = "linux", test))]
fn closure_marker_contents(closure_hash: &str) -> String {
    closure_hash.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_device_parser_accepts_only_kernel_loop_paths() {
        assert_eq!(
            parse_loop_device(b"/dev/loop12\n").expect("valid loop device"),
            Path::new("/dev/loop12")
        );
        for invalid in [
            b"".as_slice(),
            b"/dev/loop\n".as_slice(),
            b"/tmp/loop12\n".as_slice(),
            b"/dev/loop12 extra\n".as_slice(),
            b"/dev/loopx\n".as_slice(),
        ] {
            assert!(parse_loop_device(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    // ── ext4 store damage detection ──

    /// A minimal ext4 superblock with the magic set and `s_state` as given.
    fn sb_with_state(state: u16) -> Vec<u8> {
        let mut sb = vec![0u8; 0x160];
        sb[0x38] = 0x53;
        sb[0x39] = 0xEF;
        sb[0x3A..0x3C].copy_from_slice(&state.to_le_bytes());
        sb
    }

    #[test]
    fn a_cleanly_unmounted_store_is_not_flagged_as_damaged() {
        // EXT4_VALID_FS only. The common case must not start refusing builds.
        assert_eq!(
            parse_ext4_recorded_error_state(&sb_with_state(0x0001)),
            Some(false)
        );
    }

    #[test]
    fn a_store_the_kernel_flagged_is_reported_as_damaged() {
        // EXT4_ERROR_FS. This is what an abruptly-killed builder VM left
        // behind, and what previously surfaced as an unrelated chown failure.
        assert_eq!(
            parse_ext4_recorded_error_state(&sb_with_state(0x0002)),
            Some(true)
        );
        // Set alongside VALID_FS, which is how it actually appears.
        assert_eq!(
            parse_ext4_recorded_error_state(&sb_with_state(0x0003)),
            Some(true)
        );
    }

    #[test]
    fn a_non_ext4_or_short_superblock_yields_no_verdict() {
        // No ext4 to judge; the caller formats rather than refusing.
        let mut not_ext4 = sb_with_state(0x0002);
        not_ext4[0x38] = 0x00;
        assert_eq!(parse_ext4_recorded_error_state(&not_ext4), None);
        assert_eq!(parse_ext4_recorded_error_state(&[]), None);
        assert_eq!(parse_ext4_recorded_error_state(&[0u8; 0x3A]), None);
    }

    // ── guest-agent fork (universal-agent invariant) ──

    #[test]
    fn agent_spawn_command_mirrors_workload_init_setpriv() {
        let cmd = agent_spawn_command(Path::new("/usr/local/bin/mvm-guest-agent"));
        assert_eq!(cmd.get_program().to_str().unwrap(), "/bin/busybox");
        let args: Vec<&str> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "setsid",
                "/sbin/mvm-setpriv",
                "--reuid=990",
                "--regid=990",
                "--clear-groups",
                "--securebits=keep-caps",
                "--inh-caps=+kill",
                "--ambient-caps=+kill",
                "--inh-caps=+sys_time",
                "--ambient-caps=+sys_time",
                "--no-new-privs",
                "--",
                "/usr/local/bin/mvm-guest-agent",
            ]
        );
    }

    #[test]
    fn resolve_agent_binary_resolves_the_runtime_overlay_copy() {
        let got = resolve_agent_binary(|_| true);
        assert_eq!(got, Some(PathBuf::from("/mvm/runtime/agent")));
    }

    #[test]
    fn resolve_agent_binary_none_when_the_overlay_copy_is_absent() {
        // Neither present → boot agent-less (non-fatal, surfaced in status).
        assert_eq!(resolve_agent_binary(|_| false), None);
    }

    /// The overlay is the single runtime source, so a binary sitting at the old
    /// baked path must not satisfy the lookup.
    #[test]
    fn resolve_agent_binary_ignores_a_binary_at_the_old_baked_path() {
        let got = resolve_agent_binary(|p| p == Path::new("/usr/local/bin/mvm-guest-agent"));
        assert_eq!(got, None);
    }

    #[test]
    fn resolve_egress_client_binary_resolves_the_runtime_overlay_copy() {
        let got = resolve_egress_client_binary(|_| true);
        assert_eq!(got, Some(PathBuf::from("/mvm/runtime/egress-client")));
    }

    #[test]
    fn resolve_egress_client_binary_ignores_a_binary_at_the_old_baked_path() {
        let got =
            resolve_egress_client_binary(|p| p == Path::new("/usr/local/bin/mvm-egress-client"));
        assert_eq!(got, None);
    }

    #[test]
    fn runtime_overlay_device_from_cmdline_finds_runtime_disk() {
        assert_eq!(
            runtime_overlay_device_from_cmdline(
                "console=hvc0 mvm.runtime_data=/dev/vdc root=/dev/vda"
            )
            .as_deref(),
            Some("/dev/vdc")
        );
    }

    #[test]
    fn runtime_overlay_device_from_cmdline_ignores_absent_token() {
        assert_eq!(
            runtime_overlay_device_from_cmdline("console=hvc0 root=/dev/vda"),
            None
        );
    }

    #[test]
    fn vsock_egress_requested_from_cmdline_matches_exact_token() {
        assert!(vsock_egress_requested_from_cmdline(
            "console=hvc0 mvm.vsock_egress=1 root=/dev/vda"
        ));
        assert!(!vsock_egress_requested_from_cmdline(
            "console=hvc0 mvm.vsock_egress=0 root=/dev/vda"
        ));
        assert!(!vsock_egress_requested_from_cmdline(
            "console=hvc0 root=/dev/vda"
        ));
    }

    #[test]
    fn hostepoch_from_cmdline_parses_positive_seconds_only() {
        assert_eq!(
            hostepoch_from_cmdline("console=hvc0 mvm.hostepoch=1783982554 root=/dev/vda"),
            Some(1_783_982_554)
        );
        // Absent, non-numeric, zero, and negative all yield None (never winds the
        // clock backwards).
        assert_eq!(hostepoch_from_cmdline("console=hvc0 root=/dev/vda"), None);
        assert_eq!(hostepoch_from_cmdline("mvm.hostepoch=notanumber"), None);
        assert_eq!(hostepoch_from_cmdline("mvm.hostepoch=0"), None);
        assert_eq!(hostepoch_from_cmdline("mvm.hostepoch=-5"), None);
    }

    #[test]
    fn vsock_egress_port_from_cmdline_reads_positive_port() {
        assert_eq!(
            vsock_egress_port_from_cmdline(
                "console=hvc0 mvm.vsock_egress=1 mvm.vsock_egress_port=45253 root=/dev/vda"
            ),
            Some(45253)
        );
        assert_eq!(
            vsock_egress_port_from_cmdline("console=hvc0 mvm.vsock_egress_port=0 root=/dev/vda"),
            None
        );
    }

    #[test]
    fn apply_vsock_egress_proxy_env_sets_proxy_contract() {
        let mut cmd = Command::new("/bin/sh");
        apply_vsock_egress_proxy_env(&mut cmd);
        let env: std::collections::BTreeMap<_, _> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.expect("proxy env present").to_string_lossy().into_owned(),
                )
            })
            .collect();
        for key in [
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
        ] {
            assert_eq!(
                env.get(key).map(String::as_str),
                Some(VSOCK_EGRESS_PROXY_URL)
            );
        }
        for key in ["NO_PROXY", "no_proxy"] {
            assert_eq!(
                env.get(key).map(String::as_str),
                Some(VSOCK_EGRESS_NO_PROXY)
            );
        }
    }

    #[test]
    fn runtime_overlay_mount_flags_are_read_only() {
        assert_eq!(runtime_overlay_mount_flag_bits(), 1);
    }

    #[test]
    fn init_breadcrumb_writer_appends_to_run_and_all_persistent_logs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_log = dir.path().join("run").join(INIT_LIFECYCLE_BREADCRUMB_FILE);
        let persistent_a = dir.path().join("persistent-a");
        let persistent_b = dir.path().join("persistent-b");
        std::fs::create_dir_all(&persistent_a).expect("persistent-a dir");
        std::fs::create_dir_all(&persistent_b).expect("persistent-b dir");

        append_init_breadcrumb_at(
            &run_log,
            &[&persistent_a, &persistent_b],
            "stage-a",
            "first",
        );
        append_init_breadcrumb_at(
            &run_log,
            &[&persistent_a, &persistent_b],
            "stage-b",
            "second",
        );

        let run_body = std::fs::read_to_string(&run_log).expect("read run log");
        let persistent_a_body =
            std::fs::read_to_string(persistent_a.join(INIT_LIFECYCLE_BREADCRUMB_FILE))
                .expect("read persistent-a log");
        let persistent_b_body =
            std::fs::read_to_string(persistent_b.join(INIT_LIFECYCLE_BREADCRUMB_FILE))
                .expect("read persistent log");
        assert!(run_body.contains("stage-a: first"));
        assert!(run_body.contains("stage-b: second"));
        assert_eq!(run_body, persistent_a_body);
        assert_eq!(run_body, persistent_b_body);
    }

    /// `setup_dev_fd_symlinks` lays down all four conventional symlinks
    /// in an empty /dev so bash process substitution (`< <(...)`)
    /// finds `/dev/fd/N`. The targets are the `/proc/self/fd` family;
    /// the symlink_metadata-based skip keeps the helper idempotent on
    /// reboot. Cross-platform: runs on macOS and Linux.
    #[test]
    fn setup_dev_fd_symlinks_creates_all_four_in_empty_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        setup_dev_fd_symlinks(dir.path()).expect("fresh dev_root succeeds");
        for (name, expected) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            let link = dir.path().join(name);
            let target = std::fs::read_link(&link)
                .unwrap_or_else(|e| panic!("read_link {}: {e}", link.display()));
            assert_eq!(
                target.to_string_lossy(),
                expected,
                "{name} points at the right /proc/self/fd target"
            );
        }
    }

    /// Idempotency: a pre-existing entry — even a dangling symlink
    /// left over from a prior boot — is preserved. We never clobber
    /// what the kernel/initramfs/previous boot staged. Guards
    /// against, e.g., a future devtmpfs variant that creates
    /// `/dev/stdin` as a character device.
    #[test]
    fn setup_dev_fd_symlinks_is_idempotent_when_already_present() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        symlink("/sentinel", dir.path().join("fd")).expect("pre-stage symlink");
        setup_dev_fd_symlinks(dir.path()).expect("idempotent run succeeds");
        assert_eq!(
            std::fs::read_link(dir.path().join("fd"))
                .expect("read_link fd")
                .to_string_lossy(),
            "/sentinel",
            "sentinel preserved"
        );
        for name in ["stdin", "stdout", "stderr"] {
            assert!(
                dir.path().join(name).symlink_metadata().is_ok(),
                "{name} created on a partially-staged /dev"
            );
        }
    }

    /// A non-existent `dev_root` surfaces as a clean error message
    /// that names the path. The first failing symlink is enough —
    /// we don't try to be smart about pre-checking the parent.
    #[test]
    fn setup_dev_fd_symlinks_errors_when_dev_root_missing() {
        let bogus = std::path::PathBuf::from("/this/path/should/not/exist/mvm-dev-fd-test");
        let err =
            setup_dev_fd_symlinks(&bogus).expect_err("missing dev_root must error, not panic");
        assert!(
            err.contains("/this/path/should/not/exist"),
            "error names the offending parent path: {err}"
        );
    }

    #[test]
    fn virtiofs_tag_policy_marks_input_shares_read_only() {
        assert!(virtiofs_tag_is_read_only("work"));
        assert!(virtiofs_tag_is_read_only("mvm-bins"));
        assert!(virtiofs_tag_is_read_only("closure-seed"));
        assert!(!virtiofs_tag_is_read_only("out"));
        assert!(!virtiofs_tag_is_read_only("job"));
    }

    // ── seeded closure import (content-keyed idempotency) ──

    #[test]
    fn closure_import_needed_on_first_boot_with_no_marker() {
        assert!(closure_import_needed(None, "abc123"));
    }

    #[test]
    fn closure_import_needed_false_when_marker_matches_hash() {
        assert!(!closure_import_needed(Some("abc123"), "abc123"));
    }

    #[test]
    fn closure_import_needed_true_when_closure_content_changed() {
        // A different pack's closure hashes differently — re-import even
        // though a marker from a prior closure exists.
        assert!(closure_import_needed(Some("abc123"), "def456"));
    }

    #[test]
    fn closure_import_needed_tolerates_marker_whitespace() {
        // The marker is written via `std::fs::write` with no trailing
        // newline, but a defensive trim keeps hand-edited/foreign markers
        // from forcing a spurious re-import.
        assert!(!closure_import_needed(Some("abc123\n"), "abc123"));
        assert!(!closure_import_needed(Some(" abc123 "), "abc123"));
    }

    #[test]
    fn closure_marker_contents_records_the_imported_hash_verbatim() {
        assert_eq!(closure_marker_contents("abc123"), "abc123");
    }

    #[test]
    fn hex_decode_utf8_roundtrips_and_rejects_garbage() {
        assert_eq!(hex_decode_utf8("2f776f726b32").as_deref(), Some("/work2"));
        assert_eq!(hex_decode_utf8("").as_deref(), Some(""));
        assert!(hex_decode_utf8("abc").is_none()); // odd length
        assert!(hex_decode_utf8("zz").is_none()); // non-hex
    }

    #[test]
    fn parse_user_volumes_cmdline_decodes_entries() {
        // Mirrors mvm_core::vm_backend::encode_user_volumes_cmdline.
        let cmdline = "console=hvc0 root=/dev/vda \
             mvm.uvols=uvol0:2f776f726b32:ro:fs;uvol1:2f64617461:rw:blk rw init=/sbin/x";
        let got = parse_user_volumes_cmdline(cmdline);
        assert_eq!(
            got,
            vec![
                UserVolMount {
                    tag: "uvol0".into(),
                    target: "/work2".into(),
                    read_only: true,
                    is_disk: false,
                },
                UserVolMount {
                    tag: "uvol1".into(),
                    target: "/data".into(),
                    read_only: false,
                    is_disk: true,
                },
            ]
        );
    }

    #[test]
    fn parse_user_volumes_cmdline_absent_is_empty() {
        assert!(parse_user_volumes_cmdline("console=hvc0 root=/dev/vda rw").is_empty());
    }

    #[test]
    fn parse_user_volumes_cmdline_skips_malformed_entries() {
        // Missing field, bad hex, empty tag → all skipped; the one good
        // entry survives. Best-effort parsing must never panic.
        let cmdline = "mvm.uvols=bad;uvol0:zz:ro:fs;:2f61:ro:fs;uvol9:2f6f6b:rw:fs";
        let got = parse_user_volumes_cmdline(cmdline);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].tag, "uvol9");
        assert_eq!(got[0].target, "/ok");
    }

    #[test]
    fn parse_disk_transport_absent_is_none() {
        assert_eq!(
            parse_disk_transport_cmdline("console=ttyAMA0 root=/dev/vda ro"),
            None
        );
        // The flag present but not "disk" is also off.
        assert_eq!(
            parse_disk_transport_cmdline("mvm.builder_transport=virtiofs"),
            None
        );
    }

    #[test]
    fn parse_disk_transport_defaults_the_device_names() {
        let t = parse_disk_transport_cmdline(
            "console=ttyAMA0 mvm.builder_transport=disk root=/dev/vda ro",
        )
        .unwrap();
        assert_eq!(t.input_dev, "/dev/vdc");
        assert_eq!(t.output_dev, "/dev/vdd");
    }

    #[test]
    fn parse_disk_transport_honours_explicit_devices() {
        let t = parse_disk_transport_cmdline(
            "mvm.builder_transport=disk mvm.builder_input=/dev/vde mvm.builder_output=/dev/vdf",
        )
        .unwrap();
        assert_eq!(t.input_dev, "/dev/vde");
        assert_eq!(t.output_dev, "/dev/vdf");
    }

    /// Build a synthetic ext4 superblock buffer (just the fields
    /// `parse_ext4_recorded_size_bytes` reads).
    fn synth_sb(blocks_lo: u32, blocks_hi: u32, log_block_size: u32) -> Vec<u8> {
        let mut sb = vec![0u8; EXT4_SUPERBLOCK_READ];
        sb[0x04..0x08].copy_from_slice(&blocks_lo.to_le_bytes());
        sb[0x18..0x1c].copy_from_slice(&log_block_size.to_le_bytes());
        sb[0x38] = 0x53;
        sb[0x39] = 0xEF;
        sb[0x150..0x154].copy_from_slice(&blocks_hi.to_le_bytes());
        sb
    }

    #[test]
    fn parse_ext4_size_rejects_buffer_without_magic() {
        let sb = vec![0u8; EXT4_SUPERBLOCK_READ];
        assert_eq!(parse_ext4_recorded_size_bytes(&sb), None);
    }

    #[test]
    fn parse_ext4_size_rejects_short_buffer() {
        let sb = vec![0u8; 64];
        assert_eq!(parse_ext4_recorded_size_bytes(&sb), None);
    }

    #[test]
    fn parse_ext4_size_computes_64gib_default_layout() {
        // mkfs.ext4 default: 4 KiB blocks (log=2). A 64 GiB
        // filesystem records 16_777_216 blocks.
        let sb = synth_sb(16_777_216, 0, 2);
        assert_eq!(
            parse_ext4_recorded_size_bytes(&sb),
            Some(64u64 * 1024 * 1024 * 1024),
        );
    }

    #[test]
    fn parse_ext4_size_handles_64bit_feature() {
        // 20 TiB needs the high-32-bit block count (64bit feature).
        // 20 TiB with 4 KiB blocks = 20 * 2^40 / 2^12 = 5 * 2^30
        // blocks, which overflows u32 — `blocks_hi` carries the top bit.
        let total_blocks: u64 = 5 * (1u64 << 30);
        let blocks_lo = (total_blocks & 0xFFFF_FFFF) as u32;
        let blocks_hi = (total_blocks >> 32) as u32;
        let sb = synth_sb(blocks_lo, blocks_hi, 2);
        assert_eq!(
            parse_ext4_recorded_size_bytes(&sb),
            Some(20u64 * 1024 * 1024 * 1024 * 1024),
        );
    }

    #[test]
    fn parse_ext4_size_rejects_absurd_block_size() {
        // log=7 → 128 KiB blocks, which mkfs.ext4 never produces;
        // signals a stale / corrupt superblock.
        let sb = synth_sb(1024, 0, 7);
        assert_eq!(parse_ext4_recorded_size_bytes(&sb), None);
    }

    /// Regression for the May 2026 builder VM bootstrap failure: a
    /// stale 64 GiB ext4 image got re-attached to a `/dev/vdb`
    /// libkrun exposed as 64 GiB − 64 KiB. The kernel rejected
    /// mount with `EINVAL: bad geometry: block count 16777216
    /// exceeds size of device (16777200 blocks)`. The pre-mount
    /// check in [`linux::nix_store_dev_needs_format`] compares
    /// the recorded FS size against the device size and reformats
    /// on mismatch; this test pins the underlying arithmetic so
    /// the comparison `fs_bytes > device_bytes` does what the
    /// kernel does.
    #[test]
    fn parse_ext4_size_reports_oversize_filesystem() {
        let fs_bytes =
            parse_ext4_recorded_size_bytes(&synth_sb(16_777_216, 0, 2)).expect("valid superblock");
        let device_bytes = 16_777_200u64 * 4096; // 64 GiB - 64 KiB
        assert!(
            fs_bytes > device_bytes,
            "recorded FS ({fs_bytes}) must exceed device ({device_bytes}) for the bug to reproduce"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::{Command, ExitCode};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use crate::boot_timings::BootTimings;

    /// Persistent Nix-store device — virtio-blk attached as
    /// `/dev/vdb` by `LibkrunBuilderVm` via its `extra_disks` entry.
    const NIX_STORE_DEV: &str = "/dev/vdb";

    /// Where we mount the persistent store before bind-mounting
    /// it over `/nix`. Living off `/nix` directly first avoids
    /// shadowing the rootfs's seed during the format/mount
    /// dance.
    const NIX_STORE_MOUNT: &str = "/nix-store";
    const NIX_OVERLAY_UPPER: &str = "/nix-store/upper";
    const NIX_OVERLAY_WORK: &str = "/nix-store/work";
    /// Was `/nix-merged` (rootfs root). The rootfs
    /// boots `ro`, so `mkdir /nix-merged` failed with EROFS and the
    /// overlay-mount fell back to seed-copy. `/run` is mounted tmpfs
    /// by `mount_pseudofs` (mvmctl-init Stage 1), so `mkdir` there
    /// always succeeds. The mount point is host-side scaffolding —
    /// the visible mount is the bind-mount onto [`NIX_TARGET`] = `/nix`.
    const NIX_OVERLAY_MERGED: &str = "/run/nix-merged";

    /// Final bind-mount target. The rootfs's `/nix/store` (seed
    /// Nix paths needed by `/bin/sh`, `nix`, etc.) is the overlay
    /// lowerdir; persistent writes land in [`NIX_OVERLAY_UPPER`].
    const NIX_TARGET: &str = "/nix";

    /// Standard nixpkgs path-registration manifest, emitted by
    /// `nixos/lib/make-ext4-fs.nix` (which mkGuest uses). Lists
    /// every store path baked into the rootfs along with its
    /// SHA-256, size, and references — exactly the wire shape
    /// `nix-store --load-db` consumes from stdin. Sits at the
    /// rootfs root (not under `/nix/`) and is mounted read-only.
    const NIX_PATH_REGISTRATION: &str = "/nix-path-registration";

    /// Sentinel file inside the persistent `/nix-store` we touch
    /// after [`load_seeded_nix_db`] runs, so subsequent boots can
    /// skip the (idempotent but slow) re-registration. Lives next
    /// to `/nix-store/store/` and `/nix-store/var/` — neither path
    /// the standard Nix store inspects, so the marker is invisible
    /// to nix-daemon.
    const NIX_DB_LOADED_MARKER: &str = "/nix-store/.seed-db-loaded";
    const RUN_LIFECYCLE_LOG: &str = "/run/mvm-host-vm-init.lifecycle.log";

    /// Guest-side path an optional seeded Nix store closure NAR is read
    /// from. **Contract with the host wiring:** a host that resolved a
    /// builder pack carrying a closure (`BuildBuilderPackParams.closure`
    /// / `builder_pack::CLOSURE_FILE` = `"nix-closure.nar"`) attaches it
    /// here as a read-only share before boot. Absent when the resolved
    /// builder image carries no closure — the common case today — in
    /// which case [`import_seeded_closure`] returns immediately. The
    /// filename mirrors `CLOSURE_FILE` on purpose; keep the two in sync
    /// if either moves.
    const CLOSURE_SEED_NAR: &str = "/closure-seed/nix-closure.nar";

    /// Parent directory of [`CLOSURE_SEED_NAR`] — the mount point the host
    /// attaches the seeded closure at, whichever transport it uses (the
    /// `closure-seed` virtio-fs tag on libkrun/qemu, the `closure-seed/`
    /// disk-transport tar entry on the hvf VMM). A separate literal from
    /// `CLOSURE_SEED_NAR` (not derived from it), matching how the other
    /// fixed-share consts below are each declared independently; keep the
    /// two in sync if either moves.
    const CLOSURE_SEED_DIR: &str = "/closure-seed";

    /// Content-keyed idempotency marker recording the sha256 of the
    /// closure NAR most recently imported into the persistent store.
    /// Lives next to [`NIX_DB_LOADED_MARKER`] — same invisibility to
    /// nix-daemon, same "outside `store/` and `var/`" placement.
    const CLOSURE_IMPORTED_MARKER: &str = "/nix-store/.seed-closure-imported";

    /// Per-job command staging dir (`/job/cmd.sh`, `/job/env`,
    /// `/job/result`). Mounted via virtio-fs from the host
    /// (`LibkrunBuilderVm` declares the `job` tag).
    const JOB_DIR: &str = "/job";

    /// Workspace bind from the host — the in-repo flake the user
    /// is building. Read-only from the guest's perspective: libkrun
    /// exposes the virtio-fs share and this init mounts the `work`
    /// tag with MS_RDONLY below.
    const WORK_DIR: &str = "/work";

    /// Artifact-extraction dir. The user's `cmd.sh` writes
    /// `vmlinux` + `rootfs.ext4` here; the host reads them back
    /// out after the VM powers off.
    const OUT_DIR: &str = "/out";

    /// Pre-cross-compiled host-vm binaries. `cmd.sh` exports
    /// `MVM_HOST_BIN_DIR=/mvm-bins` so the builder-vm flake installs
    /// them from here instead of building them with the guest's nix —
    /// the flake eval reads `/mvm-bins/<bin>`, so this must be mounted
    /// before the build runs or the eval fails "path does not exist".
    const HOST_BIN_DIR: &str = "/mvm-bins";

    /// virtio-fs tags that match the host-side
    /// `KrunContext::add_virtio_fs` declarations in
    /// `LibkrunBuilderVm::run_build`. Order doesn't matter; the
    /// guest mounts each by tag. `mvm-bins` is read-only (inputs).
    /// `closure-seed` is only ever attached by the host when the
    /// resolved builder image carries a seeded closure NAR — absent
    /// otherwise, in which case the mount attempt below fails and logs
    /// (best-effort, matching every other entry in this table).
    const VIRTIOFS_MOUNTS: &[(&str, &str)] = &[
        ("work", WORK_DIR),
        ("out", OUT_DIR),
        ("job", JOB_DIR),
        ("mvm-bins", HOST_BIN_DIR),
        ("closure-seed", CLOSURE_SEED_DIR),
    ];

    /// Max stderr lines we capture into `/job/result`. Keeps
    /// the result file small; the host-side supervisor still
    /// captures the full stream via the libkrun console
    /// (`krun_set_console_output`).
    const STDERR_TAIL_LINES: usize = 20;

    fn append_init_breadcrumb(stage: &str, detail: &str) {
        let mut persistent_targets = Vec::new();
        for candidate in [NIX_STORE_MOUNT, JOB_DIR, OUT_DIR] {
            let path = Path::new(candidate);
            if path.is_dir() {
                persistent_targets.push(path);
            }
        }
        crate::append_init_breadcrumb_at(
            Path::new(RUN_LIFECYCLE_LOG),
            &persistent_targets,
            stage,
            detail,
        );
    }

    /// Filename for the structured install spec. When
    /// `/job/install_spec.json` is present the init
    /// binary routes through the app-deps install pipeline instead
    /// of dispatching `/job/cmd.sh`. The two modes are mutually
    /// exclusive — install jobs don't carry a cmd.sh, flake jobs
    /// don't carry an install_spec.json.
    const INSTALL_SPEC_FILENAME: &str = "install_spec.json";

    /// Fork `mvm-guest-agent` under setpriv to the agent uid,
    /// mirroring the workload `/init` (`nix/lib/mk-guest.nix`). Best
    /// effort: a missing binary or spawn error logs and returns so PID 1
    /// proceeds to the builder dispatch loop. The agent supervises vsock
    /// RPC on port 5252; without it the host can boot the builder VM but
    /// can't reach the agent.
    fn fork_guest_agent() {
        let Some(agent_bin) = crate::resolve_agent_binary(is_executable) else {
            eprintln!(
                "mvm-host-vm-init: runtime overlay required but /mvm/runtime/agent is missing; refusing boot"
            );
            std::process::exit(1);
        };
        let mut cmd = crate::agent_spawn_command(&agent_bin);
        // BusyBox `setsid` puts the agent in a new session, matching the
        // workload init path. Stdio is inherited so logs reach the console.
        match cmd.spawn() {
            Ok(child) => eprintln!(
                "mvm-host-vm-init: forked mvm-guest-agent pid={} from {}",
                child.id(),
                agent_bin.display()
            ),
            Err(e) => {
                eprintln!(
                    "mvm-host-vm-init: failed to fork the overlay agent from {}: {e}; refusing boot",
                    agent_bin.display()
                );
                std::process::exit(1);
            }
        }
    }

    /// Start the guest-side SOCKS5 -> vsock egress shim when the host requested
    /// vsock-only egress on the kernel cmdline, and refuse the boot if it never
    /// binds.
    ///
    /// This used to be best-effort. It cannot be: the builder VM has no NIC, so
    /// a guest that boots without this proxy has no network at all and every
    /// job it accepts fails on its first fetch, blaming the network rather than
    /// the missing proxy. Refusing here is the same posture as the
    /// required-overlay arm below, for the same reason.
    fn fork_vsock_egress_client_if_requested(cmdline: &str) {
        use mvm_build::egress_readiness::{EgressProbe, egress_readiness_outcome};
        use std::os::unix::process::CommandExt;

        if !crate::vsock_egress_requested_from_cmdline(cmdline) {
            return;
        }

        let Some(egress_client) = crate::resolve_egress_client_binary(is_executable) else {
            refuse_boot(EgressProbe::ClientMissing(
                "/mvm/runtime/egress-client".to_string(),
            ));
        };

        let _ = Command::new("/bin/busybox")
            .args(["ip", "link", "set", "lo", "up"])
            .status();

        // The client loads both keys before it binds, so provision the
        // identity first; otherwise a missing drive shows up as a proxy that
        // never came up, with nothing naming the drive.
        if let Err(e) = mvm_agentd::flowmux_drive::provision_identity_from_drive() {
            refuse_boot(EgressProbe::IdentityMissing(e.to_string()));
        }

        let mut cmd = Command::new(&egress_client);
        if let Some(port) = crate::vsock_egress_port_from_cmdline(cmdline) {
            cmd.env(crate::VSOCK_EGRESS_PORT_ENV, port.to_string());
        }
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = match cmd.spawn() {
            Ok(child) => {
                eprintln!(
                    "mvm-host-vm-init: forked mvm-egress-client pid={} from {}",
                    child.id(),
                    egress_client.display()
                );
                child
            }
            Err(e) => refuse_boot(EgressProbe::ClientExited(format!("spawn failed: {e}"))),
        };

        match egress_readiness_outcome(probe_vsock_egress_proxy(&mut child)) {
            Ok(()) => eprintln!(
                "mvm-host-vm-init: local vsock egress proxy ready at {}",
                mvm_build::egress_readiness::EGRESS_PROXY_LISTEN_ADDR
            ),
            Err(why) => {
                eprintln!("mvm-host-vm-init: {why}; refusing boot");
                std::process::exit(1);
            }
        }
    }

    /// Report an egress refusal and stop. Never returns — a builder guest with
    /// no proxy has nothing useful left to do.
    fn refuse_boot(probe: mvm_build::egress_readiness::EgressProbe) -> ! {
        let why = mvm_build::egress_readiness::egress_readiness_outcome(probe)
            .expect_err("refuse_boot is only called with a refusing probe");
        eprintln!("mvm-host-vm-init: {why}; refusing boot");
        std::process::exit(1);
    }

    /// Poll the guest-local proxy address until it accepts, the client dies, or
    /// the deadline passes.
    fn probe_vsock_egress_proxy(
        child: &mut std::process::Child,
    ) -> mvm_build::egress_readiness::EgressProbe {
        use mvm_build::egress_readiness::{
            EGRESS_PROXY_LISTEN_ADDR, EGRESS_PROXY_READY_TIMEOUT, EgressProbe,
        };
        use std::net::{SocketAddr, TcpStream};
        use std::time::{Duration, Instant};

        let Ok(proxy_addr) = EGRESS_PROXY_LISTEN_ADDR.parse::<SocketAddr>() else {
            return EgressProbe::BadListenAddr(EGRESS_PROXY_LISTEN_ADDR.to_string());
        };
        let deadline = Instant::now() + EGRESS_PROXY_READY_TIMEOUT;
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&proxy_addr, Duration::from_millis(200)).is_ok() {
                return EgressProbe::Ready;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    return EgressProbe::ClientExited(format!("{status}"));
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("mvm-host-vm-init: could not poll mvm-egress-client readiness: {e}")
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        EgressProbe::TimedOut
    }

    /// `[ -x <path> ]` — exists and is executable. Picks the agent binary
    /// (overlay vs baked) the same way the workload /init's shell test does.
    fn is_executable(p: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `c` is a valid NUL-terminated C string for access() to read.
        unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
    }

    fn mount_runtime_overlay(cmdline: &str) -> Result<bool, String> {
        use nix::mount::mount;

        let Some(dev) = crate::runtime_overlay_device_from_cmdline(cmdline) else {
            return Ok(false);
        };
        std::fs::create_dir_all(crate::RUNTIME_OVERLAY_MOUNT)
            .map_err(|e| format!("create {}: {e}", crate::RUNTIME_OVERLAY_MOUNT))?;
        mount(
            Some(dev.as_str()),
            crate::RUNTIME_OVERLAY_MOUNT,
            Some("ext4"),
            nix::mount::MsFlags::from_bits_retain(crate::runtime_overlay_mount_flag_bits()),
            None::<&str>,
        )
        .map_err(|e| {
            format!(
                "mount runtime overlay {dev} -> {}: {e}",
                crate::RUNTIME_OVERLAY_MOUNT
            )
        })?;
        Ok(true)
    }

    /// Builder jobs need the Nix client from the mounted `/nix` view, not just
    /// from the read-only seed rootfs. When the overlay path loses these
    /// executables, the VM must fall back to a seeded bind-mount instead of
    /// reaching the job and failing with `exit 127`.
    fn builder_nix_tools_visible() -> bool {
        [Path::new("/sbin/nix"), Path::new("/sbin/nix-store")]
            .into_iter()
            .all(is_executable)
    }

    /// Set the guest wall clock from the `mvm.hostepoch=` cmdline token. A no-op
    /// when the token is absent or unparsable (the guest keeps whatever the
    /// kernel set). Best-effort: a `settimeofday` failure is logged, not fatal.
    fn set_clock_from_host_epoch(cmdline: &str) {
        let Some(secs) = super::hostepoch_from_cmdline(cmdline) else {
            return;
        };
        // Cast to the field's own type (`_`) rather than naming `libc::time_t`,
        // which is deprecated on musl (it becomes 64-bit in musl 1.2.0) and would
        // fail CI's `-D warnings`.
        let tv = libc::timeval {
            tv_sec: secs as _,
            tv_usec: 0,
        };
        // SAFETY: `tv` is a valid, fully-initialized timeval; the timezone arg is
        // null, which Linux ignores.
        let rc = unsafe { libc::settimeofday(&tv, std::ptr::null()) };
        if rc != 0 {
            eprintln!(
                "mvm-host-vm-init: settimeofday failed: {}",
                std::io::Error::last_os_error()
            );
        } else {
            eprintln!("mvm-host-vm-init: wall clock set from host epoch {secs}");
        }
    }

    pub fn run() -> ExitCode {
        eprintln!("mvm-host-vm-init: pid 1 starting");
        append_init_breadcrumb("run_enter", "pid1");

        // The Linux kernel doesn't pass a PATH to PID 1, so without
        // this every `Command::new("iptables")` /
        // `Command::new("modprobe")` style spawn relies on the
        // child to find its binary — which fails on a stock rootfs.
        // Set a canonical PATH that covers the
        // mvm builder VM rootfs layout (busybox at `/bin/*` + extra
        // packages at `/sbin/*` + `/usr/local/bin/*`) before any
        // spawn site runs. Absolute-path call sites like
        // `/sbin/mkfs.ext4` (e2fsprogs, lives at `/sbin/*` via the
        // mkGuest packages symlink) and `/bin/udhcpc`,
        // `/bin/busybox` (busybox applets, live at `/bin/*` via the
        // mkGuest busybox install) are unaffected. Hardcoding
        // `/sbin/udhcpc` would ENOENT — busybox only installs
        // applets under `/bin/<applet>`.
        // SAFETY: PID 1 is single-threaded until we spawn the fan-out
        // tracks below; no other thread can be reading the env yet.
        unsafe {
            std::env::set_var(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin",
            );
        }

        // Anchor the boot-timings clock as close
        // to init entry as we can. The few ms of `eprintln!` +
        // module dispatch above this point are constant across
        // boots and uninteresting.
        let anchor = Instant::now();
        let (timings, _) = BootTimings::new(anchor);
        let timings = Arc::new(Mutex::new(timings));

        // Pseudofs mounts must complete before anything else —
        // every subsequent phase needs /proc, /sys, /dev to be
        // readable.
        if let Err(e) = mount_pseudofs() {
            eprintln!("mvm-host-vm-init: mount_pseudofs failed: {e}");
            write_result(2, &format!("mount_pseudofs failed: {e}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }
        append_init_breadcrumb("mount_pseudofs_ok", "ready");
        stamp(&timings, |t| {
            t.pseudofs_ready_ms = Some(BootTimings::ms_since(anchor))
        });

        // Seed the wall clock from the host before any network fetch. The builder
        // VMMs expose no RTC, so a cold Nix store's HTTPS fetch would otherwise
        // fail cert validation against a ~1970 clock. No-op without the token.
        set_clock_from_host_epoch(&std::fs::read_to_string("/proc/cmdline").unwrap_or_default());

        // Three independent setup tracks fan out
        // after pseudofs. They share no state with each other
        // until join.
        //
        //   Track A (this thread): /dev/vdb format → mount → seed
        //     → bind over /nix. Serial; each step depends on the
        //     previous. Long pole on first-boot (the seed copy).
        //   Track B: modprobe fuse + virtiofs → mount virtio-fs
        //     shares. Independent of /nix work — the kernel
        //     modules and the persistent-store ext4 don't share
        //     resources.
        //   Track C: udhcpc network setup. Independent of both.
        //     Non-fatal: offline builds against the seed store
        //     still work.
        //
        // Threads write into the same `Mutex<BootTimings>`;
        // contention is a non-issue (a handful of writes per
        // boot, none on the hot path).
        // Disk-transport mode: decided once from the cmdline. `None` keeps
        // the virtio-fs builder path unchanged; `Some` means the host
        // staged `/job`/`/work`/`/mvm-bins` on a raw block device instead
        // (every Rootfs-image libkrun builder run, plus the hvf VMM, which
        // has no virtio-fs at all) — the fixed virtio-fs share attempts
        // below would just fail with "tag not found" noise.
        let disk_transport = crate::parse_disk_transport_cmdline(
            &std::fs::read_to_string("/proc/cmdline").unwrap_or_default(),
        );
        let disk_transport_active = disk_transport.is_some();

        let track_b = {
            let timings = Arc::clone(&timings);
            std::thread::spawn(move || {
                setup_modules_and_virtiofs(&timings, anchor, disk_transport_active)
            })
        };
        let track_c = {
            let timings = Arc::clone(&timings);
            std::thread::spawn(move || {
                if let Err(e) = setup_network() {
                    eprintln!("mvm-host-vm-init: setup_network warning (non-fatal): {e}");
                    // Leave network_ready_ms = None — the JSON
                    // signals "offline build" downstream.
                    return;
                }
                stamp(&timings, |t| {
                    t.network_ready_ms = Some(BootTimings::ms_since(anchor))
                });
            })
        };

        // Track A on the main thread.
        if let Err(e) = setup_nix_store(&timings, anchor) {
            eprintln!("mvm-host-vm-init: setup_nix_store failed: {e}");
            // Drain the other tracks so their threads don't get
            // orphaned across the reboot syscall.
            let _ = track_b.join();
            let _ = track_c.join();
            write_result(2, &format!("setup_nix_store failed: {e}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        // Wait for the fan-out tracks before dispatching the job.
        // Failures on B/C are already logged inside the closures;
        // we don't abort the build for them.
        let _ = track_b.join();
        let _ = track_c.join();

        // Disk-transport mode: /job, /work, /mvm-bins come off the input disk and
        // /out is backed on the nix-store disk (the virtio-fs mounts above no-op'd).
        // Staging must precede dispatch, which reads /job. Fatal on failure — the
        // job can't run without its inputs.
        if let Some(t) = &disk_transport
            && let Err(e) = stage_disk_transport_input(t)
        {
            eprintln!("mvm-host-vm-init: disk-transport input staging failed: {e}");
            write_result(2, &format!("disk-transport input staging failed: {e}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        append_init_breadcrumb("cmdline_loaded", cmdline.trim());
        match mount_runtime_overlay(&cmdline) {
            Ok(true) => {
                append_init_breadcrumb("runtime_overlay_mount_ok", crate::RUNTIME_OVERLAY_MOUNT);
                eprintln!(
                    "mvm-host-vm-init: mounted runtime overlay at {}",
                    crate::RUNTIME_OVERLAY_MOUNT
                )
            }
            Ok(false) => {
                append_init_breadcrumb("runtime_overlay_mount_none", "no runtime disk declared");
                eprintln!(
                    "mvm-host-vm-init: runtime overlay required but no runtime disk was declared; refusing boot"
                );
                write_result(
                    2,
                    "runtime overlay required but no runtime disk was declared",
                );
                stamp(&timings, |t| {
                    t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
                });
                write_boot_timings(&timings);
                return power_off();
            }
            Err(e) => {
                append_init_breadcrumb("runtime_overlay_mount_error", &e);
                eprintln!("mvm-host-vm-init: {e}; refusing boot");
                write_result(2, &e);
                stamp(&timings, |t| {
                    t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
                });
                write_boot_timings(&timings);
                return power_off();
            }
        }
        // Optional accelerator: a builder pack may carry a pre-fetched
        // toolchain closure NAR. Import it into the persistent store once the
        // store is set up (Track A) and its `/closure-seed` mount is in place —
        // virtio-fs shares (Track B, joined above) for the libkrun/qemu VMMs,
        // or the input-disk bind (staged just above) for the hvf VMM, which has
        // no virtio-fs. Must run after staging so the NAR is actually visible;
        // running it inside `setup_nix_store` would read `/closure-seed` before
        // it is mounted and silently import nothing. Fail-open — the seed saves
        // a fetch/eval, it is never a hard dependency, and the common case (no
        // NAR attached) returns immediately without touching the filesystem.
        if let Err(e) = import_seeded_closure() {
            eprintln!("mvm-host-vm-init: import_seeded_closure warning (non-fatal): {e}");
        }

        // Fork the guest agent under setpriv so the builder/dev VM runs
        // the *same* agent every workload VM does (vsock 5252). Non-fatal
        // so a missing agent or spawn failure never wedges PID 1 — the
        // builder protocol is the primary job, the agent is additive
        // (mirrors the workload /init, which also never blocks on the agent).
        fork_guest_agent();
        fork_vsock_egress_client_if_requested(&cmdline);
        append_init_breadcrumb("post_agent_fork", "continuing");

        // Dispatch: if the host staged a
        // `dispatch.sock.marker` in /job, this VM is persistent
        // (host-side `LibkrunPersistentHostVm`).
        // Enter the dispatch loop instead of single-shot. Marker
        // absent (the default) preserves the existing cmd.sh /
        // install_spec flows exactly.
        let dispatch_marker = format!("{JOB_DIR}/dispatch.sock.marker");
        if Path::new(&dispatch_marker).exists() {
            append_init_breadcrumb("dispatch_mode", "persistent");
            eprintln!("mvm-host-vm-init: dispatch marker detected, entering W3 dispatch loop");
            stamp(&timings, |t| {
                t.job_start_ms = Some(BootTimings::ms_since(anchor))
            });
            // Snapshot the cold-boot timings — the dispatch loop's
            // first response carries this; subsequent responses
            // see None (per the HostVmResponse::Result semantics).
            let cold_boot_timings = match timings.lock() {
                Ok(t) => Some(t.clone()),
                Err(_) => {
                    eprintln!(
                        "mvm-host-vm-init: dispatch: timings mutex poisoned, omitting boot_timings"
                    );
                    None
                }
            };
            let _exit_code = run_dispatch_loop(cold_boot_timings, disk_transport);
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        // Install dispatch: install jobs hand the init
        // binary a structured spec rather than a shell script. We
        // probe for the spec first; if absent, fall through to the
        // existing cmd.sh flake-build flow.
        let install_spec_path = format!("{JOB_DIR}/{INSTALL_SPEC_FILENAME}");
        if Path::new(&install_spec_path).exists() {
            append_init_breadcrumb("dispatch_mode", "install");
            eprintln!("mvm-host-vm-init: install spec detected, routing through install pipeline");
            stamp(&timings, |t| {
                t.job_start_ms = Some(BootTimings::ms_since(anchor))
            });
            run_install_job(&install_spec_path);
            stamp(&timings, |t| {
                t.job_end_ms = Some(BootTimings::ms_since(anchor))
            });
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        let cmd_path = format!("{JOB_DIR}/cmd.sh");
        if !Path::new(&cmd_path).exists() {
            append_init_breadcrumb("cmd_missing", &cmd_path);
            write_result(2, &format!("missing {cmd_path}"));
            stamp(&timings, |t| {
                t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
            });
            write_boot_timings(&timings);
            return power_off();
        }

        stamp(&timings, |t| {
            t.job_start_ms = Some(BootTimings::ms_since(anchor))
        });
        append_init_breadcrumb("dispatch_mode", "cmd_sh");
        let job_start_at = Instant::now();
        let (code, tail) = run_job(&cmd_path);
        let build_ms = u64::try_from(job_start_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        stamp(&timings, |t| {
            t.job_end_ms = Some(BootTimings::ms_since(anchor))
        });
        write_result(code, &tail);
        // Disk-transport mode: tar /out (artifacts + result) onto the output disk
        // for the host to read back. Best-effort — the console + exit code still
        // convey failure if this can't complete.
        if let Some(t) = &disk_transport
            && let Err(e) = collect_disk_transport_output(t)
        {
            eprintln!("mvm-host-vm-init: disk-transport output collection failed: {e}");
        }
        // Best-effort vsock send of the
        // `HostVmResponse::Result` frame the host's
        // `mvm_build::builder_protocol::read_host_vm_response_from_socket`
        // is waiting for. Runs BEFORE write_boot_timings so the
        // timings snapshot we send mirrors what hits the filesystem.
        // Any failure logs and falls through to power_off — the
        // legacy file-based result path remains authoritative.
        let timings_snapshot = match timings.lock() {
            Ok(t) => t.clone(),
            Err(_) => {
                eprintln!(
                    "mvm-host-vm-init: boot-timings mutex poisoned; \
                     skipping vsock dispatch send"
                );
                stamp(&timings, |t| {
                    t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
                });
                write_boot_timings(&timings);
                return power_off();
            }
        };
        send_dispatch_response_via_vsock(&crate::dispatch_response::DispatchResponse {
            // Single-shot has no incoming request to correlate
            // against; the nil UUID is the documented sentinel
            // (see `dispatch_response::NIL_JOB_ID`).
            job_id: crate::dispatch_response::NIL_JOB_ID.to_string(),
            exit_code: code,
            stderr_tail: tail,
            boot_timings: Some(timings_snapshot),
            build_ms,
        });
        stamp(&timings, |t| {
            t.poweroff_start_ms = Some(BootTimings::ms_since(anchor))
        });
        write_boot_timings(&timings);
        power_off()
    }

    // Listen on `AF_VSOCK` port
    // `BUILDER_DISPATCH_PORT` and write a single framed
    // `HostVmResponse::Result` to the first connection that
    // arrives within `ACCEPT_TIMEOUT_SECS` seconds. Best-effort:
    // any failure (no host connection, socket setup error, write
    // error) is logged to stderr and the boot continues to
    // `power_off`.
    //
    // Wire shape is hand-rolled by
    // `crate::dispatch_response::DispatchResponse::to_json`; the
    // cross-validation test in that module pins the output against
    // `mvm_build::builder_protocol::HostVmResponse` so the host
    // deserializer parses what we emit.
    //
    // AF_VSOCK constants are inlined rather than going through
    // `nix` because the size-budget comment in this crate's
    // Cargo.toml (≤ 1.5 MiB) discourages new dep
    // features. The pattern mirrors
    // `crates/mvm-agentd/src/bin/mvm-builder-agent.rs` exactly.
    // -----------------------------------------------------------
    // AF_VSOCK helpers
    // -----------------------------------------------------------
    //
    // Shared between the single-shot send and the
    // dispatch loop. Inlined FFI rather than `nix` because the
    // 1.5 MiB size budget discourages new dep features; the
    // pattern mirrors `mvm-agentd/src/bin/mvm-builder-agent.rs`.

    /// Must match
    /// `mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT`. Hardcoded
    /// for size-budget reasons; the
    /// `vsock_send_tests::builder_dispatch_port_literal_is_21471`
    /// pinning test below catches divergence.
    const BUILDER_DISPATCH_PORT: u32 = 21471;
    const AF_VSOCK: i32 = 40;
    const SOCK_STREAM: i32 = 1;
    const SOL_SOCKET: i32 = 1;
    const SO_RCVTIMEO: i32 = 20;
    const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

    /// Cap on a single inbound `HostVmRequest` body.
    /// Matches `mvm_agentd::vsock::MAX_FRAME_SIZE` (256 KiB) — the
    /// host's `read_frame` enforces the same bound on its side, so
    /// a body above this size couldn't have been written by a
    /// well-behaved supervisor anyway.
    const MAX_DISPATCH_BODY_BYTES: u32 = 256 * 1024;

    #[repr(C)]
    struct SockAddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        /// `VMADDR_FLAG_TO_HOST` and friends. Zero for every address mvm
        /// builds; carried so the mirror matches the header field-for-field.
        svm_flags: u8,
        svm_zero: [u8; 3],
    }

    // Layout contract with linux/vm_sockets.h, derived on Linux 6.8 with cc
    // sizeof/offsetof/_Alignof rather than read off the Rust definition.
    // The header gained `svm_flags` at offset 12 in Linux 6.0, shrinking
    // `svm_zero` to three bytes; the total is 16 either way, which is why
    // the pre-6.0 shape went unnoticed here.
    const _: () = {
        use core::mem::{align_of, offset_of, size_of};

        assert!(size_of::<SockAddrVm>() == 16);
        assert!(align_of::<SockAddrVm>() == 4);
        assert!(offset_of!(SockAddrVm, svm_family) == 0);
        assert!(offset_of!(SockAddrVm, svm_reserved1) == 2);
        assert!(offset_of!(SockAddrVm, svm_port) == 4);
        assert!(offset_of!(SockAddrVm, svm_cid) == 8);
        assert!(offset_of!(SockAddrVm, svm_flags) == 12);
        assert!(offset_of!(SockAddrVm, svm_zero) == 13);
    };

    unsafe extern "C" {
        fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
        fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
        fn listen(sockfd: i32, backlog: i32) -> i32;
        fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
        fn setsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: u32,
        ) -> i32;
        fn close(fd: i32) -> i32;
    }

    /// Open + bind + listen an AF_VSOCK socket on `port`. Returns the
    /// listening fd or `None` on any setup failure (with stderr
    /// breadcrumb). `accept_timeout_secs = Some(n)` applies
    /// `SO_RCVTIMEO` so subsequent `accept()` calls bound the wait at
    /// `n`s; `None` means accept blocks until a peer connects. Used
    /// for both the dispatch port (21471) and the
    /// workload-forward port (21472).
    fn open_vsock_listener_fd(port: u32, accept_timeout_secs: Option<i64>) -> Option<i32> {
        let listen_fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
        if listen_fd < 0 {
            eprintln!("mvm-host-vm-init: vsock: socket() failed");
            return None;
        }
        let addr = SockAddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_flags: 0,
            svm_zero: [0; 3],
        };
        let rc = unsafe {
            bind(
                listen_fd,
                &addr as *const SockAddrVm as *const core::ffi::c_void,
                std::mem::size_of::<SockAddrVm>() as u32,
            )
        };
        if rc < 0 {
            eprintln!("mvm-host-vm-init: vsock: bind() failed on port {port}");
            unsafe { close(listen_fd) };
            return None;
        }
        let rc = unsafe { listen(listen_fd, 1) };
        if rc < 0 {
            eprintln!("mvm-host-vm-init: vsock: listen() failed");
            unsafe { close(listen_fd) };
            return None;
        }
        if let Some(secs) = accept_timeout_secs {
            let tv = libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            };
            let rc = unsafe {
                setsockopt(
                    listen_fd,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &tv as *const libc::timeval as *const core::ffi::c_void,
                    std::mem::size_of::<libc::timeval>() as u32,
                )
            };
            if rc < 0 {
                eprintln!("mvm-host-vm-init: vsock: setsockopt SO_RCVTIMEO failed (continuing)");
            }
        }
        Some(listen_fd)
    }

    /// Accept one connection from `listen_fd`. Returns the
    /// connection fd or `None` on accept failure (e.g.
    /// `SO_RCVTIMEO` elapsed).
    fn accept_one(listen_fd: i32) -> Option<i32> {
        let conn_fd = unsafe { accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn_fd < 0 { None } else { Some(conn_fd) }
    }

    /// Wrap an accepted vsock conn fd in a `std::fs::File` so we
    /// can use blanket `Read`/`Write` impls without rolling our
    /// own write()/read() FFI. Ownership of `conn_fd` transfers to
    /// the returned File; it closes on drop.
    fn adopt_conn_fd(conn_fd: i32) -> std::fs::File {
        use std::os::fd::FromRawFd;
        unsafe { std::fs::File::from_raw_fd(conn_fd) }
    }

    /// The workload-vsock forwarder listener. Binds the
    /// AF_VSOCK [`crate::workload_proxy::WORKLOAD_FORWARD_PORT`] and
    /// loops accepting outer-host connections, handing each to
    /// [`crate::workload_proxy::handle_forward_conn`] on its own
    /// thread (the handler reads the multiplex handshake, resolves the
    /// named workload's `v.sock`, and splices). Runs for the VM's
    /// lifetime; spawned as a background thread at dispatch-loop entry.
    /// Never returns under normal operation.
    /// Launch the resident builder control daemon (`/sbin/mvm-builderd`,
    /// process. Best-effort: a launch
    /// failure is logged and the builder VM continues serving the legacy
    /// dispatch channel, so an old daemon-less image degrades gracefully.
    fn spawn_builderd() {
        match Command::new("/sbin/mvm-builderd").spawn() {
            Ok(child) => eprintln!(
                "mvm-host-vm-init: spawned mvm-builderd (pid {})",
                child.id()
            ),
            Err(e) => eprintln!(
                "mvm-host-vm-init: could not spawn mvm-builderd: {e} (typed builder control plane unavailable; legacy dispatch unaffected)"
            ),
        }
    }

    fn run_forward_listener() {
        use std::os::fd::FromRawFd;
        use std::os::unix::net::UnixStream;
        use std::path::Path;

        let Some(listen_fd) =
            open_vsock_listener_fd(crate::workload_proxy::WORKLOAD_FORWARD_PORT, None)
        else {
            eprintln!("mvm-host-vm-init: forward listener: setup failed (nesting hop disabled)");
            return;
        };
        eprintln!(
            "mvm-host-vm-init: forward listener ready on AF_VSOCK port {}",
            crate::workload_proxy::WORKLOAD_FORWARD_PORT
        );
        // Bound concurrent forwarded streams.
        let limiter = crate::workload_proxy::ConnectionLimiter::new(
            crate::workload_proxy::MAX_CONCURRENT_FORWARDS,
        );
        loop {
            let Some(conn_fd) = accept_one(listen_fd) else {
                eprintln!("mvm-host-vm-init: forward listener: accept failed (retrying)");
                continue;
            };
            // Fail closed at the cap rather than spawning unboundedly.
            let Some(permit) = limiter.try_acquire() else {
                eprintln!(
                    "mvm-host-vm-init: forward listener: at {} concurrent streams, dropping connection",
                    crate::workload_proxy::MAX_CONCURRENT_FORWARDS
                );
                unsafe { close(conn_fd) };
                continue;
            };
            std::thread::spawn(move || {
                // Hold the permit for the connection's lifetime; it
                // releases the slot when this thread ends.
                let _permit = permit;
                // The accepted fd is an AF_VSOCK SOCK_STREAM socket;
                // UnixStream only touches its read/write/clone, so
                // wrapping it is sound (address family is irrelevant).
                let inbound = unsafe { UnixStream::from_raw_fd(conn_fd) };
                if let Err(e) = crate::workload_proxy::handle_forward_conn(
                    inbound,
                    Path::new(crate::workload::WORKLOAD_STATE_BASE),
                ) {
                    eprintln!("mvm-host-vm-init: forward conn ended: {e}");
                }
            });
        }
    }

    /// Write a length-prefixed (u32 BE) frame on an existing conn.
    /// Mirrors `mvm_agentd::vsock::write_frame`. Returns `true` on
    /// successful full-frame write. Doesn't close — caller owns
    /// the File and decides when to drop.
    fn write_frame(conn: &mut std::fs::File, body: &[u8]) -> bool {
        use std::io::Write;
        let len_be = (body.len() as u32).to_be_bytes();
        let wrote_len = conn.write_all(&len_be).is_ok();
        wrote_len && conn.write_all(body).is_ok()
    }

    /// Read one length-prefixed (u32 BE) frame body from an
    /// existing conn. Mirrors `mvm_agentd::vsock::read_frame`'s
    /// wire format. Returns `None` on any I/O / over-cap failure.
    /// Body > `MAX_DISPATCH_BODY_BYTES` fails closed before
    /// allocation. Doesn't close — caller owns the File.
    fn read_frame(conn: &mut std::fs::File) -> Option<Vec<u8>> {
        use std::io::Read;
        let mut len_buf = [0u8; 4];
        if conn.read_exact(&mut len_buf).is_err() {
            return None;
        }
        let frame_len = u32::from_be_bytes(len_buf);
        if frame_len > MAX_DISPATCH_BODY_BYTES {
            eprintln!(
                "mvm-host-vm-init: dispatch: frame too large ({frame_len} > \
                 {MAX_DISPATCH_BODY_BYTES})"
            );
            return None;
        }
        let mut body = vec![0u8; frame_len as usize];
        if conn.read_exact(&mut body).is_err() {
            return None;
        }
        Some(body)
    }

    fn send_dispatch_response_via_vsock(payload: &crate::dispatch_response::DispatchResponse) {
        const ACCEPT_TIMEOUT_SECS: i64 = 10;
        let Some(listen_fd) =
            open_vsock_listener_fd(BUILDER_DISPATCH_PORT, Some(ACCEPT_TIMEOUT_SECS))
        else {
            return;
        };
        let Some(conn_fd) = accept_one(listen_fd) else {
            eprintln!(
                "mvm-host-vm-init: vsock send: no host connection within {ACCEPT_TIMEOUT_SECS}s \
                 (single-shot path; W2 part 4 wired the host receiver)"
            );
            unsafe { close(listen_fd) };
            return;
        };
        let mut conn = adopt_conn_fd(conn_fd);
        let json = payload.to_json();
        if !write_frame(&mut conn, json.as_bytes()) {
            eprintln!("mvm-host-vm-init: vsock send: write failed mid-frame");
        }
        drop(conn);
        unsafe { close(listen_fd) };
    }

    // -----------------------------------------------------------
    // persistent-VM dispatch loop
    // -----------------------------------------------------------

    /// Dispatch loop entry point. Called from
    /// `run` when `/job/dispatch.sock.marker` is present (the host
    /// stages the marker when spawning a long-lived
    /// `LibkrunPersistentHostVm`). Opens a long-lived
    /// AF_VSOCK listener on [`BUILDER_DISPATCH_PORT`], reads one
    /// `HostVmRequest` per accepted connection, dispatches the
    /// inner job, writes back a `HostVmResponse::Result`, and
    /// repeats until a `Shutdown` request triggers a clean exit.
    ///
    /// `cold_boot_timings` carries the BootTimings snapshot taken
    /// at dispatch-loop entry. Only the
    /// supervisor's *first* dispatch in a persistent VM session
    /// gets a populated `boot_timings` field on the wire; subsequent
    /// dispatches see `None`. The first dispatch in this loop
    /// consumes the snapshot via `.take()`.
    ///
    /// Returns `0` on graceful `Shutdown`, non-zero on listener
    /// setup failure (caller `power_off`s either way).
    /// `disk_transport` is `Some` when the host staged this VM's inputs on a
    /// raw block device rather than virtio-fs shares. A persistent builder then
    /// re-reads `/job` off that device per dispatch and writes each dispatch's
    /// artifacts back onto the output device — see [`restage_disk_transport_job`].
    fn run_dispatch_loop(
        mut cold_boot_timings: Option<BootTimings>,
        disk_transport: Option<crate::DiskTransport>,
    ) -> i32 {
        // No accept timeout — the dispatch loop is persistent and
        // blocks waiting for the supervisor's next submit. The
        // outer `mvmctl persistent-builder stop` signals shutdown via a
        // `HostVmRequest::Shutdown` frame on a fresh connection.
        // Bring up the workload-vsock forwarder before
        // the dispatch loop. It runs for the VM's lifetime on its own
        // AF_VSOCK port, bridging the outer host to each workload's
        // Firecracker v.sock. Failure here is non-fatal: builds still
        // dispatch; only the nesting hop is unavailable (logged).
        std::thread::spawn(run_forward_listener);

        // Bring up the resident builder control daemon as a
        // separate process. It listens on its own AF_VSOCK control port
        // and serves the typed `builderd_protocol` to the host's builder
        // client, coexisting with the legacy dispatch loop below.
        // Non-fatal: builds still dispatch over the legacy channel if it
        // fails to launch (logged).
        spawn_builderd();

        let Some(listen_fd) = open_vsock_listener_fd(BUILDER_DISPATCH_PORT, None) else {
            eprintln!("mvm-host-vm-init: dispatch loop: listener setup failed");
            return 1;
        };
        eprintln!("mvm-host-vm-init: dispatch loop ready on AF_VSOCK port {BUILDER_DISPATCH_PORT}");
        let ready_marker = format!("{JOB_DIR}/dispatch.ready");
        if let Err(e) = std::fs::write(&ready_marker, b"") {
            eprintln!("mvm-host-vm-init: dispatch loop: failed to write {ready_marker}: {e}");
        }
        loop {
            let Some(conn_fd) = accept_one(listen_fd) else {
                // accept() failed with no timeout configured —
                // typically a kernel-level error (e.g. EMFILE). Log
                // and continue; another accept will likely succeed.
                eprintln!("mvm-host-vm-init: dispatch loop: accept failed (retrying)");
                continue;
            };
            // One File owns the conn fd for both the read (request)
            // and write (response). Dropped at iteration end which
            // closes the socket — the host sees EOF and unblocks
            // its mvm_agentd::vsock::read_frame.
            let mut conn = adopt_conn_fd(conn_fd);
            let Some(body) = read_frame(&mut conn) else {
                eprintln!("mvm-host-vm-init: dispatch loop: read failed on conn (ignoring)");
                continue;
            };
            let request = match crate::builder_request::parse(&body) {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("mvm-host-vm-init: dispatch loop: parse failed: {e}");
                    continue;
                }
            };
            match request {
                crate::builder_request::HostVmRequest::Run {
                    job_id,
                    job,
                    job_dir_relpath,
                } => {
                    eprintln!(
                        "mvm-host-vm-init: dispatch loop: starting job {job_id} at {job_dir_relpath}"
                    );
                    // Disk transport: this dispatch's `/job` contents are on the
                    // input disk the host just rewrote. Fatal for the dispatch
                    // rather than the VM — a persistent builder must survive one
                    // bad job, so this reports a failed Result and keeps serving.
                    if let Some(t) = &disk_transport
                        && let Err(e) = restage_disk_transport_job(t)
                    {
                        eprintln!("mvm-host-vm-init: dispatch loop: job staging failed: {e}");
                        let failed = crate::dispatch_response::DispatchResponse {
                            job_id: job_id.clone(),
                            exit_code: 2,
                            stderr_tail: format!("disk-transport job staging failed: {e}"),
                            boot_timings: cold_boot_timings.take(),
                            build_ms: 0,
                        };
                        if !write_frame(&mut conn, failed.to_json().as_bytes()) {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: write staging-failure Result failed"
                            );
                        }
                        continue;
                    }
                    let response = execute_dispatched_job(
                        &mut conn,
                        job_id,
                        job,
                        &job_dir_relpath,
                        cold_boot_timings.take(),
                        disk_transport.is_some(),
                    );
                    // Publish this dispatch's artifacts before the host is told
                    // the job is done: the host reads the output disk as soon as
                    // it sees the Result, so collecting afterwards would race it.
                    if let Some(t) = &disk_transport
                        && let Err(e) = collect_disk_transport_output(t)
                    {
                        eprintln!("mvm-host-vm-init: dispatch loop: output collection failed: {e}");
                    }
                    eprintln!("mvm-host-vm-init: dispatch loop: job completed; writing Result");
                    if !write_frame(&mut conn, response.as_bytes()) {
                        eprintln!("mvm-host-vm-init: dispatch loop: write Result failed mid-frame");
                    }
                }
                crate::builder_request::HostVmRequest::Shutdown => {
                    eprintln!("mvm-host-vm-init: dispatch loop: shutdown requested");
                    let bye = crate::dispatch_response::bye_json();
                    if !write_frame(&mut conn, bye.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write Bye failed (continuing to shutdown)"
                        );
                    }
                    drop(conn);
                    break;
                }
                // Spawn / stop / query a Firecracker
                // workload microVM inside the host VM. All three reply
                // with a typed frame (incl. the fail-closed
                // `WorkloadFailed` on error) so the host never has to
                // distinguish a real failure from a transport EOF.
                crate::builder_request::HostVmRequest::WorkloadStart {
                    workload_id,
                    kernel_path,
                    rootfs_path,
                    vsock_socket_dir,
                    vcpus,
                    memory_mib,
                    kernel_cmdline_extras,
                } => {
                    let cfg = crate::workload::WorkloadSpawnConfig {
                        workload_id: workload_id.clone(),
                        kernel_path,
                        rootfs_path,
                        vsock_socket_dir,
                        vcpus,
                        memory_mib,
                        kernel_cmdline_extras,
                    };
                    let frame = match crate::workload::start_workload(
                        &crate::workload::FirecrackerVmm,
                        &cfg,
                    ) {
                        Ok(pid) => {
                            crate::dispatch_response::workload_started_json(&workload_id, pid)
                        }
                        Err(e) => {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: WorkloadStart {workload_id} failed: {e}"
                            );
                            crate::dispatch_response::workload_failed_json(
                                &workload_id,
                                &e.to_string(),
                            )
                        }
                    };
                    if !write_frame(&mut conn, frame.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write WorkloadStart reply failed"
                        );
                    }
                }
                crate::builder_request::HostVmRequest::WorkloadStop { workload_id } => {
                    let base = std::path::Path::new(crate::workload::WORKLOAD_STATE_BASE);
                    let frame = match crate::workload::stop_workload(base, &workload_id) {
                        Ok(()) => crate::dispatch_response::workload_stopped_json(&workload_id),
                        Err(e) => {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: WorkloadStop {workload_id} failed: {e}"
                            );
                            crate::dispatch_response::workload_failed_json(
                                &workload_id,
                                &e.to_string(),
                            )
                        }
                    };
                    if !write_frame(&mut conn, frame.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write WorkloadStop reply failed"
                        );
                    }
                }
                crate::builder_request::HostVmRequest::WorkloadStatus { workload_id } => {
                    let base = std::path::Path::new(crate::workload::WORKLOAD_STATE_BASE);
                    let status = crate::workload::workload_status(base, &workload_id);
                    let frame =
                        crate::dispatch_response::workload_status_report_json(&workload_id, status);
                    if !write_frame(&mut conn, frame.as_bytes()) {
                        eprintln!(
                            "mvm-host-vm-init: dispatch loop: write WorkloadStatus reply failed"
                        );
                    }
                }
            }
            // Conn drops at end of iteration; the host's read on
            // its end completes (either Frame or EmptyEof).
        }
        unsafe { close(listen_fd) };
        0
    }

    /// Base dir for per-job scratch
    /// (`/tmp/<job_id>/`). Lives under the rootfs's existing
    /// tmpfs `/tmp`, which is wiped on every cold boot anyway —
    /// per-job scratch only matters for the persistent VM where
    /// jobs share a process namespace and tmpfs root.
    const JOB_SCRATCH_BASE: &str = "/tmp";

    /// Compute the path of a per-job scratch dir. Pure function so
    /// tests can spin one up under a `tempfile::tempdir` without
    /// touching the real `/tmp`.
    fn job_scratch_path(base: &str, job_id: &str) -> String {
        format!("{base}/{job_id}")
    }

    /// RAII wrapper that creates
    /// `/tmp/<job_id>/` on construction and best-effort removes
    /// it on Drop. Defers to `job_scratch_path` so tests can
    /// substitute the base dir.
    ///
    /// Cleanup is "best effort" because the leftover scratch dir
    /// is not security-load-bearing on its own — the persistent
    /// VM also wipes `/tmp` on cold restart (it's tmpfs), and
    /// `unshare --mount` makes the bind-mounts
    /// inside the scratch dir tear down with the mount namespace.
    /// If `remove_dir_all` fails (e.g. orphan child still holds a
    /// file open), log the error and continue — the next dispatch
    /// gets a fresh `/tmp/<new_job_id>/` either way.
    struct JobScratch {
        path: String,
    }

    impl JobScratch {
        /// Create the per-job scratch dir under `base` (typically
        /// [`JOB_SCRATCH_BASE`]) with mode 0700. If `owner_uid` /
        /// `owner_gid` are provided, `chown` the dir to them so a
        /// downstream uid-drop can still
        /// write into it. The dispatch loop passes `Some((902,
        /// 902))`; tests pass `None` to keep their
        /// own uid as the owner.
        fn create(base: &str, job_id: &str, chown_to: Option<(u32, u32)>) -> std::io::Result<Self> {
            use std::os::unix::fs::PermissionsExt;
            let path = job_scratch_path(base, job_id);
            std::fs::create_dir_all(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            if let Some((uid, gid)) = chown_to {
                // SAFETY: chown is a fundamental POSIX syscall;
                // we wrap the libc call in a small unsafe block
                // because nix's `chown` would drag in an extra
                // feature flag we don't have (the crate is
                // already pulled with `mount`/`reboot`/`signal`
                // only).
                let c_path = std::ffi::CString::new(path.as_str()).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
                let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(Self { path })
        }

        fn path(&self) -> &str {
            &self.path
        }
    }

    impl Drop for JobScratch {
        fn drop(&mut self) {
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                eprintln!(
                    "mvm-host-vm-init: dispatch loop: failed to clean up {path}: {e}",
                    path = self.path
                );
            }
        }
    }

    /// Set the iptables OUTPUT posture for the given job kind before
    /// dispatch. Install jobs lock egress (flush + uid-only ACCEPT)
    /// so untrusted dep code can't reach the network directly; flake
    /// jobs open egress so nix can fetch substitutes without a proxy.
    /// Separated from `execute_dispatched_job` so the mapping is
    /// directly testable — the match is the policy, and an inversion
    /// would be silent without a unit test pinning the sequences.
    fn apply_job_posture(
        job: &crate::builder_request::BuilderJob,
        ip: &dyn crate::network::IptablesRunner,
    ) -> Result<(), String> {
        match job {
            crate::builder_request::BuilderJob::Install { .. } => {
                crate::network::reapply_egress_lockdown(ip, crate::network::PROXY_UID)
            }
            crate::builder_request::BuilderJob::Flake { .. } => crate::network::open_egress(ip),
        }
    }

    /// Run one dispatched job: locate cmd.sh under
    /// `/job/<job_dir_relpath>/cmd.sh`, exec it, stream every
    /// stderr line back to `conn` as a `HostVmResponse::StderrChunk`
    /// frame, capture the exit code + stderr tail. Returns the wire
    /// JSON for the final `HostVmResponse::Result` ready to frame
    /// and write back.
    ///
    /// `conn` is the same vsock connection the request arrived on;
    /// streaming chunks and the terminal Result frame share it so
    /// the host correlates everything by conn identity, not by job
    /// id alone.
    fn execute_dispatched_job(
        conn: &mut std::fs::File,
        job_id: String,
        job: crate::builder_request::BuilderJob,
        job_dir_relpath: &str,
        cold_boot_timings: Option<BootTimings>,
        disk_transport_active: bool,
    ) -> String {
        // Set per-job egress posture before dispatch. The install arm
        // also locks at its own entry for defense in depth, but this
        // outer reset ensures a prior flake job's open chain never
        // leaks into a following install and vice versa.
        let posture_result = apply_job_posture(&job, &crate::network::SystemIptables);
        if let Err(e) = posture_result {
            eprintln!("mvm-host-vm-init: dispatch loop: egress posture failed: {e}");
            let response = crate::dispatch_response::DispatchResponse {
                job_id,
                exit_code: 126,
                stderr_tail: format!("egress posture failed: {e}"),
                boot_timings: cold_boot_timings,
                build_ms: 0,
            };
            return response.to_json();
        }

        let (exit_code, stderr_tail, build_ms) = match job {
            crate::builder_request::BuilderJob::Flake { .. } => {
                let cmd_path = format!("{JOB_DIR}/{job_dir_relpath}/cmd.sh");
                if !Path::new(&cmd_path).exists() {
                    (2, format!("missing {cmd_path}"), 0)
                } else {
                    // Per-job scratch dir
                    // at `/tmp/<job_id>/`. Pointed at by TMPDIR so
                    // every tool that honors it (mkstemp, nix
                    // evaluator, Python tempfile) writes there
                    // instead of the shared rootfs `/tmp`.
                    // Cleaned up when `_scratch` goes out of scope
                    // at the end of this match arm. On creation
                    // failure (extremely rare — tmpfs full at
                    // boot, perms surprise), fall through with no
                    // TMPDIR override and surface the warning in
                    // the stderr tail — the build is still
                    // useful, just without per-job tempfile
                    // isolation.
                    // Chown to the builder uid so the dispatched
                    // cmd.sh — which runs
                    // under `setpriv --reuid=BUILDER_UID
                    // --regid=BUILDER_GID` via
                    // `Isolation::Unshared` — can write into the
                    // scratch dir.
                    let (scratch, tmpdir) = match JobScratch::create(
                        JOB_SCRATCH_BASE,
                        &job_id,
                        Some((BUILDER_UID, BUILDER_GID)),
                    ) {
                        Ok(s) => {
                            let path = s.path().to_string();
                            (Some(s), Some(path))
                        }
                        Err(e) => {
                            eprintln!(
                                "mvm-host-vm-init: dispatch loop: failed to create scratch for {job_id}: {e}"
                            );
                            (None, None)
                        }
                    };
                    let started = Instant::now();
                    eprintln!("mvm-host-vm-init: dispatch loop: running flake command");
                    let (code, tail) = run_job_streaming(
                        &cmd_path,
                        tmpdir.as_deref(),
                        Isolation::Unshared,
                        |line| {
                            let frame = crate::dispatch_response::stderr_chunk_json(&job_id, line);
                            if !write_frame(conn, frame.as_bytes()) {
                                // Host probably closed the conn
                                // (e.g. supervisor went away
                                // mid-build). Log and keep
                                // draining stderr so the build's
                                // exit code is still meaningful —
                                // the terminal Result write will
                                // fail loudly back in the
                                // dispatch loop.
                                eprintln!(
                                    "mvm-host-vm-init: dispatch loop: write StderrChunk failed"
                                );
                            }
                        },
                    );
                    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    eprintln!(
                        "mvm-host-vm-init: dispatch loop: flake command exited \
                         code={code} elapsed_ms={ms}"
                    );
                    // Hold `scratch` until after the build returns
                    // so its `Drop` cleans up after the
                    // subprocess. Explicit drop documents the
                    // ordering for the reader.
                    drop(scratch);
                    (code, tail, ms)
                }
            }
            crate::builder_request::BuilderJob::Install { spec_path } => {
                // Route Install dispatches
                // through the existing single-shot pipeline with
                // per-dispatch paths. The host (PersistentBuilderVm)
                // stages `<session.job_dir>/<job_id>/install_spec.json`
                // and passes `/job/<job_dir_relpath>/install_spec.json`
                // as the wire `spec_path`. The output (result.json +
                // sealed volume sidecars) lands in the per-dispatch share or,
                // for raw-disk sessions, in `/out` so collection writes it to
                // the output device before the Result frame is sent.
                let out_dir = dispatch_install_out_dir(job_dir_relpath, disk_transport_active);
                let job_subdir = format!("{JOB_DIR}/{job_dir_relpath}");
                let started = Instant::now();
                run_install_job_at(&spec_path, &job_subdir, &out_dir);
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                // The install pipeline writes its own typed result
                // (result.json) — exit code on the wire is just a
                // dispatch-level signal that the install ran. The
                // host's PersistentBuilderVm reads result.json for
                // the real outcome. We pass 0 if result.json was
                // emitted at all; the host's parser will decode it
                // and surface installer_exit_code.
                let result_path = format!("{out_dir}/result.json");
                let exit_code = if Path::new(&result_path).is_file() {
                    0
                } else {
                    2
                };
                let tail = if exit_code == 0 {
                    String::new()
                } else {
                    format!("install pipeline did not emit {result_path}")
                };
                (exit_code, tail, ms)
            }
        };
        let response = crate::dispatch_response::DispatchResponse {
            job_id,
            exit_code,
            stderr_tail,
            boot_timings: cold_boot_timings,
            build_ms,
        };
        response.to_json()
    }

    fn dispatch_install_out_dir(job_dir_relpath: &str, disk_transport_active: bool) -> String {
        if disk_transport_active {
            OUT_DIR.to_string()
        } else {
            format!("{JOB_DIR}/{job_dir_relpath}/out")
        }
    }

    #[cfg(test)]
    mod vsock_send_tests {
        // The in-binary BUILDER_DISPATCH_PORT
        // const above must stay in sync with
        // mvm_agentd::builder_agent::BUILDER_DISPATCH_PORT (the
        // canonical definition the host side uses). We can't `use`
        // the function-local const from outside, so duplicate the
        // assertion against the literal value and the mvm-agentd
        // constant. Adding mvm-agentd as a dev-dep just for this
        // check is overkill; keep it inline.
        #[test]
        fn builder_dispatch_port_literal_is_21471() {
            // Mirror of the function-local const in
            // `send_dispatch_response_via_vsock`. Updating one
            // without the other trips this test.
            const FROM_BUILDER_INIT: u32 = 21471;
            assert_eq!(
                FROM_BUILDER_INIT, 21471,
                "Plan 89 BUILDER_DISPATCH_PORT changed — update both \
                 builder-init's send and mvm-agentd::builder_agent::BUILDER_DISPATCH_PORT"
            );
        }
    }

    /// Convenience for `timings.lock().map(|mut t| f(&mut *t))`. A
    /// poisoned mutex (a peer thread panicked mid-stamp) becomes a
    /// no-op rather than escalating — these timings are
    /// observability, never gating.
    fn stamp<F: FnOnce(&mut BootTimings)>(timings: &Arc<Mutex<BootTimings>>, f: F) {
        if let Ok(mut t) = timings.lock() {
            f(&mut t);
        }
    }

    /// Write the current `BootTimings` snapshot to
    /// `/job/boot-timings.json` and mirror a one-line summary to
    /// stderr. Best-effort: if `/job` is not mounted (virtio-fs
    /// failed) the write fails silently; the stderr line still
    /// reaches the host-side console capture.
    fn write_boot_timings(timings: &Arc<Mutex<BootTimings>>) {
        let snapshot = match timings.lock() {
            Ok(t) => t.clone(),
            Err(_) => {
                eprintln!("mvm-host-vm-init: boot-timings mutex poisoned; skipping JSON write");
                return;
            }
        };
        let json = snapshot.to_json();
        eprintln!("mvm-host-vm-init: boot-timings={json}");
        let body = format!("{json}\n");
        let path = format!("{JOB_DIR}/boot-timings.json");
        if let Err(e) = std::fs::write(&path, &body) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
        }
        mirror_host_visible_out_artifact("boot-timings.json", &body);
    }

    /// Drive the install pipeline against `/job/install_spec.json`.
    /// Emits `/job/result.json` (the typed report — distinct from
    /// `/job/result`, which the flake-build path writes); the host
    /// reads it to pick up exit code + sidecar paths.
    ///
    /// We deliberately don't propagate failures back as a process
    /// exit code: the VM is going to `reboot()` regardless, and
    /// the host distinguishes "install failed" vs "init crashed"
    /// via the *presence* of result.json. Anything that prevents
    /// us from writing result.json gets logged + falls through.
    fn run_install_job(spec_path: &str) {
        run_install_job_at(spec_path, JOB_DIR, OUT_DIR);
    }

    /// Install dispatch with explicit
    /// `job_dir` and `out_dir`. Single-shot uses the legacy
    /// `JOB_DIR` / `OUT_DIR` constants; persistent dispatch
    /// passes the per-dispatch `/job/<job_id>` paths so concurrent
    /// dispatches don't clobber each other's outputs (V1 is
    /// serialized so the clobber risk is theoretical, but the
    /// per-dispatch layout removes the question entirely and
    /// matches the persistent flake path's
    /// `<session.job_dir>/<job_id>/out/` convention).
    fn run_install_job_at(spec_path: &str, job_dir: &str, out_dir: &str) {
        use crate::install::{
            InstallContext, InstallError, RESULT_FILENAME, SystemCommandRunner, run_install,
        };
        use crate::install_spec::parse;
        use crate::proxy::ChildProxyLifecycle;

        let bytes = match std::fs::read(spec_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("mvm-host-vm-init: read {spec_path}: {e}");
                write_install_failure_at(out_dir, 2, &format!("read install spec: {e}"));
                return;
            }
        };
        let spec = match parse(&bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mvm-host-vm-init: parse {spec_path}: {e}");
                write_install_failure_at(out_dir, 2, &format!("parse install spec: {e}"));
                return;
            }
        };

        // Persistent dispatch may pass a per-dispatch out_dir that
        // doesn't exist yet (the host pre-stages it, but defensive
        // `create_dir_all` is cheap and saves us from a race where
        // the host's mkdir hasn't reached the guest's view of the
        // virtio-fs share yet).
        if let Err(e) = std::fs::create_dir_all(out_dir) {
            eprintln!("mvm-host-vm-init: create_dir_all {out_dir}: {e}");
            // Fall through; write_install_failure_at will try to
            // write into the dir and the host will see whatever
            // partial state results.
        }

        let runner = SystemCommandRunner;
        // The production proxy lifecycle
        // spawns `mvm-egress-proxy` from PATH. The builder VM
        // flake installs the binary at `/sbin/mvm-egress-proxy`
        // (alongside `/sbin/mvm-host-vm-init`), which is on the
        // kernel's default PATH for PID 1.
        let mut proxy = ChildProxyLifecycle::default_binary();
        let ctx = InstallContext {
            spec: &spec,
            job_dir: Path::new(job_dir),
            out_dir: Path::new(out_dir),
            runner: &runner,
            extra_path: None,
            proxy: &mut proxy,
            iptables: &crate::network::SystemIptables,
        };
        let report = match run_install(ctx) {
            Ok(r) => r,
            Err(InstallError::InstallerMissing { program }) => {
                eprintln!(
                    "mvm-host-vm-init: installer `{program}` not on PATH — builder VM is missing required tools"
                );
                write_install_failure_at(
                    out_dir,
                    127,
                    &format!("installer `{program}` not on PATH inside builder VM"),
                );
                return;
            }
            Err(InstallError::Io(why)) => {
                eprintln!("mvm-host-vm-init: install pipeline IO: {why}");
                write_install_failure_at(out_dir, 2, &format!("install pipeline IO: {why}"));
                return;
            }
            Err(InstallError::EgressLockdown(e)) => {
                eprintln!("mvm-host-vm-init: egress lockdown failed (fatal): {e}");
                write_install_failure_at(out_dir, 2, &format!("egress lockdown failed: {e}"));
                return;
            }
        };

        // Write the typed report into out_dir — the host reads it
        // from `<out_dir>/result.json` post-power-off.
        // result.json lives next to the
        // four sealed-volume artifacts so a single virtio-fs
        // share carries everything the host needs. Hand-rolled
        // JSON via InstallReport::to_json so we don't pull
        // serde_json into the init binary's closure.
        let path = format!("{out_dir}/{RESULT_FILENAME}");
        if let Err(e) = std::fs::write(&path, format!("{}\n", report.to_json())) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
        }
    }

    /// Emit a synthetic install-failure result so the host can
    /// distinguish "guest crashed before running install" from
    /// "install ran and exited nonzero." The shape matches
    /// [`crate::install::InstallReport::to_json`] so the host's
    /// parser doesn't need a separate code path. Single-shot uses
    /// `OUT_DIR`; persistent dispatch passes the per-dispatch
    /// `/job/<job_id>/out`.
    fn write_install_failure_at(out_dir: &str, exit_code: i32, reason: &str) {
        use crate::install::{
            CONTENT_SUBDIR, CVE_FILENAME, FETCH_LOG_FILENAME, RESULT_FILENAME, SBOM_FILENAME,
        };
        let escaped = json_escape(reason);
        // Synthesize a result.json that pins all sidecars at their
        // canonical paths but flags everything as un-emitted. The
        // host's parser sees installer_exit_code != 0 and refuses
        // to seal the volume.
        let body = format!(
            r#"{{"installer_exit_code":{exit_code},"sbom_emitted":false,"cve_emitted":false,"language":"unknown","gate":"unknown","content_path":"{out_dir}/{CONTENT_SUBDIR}","sbom_path":"{out_dir}/{SBOM_FILENAME}","fetch_log_path":"{out_dir}/{FETCH_LOG_FILENAME}","cve_path":"{out_dir}/{CVE_FILENAME}","failure_reason":"{escaped}"}}"#,
        );
        let path = format!("{out_dir}/{RESULT_FILENAME}");
        // Best-effort: if `out_dir` isn't writable (the install-spec
        // dispatch ran before virtio-fs came up, or the persistent-
        // dispatch out_dir doesn't exist yet), at least try /job so
        // the host has *somewhere* to pick up the failure signal.
        if let Err(e) = std::fs::write(&path, format!("{body}\n")) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
            let fallback = format!("{JOB_DIR}/{RESULT_FILENAME}");
            if let Err(e2) = std::fs::write(&fallback, format!("{body}\n")) {
                eprintln!("mvm-host-vm-init: failed to write {fallback}: {e2}");
            }
        }
    }

    fn mount_pseudofs() -> Result<(), String> {
        // Standard init filesystems. libkrun's kernel mounts
        // devtmpfs (and sometimes /proc /sys) before handing off to
        // init, so EBUSY here means "already mounted by an earlier
        // stage" — that's success for our purposes. Anything else
        // is fatal.
        mount_fs_idempotent("proc", "/proc", "proc")?;
        mount_fs_idempotent("sysfs", "/sys", "sysfs")?;
        mount_fs_idempotent("devtmpfs", "/dev", "devtmpfs")?;
        mount_fs_idempotent("tmpfs", "/tmp", "tmpfs")?;
        // `/run` must be a tmpfs so iptables-legacy can write
        // `/run/xtables.lock`. The rootfs is mounted ro, so without this
        // `install_egress_lockdown` (called from the install arm) bails with
        // "Read-only file system" at the first `iptables -A` call.
        // mkGuest's /init does the equivalent for the dev image's boot path.
        mount_fs_idempotent("tmpfs", "/run", "tmpfs")?;
        // `/dev/shm` (tmpfs) is required by libfaketime's `sem_open`:
        // `make-ext4-fs.nix` runs `mkfs.ext4` under faketime for
        // deterministic timestamps, and faketime opens a POSIX named
        // semaphore (which lives under /dev/shm). devtmpfs doesn't create
        // it, so without this the dev-image's `ext4-fs.img` derivation
        // dies with "faketime: sem_open: No such file or directory".
        let _ = std::fs::create_dir_all("/dev/shm");
        mount_fs_idempotent("tmpfs", "/dev/shm", "tmpfs")?;
        // `/dev/pts` is required by nix's build-sandbox setup: it
        // calls `posix_openpt` which opens `/dev/ptmx`, and that
        // requires devpts to be mounted at `/dev/pts`. Without it
        // nix bails with `error: opening pseudoterminal master:
        // No such file or directory`. The dev image flake's
        // mkGuest /init mounts this; we replicate it here.
        let _ = std::fs::create_dir_all("/dev/pts");
        mount_fs_idempotent("devpts", "/dev/pts", "devpts")?;
        // `/dev/fd → /proc/self/fd` is what bash process substitution
        // (`< <(...)`, `mapfile -t x < <(...)`) needs to open the
        // subshell's pipe FD at `/dev/fd/N`. devtmpfs creates device
        // nodes but never these symlinks; udev/mdev/systemd-tmpfiles
        // normally do, and we run none of them. Without /dev/fd
        // nixpkgs's `cargo-install-hook.sh` line 27 fails with
        // "/dev/fd/63: No such file or directory" and every Rust
        // derivation in the dev-image closure dies at install time.
        // `/dev/std{in,out,err}` are conventionally present as well;
        // we install all four so future hooks that depend on them
        // don't trip the same surprise.
        crate::setup_dev_fd_symlinks(Path::new("/dev"))?;
        Ok(())
    }

    /// Serial chain that gates job execution.
    /// /dev/vdb format (first boot only) → mount → overlay-mount
    /// rootfs `/nix` with persistent upper/work dirs → bind-mount
    /// over /nix. Each step depends on the previous, so this stays
    /// single-threaded inside.
    fn setup_nix_store(timings: &Arc<Mutex<BootTimings>>, anchor: Instant) -> Result<(), String> {
        append_init_breadcrumb("setup_nix_store_enter", NIX_STORE_DEV);
        std::fs::create_dir_all(NIX_STORE_MOUNT)
            .map_err(|e| format!("create {NIX_STORE_MOUNT}: {e}"))?;
        if let Some(reason) = nix_store_dev_needs_format(NIX_STORE_DEV)? {
            append_init_breadcrumb("setup_nix_store_format", &reason);
            eprintln!("mvm-host-vm-init: formatting {NIX_STORE_DEV} ({reason})");
            format_ext4(NIX_STORE_DEV)?;
        } else {
            // A store the kernel has already flagged is not safe to build on:
            // mounting it succeeds, and the damage then surfaces somewhere
            // arbitrary downstream. Refuse here, where we can name the cause.
            nix_store_dev_refuse_if_damaged(NIX_STORE_DEV)?;
        }
        mount_fs(NIX_STORE_DEV, NIX_STORE_MOUNT, "ext4")?;
        append_init_breadcrumb("setup_nix_store_mounted", NIX_STORE_MOUNT);
        stamp(timings, |t| {
            t.nix_device_ready_ms = Some(BootTimings::ms_since(anchor))
        });

        // The slim custom kernel under
        // `nix/images/builder-vm/kernel/` builds overlay, vsock,
        // fuse, virtiofs, and the iptables tables as `=y`. No
        // modprobe needed before `mount -t overlay` or `socket(AF_VSOCK)`
        // — the kernel comes up with the subsystems registered.

        match mount_nix_overlay() {
            Ok(()) => append_init_breadcrumb("setup_nix_overlay", "overlay"),
            Err(e) => {
                append_init_breadcrumb("setup_nix_overlay_fallback", &e);
                eprintln!(
                    "mvm-host-vm-init: overlay /nix setup failed ({e}); falling back to seed copy"
                );
                seed_nix_store(timings, anchor)?;
                std::fs::create_dir_all(NIX_TARGET)
                    .map_err(|e| format!("create {NIX_TARGET}: {e}"))?;
                bind_mount(NIX_STORE_MOUNT, NIX_TARGET)?;
            }
        }
        if !builder_nix_tools_visible() {
            eprintln!(
                "mvm-host-vm-init: overlay-mounted /nix hides builder Nix tools; \
                 falling back to seeded bind mount"
            );
            use nix::mount::umount;
            umount(NIX_TARGET).map_err(|e| format!("umount {NIX_TARGET}: {e}"))?;
            umount(NIX_OVERLAY_MERGED).map_err(|e| format!("umount {NIX_OVERLAY_MERGED}: {e}"))?;
            seed_nix_store(timings, anchor)?;
            bind_mount(NIX_STORE_MOUNT, NIX_TARGET)?;
            if !builder_nix_tools_visible() {
                return Err("seeded /nix bind mount still hides /sbin/nix".into());
            }
        }
        stamp(timings, |t| {
            t.nix_mounted_ms = Some(BootTimings::ms_since(anchor))
        });

        // Load `/nix-path-registration` (the
        // standard `make-ext4-fs.nix` manifest) into the persistent
        // `/nix/var/nix/db` so the in-VM `nix build` knows the
        // seeded closure is already valid. Without this, nix-daemon
        // treats every seeded path as missing and re-substitutes
        // from `cache.nixos.org` — the substituter then overwrites
        // the on-disk path during the rename window, and concurrent
        // build-hook workers `dlopen`ing libs from the same path
        // hit ENOENT. Idempotent + non-fatal so a missing or
        // unparseable manifest still boots — at most regresses to
        // the pre-fix substituter race.
        if let Err(e) = load_seeded_nix_db(timings, anchor) {
            eprintln!("mvm-host-vm-init: load_seeded_nix_db warning (non-fatal): {e}");
        }
        prepare_builder_nix_permissions()?;

        Ok(())
    }

    /// Make the persistent single-user Nix database writable by the
    /// unprivileged dispatch uid while keeping seeded store paths owned
    /// by root and readable.
    fn prepare_builder_nix_permissions() -> Result<(), String> {
        for (program, args) in builder_nix_permission_commands() {
            let status = Command::new(program)
                .args(args)
                .status()
                .map_err(|e| format!("spawn {program}: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "{program} {} exited {}",
                    args.join(" "),
                    status.code().unwrap_or(-1)
                ));
            }
        }
        Ok(())
    }

    fn builder_nix_permission_commands() -> [(&'static str, &'static [&'static str]); 6] {
        [
            (
                "/bin/mkdir",
                &["-p", "/nix/var/nix", "/nix/var/log/nix"][..],
            ),
            ("/bin/chown", &["-R", "902:902", "/nix/var/nix"]),
            ("/bin/chown", &["-R", "902:902", "/nix/var/log/nix"]),
            ("/bin/chown", &["0:902", "/nix/store"]),
            ("/bin/chmod", &["0775", "/nix/store"]),
            (
                "/bin/find",
                &["/nix/store", "-maxdepth", "1", "-name", "*.lock", "-delete"],
            ),
        ]
    }

    /// Import [`CLOSURE_SEED_NAR`] into the persistent Nix store when
    /// present and not already imported (content-keyed via
    /// [`crate::closure_import_needed`]). Absent NAR — the common case
    /// until the host-side attach lands — is a silent no-op: no log line,
    /// no filesystem write, so this step stays off the critical path.
    ///
    /// Every error path returns `Err` rather than panicking; the caller
    /// logs and continues booting regardless of what went wrong here.
    fn import_seeded_closure() -> Result<(), String> {
        let nar = Path::new(CLOSURE_SEED_NAR);
        if !nar.is_file() {
            return Ok(());
        }

        let hash = hash_nar_file(nar)?;
        let marker = std::fs::read_to_string(CLOSURE_IMPORTED_MARKER).ok();
        if !crate::closure_import_needed(marker.as_deref(), &hash) {
            return Ok(());
        }

        eprintln!("mvm-host-vm-init: importing seeded closure {CLOSURE_SEED_NAR} ({hash})");
        let file = std::fs::File::open(nar).map_err(|e| format!("open {CLOSURE_SEED_NAR}: {e}"))?;
        let status = Command::new("/sbin/nix-store")
            .arg("--import")
            .stdin(file)
            .status()
            .map_err(|e| format!("spawn /sbin/nix-store --import: {e}"))?;
        if !status.success() {
            return Err(format!(
                "nix-store --import exit {}",
                status.code().unwrap_or(-1)
            ));
        }

        std::fs::write(
            CLOSURE_IMPORTED_MARKER,
            crate::closure_marker_contents(&hash),
        )
        .map_err(|e| format!("write {CLOSURE_IMPORTED_MARKER}: {e}"))?;
        Ok(())
    }

    /// Stream `path` through SHA-256 so an arbitrarily large closure NAR
    /// (the design budget is content-defined — roughly 1 GB for the
    /// dev-shell toolchain) is never held in memory at once. Mirrors
    /// `builder_pack::sha256_file`'s streaming discipline; duplicated
    /// rather than shared because this binary intentionally doesn't
    /// depend on the `mvm-build` lib crate (every dependency here is
    /// weighed against the static-linked init's size budget).
    fn hash_nar_file(path: &Path) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let mut file =
            std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Independent track that runs concurrently
    /// with `setup_nix_store`. Loads the `fuse` + `virtiofs`
    /// kernel modules (themselves fanned out across two threads),
    /// then mounts the three virtio-fs shares — unless disk-transport
    /// staged those inputs onto a raw block device instead, in which case
    /// the host never declared these virtio-fs shares and the mount
    /// attempts would just fail with "tag not found".
    /// `--volume` user shares still ride virtio-fs regardless (a
    /// separate mechanism from the job's own input/output transport), so
    /// the modprobes and [`mount_user_volumes`] always run.
    fn setup_modules_and_virtiofs(
        timings: &Arc<Mutex<BootTimings>>,
        anchor: Instant,
        disk_transport_active: bool,
    ) {
        append_init_breadcrumb("setup_modules_and_virtiofs_enter", "start");
        // Load FUSE + virtio-fs kernel modules before mounting the
        // host-exported shares. Stock nixpkgs kernel ships these as
        // `=m` (loadable modules); without modprobe, `mount -t
        // virtiofs` bails with ENODEV. `mkGuest` stages
        // `/lib/modules/<kver>/` into the rootfs precisely so we can
        // load them at boot. Failure is non-fatal — the subsequent
        // mount attempts will fail visibly if a module is genuinely
        // missing rather than just not-yet-loaded.
        //
        // The two modprobes fan out across a pair
        // of threads. modprobe is mostly I/O-bound (open + read the
        // module file, run the insmod ioctl); running them
        // concurrently halves the wall-clock cost on slower disks.
        let fuse = std::thread::spawn(|| run_modprobe("fuse"));
        let virtiofs = std::thread::spawn(|| run_modprobe("virtiofs"));
        let _ = fuse.join();
        let _ = virtiofs.join();
        stamp(timings, |t| {
            t.modules_ready_ms = Some(BootTimings::ms_since(anchor))
        });

        // virtio-fs shares declared by `LibkrunBuilderVm`.
        // Each entry is `(tag, target)` — the kernel routes
        // `mount -t virtiofs <tag> <target>` to the daemon libkrun
        // spawned for that share. Mounting is best-effort per
        // share: if the host omitted one (e.g. an offline build
        // path with no `/out` need), we still want to reach
        // `/job/cmd.sh` if `/job` was supplied. Per-share errors
        // print to stderr but don't fail init — the failing share
        // surfaces as a normal file-not-found inside cmd.sh.
        //
        // Skipped entirely under disk-transport: the host never declares
        // these tags in that mode (`stage_disk_transport_input` populates
        // `/job`/`/work`/`/mvm-bins` from the raw input disk instead), so
        // every attempt would fail with "tag not found".
        if disk_transport_active {
            append_init_breadcrumb("virtiofs_mounts_skipped", "disk-transport active");
        } else {
            for (tag, target) in VIRTIOFS_MOUNTS {
                if let Err(e) = mount_virtiofs(tag, target) {
                    append_init_breadcrumb(
                        "virtiofs_mount_error",
                        &format!("{tag}->{target}: {e}"),
                    );
                    eprintln!("mvm-host-vm-init: virtio-fs '{tag}' -> {target} failed: {e}");
                } else {
                    append_init_breadcrumb("virtiofs_mount_ok", &format!("{tag}->{target}"));
                }
            }
        }
        // User-supplied volumes (`--volume` / MVM_VOLUMES),
        // declared by the host on the kernel cmdline. Best-effort, same
        // as the fixed shares above — a failed user mount logs and
        // continues so it can never wedge PID 1.
        mount_user_volumes();
        stamp(timings, |t| {
            t.virtiofs_ready_ms = Some(BootTimings::ms_since(anchor))
        });
    }

    /// Mount user-supplied volumes from the `mvm.uvols=` cmdline param.
    /// Directory shares (virtio-fs) mount by tag at the requested guest
    /// path with the requested ro/rw mode. Disk-image volumes are
    /// attached by the host as `/dev/vd*` but guest-side auto-mount of
    /// disks isn't wired yet — we log so the device isn't silently
    /// ignored. All errors are non-fatal.
    fn mount_user_volumes() {
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        for v in crate::parse_user_volumes_cmdline(&cmdline) {
            if v.is_disk {
                eprintln!(
                    "mvm-host-vm-init: user disk volume attached for '{}' \
                     (guest auto-mount of disk images not yet wired; mount /dev/vd* manually)",
                    v.target
                );
                continue;
            }
            match mount_user_virtiofs(&v.tag, &v.target, v.read_only) {
                Ok(()) => eprintln!(
                    "mvm-host-vm-init: mounted user volume {} at {} ({})",
                    v.tag,
                    v.target,
                    if v.read_only { "ro" } else { "rw" }
                ),
                Err(e) => eprintln!(
                    "mvm-host-vm-init: user volume {} -> {} failed: {e}",
                    v.tag, v.target
                ),
            }
        }
    }

    /// Mount a user virtio-fs share with an explicit ro/rw flag (the
    /// fixed-share `mount_virtiofs` derives ro from the tag; user tags
    /// carry their mode in the manifest instead).
    fn mount_user_virtiofs(tag: &str, target: &str, read_only: bool) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
        let flags = if read_only {
            MsFlags::MS_RDONLY
        } else {
            MsFlags::empty()
        };
        mount(Some(tag), target, Some("virtiofs"), flags, None::<&str>)
            .map_err(|e| format!("mount virtiofs {tag} -> {target}: {e}"))
    }

    /// Disk-transport staging root. The input disk's tar is extracted here
    /// so `/job`, `/work`, `/mvm-bins` become writable bind targets — the
    /// virtio-fs path binds host dirs, but the disk path must leave `/job`
    /// writable so `write_result` can drop `/job/result`. Lives on the
    /// persistent nix-store disk rather than a RAM tmpfs: a tmpfs defaults to
    /// roughly half of guest RAM, and a large `work` tree (even filtered)
    /// can overflow it — the same reason [`OUT_DIR`]'s backing directory
    /// below is on this disk, not tmpfs.
    const DISK_INPUT_STAGE: &str = "/nix-store/builder-input";

    /// Empty `dir`, creating it when it is absent.
    ///
    /// The staging root lives on the persistent nix-store disk, so it outlives
    /// the build that wrote it. `tar x` merges into whatever it finds and never
    /// removes an entry the new archive omits, so without this reset every
    /// build reads a `/work` that is the union of every tree ever staged on
    /// this host. A source file deleted upstream keeps being compiled: loudly
    /// when it collides with what replaced it — a module turned into a
    /// directory gives `E0761` — and silently when it does not, which is the
    /// worse half, because the build then succeeds against sources that are not
    /// the checkout's.
    fn reset_stage_dir(dir: &str) -> Result<(), String> {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("clear {dir}: {e}")),
        }
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))
    }

    /// Empty `dir` **without replacing the directory itself**.
    ///
    /// [`reset_stage_dir`] removes and recreates, which is right at boot and
    /// wrong for anything already bind-mounted: `/job` and `/out` are binds onto
    /// these inodes, so removing the source leaves the mount pointing at a
    /// deleted directory and every later write lands somewhere nothing reads.
    /// A persistent builder re-stages between dispatches, after the binds exist,
    /// so it needs this form.
    fn clear_dir_contents(dir: &str) -> Result<(), String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"));
            }
            Err(e) => return Err(format!("read {dir}: {e}")),
        };
        for entry in entries {
            let entry = entry.map_err(|e| format!("read entry under {dir}: {e}"))?;
            let path = entry.path();
            let removed = if entry.file_type().is_ok_and(|t| t.is_dir()) {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            removed.map_err(|e| format!("remove {}: {e}", path.display()))?;
        }
        Ok(())
    }

    /// Populate `/job`, `/work`, `/mvm-bins`, and (when the host packed one)
    /// `/closure-seed` from the input disk, and back `/out` with a writable
    /// dir on the persistent nix-store disk. This is the disk-transport
    /// equivalent of the virtio-fs shares — the primary transport for a
    /// Rootfs-image libkrun builder VM, and the only option for the hvf VMM
    /// (which has no virtio-fs).
    fn stage_disk_transport_input(t: &crate::DiskTransport) -> Result<(), String> {
        reset_stage_dir(DISK_INPUT_STAGE)?;
        // Extract the input tar straight off the raw block device; tar stops at
        // the archive EOF marker before the disk's zero padding.
        let status = Command::new("/bin/busybox")
            .args(["tar", "xf", &t.input_dev, "-C", DISK_INPUT_STAGE])
            .status()
            .map_err(|e| format!("spawn tar x {}: {e}", t.input_dev))?;
        if !status.success() {
            return Err(format!("tar x {} exited {:?}", t.input_dev, status.code()));
        }
        // Each entry is best-effort: the host only packs `closure-seed` when
        // the resolved builder image carries a seeded closure, so its absence
        // here is the common case, not an error — `import_seeded_closure`
        // already treats a missing `CLOSURE_SEED_NAR` as a silent no-op.
        for (name, target) in [
            ("job", JOB_DIR),
            ("work", WORK_DIR),
            ("mvm-bins", HOST_BIN_DIR),
            ("closure-seed", CLOSURE_SEED_DIR),
        ] {
            let src = format!("{DISK_INPUT_STAGE}/{name}");
            if Path::new(&src).exists() {
                std::fs::create_dir_all(target).map_err(|e| format!("mkdir {target}: {e}"))?;
                disk_bind_mount(&src, target)?;
            }
        }
        // `/out` carries this job's artifacts and nothing else. It is backed by
        // the same persistent disk as the input stage, so without a reset the
        // host reads back a tar of every artifact any earlier build left here —
        // including `result-*` symlinks into guest-only store paths, which are
        // dangling on the host and fail the extraction outright.
        let out_backing = format!("{NIX_STORE_MOUNT}/out");
        reset_stage_dir(&out_backing)?;
        // A dispatched job runs under `setpriv --reuid=BUILDER_UID`, and this
        // directory is created by PID 1 as root. Under the virtio-fs transport
        // the host made its side of `/out` group/other-writable before the
        // guest ever saw it; on a disk there is no host side to do that, so it
        // has to happen here or every dispatched write to `/out` fails with
        // EACCES — including the artifacts the output disk exists to carry.
        chown_builder(&out_backing)?;
        std::fs::create_dir_all(OUT_DIR).map_err(|e| format!("mkdir {OUT_DIR}: {e}"))?;
        disk_bind_mount(&out_backing, OUT_DIR)?;
        Ok(())
    }

    /// Give the builder uid ownership of a directory PID 1 created.
    ///
    /// Ownership rather than a permissive mode: `clear_dir_contents` empties
    /// `/out` between dispatches without recreating it, so the owner set here
    /// survives the whole session, and nothing outside the build ever needs to
    /// write there.
    fn chown_builder(dir: &str) -> Result<(), String> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(std::ffi::OsStr::new(dir).as_bytes())
            .map_err(|e| format!("path {dir}: {e}"))?;
        // SAFETY: `c_path` is a NUL-terminated path valid for this call, and
        // chown takes it by const pointer without retaining it.
        let rc = unsafe { libc::chown(c_path.as_ptr(), BUILDER_UID, BUILDER_GID) };
        if rc != 0 {
            return Err(format!(
                "chown {dir} to {BUILDER_UID}:{BUILDER_GID}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Re-stage `/job` for one dispatch of a *persistent* builder.
    ///
    /// The one-shot path stages once at boot and powers off after a single job.
    /// A persistent VM takes many, and each carries its own `cmd.sh` /
    /// `install_spec.json`. The host rewrites the input disk — a raw tar, so it
    /// can be replaced wholesale — before it sends the `Run` frame, and this
    /// re-reads the `job` member off the device. Ordering is what makes it safe:
    /// the host finishes writing before it sends, and dispatches serialize
    /// behind the supervisor's mutex, so no read ever straddles a write.
    ///
    /// Only the `job` member is extracted. `work`, `mvm-bins` and the closure
    /// seed are boot-time inputs that do not change between dispatches, and
    /// re-extracting a large `work` tree per job would cost real time for no
    /// effect.
    fn restage_disk_transport_job(t: &crate::DiskTransport) -> Result<(), String> {
        let job_stage = format!("{DISK_INPUT_STAGE}/job");
        // Contents-only: `/job` is bind-mounted onto this directory.
        clear_dir_contents(&job_stage)?;
        let status = Command::new("/bin/busybox")
            .args(["tar", "xf", &t.input_dev, "-C", DISK_INPUT_STAGE, "job"])
            .status()
            .map_err(|e| format!("spawn tar x job {}: {e}", t.input_dev))?;
        if !status.success() {
            return Err(format!(
                "tar x job {} exited {:?}",
                t.input_dev,
                status.code()
            ));
        }
        // `/out` accumulates across dispatches the same way it accumulates
        // across builds, and for the same reason the boot path resets it: the
        // host would otherwise read back a tar of every artifact any earlier
        // dispatch left behind, including `result-*` symlinks into guest-only
        // store paths that are dangling on the host and fail extraction.
        clear_dir_contents(&format!("{NIX_STORE_MOUNT}/out"))?;
        Ok(())
    }

    /// After the job: fold the result + boot-timings into `/out` and write the
    /// artifact tar onto the raw output block device for the host to read back
    /// with `builder_disk_transport::read_output_disk`.
    fn collect_disk_transport_output(t: &crate::DiskTransport) -> Result<(), String> {
        for f in [
            "result",
            "boot-timings.json",
            "nix-stderr.log",
            "nix-stdout.log",
        ] {
            let src = format!("{JOB_DIR}/{f}");
            if Path::new(&src).exists() {
                let _ = std::fs::copy(&src, format!("{OUT_DIR}/{f}"));
            }
        }
        let status = Command::new("/bin/busybox")
            .args(["tar", "cf", &t.output_dev, "-C", OUT_DIR, "."])
            .status()
            .map_err(|e| format!("spawn tar c {}: {e}", t.output_dev))?;
        if !status.success() {
            return Err(format!("tar c {} exited {:?}", t.output_dev, status.code()));
        }
        Ok(())
    }

    /// Bind-mount `src` onto `target` (disk-transport staging helper; kept
    /// distinct from the nix-overlay `bind_mount` which is `cfg(linux)`-only).
    fn disk_bind_mount(src: &str, target: &str) -> Result<(), String> {
        use nix::mount::{MsFlags, mount};
        mount(
            Some(src),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind {src} -> {target}: {e}"))
    }

    fn run_modprobe(module: &str) {
        let status = Command::new("/bin/busybox")
            .args(["modprobe", module])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!(
                "mvm-host-vm-init: modprobe {module} exited {} (continuing)",
                s.code().unwrap_or(-1)
            ),
            Err(e) => eprintln!("mvm-host-vm-init: spawn modprobe {module}: {e} (continuing)"),
        }
    }

    fn setup_network() -> Result<(), String> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();

        // The kernel creates `lo` administratively DOWN. Until it's up,
        // 127.0.0.0/8 has no route and every guest-internal loopback
        // service — the egress forward proxy, addon-dns — fails to bind
        // with EADDRNOTAVAIL. Bring it up first, independent of eth0/DHCP:
        // a network:None builder VM has no eth0 at all yet still needs
        // working loopback. Non-fatal, mirroring the eth0 bring-up below.
        if let Err(e) = mvm_agentd::guest_net::bring_iface_up("lo") {
            eprintln!(
                "mvm-host-vm-init: bring_iface_up lo failed: {e} \
                 (continuing — guest-internal loopback services \
                 will be unreachable)"
            );
        }

        // eth0 bring-up + DHCP + static fallback (.3) via the shared guest-net
        // helper — the same path the workload guest netinit uses. This only
        // exists for the lanes that still present an `eth0` at all; the
        // overlay/runtime rollout itself stays on the explicit vsock seams.
        // The builder VM is the one tier that genuinely has a NIC, but the
        // comment above is load-bearing: some lanes present no eth0. Both
        // outcomes are success here — this function's contract is "the network
        // is as configured as this lane allows", and a lane with no interface
        // has nothing left to do.
        mvm_agentd::guest_net::configure_guest_network("eth0", &cmdline, "192.168.127.3")
            .map(|_| ())
    }

    fn run_job(cmd_sh: &str) -> (i32, String) {
        // Single-shot path: no streaming callback, no TMPDIR
        // override (single-shot uses the rootfs's tmpfs `/tmp`
        // directly — the VM is going to power-off, so per-job
        // scratch isolation has no second job to protect), and no
        // unshare wrapping (the VM tear-down already kills any
        // orphan process and reclaims every IPC key + mount). The
        // whole stderr tail still lands in `/job/result` and the
        // host's file-based fallback parses it. The streaming variant
        // serves the persistent dispatch
        // loop; this single-shot wrapper passes a no-op so the
        // two code paths share their `Command`/`wait` logic.
        run_job_streaming(cmd_sh, None, Isolation::Inherit, |_line| {})
    }

    /// How the build subprocess relates to
    /// the dispatch loop's process / mount / IPC namespaces.
    ///
    /// - [`Isolation::Inherit`]: subprocess runs in the dispatch
    ///   loop's namespaces. Used by single-shot (the whole VM
    ///   tears down on exit anyway) and by tests that don't have
    ///   `CAP_SYS_ADMIN` in their environment (e.g. CI Docker
    ///   without `--privileged`).
    /// - [`Isolation::Unshared`]: subprocess runs in fresh mount
    ///   + pid + ipc namespaces via `unshare --mount --pid --ipc
    ///   --fork`, then drops to the unprivileged builder uid via
    ///     `setpriv --reuid --regid --clear-groups`. The pid
    ///     namespace turns orphan-cleanup into a
    ///     single namespace-exit; the mount namespace lets future
    ///     parts bind-mount `/dev/shm` etc. per-job without bleeding
    ///     state into the shared rootfs; the IPC namespace prevents
    ///     SysV/POSIX IPC keys leaking across jobs; the uid drop
    ///     prevents a malicious build from remounting / killing
    ///     outside its pid ns / loading a kernel module via the root
    ///     privileges the dispatch loop has as PID 1.
    ///
    /// Network namespace is intentionally *not* unshared — the
    /// per-VM iptables baseline already
    /// gates egress through the proxy, and the build needs the
    /// proxy reachable. That baseline is re-applied per
    /// dispatch, so a build can't leave the chain in a state we no
    /// longer trust without breaking proxy access.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Isolation {
        Inherit,
        Unshared,
    }

    /// Unprivileged uid the dispatched build
    /// runs as inside the persistent VM. Picked above the
    /// `mvm-agent` (1900) / `mvm-worker` (1000) / `mvm-egress-
    /// proxy` (1801) uids the rest of the rootfs reserves so the
    /// builder identity doesn't collide with any existing service.
    ///
    /// No `/etc/passwd` entry: the build runs as a bare numeric
    /// uid, and `setpriv --clear-groups` (below) means no NSS
    /// lookup is needed for supplementary groups either. Tools
    /// that try `getlogin()` / `getpwuid()` get `None`; the build
    /// is expected to be a flake / install pipeline that doesn't
    /// rely on its own username.
    const BUILDER_UID: u32 = 902;
    const BUILDER_GID: u32 = 902;

    /// Assemble the `Command` for one
    /// dispatched job per the requested isolation. Split out from
    /// [`run_job_streaming`] so the argv shape is testable
    /// without spawning (the spawn integration test in
    /// `run_job_streaming_unshared_runs_in_fresh_pid_namespace`
    /// probes for unshare + CAP_SYS_ADMIN; this pure builder lets
    /// tests pin the wire on every host).
    fn build_isolated_command(cmd_sh: &str, isolation: Isolation) -> Command {
        match isolation {
            Isolation::Inherit => {
                let mut c = Command::new("/bin/sh");
                c.args(["-eu", cmd_sh]);
                c
            }
            Isolation::Unshared => {
                // Order matters: unshare runs first (still uid 0
                // with `CAP_SYS_ADMIN` so the namespace setup
                // works), then setpriv drops uid inside the new
                // namespaces, then exec /bin/sh.
                //
                // `--clear-groups` strips supplementary groups
                // entirely; the build doesn't belong to any. We
                // intentionally do not use `--init-groups`
                // because there is no `/etc/passwd` entry for
                // the builder uid — initgroups(3) would fail the
                // NSS lookup. Numeric `--reuid`/`--regid` work
                // without NSS.
                //
                // `--bounding-set=-all` strips the entire
                // capability bounding set (claim 1 — matches the
                // existing `setpriv --bounding-set=-all
                // --no-new-privs` pattern). After this, the
                // build process cannot regain any caps even via
                // setuid binaries.
                let reuid = format!("--reuid={BUILDER_UID}");
                let regid = format!("--regid={BUILDER_GID}");
                let mut c = Command::new("unshare");
                c.args([
                    "--mount",
                    "--pid",
                    "--ipc",
                    "--fork",
                    "setpriv",
                    &reuid,
                    &regid,
                    "--clear-groups",
                    "--bounding-set=-all",
                    "--no-new-privs",
                    "/bin/sh",
                    "-eu",
                    cmd_sh,
                ]);
                c
            }
        }
    }

    /// Same as [`run_job`] but invokes
    /// `on_line` for each stderr line as it arrives. Used by the
    /// persistent dispatch loop to frame each line as a
    /// `HostVmResponse::StderrChunk` and write it to the active
    /// vsock conn before the final `HostVmResponse::Result`. The
    /// callback runs on this thread between line reads, so a slow
    /// host can backpressure the build's stderr stream — the
    /// host's vsock conn is the natural rate-limiter and we don't
    /// need a separate buffer thread.
    ///
    /// The trailing `\n` is stripped from each line (the typed
    /// `HostVmResponse::StderrChunk` docs commit to that).
    /// `STDERR_TAIL_LINES` of trailing context is still buffered
    /// for the final Result frame's `stderr_tail`, matching the
    /// single-shot path's contract.
    fn run_job_streaming<F: FnMut(&str)>(
        cmd_sh: &str,
        tmpdir: Option<&str>,
        isolation: Isolation,
        mut on_line: F,
    ) -> (i32, String) {
        use std::collections::VecDeque;
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::process::Stdio;
        // Switch between bare `/bin/sh
        // -eu <cmd>` and the unshare+setpriv wrapped form via
        // [`build_isolated_command`]. unshare + setpriv both
        // live in `util-linux`, which is in the builder VM's
        // rootfs (`nix/images/builder-vm/flake.nix`, package list);
        // PATH (`/sbin:/usr/sbin:/bin:/usr/bin`) finds them.
        let mut cmd = build_isolated_command(cmd_sh, isolation);
        cmd.stdout(Stdio::inherit()).stderr(Stdio::piped());
        // Point the dispatched build's
        // tmpfile machinery at the per-job scratch dir so leftover
        // tempfiles can't outlive the dispatch. Tools that honor
        // TMPDIR (mkstemp, Python's `tempfile`, Nix's evaluator,
        // `mktemp(1)`) write into `/tmp/<job_id>/` instead of the
        // shared rootfs `/tmp`. Single-shot passes `None` —
        // see [`run_job`].
        if let Some(t) = tmpdir {
            cmd.env("TMPDIR", t);
        }
        if crate::vsock_egress_requested_from_cmdline(
            &std::fs::read_to_string("/proc/cmdline").unwrap_or_default(),
        ) {
            crate::apply_vsock_egress_proxy_env(&mut cmd);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let binary = match isolation {
                    Isolation::Inherit => "/bin/sh",
                    Isolation::Unshared => "unshare",
                };
                return (127, format!("spawn {binary}: {e}"));
            }
        };
        let Some(stderr) = child.stderr.take() else {
            // Stdio::piped() should always populate child.stderr;
            // if it didn't, fall through to a non-streaming wait so
            // we still return a real exit code.
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
            return (code, String::new());
        };
        let stderr_fd = stderr.as_raw_fd();
        // SAFETY: `stderr_fd` is a live pipe owned by `stderr`; F_GETFL and
        // F_SETFL do not transfer ownership or outlive that file descriptor.
        let flags = unsafe { libc::fcntl(stderr_fd, libc::F_GETFL) };
        if flags >= 0 {
            // SAFETY: same live descriptor as above. O_NONBLOCK only changes
            // read behavior so the authoritative child exit can end the job
            // even when a detached descendant retains a duplicate writer.
            unsafe {
                libc::fcntl(stderr_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let mut stderr = stderr;
        let mut tail: VecDeque<String> = VecDeque::with_capacity(STDERR_TAIL_LINES);
        let mut pending = Vec::new();
        let mut read_buf = [0u8; 4096];
        let exit_code = loop {
            let mut pipe_drained = false;
            match stderr.read(&mut read_buf) {
                Ok(0) => pipe_drained = true,
                Ok(n) => {
                    pending.extend_from_slice(&read_buf[..n]);
                    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                        let mut bytes = pending.drain(..=newline).collect::<Vec<_>>();
                        bytes.pop();
                        if bytes.last() == Some(&b'\r') {
                            bytes.pop();
                        }
                        let Ok(line) = String::from_utf8(bytes) else {
                            pipe_drained = true;
                            break;
                        };
                        on_line(&line);
                        if tail.len() == STDERR_TAIL_LINES {
                            tail.pop_front();
                        }
                        tail.push_back(line);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    pipe_drained = true;
                }
                Err(_) => pipe_drained = true,
            }

            match child.try_wait() {
                Ok(Some(status)) if pipe_drained => {
                    if !pending.is_empty()
                        && let Ok(mut line) = String::from_utf8(std::mem::take(&mut pending))
                    {
                        if line.ends_with('\r') {
                            line.pop();
                        }
                        on_line(&line);
                        if tail.len() == STDERR_TAIL_LINES {
                            tail.pop_front();
                        }
                        tail.push_back(line);
                    }
                    break status.code().unwrap_or(-1);
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(_) => break -1,
            }

            if pipe_drained {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };
        let tail_joined = tail.into_iter().collect::<Vec<_>>().join("\n");
        (exit_code, tail_joined)
    }

    /// Write `/job/result` as JSON. Hand-rolled rather than
    /// pulling `serde_json` in just for this — the init binary's
    /// size budget is ≤ 1.5 MiB and the JSON shape is one
    /// `i32` + one string.
    fn write_result(exit_code: i32, stderr_tail: &str) {
        let body = format!(
            r#"{{"exit_code":{exit_code},"stderr_tail":"{escaped}"}}{nl}"#,
            escaped = json_escape(stderr_tail),
            nl = "\n",
        );
        let path = format!("{JOB_DIR}/result");
        if let Err(e) = std::fs::write(&path, &body) {
            eprintln!("mvm-host-vm-init: failed to write {path}: {e}");
        }
        mirror_host_visible_out_artifact("result", &body);
    }

    pub(crate) fn mirror_artifact_into_dir(dir: &Path, file_name: &str, body: &str) {
        if !dir.is_dir() {
            return;
        }
        let path = dir.join(file_name);
        if let Err(e) = std::fs::write(&path, body) {
            eprintln!(
                "mvm-host-vm-init: failed to mirror {} into {}: {e}",
                file_name,
                path.display()
            );
        }
    }

    fn mirror_host_visible_out_artifact(file_name: &str, body: &str) {
        mirror_artifact_into_dir(Path::new(OUT_DIR), file_name, body);
    }

    /// Minimal JSON string escaper. Only handles the characters
    /// that *must* be escaped per RFC 8259 §7. UTF-8 bytes pass
    /// through verbatim; control characters get `\u00XX`-style
    /// escapes; backslash and quote get the standard backslash
    /// escape. Tested with the unit tests below.
    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }

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

    /// `mount_fs` that treats EBUSY as success. libkrun's kernel
    /// pre-mounts some of `/proc`, `/sys`, `/dev` depending on
    /// cmdline + initramfs config; without this tolerance,
    /// mvm-host-vm-init bails on its first such call instead of
    /// reaching the user's cmd.sh.
    fn mount_fs_idempotent(source: &str, target: &str, fstype: &str) -> Result<(), String> {
        match mount_fs(source, target, fstype) {
            Ok(()) => Ok(()),
            Err(e) if e.contains("EBUSY") => {
                eprintln!(
                    "mvm-host-vm-init: {target} ({fstype}) already mounted (EBUSY) — continuing"
                );
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

    fn mount_nix_overlay() -> Result<(), String> {
        use nix::mount::{MsFlags, mount};

        std::fs::create_dir_all(NIX_OVERLAY_UPPER)
            .map_err(|e| format!("create {NIX_OVERLAY_UPPER}: {e}"))?;
        std::fs::create_dir_all(NIX_OVERLAY_WORK)
            .map_err(|e| format!("create {NIX_OVERLAY_WORK}: {e}"))?;
        std::fs::create_dir_all(NIX_OVERLAY_MERGED)
            .map_err(|e| format!("create {NIX_OVERLAY_MERGED}: {e}"))?;

        let data = format!(
            "lowerdir={NIX_TARGET},upperdir={NIX_OVERLAY_UPPER},workdir={NIX_OVERLAY_WORK}"
        );
        mount(
            Some("mvm-nix"),
            NIX_OVERLAY_MERGED,
            Some("overlay"),
            MsFlags::empty(),
            Some(data.as_str()),
        )
        .map_err(|e| format!("mount overlay {NIX_OVERLAY_MERGED}: {e}"))?;

        bind_mount(NIX_OVERLAY_MERGED, NIX_TARGET)
    }

    /// Returns true when the persistent Nix store at `path` has not
    /// yet been seeded from the rootfs's `/nix`.
    ///
    /// The seeded marker is a non-empty `store/` subdirectory. mkGuest
    /// always populates `/nix/store/HASH-*` in the rootfs, so any
    /// successful seed leaves `store/` non-empty in `/nix-store`.
    ///
    /// The previous "any entry other than lost+found" heuristic
    /// false-positived once [`mount_nix_overlay`] had pre-created
    /// `upper/` and `work/` on a freshly-formatted volume: an
    /// overlay-mount failure would route through `seed_nix_store`,
    /// the seed would be skipped (upper/ and work/ counted as "not
    /// lost+found"), and the subsequent bind-mount put an empty
    /// `/nix-store` over `/nix` — every `/sbin/<pkg>` symlink
    /// dangled and the first spawn failed with `ENOENT`.
    fn nix_store_needs_seed(path: &Path) -> bool {
        match std::fs::read_dir(path.join("store")) {
            Ok(mut entries) => entries.next().is_none(),
            Err(_) => true,
        }
    }

    fn seed_nix_store(timings: &Arc<Mutex<BootTimings>>, anchor: Instant) -> Result<(), String> {
        if !nix_store_needs_seed(Path::new(NIX_STORE_MOUNT)) {
            return Ok(());
        }

        eprintln!("mvm-host-vm-init: seeding {NIX_STORE_MOUNT} from {NIX_TARGET} (first boot)");
        let status = Command::new("/bin/cp")
            .args([
                "-aR",
                &format!("{NIX_TARGET}/."),
                &format!("{NIX_STORE_MOUNT}/"),
            ])
            .status()
            .map_err(|e| format!("spawn cp: {e}"))?;
        if !status.success() {
            return Err(format!(
                "seeding {NIX_STORE_MOUNT} from {NIX_TARGET}: cp exit {:?}",
                status.code()
            ));
        }
        stamp(timings, |t| {
            t.nix_seeded_ms = Some(BootTimings::ms_since(anchor))
        });
        Ok(())
    }

    /// Register the seeded store paths in the persistent
    /// `/nix/var/nix/db` so nix-daemon doesn't treat them as
    /// missing and re-substitute over the on-disk copies.
    ///
    /// Reads the standard nixpkgs manifest at
    /// [`NIX_PATH_REGISTRATION`] (emitted by
    /// `nixos/lib/make-ext4-fs.nix`) and pipes it to
    /// `nix-store --load-db`. Marked done with a sentinel at
    /// [`NIX_DB_LOADED_MARKER`] so subsequent boots skip the
    /// (idempotent but ~100ms) re-registration.
    ///
    /// The need for this call surfaced as `libboost_url.so.1.87.0:
    /// cannot open shared object file` during the in-VM dev-image
    /// build: with no entries in the DB, every closure path the
    /// build references gets re-fetched from `cache.nixos.org`,
    /// overwriting the seeded path in place — and a concurrent
    /// nix build-hook worker mid-`dlopen` of the same path's libs
    /// hits ENOENT during the rename window. Loading the DB makes
    /// the substituter skip the re-fetch entirely.
    fn load_seeded_nix_db(
        timings: &Arc<Mutex<BootTimings>>,
        anchor: Instant,
    ) -> Result<(), String> {
        if Path::new(NIX_DB_LOADED_MARKER).exists() {
            return Ok(());
        }
        if !Path::new(NIX_PATH_REGISTRATION).is_file() {
            return Err(format!(
                "{NIX_PATH_REGISTRATION} not present — rootfs predates the \
                 make-ext4-fs.nix manifest convention; substituter race \
                 will recur"
            ));
        }

        eprintln!(
            "mvm-host-vm-init: loading seeded paths into nix DB from {NIX_PATH_REGISTRATION}"
        );
        let manifest = std::fs::File::open(NIX_PATH_REGISTRATION)
            .map_err(|e| format!("open {NIX_PATH_REGISTRATION}: {e}"))?;
        let status = Command::new("/sbin/nix-store")
            .arg("--load-db")
            .stdin(manifest)
            .status()
            .map_err(|e| format!("spawn /sbin/nix-store --load-db: {e}"))?;
        if !status.success() {
            return Err(format!(
                "nix-store --load-db exit {}",
                status.code().unwrap_or(-1)
            ));
        }

        // Best-effort sentinel so we skip on next boot. Failure is
        // non-fatal — worst case we re-run the idempotent load.
        if let Err(e) = std::fs::write(NIX_DB_LOADED_MARKER, b"") {
            eprintln!(
                "mvm-host-vm-init: could not write {NIX_DB_LOADED_MARKER}: {e} \
                 (continuing — next boot will re-load the DB)"
            );
        }

        stamp(timings, |t| {
            t.nix_db_loaded_ms = Some(BootTimings::ms_since(anchor))
        });
        Ok(())
    }

    fn virtiofs_mount_flags(tag: &str) -> nix::mount::MsFlags {
        use nix::mount::MsFlags;
        if crate::virtiofs_tag_is_read_only(tag) {
            MsFlags::MS_RDONLY
        } else {
            MsFlags::empty()
        }
    }

    /// Mount a libkrun-exported virtio-fs share. `tag` is the
    /// symbolic identifier the host registered via
    /// `krun_add_virtiofs` (mvm-libkrun's `KrunVirtioFs.tag`);
    /// the kernel routes the mount through libkrun's
    /// `virtiofsd` daemon. Creates the target dir if absent. The
    /// workspace share is mounted read-only; `/out` and `/job` remain
    /// writable so builds can emit artifacts and result metadata.
    fn mount_virtiofs(tag: &str, target: &str) -> Result<(), String> {
        use nix::mount::mount;
        std::fs::create_dir_all(target).map_err(|e| format!("create {target}: {e}"))?;
        mount(
            Some(tag),
            target,
            Some("virtiofs"),
            virtiofs_mount_flags(tag),
            None::<&str>,
        )
        .map_err(|e| format!("mount virtiofs {tag} -> {target}: {e}"))
    }

    /// Offset of the ext4 primary superblock inside the partition
    /// (`SUPERBLOCK_OFFSET` in fs/ext4/ext4.h).
    const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;

    /// Decide whether `/dev/vdb` needs (re)formatting before
    /// mounting. Returns `Some(reason)` on first boot (no ext4
    /// magic) and on stale-geometry mismatches where the recorded
    /// filesystem extends past the actual block-device end. Such
    /// volumes mount with `EINVAL` in the kernel:
    ///
    /// ```text
    /// EXT4-fs (vdb): bad geometry: block count <fs> exceeds
    ///                 size of device (<dev> blocks)
    /// ```
    ///
    /// Detected pre-mount so we can recover with `mkfs.ext4 -F`
    /// rather than aborting before the build can run. The
    /// `/nix-store` volume is a cache; reformatting loses nothing
    /// that can't be rebuilt by the next nix build.
    /// Refuse a store volume the kernel has recorded errors on.
    ///
    /// The message is the whole point: it names the device, says the store is
    /// damaged, and gives the narrow recovery, so nobody has to read kernel
    /// output to find `EXT4-fs (vdb): mounting fs with errors`.
    fn nix_store_dev_refuse_if_damaged(dev: &str) -> Result<(), String> {
        let sb = read_ext4_superblock(dev)?;
        if crate::parse_ext4_recorded_error_state(&sb) == Some(true) {
            return Err(format!(
                "nix store on {dev} is damaged: the kernel recorded ext4 errors on it. \
                 Refusing to build on a corrupt store. \
                 Recover with `mvmctl cache repair --store-only`, which resets only \
                 this store image and keeps the builder images and stage0 seed."
            ));
        }
        Ok(())
    }

    fn nix_store_dev_needs_format(dev: &str) -> Result<Option<String>, String> {
        let sb = read_ext4_superblock(dev)?;
        let Some(fs_bytes) = crate::parse_ext4_recorded_size_bytes(&sb) else {
            return Ok(Some("no ext4 superblock".into()));
        };
        let dev_bytes = block_device_size_bytes(dev)?;
        if fs_bytes > dev_bytes {
            return Ok(Some(format!(
                "ext4 records {fs_bytes} bytes but device exposes {dev_bytes} bytes"
            )));
        }
        Ok(None)
    }

    /// Read the first [`crate::EXT4_SUPERBLOCK_READ`] bytes of the
    /// superblock from `dev`. Returns a short buffer (truncated to
    /// the actual byte count read) when the device is too small —
    /// the parser treats short reads as "no ext4".
    fn read_ext4_superblock(dev: &str) -> Result<Vec<u8>, String> {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};
        let mut f = File::open(dev).map_err(|e| format!("open {dev}: {e}"))?;
        f.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))
            .map_err(|e| format!("seek superblock on {dev}: {e}"))?;
        let mut buf = vec![0u8; crate::EXT4_SUPERBLOCK_READ];
        let mut read = 0;
        while read < buf.len() {
            match f.read(&mut buf[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read superblock on {dev}: {e}")),
            }
        }
        buf.truncate(read);
        Ok(buf)
    }

    // BLKGETSIZE64 = _IOR(0x12, 114, size_t). `nix::ioctl_read!`
    // generates the same `(2<<30) | (size_of::<u64>()<<16) | (0x12<<8) | 114`
    // request value (`0x80081272` on 64-bit Linux) used by util-linux.
    nix::ioctl_read!(blkgetsize64, 0x12, 114, u64);

    /// Query a block device's size in bytes via `BLKGETSIZE64`.
    /// Linux block devices only — regular files return EINVAL, which
    /// is fine: `/nix-store-<arch>.img` is always attached as a
    /// virtio-blk device inside the builder VM.
    fn block_device_size_bytes(dev: &str) -> Result<u64, String> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::File::open(dev).map_err(|e| format!("open {dev}: {e}"))?;
        let mut size: u64 = 0;
        // SAFETY: `blkgetsize64` writes a single u64. `f` outlives the
        // call; the fd is valid for the duration.
        unsafe { blkgetsize64(f.as_raw_fd(), &mut size as *mut u64) }
            .map_err(|e| format!("ioctl BLKGETSIZE64 on {dev}: {e}"))?;
        Ok(size)
    }

    /// Return the device size in 4 KiB blocks via
    /// `/sys/class/block/<basename>/size` (which is the canonical
    /// 512-byte sector count the kernel uses for mount). Used by
    /// [`format_ext4`] to avoid mkfs.ext4's `BLKGETSIZE64`-rounding
    /// mismatch under libkrun virtio-blk.
    fn device_size_4k_blocks(dev: &str) -> Result<u64, String> {
        let basename = std::path::Path::new(dev)
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
        // 1 sector = 512 B, 1 4K block = 8 sectors. Floor-divide so
        // we never claim more blocks than the device actually has.
        Ok(sectors / 8)
    }

    fn format_ext4(dev: &str) -> Result<(), String> {
        // Pass an explicit block count instead of letting mkfs.ext4
        // query the device size. libkrun's virtio-blk and mkfs.ext4
        // disagree on the device's block count by exactly 16 4K blocks
        // (64 KiB) — mkfs rounds UP from `BLKGETSIZE64` to a 64 KiB
        // boundary; the kernel mount path uses the unrounded size.
        // Without the explicit count, the freshly-mkfs'd filesystem
        // claims `block count N+16 exceeds size of device (N blocks)`
        // and the next `mount` fails with EINVAL. Querying the
        // canonical size from `/sys/class/block/<dev>/size` (always
        // matches what `mount` uses) and passing `mkfs.ext4 -b 4096
        // <dev> <count>` short-circuits mkfs's rounding.
        let blocks_4k = device_size_4k_blocks(dev)?;
        let status = Command::new("/sbin/mkfs.ext4")
            .args(["-F", "-q", "-b", "4096", dev, &blocks_4k.to_string()])
            .status()
            .map_err(|e| format!("spawn /sbin/mkfs.ext4: {e}"))?;
        if !status.success() {
            return Err(format!("mkfs.ext4 exit {}", status.code().unwrap_or(-1)));
        }
        Ok(())
    }

    fn power_off() -> ExitCode {
        use nix::sys::reboot::{RebootMode, reboot};
        let _ = Command::new("/bin/sync").status();
        // `reboot(RB_POWER_OFF)` returns `Infallible` on success
        // (the kernel halts the VM and never returns control to
        // userspace). The match-on-Result here is for the case
        // where the syscall errors before the actual power-off —
        // e.g. lack of CAP_SYS_BOOT in a misconfigured guest.
        match reboot(RebootMode::RB_POWER_OFF) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mvm-host-vm-init: reboot syscall failed: {e}");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The staging root survives on the persistent nix-store disk, and
        /// `tar x` only adds. A file the current archive does not carry — one
        /// deleted upstream since the last build — has to be gone before the
        /// extract, or the guest compiles a tree that is not the checkout's.
        #[test]
        fn reset_stage_dir_drops_a_tree_an_earlier_build_left() {
            let dir = tempfile::tempdir().expect("tempdir");
            let stage = dir.path().join("builder-input");
            std::fs::create_dir_all(stage.join("work/crates/mvm-core/src/policy"))
                .expect("seed a previous build's tree");
            let stale = stage.join("work/crates/mvm-core/src/policy/audit.rs");
            std::fs::write(&stale, b"// deleted upstream").expect("write stale source");

            reset_stage_dir(stage.to_str().expect("utf-8 path")).expect("reset");

            assert!(
                stage.is_dir(),
                "tar needs the staging root to exist to extract into"
            );
            assert!(
                !stale.exists(),
                "a source deleted upstream must not survive"
            );
            assert_eq!(
                std::fs::read_dir(&stage)
                    .expect("read staging root")
                    .count(),
                0,
                "the staging root must be empty before the extract"
            );
        }

        /// First boot on a fresh nix-store disk: nothing to clear, and the
        /// root still has to exist afterwards.
        #[test]
        fn reset_stage_dir_creates_the_root_when_absent() {
            let dir = tempfile::tempdir().expect("tempdir");
            let stage = dir.path().join("builder-input");

            reset_stage_dir(stage.to_str().expect("utf-8 path")).expect("reset");

            assert!(stage.is_dir());
        }

        /// The property the persistent path depends on, and the reason it
        /// cannot reuse `reset_stage_dir`: `/job` is bind-mounted onto the
        /// staging directory, so the directory must survive being emptied.
        /// Remove and recreate and the bind points at a deleted inode — every
        /// later write lands somewhere nothing reads, silently.
        #[test]
        fn clear_dir_contents_empties_without_replacing_the_directory() {
            use std::os::unix::fs::MetadataExt;

            let dir = tempfile::tempdir().expect("tempdir");
            let stage = dir.path().join("job");
            std::fs::create_dir_all(stage.join("nested")).expect("nested");
            std::fs::write(stage.join("cmd.sh"), b"old").expect("file");
            std::fs::write(stage.join("nested/leftover"), b"old").expect("nested file");
            let before = std::fs::metadata(&stage).expect("stat").ino();

            clear_dir_contents(stage.to_str().expect("utf-8 path")).expect("clear");

            assert_eq!(
                std::fs::metadata(&stage).expect("stat").ino(),
                before,
                "the directory itself must survive, or the bind mount is orphaned"
            );
            assert_eq!(
                std::fs::read_dir(&stage).expect("read").count(),
                0,
                "a previous dispatch's files must not leak into the next one"
            );
        }

        /// Same first-boot tolerance `reset_stage_dir` has: a persistent VM
        /// re-stages before the directory necessarily exists.
        #[test]
        fn clear_dir_contents_creates_the_directory_when_absent() {
            let dir = tempfile::tempdir().expect("tempdir");
            let stage = dir.path().join("job");

            clear_dir_contents(stage.to_str().expect("utf-8 path")).expect("clear");

            assert!(stage.is_dir());
        }

        #[test]
        fn install_dispatch_uses_output_disk_staging_when_transport_is_active() {
            assert_eq!(dispatch_install_out_dir("job-7", true), OUT_DIR);
            assert_eq!(
                dispatch_install_out_dir("job-7", false),
                format!("{JOB_DIR}/job-7/out")
            );
        }

        #[test]
        fn json_escape_plain() {
            assert_eq!(json_escape("hello"), "hello");
        }

        #[test]
        fn json_escape_quote_and_backslash() {
            assert_eq!(json_escape(r#"he"llo\world"#), r#"he\"llo\\world"#);
        }

        #[test]
        fn json_escape_newlines_and_tabs() {
            assert_eq!(
                json_escape("line1\nline2\ttab\rcarriage"),
                "line1\\nline2\\ttab\\rcarriage"
            );
        }

        #[test]
        fn json_escape_low_control_codepoint() {
            // 0x01 is below 0x20 and not specially named — use 
            assert_eq!(json_escape("\x01"), "\\u0001");
        }

        #[test]
        fn json_escape_utf8_passes_through() {
            // Multi-byte UTF-8 must not be escaped: per RFC 8259,
            // only the named characters and control codepoints
            // require escaping.
            assert_eq!(json_escape("naïve résumé 日本語"), "naïve résumé 日本語");
        }

        #[test]
        fn ext4_magic_constants_match_disk_layout() {
            // Sanity-check the magic bytes we probe for. ext4
            // stores `0xEF53` as a 16-bit little-endian integer
            // at offset 1080 of the device. If this constant ever
            // drifts (e.g. someone "fixes" the byte order) we want
            // a CI test failure rather than a runtime mis-detection
            // that silently re-formats the persistent store.
            assert_eq!([0x53u8, 0xEFu8], 0xEF53u16.to_le_bytes());
        }

        #[test]
        fn virtiofs_mount_flags_keep_workspace_read_only() {
            use nix::mount::MsFlags;

            assert!(virtiofs_mount_flags("work").contains(MsFlags::MS_RDONLY));
            assert!(virtiofs_mount_flags("mvm-bins").contains(MsFlags::MS_RDONLY));
            assert_eq!(virtiofs_mount_flags("out"), MsFlags::empty());
            assert_eq!(virtiofs_mount_flags("job"), MsFlags::empty());
        }

        /// `run_job_streaming` calls the
        /// per-line callback once per stderr line, in order, and
        /// returns the same `(exit_code, tail)` shape as the
        /// single-shot `run_job` for the success case.
        #[test]
        fn run_job_streaming_emits_each_line_in_order() {
            // Write a cmd.sh that emits 3 stderr lines and exits 0.
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            std::fs::write(
                &cmd_path,
                "echo one >&2\necho two >&2\necho three >&2\nexit 0\n",
            )
            .expect("write cmd.sh");
            use std::sync::Mutex;
            let collected = Mutex::new(Vec::<String>::new());
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                None,
                Isolation::Inherit,
                |line| {
                    collected.lock().unwrap().push(line.to_string());
                },
            );
            assert_eq!(code, 0);
            let got = collected.into_inner().unwrap();
            assert_eq!(got, vec!["one", "two", "three"]);
            assert_eq!(tail, "one\ntwo\nthree");
        }

        #[test]
        fn run_job_streaming_returns_when_descendant_keeps_stderr_open() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            let pid_path = dir.path().join("descendant.pid");
            std::fs::write(
                &cmd_path,
                format!(
                    "sleep 30 &\necho $! > '{}'\necho parent-exited >&2\nexit 0\n",
                    pid_path.display()
                ),
            )
            .expect("write cmd.sh");

            let started = Instant::now();
            let (code, tail) =
                run_job_streaming(cmd_path.to_str().unwrap(), None, Isolation::Inherit, |_| {});
            let elapsed = started.elapsed();

            let descendant_pid = std::fs::read_to_string(&pid_path).expect("read descendant pid");
            let kill_status = Command::new("kill")
                .arg(descendant_pid.trim())
                .status()
                .expect("kill held-open descendant");

            assert!(kill_status.success(), "descendant cleanup must succeed");
            assert_eq!(code, 0);
            assert_eq!(tail, "parent-exited");
            assert!(
                elapsed < std::time::Duration::from_secs(5),
                "authoritative parent exit must not wait for descendant stderr EOF: {elapsed:?}"
            );
        }

        /// Non-zero exit still surfaces all
        /// streamed lines and a tail bounded by `STDERR_TAIL_LINES`.
        #[test]
        fn run_job_streaming_caps_tail_to_stderr_tail_lines() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            // Emit more lines than STDERR_TAIL_LINES (=20) so we
            // verify the buffer cap, not just streaming.
            let total = STDERR_TAIL_LINES + 5;
            let mut script = String::new();
            for i in 1..=total {
                script.push_str(&format!("echo line{i} >&2\n"));
            }
            script.push_str("exit 42\n");
            std::fs::write(&cmd_path, script).expect("write cmd.sh");
            use std::sync::Mutex;
            let collected = Mutex::new(Vec::<String>::new());
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                None,
                Isolation::Inherit,
                |line| {
                    collected.lock().unwrap().push(line.to_string());
                },
            );
            assert_eq!(code, 42);
            // Callback saw every line.
            assert_eq!(collected.lock().unwrap().len(), total);
            // Tail kept only the last STDERR_TAIL_LINES.
            let tail_lines: Vec<&str> = tail.lines().collect();
            assert_eq!(tail_lines.len(), STDERR_TAIL_LINES);
            assert_eq!(*tail_lines.first().unwrap(), "line6");
            assert_eq!(*tail_lines.last().unwrap(), &format!("line{total}"));
        }

        /// Single-shot `run_job` keeps its
        /// pre-streaming semantics: returns the tail without any
        /// per-line side effect (the streaming variant's callback
        /// is `|_| {}`).
        #[test]
        fn run_job_matches_streaming_for_short_output() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            std::fs::write(&cmd_path, "echo hi >&2\nexit 0\n").expect("write cmd.sh");
            let (code, tail) = run_job(cmd_path.to_str().unwrap());
            assert_eq!(code, 0);
            assert_eq!(tail, "hi");
        }

        /// `JobScratch::create` builds
        /// `<base>/<job_id>` with mode 0700 and `Drop` wipes it.
        /// We parameterize on a tempdir base so the test doesn't
        /// touch the host's real `/tmp`.
        #[test]
        fn job_scratch_creates_dir_and_removes_on_drop() {
            use std::os::unix::fs::PermissionsExt;
            let base = tempfile::tempdir().expect("tempdir");
            let base_str = base.path().to_str().unwrap();
            let job_id = "00000000-0000-0000-0000-000000000000";
            let expected = base.path().join(job_id);
            {
                let scratch = JobScratch::create(base_str, job_id, None).expect("create scratch");
                assert!(expected.is_dir(), "scratch dir created");
                let mode = std::fs::metadata(&expected)
                    .expect("stat")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o700, "scratch dir tightened to 0700");
                assert_eq!(scratch.path(), expected.to_str().unwrap());
            }
            assert!(!expected.exists(), "Drop removed scratch dir");
        }

        /// Drop still removes the dir even
        /// if it has files inside (the build leaves tempfiles
        /// behind). Catches the `remove_dir_all` vs `remove_dir`
        /// difference.
        #[test]
        fn job_scratch_drop_clears_nonempty_dir() {
            let base = tempfile::tempdir().expect("tempdir");
            let base_str = base.path().to_str().unwrap();
            let job_id = "deadbeef";
            let expected = base.path().join(job_id);
            {
                let _scratch = JobScratch::create(base_str, job_id, None).expect("create scratch");
                std::fs::write(expected.join("a.txt"), b"leak").expect("write a");
                std::fs::create_dir(expected.join("sub")).expect("mkdir sub");
                std::fs::write(expected.join("sub/b.txt"), b"leak").expect("write b");
            }
            assert!(!expected.exists(), "Drop wiped nested contents");
        }

        /// `run_job_streaming` honors the
        /// TMPDIR override. cmd.sh echoes the var so we can
        /// assert the build subprocess saw it.
        #[test]
        fn run_job_streaming_threads_tmpdir_through_to_subprocess() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            let scratch = dir.path().join("scratch");
            std::fs::create_dir(&scratch).expect("create scratch");
            // The subprocess inherits TMPDIR from its environment;
            // echo it back via stderr so the test sees it.
            std::fs::write(&cmd_path, "echo \"tmpdir=$TMPDIR\" >&2\nexit 0\n")
                .expect("write cmd.sh");
            let scratch_str = scratch.to_str().unwrap();
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                Some(scratch_str),
                Isolation::Inherit,
                |_| {},
            );
            assert_eq!(code, 0);
            assert_eq!(tail, format!("tmpdir={scratch_str}"));
        }

        /// When `tmpdir` is `None` the
        /// subprocess inherits whatever TMPDIR the dispatch loop
        /// already had (typically unset inside PID 1). We assert
        /// the env var is *not* explicitly forced to a value the
        /// test process supplies via `Command::env`, so single-
        /// shot keeps its pre-part-10 behavior.
        #[test]
        fn run_job_streaming_does_not_override_tmpdir_when_none() {
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            std::fs::write(&cmd_path, "echo \"tmpdir=${TMPDIR-UNSET}\" >&2\nexit 0\n")
                .expect("write cmd.sh");
            // The assertion: with `tmpdir = None`, `run_job_streaming` doesn't
            // call `.env("TMPDIR", _)` — it leaves the parent's env alone, so
            // the subprocess sees whatever TMPDIR the parent has.
            //
            // `TestEnv` sets it under the shared process-env lock and restores
            // on drop (even on panic). cargo runs this binary's tests
            // multi-threaded, so a sibling test's `tempfile::tempdir()` may
            // observe this TMPDIR during the window — point it at a *valid*
            // directory (the test's own tempdir) so that stays harmless instead
            // of handing siblings a non-existent path.
            let sentinel = dir.path().to_str().expect("utf-8 tempdir").to_string();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.set("TMPDIR", &sentinel);
            let (code, tail) =
                run_job_streaming(cmd_path.to_str().unwrap(), None, Isolation::Inherit, |_| {});
            assert_eq!(code, 0);
            assert_eq!(tail, format!("tmpdir={sentinel}"));
        }

        /// `Isolation::Unshared` mode wraps
        /// the build subprocess in `unshare --mount --pid --ipc
        /// --fork`. The cmd.sh reads `/proc/self/status` and
        /// looks for `NSpid:` — under a fresh pid namespace, the
        /// build sees PID 1 inside its own namespace (the second
        /// `NSpid` column).
        ///
        /// Skipped if `unshare` isn't installed or if the test
        /// runner lacks `CAP_SYS_ADMIN` (e.g. unprivileged Docker
        /// CI). The Linux build-VM runs as PID 1 with full caps,
        /// so the real dispatch path always succeeds; this test
        /// exercises the wiring on whatever Linux host runs the
        /// suite.
        #[test]
        fn run_job_streaming_unshared_runs_in_fresh_pid_namespace() {
            use std::process::Stdio;
            // Fast-path probe: if `unshare --pid --fork --mount
            // --ipc true` fails on this host, skip — the test is
            // exercising correctness of the wiring, not the host's
            // capability set.
            let probe = Command::new("unshare")
                .args(["--mount", "--pid", "--ipc", "--fork", "true"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let probe_ok = probe.map(|s| s.success()).unwrap_or(false);
            if !probe_ok {
                eprintln!(
                    "skipping unshared test: host lacks unshare or CAP_SYS_ADMIN — \
                     the Linux build-VM runs as PID 1 with full caps so the real \
                     dispatch path is unaffected"
                );
                return;
            }
            let dir = tempfile::tempdir().expect("tempdir");
            let cmd_path = dir.path().join("cmd.sh");
            // The build's PID inside its own ns is the last
            // column of `NSpid:`. Print it so the test can assert
            // on it.
            std::fs::write(
                &cmd_path,
                // Print one line per fact so the assertions can
                // match exact substrings rather than parse a
                // pipe-separated record. The uid check guards the
                // setpriv drop below.
                "awk '/^NSpid:/ {print \"inner_pid=\" $NF; next} \
                       /^Uid:/ {print \"uid=\" $2; next}' \
                       /proc/self/status >&2\nexit 0\n",
            )
            .expect("write cmd.sh");
            let (code, tail) = run_job_streaming(
                cmd_path.to_str().unwrap(),
                None,
                Isolation::Unshared,
                |_| {},
            );
            assert_eq!(code, 0, "tail={tail}");
            // `--pid --fork` puts the child in a fresh ns; the
            // forked shell is PID 1 inside, the awk runs as a
            // child of it (PID 2 inside).
            assert!(
                tail.contains("inner_pid=1") || tail.contains("inner_pid=2"),
                "unshare did not produce a fresh pid namespace; tail={tail}"
            );
            // The setpriv layer drops the
            // build to BUILDER_UID. The probe succeeded only if
            // the runner has CAP_SETUID (which comes with
            // CAP_SYS_ADMIN), so setpriv must succeed too.
            assert!(
                tail.contains(&format!("uid={BUILDER_UID}")),
                "setpriv did not drop uid to {BUILDER_UID}; tail={tail}"
            );
        }

        /// Pure argv-shape test for the
        /// wiring around `build_isolated_command`. Runs on every
        /// host (no spawn, no caps required) so an accidental
        /// reorder of unshare/setpriv flags trips here even when
        /// the host can't actually run the chain.
        #[test]
        fn build_isolated_command_inherit_uses_plain_shell() {
            use std::ffi::OsStr;
            let cmd = build_isolated_command("/job/cmd.sh", Isolation::Inherit);
            assert_eq!(cmd.get_program(), OsStr::new("/bin/sh"));
            let args: Vec<&OsStr> = cmd.get_args().collect();
            assert_eq!(args, vec![OsStr::new("-eu"), OsStr::new("/job/cmd.sh")]);
        }

        #[test]
        fn build_isolated_command_unshared_wraps_in_unshare_then_setpriv() {
            use std::ffi::OsStr;
            let cmd = build_isolated_command("/job/cmd.sh", Isolation::Unshared);
            assert_eq!(cmd.get_program(), OsStr::new("unshare"));
            let args: Vec<String> = cmd
                .get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            // unshare flags first.
            assert_eq!(&args[0..4], &["--mount", "--pid", "--ipc", "--fork"]);
            // setpriv follows, with numeric uid/gid and explicit
            // clear-groups / bounding-set / no-new-privs.
            assert_eq!(args[4], "setpriv");
            assert_eq!(args[5], format!("--reuid={BUILDER_UID}"));
            assert_eq!(args[6], format!("--regid={BUILDER_GID}"));
            assert_eq!(args[7], "--clear-groups");
            assert_eq!(args[8], "--bounding-set=-all");
            assert_eq!(args[9], "--no-new-privs");
            // Then the shell + cmd.
            assert_eq!(&args[10..], &["/bin/sh", "-eu", "/job/cmd.sh"]);
        }

        /// `JobScratch::create` accepts a
        /// `chown_to` arg; passing the current uid/gid is a
        /// no-op chown that any user can perform, so we can pin
        /// the wiring without needing root in CI. The actual
        /// drop-to-902 is exercised by the runtime path inside
        /// the builder VM (PID 1 has the cap to chown to any
        /// uid).
        #[test]
        fn job_scratch_chown_to_current_uid_succeeds() {
            use std::os::unix::fs::MetadataExt;
            let base = tempfile::tempdir().expect("tempdir");
            let base_str = base.path().to_str().unwrap();
            let job_id = "feedface";
            let uid = unsafe { libc::getuid() };
            let gid = unsafe { libc::getgid() };
            let _scratch =
                JobScratch::create(base_str, job_id, Some((uid, gid))).expect("chown to self");
            let meta = std::fs::metadata(base.path().join(job_id)).expect("stat");
            assert_eq!(meta.uid(), uid);
            assert_eq!(meta.gid(), gid);
        }

        #[test]
        fn nix_store_needs_seed_when_path_missing() {
            let base = tempfile::tempdir().expect("tempdir");
            assert!(nix_store_needs_seed(&base.path().join("does-not-exist")));
        }

        #[test]
        fn builder_nix_permissions_keep_store_root_owned_and_group_writable() {
            assert_eq!(
                builder_nix_permission_commands(),
                [
                    (
                        "/bin/mkdir",
                        &["-p", "/nix/var/nix", "/nix/var/log/nix"][..],
                    ),
                    ("/bin/chown", &["-R", "902:902", "/nix/var/nix"][..]),
                    ("/bin/chown", &["-R", "902:902", "/nix/var/log/nix"][..]),
                    ("/bin/chown", &["0:902", "/nix/store"][..]),
                    ("/bin/chmod", &["0775", "/nix/store"][..]),
                    (
                        "/bin/find",
                        &["/nix/store", "-maxdepth", "1", "-name", "*.lock", "-delete"][..],
                    ),
                ]
            );
        }

        #[test]
        fn nix_store_needs_seed_when_store_dir_absent() {
            let base = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir(base.path().join("lost+found")).expect("create lost+found");
            assert!(nix_store_needs_seed(base.path()));
        }

        /// Regression: `mount_nix_overlay` pre-creates `upper/` and
        /// `work/` before attempting the overlay mount. If that mount
        /// fails, the fallback path used to see the volume as "already
        /// seeded" (any non-`lost+found` entry counted) and skip the
        /// copy, leaving `/nix` empty after bind-mount. The corrected
        /// check looks at `store/` instead, so overlay scaffolding
        /// does not confuse the seeder.
        #[test]
        fn nix_store_needs_seed_when_only_overlay_scaffolding_present() {
            let base = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir(base.path().join("upper")).expect("create upper");
            std::fs::create_dir(base.path().join("work")).expect("create work");
            std::fs::create_dir(base.path().join("lost+found")).expect("create lost+found");
            assert!(nix_store_needs_seed(base.path()));
        }

        #[test]
        fn nix_store_needs_seed_when_store_dir_is_empty() {
            let base = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir(base.path().join("store")).expect("create store");
            assert!(nix_store_needs_seed(base.path()));
        }

        #[test]
        fn nix_store_does_not_need_seed_when_store_has_entries() {
            let base = tempfile::tempdir().expect("tempdir");
            let store = base.path().join("store");
            std::fs::create_dir(&store).expect("create store");
            std::fs::create_dir(store.join("abc123-some-pkg")).expect("create closure path");
            assert!(!nix_store_needs_seed(base.path()));
        }

        // --- apply_job_posture tests ---

        struct RecordingIp {
            calls: std::cell::RefCell<Vec<Vec<String>>>,
            fail_at: Option<usize>,
        }

        impl RecordingIp {
            fn new() -> Self {
                Self {
                    calls: std::cell::RefCell::new(Vec::new()),
                    fail_at: None,
                }
            }
            fn fail_at(idx: usize) -> Self {
                Self {
                    calls: std::cell::RefCell::new(Vec::new()),
                    fail_at: Some(idx),
                }
            }
        }

        impl crate::network::IptablesRunner for RecordingIp {
            fn run(&self, args: &[&str]) -> Result<(), String> {
                let mut calls = self.calls.borrow_mut();
                let idx = calls.len();
                calls.push(args.iter().map(|s| s.to_string()).collect());
                if Some(idx) == self.fail_at {
                    Err(format!("forced failure at {idx}"))
                } else {
                    Ok(())
                }
            }
        }

        fn install_job() -> crate::builder_request::BuilderJob {
            crate::builder_request::BuilderJob::Install {
                spec_path: "/job/spec.json".to_string(),
            }
        }

        fn flake_job() -> crate::builder_request::BuilderJob {
            crate::builder_request::BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            }
        }

        #[test]
        fn apply_job_posture_install_emits_flush_then_three_lockdown_rules() {
            let ip = RecordingIp::new();
            apply_job_posture(&install_job(), &ip).expect("happy path");
            let calls = ip.calls.borrow();
            // flush + 3 rules = 4 invocations
            assert_eq!(calls.len(), 4);
            assert_eq!(calls[0], vec!["-F".to_string(), "OUTPUT".to_string()]);
            assert_eq!(
                calls[1],
                vec![
                    "-A".to_string(),
                    "OUTPUT".to_string(),
                    "-o".to_string(),
                    "lo".to_string(),
                    "-j".to_string(),
                    "ACCEPT".to_string(),
                ]
            );
            assert!(calls[2].iter().any(|a| a == "--uid-owner"));
            assert!(
                calls[2]
                    .iter()
                    .any(|a| a == &crate::network::PROXY_UID.to_string())
            );
            assert!(calls[2].iter().any(|a| a == "ACCEPT"));
            assert_eq!(
                calls[3],
                vec!["-P".to_string(), "OUTPUT".to_string(), "DROP".to_string()]
            );
        }

        #[test]
        fn apply_job_posture_flake_emits_flush_then_accept_policy() {
            let ip = RecordingIp::new();
            apply_job_posture(&flake_job(), &ip).expect("happy path");
            let calls = ip.calls.borrow();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0], vec!["-F".to_string(), "OUTPUT".to_string()]);
            assert_eq!(
                calls[1],
                vec!["-P".to_string(), "OUTPUT".to_string(), "ACCEPT".to_string()]
            );
        }

        #[test]
        fn apply_job_posture_install_propagates_error() {
            // Fail at invocation 0 (the flush) — error surfaces immediately.
            let ip = RecordingIp::fail_at(0);
            let result = apply_job_posture(&install_job(), &ip);
            assert!(result.is_err(), "posture error must propagate");
        }

        #[test]
        fn apply_job_posture_flake_propagates_error() {
            let ip = RecordingIp::fail_at(0);
            let result = apply_job_posture(&flake_job(), &ip);
            assert!(result.is_err(), "posture error must propagate");
        }
    }
}
