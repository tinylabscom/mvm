//! Cloud Hypervisor host-side runtime helpers.
//!
//! Spawn dance + JSON-API client + per-VM state tracking, factored
//! out of `cloud_hypervisor.rs` so the `VmBackend` impl stays narrow
//! and the API-building logic can be unit-tested in isolation.
//!
//! ## API model
//!
//! Cloud Hypervisor exposes its lifecycle over an HTTP-over-Unix-
//! socket API documented at
//! <https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/api.md>.
//! The endpoints we use:
//!
//! | Endpoint                       | Body                | When |
//! |--------------------------------|---------------------|------|
//! | `PUT  /api/v1/vm.create`       | full `VmConfig` JSON | Pre-boot config |
//! | `PUT  /api/v1/vm.boot`         | empty                | Start the VM |
//! | `PUT  /api/v1/vm.shutdown`     | empty                | Graceful shutdown |
//! | `PUT  /api/v1/vmm.shutdown`    | empty                | Exit the VMM (reaps daemon) |
//! | `GET  /api/v1/vm.info`         | n/a                  | (Future: snapshot/info) |
//!
//! We shell out to `curl --unix-socket` for the same reason
//! `FirecrackerBackend::api_put_socket` does — it's the only HTTP-
//! over-UDS path already in the workspace, the binary is on every
//! Linux+CH host, and pulling in a new sync HTTP client crate for
//! one backend isn't a worthwhile cost.
//!
//! ## State on disk
//!
//! Per-VM state lives under `~/microvm/vms/<name>/` (the shared
//! `VMS_DIR` convention). Files:
//!
//! - `ch.socket`     — Unix socket for the CH JSON API
//! - `ch.pid`        — PID of the running `cloud-hypervisor` daemon
//! - `ch.log`        — captured stderr (CH writes here)
//! - `console.log`   — captured guest console
//! - `v.sock`        — vsock socket for the guest agent (host side)
//! - `run-info.json` — backend-agnostic run record (same shape FC
//!   writes; consumed by `mvmctl ls`)
//!
//! ## Status (untested-without-CH-host caveat)
//!
//! This implementation has not been validated against a live
//! Cloud Hypervisor binary in CI; mvm's test infrastructure lacks
//! a Linux+CH host today. The unit tests below cover the pure
//! pieces (JSON config builder, URL construction, state-file paths).
//! The shell-out paths are reviewed against CH's published API but
//! will surface real-world fitness issues on first live run.
//! Mirrors the W7.x.2 caveat that `LibkrunBuilderVm` shipped
//! with — a real first run will refine details that pure-Rust
//! review can't catch.

use crate::base::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible, shell_quote};
use anyhow::{Context, Result};

/// Resolve the CH per-VM directory inside `VMS_DIR`. Same shape as
/// FC's `microvm::resolve_vm_dir` so `mvmctl ls` and friends can
/// walk a single directory and see both backend families.
pub(crate) fn ch_vm_dir(name: &str) -> Result<String> {
    let raw = format!("{}/{}", crate::base::config::VMS_DIR, name);
    // `~/microvm/vms/<name>` resolves against the shell that runs
    // it; surface the absolute path via the same trick `microvm.rs`
    // uses (echo it through `run_in_vm_stdout`).
    let abs = run_in_vm_stdout(&format!("echo {raw}"))
        .with_context(|| format!("resolving CH per-VM dir for {name}"))?;
    Ok(abs.trim().to_string())
}

/// Build the per-VM API socket path.
pub(crate) fn ch_api_socket(abs_dir: &str) -> String {
    format!("{abs_dir}/ch.socket")
}

/// Build the per-VM PID file path.
pub(crate) fn ch_pid_file(abs_dir: &str) -> String {
    format!("{abs_dir}/ch.pid")
}

/// Build the per-VM vsock socket path. The guest agent listens on
/// `GUEST_AGENT_PORT`; the host connects to this socket and writes
/// `CONNECT <port>\n` as the first line (CH's vsock framing).
pub(crate) fn ch_vsock_socket(abs_dir: &str) -> String {
    format!("{abs_dir}/v.sock")
}

/// Spawn the `cloud-hypervisor` daemon with an API socket. Same
/// pattern as `microvm::start_vm_firecracker`: `nohup setsid` so
/// the daemon survives the parent shell, redirect stdio into per-
/// VM log files, write the PID to `ch.pid`. Waits for the API
/// socket to appear before returning.
///
/// Path inputs are `shell_quote`d so a per-VM dir containing shell
/// metacharacters can't escape into the host shell. The inner
/// `bash -c '...'` body still uses unquoted variable references
/// because by that point the variables are bash locals, not
/// untrusted strings.
pub(crate) fn start_ch_daemon(abs_dir: &str, abs_socket: &str) -> Result<()> {
    let q_dir = shell_quote(abs_dir);
    let q_socket = shell_quote(abs_socket);
    run_in_vm_visible(&format!(
        r#"
        set -eu
        DIR={q_dir}
        SOCK={q_socket}
        mkdir -p "$DIR"
        sudo rm -f "$SOCK"
        rm -f "$DIR/v.sock"
        touch "$DIR/console.log" "$DIR/ch.log"
        sudo bash -c "nohup setsid cloud-hypervisor --api-socket \"$SOCK\" \
            </dev/null >\"$DIR/console.log\" 2>\"$DIR/ch.log\" &
            echo \$! > \"$DIR/ch.pid\""

        echo "[mvm] Waiting for CH API socket..."
        for i in $(seq 1 30); do
            [ -S "$SOCK" ] && break
            sleep 0.1
        done

        if [ ! -S "$SOCK" ]; then
            echo "[mvm] ERROR: cloud-hypervisor API socket did not appear." >&2
            exit 1
        fi
        echo "[mvm] cloud-hypervisor started."
        "#,
    ))
}

/// PUT a JSON body to a CH API endpoint.
///
/// Same shape as `microvm::api_put_socket` — shells out to
/// `curl --unix-socket`. Non-2xx responses raise an error with
/// the body included for diagnostics.
///
/// The body is written to a temp file inside the per-VM dir and
/// passed via `curl --data @<file>` so the JSON never traverses the
/// shell. This is the security fix vs. the original
/// `--data '{body}'` shape — a single-quote, backtick, or `$()` in a
/// caller-supplied path would have escaped into the host shell
/// otherwise. The endpoint string is allowlisted at the call site
/// (literal `/api/v1/vm.*` constants) so it doesn't need quoting.
pub(crate) fn api_put(abs_dir: &str, socket: &str, endpoint: &str, body: &str) -> Result<()> {
    let body_file = format!("{abs_dir}/.ch-api-body.json");
    std::fs::write(&body_file, body)
        .with_context(|| format!("writing CH API body to {body_file}"))?;
    let result = run_curl_put_with_file(socket, endpoint, Some(&body_file));
    // Clean up the body file even if the request failed — best-effort.
    let _ = std::fs::remove_file(&body_file);
    result
}

/// PUT to a CH API endpoint with no body (used for boot/shutdown).
pub(crate) fn api_put_empty(socket: &str, endpoint: &str) -> Result<()> {
    run_curl_put_with_file(socket, endpoint, None)
}

/// GET a CH API endpoint, returning the response body as a string.
///
/// Used by read-only endpoints like `/api/v1/vm.info` (and via that,
/// the balloon-state path). Same defensive quoting rules as `api_put`;
/// the endpoint argument is a compile-time constant at call sites.
pub(crate) fn api_get(socket: &str, endpoint: &str) -> Result<String> {
    let q_socket = shell_quote(socket);
    let url = format!("http://localhost{endpoint}");
    let q_url = shell_quote(&url);
    let q_endpoint = shell_quote(endpoint);
    let script = format!(
        r#"
        set -eu
        response=$(sudo curl -s -w "\n%{{http_code}}" --unix-socket {q_socket} {q_url})
        code=$(printf '%s' "$response" | tail -n1)
        out=$(printf '%s' "$response" | sed '$d')
        if [ "$code" -ge 400 ]; then
            echo "[mvm] ERROR: CH GET $(printf '%s' {q_endpoint}) returned $code: $out" >&2
            exit 1
        fi
        printf '%s' "$out"
        "#,
    );
    run_in_vm_stdout(&script)
}

/// Shared curl shell-out for both PUT variants.
///
/// The socket path is `shell_quote`d defensively even though it
/// originates inside `~/microvm/vms/<name>/` (which `name` should
/// have been validated upstream). Endpoint is interpolated raw
/// because callers pass compile-time constants — flagged here so a
/// future caller doesn't silently widen the trust assumption.
fn run_curl_put_with_file(socket: &str, endpoint: &str, body_file: Option<&str>) -> Result<()> {
    let q_socket = shell_quote(socket);
    let url = format!("http://localhost{endpoint}");
    let q_url = shell_quote(&url);
    let data_arg = match body_file {
        Some(path) => {
            // The `@`-prefix tells curl to read from a file; we still
            // shell-quote the path to defend against unusual chars.
            let q_path = shell_quote(path);
            format!(
                "--data @{q_path} -H 'Content-Type: application/json'",
                q_path = &q_path[..]
            )
        }
        None => String::new(),
    };
    let q_endpoint = shell_quote(endpoint);
    let script = format!(
        r#"
        set -eu
        response=$(sudo curl -s -w "\n%{{http_code}}" -X PUT --unix-socket {q_socket} \
            {data_arg} {q_url})
        code=$(printf '%s' "$response" | tail -n1)
        out=$(printf '%s' "$response" | sed '$d')
        if [ "$code" -ge 400 ]; then
            echo "[mvm] ERROR: CH PUT $(printf '%s' {q_endpoint}) returned $code: $out" >&2
            exit 1
        fi
        "#,
    );
    run_in_vm_visible(&script)
}

/// Build the `VmConfig` JSON body for `PUT /api/v1/vm.create`.
///
/// Pure function — no I/O, returns the serialized JSON. Designed
/// to be unit-testable: tests assert shape rather than running a
/// real CH boot.
///
/// The schema matches CH's main-branch
/// [`VmConfig`](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/vmm/src/config.rs)
/// at the subset we use. CH ignores absent fields (`net`, `vsock`,
/// `console`, etc. default to sensible values) — we only emit
/// what's strictly required for an mvm-shape boot plus the vsock
/// path so the guest agent has a host channel.
pub(crate) fn build_vm_config(args: &VmConfigArgs<'_>) -> String {
    let memory_bytes = u64::from(args.memory_mib) * 1024 * 1024;
    let initramfs = match args.initrd_path {
        Some(p) => format!(", \"initramfs\": {{ \"path\": {} }}", json_str(p)),
        None => String::new(),
    };
    let cmdline = match args.cmdline {
        Some(c) => format!(", \"cmdline\": {{ \"args\": {} }}", json_str(c)),
        None => String::new(),
    };
    // Cloud-hypervisor expresses the virtio-balloon device through
    // the top-level `balloon` field: `size` is the *initial balloon
    // inflation* in bytes (memory the guest hands back at boot).
    // Same semantics as Firecracker's `amount_mib`. We only emit the
    // field when the workload opted in; absent = no balloon device.
    let balloon = match args.balloon_mib {
        Some(mib) if mib > 0 => {
            let bytes = u64::from(mib) * 1024 * 1024;
            // `deflate_on_oom: true` matches the FC mandatory shape —
            // guest must be able to take pages back under pressure.
            format!(r#", "balloon": {{ "size": {bytes}, "deflate_on_oom": true }}"#,)
        }
        _ => String::new(),
    };
    format!(
        r#"{{
          "cpus": {{ "boot_vcpus": {cpus}, "max_vcpus": {cpus} }},
          "memory": {{ "size": {memory_bytes} }},
          "payload": {{ "kernel": {kernel}{initramfs}{cmdline} }},
          "disks": [
            {{ "path": {rootfs}, "readonly": false }}
          ],
          "vsock": {{ "cid": {vsock_cid}, "socket": {vsock_socket} }},
          "console": {{ "mode": "Off" }},
          "serial": {{ "mode": "Tty" }}{balloon}
        }}"#,
        cpus = args.cpus,
        memory_bytes = memory_bytes,
        kernel = json_str(args.kernel_path),
        initramfs = initramfs,
        cmdline = cmdline,
        rootfs = json_str(args.rootfs_path),
        vsock_cid = args.vsock_cid,
        vsock_socket = json_str(&args.vsock_socket_path),
        balloon = balloon,
    )
}

/// Caller-supplied data for `build_vm_config`. Carried as a struct
/// so the function stays clippy-clean against `too_many_arguments`.
pub(crate) struct VmConfigArgs<'a> {
    pub kernel_path: &'a str,
    pub rootfs_path: &'a str,
    pub initrd_path: Option<&'a str>,
    pub cmdline: Option<&'a str>,
    pub cpus: u32,
    pub memory_mib: u32,
    /// Initial balloon inflation in MiB. `None` (or `Some(0)`) omits
    /// the balloon device entirely. When `Some(n)` with `n > 0`, CH
    /// attaches a balloon pre-inflated to `n` MiB; the host commits
    /// `memory_mib - n` MiB at boot. Equivalent to FC's `amount_mib`.
    pub balloon_mib: Option<u32>,
    pub vsock_cid: u32,
    pub vsock_socket_path: String,
}

/// Quote a string for safe JSON interpolation. The mvm artifact
/// paths we get from upstream are well-formed paths without
/// embedded quotes, but defending against the general case keeps
/// the helper robust against arbitrary VmStartConfig inputs.
fn json_str(s: &str) -> String {
    let escaped: String = s
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect();
    format!("\"{escaped}\"")
}

/// Best-effort PID liveness check via `/proc/<pid>/comm`. Matches
/// the FC backend's `is_pid_alive` heuristic (CH binary's argv[0]
/// is `cloud-hypervisor` in Linux).
pub(crate) fn is_pid_alive(pid_file: &str) -> Result<bool> {
    let q_pid = shell_quote(pid_file);
    let out = run_in_vm_stdout(&format!(
        r#"PID={q_pid}
           [ -f "$PID" ] && p=$(cat "$PID") && \
           [ -f "/proc/$p/comm" ] && \
           [ "$(cat /proc/$p/comm)" = "cloud-hypervisor" ] && \
           echo yes || echo no"#,
    ))?;
    Ok(out.trim() == "yes")
}

/// Best-effort cleanup: kill the daemon if running, remove the API
/// socket. Idempotent.
pub(crate) fn reap(abs_dir: &str) -> Result<()> {
    let socket = ch_api_socket(abs_dir);
    let pid_file = ch_pid_file(abs_dir);
    let q_pid = shell_quote(&pid_file);
    let q_socket = shell_quote(&socket);
    let _ = run_in_vm(&format!(
        r#"PID={q_pid}
           [ -f "$PID" ] && p=$(cat "$PID") && \
           sudo kill -TERM "$p" 2>/dev/null || true"#,
    ));
    let _ = run_in_vm(&format!("sudo rm -f {q_socket}"));
    Ok(())
}

/// Scan `VMS_DIR` for per-VM dirs that contain `ch.pid`. Used by
/// `CloudHypervisorBackend::list`. The presence of a `ch.pid`
/// distinguishes CH-managed VMs from Firecracker's `fc.pid`.
///
/// `VMS_DIR` is a compile-time constant so doesn't need quoting; the
/// `echo` resolves any leading `~/` against the shell that runs it.
pub(crate) fn list_ch_vms() -> Result<Vec<String>> {
    let abs_vms = run_in_vm_stdout(&format!("echo {}", crate::base::config::VMS_DIR))?;
    let q_dir = shell_quote(abs_vms.trim());
    let listing = run_in_vm_stdout(&format!(
        r#"DIR={q_dir}
        for d in "$DIR"/*/; do
            [ -f "$d/ch.pid" ] || continue
            basename "$d"
        done
        "#,
    ))?;
    Ok(listing
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ch_paths_are_namespaced_under_vm_dir() {
        assert_eq!(ch_api_socket("/tmp/vms/x"), "/tmp/vms/x/ch.socket");
        assert_eq!(ch_pid_file("/tmp/vms/x"), "/tmp/vms/x/ch.pid");
        assert_eq!(ch_vsock_socket("/tmp/vms/x"), "/tmp/vms/x/v.sock");
    }

    #[test]
    fn json_str_quotes_simple_path() {
        assert_eq!(json_str("/path/to/file"), "\"/path/to/file\"");
    }

    #[test]
    fn json_str_escapes_embedded_quote() {
        assert_eq!(json_str(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn json_str_escapes_backslash_and_newline() {
        assert_eq!(json_str("a\\b"), r#""a\\b""#);
        assert_eq!(json_str("a\nb"), r#""a\nb""#);
    }

    #[test]
    fn build_vm_config_carries_required_fields() {
        let args = VmConfigArgs {
            kernel_path: "/k/vmlinux",
            rootfs_path: "/k/rootfs.ext4",
            initrd_path: None,
            cmdline: Some("console=ttyS0 root=/dev/vda"),
            cpus: 4,
            memory_mib: 2048,
            balloon_mib: None,
            vsock_cid: 3,
            vsock_socket_path: "/tmp/v.sock".to_string(),
        };
        let json = build_vm_config(&args);
        // Sanity: must be valid JSON.
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("config must serialize as valid JSON");
        // Spot-check key fields. We don't pin the exact wire shape
        // here because CH evolves the schema between releases; the
        // fields we care about must be present and well-formed.
        assert_eq!(parsed["cpus"]["boot_vcpus"], 4);
        assert_eq!(parsed["cpus"]["max_vcpus"], 4);
        assert_eq!(parsed["memory"]["size"], 2048u64 * 1024 * 1024);
        assert_eq!(parsed["payload"]["kernel"], "/k/vmlinux");
        assert_eq!(
            parsed["payload"]["cmdline"]["args"],
            "console=ttyS0 root=/dev/vda"
        );
        assert_eq!(parsed["disks"][0]["path"], "/k/rootfs.ext4");
        assert_eq!(parsed["disks"][0]["readonly"], false);
        assert_eq!(parsed["vsock"]["cid"], 3);
        assert_eq!(parsed["vsock"]["socket"], "/tmp/v.sock");
    }

    #[test]
    fn build_vm_config_includes_initramfs_when_present() {
        let args = VmConfigArgs {
            kernel_path: "/k/vmlinux",
            rootfs_path: "/k/rootfs.ext4",
            initrd_path: Some("/k/initrd.cpio.gz"),
            cmdline: None,
            cpus: 1,
            memory_mib: 256,
            balloon_mib: None,
            vsock_cid: 3,
            vsock_socket_path: "/tmp/v.sock".to_string(),
        };
        let json = build_vm_config(&args);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["payload"]["initramfs"]["path"], "/k/initrd.cpio.gz");
    }

    #[test]
    fn build_vm_config_omits_initramfs_when_absent() {
        let args = VmConfigArgs {
            kernel_path: "/k/vmlinux",
            rootfs_path: "/k/rootfs.ext4",
            initrd_path: None,
            cmdline: None,
            cpus: 1,
            memory_mib: 256,
            balloon_mib: None,
            vsock_cid: 3,
            vsock_socket_path: "/tmp/v.sock".to_string(),
        };
        let json = build_vm_config(&args);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed["payload"]["initramfs"].is_null());
    }

    #[test]
    fn build_vm_config_omits_balloon_when_unset() {
        let args = VmConfigArgs {
            kernel_path: "/k/vmlinux",
            rootfs_path: "/k/rootfs.ext4",
            initrd_path: None,
            cmdline: None,
            cpus: 1,
            memory_mib: 1024,
            balloon_mib: None,
            vsock_cid: 3,
            vsock_socket_path: "/tmp/v.sock".to_string(),
        };
        let json = build_vm_config(&args);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(
            parsed["balloon"].is_null(),
            "no balloon device emitted when balloon_mib is None: {json}"
        );
    }

    #[test]
    fn build_vm_config_omits_balloon_when_zero() {
        // Zero is a defensive "user opted in but to nothing useful";
        // the CH config builder treats it the same as None.
        let args = VmConfigArgs {
            kernel_path: "/k/vmlinux",
            rootfs_path: "/k/rootfs.ext4",
            initrd_path: None,
            cmdline: None,
            cpus: 1,
            memory_mib: 1024,
            balloon_mib: Some(0),
            vsock_cid: 3,
            vsock_socket_path: "/tmp/v.sock".to_string(),
        };
        let json = build_vm_config(&args);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed["balloon"].is_null(), "balloon: 0 should be omitted");
    }

    #[test]
    fn build_vm_config_emits_balloon_when_present() {
        // mem 1024 MiB, balloon 256 MiB → host commits 768 MiB.
        let args = VmConfigArgs {
            kernel_path: "/k/vmlinux",
            rootfs_path: "/k/rootfs.ext4",
            initrd_path: None,
            cmdline: None,
            cpus: 1,
            memory_mib: 1024,
            balloon_mib: Some(256),
            vsock_cid: 3,
            vsock_socket_path: "/tmp/v.sock".to_string(),
        };
        let json = build_vm_config(&args);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        // CH expects balloon size in bytes.
        assert_eq!(parsed["balloon"]["size"], 256u64 * 1024 * 1024);
        assert_eq!(parsed["balloon"]["deflate_on_oom"], true);
        // Memory cap stays unchanged.
        assert_eq!(parsed["memory"]["size"], 1024u64 * 1024 * 1024);
    }
}
