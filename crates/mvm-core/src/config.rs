use sha2::Digest as _;

/// Default Firecracker version, overridable at build time via `MVM_FC_VERSION` env var.
pub const FC_VERSION_DEFAULT: &str = match option_env!("MVM_FC_VERSION") {
    Some(v) => v,
    None => "v1.14.1",
};

/// Host CPU architecture for arch-tagged downloads (the Firecracker release
/// binary, firecracker-ci kernel/rootfs). `std::env::consts::ARCH` is the arch
/// mvmctl was compiled for == the arch it runs on, so the downloaded binaries
/// match the host. (Was hardcoded `"aarch64"` — wrong on x86_64: a build
/// fetched the aarch64 firecracker on an x86_64 host → "Exec format error".)
pub const ARCH: &str = std::env::consts::ARCH;

/// Normalize Firecracker version strings to a canonical form (e.g., "Firecracker v1.14.1" -> "v1.14.1").
pub fn normalize_fc_version(raw: &str) -> String {
    // Capture the last semantic version (v?MAJOR.MINOR[.PATCH])
    let re = regex::Regex::new(r"(?:v)?\d+\.\d+(?:\.\d+)?").expect("valid regex");
    let candidate = re
        .captures_iter(raw)
        .last()
        .or_else(|| re.captures_iter(FC_VERSION_DEFAULT).last())
        .map(|c| {
            c.get(0)
                .expect("regex capture group 0 must exist")
                .as_str()
                .to_string()
        })
        .unwrap_or_else(|| FC_VERSION_DEFAULT.to_string());

    if candidate.starts_with('v') {
        candidate
    } else {
        format!("v{}", candidate)
    }
}

/// Get the effective Firecracker version.
/// Priority: runtime env `MVM_FC_VERSION` > compile-time default.
/// The CLI `--fc-version` flag sets `MVM_FC_VERSION` before calling this.
pub fn fc_version() -> String {
    let raw = std::env::var("MVM_FC_VERSION").unwrap_or_else(|_| FC_VERSION_DEFAULT.to_string());
    normalize_fc_version(&raw)
}

/// Short Firecracker version for S3 asset paths (e.g., "v1.13").
/// Strips the patch component from the effective version.
pub fn fc_version_short() -> String {
    let full = fc_version();
    let trimmed = full.trim_start_matches('v');
    let parts = trimmed.split('.').collect::<Vec<_>>();
    if parts.len() >= 2 {
        format!("v{}.{}", parts[0], parts[1])
    } else {
        full
    }
}

/// The single root directory for ALL host-side mvm state.
///
/// Resolution order:
///   1. `MVM_HOME` env var (explicit override, non-empty)
///   2. `$HOME/.mvm`
///   3. `/tmp/.mvm` (lenient last resort when `$HOME` is unset; use
///      [`mvm_home_strict`] for anything security-sensitive)
///
/// Everything mvm writes on the host lives under this one root: data
/// children (`keys/`, `audit/`, `volumes/`, …) sit directly at the root,
/// and the former standalone roots are subdirectories — `cache/`,
/// `config/`, `run/`, `state/`, `share/`, `vms/`. This deliberately
/// deviates from the XDG base-directory spec: one hermetic, discoverable
/// root means `MVM_HOME` relocates the whole world for parallel sessions,
/// and `rm -rf ~/.mvm` removes every trace. No `XDG_*` variable is
/// consulted anywhere.
///
/// This is a user-owned directory — no sudo required.
/// Fleet orchestration state (tenants, pools, instances) uses `/var/lib/mvm/`
/// and is managed by mvmd with appropriate permissions.
pub fn mvm_home() -> String {
    if let Ok(d) = std::env::var("MVM_HOME")
        && !d.is_empty()
    {
        return d;
    }
    format!("{}/.mvm", home_dir())
}

/// Like [`mvm_home`] but fails instead of silently falling back to
/// `/tmp` when neither `MVM_HOME` nor `$HOME` is set. Use this for
/// security-sensitive state — secrets, signed bundles, the trusted-
/// publisher store, per-tenant policy — that must never land in a
/// world-traversable `/tmp` just because `$HOME` happened to be unset.
/// Honors the `MVM_HOME` override so parallel sessions stay isolated
/// (the inline `$HOME/.mvm` derivations this replaces silently ignored it).
pub fn mvm_home_strict() -> std::io::Result<std::path::PathBuf> {
    if let Ok(d) = std::env::var("MVM_HOME")
        && !d.is_empty()
    {
        return Ok(std::path::PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "$HOME unset and MVM_HOME not set; cannot locate ~/.mvm",
        )
    })?;
    Ok(std::path::PathBuf::from(home).join(".mvm"))
}

/// Create `~/.mvm` (or whatever `mvm_home()` resolves to) with
/// mode `0700` and return its path. Idempotent: if the dir already
/// exists with looser perms, chmod it to `0700` so a host that was
/// created before this lockdown still gets locked down on the next
/// run.
///
/// `~/.mvm` holds the dev VM's GC root, the host-backed Nix store
/// disk image, the per-VM `vsock.sock` proxy listener path, build
/// artifacts in `dev/builds/<rev>/`, and (for production microVMs)
/// any persisted volumes — every secret-shaped piece of state in
/// the project. Defaulting to umask perms (typ. 0755) means a
/// same-host other user can read all of it; this is the project's
/// privacy boundary.
#[cfg(unix)]
pub fn ensure_home_dir() -> std::io::Result<String> {
    let dir = mvm_home();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Create `~/.mvm/cache` (or wherever `mvm_cache_dir()` resolves to)
/// with mode `0700`. Same rationale as `ensure_home_dir`. The cache
/// holds the dev image kernel/rootfs, daemon stdout/stderr logs,
/// and the GC sentinel — none of it is secret on its own, but the
/// daemon logs *do* capture guest stdout, which can leak whatever
/// the guest prints. Lock it down by default.
#[cfg(unix)]
pub fn ensure_cache_dir() -> std::io::Result<String> {
    let dir = mvm_cache_dir();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Create `dir` (and parents) and chmod it to mode `0700`. Both the
/// initial create and the chmod are idempotent.
#[cfg(unix)]
fn ensure_private_dir(dir: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir)?;
    let mut perms = std::fs::metadata(dir)?.permissions();
    if perms.mode() & 0o777 != 0o700 {
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

// ============================================================================
// Subtree accessors under the single root
// ============================================================================
//
// Each former standalone root is now a fixed child of `mvm_home()`. The
// accessors stay so call sites read as intent (`mvm_cache_dir()`), but they
// take no overrides of their own — `MVM_HOME` moves the whole tree.

fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
}

/// Cache directory for build artifacts, images, VM runtime state:
/// `<mvm_home>/cache`.
pub fn mvm_cache_dir() -> String {
    format!("{}/cache", mvm_home())
}

/// The cache directory of the *default* root (`$HOME/.mvm/cache`),
/// deliberately ignoring the `MVM_HOME` override. Isolated sessions
/// (worktrees pointing `MVM_HOME` at a tempdir) use this to
/// opportunistically seed expensive artifacts — the builder VM image,
/// the runtime overlay — from the host's shared cache instead of
/// re-bootstrapping from scratch.
pub fn default_mvm_cache_dir() -> String {
    format!("{}/.mvm/cache", home_dir())
}

/// Config directory for user configuration files: `<mvm_home>/config`.
pub fn mvm_config_dir() -> String {
    format!("{}/config", mvm_home())
}

/// Runtime directory for ephemeral per-session / per-call state:
/// `<mvm_home>/run`.
///
/// Holds short-lived state like the session table at
/// `<runtime>/sessions/<id>.json`. By contract the dir is mode 0700;
/// entries within it are 0600 unless the writer explicitly relaxes
/// them. Unlike a systemd-style runtime dir it survives reboots, so
/// readers must treat stale entries as garbage, not truth.
pub fn mvm_runtime_dir() -> String {
    format!("{}/run", mvm_home())
}

/// Create the runtime dir 0700 and return its path. Idempotent.
#[cfg(unix)]
pub fn ensure_runtime_dir() -> std::io::Result<String> {
    let dir = mvm_runtime_dir();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// State directory for logs and long-lived operational state:
/// `<mvm_home>/state`.
pub fn mvm_state_dir() -> String {
    format!("{}/state", mvm_home())
}

/// Share directory for templates, network definitions, and registries:
/// `<mvm_home>/share`.
pub fn mvm_share_dir() -> String {
    format!("{}/share", mvm_home())
}

/// Root directory for application-dependency volumes sealed by
/// `mvm_sdk::compile::deps_audit::seal_volume`: `<mvm_home>/volumes/deps`.
/// Each immediate child is a `<volume_hash>/` directory containing
/// `content/`, `sbom.cdx.json`, `fetch.log`, `cve.json`, `meta.json`.
///
/// The supervisor's admission gate (security claim 9 — every
/// application-dep volume is hash-locked and audited) reads this
/// dir; `mvmctl build` writes to it.
pub fn mvm_deps_volumes_dir() -> String {
    format!("{}/volumes/deps", mvm_home())
}

/// Custom volume specs from the `MVM_VOLUMES` env var: a comma-separated
/// list of `--volume` specs (e.g. `~/src:/work:ro,data.img:/data:10G`).
/// Whitespace around each entry is trimmed and empty entries dropped;
/// unset or empty → `[]`. The CLI merges these *before* `--volume` flag
/// values (env is the baseline, flags append). Parsing/validation of
/// each spec lives in the CLI crate (`commands::shared::parse`), so this
/// returns raw strings and keeps `mvm-core` dependency-free.
pub fn mvm_volumes_env() -> Vec<String> {
    std::env::var("MVM_VOLUMES")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve `<deps_volumes_dir>/<volume_hash>` for a single deps
/// volume. The caller is responsible for verifying the directory
/// exists and matches its sealed manifest — see
/// `mvm_sdk::compile::deps_audit::verify_sealed_volume`.
pub fn deps_volume_dir(volume_hash: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_deps_volumes_dir()).join(volume_hash)
}

/// Root directory for content-addressed attested packs promoted by
/// `mvm_core::pack_cache`. Each immediate child is a `<pack_hash>/`
/// directory holding the verified file set plus a serialized manifest;
/// the `.incoming/` sibling is the same-filesystem quarantine staging
/// area the atomic rename-promote moves out of.
pub fn pack_cache_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_cache_dir()).join("packs")
}

/// Resolve `<pack_cache_dir>/<pack_hash>` for a single promoted pack.
/// The directory only appears after `verify_pack_at` accepts the staged
/// pack, so a reader that observes it can trust its content — but every
/// use re-verifies (`pack_cache::resolve_pack`) to catch later tampering.
pub fn pack_dir(pack_hash: &str) -> std::path::PathBuf {
    pack_cache_dir().join(pack_hash)
}

// ============================================================================
// Per-VM host-side state paths
// ============================================================================
//
// Every per-VM artifact mvm writes on the host lives under
// `<mvm_home>/vms/<name>/`. Build these paths ONLY through the helpers
// below: a single source of truth for the layout, and `MVM_HOME` is
// honored everywhere. The inline `$HOME/.mvm/vms/...` derivations these
// replace duplicated the convention — which let the libkrun vsock socket
// name drift between two resolvers — and silently ignored the override,
// so parallel sessions collided despite setting it.

/// Root of all per-VM directories: `<mvm_home>/vms/`. One tree for every
/// backend — the Firecracker workspace (fc.pid, fc.socket, run-info.json,
/// disk images) and the host-side VMM state (pid files, console log,
/// vsock sockets) share the same per-VM directory with disjoint file names.
pub fn vms_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("vms")
}

/// Per-VM state directory: `<mvm_home>/vms/<name>/`. Holds the
/// libkrun pid file, console log, vsock listener socket(s), runtime
/// `mode.json`, `rootfs.ref` / `kernel.ref`, and the `ports` file.
pub fn vm_state_dir(name: &str) -> std::path::PathBuf {
    vms_dir().join(name)
}

/// Per-instance state root: `<mvm_home>/instances/<name>/`. Distinct from
/// `vms/` (the VMM runtime dir) — this holds instance-snapshot artifacts that
/// must outlive a VMM restart. Shared by the mvm-layer pause/resume
/// orchestration and the backend warm-start path so both agree on one path.
pub fn instance_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home())
        .join("instances")
        .join(name)
}

/// Sealed instance-snapshot directory: `<mvm_home>/instances/<name>/snapshot/`.
/// Holds `vmstate.bin` + `mem.bin` + the integrity sidecar a warm-start loads.
pub fn instance_snapshot_dir(name: &str) -> std::path::PathBuf {
    instance_dir(name).join("snapshot")
}

// ============================================================================
// Persistent `mvmctl machine` specs
// ============================================================================
//
// Named machines are product-level state, not a VMM runtime directory. Keep
// their declarative spec under `<mvm_home>/machines/<name>/` so runtime
// sockets/pids under `vms/` can be replaced without migrating the UX contract.

/// Root of persistent named machine specs: `<mvm_home>/machines/`.
pub fn machine_state_root() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("machines")
}

/// Persistent named machine directory: `<mvm_home>/machines/<name>/`.
pub fn machine_state_dir(name: &str) -> std::path::PathBuf {
    machine_state_root().join(name)
}

/// Persistent named machine spec: `<mvm_home>/machines/<name>/machine.json`.
pub fn machine_spec_path(name: &str) -> std::path::PathBuf {
    machine_state_dir(name).join("machine.json")
}

/// Root of the per-tenant host-agent daemon dirs: `<mvm_home>/host-agent`.
/// Each `<tenant>/` subdir holds one resident daemon's control UDS, pid file,
/// and spawn lock. Enumerated by `mvmctl doctor` to report daemon state.
pub fn host_agent_root() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("host-agent")
}

/// Per-tenant host-agent daemon directory: `<mvm_home>/host-agent/<tenant>/`.
/// Holds the resident daemon's control UDS, pid file, worker pid file, and
/// spawn lock — one set per tenant, so the daemon is `O(active tenants)` not
/// `O(VMs)`.
pub fn host_agent_dir(tenant: &str) -> std::path::PathBuf {
    host_agent_root().join(tenant)
}

/// The per-tenant host-agent control UDS the daemon binds (mode 0700) and the
/// backend registers VMs over.
pub fn host_agent_control_socket(tenant: &str) -> std::path::PathBuf {
    host_agent_dir(tenant).join("control.sock")
}

/// The per-tenant host-agent worker pid file used by restart recovery.
pub fn host_agent_worker_pid(tenant: &str) -> std::path::PathBuf {
    host_agent_dir(tenant).join("worker.pid")
}

/// The per-tenant signer-helper UDS the host-agent daemon connects to. The
/// helper is a child of the host-agent and owns the tenant's signing keys plus
/// per-VM workload chain heads.
pub fn host_agent_signer_helper_socket(tenant: &str) -> std::path::PathBuf {
    host_agent_dir(tenant).join("signer-helper.sock")
}

/// `<mvm_home>/pool/` — the supervisor standby pool root.
/// Each idle standby gets a `pool/<id>/` subdir holding its control UDS +
/// `standby.json`. Uses the strict resolver so a missing `$HOME`/`MVM_HOME`
/// surfaces as an error rather than silently writing entitled processes' state to
/// `/tmp`.
pub fn mvm_pool_dir() -> std::io::Result<std::path::PathBuf> {
    Ok(mvm_home_strict()?.join("pool"))
}

/// `<mvm_home>/pool/<id>/` for a single standby.
pub fn pool_standby_dir(id: &str) -> std::io::Result<std::path::PathBuf> {
    Ok(mvm_pool_dir()?.join(id))
}

/// Filename of libkrun's per-port vsock listener socket: `vsock-<port>.sock`.
/// The single source of truth for the name. Callers that already hold the
/// per-VM dir (e.g. a `VsockTransport` constructed from an explicit dir)
/// join this; callers that hold the VM name use [`vm_vsock_port_socket`].
pub fn vsock_socket_filename(port: u32) -> String {
    format!("vsock-{port}.sock")
}

/// Conservative per-path byte budget for Unix-domain sockets. macOS caps
/// `sockaddr_un.sun_path` at roughly 104 bytes including the trailing NUL, so
/// keep generated paths at or below 103 bytes and fall back to a short `/tmp`
/// namespace when a worktree-local `MVM_HOME` would overflow it.
const UNIX_SOCKET_PATH_MAX_BYTES: usize = 103;
const SHORT_VM_SOCKET_ROOT: &str = "/tmp/mvm-sock";

fn unix_socket_path_len(path: &std::path::Path) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().len()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().len()
    }
}

fn fits_unix_socket_path(path: &std::path::Path) -> bool {
    unix_socket_path_len(path) <= UNIX_SOCKET_PATH_MAX_BYTES
}

fn short_vm_socket_dir_at(state_dir: &std::path::Path) -> std::path::PathBuf {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt as _;

    let digest = {
        #[cfg(unix)]
        {
            sha2::Sha256::digest(state_dir.as_os_str().as_bytes())
        }
        #[cfg(not(unix))]
        {
            let path = state_dir.to_string_lossy();
            sha2::Sha256::digest(path.as_bytes())
        }
    };
    std::path::PathBuf::from(SHORT_VM_SOCKET_ROOT).join(hex::encode(&digest[..8]))
}

/// Per-VM Unix-socket directory. Uses the normal `vm_state_dir` when its known
/// socket shapes fit within the Unix-domain path budget; otherwise falls back to
/// a hashed short namespace under `/tmp/mvm-sock/` so interactive HVF runs from
/// deep worktrees still bind on macOS.
pub fn vm_socket_dir_at(state_dir: &std::path::Path) -> std::path::PathBuf {
    let max_root_socket = state_dir.join("substitution-endpoint.sock");
    let max_vsock_socket = state_dir
        .join("vsock")
        .join(vsock_socket_filename(u16::MAX.into()));
    if fits_unix_socket_path(&max_root_socket) && fits_unix_socket_path(&max_vsock_socket) {
        state_dir.to_path_buf()
    } else {
        short_vm_socket_dir_at(state_dir)
    }
}

/// Per-VM Unix-socket directory for a named VM.
pub fn vm_socket_dir(name: &str) -> std::path::PathBuf {
    vm_socket_dir_at(&vm_state_dir(name))
}

/// libkrun's per-port vsock listener socket: `<socket-dir>/vsock-<port>.sock`.
/// `socket-dir` is normally the per-VM state dir, but falls back to a short
/// hashed `/tmp` namespace when a deep worktree path would overflow macOS's
/// Unix-socket limit. libkrun's supervisor binds one socket per forwarded
/// port, so a client connects directly with no port handshake. This +
/// [`vsock_socket_filename`] are the single source of truth for the convention
/// — every host-side resolver (the console transport, the dev-VM connect path)
/// must use them so they cannot drift.
pub fn vm_vsock_port_socket(name: &str, port: u32) -> std::path::PathBuf {
    vm_vsock_port_socket_at(&vm_state_dir(name), port)
}

/// Same as [`vm_vsock_port_socket`] when the caller already has the per-VM
/// state dir and only needs the port-specific socket path.
pub fn vm_vsock_port_socket_at(state_dir: &std::path::Path, port: u32) -> std::path::PathBuf {
    vm_socket_dir_at(state_dir).join(vsock_socket_filename(port))
}

/// The Apple-Container cross-process vsock proxy socket:
/// `<vm_state_dir>/vsock.sock`. The dev daemon listens here and
/// multiplexes ports via a 4-byte little-endian port prefix.
pub fn vm_vsock_proxy_socket(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("vsock.sock")
}

/// Filename of the in-house runner's guest-agent RPC bridge socket:
/// `agent.sock`. Single source of truth for the name; callers that hold the
/// per-VM dir join this via [`vm_inhouse_agent_socket_at`], callers that hold
/// the VM name use [`vm_inhouse_agent_socket`].
pub fn inhouse_agent_socket_filename() -> &'static str {
    "agent.sock"
}

/// The `WorkloadRunner`'s generic standing guest-agent RPC hint under an
/// explicit per-VM state dir: `<socket-dir>/agent.sock`. It is a backend-neutral
/// placeholder the runner threads onto the spec's `GUEST_AGENT_PORT` channel; a
/// concrete driver re-derives its own agent-bridge path and ignores this value,
/// exactly as the FC and libkrun drivers ignore the spec's agent host_uds. The
/// detached-supervisor HVF path binds and probes [`vm_hvf_agent_socket_at`]
/// (`hvf-agent.sock`) instead — that is the socket that must not drift between
/// binder and host resolver.
pub fn vm_inhouse_agent_socket_at(state_dir: &std::path::Path) -> std::path::PathBuf {
    vm_socket_dir_at(state_dir).join(inhouse_agent_socket_filename())
}

/// The in-house runner's guest-agent RPC bridge for a VM by name:
/// `<socket-dir>/agent.sock`. See [`vm_inhouse_agent_socket_at`].
pub fn vm_inhouse_agent_socket(name: &str) -> std::path::PathBuf {
    vm_inhouse_agent_socket_at(&vm_state_dir(name))
}

/// The directory the HVF supervisor nests its per-port vsock listener
/// sockets under: `<socket-dir>/vsock`. Unlike libkrun (which binds
/// `<vm_state_dir>/vsock-<port>.sock` directly), the HVF `VsockProxy`
/// listens inside this subdir. `socket-dir` is normally the per-VM state dir,
/// but falls back to a short hashed `/tmp` namespace when a deep worktree path
/// would overflow macOS's Unix-socket limit. Single source of truth so
/// `mvm-backend`'s supervisor config and the host-side `HvfVsockTransport`
/// can't drift.
pub fn vm_hvf_vsock_dir_at(state_dir: &std::path::Path) -> std::path::PathBuf {
    vm_socket_dir_at(state_dir).join("vsock")
}

/// The directory the HVF supervisor nests its per-port vsock listener
/// sockets under for a named VM.
pub fn vm_hvf_vsock_dir(name: &str) -> std::path::PathBuf {
    vm_hvf_vsock_dir_at(&vm_state_dir(name))
}

/// HVF's per-port vsock listener socket: `<vm_state_dir>/vsock/vsock-<port>.sock`.
/// The HVF supervisor listens here and forwards to the guest's vsock port, so a
/// host client connects directly with no port handshake (same shape as libkrun,
/// one subdir deeper). Pairs with [`vm_hvf_vsock_dir`] + [`vsock_socket_filename`].
pub fn vm_hvf_vsock_port_socket_at(state_dir: &std::path::Path, port: u32) -> std::path::PathBuf {
    vm_hvf_vsock_dir_at(state_dir).join(vsock_socket_filename(port))
}

/// HVF's per-port vsock listener socket for a named VM.
pub fn vm_hvf_vsock_port_socket(name: &str, port: u32) -> std::path::PathBuf {
    vm_hvf_vsock_port_socket_at(&vm_state_dir(name), port)
}

/// libkrun supervisor pid file: `<vm_state_dir>/libkrun.pid`.
pub fn vm_libkrun_pid(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("libkrun.pid")
}

/// Guest console capture log: `<vm_state_dir>/console.log`.
pub fn vm_console_log(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("console.log")
}

/// Per-VM JSON file of `(guest var, placeholder)` pairs the
/// substitution endpoint minted at boot. The backend writes it; the invoke
/// path reads it to inject `HTTP_PROXY` + the placeholder env vars into the
/// workload. Holds opaque placeholders only — never secret values.
pub fn vm_substitution_env_path(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("substitution-env.json")
}

/// Per-VM marker that the guest booted with the loopback SOCKS5 vsock egress
/// client enabled. Invoke-time env synthesis reads it to route plain workload
/// egress through the vsock proxy rather than any guest NIC path.
pub fn vm_vsock_egress_marker_path(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("vsock-egress-enabled")
}

/// Per-VM Unix socket the `mvm-substitution-endpoint` binds and the hvf VMM's
/// substitution bridge connects to: `<socket-dir>/substitution-endpoint.sock`.
/// Unlike the per-port `vsock/`-nested convention (see
/// [`vm_hvf_vsock_dir_at`]), the hvf VMM's device bridges `EGRESS_PORT`
/// straight to this socket, so it lives at the socket-dir root.
/// `socket-dir` is normally the per-VM state dir, but falls back to a short
/// hashed `/tmp` namespace when a deep worktree path would overflow macOS's
/// Unix-socket limit. Single source of truth: the backend spawn (which binds
/// it) and the supervisor config (which hands it to the device) both resolve it
/// here.
pub fn vm_substitution_endpoint_socket(name: &str) -> std::path::PathBuf {
    vm_socket_dir(name).join("substitution-endpoint.sock")
}

/// Filename of the hvf VMM's host→guest agent-RPC bridge socket:
/// `hvf-agent.sock`. Single source of truth for the name; callers that hold the
/// per-VM state dir join it via [`vm_hvf_agent_socket_at`], callers that hold
/// the VM name use [`vm_hvf_agent_socket`].
pub fn hvf_agent_socket_filename() -> &'static str {
    "hvf-agent.sock"
}

/// The hvf VMM's host→guest agent-RPC socket under an explicit per-VM state dir:
/// `<socket-dir>/hvf-agent.sock`. The detached `mvm-hvf-supervisor`'s
/// `AgentBridge` binds it and bridges every host connection to the guest agent
/// on `GUEST_AGENT_PORT`. Single source of truth so all three sides that name it
/// — the detached supervisor (which binds it), the `HvfDriver` / `HvfBackend`
/// (which derive the value they hand the supervisor), and the host-side
/// agent-RPC resolvers (`DevConsoleTransport`, the `for_vm` ladder, which
/// connect to it) — cannot drift. A mismatch here silently makes the guest
/// agent unreachable and every non-interactive `machine run` RPC time out.
pub fn vm_hvf_agent_socket_at(state_dir: &std::path::Path) -> std::path::PathBuf {
    vm_socket_dir_at(state_dir).join(hvf_agent_socket_filename())
}

/// The hvf VMM's host→guest agent-RPC socket for a VM by name:
/// `<socket-dir>/hvf-agent.sock`. See [`vm_hvf_agent_socket_at`].
pub fn vm_hvf_agent_socket(name: &str) -> std::path::PathBuf {
    vm_hvf_agent_socket_at(&vm_state_dir(name))
}

/// The hvf VMM's per-VM `BROKER_PORT` listener socket the host-agent daemon
/// (or, on the fork path, the per-VM broker) binds on behalf of this VM:
/// `<socket-dir>/hvf-broker.sock`. Sits at the socket-dir root like the
/// substitution-endpoint socket (the `BROKER_PORT` channel has no `vsock/`
/// subdir the way the per-port console channels do — see
/// [`vm_hvf_vsock_dir_at`]). `socket-dir` is normally the per-VM state dir, but falls
/// back to a short hashed `/tmp` namespace when a deep worktree path would
/// overflow macOS's Unix-socket limit. Single source of truth so the backend
/// (which passes it to registration) and whatever eventually bridges the
/// guest's `BROKER_PORT` dial to it cannot drift.
pub fn vm_hvf_broker_socket(name: &str) -> std::path::PathBuf {
    vm_socket_dir(name).join("hvf-broker.sock")
}

// ============================================================================
// Sensitive ~/.mvm subdirectories
// ============================================================================
//
// Build these ONLY through the helpers below so they honor MVM_HOME and
// stay consistent across the diagnostics, signer, and audit paths. The
// inline `$HOME/.mvm/<sub>` derivations these replace ignored MVM_HOME.

/// Host signing keys (e.g. `host-signer.ed25519`): `<mvm_home>/keys/`.
pub fn mvm_keys_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("keys")
}

/// Immutable checkpoint store: `<mvm_home>/checkpoints/`. Each checkpoint is
/// a subdirectory `<id>/` holding `meta.json` + cloned `content/`.
pub fn checkpoints_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("checkpoints")
}

/// Immutable image version-lineage store: `<mvm_home>/images/`. Each node is a
/// subdirectory `<node-digest>/` holding `node.json`.
pub fn images_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("images")
}

/// Chain-signed audit logs: `<mvm_home>/audit/`.
pub fn mvm_audit_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("audit")
}

/// Published Merkle transparency-log root for a tenant's audit chain:
/// `<mvm_home>/audit/<tenant>.root.json`. Sibling to the `<tenant>.jsonl`
/// chain the root is computed over; the host writes it and an external
/// auditor pins it. Shared so the writer (`publish_root`) and the reader
/// (`mvmctl trust audit verify-inclusion`) can't drift on the location.
pub fn audit_root_path(tenant: &str) -> std::path::PathBuf {
    mvm_audit_dir().join(format!("{tenant}.root.json"))
}

/// Forensic transcript captures: `<mvm_home>/audit/transcripts/`. Each
/// capture is `<tenant>/<vm>/<capture-id>/` holding `manifest.json` + encrypted
/// chunk files. Kept under `audit/` since it is opt-in forensic evidence.
pub fn mvm_transcripts_dir() -> std::path::PathBuf {
    mvm_audit_dir().join("transcripts")
}

/// Filename suffix for a per-VM workload audit chain.
pub const WORKLOAD_AUDIT_SUFFIX: &str = ".workload.jsonl";

/// Per-VM workload audit-chain file:
/// `<mvm_home>/audit/<tenant>.<vm>.workload.jsonl`.
///
/// Distinct from the per-tenant *lifecycle* chain (`<tenant>.jsonl`, written
/// in-process by `FileAuditSigner`). The workload chain carries the
/// `workload_audit` entries the per-VM `mvm-audit-signer` writes. It is keyed
/// **per VM, not per tenant**, because that signer's chain writer is
/// single-writer (in-memory head, `O_APPEND`, no flock) — two VMs of one tenant
/// must not co-write one file, so each signer owns its own. Shared by the writer
/// (the backend spawn) and the verifier (`mvmctl audit verify`) so the path
/// can't drift between them.
pub fn workload_audit_path(tenant: &str, vm_name: &str) -> std::path::PathBuf {
    mvm_audit_dir().join(format!("{tenant}.{vm_name}{WORKLOAD_AUDIT_SUFFIX}"))
}

/// If `file_name` is a workload audit chain for `tenant`
/// (`<tenant>.<vm>{WORKLOAD_AUDIT_SUFFIX}`), return its VM name. Lets
/// `mvmctl audit verify` enumerate a tenant's per-VM workload chains from a
/// directory listing without re-deriving the naming convention.
pub fn workload_audit_vm_name<'a>(file_name: &'a str, tenant: &str) -> Option<&'a str> {
    let prefix = format!("{tenant}.");
    file_name
        .strip_prefix(&prefix)?
        .strip_suffix(WORKLOAD_AUDIT_SUFFIX)
        .filter(|vm| !vm.is_empty())
}

/// Overlay receipts / destruction certificates: `<mvm_home>/overlays/`.
pub fn mvm_overlays_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("overlays")
}

/// Secret-material staging: `<mvm_home>/secrets/`.
pub fn mvm_secrets_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("secrets")
}

/// The long-lived host egress CA's home:
/// `<mvm_home>/egress-ca/` (holds `ca.crt` + `ca.key`, key mode 0400).
/// The per-VM name-constrained intermediates the transparent `https`
/// terminator uses are minted under this CA; see `crypto::egress_ca`.
pub fn egress_ca_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_home()).join("egress-ca")
}

/// Check if running in production mode (MVM_PRODUCTION=1).
pub fn is_production_mode() -> bool {
    std::env::var("MVM_PRODUCTION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Check if running in dev mode (`MVM_ENV=dev`). Dev-mode commands default
/// to interactive (drop into the dev VM shell when a TTY is present) and run
/// at the dev security tier. `dev` subcommands are inherently dev mode
/// regardless of this var; `MVM_ENV=dev` marks a whole session so other
/// commands can opt into the dev experience. If `MVM_PRODUCTION` is also set,
/// production wins (fail-safe — never silently relax the prod tier). Note:
/// interactivity still requires a host TTY (the console bridges raw-mode
/// stdin) — this marks intent, it does not conjure a terminal.
pub fn is_dev_mode() -> bool {
    !is_production_mode()
        && std::env::var("MVM_ENV")
            .map(|v| v.eq_ignore_ascii_case("dev") || v.eq_ignore_ascii_case("development"))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_env::TestEnv;

    #[test]
    fn workload_audit_path_roundtrips_with_vm_name_matcher() {
        // The writer (backend spawn) builds the path; the verifier
        // (`mvmctl audit verify`) recovers the VM name from a dir listing.
        // They must agree — assert on the file name (env-independent).
        let path = workload_audit_path("local", "vm-7");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "local.vm-7.workload.jsonl");
        assert_eq!(workload_audit_vm_name(name, "local"), Some("vm-7"));
    }

    #[test]
    fn workload_audit_vm_name_rejects_other_tenants_and_shapes() {
        assert_eq!(
            workload_audit_vm_name("local.vm-1.workload.jsonl", "other"),
            None
        );
        // The per-tenant lifecycle chain is not a workload chain.
        assert_eq!(workload_audit_vm_name("local.jsonl", "local"), None);
        // Empty VM segment is rejected.
        assert_eq!(
            workload_audit_vm_name("local..workload.jsonl", "local"),
            None
        );
        // Wrong suffix.
        assert_eq!(workload_audit_vm_name("local.vm.jsonl", "local"), None);
    }

    // Tests here mutate process-global env vars (`MVM_*`, `HOME`).
    // Each grabs a `TestEnv` guard, which serializes env-mutating tests behind a
    // shared process-wide lock and restores the prior values on drop. Pure-logic
    // tests (`normalize_*`) take no guard and run in parallel.

    #[test]
    fn test_not_production_by_default() {
        let _ = is_production_mode();
    }

    #[test]
    fn test_is_dev_mode() {
        let mut env = TestEnv::new();
        env.remove("MVM_PRODUCTION");

        env.remove("MVM_ENV");
        assert!(!is_dev_mode(), "unset MVM_ENV is not dev mode");

        for v in ["dev", "DEV", "Development"] {
            env.set("MVM_ENV", v);
            assert!(is_dev_mode(), "MVM_ENV={v} should be dev mode");
        }

        env.set("MVM_ENV", "prod");
        assert!(!is_dev_mode(), "MVM_ENV=prod is not dev mode");

        // Production wins (fail-safe): never relax the prod tier even if dev
        // is also requested.
        env.set("MVM_ENV", "dev");
        env.set("MVM_PRODUCTION", "1");
        assert!(!is_dev_mode(), "MVM_PRODUCTION=1 overrides MVM_ENV=dev");

        env.remove("MVM_ENV");
        env.remove("MVM_PRODUCTION");
    }

    #[test]
    fn test_fc_version_default() {
        let mut env = TestEnv::new();
        // Without runtime env override, should return the compiled-in default
        env.remove("MVM_FC_VERSION");
        let v = fc_version();
        assert!(v.starts_with('v'), "FC version should start with 'v'");
        assert!(v.contains('.'), "FC version should contain a dot");
    }

    #[test]
    fn test_fc_version_short() {
        let mut env = TestEnv::new();
        env.remove("MVM_FC_VERSION");
        let short = fc_version_short();
        assert!(short.starts_with('v'));
        // Should have exactly one dot (major.minor)
        assert_eq!(short.matches('.').count(), 1);
    }

    #[test]
    fn normalize_firecracker_banner() {
        let raw = "Firecracker v1.14.1";
        assert_eq!(normalize_fc_version(raw), "v1.14.1");
    }

    #[test]
    fn normalize_with_leading_v() {
        let raw = "v1.14.1";
        assert_eq!(normalize_fc_version(raw), "v1.14.1");
    }

    #[test]
    fn normalize_without_v() {
        let raw = "1.14.1";
        assert_eq!(normalize_fc_version(raw), "v1.14.1");
    }

    #[test]
    fn normalize_minor_only() {
        let mut env = TestEnv::new();
        let raw = "Firecracker v1.14";
        assert_eq!(normalize_fc_version(raw), "v1.14");
        // short should remain the same when no patch component
        assert_eq!(fc_version_short_from(&mut env, raw), "v1.14");
    }

    #[test]
    fn normalize_garbage_falls_back() {
        let raw = "nonsense";
        assert_eq!(
            normalize_fc_version(raw),
            normalize_fc_version(FC_VERSION_DEFAULT)
        );
    }

    // Helper to test short derivation with a temp env override.
    fn fc_version_short_from(env: &mut TestEnv, raw: &str) -> String {
        env.set("MVM_FC_VERSION", raw);
        let short = fc_version_short();
        env.remove("MVM_FC_VERSION");
        short
    }

    // --- Single-root layout tests ---

    #[test]
    fn test_mvm_home_env_override() {
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/root");
        assert_eq!(mvm_home(), "/custom/root");
        env.remove("MVM_HOME");
    }

    #[test]
    fn test_mvm_home_default_under_home() {
        let mut env = TestEnv::new();
        env.remove("MVM_HOME");
        env.set("HOME", "/home/user");
        assert_eq!(mvm_home(), "/home/user/.mvm");
    }

    #[test]
    fn test_mvm_home_lenient_tmp_fallback() {
        // The infallible resolver falls back to /tmp/.mvm when $HOME is
        // unset; security-sensitive callers use mvm_home_strict() instead.
        let mut env = TestEnv::new();
        env.remove("MVM_HOME");
        env.remove("HOME");
        assert_eq!(mvm_home(), "/tmp/.mvm");
    }

    #[test]
    fn test_mvm_volumes_env() {
        let mut env = TestEnv::new();
        env.remove("MVM_VOLUMES");
        assert!(mvm_volumes_env().is_empty(), "unset → empty");

        env.set("MVM_VOLUMES", "");
        assert!(mvm_volumes_env().is_empty(), "empty → empty");

        env.set("MVM_VOLUMES", " ~/a:/a:ro , data.img:/d:10G ,, ");
        assert_eq!(
            mvm_volumes_env(),
            vec!["~/a:/a:ro".to_string(), "data.img:/d:10G".to_string()],
            "comma-split, trimmed, empties dropped"
        );
        env.remove("MVM_VOLUMES");
    }

    #[test]
    fn subtree_accessors_are_children_of_the_single_root() {
        // One override moves the whole world: every former standalone root
        // is a fixed child of MVM_HOME.
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/root");

        assert_eq!(mvm_cache_dir(), "/custom/root/cache");
        assert_eq!(mvm_config_dir(), "/custom/root/config");
        assert_eq!(mvm_runtime_dir(), "/custom/root/run");
        assert_eq!(mvm_state_dir(), "/custom/root/state");
        assert_eq!(mvm_share_dir(), "/custom/root/share");
        assert_eq!(mvm_deps_volumes_dir(), "/custom/root/volumes/deps");
        assert_eq!(vms_dir(), std::path::PathBuf::from("/custom/root/vms"));
    }

    #[test]
    fn test_default_mvm_cache_dir_ignores_override() {
        // Seeding expensive artifacts from the host's shared cache needs
        // the *default* root even when MVM_HOME points at a tempdir.
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/root");
        env.set("HOME", "/home/user");
        assert_eq!(default_mvm_cache_dir(), "/home/user/.mvm/cache");
        assert_ne!(default_mvm_cache_dir(), mvm_cache_dir());
    }

    #[test]
    fn test_mvm_home_strict_honors_override() {
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/data");
        assert_eq!(
            mvm_home_strict().unwrap(),
            std::path::PathBuf::from("/custom/data")
        );
        env.remove("MVM_HOME");
    }

    #[test]
    fn pool_dirs_live_under_mvm_home() {
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/data");
        assert_eq!(
            mvm_pool_dir().unwrap(),
            std::path::PathBuf::from("/custom/data/pool")
        );
        assert_eq!(
            pool_standby_dir("standby-abc").unwrap(),
            std::path::PathBuf::from("/custom/data/pool/standby-abc")
        );
        env.remove("MVM_HOME");
    }

    #[test]
    fn test_mvm_home_strict_errs_without_home_or_override() {
        // The security contract: secrets/bundles/trust-store callers must
        // never get a silent /tmp fallback. With neither MVM_HOME nor
        // $HOME set, the strict resolver errors (unlike infallible
        // mvm_home(), which returns /tmp/.mvm).
        let mut env = TestEnv::new();
        env.remove("MVM_HOME");
        env.remove("HOME");
        let res = mvm_home_strict();
        assert!(res.is_err());
    }

    #[test]
    fn subtree_accessors_default_under_home_dot_mvm() {
        let mut env = TestEnv::new();
        env.remove("MVM_HOME");
        env.set("HOME", "/home/user");
        assert_eq!(mvm_cache_dir(), "/home/user/.mvm/cache");
        assert_eq!(mvm_config_dir(), "/home/user/.mvm/config");
        assert_eq!(mvm_runtime_dir(), "/home/user/.mvm/run");
        assert_eq!(mvm_state_dir(), "/home/user/.mvm/state");
        assert_eq!(mvm_share_dir(), "/home/user/.mvm/share");
        assert_eq!(vms_dir(), std::path::PathBuf::from("/home/user/.mvm/vms"));
    }

    /// `ensure_home_dir` / `ensure_cache_dir` create their
    /// directories with mode 0700, AND chmod existing dirs
    /// with looser perms down to 0700 — that's the upgrade path
    /// for hosts created before this change landed.
    #[cfg(unix)]
    #[test]
    fn test_ensure_private_dir_locks_existing_loose_perms() {
        use std::os::unix::fs::PermissionsExt as _;

        // Pick a stable temp path; tests share env-var state so we
        // serialise via a unique-id suffix.
        let temp = format!(
            "/tmp/mvm-private-dir-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        std::fs::create_dir_all(&temp).expect("create temp");
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
            .expect("loosen for setup");

        ensure_private_dir(&temp).expect("ensure_private_dir");

        let mode = std::fs::metadata(&temp)
            .expect("temp exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got 0{:o}", mode);

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn checkpoints_dir_is_under_data_dir() {
        let mut env = TestEnv::new();
        let temp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", temp.path());
        let dir = checkpoints_dir();
        assert_eq!(dir, temp.path().join("checkpoints"));
        env.remove("MVM_HOME");
    }

    #[test]
    fn audit_root_path_is_sibling_of_chain() {
        let mut env = TestEnv::new();
        let temp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", temp.path());
        // The published root sits next to the `<tenant>.jsonl` chain it covers.
        assert_eq!(
            audit_root_path("local"),
            temp.path().join("audit").join("local.root.json")
        );
        assert_eq!(
            audit_root_path("local").parent(),
            mvm_audit_dir().to_str().map(std::path::Path::new)
        );
        env.remove("MVM_HOME");
    }

    #[test]
    fn vm_state_paths_honor_data_dir_and_share_one_source() {
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/data");

        // Per-VM dir + sockets derive from MVM_HOME; the inline
        // `$HOME/.mvm/vms/...` derivations this centralizes silently ignored
        // it, so parallel sessions collided despite setting it.
        assert_eq!(
            vm_state_dir("foo"),
            std::path::PathBuf::from("/custom/data/vms/foo")
        );
        assert_eq!(
            vm_vsock_port_socket("foo", 5252),
            std::path::PathBuf::from("/custom/data/vms/foo/vsock-5252.sock")
        );
        assert_eq!(
            vm_vsock_proxy_socket("foo"),
            std::path::PathBuf::from("/custom/data/vms/foo/vsock.sock")
        );
        // HVF nests its per-port listener under a `vsock/` subdir; the console
        // HvfVsockTransport must derive the same path so they can't drift.
        assert_eq!(
            vm_hvf_vsock_port_socket("foo", 5252),
            std::path::PathBuf::from("/custom/data/vms/foo/vsock/vsock-5252.sock")
        );
        assert_eq!(
            vm_hvf_vsock_port_socket_at(&vm_state_dir("foo"), 5252),
            vm_hvf_vsock_port_socket("foo", 5252)
        );
        // The dev-VM connect resolver (mvm-backend) and the console transport
        // (mvm) both build the libkrun socket from the shared socket-dir +
        // filename helper, so they cannot drift again.
        assert_eq!(
            vm_socket_dir("foo").join(vsock_socket_filename(5252)),
            vm_vsock_port_socket("foo", 5252)
        );
        assert_eq!(
            vm_vsock_port_socket_at(&vm_state_dir("foo"), 5252),
            vm_vsock_port_socket("foo", 5252)
        );
        // The hvf VMM's substitution-endpoint socket sits at the state-dir
        // root (the device bridges to it directly) and honors MVM_HOME.
        assert_eq!(
            vm_substitution_endpoint_socket("foo"),
            std::path::PathBuf::from("/custom/data/vms/foo/substitution-endpoint.sock")
        );
        // Same shape for the hvf VMM's per-VM BROKER_PORT socket.
        assert_eq!(
            vm_hvf_broker_socket("foo"),
            std::path::PathBuf::from("/custom/data/vms/foo/hvf-broker.sock")
        );
        // The hvf agent-RPC bridge: the detached supervisor binds it and the host
        // resolver probes it, so the name-based and state-dir-based accessors must
        // resolve to ONE socket or the guest agent goes unreachable.
        assert_eq!(
            vm_hvf_agent_socket("foo"),
            std::path::PathBuf::from("/custom/data/vms/foo/hvf-agent.sock")
        );
        assert_eq!(
            vm_hvf_agent_socket_at(&vm_state_dir("foo")),
            vm_hvf_agent_socket("foo")
        );

        env.remove("MVM_HOME");
    }

    #[test]
    fn long_vm_socket_paths_fall_back_to_short_tmp_namespace() {
        let mut env = TestEnv::new();
        env.set(
            "MVM_HOME",
            "/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-interactive-oci-dev-console/.mvm-test",
        );

        let state_dir = vm_state_dir("sunny-badger-e546");
        let socket_dir = vm_socket_dir("sunny-badger-e546");
        assert_ne!(socket_dir, state_dir, "long worktree paths must shorten");
        assert!(
            socket_dir.starts_with(SHORT_VM_SOCKET_ROOT),
            "short socket dir should live under {SHORT_VM_SOCKET_ROOT}: {}",
            socket_dir.display()
        );

        let substitution = vm_substitution_endpoint_socket("sunny-badger-e546");
        let agent = vm_inhouse_agent_socket_at(&state_dir);
        let hvf_agent = vm_hvf_agent_socket("sunny-badger-e546");
        let broker = vm_hvf_broker_socket("sunny-badger-e546");
        let libkrun = vm_vsock_port_socket_at(&state_dir, 5252);
        let console = vm_hvf_vsock_port_socket_at(&state_dir, 20001);

        for path in [
            &substitution,
            &agent,
            &hvf_agent,
            &broker,
            &libkrun,
            &console,
        ] {
            assert!(
                fits_unix_socket_path(path),
                "socket path must fit AF_UNIX budget ({} bytes): {}",
                unix_socket_path_len(path),
                path.display()
            );
        }

        env.remove("MVM_HOME");
    }

    #[test]
    fn machine_state_paths_honor_data_dir() {
        let mut env = TestEnv::new();
        env.set("MVM_HOME", "/custom/data");

        assert_eq!(
            machine_state_root(),
            std::path::PathBuf::from("/custom/data/machines")
        );
        assert_eq!(
            machine_state_dir("web"),
            std::path::PathBuf::from("/custom/data/machines/web")
        );
        assert_eq!(
            machine_spec_path("web"),
            std::path::PathBuf::from("/custom/data/machines/web/machine.json")
        );

        env.remove("MVM_HOME");
    }
}
