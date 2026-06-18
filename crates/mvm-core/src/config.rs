/// Default Firecracker version, overridable at build time via `MVM_FC_VERSION` env var.
pub const FC_VERSION_DEFAULT: &str = match option_env!("MVM_FC_VERSION") {
    Some(v) => v,
    None => "v1.14.1",
};

/// Host CPU architecture for arch-tagged downloads (the Firecracker release
/// binary, firecracker-ci kernel/rootfs). `std::env::consts::ARCH` is the arch
/// mvmctl was compiled for == the arch it runs on, so the downloaded binaries
/// match the host. (Was hardcoded `"aarch64"` — wrong on x86_64: `dev up`
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

/// Root data directory for mvm dev-tool state.
///
/// Resolution order:
///   1. `MVM_DATA_DIR` env var (explicit override)
///   2. `$HOME/.mvm`
///
/// This is a user-owned directory — no sudo required.
/// Fleet orchestration state (tenants, pools, instances) uses `/var/lib/mvm/`
/// and is managed by mvmd with appropriate permissions.
pub fn mvm_data_dir() -> String {
    if let Ok(d) = std::env::var("MVM_DATA_DIR")
        && !d.is_empty()
    {
        return d;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/.mvm", home)
}

/// Like [`mvm_data_dir`] but fails instead of silently falling back to
/// `/tmp` when neither `MVM_DATA_DIR` nor `$HOME` is set. Use this for
/// security-sensitive state — secrets, signed bundles, the trusted-
/// publisher store, per-tenant policy — that must never land in a
/// world-traversable `/tmp` just because `$HOME` happened to be unset.
/// Honors the `MVM_DATA_DIR` override so parallel sessions stay isolated
/// (the inline `$HOME/.mvm` derivations this replaces silently ignored it).
pub fn mvm_data_dir_strict() -> std::io::Result<std::path::PathBuf> {
    if let Ok(d) = std::env::var("MVM_DATA_DIR")
        && !d.is_empty()
    {
        return Ok(std::path::PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "$HOME unset and MVM_DATA_DIR not set; cannot locate ~/.mvm",
        )
    })?;
    Ok(std::path::PathBuf::from(home).join(".mvm"))
}

/// Create `~/.mvm` (or whatever `mvm_data_dir()` resolves to) with
/// mode `0700` and return its path. Idempotent: if the dir already
/// exists with looser perms, chmod it to `0700` so a host that was
/// created before this lockdown still gets locked down on the next
/// `dev up`.
///
/// `~/.mvm` holds the dev VM's GC root, the host-backed Nix store
/// disk image, the per-VM `vsock.sock` proxy listener path, build
/// artifacts in `dev/builds/<rev>/`, and (for production microVMs)
/// any persisted volumes — every secret-shaped piece of state in
/// the project. Defaulting to umask perms (typ. 0755) means a
/// same-host other user can read all of it; this is the project's
/// privacy boundary.
#[cfg(unix)]
pub fn ensure_data_dir() -> std::io::Result<String> {
    let dir = mvm_data_dir();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Create `~/.cache/mvm` (or wherever `mvm_cache_dir()` resolves to)
/// with mode `0700`. Same rationale as `ensure_data_dir`. The cache
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
// XDG-compliant directory functions
// ============================================================================

fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
}

/// Cache directory for build artifacts, images, VM runtime state.
///
/// Resolution order:
///   1. `MVM_CACHE_DIR` env var
///   2. `$XDG_CACHE_HOME/mvm`
///   3. `$HOME/.cache/mvm`
pub fn mvm_cache_dir() -> String {
    if let Ok(d) = std::env::var("MVM_CACHE_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.cache/mvm", home_dir())
}

/// Config directory for user configuration files.
///
/// Resolution order:
///   1. `MVM_CONFIG_DIR` env var
///   2. `$XDG_CONFIG_HOME/mvm`
///   3. `$HOME/.config/mvm`
pub fn mvm_config_dir() -> String {
    if let Ok(d) = std::env::var("MVM_CONFIG_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.config/mvm", home_dir())
}

/// Runtime directory for ephemeral per-session / per-call state.
///
/// Resolution order:
///   1. `MVM_RUNTIME_DIR` env var
///   2. `$XDG_RUNTIME_DIR/mvm`
///   3. `$HOME/.cache/mvm/runtime` (fallback when no XDG runtime dir;
///      not as good — survives reboots, slightly looser perms — but
///      works on macOS where systemd-style `XDG_RUNTIME_DIR` is rare)
///
/// Holds short-lived state like the session table at
/// `<runtime>/sessions/<id>.json`. By contract the dir is mode 0700;
/// entries within it are 0600 unless the writer explicitly relaxes
/// them.
pub fn mvm_runtime_dir() -> String {
    if let Ok(d) = std::env::var("MVM_RUNTIME_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.cache/mvm/runtime", home_dir())
}

/// Create the runtime dir 0700 and return its path. Idempotent.
#[cfg(unix)]
pub fn ensure_runtime_dir() -> std::io::Result<String> {
    let dir = mvm_runtime_dir();
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// State directory for logs and audit trails.
///
/// Resolution order:
///   1. `MVM_STATE_DIR` env var
///   2. `$XDG_STATE_HOME/mvm`
///   3. `$HOME/.local/state/mvm`
pub fn mvm_state_dir() -> String {
    if let Ok(d) = std::env::var("MVM_STATE_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.local/state/mvm", home_dir())
}

/// Share directory for templates, network definitions, and registries.
///
/// Resolution order:
///   1. `MVM_SHARE_DIR` env var
///   2. `$XDG_DATA_HOME/mvm`
///   3. `$HOME/.local/share/mvm`
pub fn mvm_share_dir() -> String {
    if let Ok(d) = std::env::var("MVM_SHARE_DIR")
        && !d.is_empty()
    {
        return d;
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME")
        && !xdg.is_empty()
    {
        return format!("{xdg}/mvm");
    }
    format!("{}/.local/share/mvm", home_dir())
}

/// Root directory for application-dependency volumes sealed by
/// `mvm_sdk::compile::deps_audit::seal_volume`. Each immediate child
/// is a `<volume_hash>/` directory containing `content/`,
/// `sbom.cdx.json`, `fetch.log`, `cve.json`, `meta.json`.
///
/// Resolution order:
///   1. `MVM_DEPS_VOLUMES_DIR` env var (test override)
///   2. `<mvm_data_dir()>/volumes/deps`
///
/// The supervisor's admission gate (security claim 9 — every
/// application-dep volume is hash-locked and audited) reads this
/// dir; `mvmctl build` writes to it.
pub fn mvm_deps_volumes_dir() -> String {
    if let Ok(d) = std::env::var("MVM_DEPS_VOLUMES_DIR")
        && !d.is_empty()
    {
        return d;
    }
    format!("{}/volumes/deps", mvm_data_dir())
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

// ============================================================================
// Per-VM host-side state paths
// ============================================================================
//
// Every per-VM artifact mvm writes on the host lives under
// `<mvm_data_dir>/vms/<name>/`. Build these paths ONLY through the helpers
// below: a single source of truth for the layout, and `MVM_DATA_DIR` is
// honored everywhere. The inline `$HOME/.mvm/vms/...` derivations these
// replace duplicated the convention — which let the libkrun vsock socket
// name drift between two resolvers — and silently ignored `MVM_DATA_DIR`,
// so parallel sessions collided despite setting it.

/// Per-VM state directory: `<mvm_data_dir>/vms/<name>/`. Holds the
/// libkrun pid file, console log, vsock listener socket(s), runtime
/// `mode.json`, `rootfs.ref` / `kernel.ref`, and the `ports` file.
pub fn vm_state_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir())
        .join("vms")
        .join(name)
}

// ============================================================================
// Persistent `mvmctl machine` specs
// ============================================================================
//
// Named machines are product-level state, not a VMM runtime directory. Keep
// their declarative spec under `<mvm_data_dir>/machines/<name>/` so runtime
// sockets/pids under `vms/` can be replaced without migrating the UX contract.

/// Root of persistent named machine specs: `<mvm_data_dir>/machines/`.
pub fn machine_state_root() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("machines")
}

/// Persistent named machine directory: `<mvm_data_dir>/machines/<name>/`.
pub fn machine_state_dir(name: &str) -> std::path::PathBuf {
    machine_state_root().join(name)
}

/// Persistent named machine spec: `<mvm_data_dir>/machines/<name>/machine.json`.
pub fn machine_spec_path(name: &str) -> std::path::PathBuf {
    machine_state_dir(name).join("machine.json")
}

/// Root of the per-tenant host-agent daemon dirs: `<mvm_data_dir>/host-agent`.
/// Each `<tenant>/` subdir holds one resident daemon's control UDS, pid file,
/// and spawn lock. Enumerated by `mvmctl doctor` to report daemon state.
pub fn host_agent_root() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("host-agent")
}

/// Per-tenant host-agent daemon directory: `<mvm_data_dir>/host-agent/<tenant>/`.
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

/// `<mvm_data_dir>/pool/` — the supervisor standby pool root.
/// Each idle standby gets a `pool/<id>/` subdir holding its control UDS +
/// `standby.json`. Uses the strict resolver so a missing `$HOME`/`MVM_DATA_DIR`
/// surfaces as an error rather than silently writing entitled processes' state to
/// `/tmp`.
pub fn mvm_pool_dir() -> std::io::Result<std::path::PathBuf> {
    Ok(mvm_data_dir_strict()?.join("pool"))
}

/// `<mvm_data_dir>/pool/<id>/` for a single standby.
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

/// libkrun's per-port vsock listener socket: `<vm_state_dir>/vsock-<port>.sock`.
/// libkrun's supervisor binds one socket per forwarded port, so a client
/// connects directly with no port handshake. This + [`vsock_socket_filename`]
/// are the single source of truth for the convention — every host-side
/// resolver (the console transport, the dev-VM connect path) must use them
/// so they cannot drift.
pub fn vm_vsock_port_socket(name: &str, port: u32) -> std::path::PathBuf {
    vm_state_dir(name).join(vsock_socket_filename(port))
}

/// The Apple-Container cross-process vsock proxy socket:
/// `<vm_state_dir>/vsock.sock`. The dev daemon listens here and
/// multiplexes ports via a 4-byte little-endian port prefix.
pub fn vm_vsock_proxy_socket(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("vsock.sock")
}

/// The directory the Vz supervisor nests its per-port vsock listener
/// sockets under: `<vm_state_dir>/vsock`. Unlike libkrun (which binds
/// `<vm_state_dir>/vsock-<port>.sock` directly), the Vz `VsockProxy`
/// listens inside this subdir. Single source of truth for the subdir so
/// `mvm-backend`'s supervisor config and the host-side `VzTransport`
/// can't drift.
pub fn vm_vz_vsock_dir(name: &str) -> std::path::PathBuf {
    vm_state_dir(name).join("vsock")
}

/// Vz's per-port vsock listener socket: `<vm_state_dir>/vsock/vsock-<port>.sock`.
/// The Vz supervisor listens here and forwards to the guest's vsock port, so a
/// host client connects directly with no port handshake (same shape as libkrun,
/// one subdir deeper). Pairs with [`vm_vz_vsock_dir`] + [`vsock_socket_filename`].
pub fn vm_vz_vsock_port_socket(name: &str, port: u32) -> std::path::PathBuf {
    vm_vz_vsock_dir(name).join(vsock_socket_filename(port))
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

// ============================================================================
// Sensitive ~/.mvm subdirectories
// ============================================================================
//
// Build these ONLY through the helpers below so they honor MVM_DATA_DIR and
// stay consistent across the diagnostics, signer, and audit paths. The
// inline `$HOME/.mvm/<sub>` derivations these replace ignored MVM_DATA_DIR.

/// Host signing keys (e.g. `host-signer.ed25519`): `<mvm_data_dir>/keys/`.
pub fn mvm_keys_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("keys")
}

/// Immutable checkpoint store: `<mvm_data_dir>/checkpoints/`. Each checkpoint is
/// a subdirectory `<id>/` holding `meta.json` + cloned `content/`.
pub fn checkpoints_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("checkpoints")
}

/// Chain-signed audit logs: `<mvm_data_dir>/audit/`.
pub fn mvm_audit_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("audit")
}

/// Filename suffix for a per-VM workload audit chain.
pub const WORKLOAD_AUDIT_SUFFIX: &str = ".workload.jsonl";

/// Per-VM workload audit-chain file:
/// `<mvm_data_dir>/audit/<tenant>.<vm>.workload.jsonl`.
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

/// Overlay receipts / destruction certificates: `<mvm_data_dir>/overlays/`.
pub fn mvm_overlays_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("overlays")
}

/// Secret-material staging: `<mvm_data_dir>/secrets/`.
pub fn mvm_secrets_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("secrets")
}

/// The long-lived host egress CA's home:
/// `<mvm_data_dir>/egress-ca/` (holds `ca.crt` + `ca.key`, key mode 0400).
/// The per-VM name-constrained intermediates the transparent `https`
/// terminator uses are minted under this CA; see `crypto::egress_ca`.
pub fn egress_ca_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("egress-ca")
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

    // Tests here mutate process-global env vars (`MVM_*`, `XDG_*_HOME`, `HOME`).
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

    // --- XDG directory tests ---

    #[test]
    fn test_mvm_cache_dir_env_override() {
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", "/custom/cache");
        assert_eq!(mvm_cache_dir(), "/custom/cache");
        env.remove("MVM_CACHE_DIR");
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
    fn test_mvm_cache_dir_xdg_override() {
        let mut env = TestEnv::new();
        env.remove("MVM_CACHE_DIR");
        env.set("XDG_CACHE_HOME", "/xdg/cache");
        assert_eq!(mvm_cache_dir(), "/xdg/cache/mvm");
        env.remove("XDG_CACHE_HOME");
    }

    #[test]
    fn test_mvm_cache_dir_default() {
        let mut env = TestEnv::new();
        env.remove("MVM_CACHE_DIR");
        env.remove("XDG_CACHE_HOME");
        let dir = mvm_cache_dir();
        assert!(dir.ends_with("/.cache/mvm"));
    }

    #[test]
    fn test_mvm_data_dir_strict_honors_override() {
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", "/custom/data");
        assert_eq!(
            mvm_data_dir_strict().unwrap(),
            std::path::PathBuf::from("/custom/data")
        );
        env.remove("MVM_DATA_DIR");
    }

    #[test]
    fn pool_dirs_live_under_mvm_data_dir() {
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", "/custom/data");
        assert_eq!(
            mvm_pool_dir().unwrap(),
            std::path::PathBuf::from("/custom/data/pool")
        );
        assert_eq!(
            pool_standby_dir("standby-abc").unwrap(),
            std::path::PathBuf::from("/custom/data/pool/standby-abc")
        );
        env.remove("MVM_DATA_DIR");
    }

    #[test]
    fn test_mvm_data_dir_strict_errs_without_home_or_override() {
        // The security contract: secrets/bundles/trust-store callers must
        // never get a silent /tmp fallback. With neither MVM_DATA_DIR nor
        // $HOME set, the strict resolver errors (unlike infallible
        // mvm_data_dir(), which returns /tmp/.mvm).
        let mut env = TestEnv::new();
        env.remove("MVM_DATA_DIR");
        env.remove("HOME");
        let res = mvm_data_dir_strict();
        assert!(res.is_err());
    }

    #[test]
    fn test_mvm_config_dir_env_override() {
        let mut env = TestEnv::new();
        env.set("MVM_CONFIG_DIR", "/custom/config");
        assert_eq!(mvm_config_dir(), "/custom/config");
        env.remove("MVM_CONFIG_DIR");
    }

    #[test]
    fn test_mvm_config_dir_default() {
        let mut env = TestEnv::new();
        env.remove("MVM_CONFIG_DIR");
        env.remove("XDG_CONFIG_HOME");
        let dir = mvm_config_dir();
        assert!(dir.ends_with("/.config/mvm"));
    }

    #[test]
    fn test_mvm_state_dir_env_override() {
        let mut env = TestEnv::new();
        env.set("MVM_STATE_DIR", "/custom/state");
        assert_eq!(mvm_state_dir(), "/custom/state");
        env.remove("MVM_STATE_DIR");
    }

    #[test]
    fn test_mvm_state_dir_default() {
        let mut env = TestEnv::new();
        env.remove("MVM_STATE_DIR");
        env.remove("XDG_STATE_HOME");
        let dir = mvm_state_dir();
        assert!(dir.ends_with("/.local/state/mvm"));
    }

    #[test]
    fn test_mvm_share_dir_env_override() {
        let mut env = TestEnv::new();
        env.set("MVM_SHARE_DIR", "/custom/share");
        assert_eq!(mvm_share_dir(), "/custom/share");
        env.remove("MVM_SHARE_DIR");
    }

    #[test]
    fn test_mvm_share_dir_default() {
        let mut env = TestEnv::new();
        env.remove("MVM_SHARE_DIR");
        env.remove("XDG_DATA_HOME");
        let dir = mvm_share_dir();
        assert!(dir.ends_with("/.local/share/mvm"));
    }

    #[test]
    fn test_mvm_share_dir_xdg_override() {
        let mut env = TestEnv::new();
        env.remove("MVM_SHARE_DIR");
        env.set("XDG_DATA_HOME", "/xdg/data");
        assert_eq!(mvm_share_dir(), "/xdg/data/mvm");
        env.remove("XDG_DATA_HOME");
    }

    /// `ensure_data_dir` / `ensure_cache_dir` create their
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
        env.set("MVM_DATA_DIR", temp.path());
        let dir = checkpoints_dir();
        assert_eq!(dir, temp.path().join("checkpoints"));
        env.remove("MVM_DATA_DIR");
    }

    #[test]
    fn vm_state_paths_honor_data_dir_and_share_one_source() {
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", "/custom/data");

        // Per-VM dir + sockets derive from MVM_DATA_DIR; the inline
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
        // Vz nests its per-port listener under a `vsock/` subdir (vz.rs
        // builds `<state_dir>/vsock`); the console VzTransport must derive
        // the same path so they can't drift.
        assert_eq!(
            vm_vz_vsock_port_socket("foo", 5252),
            std::path::PathBuf::from("/custom/data/vms/foo/vsock/vsock-5252.sock")
        );
        assert_eq!(
            vm_vz_vsock_dir("foo").join(vsock_socket_filename(5252)),
            vm_vz_vsock_port_socket("foo", 5252)
        );
        // The dev-VM connect resolver (mvm-backend) and the console transport
        // (mvm) both build the libkrun socket as state-dir + shared filename,
        // so they cannot drift again.
        assert_eq!(
            vm_state_dir("foo").join(vsock_socket_filename(5252)),
            vm_vsock_port_socket("foo", 5252)
        );

        env.remove("MVM_DATA_DIR");
    }

    #[test]
    fn machine_state_paths_honor_data_dir() {
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", "/custom/data");

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

        env.remove("MVM_DATA_DIR");
    }
}
