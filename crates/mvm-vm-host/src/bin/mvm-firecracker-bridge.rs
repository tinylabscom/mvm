//! Per-VM Firecracker bridge sidecar.
//!
//! Linux-only process that runs alongside every Firecracker microVM
//! the host launches via `mvm-backend::firecracker`. Reads a
//! [`mvm_vm_host::firecracker_bridge::parse::BridgeConfigJson`] document from
//! stdin, verifies the operator-pinned `passt` binary hash, applies
//! `mvm-jailer-lite` confinement (seccomp + Landlock),
//! reconstructs the parent-inherited socketpair fds into a
//! [`BridgeEndpoints::Passt`] pair, and hands the packet loop to
//! `mvm_hostd::supervisor::gateway_bridge::spawn_bridge_thread`.
//!
//! Spawned by `FirecrackerBackend::start` between
//! the host passt `spawn_detached` step and the Firecracker VM boot.
//! The parent owns an `AttachedBridgeGuard` that kills this process on
//! early return / panic / VM teardown; the bridge's own `catch_unwind →
//! exit(1)` is the fail-closed signal for the claim-10 substrate.
//!
//! ## Trust model
//!
//! The bridge's stdin contract is identical to `mvm-vz-drainer`'s and
//! `mvm-libkrun-supervisor`'s: the producer (`FirecrackerBackend`) is
//! trusted and has already verified the
//! signed plan envelope via `mvm-cli`'s `admit_for_run` path before
//! launch. The bridge parses the plan JSON directly into an
//! [`ExecutionPlan`] without an additional envelope check — mirroring
//! `mvm-vz-drainer`'s and `mvm-libkrun-supervisor`'s pattern.
//! Re-verification of the plan envelope at
//! this leaf would require host signer state (`mvm-cli::host_signer`)
//! which the bridge cannot reach without closing a dependency cycle
//! (`mvm-cli → mvm-supervisor → mvm-cli`). The host is in-scope under
//! the trust model; the bridge runs in the same TCB as the supervisor.
//!
//! ## Parser surface
//!
//! `BridgeConfigJson`, `PasstHashesFile`, and `verify_passt_hash` live
//! in `mvm_vm_host::firecracker_bridge::parse` (the crate's `src/lib.rs` /
//! `src/parse.rs`). The `firecracker-bridge-fuzz` CI
//! lane drives `cargo fuzz` against those serde deserializers
//! directly via the crate's lib surface; the binary's `main()` uses
//! the same parser entry points so the fuzzed code path and the
//! production code path are byte-identical.
//!
//! ## File-descriptor inheritance contract
//!
//! `gateway_fd_raw` + `supervisor_fd_raw` in `BridgeConfigJson` are
//! raw fd numbers (`i32`) that name file descriptors already open in
//! this process's fd table. **Standard Rust `std::process::Command`
//! only inherits stdin/stdout/stderr;** `FirecrackerBackend`
//! honours the bridge contract via `CommandExt::pre_exec` — it
//! `dup2`s the socketpair fds into known raw positions, clears
//! `O_CLOEXEC` on each, and then `exec`s this binary. By the time
//! `main` runs, the fds are inheritied and owned by this process; the
//! bridge takes ownership via `OwnedFd::from_raw_fd` (the only
//! `unsafe` block in the file) and never duplicates them.
//!
//! ## Capability profile
//!
//! Firecracker leaves report
//! `payload_tap: true`. The bridge sits directly on the virtio-net
//! byte stream between the guest and host passt, so payload-tap
//! observers (a future SNI inspector / L7 MITM) can plug into the same
//! `FlowPolicy` seam libkrun uses today.

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, anyhow};
#[cfg(target_os = "linux")]
use ed25519_dalek::SigningKey;
#[cfg(target_os = "linux")]
use mvm_core::plan::ExecutionPlan;
#[cfg(target_os = "linux")]
use mvm_core::policy::PolicyBundle;
#[cfg(target_os = "linux")]
use mvm_hostd::jailer::{ConfinementSpec, confine_self};
#[cfg(target_os = "linux")]
use mvm_hostd::supervisor::audit::AuditSigner;
#[cfg(target_os = "linux")]
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
#[cfg(target_os = "linux")]
use mvm_hostd::supervisor::gateway_bridge::{BridgeConfig, BridgeEndpoints, spawn_bridge_thread};
#[cfg(target_os = "linux")]
use mvm_hostd::supervisor::network::{
    ObserverAllowlist, Pipeline, ProviderCapabilities, resolve_observer_chain_from_policy_source,
};
#[cfg(target_os = "linux")]
use mvm_hostd::supervisor::transcript_capture::TranscriptObserver;
#[cfg(target_os = "linux")]
use mvm_vm_host::firecracker_bridge::parse::{BridgeConfigJson, verify_passt_hash};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::process::ExitCode;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    // Stderr-only tracing keeps stdout clean for any future protocol
    // (the parent reads stdin only; we are not expected to print to
    // stdout). Same posture as `mvm-libkrun-supervisor` and
    // `mvm-vz-drainer`.
    // Default to quiet (errors only); honor RUST_LOG when set.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "mvm-firecracker-bridge exiting with error");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    // ── Step 1: read + parse stdin contract ─────────────────────────
    let mut json = String::new();
    std::io::stdin()
        .read_to_string(&mut json)
        .context("read BridgeConfigJson from stdin")?;
    let cfg: BridgeConfigJson = serde_json::from_str(&json).context("parse BridgeConfigJson")?;

    // ── Step 2: verify passt binary hash BEFORE confinement ─────────
    //
    // Landlock clamps reads to `cfg.passt_path` + `cfg.keys_dir`
    // after `confine_self`; if we ran the hash check after
    // confinement, a misconfigured `passt_hashes_path` would surface
    // as a confusing EACCES instead of "operator forgot to populate
    // the allowlist". Cardoso minimum-viable-policy: the operator-
    // pinned allowlist is the supply-chain gate; this is the right
    // place for it.
    verify_passt_hash(&cfg.passt_path, &cfg.passt_hashes_path)
        .context("verify passt binary hash against operator allowlist")?;

    // ── Step 3: apply mvm-jailer-lite confinement ───────────────────
    //
    // After this call, the process can only:
    //   * read from `cfg.passt_path` + `cfg.keys_dir`
    //   * read/write under `cfg.audit_dir`
    //   * invoke the allowlisted syscalls (see
    //     `mvm_hostd::jailer::seccomp::BRIDGE_SYSCALLS`)
    //
    // Per `confine_self`'s partial-confinement contract: any error
    // here MUST cause hard exit. We propagate up to `main()` which
    // turns the error into `ExitCode::FAILURE`; the parent's watchdog
    // sees the nonzero exit and tears down the VM.
    let spec = ConfinementSpec::firecracker_bridge(
        cfg.audit_dir.clone(),
        cfg.keys_dir.clone(),
        cfg.passt_path.clone(),
    );
    confine_self(&spec).context("apply mvm-jailer-lite confinement")?;

    // ── Step 4: parse trusted plan + bundle ─────────────────────────
    //
    // Trust model (see module doc): the producer (`FirecrackerBackend`)
    // has already verified the signed envelope
    // via `mvm-cli::admit_for_run`; we parse the inner ExecutionPlan
    // body directly.
    let plan: ExecutionPlan = serde_json::from_str(&cfg.plan_json)
        .context("decode BridgeConfigJson.plan_json into ExecutionPlan")?;
    let bundle: Option<PolicyBundle> = match &cfg.bundle_json {
        Some(s) => Some(
            serde_json::from_str(s)
                .context("decode BridgeConfigJson.bundle_json into PolicyBundle")?,
        ),
        None => None,
    };

    // ── Step 5: load host signer key + build FileAuditSigner ────────
    //
    // The file is mode 0600 and was written by `mvm-cli::host_signer::
    // load_or_init_at` at admit time. Landlock granted read on
    // `cfg.keys_dir`; this read succeeds inside the ruleset.
    let key_bytes = std::fs::read(&cfg.signing_key_path)
        .with_context(|| format!("read signing key {}", cfg.signing_key_path.display()))?;
    let key_array: [u8; 32] = key_bytes.as_slice().try_into().with_context(|| {
        format!(
            "signing key {} is {} bytes, expected 32",
            cfg.signing_key_path.display(),
            key_bytes.len()
        )
    })?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let file_signer = FileAuditSigner::open(signing_key, &cfg.audit_dir)
        .with_context(|| format!("open FileAuditSigner at {}", cfg.audit_dir.display()))?;
    let signer: Arc<dyn AuditSigner> = Arc::new(file_signer);

    // ── Step 6: resolve observer chain from admitted plan ───────────
    //
    // Observer chain from admitted plan + host allowlist. Firecracker
    // reports `payload_tap: true` so payload-tap observers admit at the
    // `from_admitted` gate.
    let leaf_caps = ProviderCapabilities {
        flow_events: true,
        payload_tap: true,
    };
    let observer_names = resolve_observer_chain_from_policy_source(&plan, bundle.as_ref())
        .map_err(|e| anyhow!("resolve observer chain from admitted policy source: {e}"))?;
    let mut observers = if observer_names.is_empty() {
        Vec::new()
    } else {
        let allowlist = ObserverAllowlist::load_from_host_config().map_err(|e| {
            anyhow!("load ObserverAllowlist from ~/.mvm/observers/allowlist.toml: {e}")
        })?;
        let mut pipe = Pipeline::new();
        for name in observer_names {
            let obs = allowlist
                .resolve(&name)
                .map_err(|e| anyhow!("resolve observer name in allowlist: {e}"))?;
            pipe = pipe
                .observe(obs, leaf_caps)
                .map_err(|e| anyhow!("observer capability gate: {e}"))?;
        }
        pipe.build_observers()
    };

    // A host-initiated forensic capture is not a tenant-policy
    // observer (it carries a per-capture key, so it's not in the no-arg
    // allowlist). When the producer armed one for this VM, add it directly. The
    // capture dir lives under `audit_dir`, already read/write inside the
    // Landlock ruleset; the host KEK under `keys_dir` is read-only there.
    if let Some(capture_dir) = &cfg.transcript_capture_dir {
        let obs = TranscriptObserver::activate(capture_dir, &cfg.keys_dir)
            .with_context(|| format!("activate transcript capture at {}", capture_dir.display()))?;
        observers.push(Arc::new(obs) as Arc<dyn mvm_hostd::supervisor::network::Observer>);
    }

    tracing::info!(
        vm = %cfg.vm_name,
        tenant = %plan.tenant.0,
        audit_socket = %cfg.audit_socket.display(),
        audit_dir = %cfg.audit_dir.display(),
        passt_path = %cfg.passt_path.display(),
        gateway_fd = cfg.gateway_fd_raw,
        supervisor_fd = cfg.supervisor_fd_raw,
        observers = observers.len(),
        "starting mvm-firecracker-bridge; reconstructing socketpair fds"
    );

    // ── Step 7: reconstruct parent-inherited fds + build endpoints ──
    //
    // SAFETY: the caller MUST guarantee that
    //   1. `cfg.gateway_fd_raw` and `cfg.supervisor_fd_raw` name
    //      valid, open file descriptors in this process's fd table,
    //   2. those fds were duped (or socketpair'd) by the parent
    //      before exec and inherited across exec with `O_CLOEXEC`
    //      cleared,
    //   3. no other code in this process holds owning references to
    //      those fds (ownership transfers to the returned `OwnedFd`).
    // `FirecrackerBackend` honours this via the
    // `CommandExt::pre_exec` dup2 + fcntl(FD_CLOEXEC clear) path
    // documented in its module header. There is no validation we
    // can perform on the host side (the kernel will EBADF on first
    // use if the fd is bad, which the bridge thread surfaces via
    // `tokio::io::copy_bidirectional` → exit(1)).
    let (gateway_fd, supervisor_fd) = unsafe {
        (
            OwnedFd::from_raw_fd(cfg.gateway_fd_raw),
            OwnedFd::from_raw_fd(cfg.supervisor_fd_raw),
        )
    };

    let bridge_cfg = BridgeConfig {
        vm_name: cfg.vm_name.clone(),
        plan: Arc::new(plan),
        bundle: bundle.map(Arc::new),
        audit_socket: cfg.audit_socket,
        signer,
        observers,
        // Firecracker's authoritative egress gate is the kernel nftables
        // `install_default_deny` chain at the FC start path (claim 10 leg 1);
        // this passt sidecar is the audit/observer + relay, not the enforcer.
        // So the bridge flow gate must DEFER (open) rather than double-gate —
        // `unrestricted` keeps the no-bundle arm flow-open. (A bundle, when
        // present, still drives the bundle path.) Using `None` would fail closed
        // to deny-all and over-block FC.
        network_policy: Some(mvm_core::network_policy::NetworkPolicy::unrestricted()),
        // Native rvproxy flow-audit follower is the libkrun path; Firecracker
        // uses passt + the nft moat, not a native rvproxy gateway.
        native_flow_audit_path: None,
    };

    let endpoints = BridgeEndpoints::Passt {
        gateway_fd,
        supervisor_fd,
    };

    // ── Step 8: spawn the bridge thread + park ──────────────────────
    //
    // JoinHandle is intentionally dropped. The parent
    // (`FirecrackerBackend`) holds an `AttachedBridgeGuard` that
    // kills this process on early return / panic / VM teardown; the
    // bridge's own `catch_unwind → exit(1)` is the fail-closed
    // signal for the claim-10 substrate.
    let _join = spawn_bridge_thread(endpoints, bridge_cfg);

    tracing::info!(vm = %cfg.vm_name, "bridge thread spawned; parking main thread");

    // Park indefinitely. The parent kills us via SIGTERM/SIGKILL on
    // VM shutdown; without a `park`, the bin would exit immediately
    // and the OS would reap the bridge thread before the first
    // FlowEvent arrives. A loop guards against spurious unparks.
    loop {
        std::thread::park();
    }
}

/// Non-Linux guard. Print a clear error and exit nonzero. This binary
/// is meaningless off Linux — `mvm-jailer-lite::confine_self` returns
/// `Err(SeccompUnavailable)` on macOS/Windows stubs, and the
/// `BridgeEndpoints::Passt` path requires Linux socketpair semantics
/// the macOS Firecracker port does not support. The cfg-gate keeps
/// workspace builds green on contributor hosts.
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "mvm-firecracker-bridge is a Linux-only sidecar; this binary \
         was built for a non-Linux target and refuses to run. The \
         Vz drainer (`mvm-vz-drainer`) is the macOS equivalent for the \
         gateway audit bridge."
    );
    std::process::ExitCode::FAILURE
}
