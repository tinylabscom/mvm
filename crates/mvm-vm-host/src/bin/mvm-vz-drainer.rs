//! Per-VM Vz drainer binary.
//!
//! Closes the Vz flow-audit carve-out: binds the
//! `events_ingest_socket_path` (Swift `mvm-vz-supervisor`'s NDJSON
//! `FlowEventWire` output socket), reads
//! NDJSON lines, and threads the events through the same
//! chain-signing audit pipeline that `mvm-libkrun-supervisor` uses
//! for the libkrun path.
//!
//! Reads a [`DrainerConfig`] JSON document on stdin, constructs a
//! `BridgeConfig` + `BridgeEndpoints::VzIngest`, then calls
//! `mvm_hostd::supervisor::gateway_bridge::spawn_bridge_thread`. The bridge
//! thread internally builds its own tokio current-thread runtime, so
//! this binary does not pull tokio as a direct dep — the
//! `mvm-supervisor` crate already carries it transitively.
//!
//! Spawned by `mvm-backend::vz::start()` between the host
//! gvproxy `spawn_detached` step and the Vz VM boot. The parent owns
//! an `AttachedDrainerGuard` that kills this process on early
//! return / panic / VM teardown.
//!
//! ## Trust model
//!
//! The drainer's stdin contract is identical to
//! `mvm-libkrun-supervisor`'s `SupervisorConfig` contract: the
//! producer (`mvm-backend`) is trusted and has already verified the
//! signed plan envelope via `mvm-cli`'s `admit_for_run` path before
//! launch. `plan_json` carries a `SignedExecutionPlan` envelope;
//! `decode_plan_json` unwraps it with `plan_from_admitted_json`, which
//! accepts both the signed envelope shape and the bare `ExecutionPlan`
//! shape (the on-disk form used by lifecycle verbs). No re-verification
//! of the Ed25519 signature: the host verified it at admission, and the
//! host is in the TCB. Re-verification here would require the
//! host-signer state managed by `mvm-cli`, which the drainer cannot
//! reach without introducing a dep cycle (`mvm-cli → mvm-supervisor →
//! mvm-cli`). This matches the `secrets_from_signed_json` and
//! `redaction_from_signed_json` helpers used on every other backend path.
//!
//! ## Capability profile
//!
//! Vz leaves report `payload_tap: false`. The
//! Swift bridge emits flow-open / flow-close events but does not
//! tap packet bytes; observers requiring `payload_tap` capability
//! refuse at `Pipeline::observe` time with
//! `BuildError::CapabilityMismatch`. A future plan extends Swift
//! the Rust `SupervisorConfig` to close that gap.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::SigningKey;
use mvm_core::plan::{ExecutionPlan, plan_from_admitted_json};
use mvm_core::policy::PolicyBundle;
use mvm_hostd::supervisor::audit::AuditSigner;
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
use mvm_hostd::supervisor::gateway_bridge::{
    BridgeConfig, BridgeEndpoints, spawn_bridge_thread,
};
use mvm_hostd::supervisor::network::{ObserverAllowlist, ProviderCapabilities, from_admitted};
use serde::Deserialize;

/// Stdin JSON contract. Producer is `mvm-backend::vz::start()`.
/// All paths are absolute and already-canonicalised by the parent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainerConfig {
    /// VM name; used to label the bridge thread + the audit chain
    /// `vm` field.
    vm_name: String,

    /// `~/.mvm/audit/` — destination of the chain-signed JSONL log
    /// that `FileAuditSigner` appends to. Shared with sibling VMs;
    /// the cross-process flock inside `FileAuditSigner` serialises
    /// writes per tenant.
    audit_dir: PathBuf,

    /// `~/.mvm/audit/gateway-<vm>.sock` — subscriber socket the
    /// bridge binds at startup so `nc -U <path>` consumers see the
    /// live NDJSON flow-event tail. Same shape as the libkrun path.
    audit_socket: PathBuf,

    /// `~/.mvm/keys/host-signer.ed25519` — mode 0600 file owned by
    /// the calling user. The drainer re-reads it on each launch to
    /// seed the `FileAuditSigner`'s `SigningKey`.
    signing_key_path: PathBuf,

    /// Path the Swift `mvm-vz-supervisor` writes its NDJSON
    /// `FlowEventWire` stream to. The drainer binds this socket
    /// (mode 0700) and reads from each accepted connection.
    events_socket_path: PathBuf,

    /// Serialised `SignedExecutionPlan` envelope as produced by
    /// `mvm-cli::plan_admission::populate_audit_substrate`.
    /// `decode_plan_json` unwraps it via `plan_from_admitted_json` —
    /// see "Trust model" in the module doc for the signature-skip rationale.
    plan_json: String,

    /// Optional serialised `PolicyBundle` (the resolved bundle pin
    /// rather than the bundle archive itself; the bridge uses it
    /// to label flow-event audit entries with the bundle digest).
    #[serde(default)]
    bundle_json: Option<String>,
}

fn main() -> ExitCode {
    // Stderr-only tracing keeps stdout clean for any future protocol
    // (the parent reads stdin only; we are not expected to print to
    // stdout). Same posture as `mvm-libkrun-supervisor`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "mvm-vz-drainer exiting with error");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut json = String::new();
    std::io::stdin()
        .read_to_string(&mut json)
        .context("read DrainerConfig from stdin")?;
    let cfg: DrainerConfig = serde_json::from_str(&json).context("parse DrainerConfig JSON")?;

    let plan = decode_plan_json(&cfg.plan_json)
        .context("decode DrainerConfig.plan_json into ExecutionPlan")?;

    let bundle: Option<PolicyBundle> = match &cfg.bundle_json {
        Some(s) => Some(
            serde_json::from_str(s)
                .context("decode DrainerConfig.bundle_json into PolicyBundle")?,
        ),
        None => None,
    };

    // Re-read the host signer secret bytes. The file is mode 0600
    // and was written by `mvm-cli::host_signer::load_or_init_at` at
    // admit time; the drainer trusts the path produced by the
    // parent. Refusing on length mismatch is the same defensive
    // posture the libkrun supervisor takes.
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

    // `FileAuditSigner` wraps the per-tenant cross-process flock
    // so concurrent supervisors for the same tenant serialise their
    // chain-signing writes safely.
    let file_signer = FileAuditSigner::open(signing_key, &cfg.audit_dir)
        .with_context(|| format!("open FileAuditSigner at {}", cfg.audit_dir.display()))?;
    let signer: Arc<dyn AuditSigner> = Arc::new(file_signer);

    // Observer chain from admitted plan + host allowlist. Vz leaves
    // report `payload_tap: false`. Observers that require payload tap
    // refuse via `BuildError::CapabilityMismatch` at the
    // `from_admitted` call below.
    let leaf_caps = ProviderCapabilities {
        flow_events: true,
        payload_tap: false,
    };
    let allowlist = ObserverAllowlist::load_from_host_config()
        .map_err(|e| anyhow!("load ObserverAllowlist from ~/.mvm/observers/allowlist.toml: {e}"))?;
    let observers = from_admitted(&plan, leaf_caps, &allowlist)
        .map_err(|e| anyhow!("resolve observer chain from admitted plan: {e}"))?;

    tracing::info!(
        vm = %cfg.vm_name,
        tenant = %plan.tenant.0,
        audit_socket = %cfg.audit_socket.display(),
        audit_dir = %cfg.audit_dir.display(),
        events_socket = %cfg.events_socket_path.display(),
        observers = observers.len(),
        "starting mvm-vz-drainer; binding Swift NDJSON FlowEventWire socket"
    );

    let bridge_cfg = BridgeConfig {
        vm_name: cfg.vm_name.clone(),
        plan: Arc::new(plan),
        bundle: bundle.map(Arc::new),
        audit_socket: cfg.audit_socket,
        signer,
        observers,
        // Bare-policy is not threaded for the legacy Vz NDJSON drainer (a
        // non-primary path; the live Vz workload runs the in-process VzGvproxy
        // bridge). This is safe: when a bundle is absent, run_bridge_inner's
        // no-bundle arm fails CLOSED to deny-all, so a bundle-less drainer run
        // cannot open egress.
        network_policy: None,
    };

    let endpoints = BridgeEndpoints::VzIngest {
        events_socket_path: cfg.events_socket_path,
    };

    // Bridge thread JoinHandle is intentionally dropped. The parent
    // (`mvm-backend::vz`) holds an `AttachedDrainerGuard` that
    // kills this process on early return / panic / VM teardown;
    // the bridge's own `catch_unwind → exit(1)` is the fail-closed
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

/// Decode a `plan_json` string into an `ExecutionPlan`.
///
/// Accepts both the `SignedExecutionPlan` envelope shape (what
/// `populate_audit_substrate` threads in, serialised from
/// `admitted.signed`) and the bare `ExecutionPlan` shape (the on-disk
/// form written by lifecycle verbs). The signature is not re-verified:
/// the host checked it at admission; the host is in the TCB. This is
/// the same trust posture as `plan_from_admitted_json`, the shared
/// helper used by the Firecracker bridge and QEMU paths.
pub(crate) fn decode_plan_json(plan_json: &str) -> Result<ExecutionPlan, serde_json::Error> {
    plan_from_admitted_json(plan_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::signing::{sign_plan, test_support::sample_plan};

    fn test_key() -> SigningKey {
        // Deterministic 32-byte key for tests — no OsRng dep.
        SigningKey::from_bytes(&[0xdd; 32])
    }

    #[test]
    fn decode_signed_envelope_yields_inner_plan() {
        let plan = sample_plan();
        let signed = sign_plan(&plan, &test_key(), "test-drainer-key");
        let json = serde_json::to_string(&signed).expect("signed plan serialises");

        let decoded = decode_plan_json(&json).expect("signed envelope decodes");
        assert_eq!(decoded.plan_id, plan.plan_id);
        assert_eq!(decoded.tenant, plan.tenant);
        assert_eq!(decoded.workload, plan.workload);
    }

    #[test]
    fn decode_bare_plan_still_works() {
        let plan = sample_plan();
        let json = serde_json::to_string(&plan).expect("bare plan serialises");

        let decoded = decode_plan_json(&json).expect("bare ExecutionPlan decodes");
        assert_eq!(decoded.plan_id, plan.plan_id);
    }

    #[test]
    fn decode_garbage_returns_err() {
        assert!(decode_plan_json("not json at all").is_err());
        assert!(decode_plan_json(r#"{"unknown_field": 42}"#).is_err());
    }
}
