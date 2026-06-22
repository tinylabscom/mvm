//! Shared per-VM bridge sidecar (ADR-094 / Plan 209).
//!
//! One sidecar binary for every backend. Reads a single
//! [`mvm_vm_host::bridge::parse::BridgeConfigJson`] document on stdin and
//! dispatches on its [`BridgeEndpointKind`] discriminant to build the matching
//! `mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints` variant, then hands
//! the packet/flow loop to the unchanged
//! `mvm_hostd::supervisor::gateway_bridge::spawn_bridge_thread`. Folds the
//! former `mvm-firecracker-bridge` (Passt) and `mvm-vz-drainer` (VzIngest) into
//! one — the contract the source already described as "identical across all
//! three".
//!
//! Spawned by the active backend (`mvm-backend::microvm` Firecracker /
//! `::vz` / `::libkrun` after Plan 209 Task 3) with an RAII teardown guard
//! (`AttachedBridgeGuard` / `AttachedDrainerGuard`) that kills this process on
//! early return / panic / VM teardown; the bridge's own `catch_unwind →
//! exit(1)` is the fail-closed signal for the claim-10 substrate.
//!
//! ## Cross-platform / confinement
//!
//! Unlike the old `mvm-firecracker-bridge` (whole-binary Linux gate), this
//! binary is cross-platform: the `Passt` endpoint is Linux-only (socketpair +
//! passt + `mvm-jailer-lite` confinement), while `VzIngest` is macOS (the
//! Swift Vz supervisor's NDJSON stream). `confine_self` (Landlock + seccomp) is
//! **Linux-only** — on macOS it is a hard-erroring stub because the OS has no
//! kernel LSM — so confinement is applied per-arm where the OS supports it; the
//! macOS paths run unconfined, exactly as the vz drainer did.
//!
//! ## Trust model
//!
//! Identical to the bins it replaces: the producer (the backend) is trusted and
//! has already verified the signed plan envelope via `mvm-cli`'s
//! `admit_for_run` path before launch. `plan_json` carries the
//! `SignedExecutionPlan` envelope; `decode_plan_json` extracts the inner
//! `ExecutionPlan` without re-verifying the Ed25519 signature (the host checked
//! it at admit time and is in the TCB; re-verification here would require host
//! signer state the sidecar cannot reach without a dep cycle).

use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mvm_core::policy::PolicyBundle;
use mvm_hostd::supervisor::audit::AuditSigner;
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
use mvm_hostd::supervisor::gateway_bridge::{BridgeConfig, BridgeEndpoints, spawn_bridge_thread};
use mvm_hostd::supervisor::network::{
    ObserverAllowlist, Pipeline, ProviderCapabilities, resolve_observer_chain_from_policy_source,
};
use mvm_vm_host::bridge::parse::{
    BridgeConfigJson, BridgeEndpointKind, decode_network_policy, decode_plan_json,
};

fn main() -> ExitCode {
    // Stderr-only tracing keeps stdout clean (the parent reads stdin only).
    // Default to quiet (errors only); honor RUST_LOG when set. Same posture as
    // the bins this replaces.
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
            tracing::error!(error = %format!("{e:#}"), "mvm-bridge exiting with error");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    // ── Step 1: read + parse the unified stdin contract ─────────────
    let mut json = String::new();
    std::io::stdin()
        .read_to_string(&mut json)
        .context("read BridgeConfigJson from stdin")?;
    let cfg: BridgeConfigJson = serde_json::from_str(&json).context("parse BridgeConfigJson")?;

    // ── Step 2: refuse an endpoint the host OS cannot serve ─────────
    check_endpoint_platform(&cfg.endpoint)?;

    // ── Step 3: passt hash verify BEFORE confinement (Passt only) ───
    //
    // Landlock clamps reads after `confine_self`; verifying the operator-pinned
    // passt allowlist first keeps a misconfigured allowlist surfacing as a clear
    // error instead of a confusing EACCES. Cardoso minimum-viable-policy gate.
    #[cfg(target_os = "linux")]
    if let BridgeEndpointKind::Passt {
        passt_path,
        passt_hashes_path,
        ..
    } = &cfg.endpoint
    {
        mvm_vm_host::bridge::parse::verify_passt_hash(passt_path, passt_hashes_path)
            .context("verify passt binary hash against operator allowlist")?;
    }

    // ── Step 4: apply mvm-jailer-lite confinement where supported ───
    //
    // Linux-only: `confine_self` is Landlock+seccomp. On macOS it is a
    // hard-erroring stub (no kernel LSM), so the macOS arms (VzIngest, and
    // libkrun-gvproxy on macOS) run unconfined exactly as the vz drainer did.
    // Per the partial-confinement contract, any error here is a hard exit.
    #[cfg(target_os = "linux")]
    confine_for_endpoint(&cfg)?;

    // ── Step 5: decode the trusted plan + bundle + egress policy ────
    let plan = decode_plan_json(&cfg.plan_json).context("decode BridgeConfigJson.plan_json")?;
    let bundle: Option<PolicyBundle> = match &cfg.bundle_json {
        Some(s) => Some(
            serde_json::from_str(s)
                .context("decode BridgeConfigJson.bundle_json into PolicyBundle")?,
        ),
        None => None,
    };
    let network_policy = decode_network_policy(&cfg)?;

    // ── Step 6: load host signer key + build FileAuditSigner ────────
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

    // ── Step 7: resolve observer chain (leaf caps per endpoint) ─────
    let leaf_caps = leaf_caps_for(&cfg.endpoint);
    let observer_names = resolve_observer_chain_from_policy_source(&plan, bundle.as_ref())
        .map_err(|e| anyhow::anyhow!("resolve observer chain from admitted policy source: {e}"))?;
    let observers = if observer_names.is_empty() {
        Vec::new()
    } else {
        let allowlist = ObserverAllowlist::load_from_host_config().map_err(|e| {
            anyhow::anyhow!("load ObserverAllowlist from ~/.mvm/observers/allowlist.toml: {e}")
        })?;
        let mut pipe = Pipeline::new();
        for name in observer_names {
            let obs = allowlist
                .resolve(&name)
                .map_err(|e| anyhow::anyhow!("resolve observer name in allowlist: {e}"))?;
            pipe = pipe
                .observe(obs, leaf_caps)
                .map_err(|e| anyhow::anyhow!("observer capability gate: {e}"))?;
        }
        pipe.build_observers()
    };

    tracing::info!(
        vm = %cfg.vm_name,
        tenant = %plan.tenant.0,
        endpoint = endpoint_label(&cfg.endpoint),
        audit_socket = %cfg.audit_socket.display(),
        observers = observers.len(),
        "starting mvm-bridge"
    );

    let bridge_cfg = BridgeConfig {
        vm_name: cfg.vm_name.clone(),
        plan: Arc::new(plan),
        bundle: bundle.map(Arc::new),
        audit_socket: cfg.audit_socket.clone(),
        signer,
        observers,
        network_policy,
        // The native rvproxy flow-audit follower is the libkrun-native-gateway
        // path; it is wired when libkrun moves onto this sidecar (Plan 209
        // Task 3). FC + vz do not run a native rvproxy gateway.
        native_flow_audit_path: None,
    };

    // ── Step 8: build the backend endpoint + spawn the bridge ───────
    let endpoints = build_endpoints(&cfg)?;

    // JoinHandle intentionally dropped: the parent's RAII guard kills this
    // process on teardown; the bridge's own `catch_unwind → exit(1)` is the
    // fail-closed signal.
    let _join = spawn_bridge_thread(endpoints, bridge_cfg);

    tracing::info!(vm = %cfg.vm_name, "bridge thread spawned; parking main thread");

    // Park indefinitely. The parent kills us via SIGTERM/SIGKILL on VM
    // shutdown; without a park the bin would exit and the OS would reap the
    // bridge thread before the first event.
    loop {
        std::thread::park();
    }
}

/// Observer leaf capabilities by endpoint. Passt and the in-process gvproxy
/// shuffle sit directly on the byte stream (`payload_tap: true`); the Vz Swift
/// ingest path sees only flow-open/close events (`payload_tap: false`), so
/// payload-tap observers refuse at the capability gate. Pure — unit-tested.
fn leaf_caps_for(kind: &BridgeEndpointKind) -> ProviderCapabilities {
    match kind {
        BridgeEndpointKind::Passt { .. } | BridgeEndpointKind::LibkrunGvproxy { .. } => {
            ProviderCapabilities {
                flow_events: true,
                payload_tap: true,
            }
        }
        BridgeEndpointKind::VzIngest { .. } => ProviderCapabilities {
            flow_events: true,
            payload_tap: false,
        },
    }
}

/// Stable label for tracing/tests. Pure.
fn endpoint_label(kind: &BridgeEndpointKind) -> &'static str {
    match kind {
        BridgeEndpointKind::Passt { .. } => "passt",
        BridgeEndpointKind::VzIngest { .. } => "vz_ingest",
        BridgeEndpointKind::LibkrunGvproxy { .. } => "libkrun_gvproxy",
    }
}

/// Refuse an endpoint the running OS cannot serve. `Passt` requires Linux
/// (socketpair + passt + jailer-lite); the gvproxy/Vz paths run on macOS.
/// Pure (cfg-dependent) — unit-tested against the host it compiles on.
fn check_endpoint_platform(kind: &BridgeEndpointKind) -> Result<()> {
    match kind {
        BridgeEndpointKind::Passt { .. } => {
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!(
                    "Passt endpoint requires Linux (socketpair + passt + jailer-lite); \
                     this mvm-bridge was built for a non-Linux target"
                );
            }
            #[cfg(target_os = "linux")]
            {
                Ok(())
            }
        }
        BridgeEndpointKind::VzIngest { .. } | BridgeEndpointKind::LibkrunGvproxy { .. } => Ok(()),
    }
}

/// Apply the right `mvm-jailer-lite` confinement for the endpoint (Linux only).
#[cfg(target_os = "linux")]
fn confine_for_endpoint(cfg: &BridgeConfigJson) -> Result<()> {
    use mvm_hostd::jailer::{ConfinementSpec, confine_self};
    match &cfg.endpoint {
        BridgeEndpointKind::Passt { passt_path, .. } => {
            let spec = ConfinementSpec::firecracker_bridge(
                cfg.audit_dir.clone(),
                cfg.keys_dir.clone(),
                passt_path.clone(),
            );
            confine_self(&spec).context("apply mvm-jailer-lite confinement (passt)")
        }
        // libkrun-gvproxy on Linux needs a dedicated (passt-free) confinement
        // spec; that arm has no producer until libkrun moves onto this sidecar,
        // so refuse rather than ship an unconfined Linux path. VzIngest never
        // reaches here (vz is macOS).
        BridgeEndpointKind::LibkrunGvproxy { .. } => anyhow::bail!(
            "libkrun-gvproxy confinement on Linux is wired in Plan 209 Task 3; refusing \
             to run an unconfined Linux bridge"
        ),
        BridgeEndpointKind::VzIngest { .. } => Ok(()),
    }
}

/// Build the `BridgeEndpoints` variant from the parsed config. The `Passt` fd
/// reconstruction is Linux-only and `unsafe` (the parent's `pre_exec` dup2'd
/// the inherited fds, clearing `O_CLOEXEC`); the other arms carry only paths.
fn build_endpoints(cfg: &BridgeConfigJson) -> Result<BridgeEndpoints> {
    match &cfg.endpoint {
        BridgeEndpointKind::Passt {
            gateway_fd_raw,
            supervisor_fd_raw,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::{FromRawFd, OwnedFd};
                // SAFETY: the parent (`spawn_fc_bridge`) dup2'd these raw fds
                // into this process's table and cleared O_CLOEXEC before exec;
                // ownership transfers to the returned `OwnedFd`. There is no
                // host-side validation — a bad fd EBADFs on first use, which the
                // bridge thread surfaces via copy_bidirectional → exit(1).
                let gateway_fd = unsafe { OwnedFd::from_raw_fd(*gateway_fd_raw) };
                let supervisor_fd = unsafe { OwnedFd::from_raw_fd(*supervisor_fd_raw) };
                Ok(BridgeEndpoints::Passt {
                    gateway_fd,
                    supervisor_fd,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (gateway_fd_raw, supervisor_fd_raw);
                // Unreachable in practice: check_endpoint_platform refuses Passt
                // off Linux before we get here. Kept as a compile-time total
                // match.
                anyhow::bail!("Passt endpoint is Linux-only")
            }
        }
        BridgeEndpointKind::VzIngest { events_socket_path } => Ok(BridgeEndpoints::VzIngest {
            events_socket_path: events_socket_path.clone(),
        }),
        BridgeEndpointKind::LibkrunGvproxy {
            gvproxy_socket_path,
            supervisor_listen_path,
        } => Ok(BridgeEndpoints::LibkrunGvproxy {
            gvproxy_socket_path: gvproxy_socket_path.clone(),
            supervisor_listen_path: supervisor_listen_path.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn passt() -> BridgeEndpointKind {
        BridgeEndpointKind::Passt {
            passt_path: PathBuf::from("/usr/bin/passt"),
            passt_hashes_path: PathBuf::from("/h/.mvm/passt-hashes.toml"),
            gateway_fd_raw: 7,
            supervisor_fd_raw: 8,
        }
    }
    fn vz() -> BridgeEndpointKind {
        BridgeEndpointKind::VzIngest {
            events_socket_path: PathBuf::from("/h/.mvm/vms/x/events.sock"),
        }
    }
    fn gvproxy() -> BridgeEndpointKind {
        BridgeEndpointKind::LibkrunGvproxy {
            gvproxy_socket_path: PathBuf::from("/tmp/gv.sock"),
            supervisor_listen_path: PathBuf::from("/tmp/sup.sock"),
        }
    }

    #[test]
    fn leaf_caps_track_endpoint_payload_visibility() {
        assert!(leaf_caps_for(&passt()).payload_tap);
        assert!(leaf_caps_for(&gvproxy()).payload_tap);
        // Swift Vz emits flow events only — no payload tap.
        assert!(!leaf_caps_for(&vz()).payload_tap);
        assert!(leaf_caps_for(&vz()).flow_events);
    }

    #[test]
    fn endpoint_labels_are_stable() {
        assert_eq!(endpoint_label(&passt()), "passt");
        assert_eq!(endpoint_label(&vz()), "vz_ingest");
        assert_eq!(endpoint_label(&gvproxy()), "libkrun_gvproxy");
    }

    #[test]
    fn passt_platform_gate_matches_host() {
        // Passt is admitted only on Linux; the gvproxy/Vz paths always pass.
        assert_eq!(
            check_endpoint_platform(&passt()).is_ok(),
            cfg!(target_os = "linux"),
            "Passt must be admitted iff on Linux"
        );
        assert!(check_endpoint_platform(&vz()).is_ok());
        assert!(check_endpoint_platform(&gvproxy()).is_ok());
    }

    #[test]
    fn build_endpoints_maps_path_based_variants() {
        // The path-only variants build without any live fds, so they are
        // testable here. (Passt requires real inherited fds → exercised on-host
        // in Task 6.)
        let mut cfg = BridgeConfigJson {
            vm_name: "x".into(),
            audit_dir: PathBuf::from("/a"),
            audit_socket: PathBuf::from("/a/s.sock"),
            keys_dir: PathBuf::from("/k"),
            signing_key_path: PathBuf::from("/k/host.ed25519"),
            plan_json: "{}".into(),
            bundle_json: None,
            network_policy_json: None,
            endpoint: vz(),
        };
        assert!(matches!(
            build_endpoints(&cfg).unwrap(),
            BridgeEndpoints::VzIngest { .. }
        ));
        cfg.endpoint = gvproxy();
        assert!(matches!(
            build_endpoints(&cfg).unwrap(),
            BridgeEndpoints::LibkrunGvproxy { .. }
        ));
    }
}
