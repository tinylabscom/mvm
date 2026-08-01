//! Bridge entry point — spawns the dedicated per-VM thread + tokio
//! runtime, resolves the tenant's egress policy into the packet-observer
//! wiring, and dispatches to the [`super::passt`] or [`super::native_gateway`]
//! variant.

use std::collections::HashSet;
use std::sync::Arc;
use std::thread::JoinHandle;

use mvm_core::policy::EmergencyDeny;

use crate::supervisor::gateway_audit::GatewayAuditSink;
use crate::supervisor::network::latency::ObserverLatency;
use crate::supervisor::network::stages::{RedactingSubstitution, build_egress_scan};

use super::config::{BridgeConfig, BridgeEndpoints};
use super::events::{BRIDGE_MTU, EVENT_CHANNEL_CAPACITY, ObserverWiring, audit_event_channel};
use super::flow_policy::{
    FlowPolicy, PlanFlowPolicy, bare_network_policy_egress, resolve_bare_dns_pins,
};
use super::native_gateway::run_libkrun_native_gateway_bridge;
use super::passt::run_passt_bridge;
use super::signer_task;

/// Spawn the per-VM bridge thread. Returns the `JoinHandle` so the
/// caller (`mvm-libkrun-supervisor::main`) can drop it; libkrun's
/// `start_enter()` calls `exit()` on guest shutdown, which reaps
/// the thread without graceful join.
pub fn spawn_bridge_thread(endpoints: BridgeEndpoints, cfg: BridgeConfig) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("mvm-bridge-{}", cfg.vm_name))
        .spawn(move || {
            // Bridge thread panic → exit(1). Fail-closed; the
            // gateway audit substrate is claim-10 load-bearing.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_bridge_inner(endpoints, cfg);
            }));
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                };
                tracing::error!(panic = %msg, "gateway bridge panic — exiting (claim-10 fail-closed)");
                std::process::exit(1);
            }
        })
        .expect("spawn bridge thread")
}

/// Spawn the per-VM **native** audit feed thread. Used when the gateway is
/// native `rvproxy run --config` and libkrun attaches to it directly (no splice
/// in the data path). rvproxy is the sole egress enforcer; this thread only
/// re-feeds rvproxy's flow-audit export into the chain-signed audit, so the
/// claim-10 audit chain stays mvm's source of truth. `cfg.native_flow_audit_path`
/// must be `Some`. Same panic→exit(1) fail-closed contract as
/// [`spawn_bridge_thread`].
pub fn spawn_native_audit_feed(cfg: BridgeConfig) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("mvm-native-audit-{}", cfg.vm_name))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_native_audit_inner(cfg);
            }));
            if let Err(panic) = result {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic>".to_string()
                };
                tracing::error!(panic = %msg, "native audit feed panic — exiting (claim-10 fail-closed)");
                std::process::exit(1);
            }
        })
        .expect("spawn native audit feed thread")
}

/// Native audit feed: bind the per-VM gateway audit subscriber socket, run the
/// chain `signer_task`, and follow rvproxy's flow-audit export — mapping each
/// `FlowEvent` into the signer's mpsc so it's chain-signed. No splice / copy
/// tasks: rvproxy (attached directly to libkrun) is the enforcer + the flow
/// source. Blocks until the signer task ends, which happens when the follower
/// stops (all senders dropped) — i.e. on process teardown when libkrun's
/// `start_enter` calls `exit()` at guest poweroff.
fn run_native_audit_inner(cfg: BridgeConfig) {
    let flow_audit_path = match cfg.native_flow_audit_path.clone() {
        Some(p) => p,
        None => {
            tracing::error!("native audit feed started without native_flow_audit_path; exiting");
            return;
        }
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build native audit feed tokio runtime");
    let local = tokio::task::LocalSet::new();

    rt.block_on(local.run_until(async move {
        let sink = match GatewayAuditSink::bind(&cfg.audit_socket) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    path = %cfg.audit_socket.display(),
                    error = %e,
                    "gateway audit sink bind failed; exiting native audit feed"
                );
                return;
            }
        };
        let broadcast_tx = sink.sender();

        let (event_tx, event_rx) = audit_event_channel(EVENT_CHANNEL_CAPACITY);
        let signer_handle = tokio::task::spawn_local(signer_task(
            event_rx,
            cfg.plan.clone(),
            cfg.bundle.clone(),
            cfg.signer.clone(),
            broadcast_tx,
            cfg.observers.clone(),
        ));
        tokio::task::spawn_local(sink.run());

        // Follower (blocking file IO) holds the only surviving sender, so the
        // signer task lives until the follower stops (process teardown).
        let feed_tx = event_tx.clone();
        let vm = cfg.vm_name.clone();
        std::thread::Builder::new()
            .name(format!("mvm-rvproxy-flowaudit-{}", cfg.vm_name))
            .spawn(move || {
                if let Err(e) = crate::supervisor::network::rvproxy_flow_audit::follow_flow_audit(
                    &flow_audit_path,
                    &vm,
                    |ev| feed_tx.blocking_send(ev).is_ok(),
                ) {
                    tracing::warn!(
                        error = %e,
                        path = %flow_audit_path.display(),
                        "rvproxy flow-audit follower exited"
                    );
                }
            })
            .expect("spawn rvproxy flow-audit follower");
        drop(event_tx);

        let _ = signer_handle.await;
    }));
}

fn run_bridge_inner(endpoints: BridgeEndpoints, cfg: BridgeConfig) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("build bridge tokio runtime");
    let local = tokio::task::LocalSet::new();

    // Admission-time DNS pin for the bare (no-bundle) path: resolve the bare
    // allow-list's hosts to IPs on the host BEFORE entering the async bridge
    // (blocking DNS belongs in this sync prologue, not the runtime). The pins
    // feed the L4 scan so libkrun gate host:port — not host name only —
    // mirroring Firecracker resolving `-d <host>` at nftables-insert time. The
    // bundle path resolves its own L4 from the signed policy and ignores these.
    let bare_pins = match (cfg.bundle.is_none(), cfg.network_policy.as_ref()) {
        (true, Some(np)) => resolve_bare_dns_pins(np),
        _ => mvm_core::policy::dns_pin::DnsPinRegistry::new(),
    };

    rt.block_on(local.run_until(async move {
        let sink = match GatewayAuditSink::bind(&cfg.audit_socket) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    path = %cfg.audit_socket.display(),
                    error = %e,
                    "gateway audit sink bind failed; exiting bridge"
                );
                return;
            }
        };
        let broadcast_tx = sink.sender();

        let (event_tx, event_rx) = audit_event_channel(EVENT_CHANNEL_CAPACITY);

        // Signer task — sole writer of sign_and_emit per VM. Observers
        // fan out BEFORE chain signing inside the task body; the
        // chain-signing call is structural.
        let signer_handle = tokio::task::spawn_local(signer_task(
            event_rx,
            cfg.plan.clone(),
            cfg.bundle.clone(),
            cfg.signer.clone(),
            broadcast_tx,
            cfg.observers.clone(),
        ));

        // Subscriber-sink accept loop.
        let sink_handle = tokio::task::spawn_local(sink.run());

        // Resolve the tenant's egress policy from the admitted policy
        // bundle, if one reached the bridge, so the per-tenant
        // filters compose under mandatory-deny. No bundle (the common case
        // today: bundle_json carries a PlanArtifact pin, not resolved content)
        // → mandatory-deny only, the prior live default. A bundle whose L4
        // specs fail to translate (admission should have rejected it) fails
        // CLOSED to deny-all, never open. Emergency/now only gate the tool
        // policy, so the network resolution is stable.
        let (egress_l4, dns_allow, flow_policy) = match cfg.bundle.as_deref() {
            Some(bundle) => {
                let eff = mvm_core::policy::resolve(
                    bundle,
                    &cfg.plan.tenant,
                    chrono::Utc::now(),
                    &EmergencyDeny::default(),
                );
                // L4 egress + DNS hostname allow-list, derived from the resolved
                // policy. The same derivation the native rvproxy gateway uses
                // (`rvproxy_launch::egress_and_dns_from_effective`), so the splice
                // and the native substrate enforce byte-identical policy. An
                // empty DNS list adds no sink-hole (build_egress_scan), so
                // "open"/unset stays ungated.
                let (l4, dns_allow) =
                    crate::supervisor::network::rvproxy_launch::egress_and_dns_from_effective(&eff);
                // The per-tenant deny-by-default flow-open gate,
                // derived from the SAME resolved policy as the packet scan above
                // (so the coarse gate never drops a flow the scan would admit).
                // This is the libkrun analogue of the Firecracker
                // `install_default_deny`. The two compose: flow must open AND
                // every packet must pass mandatory-deny + L4 + DNS.
                let flow_policy: Arc<dyn FlowPolicy> =
                    Arc::new(PlanFlowPolicy::from_effective(&eff));
                (Some(l4), dns_allow, flow_policy)
            }
            // No resolved policy bundle. A transient/dev run carries its bare
            // egress policy on `cfg.network_policy` instead — enforce it directly
            // (deny-by-default flow gate + DNS host allow-list), the libkrun
            // analogue of Firecracker consuming `VmStartConfig.network_policy`.
            // Composes under the always-on mandatory-deny + placeholder-leak
            // scans exactly as the bundle path does.
            None => match &cfg.network_policy {
                Some(np) => bare_network_policy_egress(np, &bare_pins),
                // Neither bundle nor a threaded policy: fail CLOSED to deny-all.
                // Every workload-bearing spawn now threads a policy (cold boot +
                // warm-claim attach frame); this arm is the backstop so a missing
                // policy can't silently open egress on a pool hit. The always-on
                // mandatory-deny + placeholder scans still compose on top.
                None => bare_network_policy_egress(
                    &mvm_core::network_policy::NetworkPolicy::deny_all(),
                    &bare_pins,
                ),
            },
        };

        // Packet-observer wiring shared across both directions.
        let wiring = ObserverWiring {
            observers: cfg.observers.clone(),
            latency: Arc::new(ObserverLatency::new(
                cfg.vm_name.clone(),
                cfg.plan.tenant.0.clone(),
            )),
            killed_flows: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            mtu: BRIDGE_MTU,
            transcript_capture_roots: None,
            // Always-on egress redactor: mask any UNDECLARED
            // secret-shaped / PII run in the guest's outbound bytes to `XXX`
            // (mask-and-continue). Declared secrets never reach the guest (they
            // substitute host-side via the endpoint); this is the backstop for
            // anything that got onto the guest by another path.
            substitution: Arc::new(RedactingSubstitution::with_default_rules()),
            // Host-side mandatory-deny (link-local + cloud metadata), always on
            // and unbypassable from inside a compromised guest; the per-tenant
            // L4 + DNS filters compose under it when a bundle is present.
            scan: build_egress_scan(egress_l4, dns_allow),
        };

        // Bridge task — variant-specific.
        match endpoints {
            BridgeEndpoints::Passt {
                gateway_fd,
                supervisor_fd,
            } => {
                run_passt_bridge(
                    gateway_fd,
                    supervisor_fd,
                    cfg.vm_name.clone(),
                    cfg.plan.tenant.0.clone(),
                    flow_policy.clone(),
                    event_tx,
                    wiring,
                )
                .await;
            }
            BridgeEndpoints::LibkrunNativeGateway {
                gateway_socket_path,
                supervisor_listen_path,
            } => {
                run_libkrun_native_gateway_bridge(
                    gateway_socket_path,
                    supervisor_listen_path,
                    cfg.vm_name.clone(),
                    cfg.plan.tenant.0.clone(),
                    flow_policy.clone(),
                    event_tx,
                    wiring,
                )
                .await;
            }
        }

        // The bridge owns the last sender. Once it returns, drain every queued
        // flow close and transcript seal before ending the signer task.
        let _ = signer_handle.await;
        sink_handle.abort();
    }));
}
