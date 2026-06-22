//! Unified stdin contract for the shared `mvm-bridge` sidecar.
//!
//! One `BridgeConfigJson` shape for every backend, carrying the common
//! audit/plan substrate plus a [`BridgeEndpointKind`] discriminant that selects
//! the transport. The `mvm-bridge` binary parses this once
//! and builds the matching
//! `mvm_hostd::supervisor::gateway_bridge::BridgeEndpoints` variant, applying
//! `mvm-jailer-lite` confinement through one cfg-gated codepath wherever the OS
//! supports it (the Linux `Passt` endpoint). The macOS arms (`VzIngest`,
//! libkrun-gvproxy on macOS) run unconfined — `confine_self` is Linux-only
//! (Landlock+seccomp), unchanged from the vz drainer.
//!
//! ## Fail-closed parsing
//!
//! Every struct and enum here carries `#[serde(deny_unknown_fields)]` so a
//! malicious or sloppy producer cannot smuggle an attacker-controlled field a
//! future schema bump might interpret — the same contract the per-backend
//! parsers held (claim 5). The endpoint discriminant is **externally tagged**
//! (`{"endpoint": {"passt": {…}}}`) rather than internally tagged because
//! `deny_unknown_fields` is not honoured on internally-tagged enums; external
//! tagging keeps the rejection guarantee intact on both the wrapper struct and
//! each variant.
//!
//! The plan-decode and passt-hash-verify helpers are re-exported from
//! [`crate::firecracker_bridge::parse`] unchanged — no parser duplication, and
//! the `firecracker-bridge-fuzz` lane keeps exercising the same code.

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_core::network_policy::NetworkPolicy;
use serde::{Deserialize, Serialize};

// Reused verbatim — the unified sidecar decodes the plan and verifies the passt
// binary through exactly the helpers the per-backend bins used.
pub use crate::firecracker_bridge::parse::{PasstHashesFile, decode_plan_json, verify_passt_hash};

/// Stdin JSON contract for the shared `mvm-bridge` sidecar. Producer is the
/// active backend (`mvm-backend::libkrun` / `::microvm` (Firecracker) / `::vz`).
/// All paths are absolute and already-canonicalised by the parent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfigJson {
    /// VM name; labels the bridge thread + the audit chain `vm` field.
    pub vm_name: String,

    /// `~/.mvm/audit/` — destination of the chain-signed JSONL log
    /// `FileAuditSigner` appends to. Shared with sibling VMs; the
    /// cross-process flock inside `FileAuditSigner` serialises writes per
    /// tenant.
    pub audit_dir: PathBuf,

    /// `~/.mvm/audit/gateway-<vm>.sock` — subscriber socket the bridge binds
    /// at startup so `nc -U <path>` consumers see the live NDJSON flow-event
    /// tail. Same shape across every backend.
    pub audit_socket: PathBuf,

    /// `~/.mvm/keys/` — directory holding the host signer key. Scopes the
    /// Linux Landlock confinement spec. A common field across every endpoint
    /// kind, though only consumed by confinement on Linux (macOS has no LSM).
    pub keys_dir: PathBuf,

    /// `~/.mvm/keys/host-signer.ed25519` — mode 0600 file owned by the calling
    /// user. Re-read on each launch to seed the `FileAuditSigner` signing key.
    pub signing_key_path: PathBuf,

    /// Serialised `SignedExecutionPlan` envelope (what
    /// `mvm-cli::plan_admission::populate_audit_substrate` threads in).
    /// Decoded via [`decode_plan_json`]; the envelope signature is not
    /// re-verified — the host checked it at admit time and is in the TCB.
    pub plan_json: String,

    /// Optional serialised `PolicyBundle` (the resolved bundle pin, used to
    /// label flow-event audit entries with the bundle digest).
    #[serde(default)]
    pub bundle_json: Option<String>,

    /// Optional serialised bare `NetworkPolicy` — the producer's egress-policy
    /// intent for the **no-bundle** path, decoded into the
    /// `BridgeConfig.network_policy` field. Producer-supplied because endpoint
    /// kind alone cannot determine it: the `Passt` kind serves both Firecracker
    /// (which defers egress enforcement to its kernel nftables moat, so the
    /// bridge gate must be `unrestricted` to avoid double-gating) *and*
    /// libkrun-on-Linux (where the bridge IS the enforcer, so it carries the
    /// real policy). `None` ⇒ the bridge's no-bundle arm fails closed to
    /// deny-all.
    #[serde(default)]
    pub network_policy_json: Option<String>,

    /// Transport selector. Externally tagged so `deny_unknown_fields` holds.
    pub endpoint: BridgeEndpointKind,
}

/// Backend-specific transport for the bridge, selecting which
/// `BridgeEndpoints` variant the sidecar builds.
///
/// Externally tagged (`{"passt": {…}}` / `{"vz_ingest": {…}}` /
/// `{"libkrun_gvproxy": {…}}`) with per-variant `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeEndpointKind {
    /// Linux libkrun + passt, **and** the Firecracker path: both halves are
    /// passed as raw fds the parent `dup2`'d into the child across exec. The
    /// sidecar verifies `passt_path` against `passt_hashes_path` before
    /// confinement, then reconstructs the fds into `BridgeEndpoints::Passt`.
    Passt {
        /// Operator-installed `passt` binary the bridge relays packets to.
        passt_path: PathBuf,
        /// `~/.mvm/passt-hashes.toml` — operator-pinned SHA256 allowlist.
        passt_hashes_path: PathBuf,
        /// Raw fd of the parent half of the passt socketpair (faces passt).
        gateway_fd_raw: i32,
        /// Raw fd of the supervisor half of the inner virtio-net socketpair.
        supervisor_fd_raw: i32,
    },
    /// Vz Swift supervisor + gvproxy: the splice happens in Swift, which writes
    /// NDJSON `FlowEvent`s over the unix stream at `events_socket_path`.
    VzIngest {
        /// Socket the Swift `mvm-vz-supervisor` writes its NDJSON
        /// `FlowEventWire` stream to; the bridge binds (mode 0700) and reads.
        events_socket_path: PathBuf,
    },
    /// macOS libkrun + gvproxy: gvproxy owns its listener at
    /// `gvproxy_socket_path`; the bridge binds `supervisor_listen_path` and
    /// libkrun connects to that. Datagrams are relayed both directions.
    LibkrunGvproxy {
        gvproxy_socket_path: PathBuf,
        supervisor_listen_path: PathBuf,
    },
}

/// Decode the optional `network_policy_json` field into a bare
/// [`NetworkPolicy`]. `None` (field absent) yields `None`, which the bridge's
/// no-bundle arm treats as fail-closed deny-all.
pub fn decode_network_policy(cfg: &BridgeConfigJson) -> Result<Option<NetworkPolicy>> {
    match &cfg.network_policy_json {
        Some(s) => Ok(Some(
            serde_json::from_str(s).context("decode network_policy_json into NetworkPolicy")?,
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_fields() -> serde_json::Value {
        serde_json::json!({
            "vm_name": "vm-1",
            "audit_dir": "/home/u/.mvm/audit",
            "audit_socket": "/home/u/.mvm/audit/gateway-vm-1.sock",
            "keys_dir": "/home/u/.mvm/keys",
            "signing_key_path": "/home/u/.mvm/keys/host-signer.ed25519",
            "plan_json": "{}",
        })
    }

    fn with_endpoint(endpoint: serde_json::Value) -> String {
        let mut v = base_fields();
        v.as_object_mut()
            .unwrap()
            .insert("endpoint".into(), endpoint);
        serde_json::to_string(&v).unwrap()
    }

    #[test]
    fn passt_endpoint_roundtrips() {
        let json = with_endpoint(serde_json::json!({
            "passt": {
                "passt_path": "/usr/bin/passt",
                "passt_hashes_path": "/home/u/.mvm/passt-hashes.toml",
                "gateway_fd_raw": 7,
                "supervisor_fd_raw": 8,
            }
        }));
        let cfg: BridgeConfigJson = serde_json::from_str(&json).expect("passt parses");
        assert_eq!(cfg.vm_name, "vm-1");
        assert!(cfg.bundle_json.is_none(), "bundle_json defaults to None");
        match &cfg.endpoint {
            BridgeEndpointKind::Passt {
                passt_path,
                gateway_fd_raw,
                supervisor_fd_raw,
                ..
            } => {
                assert_eq!(passt_path, &PathBuf::from("/usr/bin/passt"));
                assert_eq!(*gateway_fd_raw, 7);
                assert_eq!(*supervisor_fd_raw, 8);
            }
            other => panic!("expected Passt, got {other:?}"),
        }
        // Serialize → deserialize must round-trip identically.
        let reser = serde_json::to_string(&cfg).unwrap();
        let again: BridgeConfigJson = serde_json::from_str(&reser).unwrap();
        assert_eq!(cfg, again);
    }

    #[test]
    fn vz_ingest_endpoint_roundtrips() {
        let json = with_endpoint(serde_json::json!({
            "vz_ingest": { "events_socket_path": "/home/u/.mvm/vms/vm-1/events.sock" }
        }));
        let cfg: BridgeConfigJson = serde_json::from_str(&json).expect("vz_ingest parses");
        match &cfg.endpoint {
            BridgeEndpointKind::VzIngest { events_socket_path } => {
                assert_eq!(
                    events_socket_path,
                    &PathBuf::from("/home/u/.mvm/vms/vm-1/events.sock")
                );
            }
            other => panic!("expected VzIngest, got {other:?}"),
        }
    }

    #[test]
    fn libkrun_gvproxy_endpoint_roundtrips() {
        let json = with_endpoint(serde_json::json!({
            "libkrun_gvproxy": {
                "gvproxy_socket_path": "/tmp/gv.sock",
                "supervisor_listen_path": "/tmp/sup.sock",
            }
        }));
        let cfg: BridgeConfigJson = serde_json::from_str(&json).expect("libkrun_gvproxy parses");
        assert!(matches!(
            cfg.endpoint,
            BridgeEndpointKind::LibkrunGvproxy { .. }
        ));
    }

    #[test]
    fn bundle_json_is_carried_when_present() {
        let mut v = base_fields();
        let obj = v.as_object_mut().unwrap();
        obj.insert("bundle_json".into(), serde_json::json!("{\"x\":1}"));
        obj.insert(
            "endpoint".into(),
            serde_json::json!({ "vz_ingest": { "events_socket_path": "/x.sock" } }),
        );
        let cfg: BridgeConfigJson = serde_json::from_str(&serde_json::to_string(&v).unwrap())
            .expect("parses with bundle_json");
        assert_eq!(cfg.bundle_json.as_deref(), Some("{\"x\":1}"));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let mut v = base_fields();
        let obj = v.as_object_mut().unwrap();
        obj.insert("attacker_injected".into(), serde_json::json!("evil"));
        obj.insert(
            "endpoint".into(),
            serde_json::json!({ "vz_ingest": { "events_socket_path": "/x.sock" } }),
        );
        let err = serde_json::from_str::<BridgeConfigJson>(&serde_json::to_string(&v).unwrap())
            .expect_err("deny_unknown_fields must reject");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    #[test]
    fn unknown_field_within_a_variant_is_rejected() {
        let json = with_endpoint(serde_json::json!({
            "vz_ingest": {
                "events_socket_path": "/x.sock",
                "sneaky": true,
            }
        }));
        let err = serde_json::from_str::<BridgeConfigJson>(&json)
            .expect_err("deny_unknown_fields must reject within a variant");
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    #[test]
    fn unknown_endpoint_kind_is_rejected() {
        let json = with_endpoint(serde_json::json!({
            "wireguard": { "whatever": 1 }
        }));
        let err = serde_json::from_str::<BridgeConfigJson>(&json)
            .expect_err("unknown endpoint kind must reject");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn missing_endpoint_is_rejected() {
        // base_fields() has no endpoint — required field.
        let err = serde_json::from_str::<BridgeConfigJson>(&base_fields().to_string())
            .expect_err("missing endpoint must reject");
        assert!(err.to_string().contains("endpoint"), "got: {err}");
    }

    #[test]
    fn reexported_decode_plan_json_resolves() {
        // Smoke: the re-export path is wired (the FC fuzz target + the sidecar
        // both reach the same helper through this module).
        assert!(super::decode_plan_json(r#"{"not_a_plan":true}"#).is_err());
    }

    #[test]
    fn network_policy_json_defaults_to_none_and_decodes_none() {
        let json = with_endpoint(serde_json::json!({
            "vz_ingest": { "events_socket_path": "/x.sock" }
        }));
        let cfg: BridgeConfigJson = serde_json::from_str(&json).unwrap();
        assert!(cfg.network_policy_json.is_none());
        assert!(decode_network_policy(&cfg).unwrap().is_none());
    }

    #[test]
    fn network_policy_json_roundtrips_and_decodes() {
        let policy = NetworkPolicy::unrestricted();
        let policy_json = serde_json::to_string(&policy).unwrap();
        let mut v = base_fields();
        let obj = v.as_object_mut().unwrap();
        obj.insert("network_policy_json".into(), serde_json::json!(policy_json));
        obj.insert(
            "endpoint".into(),
            serde_json::json!({ "vz_ingest": { "events_socket_path": "/x.sock" } }),
        );
        let cfg: BridgeConfigJson =
            serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        let decoded = decode_network_policy(&cfg)
            .unwrap()
            .expect("policy present");
        assert_eq!(decoded, policy);
    }

    // ── Producer byte-equivalence (golden) ──────────────────────────────
    //
    // The FC + vz backends build this config as raw JSON (they cannot depend on
    // the leaf bin crate). These two tests mirror those producer `json!` blocks
    // EXACTLY so a key/nesting drift between producer and consumer is caught in
    // CI without a live VM — the main guard for the Firecracker leg, whose
    // producer (`mvm-backend::microvm::spawn_fc_bridge`) is Linux-only and not
    // compiled on a macOS dev host. Keep these in sync with the producers; the
    // live runs (Hetzner KVM for FC, macOS-26 for vz) are the end-to-end proof.

    #[test]
    fn fc_producer_passt_config_deserializes() {
        // Mirror of `mvm-backend::microvm::spawn_fc_bridge`'s bridge_cfg.
        let np = serde_json::to_string(&NetworkPolicy::unrestricted()).unwrap();
        let json = serde_json::json!({
            "vm_name": "fc-vm",
            "audit_dir": "/h/.mvm/audit",
            "audit_socket": "/h/.mvm/audit/gateway-fc-vm.sock",
            "keys_dir": "/h/.mvm/keys",
            "signing_key_path": "/h/.mvm/keys/host-signer.ed25519",
            "plan_json": "{}",
            "bundle_json": serde_json::Value::Null,
            "network_policy_json": np,
            "endpoint": {
                "passt": {
                    "passt_path": "/usr/bin/passt",
                    "passt_hashes_path": "/h/.mvm/passt-hashes.toml",
                    "gateway_fd_raw": 7,
                    "supervisor_fd_raw": 8,
                }
            },
        });
        let cfg: BridgeConfigJson =
            serde_json::from_value(json).expect("FC producer JSON must deserialize");
        assert!(cfg.bundle_json.is_none(), "null bundle_json → None");
        // FC defers egress to nftables → unrestricted.
        assert_eq!(
            decode_network_policy(&cfg).unwrap(),
            Some(NetworkPolicy::unrestricted())
        );
        match cfg.endpoint {
            BridgeEndpointKind::Passt {
                gateway_fd_raw,
                supervisor_fd_raw,
                ..
            } => {
                assert_eq!(gateway_fd_raw, 7);
                assert_eq!(supervisor_fd_raw, 8);
            }
            other => panic!("expected Passt, got {other:?}"),
        }
    }

    #[test]
    fn vz_producer_vz_ingest_config_deserializes() {
        // Mirror of `mvm-backend::vz::spawn_vz_drainer`'s drainer_cfg.
        let json = serde_json::json!({
            "vm_name": "vz-vm",
            "audit_dir": "/h/.mvm/audit",
            "audit_socket": "/h/.mvm/audit/gateway-vz-vm.sock",
            "keys_dir": "/h/.mvm/keys",
            "signing_key_path": "/h/.mvm/keys/host-signer.ed25519",
            "plan_json": "{}",
            "bundle_json": serde_json::Value::Null,
            "endpoint": { "vz_ingest": { "events_socket_path": "/h/.mvm/vms/vz-vm/events.sock" } },
        });
        let cfg: BridgeConfigJson =
            serde_json::from_value(json).expect("vz producer JSON must deserialize");
        // vz omits network_policy_json → None (no-bundle arm fails closed).
        assert!(decode_network_policy(&cfg).unwrap().is_none());
        assert!(matches!(cfg.endpoint, BridgeEndpointKind::VzIngest { .. }));
    }
}
