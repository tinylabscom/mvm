//! Host-agent control protocol DTOs — `RegisterVm` / `DeregisterVm` /
//! `ControlRequest` / `SignedControl` / `ControlResponse`.
//!
//! The shared wire contract for the host-agent daemon (`mvm-hostd`) and the
//! backend that registers VMs with it (`mvm-runtime`): it lives here so both
//! speak the same types, not a duplicated raw-JSON shape.
//!
//! The host-agent daemon is resident and per-tenant: VMs register with it at
//! boot and deregister at teardown. This module is the wire contract for that
//! control plane.
//!
//! The control plane is **host-only and host-signed**. It is reached over a
//! per-tenant control UDS (mode 0700, host-owned) that no guest can touch, and
//! every message is signed by the host signer key over the JCS (RFC 8785)
//! canonical bytes of the request — the same canonical-JSON-then-Ed25519
//! discipline the audit chain uses, so the envelope is order-insensitive and a
//! single byte of tampering fails closed. `ControlRequest`'s serde shape is
//! therefore a signed byte-for-byte contract: field names/order, tagging, and
//! `deny_unknown_fields` must never change on this type without invalidating
//! every existing signature.
//!
//! Sign/verify (`serde_jcs` + `ed25519-dalek`, both host-only) and
//! `ControlError` live in `mvm_core::protocol::broker_control`, which
//! re-exports these DTOs at their existing paths. The daemon that binds the
//! control socket and acts on these messages is `mvm_hostd::broker::daemon`;
//! the backend that signs + sends them registers VMs at `start()`.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::agent_capability::CapabilityBinding;
use super::broker::ServiceId;

/// Register a VM with the host-agent daemon: bind its `BROKER_PORT` listen
/// socket and record the bindings + audit-chain path the daemon dispatches
/// and forwards against. Sent once at VM start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterVm {
    /// Server-side VM identity. The daemon keys every dispatch and every
    /// forwarded audit entry off the socket that accepted the connection, not
    /// off any guest-supplied field; this label is how the host names that VM
    /// in the registration and in the chain path.
    pub vm_id: String,
    /// Workload identifier stamped into helper registration. Older callers may
    /// omit it; the daemon falls back to `vm_id`.
    #[serde(default)]
    pub workload_id: Option<String>,
    /// Tenant the VM belongs to. The daemon is per-tenant, so this matches the
    /// daemon's own tenant; carried for validation + audit labelling.
    pub tenant_id: String,
    /// The `BROKER_PORT` UDS the daemon binds for this VM — the backend-specific
    /// path the VMM splices the guest's `connect_host_vsock(BROKER_PORT)` to
    /// (libkrun `<state>/vsock-<port>.sock`, hvf `<state>/vsock/vsock-<port>.sock`).
    pub broker_listen_socket: String,
    /// Per-VM workload audit chain the daemon forwards `host.audit.v1` entries
    /// into (`<tenant>.<vm>.workload.jsonl`).
    pub workload_chain_path: String,
    /// Secondary persisted head for the per-VM workload chain. Older callers
    /// may omit it; the daemon derives a sibling fallback.
    #[serde(default)]
    pub workload_chain_head_path: Option<String>,
    /// The signer UDS the daemon forwards accepted audit entries to. `None`
    /// disables `host.audit.v1` for this VM (the handler returns `NotBound`).
    #[serde(default)]
    pub audit_signer_uds_path: Option<String>,
    /// The services the admitted plan authorizes for this VM (claim 12). The
    /// daemon dispatch-gates every call on this set. `host.audit.v1` is
    /// implicitly available and need not be listed.
    #[serde(default)]
    pub services_bindings: Vec<ServiceId>,
    /// Exact per-verb capability bindings approved for this workload. The
    /// host-signed registration is the only source of this list.
    #[serde(default)]
    pub capability_bindings: Vec<CapabilityBinding>,
}

/// Deregister a VM at teardown: the daemon unbinds + drops its listen socket
/// and flushes + closes its chain head. Idempotent on the daemon side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeregisterVm {
    /// The VM to drop, matching a prior [`RegisterVm::vm_id`].
    pub vm_id: String,
}

/// A control request the host-agent daemon's control socket accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlRequest {
    /// Bind + record a VM.
    Register(RegisterVm),
    /// Unbind + drop a VM.
    Deregister(DeregisterVm),
}

/// A host-signed control message: the [`ControlRequest`] plus an Ed25519
/// signature over its JCS canonical bytes by the host signer key.
///
/// Sign/verify live in `mvm_core::protocol::broker_control` as free functions
/// (`sign`, `sign_with_key_bytes`, `verify`) — this type cannot carry them as
/// inherent methods since `serde_jcs`/`ed25519-dalek` signing is host-only and
/// the orphan rule forbids `mvm-core` from adding inherent `impl`s to a
/// foreign type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControl {
    /// The request.
    pub request: ControlRequest,
    /// Base64 (standard) Ed25519 signature over `request`'s JCS bytes.
    pub sig: String,
}

/// The daemon's reply to a control request, read by the registering backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResponse {
    /// The request was applied.
    Ok,
    /// The request was rejected (bad signature, wrong tenant, unsafe id, bind
    /// failure). Carries a host-authored message; never guest-authored.
    Err {
        /// Why the request was refused.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn sample_register() -> ControlRequest {
        ControlRequest::Register(RegisterVm {
            vm_id: "vm-1".into(),
            workload_id: Some("wl-1".into()),
            tenant_id: "local".into(),
            broker_listen_socket: "/run/state/vm-1/vsock-5300.sock".into(),
            workload_chain_path: "/audit/local.vm-1.workload.jsonl".into(),
            workload_chain_head_path: Some("/run/state/vm-1/audit-signer.head".into()),
            audit_signer_uds_path: Some("/run/state/vm-1/audit-signer.sock".into()),
            services_bindings: vec![ServiceId::parse("host.time.v1").unwrap()],
            capability_bindings: vec![],
        })
    }

    #[test]
    fn control_request_serde_roundtrips() {
        for req in [
            sample_register(),
            ControlRequest::Deregister(DeregisterVm {
                vm_id: "vm-1".into(),
            }),
        ] {
            let json = serde_json::to_string(&req).unwrap();
            let back: ControlRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(req, back);
        }
    }

    #[test]
    fn unknown_field_is_rejected() {
        // `deny_unknown_fields` fails closed on an unexpected key.
        let bad = r#"{"kind":"deregister","vm_id":"vm-1","extra":true}"#;
        assert!(serde_json::from_str::<ControlRequest>(bad).is_err());
    }
}
