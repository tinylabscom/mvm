//! Host-agent control protocol — `RegisterVm` / `DeregisterVm` / `ControlResponse`.
//!
//! The shared wire contract for the host-agent daemon (`mvm-hostd`) and the
//! backend that registers VMs with it (`mvm-backend`): it lives in `mvm-core`
//! so both speak the same types, not a duplicated raw-JSON shape.
//!
//! The host-agent daemon is resident and per-tenant: VMs register with it at
//! boot and deregister at teardown, instead of the daemon being forked per VM
//! and handed a one-shot [`super::config::SubprocessConfig`] on stdin. This
//! module is the wire contract for that control plane.
//!
//! The control plane is **host-only and host-signed**. It is reached over a
//! per-tenant control UDS (mode 0700, host-owned) that no guest can touch, and
//! every message is signed by the host signer key. A guest — which holds
//! neither the socket nor the key — therefore cannot register a VM, point a
//! VM's audit chain at another's file, or unbind a sibling's socket. The
//! signature is over the JCS (RFC 8785) canonical bytes of the request, the
//! same canonical-JSON-then-Ed25519 discipline the audit chain uses, so the
//! envelope is order-insensitive and a single byte of tampering fails closed.
//!
//! This module is types + sign/verify only. The daemon that binds the control
//! socket and acts on these messages is `mvm_hostd::broker::daemon`; the
//! backend that signs + sends them registers VMs at `start()`.

use std::path::PathBuf;

use super::broker::ServiceId;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

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
    /// Tenant the VM belongs to. The daemon is per-tenant, so this matches the
    /// daemon's own tenant; carried for validation + audit labelling.
    pub tenant_id: String,
    /// The `BROKER_PORT` UDS the daemon binds for this VM — the backend-specific
    /// path the VMM splices the guest's `connect_host_vsock(BROKER_PORT)` to
    /// (libkrun `<state>/vsock-<port>.sock`, vz `<state>/vsock/vsock-<port>.sock`).
    pub broker_listen_socket: PathBuf,
    /// Per-VM workload audit chain the daemon forwards `host.audit.v1` entries
    /// into (`<tenant>.<vm>.workload.jsonl`).
    pub workload_chain_path: PathBuf,
    /// The signer UDS the daemon forwards accepted audit entries to. `None`
    /// disables `host.audit.v1` for this VM (the handler returns `NotBound`).
    #[serde(default)]
    pub audit_signer_uds_path: Option<PathBuf>,
    /// The services the admitted plan authorizes for this VM (claim 12). The
    /// daemon dispatch-gates every call on this set. `host.audit.v1` is
    /// implicitly available and need not be listed.
    #[serde(default)]
    pub services_bindings: Vec<ServiceId>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControl {
    /// The request.
    pub request: ControlRequest,
    /// Base64 (standard) Ed25519 signature over `request`'s JCS bytes.
    pub sig: String,
}

/// Control-plane sign/verify failure.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The request could not be canonicalized for signing/verification.
    #[error("control request canonicalization failed: {0}")]
    Canonicalize(#[from] serde_json::Error),
    /// The base64 signature did not decode.
    #[error("control signature is not valid base64: {0}")]
    SignatureEncoding(#[from] base64::DecodeError),
    /// The decoded signature was not 64 bytes.
    #[error("control signature must be 64 bytes, got {0}")]
    SignatureLength(usize),
    /// The signature did not verify against the host signer key.
    #[error("control signature verification failed")]
    SignatureInvalid,
}

impl SignedControl {
    /// Sign `request` with the raw 32-byte host signer key. Lets a caller that
    /// only reads the key file (e.g. the backend that registers VMs) sign
    /// without taking an `ed25519_dalek` dependency of its own.
    pub fn sign_with_key_bytes(
        request: ControlRequest,
        key_bytes: &[u8; 32],
    ) -> Result<Self, ControlError> {
        Self::sign(request, &SigningKey::from_bytes(key_bytes))
    }

    /// Sign `request` with the host signer key over its JCS canonical bytes.
    pub fn sign(request: ControlRequest, key: &SigningKey) -> Result<Self, ControlError> {
        let bytes = serde_jcs::to_vec(&request)?;
        let sig = key.sign(&bytes);
        Ok(Self {
            request,
            sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        })
    }

    /// Verify the signature against `verifying_key`, returning the request on
    /// success. Re-canonicalizes the request — so any tampering with its
    /// fields, or with the signature, fails closed.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<&ControlRequest, ControlError> {
        let bytes = serde_jcs::to_vec(&self.request)?;
        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(self.sig.as_bytes())?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ControlError::SignatureLength(sig_bytes.len()))?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&bytes, &sig)
            .map_err(|_| ControlError::SignatureInvalid)?;
        Ok(&self.request)
    }
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
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        // Deterministic test key (no RNG dependency in the unit test).
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_register() -> ControlRequest {
        ControlRequest::Register(RegisterVm {
            vm_id: "vm-1".into(),
            tenant_id: "local".into(),
            broker_listen_socket: PathBuf::from("/run/state/vm-1/vsock-5300.sock"),
            workload_chain_path: PathBuf::from("/audit/local.vm-1.workload.jsonl"),
            audit_signer_uds_path: Some(PathBuf::from("/run/state/vm-1/audit-signer.sock")),
            services_bindings: vec![ServiceId::parse("host.time.v1").unwrap()],
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

    #[test]
    fn sign_with_key_bytes_matches_sign() {
        let kb = [7u8; 32];
        let from_bytes = SignedControl::sign_with_key_bytes(sample_register(), &kb).unwrap();
        let vk = SigningKey::from_bytes(&kb).verifying_key();
        // Verifies under the key derived from the same bytes.
        assert_eq!(from_bytes.verify(&vk).unwrap(), &sample_register());
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let k = key();
        let signed = SignedControl::sign(sample_register(), &k).unwrap();
        let verified = signed.verify(&k.verifying_key()).unwrap();
        assert_eq!(verified, &sample_register());
    }

    #[test]
    fn tampered_request_fails_verification() {
        let k = key();
        let mut signed = SignedControl::sign(sample_register(), &k).unwrap();
        // Flip a field the guest would love to control — the chain path.
        if let ControlRequest::Register(ref mut r) = signed.request {
            r.workload_chain_path = PathBuf::from("/audit/local.victim.workload.jsonl");
        }
        assert!(matches!(
            signed.verify(&k.verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let k = key();
        let mut signed = SignedControl::sign(sample_register(), &k).unwrap();
        // Corrupt one signature byte (still valid base64 / 64 bytes).
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(signed.sig.as_bytes())
            .unwrap();
        raw[0] ^= 0xff;
        signed.sig = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(matches!(
            signed.verify(&k.verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signed = SignedControl::sign(sample_register(), &key()).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            signed.verify(&other.verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn malformed_signature_encoding_fails_closed() {
        let mut signed = SignedControl::sign(sample_register(), &key()).unwrap();
        signed.sig = "not base64 !!!".into();
        assert!(matches!(
            signed.verify(&key().verifying_key()),
            Err(ControlError::SignatureEncoding(_))
        ));
    }

    #[test]
    fn short_signature_is_rejected() {
        let mut signed = SignedControl::sign(sample_register(), &key()).unwrap();
        signed.sig = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        assert!(matches!(
            signed.verify(&key().verifying_key()),
            Err(ControlError::SignatureLength(10))
        ));
    }
}
