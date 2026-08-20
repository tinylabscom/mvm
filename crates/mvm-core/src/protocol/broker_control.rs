//! Host-agent control protocol sign/verify — the crypto half of
//! `mvm_contract::protocol::broker_control`.
//!
//! The DTOs ([`RegisterVm`], [`DeregisterVm`], [`ControlRequest`],
//! [`SignedControl`], [`ControlResponse`]) live in `mvm-contract`, re-exported
//! here so every existing `crate::protocol::broker_control::X` path keeps
//! resolving unchanged. `sign`/`sign_with_key_bytes`/`verify` stay in
//! `mvm-core` as free functions — they need `serde_jcs` + `ed25519-dalek`,
//! neither available in the no_std `mvm-contract` crate, and the orphan rule
//! forbids adding inherent `impl`s to a foreign type from here.
//!
//! `ControlRequest`'s serde shape is a signed byte-for-byte contract: it is
//! JCS-canonicalized then Ed25519-signed, so a single field rename, reorder,
//! or type change invalidates every existing signature. See
//! `control_request_canonical_bytes_are_pinned` below for the frozen fixture.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub use mvm_contract::protocol::broker_control::{
    ControlRequest, ControlResponse, DeregisterVm, RegisterVm, SignedControl,
};

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

/// Sign `request` with the raw 32-byte host signer key. Lets a caller that
/// only reads the key file (e.g. the backend that registers VMs) sign
/// without taking an `ed25519_dalek` dependency of its own.
pub fn sign_with_key_bytes(
    request: ControlRequest,
    key_bytes: &[u8; 32],
) -> Result<SignedControl, ControlError> {
    sign(request, &SigningKey::from_bytes(key_bytes))
}

/// Sign `request` with the host signer key over its JCS canonical bytes.
pub fn sign(request: ControlRequest, key: &SigningKey) -> Result<SignedControl, ControlError> {
    let bytes = serde_jcs::to_vec(&request)?;
    let sig = key.sign(&bytes);
    Ok(SignedControl {
        request,
        sig: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
    })
}

/// Verify `signed`'s signature against `verifying_key`, returning the request
/// on success. Re-canonicalizes the request — so any tampering with its
/// fields, or with the signature, fails closed.
pub fn verify<'a>(
    signed: &'a SignedControl,
    verifying_key: &VerifyingKey,
) -> Result<&'a ControlRequest, ControlError> {
    let bytes = serde_jcs::to_vec(&signed.request)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(signed.sig.as_bytes())?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ControlError::SignatureLength(sig_bytes.len()))?;
    let sig = Signature::from_bytes(&sig_arr);
    verifying_key
        .verify(&bytes, &sig)
        .map_err(|_| ControlError::SignatureInvalid)?;
    Ok(&signed.request)
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
        ControlRequest::Register(Box::new(RegisterVm {
            vm_id: "vm-1".into(),
            workload_id: Some("wl-1".into()),
            tenant_id: "local".into(),
            broker_listen_socket: "/run/state/vm-1/vsock-5300.sock".into(),
            workload_chain_path: "/audit/local.vm-1.workload.jsonl".into(),
            workload_chain_head_path: Some("/run/state/vm-1/audit-signer.head".into()),
            audit_signer_uds_path: Some("/run/state/vm-1/audit-signer.sock".into()),
            services_bindings: vec![
                mvm_contract::protocol::broker::ServiceId::parse("host.time.v1").unwrap(),
            ],
            capability_bindings: vec![],
            assurance: None,
            service_proxies: vec![],
        }))
    }

    /// Pins `ControlRequest`'s JCS canonical bytes. `ControlRequest` is
    /// signed via `serde_jcs::to_vec` then Ed25519 (see `sign`/`verify`
    /// above); this is the byte-for-byte proof that moving `RegisterVm`'s
    /// four path fields from `PathBuf` to `String` did not change the
    /// signed wire shape — a `PathBuf` and a `String` serialize to the same
    /// JSON string for a normal path, and this fixture is the regression
    /// net for that claim.
    #[test]
    fn control_request_canonical_bytes_are_pinned() {
        let bytes = serde_jcs::to_vec(&sample_register()).unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert_eq!(
            json,
            concat!(
                r#"{"audit_signer_uds_path":"/run/state/vm-1/audit-signer.sock","#,
                r#""broker_listen_socket":"/run/state/vm-1/vsock-5300.sock","kind":"register","#,
                r#""services_bindings":["host.time.v1"],"tenant_id":"local","vm_id":"vm-1","#,
                r#""workload_chain_head_path":"/run/state/vm-1/audit-signer.head","#,
                r#""workload_chain_path":"/audit/local.vm-1.workload.jsonl","workload_id":"wl-1"}"#
            )
        );
    }

    /// An empty `capability_bindings` must vanish from the signed bytes
    /// entirely rather than appear as `[]`.
    ///
    /// `ControlRequest` is signed over its JCS canonical bytes, so a field
    /// that serialized on every registration would change the bytes for every
    /// workload binding no capabilities — breaking signatures produced before
    /// the field existed. The pin above covers the whole document; this
    /// asserts the specific property directly, so a future edit that drops
    /// `skip_serializing_if` fails with a message naming the cause instead of
    /// a whole-string diff the reader has to decode.
    #[test]
    fn empty_capability_bindings_are_omitted_from_the_signed_bytes() {
        let json = String::from_utf8(serde_jcs::to_vec(&sample_register()).unwrap()).unwrap();
        assert!(
            !json.contains("capability_bindings"),
            "an empty capability binding set must be omitted, not serialized as []: {json}"
        );
    }

    /// The converse: a non-empty binding set is carried in the signed bytes.
    /// Without this, `skip_serializing_if` could be widened to always skip and
    /// the test above would still pass while the host silently signed a
    /// registration that authorized nothing.
    #[test]
    fn non_empty_capability_bindings_reach_the_signed_bytes() {
        use mvm_contract::protocol::agent_capability::{CapabilityBinding, CapabilityId};

        let mut req = sample_register();
        if let ControlRequest::Register(ref mut r) = req {
            r.capability_bindings = vec![CapabilityBinding {
                capability: CapabilityId::new(
                    mvm_contract::protocol::broker::ServiceId::parse("host.time.v1").unwrap(),
                    "now",
                )
                .unwrap(),
                descriptor_digest: [9u8; 32],
            }];
        }
        let json = String::from_utf8(serde_jcs::to_vec(&req).unwrap()).unwrap();
        assert!(
            json.contains("capability_bindings"),
            "a non-empty capability binding set must be signed over: {json}"
        );
    }

    #[test]
    fn sign_with_key_bytes_matches_sign() {
        let kb = [7u8; 32];
        let from_bytes = sign_with_key_bytes(sample_register(), &kb).unwrap();
        let vk = SigningKey::from_bytes(&kb).verifying_key();
        // Verifies under the key derived from the same bytes.
        assert_eq!(verify(&from_bytes, &vk).unwrap(), &sample_register());
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let k = key();
        let signed = sign(sample_register(), &k).unwrap();
        let verified = verify(&signed, &k.verifying_key()).unwrap();
        assert_eq!(verified, &sample_register());
    }

    #[test]
    fn tampered_request_fails_verification() {
        let k = key();
        let mut signed = sign(sample_register(), &k).unwrap();
        // Flip a field the guest would love to control — the chain path.
        if let ControlRequest::Register(ref mut r) = signed.request {
            r.workload_chain_path = "/audit/local.victim.workload.jsonl".into();
        }
        assert!(matches!(
            verify(&signed, &k.verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let k = key();
        let mut signed = sign(sample_register(), &k).unwrap();
        // Corrupt one signature byte (still valid base64 / 64 bytes).
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(signed.sig.as_bytes())
            .unwrap();
        raw[0] ^= 0xff;
        signed.sig = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(matches!(
            verify(&signed, &k.verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn controller_proxy_binding_is_covered_by_the_host_signature() {
        use mvm_contract::protocol::agent_capability::{
            CapabilityDescriptor, CapabilityId, CapabilityLimits, SchemaRef,
        };
        use mvm_contract::protocol::broker::ServiceId;
        use mvm_contract::protocol::broker_control::ServiceProxyBinding;

        let service = ServiceId::parse("host.test.controller.v1").unwrap();
        let descriptor = CapabilityDescriptor::builder()
            .id(CapabilityId::new(service.clone(), "probe").unwrap())
            .description("bounded test controller")
            .input_schema(SchemaRef::new("test.input.v1", [1; 32]).unwrap())
            .output_schema(SchemaRef::new("test.output.v1", [2; 32]).unwrap())
            .limits(CapabilityLimits::new(128, 128, 100).unwrap())
            .build()
            .unwrap();
        let mut request = sample_register();
        let ControlRequest::Register(registration) = &mut request else {
            panic!("sample is a registration");
        };
        registration.service_proxies.push(ServiceProxyBinding {
            service,
            endpoint: "/run/mvm/controller.sock".to_string(),
            capabilities: vec![descriptor],
        });
        let mut signed = sign(request, &key()).unwrap();
        let ControlRequest::Register(registration) = &mut signed.request else {
            panic!("signed sample is a registration");
        };
        registration.service_proxies[0].endpoint = "/run/mvm/other.sock".to_string();
        assert!(matches!(
            verify(&signed, &key().verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signed = sign(sample_register(), &key()).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            verify(&signed, &other.verifying_key()),
            Err(ControlError::SignatureInvalid)
        ));
    }

    #[test]
    fn malformed_signature_encoding_fails_closed() {
        let mut signed = sign(sample_register(), &key()).unwrap();
        signed.sig = "not base64 !!!".into();
        assert!(matches!(
            verify(&signed, &key().verifying_key()),
            Err(ControlError::SignatureEncoding(_))
        ));
    }

    #[test]
    fn short_signature_is_rejected() {
        let mut signed = sign(sample_register(), &key()).unwrap();
        signed.sig = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        assert!(matches!(
            verify(&signed, &key().verifying_key()),
            Err(ControlError::SignatureLength(10))
        ));
    }
}
