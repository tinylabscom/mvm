//! Prelaunched-supervisor attach verify+merge.
//!
//! The cold/legacy supervisor path extracts the admitted plan without
//! re-verifying (host-trusted private stdin pipe). The warm path's
//! control UDS is **same-uid-reachable**, so it is NOT a trusted private
//! channel — this module re-verifies the signed `ExecutionPlan` (Ed25519
//! signature + G4 window + nonce-replay) before the caller may `start_enter`.
//! Reuses `mvm_core::plan::{verify_plan, check_window, NonceStore}`; no fork.

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use libkrun_sys::{SupervisorAttachConfig, SupervisorBaseConfig, SupervisorConfig};
use mvm_core::plan::{NonceStore, SignedExecutionPlan, check_window, verify_plan};

/// Why an attach was refused. Every variant means the caller must NOT
/// `start_enter` — the standby exits non-zero.
#[derive(Debug, thiserror::Error)]
pub enum AttachVerifyError {
    #[error("decode attach config: {0}")]
    Decode(String),
    #[error("merge base+attach: {0}")]
    Merge(#[from] libkrun_sys::AttachMergeError),
    #[error("read host signing key {0}: {1}")]
    ReadKey(String, String),
    #[error("host signing key is {0} bytes, expected 32")]
    KeyLen(usize),
    #[error("decode SignedExecutionPlan envelope: {0}")]
    Envelope(String),
    #[error("plan signature verify failed: {0}")]
    PlanVerify(String),
    #[error("plan validity (window/nonce): {0}")]
    Validity(String),
}

/// Verify a control-UDS `attach` against a prelaunched standby's `base` and,
/// on success, return the whole `SupervisorConfig` the caller hands to the
/// existing `run_with_bridge` path. **Never boots** — the caller calls
/// `start_enter` only on `Ok`.
///
/// Order mirrors `mvm_hostd::supervisor::aggregate::launch`:
/// merge (binding-nonce echo) → signature → G4 window → nonce-replay.
pub fn verify_and_merge_attach(
    base: SupervisorBaseConfig,
    attach_bytes: &[u8],
    now: DateTime<Utc>,
    nonce_store: &mut NonceStore,
) -> Result<SupervisorConfig, AttachVerifyError> {
    // Pull the bits we still need after `base`/`attach` are moved into the merge.
    let signer_id = base.signer_id.clone();
    let key_path = base.signing_key_path.clone();

    let attach: SupervisorAttachConfig = serde_json::from_slice(attach_bytes)
        .map_err(|e| AttachVerifyError::Decode(e.to_string()))?;
    let plan_value = attach.plan.clone();

    // Binding-nonce echo + field merge (also rejects a base carrying a rootfs).
    let cfg = SupervisorConfig::from_base_and_attach(base, attach)?;

    // Derive the host-signer PUBLIC key from the on-disk secret. The key is
    // host-trusted state (claim 8); the secret never leaves this process. Same
    // 32-byte read the cold path's audit signer performs.
    let key_bytes = std::fs::read(&key_path)
        .map_err(|e| AttachVerifyError::ReadKey(key_path.display().to_string(), e.to_string()))?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AttachVerifyError::KeyLen(key_bytes.len()))?;
    let vk: VerifyingKey = SigningKey::from_bytes(&key_arr).verifying_key();

    // Re-verify the signature — the load-bearing warm-path invariant.
    let signed: SignedExecutionPlan = serde_json::from_value(plan_value)
        .map_err(|e| AttachVerifyError::Envelope(e.to_string()))?;
    let plan = verify_plan(&signed, &[(signer_id.as_str(), &vk)])
        .map_err(|e| AttachVerifyError::PlanVerify(e.to_string()))?;

    // G4 validity window + per-signer nonce-replay.
    check_window(&plan, now).map_err(|e| AttachVerifyError::Validity(e.to_string()))?;
    nonce_store
        .check_and_insert(&signed.0.signer_id, &plan)
        .map_err(|e| AttachVerifyError::Validity(e.to_string()))?;

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use libkrun_sys::{
        BridgeRestartPolicy, KrunContext, SupervisorAttachConfig, SupervisorBaseConfig,
    };
    use mvm_core::plan::signing::test_support::sample_plan;
    use mvm_core::plan::{ExecutionPlan, NonceStore, sign_plan};
    use std::io::Write;

    const NONCE: &str = "binding-nonce-fixed-for-tests";

    // A 32-byte ed25519 secret written to a tempfile; returns (path, signing key).
    fn write_key(dir: &std::path::Path) -> (std::path::PathBuf, SigningKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let path = dir.join("host-signer.ed25519");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(key.to_bytes().as_slice()).unwrap();
        (path, key)
    }

    fn plan_around(now: chrono::DateTime<Utc>) -> ExecutionPlan {
        let mut p = sample_plan();
        p.valid_from = now - Duration::minutes(5);
        p.valid_until = now + Duration::minutes(5);
        p
    }

    fn base(key_path: std::path::PathBuf, signer_id: &str) -> SupervisorBaseConfig {
        let mut krun = KrunContext::new("standby-0", "/k/vmlinux", "/placeholder");
        krun.rootfs_path = None;
        SupervisorBaseConfig {
            krun,
            vm_state_dir: "/run/mvm/standby-0".into(),
            pid_file_name: None,
            signing_key_path: key_path,
            signer_id: signer_id.into(),
            binding_nonce: NONCE.into(),
            control_socket_path: "/run/mvm/standby-0/control.sock".into(),
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
        }
    }

    fn attach_bytes(nonce: &str, plan_envelope: serde_json::Value) -> Vec<u8> {
        let attach = SupervisorAttachConfig {
            binding_nonce: nonce.into(),
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/g.sock".into(),
            gateway_events_socket: None,
            plan: plan_envelope,
            bundle: None,
            network_policy: None,
            transparent_terminator_port: None,
        };
        serde_json::to_vec(&attach).unwrap()
    }

    fn signed_envelope(
        plan: &ExecutionPlan,
        key: &SigningKey,
        signer_id: &str,
    ) -> serde_json::Value {
        serde_json::to_value(sign_plan(plan, key, signer_id)).unwrap()
    }

    #[test]
    fn happy_path_returns_admitted_config() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let plan = plan_around(now);
        let bytes = attach_bytes(NONCE, signed_envelope(&plan, &key, "host:test"));
        let mut store = NonceStore::new();
        let cfg = verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap();
        assert_eq!(cfg.krun.rootfs_path.as_deref(), Some("/vol/rootfs.ext4"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn rejects_wrong_binding_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let bytes = attach_bytes(
            "WRONG",
            signed_envelope(&plan_around(now), &key, "host:test"),
        );
        let mut store = NonceStore::new();
        let err =
            verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::Merge(_)));
    }

    #[test]
    fn rejects_unsigned_plan_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, _real) = write_key(dir.path());
        let attacker = SigningKey::from_bytes(&[9u8; 32]); // not the on-disk key
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let bytes = attach_bytes(
            NONCE,
            signed_envelope(&plan_around(now), &attacker, "host:test"),
        );
        let mut store = NonceStore::new();
        let err =
            verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::PlanVerify(_)));
    }

    #[test]
    fn rejects_out_of_window_plan() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let plan_now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let plan = plan_around(plan_now);
        let bytes = attach_bytes(NONCE, signed_envelope(&plan, &key, "host:test"));
        // Verify an hour after the window closed.
        let later = plan_now + Duration::hours(1);
        let mut store = NonceStore::new();
        let err =
            verify_and_merge_attach(base(kp, "host:test"), &bytes, later, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::Validity(_)));
    }

    #[test]
    fn rejects_replayed_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let plan = plan_around(now);
        let bytes = attach_bytes(NONCE, signed_envelope(&plan, &key, "host:test"));
        let mut store = NonceStore::new();
        // First admit succeeds; second (same store, same plan) is a replay.
        verify_and_merge_attach(base(kp.clone(), "host:test"), &bytes, now, &mut store).unwrap();
        let err =
            verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::Validity(_)));
    }
}
