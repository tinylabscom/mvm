//! Admission for removal of original protected-capture audit evidence.
use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, ensure};
use ed25519_dalek::VerifyingKey;
use mvm_core::audit_verify::set::read_verified_set;
use mvm_core::transcript::evidence::{
    LABEL_CAPTURE_ID, TRANSCRIPT_OPENED_EVENT, TRANSCRIPT_RETIRED_EVENT, TRANSCRIPT_SEALED_EVENT,
    authenticate_opening, authenticated_retirement_at, authenticated_seal,
};
use mvm_core::transcript::verify_sealed_root;

#[path = "prune_inventory.rs"]
mod inventory;

pub(crate) struct PinGuard {
    _inventory: inventory::Inventory,
}

pub(crate) fn validate_tenant(tenant: &str) -> Result<()> {
    let mut components = Path::new(tenant).components();
    ensure!(
        matches!(components.next(), Some(std::path::Component::Normal(name)) if name == tenant)
            && components.next().is_none(),
        "invalid prune tenant component"
    );
    Ok(())
}

/// Call only with the tenant chain lock held, and retain the returned guard
/// until after recording and unlinking the prefix. Never wait for a capture
/// lease: producers take those before entering the audit-chain transaction.
pub(crate) fn admit(
    dir: &Path,
    tenant: &str,
    key: &VerifyingKey,
    through: u64,
) -> Result<PinGuard> {
    validate_tenant(tenant)?;
    let segments = read_verified_set(dir, tenant, key)
        .map_err(|_| anyhow::anyhow!("protected evidence chain verification refused"))?;
    let inventory = inventory::Inventory::read(dir, tenant)?;
    let mut protected = BTreeSet::new();
    let mut legacy = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for capture in &inventory.captures {
        let identity = capture
            .seed
            .as_ref()
            .or(capture.manifest.as_ref())
            .ok_or_else(|| anyhow::anyhow!("protected candidate has no verification metadata"))?;
        verify_sealed_root(identity)
            .map_err(|_| anyhow::anyhow!("protected candidate root verification refused"))?;
        ensure!(
            seen.insert((
                identity.binding.tenant_id.clone(),
                identity.capture_id.clone()
            )),
            "duplicate protected candidate identity"
        );
        ensure!(
            capture.vm_component.is_none() || identity.at_rest.is_none() || capture.seed.is_some(),
            "managed protected candidate opening metadata absent"
        );
        ensure!(
            capture
                .vm_component
                .as_ref()
                .is_none_or(|vm| { *vm == hex::encode(identity.binding.vm_name.as_bytes()) })
                && capture
                    .tenant_component
                    .as_ref()
                    .is_none_or(|tenant| { *tenant == identity.binding.tenant_id })
                && capture
                    .capture_component
                    .as_ref()
                    .is_none_or(|id| *id == identity.capture_id),
            "protected candidate managed identity mismatch"
        );

        let opening =
            if let Some(seed) = &capture.seed {
                Some(authenticate_opening(dir, key, seed).map_err(|_| {
                    anyhow::anyhow!("protected candidate opening authority refused")
                })?)
            } else {
                None
            };
        if let Some(manifest) = &capture.manifest {
            if let Some(seed) = &capture.seed {
                ensure!(
                    seed.capture_id == manifest.capture_id
                        && seed.binding == manifest.binding
                        && seed.at_rest == manifest.at_rest,
                    "protected candidate seed and manifest conflict"
                );
            }
            let seal = if manifest.at_rest.is_some() {
                authenticated_retirement_at(dir, key, manifest, None)
                    .map(|proof| proof.0)
                    .map_err(|_| {
                        anyhow::anyhow!("protected candidate seal or retirement authority refused")
                    })?
            } else {
                authenticated_seal(dir, key, manifest)
                    .map_err(|_| anyhow::anyhow!("legacy candidate seal authority refused"))?
                    .ok_or_else(|| {
                        anyhow::anyhow!("candidate enrollment cannot be authenticated")
                    })?
            };
            if let Some(mut opening) = opening {
                opening.timestamp = seal.timestamp;
                opening.event = seal.event.clone();
                opening.labels = seal.labels.clone();
                ensure!(
                    opening == seal,
                    "protected opening and seal attribution conflict"
                );
            }
            if manifest.binding.tenant_id == tenant {
                if manifest.at_rest.is_some() {
                    protected.insert(manifest.capture_id.clone());
                } else {
                    legacy.insert(manifest.capture_id.clone());
                }
            }
        } else if identity.binding.tenant_id == tenant {
            ensure!(
                opening.is_some(),
                "protected candidate opening authority absent"
            );
            protected.insert(identity.capture_id.clone());
        }
    }

    // Opening publication shares this lock. Metadata is never disposed by the
    // retention owner. Keep every signed opening even if its metadata is not
    // yet visible: a newly created family cannot introduce old evidence after
    // the inventory scan. A later opening can only land in the surviving chain.
    for segment in &segments {
        for entry in segment.entries.as_deref().unwrap_or_default() {
            if entry.event == TRANSCRIPT_OPENED_EVENT {
                ensure!(
                    entry.tenant.0 == tenant,
                    "protected opening tenant conflict"
                );
                let id = entry
                    .labels
                    .get(LABEL_CAPTURE_ID)
                    .ok_or_else(|| anyhow::anyhow!("protected opening identity absent"))?;
                ensure!(
                    !legacy.contains(id),
                    "protected opening conflicts with legacy metadata"
                );
                protected.insert(id.clone());
            }
        }
    }
    for segment in &segments {
        if segment.active || segment.seq > through {
            continue;
        }
        for entry in segment.entries.as_deref().unwrap_or_default() {
            if !matches!(
                entry.event.as_str(),
                TRANSCRIPT_OPENED_EVENT | TRANSCRIPT_SEALED_EVENT | TRANSCRIPT_RETIRED_EVENT
            ) {
                continue;
            }
            ensure!(
                entry.tenant.0 == tenant,
                "protected evidence tenant conflict"
            );
            let id = entry
                .labels
                .get(LABEL_CAPTURE_ID)
                .ok_or_else(|| anyhow::anyhow!("capture evidence identity absent"))?;
            if protected.contains(id) {
                anyhow::bail!(
                    "protected capture evidence pins segment {}; retain original opening, seal and retirement intent; missing metadata does not establish release",
                    segment.seq
                );
            }
            ensure!(
                legacy.contains(id) && entry.event == TRANSCRIPT_SEALED_EVENT,
                "capture evidence enrollment is unknown; refusing candidate segment {}",
                segment.seq
            );
        }
    }
    Ok(PinGuard {
        _inventory: inventory,
    })
}

#[cfg(test)]
thread_local! {
    static COMMIT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static FAIL_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn sync_boundary() -> std::io::Result<()> {
    if FAIL_SYNC.replace(false) {
        return Err(std::io::Error::other("injected directory sync failure"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn commit_boundary() {
    let hook = COMMIT_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::{AuditSigner, PlanAuditEntry};
    use crate::supervisor::audit_file::{FileAuditSigner, RotationPolicy};
    use mvm_core::plan::{PlanId, TenantId};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn tenant_inventory_components_never_escape_the_managed_root() {
        for tenant in [
            "",
            "/",
            "/outside",
            "..",
            ".",
            "../outside",
            "a/b",
            "a/",
            "./a",
            "a/../b",
        ] {
            assert!(validate_tenant(tenant).is_err(), "{tenant}");
        }
        // On Unix a backslash or colon is an ordinary filename character, not
        // a separator or drive prefix. This module is Unix-only.
        for tenant in ["local", "tenant-1", "tenant_2", "a\\b", "C:tenant"] {
            assert!(validate_tenant(tenant).is_ok(), "{tenant}");
        }
        let root = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(
            ed25519_dalek::SigningKey::from_bytes(&[73; 32]),
            root.path(),
        )
        .unwrap();
        for tenant in ["/", "../outside", "a/b"] {
            assert!(signer.prune_through(&TenantId(tenant.into()), 1).is_err());
            assert!(
                signer
                    .check_prune_pins(&TenantId(tenant.into()), 1)
                    .is_err()
            );
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    async fn rotated() -> (tempfile::TempDir, FileAuditSigner) {
        let root = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        let signer = FileAuditSigner::open(key, root.path())
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(1));
        for _ in 0..3 {
            signer
                .sign_and_emit(&PlanAuditEntry {
                    timestamp: chrono::Utc::now(),
                    tenant: TenantId("local".into()),
                    plan_id: PlanId("synthetic-run".into()),
                    plan_version: 1,
                    bundle_id: None,
                    bundle_version: None,
                    image_name: "synthetic".into(),
                    image_sha256: "0".repeat(64),
                    event: "plan.launched".into(),
                    caller_commitment: None,
                    labels: Default::default(),
                })
                .await
                .unwrap();
        }
        (root, signer)
    }

    #[tokio::test]
    async fn commit_boundary_holds_audit_and_inventory_leases_together() {
        let (root, signer) = rotated().await;
        let family = root.path().join("workload-output").join(hex::encode("vm"));
        mvm_core::config::create_private_dir(&family).unwrap();
        let lock = root.path().join("local.jsonl.lock");
        let segment = root.path().join("local.seg-000001.jsonl");
        let observed = Arc::new(AtomicBool::new(false));
        let hit = Arc::clone(&observed);
        COMMIT_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                assert!(segment.exists(), "hook must precede prune mutation");
                for path in [&family, &lock] {
                    let competing = std::fs::File::open(path).unwrap();
                    assert!(
                        rustix::fs::flock(
                            &competing,
                            rustix::fs::FlockOperation::NonBlockingLockExclusive,
                        )
                        .is_err(),
                        "competing owner acquired a commit-held lease"
                    );
                }
                hit.store(true, Ordering::SeqCst);
            }))
        });
        signer.prune_through(&TenantId("local".into()), 1).unwrap();
        assert!(observed.load(Ordering::SeqCst));
        assert!(!root.path().join("local.seg-000001.jsonl").exists());
    }

    #[tokio::test]
    async fn sync_failure_reports_committed_removal_not_an_unchanged_refusal() {
        let (root, signer) = rotated().await;
        FAIL_SYNC.set(true);
        let error = signer
            .prune_through(&TenantId("local".into()), 1)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("prune recorded and segments removed")
        );
        assert!(!root.path().join("local.seg-000001.jsonl").exists());
        let verification = mvm_core::audit_verify::set::verify_segment_set(
            root.path(),
            "local",
            &ed25519_dalek::SigningKey::from_bytes(&[73; 32]).verifying_key(),
        )
        .unwrap();
        assert_eq!(verification.pruned.unwrap().through, 1);
        assert!(
            signer
                .prune_through(&TenantId("local".into()), 1)
                .unwrap_err()
                .to_string()
                .contains("already pruned")
        );
    }
}
