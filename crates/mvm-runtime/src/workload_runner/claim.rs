//! Fail-closed reasons a warm-pool claim can be refused, and the outcome type
//! the bind gate returns. Kept separate from the crate-wide `anyhow::Result`
//! convention: refusals here are a closed set the caller must exhaustively
//! handle (audit, retry, or surface to the operator), not an open-ended error
//! bag.

use mvm_core::checkpoint::CheckpointMeta;
use mvm_core::vm_backend::VmId;

#[derive(Debug, thiserror::Error)]
pub enum ClaimRefusal {
    #[error("parent is not in a claimable state")]
    ParentNotClaimable,
    #[error("parent has no signed audit entry; refusing to fork an un-audited parent")]
    ParentUnaudited,
    #[error("parent record drifted from its sealed content; refusing a tampered parent")]
    ParentTampered,
    #[error("child plan is outside its validity window")]
    PlanExpired,
    #[error("child plan nonce was already seen; refusing a replayed claim")]
    PlanReplayed,
    #[error("plan image digest {expected} does not match parent rootfs digest {got}")]
    PlanParentMismatch { expected: String, got: String },
    #[error("refusing to run a workload directly on a warm parent")]
    ParentPromotionRefused,
}

#[derive(Debug)]
pub enum ClaimOutcome {
    Claimed(VmId),
    Refused(ClaimRefusal),
}

/// Name of the [`mvm_core::checkpoint::ContentBlob`] holding the parent's
/// sealed rootfs image. `verify_content` (run earlier in the claim) already
/// proved this blob's `sha256` equals the file on disk, so comparing a plan's
/// image digest against it transitively binds the plan to the exact bytes
/// that boot.
const ROOTFS_BLOB_NAME: &str = "rootfs.ext4";

/// The parent checkpoint's verified rootfs digest (bare 64-hex, no `sha256:`
/// prefix), or a refusal if the parent carries no `rootfs.ext4` blob.
pub fn parent_rootfs_digest(meta: &CheckpointMeta) -> Result<&str, ClaimRefusal> {
    meta.content
        .iter()
        .find(|b| b.name == ROOTFS_BLOB_NAME)
        .map(|b| b.sha256.as_str())
        .ok_or_else(|| ClaimRefusal::PlanParentMismatch {
            expected: String::new(),
            got: String::from("<parent carries no rootfs.ext4 blob>"),
        })
}

/// Binds an admitted plan's image digest to the verified parent's actual
/// rootfs so the audit-recorded plan always describes exactly what boots.
/// `plan_image_sha256` is `plan.image.sha256` — bare 64-hex, compared
/// directly against the parent's bare-hex blob digest.
pub fn bind_plan_to_parent(
    plan_image_sha256: &str,
    meta: &CheckpointMeta,
) -> Result<(), ClaimRefusal> {
    let parent = parent_rootfs_digest(meta)?;
    if parent == plan_image_sha256 {
        Ok(())
    } else {
        Err(ClaimRefusal::PlanParentMismatch {
            expected: plan_image_sha256.to_string(),
            got: parent.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, ContentBlob};

    fn fake_meta_with_rootfs(hex: String) -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new("cp-test"),
            CheckpointClass::FsQuick,
            "vm-test",
        )
        .content(vec![ContentBlob {
            name: ROOTFS_BLOB_NAME.to_string(),
            sha256: hex,
        }])
        .build()
    }

    fn fake_meta_without_rootfs() -> CheckpointMeta {
        CheckpointMeta::builder(
            CheckpointId::new("cp-test"),
            CheckpointClass::FsQuick,
            "vm-test",
        )
        .build()
    }

    #[test]
    fn bind_accepts_matching_and_rejects_mismatched_rootfs() {
        let meta = fake_meta_with_rootfs("aa".repeat(32));
        // matching
        assert!(bind_plan_to_parent(&"aa".repeat(32), &meta).is_ok());
        // mismatch -> PlanParentMismatch
        let err = bind_plan_to_parent(&"bb".repeat(32), &meta).unwrap_err();
        assert!(matches!(err, ClaimRefusal::PlanParentMismatch { .. }));
    }

    #[test]
    fn parent_without_rootfs_blob_refuses() {
        let meta = fake_meta_without_rootfs();
        assert!(matches!(
            bind_plan_to_parent(&"aa".repeat(32), &meta),
            Err(ClaimRefusal::PlanParentMismatch { .. })
        ));
    }

    #[test]
    fn refusal_reasons_are_distinct_and_described() {
        let m = ClaimRefusal::PlanParentMismatch {
            expected: "sha256:aa".into(),
            got: "sha256:bb".into(),
        };
        assert!(m.to_string().contains("sha256:aa"));
        assert!(m.to_string().contains("sha256:bb"));
        // Distinct variants must not compare equal.
        assert_ne!(
            ClaimRefusal::ParentUnaudited.to_string(),
            ClaimRefusal::ParentTampered.to_string()
        );
    }
}
