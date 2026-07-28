//! Same-page-merge confinement policy: the pure decision of whether two
//! guest-memory merge candidates may have their pages host-wide merged
//! (KSM-style content-based deduplication).
//!
//! Density benefits from sharing identical guest pages, but host-wide
//! same-page merging across unrelated guests is a cross-VM timing side
//! channel: a write to a merged page faults measurably slower than a write to
//! an unmerged one, leaking co-residency and page contents across the
//! boundary and amplifying rowhammer. This module answers only "may these two
//! scopes share pages" as a pure function of their identity; it does not
//! touch the kernel merge knob, `madvise`, or fault timing, and it performs no
//! I/O — the runtime enforcement that actually enables or disables merging is
//! a separate concern.
//!
//! Confinement rule: page sharing is permitted only *within a single fork
//! family* — the paused parent and every child forked from it, all running
//! the same sealed image for the same tenant. It is refused across tenants
//! and across distinct workload images, even when the fork family happens to
//! coincide (which should not otherwise occur, but the check does not assume
//! it).

use crate::checkpoint::CheckpointId;
use crate::plan::{SignedImageRef, TenantId};

/// Identity of one merge candidate: the tenant it belongs to, the sealed
/// image it runs, and the fork family it descends from.
///
/// `fork_family` is keyed on the paused parent's [`CheckpointId`]: every
/// sibling forked from the same paused parent carries that parent's
/// checkpoint id here, so "same fork family" reduces to "forked from the same
/// paused parent" rather than a separately maintained identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageMergeScope {
    pub tenant: TenantId,
    pub image: SignedImageRef,
    pub fork_family: CheckpointId,
}

/// Whether same-page merging may occur between two [`PageMergeScope`]s.
///
/// Fails closed: [`Default`] resolves to `Refuse`, never `Permit`, so any
/// code path that constructs a decision without explicitly reaching
/// `Permit` — an unconfigured policy, a placeholder, a future variant this
/// module doesn't yet model — refuses merging rather than allowing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergeDecision {
    Permit,
    #[default]
    Refuse,
}

/// Decide whether pages from `a` and `b` may be same-page-merged.
///
/// `Permit` iff `a` and `b` agree on tenant, sealed image, and fork family.
/// Any mismatch on any field — including ones this function doesn't
/// distinguish by name — refuses, since equality across every field is the
/// only path to `Permit`.
pub fn may_merge(a: &PageMergeScope, b: &PageMergeScope) -> MergeDecision {
    if a.tenant == b.tenant && a.image == b.image && a.fork_family == b.fork_family {
        MergeDecision::Permit
    } else {
        MergeDecision::Refuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(tenant: &str, image_sha256: &str, fork_family: &str) -> PageMergeScope {
        PageMergeScope {
            tenant: TenantId(tenant.to_string()),
            image: SignedImageRef {
                name: "example-image".to_string(),
                sha256: image_sha256.to_string(),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            fork_family: CheckpointId::new(fork_family),
        }
    }

    #[test]
    fn may_merge_permits_same_family_same_image_same_tenant() {
        let a = scope("tenant-a", "deadbeef", "parent-1");
        let b = scope("tenant-a", "deadbeef", "parent-1");
        assert_eq!(may_merge(&a, &b), MergeDecision::Permit);
    }

    #[test]
    fn may_merge_refuses_different_tenant() {
        let a = scope("tenant-a", "deadbeef", "parent-1");
        let b = scope("tenant-b", "deadbeef", "parent-1");
        assert_eq!(may_merge(&a, &b), MergeDecision::Refuse);
    }

    #[test]
    fn may_merge_refuses_different_image() {
        let a = scope("tenant-a", "deadbeef", "parent-1");
        let b = scope("tenant-a", "cafef00d", "parent-1");
        assert_eq!(may_merge(&a, &b), MergeDecision::Refuse);
    }

    #[test]
    fn may_merge_refuses_different_fork_family() {
        let a = scope("tenant-a", "deadbeef", "parent-1");
        let b = scope("tenant-a", "deadbeef", "parent-2");
        assert_eq!(may_merge(&a, &b), MergeDecision::Refuse);
    }

    #[test]
    fn default_decision_is_refuse() {
        assert_eq!(MergeDecision::default(), MergeDecision::Refuse);
    }
}
