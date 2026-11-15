//! Match a volume against the signed share grant before attachment.

use anyhow::Result;
use mvm_core::plan::{ExecutionPlan, HostShareGrant, ShareKind};
use mvm_core::vm_backend::VmVolume;

pub(super) fn matches_grant(grant: &HostShareGrant, volume: &VmVolume, kind: ShareKind) -> bool {
    grant.host_path == volume.host
        && grant.guest_path == volume.guest
        && grant.kind == kind
        && grant.read_only == volume.read_only
        && grant.encrypted == volume.encrypted
        // Bind the deny set at claim time: a re-bind cannot hand the guest a
        // different tree from the one the signed plan admitted.
        && grant.include == volume.share_include
        && grant.exclude == volume.share_exclude
}

/// Admission enforcement: every volume about to be attached must be
/// named in the verified `ExecutionPlan.shares`, with matching
/// host path, guest path, kind, ro/rw, and encryption.
///
/// On the local `mvmctl machine run` path the CLI builds both the signed
/// plan and the launch config from one source, so this is self-consistent
/// by construction — but it **fails closed** if they ever diverge (a CLI
/// bug, or a future caller that hands a config the plan didn't authorize).
/// It's the trust-boundary hook: no host-fs grant reaches a guest unless
/// the signed plan admitted it (claim 1 / claim 8). The supervisor +
/// mvmd enforcement mirror this check against the same `plan.shares`.
pub fn enforce_admitted_shares(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan: &ExecutionPlan,
) -> Result<()> {
    for v in volumes {
        let want_kind = if v.materialized_image.is_some() {
            mvm_core::plan::ShareKind::DirShare
        } else {
            mvm_core::plan::ShareKind::Disk
        };
        let admitted = plan.shares.iter().find(|g| matches_grant(g, v, want_kind));
        let Some(grant) = admitted else {
            anyhow::bail!(
                "refusing to attach volume '{}' -> '{}' ({}): it is not named in the signed \
                 ExecutionPlan's admitted shares — every host-fs grant must be admitted (claim 1).",
                v.host,
                v.guest,
                if v.read_only { "ro" } else { "rw" },
            );
        };
        // Content identity (claim 19): a grant that recorded what the shared
        // tree hashed to at admission must still hash the same at attach
        // time. The admitted digest is inside the signed plan, so this closes
        // the window between admission and boot where the host directory
        // could change under the granted path — the guest would otherwise
        // receive bytes the plan never vouched for.
        if let Some(expected) = &grant.content_sha256 {
            // Canonicalize so a symlinked host dir (macOS `/tmp`) hashes
            // the same tree admission pinned, whichever alias names it.
            let actual = if let Some(image) = &v.materialized_image {
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(image)).map_err(
                    |e| {
                        anyhow::anyhow!(
                            "refusing to attach volume '{}' -> '{}': cannot re-hash frozen image \
                             '{}': {e}",
                            v.host,
                            v.guest,
                            image,
                        )
                    },
                )?
            } else {
                let resolved = std::fs::canonicalize(&v.host)?;
                mvm_fs::hash::hash_source(&resolved).map_err(|e| {
                    anyhow::anyhow!(
                        "refusing to attach volume '{}' -> '{}': cannot re-hash the granted \
                         directory to check its admitted content identity: {e}",
                        v.host,
                        v.guest,
                    )
                })?
            };
            if actual != *expected {
                anyhow::bail!(
                    "refusing to attach volume '{}' -> '{}': the directory changed after \
                     admission — admitted content identity {expected}, now {actual}. Re-admit \
                     the plan against the current tree.",
                    v.host,
                    v.guest,
                );
            }
        }
    }
    Ok(())
}
