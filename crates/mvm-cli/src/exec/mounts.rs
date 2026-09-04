use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};

use crate::commands::DirShareSpec;

/// The ext4 volume label for the `index`-th `--mount` image.
///
/// One authority, called both when the image is written and when the volume
/// that describes it is built: if those two disagreed the guest would look for
/// a label that is not on the bytes and fall back to the device node, silently
/// losing the identity check this exists to provide.
///
/// ext4 caps a volume label at 16 bytes; `mvmmnt` plus a `usize` stays inside
/// that for any plausible mount count.
pub(crate) fn mount_volume_label(index: usize) -> String {
    format!("mvmmnt{index}")
}

/// Turn each `--mount` into a volume backed by a materialized ext4 image.
///
/// `host` stays the directory that was granted so the admission record names
/// it; `materialized_image` carries what the backend attaches.
pub(crate) fn materialize_mount_volumes(
    shares: &[DirShareSpec],
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<Vec<VmVolume>> {
    use crate::commands::vm::phase_timing::SubPhase;

    if shares.is_empty() {
        return Ok(Vec::new());
    }
    let cache = crate::mount_cache::MountImageCache::new()?;
    sub.start(SubPhase::MountFingerprint);
    let fingerprints = shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            cache.fingerprint(
                std::path::Path::new(&share.host_dir),
                &mount_volume_label(index),
            )
        })
        .collect::<Result<Vec<_>>>();
    sub.finish(SubPhase::MountFingerprint);
    let fingerprints = fingerprints?;

    sub.start(SubPhase::MountCacheLookup);
    // Cache misses retain their per-key lock through materialization. Acquire
    // keys in one stable order so concurrent launches with the same mounts
    // cannot wait on each other in opposite orders.
    let mut indexed_fingerprints = fingerprints.into_iter().enumerate().collect::<Vec<_>>();
    indexed_fingerprints.sort_by(|(_, left), (_, right)| left.cache_key().cmp(right.cache_key()));
    let mut indexed_lookups = (0..shares.len()).map(|_| None).collect::<Vec<_>>();
    for (index, fingerprint) in indexed_fingerprints {
        indexed_lookups[index] = Some(cache.lookup(fingerprint)?);
    }
    let lookups = indexed_lookups
        .into_iter()
        .map(|lookup| lookup.expect("every mount fingerprint has one cache lookup"))
        .collect::<Vec<_>>();
    sub.finish(SubPhase::MountCacheLookup);
    let materialized = lookups.iter().any(|lookup| lookup.is_miss());
    if materialized {
        sub.start(SubPhase::MountMaterialize);
    }
    let volumes = shares
        .iter()
        .zip(lookups)
        .enumerate()
        .map(|(index, (share, lookup))| {
            let image = lookup.resolve()?;
            Ok(VmVolume {
                host: share.host_dir.clone(),
                guest: share.guest_mount.clone(),
                read_only: share.read_only,
                kind: VmVolumeKind::DirShare,
                materialized_image: Some(image.path().display().to_string()),
                // Same authority the image was written with, so the guest
                // mounts the label that is actually on the bytes.
                volume_label: Some(mount_volume_label(index)),
                ..Default::default()
            })
        })
        .collect();
    if materialized {
        sub.finish(SubPhase::MountMaterialize);
    }
    volumes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_mounts_create_no_state_or_volumes() {
        let mut sub = crate::commands::vm::phase_timing::LaunchSubMarks::new(true);
        assert!(materialize_mount_volumes(&[], &mut sub).unwrap().is_empty());
    }

    #[test]
    fn a_missing_host_directory_is_refused() {
        let scratch = tempfile::TempDir::new().unwrap();
        let share = DirShareSpec {
            host_dir: scratch.path().join("missing").display().to_string(),
            guest_mount: "/work".to_string(),
            read_only: true,
        };
        let mut sub = crate::commands::vm::phase_timing::LaunchSubMarks::new(true);
        let err = materialize_mount_volumes(&[share], &mut sub).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err:#}");
    }

    #[test]
    fn mount_cache_miss_and_hit_produce_the_declared_timing_spans() {
        use crate::commands::vm::phase_timing::SubPhase;

        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(scratch.path());
        let source = scratch.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("marker"), b"content").unwrap();
        let share = DirShareSpec {
            host_dir: source.display().to_string(),
            guest_mount: "/work".to_string(),
            read_only: true,
        };

        let mut miss_marks = crate::commands::vm::phase_timing::LaunchSubMarks::new(true);
        let miss =
            materialize_mount_volumes(std::slice::from_ref(&share), &mut miss_marks).unwrap();
        assert!(miss_marks.recorded(SubPhase::MountFingerprint));
        assert!(miss_marks.recorded(SubPhase::MountCacheLookup));
        assert!(miss_marks.recorded(SubPhase::MountMaterialize));

        let mut hit_marks = crate::commands::vm::phase_timing::LaunchSubMarks::new(true);
        let hit = materialize_mount_volumes(&[share], &mut hit_marks).unwrap();
        assert!(hit_marks.recorded(SubPhase::MountFingerprint));
        assert!(hit_marks.recorded(SubPhase::MountCacheLookup));
        assert!(!hit_marks.recorded(SubPhase::MountMaterialize));
        assert_eq!(miss[0].materialized_image, hit[0].materialized_image);
    }
}

/// Refuse a launch whose SDK sidecar the guest could not `dlopen`.
///
/// The check itself is admission's, in `mvm-hostd`, and it runs there for
/// callers that go through `admit_and_start`. `mvmctl run` does not — it admits
/// through `admit_for_run`, which skips the post-admission gates — so without
/// this call the refusal never fires on the path most workloads take, and a
/// libc mismatch surfaces inside the guest as a relocation error instead.
///
/// `plan_json` is `None` for a launch that was not admitted (a template
/// restore), which carries no host-service binding and so nothing to check.
/// When present it is the *signed* envelope the supervisor receives, not a bare
/// plan — the payload has to be opened to read the bindings.
pub(crate) fn refuse_unloadable_sidecar(
    rootfs: &str,
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan_json: Option<&str>,
) -> Result<()> {
    let Some(plan_json) = plan_json else {
        return Ok(());
    };
    let signed: mvm_core::plan::SignedExecutionPlan = serde_json::from_str(plan_json)
        .context("re-reading the admitted plan to check the SDK sidecar attachment")?;
    let plan: mvm_core::plan::ExecutionPlan = serde_json::from_slice(&signed.0.payload)
        .context("reading the admitted plan's payload to check the SDK sidecar attachment")?;
    mvm_hostd::plan_admission::enforce_sdk_sidecar_for_launch(rootfs, volumes, &plan)
}

#[cfg(test)]
mod sidecar_gate_tests {
    use super::*;

    /// A launch that was never admitted carries no binding, so there is nothing
    /// to check and nothing to refuse. Template restores take this path.
    #[test]
    fn an_unadmitted_launch_is_not_refused() {
        refuse_unloadable_sidecar("/img/rootfs.ext4", &[], None)
            .expect("a launch with no admitted plan has no binding to check");
    }

    /// A plan that does not deserialize is an error rather than a skip: the
    /// alternative is treating an unreadable authority as "nothing bound".
    #[test]
    fn an_unreadable_plan_refuses_rather_than_skipping() {
        let err = refuse_unloadable_sidecar("/img/rootfs.ext4", &[], Some("{not json"))
            .expect_err("an unreadable plan must not be treated as unbound");
        assert!(
            format!("{err:#}").contains("re-reading the admitted plan"),
            "{err:#}"
        );
    }

    /// What the run path actually hands over is the signed envelope, not a bare
    /// plan. A test that built an `ExecutionPlan` directly accepted a shape the
    /// launch never produces, and the mismatch only surfaced when a real guest
    /// booted — so the fixture here is the envelope, serialized the same way
    /// admission writes it.
    #[test]
    fn the_signed_envelope_is_what_the_run_path_hands_over() {
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let signed =
            mvm_core::plan::SignedExecutionPlan(mvm_contract::protocol::signing::SignedPayload {
                payload: serde_json::to_vec(&plan).expect("serialize the plan payload"),
                signature: Vec::new(),
                signer_id: "test".to_string(),
            });
        let envelope = serde_json::to_string(&signed).expect("serialize the envelope");

        refuse_unloadable_sidecar("/img/rootfs.ext4", &[], Some(&envelope))
            .expect("a plan binding no SDK service and carrying no sidecar is admissible");
    }
}
