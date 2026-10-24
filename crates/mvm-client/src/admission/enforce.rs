//! Boot-time enforcement of an admitted plan: the volumes about to attach
//! and the kernel about to load must be the ones the signed plan named.

use anyhow::{Context, Result};

use super::AdmissionContext;

/// Tier A.1 admission enforcement: refuse to boot if any volume about to
/// be attached isn't named in the verified `ExecutionPlan.shares`, so no
/// host-fs grant reaches a guest unless the signed plan admitted it
/// (claim 1 / claim 8).
pub fn enforce_shares(
    ctx: &AdmissionContext,
    volumes: &[mvm_core::vm_backend::VmVolume],
) -> Result<()> {
    mvm_hostd::plan_admission::enforce_admitted_shares(volumes, ctx.admitted.plan())
        .context("admission share check")
}

/// The claim-time sibling of [`enforce_shares`]: re-check every volume a warm
/// claim will attach against the shares its signed plan admitted, immediately
/// before the claim, exactly as a cold boot checks them before it attaches
/// anything. The volume must be named by the plan, and a directory whose
/// content digest the plan pinned must still hash to it. A launch with no
/// volumes attaches nothing, so its plan is never decoded here.
pub fn enforce_shares_for_claim(
    volumes: &[mvm_core::vm_backend::VmVolume],
    plan_json: &str,
) -> Result<()> {
    if volumes.is_empty() {
        return Ok(());
    }
    let plan = mvm_core::plan::plan_from_admitted_json(plan_json)
        .context("a warm claim attaching volumes needs its admitted plan")?;
    mvm_hostd::plan_admission::enforce_admitted_shares(volumes, &plan)
        .context("checking the volumes a warm claim attaches against its admitted shares")
}

/// Refuse to boot if the kernel about to be loaded is not the one the verified
/// `ExecutionPlan` pinned.
///
/// The sibling of [`enforce_shares`], called at the same point for the same
/// reason: `mvmctl` admits its plan and then starts the backend itself rather
/// than going through `start_admitted`, so every gate that path runs has to be
/// run here too or it does not run at all. The admitted-environment gate was
/// the one nobody called.
pub fn enforce_kernel(ctx: &AdmissionContext, kernel_path: Option<&std::path::Path>) -> Result<()> {
    mvm_hostd::plan_admission::enforce_admitted_environment(kernel_path, ctx.admitted.plan())
        .context("admission kernel check")
}

#[cfg(test)]
mod claim_shares_tests {
    use super::*;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::vm_backend::VmVolume;

    fn read_only_mount(guest: &str) -> VmVolume {
        VmVolume {
            host: "/workspace".into(),
            guest: guest.into(),
            materialized_image: Some(format!("/cache{guest}.ext4")),
            read_only: true,
            ..Default::default()
        }
    }

    /// A volume the signed plan never admitted is refused before any parent is
    /// touched, and so is a launch with volumes whose plan cannot be read.
    #[test]
    fn a_volume_the_plan_did_not_admit_is_refused_before_the_claim() {
        let volumes = vec![read_only_mount("/data")];
        let plan = PlanFixture::new().build();
        let plan_json = serde_json::to_string(&plan).unwrap();
        let err = enforce_shares_for_claim(&volumes, &plan_json).unwrap_err();
        assert!(
            format!("{err:#}").contains("not named in the signed"),
            "{err:#}"
        );
        assert!(enforce_shares_for_claim(&volumes, "not a plan").is_err());
        assert!(enforce_shares_for_claim(&[], "not a plan").is_ok());
    }

    /// The content digest a plan pinned for a mount is re-checked right before
    /// the claim, as a cold boot re-checks it: an image whose bytes changed
    /// after admission is refused, the unchanged one is attached.
    #[test]
    fn a_mount_whose_bytes_changed_after_admission_is_refused_before_the_claim() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("mount.ext4");
        std::fs::write(&image, b"admitted bytes").unwrap();
        let mut volume = read_only_mount("/data");
        volume.materialized_image = Some(image.display().to_string());
        let volumes = vec![volume.clone()];

        let mut plan = PlanFixture::new().build();
        plan.shares = vec![mvm_core::plan::HostShareGrant {
            tag: "uvol0".into(),
            host_path: volume.host.clone(),
            guest_path: volume.guest.clone(),
            kind: mvm_core::plan::ShareKind::DirShare,
            read_only: true,
            encrypted: false,
            content_sha256: Some(mvm_core::crypto::image_verify::sha256_file(&image).unwrap()),
        }];
        let plan_json = serde_json::to_string(&plan).unwrap();
        enforce_shares_for_claim(&volumes, &plan_json).expect("unchanged bytes are attached");

        std::fs::write(&image, b"changed after admission").unwrap();
        assert!(
            enforce_shares_for_claim(&volumes, &plan_json).is_err(),
            "bytes the plan never vouched for must not reach a claimed child"
        );
    }
}
