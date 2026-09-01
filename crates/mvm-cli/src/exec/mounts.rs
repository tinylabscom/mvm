use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};

use crate::commands::DirShareSpec;

/// Turn each `--mount` into a volume backed by a materialized ext4 image.
///
/// `host` stays the directory that was granted so the admission record names
/// it; `materialized_image` carries what the backend attaches.
pub(crate) fn materialize_mount_volumes(
    shares: &[DirShareSpec],
    vm_name: &str,
) -> Result<Vec<VmVolume>> {
    if shares.is_empty() {
        return Ok(Vec::new());
    }
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    std::fs::create_dir_all(&state_dir).with_context(|| {
        format!(
            "creating the VM state directory {} for --mount images",
            state_dir.display()
        )
    })?;
    shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            let image = materialize_mount_image(share, &state_dir, index)?;
            Ok(VmVolume {
                host: share.host_dir.clone(),
                guest: share.guest_mount.clone(),
                read_only: share.read_only,
                kind: VmVolumeKind::DirShare,
                materialized_image: Some(image.display().to_string()),
                ..Default::default()
            })
        })
        .collect()
}

/// Materialize a granted host directory into an ext4 image and return its path.
///
/// `--mount` used to attach the directory itself over virtio-fs. That put a
/// FUSE server on the host, parsing requests the guest composed, pointed at a
/// host directory — the one mechanism by which a guest addressed host
/// filesystem *structure* rather than opaque blocks. An image has no protocol
/// for a guest to drive.
///
/// The image is written by the same pure-Rust ext4 writer that materializes
/// every rootfs: no `mkfs`, no subprocess, and — the part that matters here —
/// it reads host bytes rather than guest requests, so it is not a surface the
/// guest can reach at all.
///
/// The directory is read as-is, unfiltered. The builder's own
/// dir-to-image packer excludes build outputs because it is packing *this*
/// workspace for a Nix build; a user who mounts a directory means the
/// directory.
///
/// # What a caller loses
///
/// The image is a snapshot taken now. Host edits during the run are not
/// visible to the guest. `--mount` was already read-only — the CLI refuses
/// `rw` with "transient live shares are read-only" — so mid-run visibility is
/// the only property that goes.
pub(crate) fn materialize_mount_image(
    share: &DirShareSpec,
    state_dir: &std::path::Path,
    index: usize,
) -> Result<std::path::PathBuf> {
    let host_dir = std::path::PathBuf::from(&share.host_dir);
    if !host_dir.is_dir() {
        anyhow::bail!(
            "--mount {}:{}: the host path is not a directory",
            share.host_dir,
            share.guest_mount
        );
    }
    let output = state_dir.join(format!("mount-{index}.ext4"));
    // Labelled so the guest mounts by identity rather than by enumeration
    // order, the same reason `stage0-init` reads its work disk by label.
    let label = format!("mvmmnt{index}");
    let input = mvm_build::rootfs::MaterializeExt4Input::builder()
        .unpacked_root(host_dir.clone())
        .output(output.clone())
        .uncompressed_size_bytes(tree_size_bytes(&host_dir))
        .volume_label(label)
        .emit_verity(false)
        // Only an OCI unpack on a case-folding host defers nodes; a host
        // directory is read as it is.
        .deferred_nodes(Vec::new())
        .build()
        .context("assembling the mount image inputs")?;
    mvm_build::rootfs::materialize_ext4_pure(&input).with_context(|| {
        format!(
            "materializing --mount {} into an ext4 image",
            share.host_dir
        )
    })?;
    Ok(output)
}

/// Sum of the regular-file bytes under `dir`, for sizing the image.
///
/// Best effort: an entry that cannot be read contributes nothing rather than
/// failing the launch, because this only feeds a size *estimate* and the
/// writer grows the image to fit what it actually writes. Symlinks are not
/// followed, so a link out of the tree is counted as the link it is.
fn tree_size_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                pending.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_mounts_create_no_state_or_volumes() {
        assert!(materialize_mount_volumes(&[], "unused").unwrap().is_empty());
    }

    #[test]
    fn a_missing_host_directory_is_refused() {
        let scratch = tempfile::TempDir::new().unwrap();
        let share = DirShareSpec {
            host_dir: scratch.path().join("missing").display().to_string(),
            guest_mount: "/work".to_string(),
            read_only: true,
        };
        let err = materialize_mount_image(&share, scratch.path(), 0).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err:#}");
        assert!(!scratch.path().join("mount-0.ext4").exists());
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
