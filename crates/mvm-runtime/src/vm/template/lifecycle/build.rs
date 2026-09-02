//! Building a manifest-keyed slot via the dev build pipeline, and the
//! fixed-output-derivation hash recompute it can trigger.

use anyhow::{Context, Result, anyhow};
use mvm_core::arch::GuestArch;
use mvm_core::manifest::{PersistedManifest, Provenance, slot_current_symlink, slot_revision_dir};
use mvm_core::pool::ArtifactPaths;
use mvm_core::template::TemplateRevision;
use mvm_core::time::utc_now;
use tracing::{instrument, warn};

use crate::shell;
use crate::ui;

use super::artifacts::{
    RevisionArtifactSources, install_revision_artifacts, slot_kernel_source, slot_sidecar_source,
};
use super::build_mode_label;
use super::slots::template_persist_slot;

/// Build a manifest-keyed slot using the dev build pipeline (local Nix in
/// the builder VM or on the host). Mirrors `template_build` but operates on a
/// [`PersistedManifest`] instead of looking up by name.
///
/// On success, the slot's `current` symlink points at
/// `artifacts/revisions/<revision_hash>/`, the persisted manifest record
/// is refreshed (`updated_at` + `provenance`), and a `revision.json` is
/// written next to the artifacts. Returns the [`TemplateRevision`] for
/// display / further use.
///
/// `force` clears the dev build cache (`~/.mvm/dev/builds/`) so the
/// underlying Nix build runs from scratch. `update_hash` recomputes the
/// FOD hash in the flake first (rare; used after package version bumps).
#[instrument(skip_all, fields(slot_hash = %persisted.manifest_hash, force, update_hash))]
pub fn template_build_from_manifest(
    persisted: &PersistedManifest,
    force: bool,
    update_hash: bool,
    mode: mvm_build::pipeline::BuildMode,
) -> Result<TemplateRevision> {
    let build_env = crate::build_env::default_build_env();
    let env = build_env.as_ref();

    ui::info(&format!(
        "Building manifest at '{}' (flake: {}, profile: {})",
        persisted.manifest_path, persisted.flake_ref, persisted.profile
    ));

    if update_hash {
        update_fod_hash(&persisted.flake_ref)?;
    }

    if force {
        ui::info("Force build: clearing dev build cache");
        let builds_dir = format!("{}/dev/builds", mvm_core::config::mvm_home());
        if let Err(e) = env.shell_exec(&format!("rm -rf {builds_dir}")) {
            warn!("failed to clear dev build cache: {e}");
        }
    }

    let result =
        mvm_build::dev_build::dev_build(env, &persisted.flake_ref, Some(&persisted.profile), mode)?;

    // No post-build agent injection: every mkGuest image resolves its
    // agent from the runtime overlay (or mkGuest's own bake) at boot,
    // so there is nothing to verify or patch into the rootfs here.

    // Store artifacts under the slot's revision directory. Both the
    // finished dev build and the slot tree are host paths, so this is
    // a plain filesystem install — see `install_revision_artifacts`.
    let slot_hash = &persisted.manifest_hash;
    let rev = &result.revision_hash;
    let rev_dst = slot_revision_dir(slot_hash, rev);
    ui::info("Storing artifacts in slot revision directory...");
    let kernel_src = slot_kernel_source(
        std::path::Path::new(&result.vmlinux_path),
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        GuestArch::host(),
    )?;
    let sidecar_src = slot_sidecar_source(std::path::Path::new(&result.build_dir))?;

    // Generate a minimal fc-base.json for reference. Same logic as
    // template_build: minimal guests (no initrd) need root= and init=
    // on the kernel cmdline; initrd-bearing guests rely on the initrd's
    // /init.
    let boot_args = if result.initrd_path.is_some() {
        "console=ttyS0 reboot=k panic=1 net.ifnames=0".to_string()
    } else {
        "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0"
            .to_string()
    };
    let mut boot_source = serde_json::json!({
        "kernel_image_path": "vmlinux",
        "boot_args": boot_args
    });
    if result.initrd_path.is_some() {
        boot_source["initrd_path"] = serde_json::json!("initrd");
    }
    let fc_config = serde_json::json!({
        "boot-source": boot_source,
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": "rootfs.ext4",
            "is_root_device": true,
            "is_read_only": false
        }],
        "machine-config": {
            "vcpu_count": persisted.vcpus,
            "mem_size_mib": persisted.mem_mib
        }
    });
    let fc_json = serde_json::to_string_pretty(&fc_config)?;

    // OCI image tarball: present only when the flake's `mkGuest` emits
    // one via `dockerTools.streamLayeredImage`. When present, this is
    // what `mvmctl manifest export-oci <template>` returns so users
    // can `docker load` the mvm-built workload on a non-KVM host.
    // Best-effort: flakes that don't emit `image.tar.gz` just don't
    // get one in the slot, and `export-oci` errors with a clear
    // "rebuild with the OCI output enabled" message.
    let oci_tarball = std::path::PathBuf::from(format!("{}/image.tar.gz", result.build_dir));

    // Update the slot's `current` symlink (relative target so the slot
    // is portable across host filesystems).
    let current_link = slot_current_symlink(slot_hash);
    install_revision_artifacts(
        &RevisionArtifactSources {
            kernel: kernel_src,
            initrd: result.initrd_path.as_ref().map(std::path::PathBuf::from),
            rootfs: std::path::PathBuf::from(&result.rootfs_path),
            sidecar: sidecar_src,
            oci_tarball,
            fc_base_json: fc_json,
        },
        std::path::Path::new(&rev_dst),
        std::path::Path::new(&current_link),
        rev,
    )?;

    // Compute the actual flake.lock hash for accurate cache keys.
    // Pool builds delegate this; dev/manifest builds compute it inline.
    // Falls back to revision hash for remote flakes (no flake.lock on disk).
    let flake_lock_hash = shell::run_in_vm_stdout(&format!(
        "if [ -f {flake}/flake.lock ]; then nix hash path {flake}/flake.lock; else echo ''; fi",
        flake = persisted.flake_ref
    ))
    // On a tier with no Linux builder to run this against, the call itself
    // errors here and silently degrades to the revision hash below.
    .unwrap_or_default()
    .trim()
    .to_string();
    let flake_lock_hash = if flake_lock_hash.is_empty() {
        rev.clone()
    } else {
        flake_lock_hash
    };

    let sizes = result.artifact_sizes.clone();
    let revision = TemplateRevision {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        revision_hash: rev.clone(),
        flake_ref: persisted.flake_ref.clone(),
        flake_lock_hash,
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
            initrd: if result.initrd_path.is_some() {
                Some("initrd".to_string())
            } else {
                None
            },
            sizes: Some(sizes.clone()),
        },
        built_at: utc_now(),
        profile: persisted.profile.clone(),
        // role is preserved on the on-disk struct for backward
        // compatibility with old revision.json files; manifest-built
        // slots emit an empty string. cache_key no longer keys off
        // role; this field is informational only.
        vcpus: persisted.vcpus,
        mem_mib: persisted.mem_mib,
        data_disk_mib: persisted.data_disk_mib,
        snapshot: None,
        build_mode: Some(build_mode_label(mode).to_string()),
    };
    // `rev_dst` (thus `rev_meta_path`) is a host path — this is a
    // plain metadata write, not a VM operation.
    let rev_json = serde_json::to_string_pretty(&revision)?;
    let rev_meta_path = format!("{rev_dst}/revision.json");
    std::fs::write(&rev_meta_path, &rev_json)
        .with_context(|| format!("writing {rev_meta_path}"))?;

    // Refresh the slot's persisted manifest record with the new
    // updated_at + provenance. Caller can pre-supply provenance via
    // the `persisted` arg's `provenance` field; on rebuild we touch
    // it to reflect the current build.
    let refreshed = persisted.clone().touch(Provenance::current());
    template_persist_slot(&refreshed)?;

    use mvm_core::pool::format_bytes;
    ui::success(&format!(
        "Manifest at '{}' built successfully (revision: {}, rootfs: {}, kernel: {})",
        persisted.manifest_path,
        &rev[..rev.len().min(12)],
        format_bytes(sizes.rootfs_bytes),
        format_bytes(sizes.vmlinux_bytes),
    ));

    Ok(revision)
}

/// Recompute the Nix fixed-output derivation hash in a flake's `flake.nix`.
///
/// Blanks the `outputHash` field, runs `nix build` to trigger hash computation,
/// extracts the correct hash from the error output, and writes it back.
/// On failure, the original hash is restored.
#[instrument(skip_all, fields(flake_ref))]
fn update_fod_hash(flake_ref: &str) -> Result<()> {
    crate::linux_env::require_guest_exec_available(
        "recomputing the fixed-output-derivation hash needs a real 'nix build'",
    )?;

    ui::info("Recomputing fixed-output derivation hash...");

    // Save original hash for recovery.
    let orig_hash = shell::run_in_vm_stdout(&format!(
        r#"sed -n 's/.*outputHash = "\([^"]*\)".*/\1/p' {flake}/flake.nix"#,
        flake = flake_ref
    ))?
    .trim()
    .to_string();

    // Blank the hash to trigger TOFU computation.
    shell::run_in_vm(&format!(
        r#"sed -i.bak 's|outputHash = "[^"]*"|outputHash = ""|' {flake}/flake.nix && rm -f {flake}/flake.nix.bak"#,
        flake = flake_ref
    ))?;

    // Run nix build and capture all output. It will fail with hash mismatch,
    // printing the correct hash. Phase 2/3 never execute; only the FOD runs.
    ui::info("Running nix build to compute hash (this downloads the package)...");
    let build_output = shell::run_in_vm_stdout(&format!(
        r#"cd {flake} && nix build '.#' --no-link 2>&1 || true"#,
        flake = flake_ref
    ))?;

    // Extract the "got: sha256-..." hash from the build output.
    let new_hash = build_output
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("got:") {
                Some(trimmed.trim_start_matches("got:").trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    if new_hash.is_empty() {
        // Show the nix output so the user can diagnose the failure.
        for line in build_output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                ui::info(&format!("  nix: {trimmed}"));
            }
        }
        // Restore original hash.
        if let Err(e) = shell::run_in_vm(&format!(
            r#"sed -i.bak 's|outputHash = "[^"]*"|outputHash = "{orig}"|' {flake}/flake.nix && rm -f {flake}/flake.nix.bak"#,
            orig = orig_hash,
            flake = flake_ref
        )) {
            warn!("failed to restore original FOD hash: {e}");
        }
        return Err(anyhow!("Could not extract FOD hash from nix build output."));
    }

    // Write the correct hash.
    shell::run_in_vm(&format!(
        r#"sed -i.bak 's|outputHash = "[^"]*"|outputHash = "{hash}"|' {flake}/flake.nix && rm -f {flake}/flake.nix.bak"#,
        hash = new_hash,
        flake = flake_ref
    ))?;

    ui::success(&format!("Updated outputHash: {}", new_hash));
    Ok(())
}

#[cfg(test)]
mod tests {
    // The one test here is macOS-only; keep the glob gated to match, else it is
    // an unused import when the test compiles out (e.g. the Linux test build).
    #[cfg(target_os = "macos")]
    use super::*;

    /// `update_fod_hash` needs a real Linux builder to run `nix build`
    /// against; on the macOS 26+ tier (no builder to dispatch to) it must
    /// fail closed with an actionable error up front rather than failing
    /// deep inside a doomed `run_in_vm` call. Host-conditioned: only
    /// asserts on the tier it actually applies to.
    #[cfg(target_os = "macos")]
    #[test]
    fn update_fod_hash_fails_closed_on_hvf_default_tier() {
        if !mvm_core::platform::current().is_hvf_default_tier() {
            return;
        }
        let err = update_fod_hash("/nonexistent/flake")
            .expect_err("must fail closed with no builder available");
        assert!(
            err.to_string().contains("fixed-output-derivation"),
            "unexpected message: {err}"
        );
    }
}
