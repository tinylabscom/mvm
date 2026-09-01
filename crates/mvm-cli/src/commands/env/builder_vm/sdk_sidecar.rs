#[cfg(feature = "builder-vm")]
use super::*;

/// Build the checkout's SDK sidecar inside the selected Linux builder boundary
/// and atomically install it into the same cache layout the launch resolver
/// reads.
#[cfg(feature = "builder-vm")]
pub(crate) fn build_sdk_sidecar_from_checkout(
    workspace_root: &std::path::Path,
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
    verbose: bool,
) -> Result<mvm_fs::sdk_sidecar::SdkSidecarArtifact> {
    if arch != mvm_core::arch::GuestArch::host() {
        anyhow::bail!(
            "builder VMs build SDK sidecars for their host architecture only: requested {arch}, host is {}",
            mvm_core::arch::GuestArch::host()
        );
    }

    let builder_choice = mvm_build::builder_backend_select::resolve_choice();
    if builder_choice == mvm_build::builder_backend_select::BuilderBackendChoice::Hvf {
        super::bootstrap::bootstrap_builder_vm_image()
            .context("preparing the HVF builder image for the SDK sidecar build")?;
    }

    let fingerprint = mvm_build::guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)
        .context("fingerprinting SDK sidecar source inputs")?;
    let arch_dir = arch.to_string();
    let builder_lock_scope = cache_root.join("builder-vm").join(&arch_dir);
    let lock_scope = builder_lock_scope.to_string_lossy();
    let _stage0_guard = acquire_stage0_lock(&lock_scope)?;
    let removed = sweep_stage0_staging_siblings(&builder_lock_scope)?;
    if removed > 0 {
        ui::info(&format!(
            "Removed {removed} incomplete Stage 0 artifact build director{} from an earlier interruption.",
            if removed == 1 { "y" } else { "ies" }
        ));
    }

    let staging_dir = unique_builder_vm_stage0_staging_dir(&builder_lock_scope)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let request =
        super::stage0_artifact::Stage0ArtifactBuild::builder(workspace_root, &staging_dir)
            .build_attr(sidecar_build_attr(libc))
            .output_mode("sdk-sidecar")
            .verbose(verbose)
            .build()?;

    let build_result =
        if builder_choice == mvm_build::builder_backend_select::BuilderBackendChoice::Hvf {
            ui::info(&format!(
                "Building SDK sidecar for {arch} in the HVF builder from {}...",
                workspace_root.display()
            ));
            build_sdk_sidecar_via_hvf(workspace_root, &staging_dir, arch, libc)
        } else {
            ui::info(&format!(
                "Building SDK sidecar for {arch} via Stage 0 from {}...",
                workspace_root.display()
            ));
            request.run()
        };
    if let Err(error) = build_result {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error.context("building SDK sidecar inside the builder VM"));
    }

    let installed = mvm_build::sdk_sidecar::install_source_built_sidecar(
        &staging_dir,
        cache_root,
        version,
        arch,
        libc,
        &fingerprint,
    )
    .context("validating and installing the source-built SDK sidecar");
    let _ = std::fs::remove_dir_all(&staging_dir);
    installed
}

/// The runtime-overlay flake attribute that builds `libc`'s sidecar image.
///
/// The glibc attribute is unsuffixed because it was the only one when the
/// output was named; the musl one carries the suffix the flake exposes.
/// `Unknown` cannot reach here — the build command enumerates the variants it
/// knows — so it maps to glibc rather than growing a fallible return for a
/// case the type permits and the caller cannot produce.
#[cfg(feature = "builder-vm")]
fn sidecar_build_attr(libc: mvm_contract::guest_libc::GuestLibc) -> &'static str {
    match libc {
        mvm_contract::guest_libc::GuestLibc::Musl => "sdk-sidecar-image-musl",
        _ => "sdk-sidecar-image",
    }
}

#[cfg(feature = "builder-vm")]
fn build_sdk_sidecar_via_hvf(
    workspace_root: &std::path::Path,
    staging_dir: &std::path::Path,
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> Result<()> {
    let (kernel, rootfs, closure_nar) =
        crate::commands::build::hvf_builder_image::resolve_hvf_builder_image()
            .map_err(|error| anyhow::anyhow!("resolving HVF builder image: {error}"))?;
    let job = mvm_build::libkrun_builder::BuilderShellJob {
        work_dir: workspace_root.to_path_buf(),
        artifact_out: staging_dir.to_path_buf(),
        script: sdk_sidecar_builder_script(arch, libc),
        extra_disks: Vec::new(),
    };
    mvm_runtime::builder_runner::hvf_builder::HvfBuilderVm::new(kernel, rootfs)
        .with_closure_nar(closure_nar)
        .run_shell_script(&job)
        .map_err(|error| anyhow::anyhow!("HVF builder shell job: {error}"))?;
    Ok(())
}

/// Render the `cmd.sh` the builder guest runs to produce the SDK sidecar
/// image.
///
/// The flake reference names the whole staged workspace and selects the
/// builder-VM flake with `?dir=`, rather than naming the subdirectory
/// directly. The builder-VM flake reaches out of its own directory to import
/// the workspace's runtime-overlay flake, and `path:` copies exactly the tree
/// it names into the store: naming the subdirectory leaves that relative walk
/// pointing at the store root's parent, so the import resolves to `/nix/...`
/// and the build fails before it compiles anything. `?dir=` copies the
/// workspace and evaluates the flake inside it, so the walk lands where the
/// flake expects and the copy stays immutable.
#[cfg(feature = "builder-vm")]
fn sdk_sidecar_builder_script(
    arch: mvm_core::arch::GuestArch,
    libc: mvm_contract::guest_libc::GuestLibc,
) -> String {
    let attr = sidecar_build_attr(libc);
    let image = mvm_fs::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE;
    let version = mvm_fs::sdk_sidecar::SDK_SIDECAR_VERSION_FILE;
    let checksums = mvm_fs::overlay::CHECKSUM_MANIFEST_FILE;
    format!(
        r#"#!/bin/sh
set -eu
export HOME=/tmp
export XDG_CACHE_HOME=/nix-store/.cache
export XDG_STATE_HOME=/tmp/.local/state
export NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
export NIX_CONFIG='experimental-features = nix-command flakes
sandbox = false
build-users-group =
substituters = https://cache.nixos.org/
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY='
mkdir -p "$XDG_CACHE_HOME" "$XDG_STATE_HOME"
out=$(/sbin/nix build 'path:/work?dir=nix/images/builder-vm#packages.{arch}-linux.{attr}' \
  --no-link --print-out-paths --no-write-lock-file --impure --print-build-logs)
test -n "$out"
for name in '{image}' '{version}' '{checksums}'; do
  test -f "$out/$name"
  cp -L "$out/$name" "/out/$name"
  chmod 0644 "/out/$name" 2>/dev/null || true
done
sync
"#,
    )
}

#[cfg(all(test, feature = "builder-vm"))]
mod tests {
    use super::*;

    #[test]
    fn hvf_builder_script_copies_the_complete_sidecar_contract() {
        let script = sdk_sidecar_builder_script(
            mvm_core::arch::GuestArch::X86_64,
            mvm_contract::guest_libc::GuestLibc::Glibc,
        );

        assert!(script.contains("packages.x86_64-linux.sdk-sidecar-image"));
        for name in ["sdk.ext4", "VERSION", "checksums-sha256.txt"] {
            assert!(script.contains(name));
        }
        assert!(script.contains("\"/out/$name\""));
        assert!(script.contains("--no-write-lock-file"));
        assert!(script.contains("--impure"));
    }

    /// The builder-VM flake imports the workspace's runtime-overlay flake by
    /// walking out of its own directory, so the store copy has to be the whole
    /// workspace. Naming the subdirectory directly copies only that
    /// subdirectory and the walk escapes it — the build then dies on a missing
    /// `/nix/images/runtime-overlay/flake.nix` before compiling anything.
    #[test]
    fn sidecar_flake_reference_copies_the_workspace_and_selects_the_subdirectory() {
        for arch in [
            mvm_core::arch::GuestArch::X86_64,
            mvm_core::arch::GuestArch::Aarch64,
        ] {
            let script =
                sdk_sidecar_builder_script(arch, mvm_contract::guest_libc::GuestLibc::Glibc);
            assert!(
                script.contains(&format!(
                    "'path:/work?dir=nix/images/builder-vm#packages.{arch}-linux.sdk-sidecar-image'"
                )),
                "sidecar build must select the builder-VM flake out of a whole-workspace copy: {script}"
            );
            assert!(
                !script.contains("path:/work/nix/images/builder-vm"),
                "naming the flake subdirectory strands the runtime-overlay import: {script}"
            );
        }
    }
}
