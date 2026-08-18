//! `mvmctl bundle export <template> --out <path>` — seal a built
//! template into a signed `.mvmpkg`.
//!
//! Reads the template's current revision artifacts (kernel,
//! rootfs, optional initrd, optional dm-verity sidecar), hashes
//! each, builds a [`BundleManifest`], signs it under the host
//! signer, and writes the archive bytes to `--out`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args as ClapArgs;
use mvm_core::plan::bundle::{
    ARTIFACTS_DIR, ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, VerityInfo,
    key_id_from_pubkey, sha256_hex, write_bundle,
};

use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;
use super::super::vm::host_signer;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Template name or 64-char slot hash to export.
    #[arg(value_name = "TEMPLATE")]
    pub template: String,
    /// Output path for the `.mvmpkg` archive. Parent directory must
    /// exist; the file is overwritten if it already exists.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Optional human-readable workload label baked into the
    /// manifest. Surfaced by `mvmctl bundle fetch` for diagnostics.
    #[arg(long)]
    pub label: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // ---- 1. Resolve the template's artifact paths ----
    let (spec, vmlinux, initrd, rootfs, _rev) = tmpl::template_artifacts_dispatched(&args.template)
        .with_context(|| {
            format!(
                "loading template {:?} — does it exist? Try `mvmctl manifest ls`",
                args.template
            )
        })?;

    // Carry a re-exported bundle's own architecture through rather than
    // re-stamping this host's. `template_artifacts_dispatched` resolves an
    // installed bundle as happily as a local slot, so an aarch64 bundle
    // re-exported from an x86_64 host would otherwise be relabelled x86_64
    // while still containing an aarch64 rootfs — and the label is what the
    // boot-time gate trusts. A slot built here has no manifest, so it takes
    // the host arch, which is correct for that case.
    let source_arch = tmpl::installed_bundle_arch_for_export(&args.template)
        .unwrap_or_else(|| mvm_core::arch::GuestArch::host().to_string());

    // Verity sidecar lives next to the rootfs by convention; the
    // backend's probe is the source of truth.
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    // ---- 2. Load every artifact byte blob ----
    //
    // Today bundles hold the bytes in memory; multi-GiB rootfs
    // streaming is a v2 concern. The `read_and_verify_bundle`
    // counterpart has the same shape.
    let kernel_bytes =
        std::fs::read(&vmlinux).with_context(|| format!("reading kernel at {vmlinux}"))?;
    let rootfs_bytes =
        std::fs::read(&rootfs).with_context(|| format!("reading rootfs at {rootfs}"))?;
    let initrd_bytes = match initrd.as_deref() {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("reading initrd at {p}"))?),
        None => None,
    };
    let verity_bytes = match verity_path.as_deref() {
        Some(p) => {
            Some(std::fs::read(p).with_context(|| format!("reading verity sidecar at {p}"))?)
        }
        None => None,
    };

    // ---- 3. Build the BundleManifest ----
    let signer = host_signer::load_or_init().context("loading host signer for bundle sign")?;
    let key_id = key_id_from_pubkey(&signer.verifying);

    let mut artifacts: Vec<BundleArtifact> = Vec::new();
    let mut payload: Vec<(String, Vec<u8>)> = Vec::new();

    let push = |artifacts: &mut Vec<BundleArtifact>,
                payload: &mut Vec<(String, Vec<u8>)>,
                name: &str,
                role: ArtifactRole,
                bytes: Vec<u8>| {
        let path = format!("{ARTIFACTS_DIR}/{name}");
        artifacts.push(BundleArtifact {
            name: name.to_string(),
            role,
            path: path.clone(),
            sha256: sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
        payload.push((path, bytes));
    };

    push(
        &mut artifacts,
        &mut payload,
        "vmlinux",
        ArtifactRole::Kernel,
        kernel_bytes,
    );
    push(
        &mut artifacts,
        &mut payload,
        "rootfs.ext4",
        ArtifactRole::Rootfs,
        rootfs_bytes,
    );
    if let Some(b) = initrd_bytes {
        push(
            &mut artifacts,
            &mut payload,
            "initrd",
            ArtifactRole::Initrd,
            b,
        );
    }
    let verity = match (verity_bytes, roothash) {
        (Some(b), Some(roothash)) => {
            push(
                &mut artifacts,
                &mut payload,
                "rootfs.verity",
                ArtifactRole::VerityHashSidecar,
                b,
            );
            Some(VerityInfo {
                roothash,
                sidecar_artifact: "rootfs.verity".to_string(),
            })
        }
        // Sidecar without a roothash is a misbuild — the backend's
        // probe returns paired Some/Some or paired None/None.
        // Surface inconsistency loudly rather than dropping the
        // sidecar silently.
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "template carries an incomplete dm-verity binding (sidecar without roothash, or vice versa); rebuild before exporting"
            );
        }
        (None, None) => None,
    };

    // The runtime refuses to boot a rootfs whose `mvm-meta.json` sidecar is
    // missing, so a bundle exported without it is unbootable on arrival —
    // `bundle install` succeeds and the failure only surfaces at admission on
    // the target host. Carry it, and fail here if the template hasn't got one.
    let sidecar_src = sidecar_path_for_rootfs(&rootfs)?;
    let sidecar_bytes = std::fs::read(&sidecar_src).with_context(|| {
        format!(
            "reading guest sidecar at {} — rebuild the template before exporting",
            sidecar_src.display()
        )
    })?;
    push(
        &mut artifacts,
        &mut payload,
        mvm_build::builder_vm::SIDECAR_FILENAME,
        ArtifactRole::Other,
        sidecar_bytes,
    );

    // Bake the template's declared resources into the bundle so
    // `mvmctl up <bundle-sha>` on another host gets sensible
    // defaults without re-discovering them. CLI `--cpus` /
    // `--memory` still override at launch time.
    let resources = Some(mvm_core::plan::BundleResources {
        vcpus: spec.vcpus as u32,
        mem_mib: spec.mem_mib,
    });

    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: host_signer::host_signer_id(),
        key_id: key_id.clone(),
        arch: source_arch,
        kernel_version: None,
        profile: Some(spec.profile.clone()),
        workload_label: args.label,
        created_at: Utc::now().to_rfc3339(),
        labels: Default::default(),
        artifacts,
        verity,
        resources,
    };

    // ---- 4. Sign + write the archive ----
    let archive_bytes = write_bundle(&manifest, &signer.signing, payload)
        .context("sealing bundle (manifest + signature + artifacts)")?;

    if let Some(parent) = args.out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    std::fs::write(&args.out, &archive_bytes)
        .with_context(|| format!("writing bundle to {}", args.out.display()))?;

    println!(
        "Exported bundle to {} ({} bytes, key_id={})",
        args.out.display(),
        archive_bytes.len(),
        key_id.0,
    );

    Ok(())
}

/// The guest sidecar the runtime admission gate looks for sits beside the
/// rootfs image the template resolved to.
fn sidecar_path_for_rootfs(rootfs: &str) -> Result<std::path::PathBuf> {
    std::path::Path::new(rootfs)
        .parent()
        .map(|dir| dir.join(mvm_build::builder_vm::SIDECAR_FILENAME))
        .ok_or_else(|| anyhow::anyhow!("rootfs path {rootfs} has no parent directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_resolves_beside_the_rootfs() {
        assert_eq!(
            sidecar_path_for_rootfs("/slots/abc/artifacts/rootfs.ext4").unwrap(),
            std::path::Path::new("/slots/abc/artifacts/mvm-meta.json")
        );
    }

    #[test]
    fn rootfs_without_a_parent_directory_is_refused() {
        assert!(sidecar_path_for_rootfs("/").is_err());
    }
}
