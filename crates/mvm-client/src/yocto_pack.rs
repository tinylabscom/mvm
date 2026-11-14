//! Build a pinned Yocto rootfs into a locally signed, health-checked pack.
//!
//! This is an in-process operation for embedders as well as the CLI. A Yocto
//! archive is not a pack: the host first checks its pinned inputs, installs its
//! own verified runtime, boots the sealed result, and only then signs it.

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use mvm_build::oci_runtime_inject::ImageRuntimeConfig;
use mvm_build::yocto::YoctoInput;
use mvm_contract::pack_spec::PackSource;
pub use mvm_contract::pack_spec::{PackSpec, PackTarget};
use mvm_core::arch::GuestArch;
use mvm_core::plan::BundleResources;
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::security::AgentProfile;

use crate::bundle::{
    PackArtifactDigests, PostureInputs, TemplateExport, pack_environment, seal_template_rootfs,
    stage_template, template_entrypoint,
};
use crate::entrypoint::{
    CallLifecycle, CallStdin, CapturedOutput, EntrypointAdmission, EntrypointCall, EntrypointVm,
    SessionVmName, backend_name_for, install_output_capture, run_entrypoint_call,
};
use crate::image_producer::{WorkloadImageProducer, YoctoImage};
use crate::portable_boot_assets::PreparedPortableBootAssets;

/// Everything the host needs to import one independently built Yocto rootfs.
#[derive(Debug, Clone)]
pub struct YoctoPackRequest {
    /// Authored identity, target, resources and baked entrypoint.
    pub spec: PackSpec,
    /// Directory containing the spec and its relative producer input paths.
    pub spec_dir: PathBuf,
    /// New destination for the locally signed archive; never overwritten.
    pub out: PathBuf,
    /// Optional human-readable label; does not change the signed pack identity.
    pub label: Option<String>,
    /// Maximum entrypoint execution time during the health boot.
    pub health_timeout_secs: u64,
    /// Health backend selection; only same-host Linux Firecracker is supported.
    pub hypervisor: Option<String>,
}

impl YoctoPackRequest {
    /// Parse an authored pack spec and resolve its producer paths from that file.
    ///
    /// # Errors
    ///
    /// Refuses unreadable, malformed or invalid pack specifications.
    pub fn from_file(spec_path: &Path, out: PathBuf) -> Result<Self> {
        let bytes = fs::read(spec_path)
            .with_context(|| format!("reading pack spec {}", spec_path.display()))?;
        let spec: PackSpec = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing pack spec {}", spec_path.display()))?;
        let spec_dir = spec_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok(Self {
            spec,
            spec_dir,
            out,
            label: None,
            health_timeout_secs: 120,
            hypervisor: None,
        })
    }
}

/// The archive actually published after its entrypoint booted successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltYoctoPack {
    /// Published archive path.
    pub path: PathBuf,
    /// SHA-256 of the published archive.
    pub sha256: String,
    /// Host signing key identifier, not an official publisher identity.
    pub key_id: String,
}

/// Validate, materialize, health-boot, and locally sign one pinned Yocto pack.
///
/// The archive is not published if boot, stop, post-boot integrity checking,
/// signing, or the comparison with the staged bundle fails. This does not
/// publish an official registry pack or attest the Yocto producer's build.
///
/// # Errors
///
/// Refuses a foreign architecture, invalid inputs, unavailable signed runtime
/// or backend, unsuccessful health boot, changed artifacts, or failed signing.
pub fn build_yocto_pack(request: YoctoPackRequest) -> Result<BuiltYoctoPack> {
    validate_spec(&request.spec)?;
    let PackSource::Yocto { archive, inputs } = &request.spec.source else {
        bail!("a Yocto pack requires source.kind=yocto");
    };
    ensure!(
        target_arch(request.spec.target) == GuestArch::host(),
        "pack targets {}-linux but this host builds {}-linux",
        target_arch(request.spec.target),
        GuestArch::host()
    );
    let work = tempfile::tempdir().context("stage Yocto pack inputs")?;
    let input = YoctoInput::stage(
        &request.spec_dir.join(inputs),
        &request.spec_dir.join(archive),
        request.spec.target,
        work.path(),
    )?;
    // A selected checkout requires pair-stamped launch artifacts. Do not
    // silently turn that selection into the released-set path.
    ensure!(
        matches!(
            mvm_build::image_source::resolve_current_source()?,
            mvm_build::image_source::ImageSource::Released
        ),
        "Yocto library pack build requires a published image set; a selected local checkout needs pair-stamped launch artifacts"
    );
    let backend = backend_name_for(request.hypervisor.as_deref())?;
    ensure!(
        cfg!(target_os = "linux") && backend == "firecracker",
        "Yocto pack health requires same-host Linux Firecracker; native HVF requires owner-preserving health custody"
    );
    let boot = Arc::new(PreparedPortableBootAssets::acquire(GuestArch::host())?);
    let rootfs = work.path().join("rootfs.ext4");
    let entrypoint = ImageRuntimeConfig {
        argv: request.spec.entrypoint.clone(),
        env: Vec::new(),
        working_dir: Some("/srv/app".to_string()),
    };
    let mut slot = mvm_core::manifest::PersistedManifest::from_flake_identity(
        &format!("yocto:{}:{}", input.archive_digest(), uuid::Uuid::new_v4()),
        None,
        &backend,
    );
    slot.vcpus = u8::try_from(request.spec.resources.cpu_cores)
        .context("Yocto pack CPU cores exceed slot capacity")?;
    slot.mem_mib = request.spec.resources.memory_mb;
    let revision = YoctoImage::new(&input, &rootfs, &entrypoint, &boot).build_slot(&slot)?;
    let owner = YoctoSlot {
        slot_hash: slot.manifest_hash,
        revision_hash: revision.revision_hash,
        work: Some(work),
        boot,
        retain: Cell::new(false),
    };
    finish_pack(&request, &input, &owner, &backend)
}

fn validate_spec(spec: &PackSpec) -> Result<()> {
    spec.validate().context("validate Yocto pack declaration")?;
    ensure!(
        matches!(spec.source, PackSource::Yocto { .. }),
        "a Yocto pack requires source.kind=yocto"
    );
    Ok(())
}

fn target_arch(target: PackTarget) -> GuestArch {
    match target {
        PackTarget::X86_64Linux => GuestArch::X86_64,
        PackTarget::Aarch64Linux => GuestArch::Aarch64,
    }
}

struct YoctoSlot {
    slot_hash: String,
    revision_hash: String,
    work: Option<tempfile::TempDir>,
    boot: Arc<PreparedPortableBootAssets>,
    retain: Cell<bool>,
}

impl YoctoSlot {
    fn verify_revision(&self) -> Result<()> {
        let current = fs::canonicalize(mvm_core::manifest::slot_current_symlink(&self.slot_hash))?;
        let expected = fs::canonicalize(mvm_core::manifest::slot_revision_dir(
            &self.slot_hash,
            &self.revision_hash,
        ))?;
        ensure!(
            current == expected,
            "Yocto slot changed after materialization"
        );
        self.boot.verify_integrity()
    }
}

impl Drop for YoctoSlot {
    fn drop(&mut self) {
        if self.retain.get() {
            // A stop acknowledgement is not proof that no native reader still
            // owns these bytes. Retain all producer and boot inputs together.
            if let Some(work) = self.work.take() {
                std::mem::forget(work);
            }
            std::mem::forget(Arc::clone(&self.boot));
            tracing::warn!(slot = %self.slot_hash, "retaining Yocto producer inputs after health boot");
            return;
        }
        let path = mvm_core::manifest::slot_dir(&self.slot_hash);
        if let Err(error) = fs::remove_dir_all(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, %path, "removing private Yocto build slot failed");
        }
    }
}

fn finish_pack(
    request: &YoctoPackRequest,
    input: &YoctoInput,
    owner: &YoctoSlot,
    backend: &str,
) -> Result<BuiltYoctoPack> {
    let slot = owner.slot_hash.as_str();
    let pack_name = format!(
        "{}@{}",
        request.spec.identity.name, request.spec.identity.version
    );
    seal_template_rootfs(slot)?.context(
        "the built pack's image does not declare itself sealed; a pack must boot from a dm-verity rootfs",
    )?;
    let image_argv = template_entrypoint(slot)?;
    let built = PackArtifactDigests::read(slot)?;
    ensure!(
        !built.missing("verity"),
        "the built pack has no dm-verity hash tree beside its rootfs; nothing was signed"
    );
    let expected = built
        .clone()
        .selecting_initrd(owner.boot.initramfs_path())?;

    owner.verify_revision()?;
    install_output_capture();
    let admission = EntrypointAdmission::builder(backend.to_string())
        .cpus(u32::from(request.spec.resources.cpu_cores))
        .mem_mib(u64::from(request.spec.resources.memory_mb))
        .network_policy(mvm_core::network_policy::NetworkPolicy::deny_all())
        .build()?;
    let mut output = CapturedOutput::default();
    owner.retain.set(true);
    let outcome = run_entrypoint_call(
        EntrypointCall {
            vm: EntrypointVm {
                slot,
                vm_name: SessionVmName::Prefixed("invoke"),
                cpus: u32::from(request.spec.resources.cpu_cores),
                memory_mib: request.spec.resources.memory_mb,
                admission,
                portable_boot_assets: Some(&owner.boot),
            },
            stdin: CallStdin::OneShot(Vec::new()),
            timeout_secs: request.health_timeout_secs,
            lifecycle: CallLifecycle::Transient,
        },
        None,
        &mut output,
    )
    .context("booting the built pack for its health check")?;
    ensure!(
        outcome.exit_code() == 0,
        "health check failed: the entrypoint exited {}; nothing was signed",
        outcome.exit_code()
    );
    owner.verify_revision()?;
    let checked = PackArtifactDigests::read(slot)?;
    ensure!(
        built == checked,
        "built artifacts changed after the health check ({}); nothing was signed",
        built.changed(&checked).join(", ")
    );

    let digest = file_sha256(input.manifest_path())?;
    ensure!(
        digest == input.manifest_digest(),
        "Yocto input document changed before signing"
    );
    let mut export = TemplateExport::new(request.out.clone());
    export.environment = Some(pack_environment(&request.spec, image_argv));
    export.label = Some(request.label.clone().unwrap_or_else(|| pack_name.clone()));
    export.resources = Some(BundleResources {
        vcpus: u32::from(request.spec.resources.cpu_cores),
        mem_mib: request.spec.resources.memory_mb,
    });
    export.posture = Some(PostureInputs::new(AgentProfile::SealedProd));
    export.provenance = Some(BuildProvenance {
        input_kind: InputKind::Yocto,
        input_ref: format!(
            "yocto:{}@sha256:{}",
            input.machine(),
            input.archive_digest()
        ),
        lock_digest: Some(digest.clone()),
        builder_id: None,
        artifacts: Default::default(),
    });
    export.local_build = true;
    export.portable_boot_assets = Some(Arc::clone(&owner.boot));
    export.supplemental_artifacts.push((
        "yocto-inputs.json".into(),
        input.manifest_path().to_path_buf(),
    ));

    let mut staged = stage_template(slot, export)?;
    let validation = (|| -> Result<String> {
        owner.verify_revision()?;
        let manifest = staged.manifest()?;
        ensure!(
            manifest
                .find_by_name("yocto-inputs.json")
                .is_some_and(|artifact| artifact.sha256 == digest),
            "sealed Yocto inputs differ from the verified source document"
        );
        let sealed = PackArtifactDigests::from_manifest(&manifest);
        ensure!(
            sealed == expected,
            "the sealed archive differs from the health-checked build ({}); archive not published",
            expected.changed(&sealed).join(", ")
        );
        let sha256 = staged.sha256()?;
        owner.verify_revision()?;
        Ok(sha256)
    })();
    let sha256 = match validation {
        Ok(digest) => digest,
        Err(error) => return Err(staged.abort(error)),
    };
    let exported = staged.publish()?;
    mvm_core::audit_emit!(
        PackBuild,
        "pack={pack_name},yocto_archive_sha256={},bundle_sha256={sha256},key_id={}",
        input.archive_digest(),
        exported.key_id.0
    );
    Ok(BuiltYoctoPack {
        path: exported.path,
        sha256,
        key_id: exported.key_id.0,
    })
}

fn file_sha256(path: &Path) -> Result<String> {
    Ok(mvm_core::crypto::image_verify::sha256_file(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PackSpec {
        serde_json::from_str(include_str!("../../../examples/yocto/pack.json"))
            .expect("representative Yocto pack spec parses")
    }

    #[test]
    fn the_library_reads_producer_paths_from_the_pack_document() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pack.json");
        fs::write(&path, include_str!("../../../examples/yocto/pack.json")).unwrap();
        let request = YoctoPackRequest::from_file(&path, temp.path().join("app.mvmpkg")).unwrap();
        assert_eq!(request.spec_dir, temp.path());
        assert!(matches!(
            request.spec.source,
            PackSource::Yocto { archive, inputs }
                if archive == "mvm-workload-qemuarm64.rootfs.tar.gz"
                    && inputs == "yocto-inputs.json"
        ));
    }

    #[test]
    fn yocto_pack_declares_only_content_already_in_its_rootfs() {
        let sample = sample();
        validate_spec(&sample).expect("representative spec is importable");

        let mut with_nix_package = sample.clone();
        with_nix_package
            .packages
            .push(mvm_contract::pack_spec::PackageRequest {
                name: "python3".into(),
                version: None,
                scope: mvm_contract::pack_spec::PackageScope::Runtime,
            });
        assert!(validate_spec(&with_nix_package).is_err());

        let mut with_nix_source = sample;
        with_nix_source.source = PackSource::Local { path: "src".into() };
        assert!(validate_spec(&with_nix_source).is_err());
    }

    #[test]
    fn the_signed_environment_names_the_baked_entrypoint_and_no_extra_capabilities() {
        let spec = sample();
        let environment = pack_environment(&spec, spec.entrypoint.clone());
        environment.validate().expect("pack environment is valid");
        assert_eq!(environment.pack, Some(spec.identity));
        assert_eq!(environment.entrypoint.argv, spec.entrypoint);
        assert!(environment.capabilities.is_empty());
        assert!(environment.volumes.is_empty());
        assert!(environment.services.is_empty());
    }

    #[test]
    fn a_foreign_target_refuses_before_reading_any_input() {
        let temp = tempfile::tempdir().unwrap();
        let mut spec = sample();
        spec.target = match GuestArch::host() {
            GuestArch::Aarch64 => PackTarget::X86_64Linux,
            _ => PackTarget::Aarch64Linux,
        };
        let out = temp.path().join("never.mvmpkg");
        let error = build_yocto_pack(YoctoPackRequest {
            spec,
            spec_dir: temp.path().to_path_buf(),
            out: out.clone(),
            label: None,
            health_timeout_secs: 120,
            hypervisor: None,
        })
        .expect_err("a foreign target is refused before any effects");
        assert!(format!("{error:#}").contains("targets"), "{error:#}");
        assert!(!out.exists(), "no pack is written after a target refusal");
    }

    #[test]
    fn a_wrong_archive_digest_refuses_before_acquiring_boot_assets() {
        let temp = tempfile::tempdir().unwrap();
        let mut spec = sample();
        spec.target = match GuestArch::host() {
            GuestArch::Aarch64 => PackTarget::Aarch64Linux,
            _ => PackTarget::X86_64Linux,
        };
        let archive = temp.path().join("mvm-workload-qemuarm64.rootfs.tar.gz");
        fs::write(&archive, b"not the pinned archive").unwrap();
        let inputs = temp.path().join("yocto-inputs.json");
        fs::write(
            &inputs,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "target": spec.target,
                "machine": "qemu-test",
                "layers": {"poky": "72983ac391008ebceb45edc7a8f0f6d5f4fe715c"},
                "rootfs_archive_sha256": "0".repeat(64)
            }))
            .unwrap(),
        )
        .unwrap();
        let out = temp.path().join("never.mvmpkg");
        let error = build_yocto_pack(YoctoPackRequest {
            spec,
            spec_dir: temp.path().to_path_buf(),
            out: out.clone(),
            label: None,
            health_timeout_secs: 120,
            hypervisor: None,
        })
        .expect_err("a different archive cannot reach runtime acquisition");
        assert!(format!("{error:#}").contains("does not match"), "{error:#}");
        assert!(!out.exists(), "nothing is signed for an altered archive");
    }
}
