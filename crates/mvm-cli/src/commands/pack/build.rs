//! `mvmctl pack build` — turn a locked pack spec into a signed `.mvmpkg`.
//!
//! One path, every step reusing what already exists: the frozen compile
//! (`mvm_compiler::pack`), the flake build into a template slot (the builder
//! VM), a health boot of the baked entrypoint under the admitted launch path,
//! and the bundle export signed by the host key. Each artifact is digested
//! before the health boot and again before signing; anything that changed in
//! between is refused, so what is signed is exactly what was checked.
//!
//! The spec is parsed as data. Nothing here evaluates an author's Python or
//! TypeScript; an SDK that produced the spec ran in the author's own process.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use mvm_build::pipeline::frozen::{FrozenInputs, tree_digest};
use mvm_compiler::pack::compile_frozen;
use mvm_contract::pack_lock::PackLock;
use mvm_contract::pack_spec::{PackSpec, PackTarget};
use mvm_core::arch::GuestArch;
use mvm_core::plan::BundleResources;
use mvm_core::plan::bundle::{
    ArtifactRole, BundleManifest, ENVIRONMENT_DESCRIPTOR_VERSION, EnvironmentDescriptor,
    EnvironmentEntrypoint, MANIFEST_FILENAME,
};
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::security::AgentProfile;

use super::author::{LoadedSpec, locked_revision, read_lock};
use crate::commands::bundle::export::{TemplateExport, export_template};
use crate::commands::vm::denial_review::{NoManifest, ReviewSource};
use crate::commands::vm::invoke::{EntrypointCall, EntrypointStdin, boot_entrypoint};
use mvm_client::bundle::{
    PostureInputs, seal_template_rootfs, template_artifact_digests, template_entrypoint,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct BuildArgs {
    /// The authored `mvm.pack-spec/v1` JSON document
    #[arg(value_name = "SPEC.json")]
    pub spec: PathBuf,
    /// The lock the build must match (default: pack.lock.json beside the spec)
    #[arg(long, value_name = "FILE")]
    pub lock: Option<PathBuf>,
    /// Where to write the signed `.mvmpkg` archive
    #[arg(long, value_name = "FILE.mvmpkg")]
    pub out: PathBuf,
    /// Seconds the health boot's entrypoint may run before it counts as failed
    #[arg(long, default_value_t = 120)]
    pub health_timeout: u64,
    /// Hypervisor for the health boot (default: this host's auto-selection)
    #[arg(long)]
    pub hypervisor: Option<String>,
}

pub(super) fn run(args: BuildArgs) -> Result<()> {
    let loaded = LoadedSpec::read(&args.spec)?;
    let lock_path = args
        .lock
        .clone()
        .unwrap_or_else(|| loaded.default_lock_path());
    let lock = read_lock(&lock_path)?;
    require_host_target(&loaded.spec)?;

    // ---- 1. Frozen compile into an invocation-owned directory ----
    let work = tempfile::TempDir::new().context("creating private pack compile directory")?;
    let artifact = work.path().join("artifact");
    let revision = locked_revision(&lock)?;
    compile_frozen(&loaded.input(&revision), &lock, &artifact).with_context(|| {
        format!(
            "compiling pack spec {} against {}",
            args.spec.display(),
            lock_path.display()
        )
    })?;
    let compiled = tree_digest(&artifact)?;

    // ---- 2. Build the flake into a template slot in the builder VM ----
    eprintln!("building {} in the builder VM", pack_ref(&lock));
    let inputs = FrozenInputs::stage(&artifact, &compiled)?;
    let owned = crate::commands::build::build::FrozenFlakeSlot::build(inputs)
        .context("building the compiled pack")?;
    let slot = owned.slot_hash();
    // A pack ships sealed: its rootfs gets the dm-verity pair here, before the
    // health boot, so the boot checks it and the archive carries it.
    seal_template_rootfs(slot)?.context(
        "the built pack's image does not declare itself sealed; a pack must boot from a \
         dm-verity rootfs",
    )?;
    // The argv the image records for itself, which is what the health boot
    // runs and what a launch of the archive is measured against.
    let image_argv = template_entrypoint(slot)?;
    let built = SlotDigests::read(slot)?;
    if built.missing("verity") {
        bail!("the built pack has no dm-verity hash tree beside its rootfs; nothing was signed");
    }

    // ---- 3. Health: boot the baked entrypoint, require a clean exit ----
    eprintln!(
        "health check: booting {} and running its entrypoint",
        pack_ref(&lock)
    );
    owned.verify_revision()?;
    let exit_code = boot_entrypoint(health_call(slot, &loaded.spec, &args))
        .context("booting the built pack for its health check")?;
    if exit_code != 0 {
        bail!("health check failed: the entrypoint exited {exit_code}; nothing was signed");
    }

    // ---- 4. Nothing may change between the health check and signing ----
    owned.verify_revision()?;
    let checked = SlotDigests::read(slot)?;
    if checked != built {
        bail!(
            "built artifacts changed after the health check ({}); nothing was signed",
            built.changed(&checked).join(", ")
        );
    }

    // ---- 5. Seal and sign under the host key ----
    owned.verify_revision()?;
    let exported = export_template(
        slot,
        pack_export(&args.out, &loaded.spec, &lock, image_argv)?,
    )?;
    // The exporter re-read the slot's files; what it sealed must be what the
    // health check booted.
    if let Err(error) = owned.verify_revision() {
        let _ = fs::remove_file(&exported.path);
        return Err(error.context("private build revision changed during export; archive removed"));
    }
    let sealed = SlotDigests::sealed(&exported.path)?;
    if sealed != checked {
        let _ = fs::remove_file(&exported.path);
        bail!(
            "the sealed archive differs from the health-checked build ({}); it was removed",
            checked.changed(&sealed).join(", ")
        );
    }
    let digest = file_sha256(&exported.path)?;
    mvm_core::audit_emit!(
        PackBuild,
        "pack={},workload_sha256={},bundle_sha256={digest},key_id={}",
        pack_ref(&lock),
        lock.workload_sha256,
        exported.key_id.0
    );
    println!(
        "Built pack {} -> {} (sha256={digest}, key_id={})",
        pack_ref(&lock),
        exported.path.display(),
        exported.key_id.0
    );
    Ok(())
}

/// The builder produces images for this host's architecture; a spec that
/// targets another one is refused rather than built for the wrong machine.
fn require_host_target(spec: &PackSpec) -> Result<()> {
    let wanted = target_arch(spec.target);
    let host = GuestArch::host();
    if wanted != host {
        bail!(
            "pack targets {wanted}-linux but this host builds {host}-linux; build it on a {wanted} host"
        );
    }
    Ok(())
}

fn target_arch(target: PackTarget) -> GuestArch {
    match target {
        PackTarget::X86_64Linux => GuestArch::X86_64,
        PackTarget::Aarch64Linux => GuestArch::Aarch64,
    }
}

fn pack_ref(lock: &PackLock) -> String {
    format!("{}@{}", lock.identity.name, lock.identity.version)
}

fn health_call(slot: &str, spec: &PackSpec, args: &BuildArgs) -> EntrypointCall {
    EntrypointCall {
        source: slot.to_string(),
        stdin: EntrypointStdin::OneShot(Vec::new()),
        timeout: args.health_timeout,
        cpus: u32::from(spec.resources.cpu_cores),
        memory_mib: spec.resources.memory_mb,
        from_workload_ir: None,
        secret_flags: Vec::new(),
        manifest_secrets: Vec::new(),
        agent_verb_override: Vec::new(),
        caller_commitment: None,
        reset: false,
        keep_alive: false,
        machine_name: None,
        keep_alive_dev: false,
        session: None,
        r#fn: None,
        attach: false,
        show_denials: true,
        json_denials: false,
        review_source: ReviewSource::Unavailable(NoManifest::NotNamed),
        network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        hypervisor: args.hypervisor.clone(),
    }
}

/// What the archive records: the pack's identity as its label, the spec's
/// sizing, a sealed-production posture with no egress and no volumes, the lock
/// as the build's pinned input, and a signed environment naming the entrypoint
/// the health check ran, as the image records it. The environment requires no capability, so it fits
/// inside that posture, and a launch of the archive is refused if the image it
/// boots runs anything else.
fn pack_export(
    out: &Path,
    spec: &PackSpec,
    lock: &PackLock,
    image_argv: Vec<String>,
) -> Result<TemplateExport> {
    Ok(TemplateExport {
        environment: Some(pack_environment(spec, lock, image_argv)),
        label: Some(pack_ref(lock)),
        resources: Some(BundleResources {
            vcpus: u32::from(spec.resources.cpu_cores),
            mem_mib: spec.resources.memory_mb,
        }),
        posture: Some(PostureInputs::new(AgentProfile::SealedProd)),
        provenance: Some(BuildProvenance {
            input_kind: InputKind::NixFlake,
            input_ref: format!("pack:{}", pack_ref(lock)),
            lock_digest: Some(lock_digest(lock)?),
            builder_id: None,
            artifacts: Default::default(),
        }),
        ..TemplateExport::new(out.to_path_buf())
    })
}

/// The environment a launch of the built pack is held to.
fn pack_environment(
    spec: &PackSpec,
    lock: &PackLock,
    image_argv: Vec<String>,
) -> EnvironmentDescriptor {
    EnvironmentDescriptor {
        descriptor_version: ENVIRONMENT_DESCRIPTOR_VERSION,
        pack: Some(lock.identity.clone()),
        target: spec.target,
        entrypoint: EnvironmentEntrypoint {
            argv: image_argv,
            working_dir: None,
        },
        resources: Some(spec.resources.clone()),
        volumes: Vec::new(),
        secret_slots: Vec::new(),
        capabilities: Vec::new(),
        services: Vec::new(),
    }
}

/// SHA-256 of the lock's compact JSON, the form the build consumed.
fn lock_digest(lock: &PackLock) -> Result<String> {
    let bytes = serde_json::to_vec(lock).context("serializing pack lock")?;
    Ok(mvm_core::plan::bundle::sha256_hex(&bytes))
}

/// Digests of the artifacts a slot's current revision points at.
#[derive(Debug, PartialEq, Eq)]
struct SlotDigests {
    files: Vec<(&'static str, Option<String>)>,
}

impl SlotDigests {
    fn read(slot: &str) -> Result<Self> {
        let digests = template_artifact_digests(slot)?;
        Ok(Self::from_digests(
            Some(digests.kernel),
            digests.initrd,
            Some(digests.rootfs),
            digests.verity,
        ))
    }

    /// The same digests, as the manifest of a sealed archive records them.
    fn sealed(archive: &Path) -> Result<Self> {
        let manifest = sealed_manifest(archive)?;
        let digest = |role: ArtifactRole| {
            manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .map(|artifact| artifact.sha256.clone())
        };
        Ok(Self::from_digests(
            digest(ArtifactRole::Kernel),
            digest(ArtifactRole::Initrd),
            digest(ArtifactRole::Rootfs),
            digest(ArtifactRole::VerityHashSidecar),
        ))
    }

    fn from_digests(
        kernel: Option<String>,
        initrd: Option<String>,
        rootfs: Option<String>,
        verity: Option<String>,
    ) -> Self {
        Self {
            files: vec![
                ("kernel", kernel),
                ("initrd", initrd),
                ("rootfs", rootfs),
                ("verity", verity),
            ],
        }
    }

    /// Whether the artifact named `name` is absent.
    fn missing(&self, name: &str) -> bool {
        self.files
            .iter()
            .any(|(file, digest)| *file == name && digest.is_none())
    }

    fn changed(&self, other: &Self) -> Vec<&'static str> {
        self.files
            .iter()
            .zip(&other.files)
            .filter(|(a, b)| a != b)
            .map(|((name, _), _)| *name)
            .collect()
    }
}

/// The manifest of an archive this process just sealed. Only its artifact
/// digests are read, to compare with the build; the signature over it was
/// made a moment ago by this process.
fn sealed_manifest(archive: &Path) -> Result<BundleManifest> {
    let file = fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut entries = tar::Archive::new(file);
    for entry in entries
        .entries()
        .with_context(|| format!("reading {}", archive.display()))?
    {
        let entry = entry.with_context(|| format!("reading {}", archive.display()))?;
        if entry.path()?.as_os_str() == MANIFEST_FILENAME {
            return serde_json::from_reader(entry.take(MAX_MANIFEST_BYTES))
                .with_context(|| format!("parsing the manifest of {}", archive.display()));
        }
    }
    bail!("{} carries no {MANIFEST_FILENAME}", archive.display())
}

/// Bound on the manifest read back from a sealed archive.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

fn file_sha256(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn spec(target: &str) -> PackSpec {
        serde_json::from_value(serde_json::json!({
            "schema": "mvm.pack-spec/v1",
            "identity": { "name": "acme/hello", "version": "1.0.0" },
            "target": target,
            "source": { "kind": "local", "path": "." },
            "packages": [],
            "dependencies": [],
            "copy": [],
            "entrypoint": ["true"],
            "resources": { "cpu_cores": 2, "memory_mb": 256 }
        }))
        .unwrap()
    }

    #[test]
    fn a_spec_for_another_architecture_is_refused() {
        let other = match GuestArch::host() {
            GuestArch::X86_64 => "aarch64-linux",
            GuestArch::Aarch64 => "x86_64-linux",
        };
        let error = require_host_target(&spec(other)).unwrap_err();
        assert!(error.to_string().contains("build it on"));
        let own = match GuestArch::host() {
            GuestArch::X86_64 => "x86_64-linux",
            GuestArch::Aarch64 => "aarch64-linux",
        };
        require_host_target(&spec(own)).unwrap();
    }

    #[test]
    fn tree_digest_sees_content_mode_and_new_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/a"), "a").unwrap();
        let base = tree_digest(dir.path()).unwrap();
        assert_eq!(base, tree_digest(dir.path()).unwrap());

        fs::set_permissions(dir.path().join("src/a"), fs::Permissions::from_mode(0o755)).unwrap();
        let moded = tree_digest(dir.path()).unwrap();
        assert_ne!(base, moded);
        fs::write(dir.path().join("src/b"), "").unwrap();
        assert_ne!(moded, tree_digest(dir.path()).unwrap());
    }

    #[test]
    fn changed_names_each_artifact_that_differs() {
        let before = SlotDigests {
            files: vec![("kernel", Some("k".into())), ("rootfs", Some("r".into()))],
        };
        let after = SlotDigests {
            files: vec![("kernel", Some("k".into())), ("rootfs", Some("x".into()))],
        };
        assert_eq!(before.changed(&after), vec!["rootfs"]);
        assert!(before.changed(&before).is_empty());
        let unsealed = SlotDigests::from_digests(Some("k".into()), None, Some("r".into()), None);
        assert!(unsealed.missing("verity"));
        assert!(!unsealed.missing("rootfs"));
    }

    #[test]
    fn an_archive_without_a_manifest_is_not_taken_as_sealed() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("x.mvmpkg");
        let mut tar = tar::Builder::new(fs::File::create(&archive).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_cksum();
        tar.append_data(&mut header, "artifacts/vmlinux", &b"k"[..])
            .unwrap();
        tar.finish().unwrap();
        drop(tar);
        let error = SlotDigests::sealed(&archive).unwrap_err();
        assert!(error.to_string().contains(MANIFEST_FILENAME), "{error:#}");
    }

    #[test]
    fn the_export_records_identity_sizing_posture_and_lock() {
        let spec = spec("x86_64-linux");
        let lock: PackLock = serde_json::from_str(include_str!(
            "../../../../mvm-contract/tests/fixtures/pack-lock-v1/minimal.json"
        ))
        .unwrap();
        let boot = vec!["/nix/store/x-hello-boot".to_string()];
        let export = pack_export(Path::new("/tmp/x.mvmpkg"), &spec, &lock, boot.clone()).unwrap();
        assert_eq!(export.label.as_deref(), Some("acme/hello@1.0.0"));
        assert_eq!(
            export.resources,
            Some(BundleResources {
                vcpus: 2,
                mem_mib: 256
            })
        );
        let environment = export.environment.expect("a pack seals its environment");
        assert_eq!(environment.entrypoint.argv, boot);
        assert_eq!(environment.target, spec.target);
        assert!(environment.capabilities.is_empty());
        environment
            .validate()
            .expect("the sealed environment is well-formed");
        let provenance = export.provenance.unwrap();
        assert_eq!(provenance.input_ref, "pack:acme/hello@1.0.0");
        assert_eq!(provenance.lock_digest.unwrap().len(), 64);
        assert!(export.posture.is_some());
    }
}
