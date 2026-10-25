//! Pack-source implementation for the `mvmctl build` front door.
//!
//! One path, every step reusing what already exists: the frozen compile
//! (`mvm_compiler::pack`), the flake build into a template slot (the builder
//! VM), a health boot of the baked entrypoint under the admitted launch path,
//! and the archive signed by the host key. Each artifact is digested
//! before the health boot and again before signing; anything that changed in
//! between is refused, so what is signed is exactly what was checked.
//!
//! The spec is parsed as data. Nothing here evaluates an author's Python or
//! TypeScript; an SDK that produced the spec ran in the author's own process.

use std::fs;
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
    EnvironmentEntrypoint,
};
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::security::AgentProfile;

use super::author::{LoadedSpec, locked_revision, read_lock};
use crate::commands::bundle::export::{ExportOptions, TemplateExport, stage_template};
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
    /// New path for the signed `.mvmpkg` archive; existing destinations are refused
    #[arg(long, value_name = "FILE.mvmpkg")]
    pub out: PathBuf,
    /// Seconds the health boot's entrypoint may run before it counts as failed
    #[arg(long, default_value_t = 120)]
    pub health_timeout: u64,
    /// Hypervisor for the health boot (default: this host's auto-selection)
    #[arg(long)]
    pub hypervisor: Option<String>,
    /// Write bounded frozen Nix input diagnostics (not an admission credential)
    #[arg(long, value_name = "PATH")]
    pub input_observation: Option<PathBuf>,
}

pub(in crate::commands) fn run_for_front_door(
    args: BuildArgs,
    options: ExportOptions,
) -> Result<()> {
    run_inner(args, options)
}

fn run_inner(args: BuildArgs, options: ExportOptions) -> Result<()> {
    let observation = args
        .input_observation
        .as_ref()
        .map(|destination| {
            if fs::symlink_metadata(destination).is_ok() {
                bail!("input observation destination already exists");
            }
            let parent = destination
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            tempfile::NamedTempFile::new_in(parent)
                .context("creating private input observation output")
        })
        .transpose()?;
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
    let health_backend = mvm_client::entrypoint::backend_name_for(args.hypervisor.as_deref())?;
    require_descriptor_health_backend(&health_backend)?;
    // Validate the frozen lock before any acquisition. Capture once before
    // builder/health effects; never build a runtime or substitute host caches.
    let portable = std::sync::Arc::new(
        mvm_client::portable_boot_assets::PreparedPortableBootAssets::acquire(GuestArch::host())?,
    );

    // ---- 2. Build the flake into a template slot in the builder VM ----
    eprintln!("building {} in the builder VM", pack_ref(&lock));
    let mut inputs = FrozenInputs::stage(&artifact, &compiled)?;
    if let Some(report) = &observation {
        inputs = inputs.with_input_observation(revision.as_str(), report.path().to_path_buf())?;
    }
    let owned = crate::commands::build::build::FrozenFlakeSlot::build(inputs)
        .context("building the compiled pack")?;
    let label = format!(
        "{}; {}",
        mvm_core::manifest::slot_dir(owned.slot_hash()),
        portable
            .retention_paths()
            .map(|p| p.display().to_string())
            .join("; "),
    );
    let producer = HealthInputRetention::new(
        ProducerInputs {
            build: owned,
            boot: portable,
        },
        label,
    );
    let slot = producer.build.slot_hash();
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
    let expected_export = built
        .clone()
        .selecting_initrd(producer.boot.initramfs_path())?;
    if built.missing("verity") {
        bail!("the built pack has no dm-verity hash tree beside its rootfs; nothing was signed");
    }

    // ---- 3. Health: boot the baked entrypoint, require a clean exit ----
    eprintln!(
        "health check: booting {} and running its entrypoint",
        pack_ref(&lock)
    );
    producer.build.verify_revision()?;
    let mut health = health_call(slot, &loaded.spec, &args);
    health.portable_boot_assets = Some(std::sync::Arc::clone(&producer.boot));
    // An error/panic does not prove no VM can still read these inputs.
    // This API returns a workload status, not an opaque generation-exit proof;
    // retain conservatively even after an acknowledged stop.
    producer.retain();
    let exit_code =
        boot_entrypoint(health).context("booting the built pack for its health check")?;
    if exit_code != 0 {
        bail!("health check failed: the entrypoint exited {exit_code}; nothing was signed");
    }

    // ---- 4. Nothing may change between the health check and signing ----
    producer.build.verify_revision()?;
    producer.boot.verify_integrity()?;
    let checked = SlotDigests::read(slot)?;
    if checked != built {
        bail!(
            "built artifacts changed after the health check ({}); nothing was signed",
            built.changed(&checked).join(", ")
        );
    }

    // ---- 5. Seal and sign under the host key ----
    producer.build.verify_revision()?;
    let mut export = options.apply(pack_export(&args.out, &loaded.spec, &lock, image_argv)?)?;
    export.local_build = true;
    export.portable_boot_assets = Some(std::sync::Arc::clone(&producer.boot));
    let mut staged = stage_template(slot, export)?;
    // The exporter re-read the slot's files; what it sealed must be what the
    // health check booted. Read and hash the same owned file before publication.
    let validation = (|| -> Result<String> {
        producer
            .build
            .verify_revision()
            .context("private build revision changed during export; archive not published")?;
        producer.boot.verify_integrity()?;
        let sealed = SlotDigests::from_manifest(&staged.manifest()?);
        if sealed != expected_export {
            bail!(
                "the sealed archive differs from the health-checked build ({}); \
                 archive not published",
                expected_export.changed(&sealed).join(", ")
            );
        }
        let digest = staged.sha256()?;
        producer
            .build
            .verify_revision()
            .context("private build revision changed during validation; archive not published")?;
        if let (Some(report), Some(destination)) = (observation, &args.input_observation) {
            report
                .persist_noclobber(destination)
                .context("publishing input observation without overwriting")?;
        }
        Ok(digest)
    })();
    let digest = match validation {
        Ok(digest) => digest,
        Err(error) => return Err(staged.abort(error)),
    };
    let exported = staged.publish()?;
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

fn require_descriptor_health_backend(backend: &str) -> Result<()> {
    anyhow::ensure!(
        backend == "hvf" || (cfg!(target_os = "linux") && backend == "firecracker"),
        "portable pack health requires HVF or same-host Linux Firecracker kernel descriptors"
    );
    Ok(())
}

struct ProducerInputs {
    build: crate::commands::build::build::FrozenFlakeSlot,
    boot: std::sync::Arc<mvm_client::portable_boot_assets::PreparedPortableBootAssets>,
}

/// Retaining input bytes is a one-way resource decision, not VM/exit authority.
/// An acknowledged stop alone never authorizes their deletion.
struct HealthInputRetention<T> {
    value: Option<T>,
    retain: std::cell::Cell<bool>,
    label: String,
}

impl<T> HealthInputRetention<T> {
    fn new(value: T, label: String) -> Self {
        Self {
            value: Some(value),
            retain: std::cell::Cell::new(false),
            label,
        }
    }
    fn retain(&self) {
        self.retain.set(true);
    }
}

impl<T> std::ops::Deref for HealthInputRetention<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value
            .as_ref()
            .expect("health input owner lives until Drop")
    }
}

impl<T> Drop for HealthInputRetention<T> {
    fn drop(&mut self) {
        if self.retain.get()
            && let Some(value) = self.value.take()
        {
            tracing::warn!(inputs = %self.label, "retaining producer inputs: deletion requires independently confirmed absence of native readers");
            std::mem::forget(value);
        }
    }
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
        portable_boot_assets: None,
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
        policy: None,
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct SlotDigests {
    files: Vec<(&'static str, Option<String>)>,
}

impl SlotDigests {
    /// Health selects the retained release initramfs, not an unused factory
    /// stage-1 initrd. The unchanged build slot is checked separately.
    fn selecting_initrd(mut self, path: &Path) -> Result<Self> {
        let digest = file_sha256(path)?;
        for (name, value) in &mut self.files {
            if *name == "initrd" {
                *value = Some(digest.clone());
            }
        }
        Ok(self)
    }

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
    fn from_manifest(manifest: &BundleManifest) -> Self {
        let digest = |role: ArtifactRole| {
            manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .map(|artifact| artifact.sha256.clone())
        };
        Self::from_digests(
            digest(ArtifactRole::Kernel),
            digest(ArtifactRole::Initrd),
            digest(ArtifactRole::Rootfs),
            digest(ArtifactRole::VerityHashSidecar),
        )
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

fn file_sha256(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_backend_requires_an_actual_same_host_descriptor_route() {
        assert!(require_descriptor_health_backend("hvf").is_ok());
        assert_eq!(
            require_descriptor_health_backend("firecracker").is_ok(),
            cfg!(target_os = "linux")
        );
        for backend in ["qemu", "libkrun", "mock", "docker", "unknown"] {
            assert!(require_descriptor_health_backend(backend).is_err());
        }
    }

    #[test]
    fn health_input_retention_survives_error_and_unwind_without_claiming_exit() {
        struct Probe(std::rc::Rc<std::cell::Cell<usize>>);
        impl Drop for Probe {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let dropped = std::rc::Rc::new(std::cell::Cell::new(0));
        drop(HealthInputRetention::new(
            Probe(dropped.clone()),
            "never-started".into(),
        ));
        assert_eq!(dropped.get(), 1);
        {
            let inputs = HealthInputRetention::new(Probe(dropped.clone()), "health-attempt".into());
            inputs.retain();
            // A returned status/error is not independent kernel-exit evidence.
        }
        assert_eq!(dropped.get(), 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let inputs = HealthInputRetention::new(Probe(dropped.clone()), "unwinding".into());
            inputs.retain();
            panic!("unit health failure");
        }));
        assert!(result.is_err());
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn selected_release_initrd_is_the_export_expectation_not_unused_factory_initrd() {
        let directory = tempfile::tempdir().unwrap();
        let initrd = directory.path().join("release-initrd");
        fs::write(&initrd, b"health-selected initrd").unwrap();
        let source = || {
            SlotDigests::from_digests(
                Some("kernel".into()),
                Some("factory-initrd".into()),
                Some("rootfs".into()),
                Some("verity".into()),
            )
        };
        let expected = source().selecting_initrd(&initrd).unwrap();
        assert_eq!(source().changed(&expected), vec!["initrd"]);
        let actual = SlotDigests::from_digests(
            Some("kernel".into()),
            Some(file_sha256(&initrd).unwrap()),
            Some("rootfs".into()),
            Some("verity".into()),
        );
        assert_eq!(expected, actual);
        fs::write(&initrd, b"substituted after health").unwrap();
        assert_eq!(
            expected.changed(&source().selecting_initrd(&initrd).unwrap()),
            vec!["initrd"],
        );
    }

    #[test]
    fn missing_selected_initrd_is_not_silently_omitted() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            SlotDigests::from_digests(Some("kernel".into()), None, Some("rootfs".into()), None,)
                .selecting_initrd(&directory.path().join("missing"))
                .is_err()
        );
    }

    #[test]
    fn input_observation_is_explicit_and_never_clobbers_existing_output() {
        #[derive(clap::Parser)]
        struct Parser {
            #[command(flatten)]
            args: BuildArgs,
        }
        use clap::Parser as _;
        let plain =
            Parser::try_parse_from(["pack-build", "missing.json", "--out", "out.mvmpkg"]).unwrap();
        assert!(plain.args.input_observation.is_none());
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        fs::write(&report, b"existing").unwrap();
        let parsed = Parser::try_parse_from([
            "pack-build",
            "missing.json",
            "--out",
            "out.mvmpkg",
            "--input-observation",
            report.to_str().unwrap(),
        ])
        .unwrap();
        let error = run_for_front_door(parsed.args, ExportOptions::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("destination already exists"), "{error}");
        assert_eq!(fs::read(&report).unwrap(), b"existing");
    }
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
    fn sealed_digests_follow_manifest_roles_and_expose_missing_artifacts() {
        use mvm_core::plan::bundle::BundleArtifact;

        let artifact = |role, name: &str, digest: &str| BundleArtifact {
            name: name.to_owned(),
            role,
            path: format!("artifacts/{name}"),
            sha256: digest.to_owned(),
            size_bytes: 1,
        };
        let mut manifest = BundleManifest {
            schema_version: 1,
            publisher: "host:test".into(),
            key_id: mvm_core::plan::KeyId("test-key".into()),
            arch: "aarch64".into(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-10-16T00:00:00Z".into(),
            labels: Default::default(),
            artifacts: vec![
                artifact(ArtifactRole::Rootfs, "rootfs", &"a".repeat(64)),
                artifact(ArtifactRole::Kernel, "vmlinux", &"b".repeat(64)),
                artifact(ArtifactRole::VerityHashSidecar, "verity", &"c".repeat(64)),
            ],
            members: Vec::new(),
            verity: None,
            resources: None,
        };
        let sealed = SlotDigests::from_manifest(&manifest);
        let expected = SlotDigests::from_digests(
            Some("b".repeat(64)),
            None,
            Some("a".repeat(64)),
            Some("c".repeat(64)),
        );
        assert_eq!(sealed, expected);
        assert!(sealed.missing("initrd"));
        assert!(!sealed.missing("verity"));

        manifest.artifacts[0].sha256 = "d".repeat(64);
        assert_eq!(
            sealed.changed(&SlotDigests::from_manifest(&manifest)),
            vec!["rootfs"]
        );
        manifest.artifacts.clear();
        let missing = SlotDigests::from_manifest(&manifest);
        for name in ["kernel", "initrd", "rootfs", "verity"] {
            assert!(missing.missing(name), "{name}");
        }
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
