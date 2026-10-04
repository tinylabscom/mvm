//! Start a persisted machine from its spec.
//!
//! The lifecycle half of `mvmctl machine start`: choose the backend, derive the
//! enforced network policy from the spec's grants, resolve what to boot (a
//! deployment, a built manifest slot, or an OCI image), and start it through
//! the persistent admission path. Presentation — dry runs, JSON, prompts,
//! receipts — stays with the caller.
//!
//! What differs between the processes that start machines comes through
//! [`StartHost`]: where the workload kernel comes from, how an OCI image
//! reference becomes a bootable rootfs, and how the machine's volumes are
//! prepared. The CLI may build a kernel or materialize a rootfs through the
//! builder VM; a library embedder never builds.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::machine::persist as mp;

use super::persistent::{PersistentImageStartParams, start_persistent_oci_machine};
use crate::secret::SecretService;
use crate::volume::LaunchPreparation;

/// What the process starting a machine supplies that differs between the CLI
/// and a library embedder.
pub trait StartHost {
    /// The workload kernel to boot on `backend`, or `None` when that backend
    /// carries its own.
    fn workload_kernel(&self, backend: &str) -> Result<Option<String>>;

    /// The bootable rootfs for the OCI image `reference`, pulling and
    /// materializing it if it is not cached.
    fn resolve_image(&self, reference: &str) -> Result<BootImage>;

    /// `name`'s volumes, from the spec's volume declarations, merged with the
    /// machine's registered volumes and leased for this launch.
    fn prepare_volumes(&self, name: &str, volume_specs: &[String]) -> Result<LaunchPreparation>;

    /// The secret service the machine's recorded secret references are
    /// validated against before admission: the host's own unless the caller
    /// was handed a different one.
    fn secret_service(&self) -> Result<Arc<SecretService>> {
        Ok(Arc::new(
            SecretService::local().context("opening the local secret service")?,
        ))
    }

    /// The backend that starts the machine on `hypervisor`.
    fn backend(&self, hypervisor: &str) -> AnyBackend {
        AnyBackend::from_hypervisor(hypervisor)
    }
}

/// A bootable rootfs and what it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootImage {
    /// How the image is named in the launch record, e.g. its reference.
    pub label: String,
    /// The materialized rootfs.
    pub rootfs: PathBuf,
    /// The digest the image resolved to.
    pub digest: String,
}

/// How to start a machine, beyond what its spec says.
#[derive(Debug, Clone, Copy)]
pub struct MachineStartParams<'a> {
    /// The backend to boot on, already resolved (see
    /// [`resolve_effective_hypervisor`]).
    pub hypervisor: &'a str,
    /// Whether the caller will run an ad-hoc command after boot, which issues
    /// a DevOnly verb and so rules out an attenuated ProdSafe grant.
    pub has_ad_hoc_argv: bool,
}

/// What a start resolved, for the caller to record once the machine is up.
#[derive(Debug)]
pub struct MachineStart {
    /// The digest of the artifact that booted.
    pub resolved_digest: String,
    /// The plan the machine was admitted and booted under.
    pub admitted: mvm_hostd::plan_admission::AdmittedPlan,
}

/// A validated local deployment: its directory, the rootfs it boots, and that
/// rootfs's recorded digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDeployment {
    pub directory: PathBuf,
    pub rootfs: PathBuf,
    pub boot_artifact_sha256: String,
}

/// Validate and resolve a local deployment before it can influence boot.
/// Both the record schema and the exact selected rootfs bytes are checked.
pub fn resolve_local_deployment(path: &Path) -> Result<LocalDeployment> {
    let directory = std::fs::canonicalize(path)
        .with_context(|| format!("resolving deployment directory {}", path.display()))?;
    if !directory.is_dir() {
        bail!(
            "deployment path is not a directory: {}",
            directory.display()
        );
    }
    let record_path = directory.join("deploy.json");
    let rootfs = directory.join("rootfs.ext4");
    let record = mvm_sdk::deploy::read_deploy_record(&record_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("reading deployment record {}", record_path.display()))?;
    mvm_sdk::deploy::verify_boot_artifact(&rootfs, &record.boot_artifact)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("verifying deployment boot artifact {}", rootfs.display()))?;
    Ok(LocalDeployment {
        directory,
        rootfs,
        boot_artifact_sha256: record.boot_artifact.sha256,
    })
}

/// Resolve the requested hypervisor to the effective one for this host.
/// `firecracker` (the default `--hypervisor`) delegates to the runtime's
/// canonical auto-detect ladder: KVM → firecracker, supported Apple Silicon
/// macOS → hvf, else firecracker (surfaces a clear "not available" error). Any
/// explicit value is returned as-is. The `MVM_HYPERVISOR` env var (alias
/// `MVM_BACKEND`) overrides auto-detect — the workload-VMM override mirroring
/// `MVM_BUILDER_BACKEND` for the builder, so a Linux/KVM host can opt into
/// `libkrun` instead of the Firecracker default. Single source of truth, shared
/// by the run/pool paths so they agree on the backend.
pub fn resolve_effective_hypervisor(requested: &str) -> String {
    if requested != "firecracker" {
        return requested.to_string();
    }
    // Env override (auto-detect mode only — an explicit `--hypervisor` flag
    // already won above): `MVM_HYPERVISOR=<firecracker|libkrun|hvf|qemu>`, with
    // the older `MVM_BACKEND` kept as a back-compat alias. Does not change the
    // platform default.
    for var in ["MVM_HYPERVISOR", "MVM_BACKEND"] {
        if let Some(name) = std::env::var_os(var) {
            let name = name.to_string_lossy().trim().to_ascii_lowercase();
            if !name.is_empty() {
                return name;
            }
        }
    }
    crate::auto_selected_backend_name()
}

/// What a machine boots, resolved from its spec.
struct BootSource {
    /// A kernel the source names itself (the direct-boot test path), in place
    /// of the host's workload kernel.
    kernel: Option<String>,
    label: String,
    rootfs: PathBuf,
    digest: String,
}

/// Resolve what `spec` boots: a deployment, a built manifest slot, or an OCI
/// image the host resolves. `MVM_DIRECT_BOOT=1` substitutes a
/// kernel and rootfs from the environment, for tests.
fn resolve_boot_source(spec: &mp::MachineSpec, host: &dyn StartHost) -> Result<BootSource> {
    if std::env::var("MVM_DIRECT_BOOT").as_deref() == Ok("1") {
        let kernel = std::env::var("MVM_KERNEL_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_DIRECT_BOOT requires MVM_KERNEL_PATH"))?;
        let rootfs = std::env::var("MVM_ROOTFS_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_DIRECT_BOOT requires MVM_ROOTFS_PATH"))?;
        return Ok(BootSource {
            kernel: Some(kernel),
            label: "direct-boot".to_string(),
            rootfs: PathBuf::from(rootfs),
            digest: "direct-boot".to_string(),
        });
    }
    if let Some(deployment_path) = &spec.deployment {
        let deployment = resolve_local_deployment(Path::new(deployment_path))?;
        return Ok(BootSource {
            kernel: None,
            label: format!("deployment:{}", deployment.directory.display()),
            rootfs: deployment.rootfs,
            digest: deployment.boot_artifact_sha256,
        });
    }
    if let Some(slot_hash) = &spec.manifest {
        let (_, _vmlinux, _initrd, rootfs, rev) =
            mvm_runtime::vm::template::lifecycle::template_artifacts_for_slot(slot_hash)
                .with_context(|| {
                    format!("loading manifest slot {slot_hash:?} for machine start")
                })?;
        return Ok(BootSource {
            kernel: None,
            label: format!("manifest:{slot_hash}"),
            rootfs: PathBuf::from(rootfs),
            digest: rev,
        });
    }
    if let Some(image_ref) = &spec.image {
        let image = host.resolve_image(image_ref)?;
        return Ok(BootSource {
            kernel: None,
            label: image.label,
            rootfs: image.rootfs,
            digest: image.digest,
        });
    }
    bail!(
        "machine {name:?} spec has neither deployment, image, nor manifest — use `machine rm` to remove and recreate it",
        name = spec.name
    )
}

fn persisted_network_policy(
    spec: &mp::MachineSpec,
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    // A granted allow-list is what the gate enforces; the legacy
    // `net`/`allow_host` fields decide the policy only for a spec that granted
    // no egress. Deriving it from the same spec the plan is admitted under is
    // what keeps the enforced policy and the signed one from diverging.
    Ok(crate::admission::run_grants::enforced_network_policy(
        spec.grants.as_ref().and_then(|g| g.egress.as_ref()),
        spec.net,
        None,
        &spec.allow_host,
    )?
    .with_ai(spec.ai.clone())
    .with_routes(spec.routes.clone()))
}

/// Start the machine `spec` describes on `params.hypervisor`.
///
/// The spec is not modified; once the machine is up and anything the caller
/// runs after boot has succeeded, the caller stamps it with
/// [`record_machine_started`].
pub fn start_machine_spec(
    spec: &mp::MachineSpec,
    host: &dyn StartHost,
    params: MachineStartParams<'_>,
) -> Result<MachineStart> {
    AnyBackend::require_hypervisor_selectable(params.hypervisor)?;
    validate_registry_pack_source(spec)?;
    let network_policy = persisted_network_policy(spec)?;
    let (memory_mib, mem_initial_mib) =
        mp::validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let boot = resolve_boot_source(spec, host)?;
    let kernel_path = match boot.kernel {
        Some(kernel) => Some(kernel),
        None => host.workload_kernel(params.hypervisor)?,
    };
    // Validated before any volume is leased, so a missing secret refuses the
    // start without leaving a lease behind.
    let secrets =
        crate::admission::secrets::resolve_machine_secrets(&spec.name, &*host.secret_service()?)?;
    let prepared_volumes = host
        .prepare_volumes(&spec.name, &spec.volumes)
        .context("resolving registered local volumes before admission")?;
    let workload_dir = persistent_workload_dir(spec);
    let admitted = start_persistent_oci_machine(PersistentImageStartParams {
        name: &spec.name,
        image_label: &boot.label,
        resolved_digest: &boot.digest,
        rootfs_path: &boot.rootfs,
        profile: &spec.profile,
        cpus: spec.cpus,
        memory_mib,
        mem_initial_mib,
        prepared_volumes,
        network_policy,
        ports: &spec.ports,
        backend_name: params.hypervisor,
        kernel_path,
        agent_verb: spec.agent_verb.clone(),
        caller_commitment: spec.caller_commitment.clone(),
        registry_pack_image: spec.registry_pack_image.clone(),
        tools: spec.tools.clone(),
        has_ad_hoc_argv: params.has_ad_hoc_argv,
        grants: spec.grants.clone(),
        gpu: spec.gpu,
        gpu_device: spec.gpu_device,
        workload_dir: workload_dir.as_deref(),
        secrets,
        backend: host.backend(params.hypervisor),
    })?;
    Ok(MachineStart {
        resolved_digest: boot.digest,
        admitted,
    })
}

fn validate_registry_pack_source(spec: &mp::MachineSpec) -> Result<()> {
    if spec.registry_pack_image.is_some() {
        anyhow::ensure!(
            spec.manifest.is_some()
                && spec.image.is_none()
                && spec.deployment.is_none()
                && !spec.runtime_pack,
            "a pinned registry pack image requires exactly a built manifest source"
        );
    }
    Ok(())
}

/// The workload kernel a process that never builds one can boot on
/// `backend`: `None` for a backend that carries its own kernel (libkrun boots
/// libkrunfw's, the mock boots nothing), otherwise the verified kernel in the
/// cache. A cache hit means the bytes matched their recorded digest; a miss,
/// or an entry that failed to verify and was evicted, is refused with the
/// command that fills it.
pub fn cached_workload_kernel(backend: &str) -> Result<Option<String>> {
    use mvm_core::protocol::vm_backend::BackendKind;
    match crate::backend_kind_for(backend) {
        BackendKind::Mock | BackendKind::Libkrun => return Ok(None),
        _ => {}
    }
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let (resolution, label) =
        mvm_build::kernel_fetch::resolve_kernel_for_workload(&cache, &arch, false);
    match resolution {
        mvm_build::kernel_fetch::KernelResolution::Cached(verified) => {
            Ok(Some(verified.path().display().to_string()))
        }
        _ => bail!(
            "{backend} needs a verified workload kernel at {}, and this process does not \
             build one — create it once with `mvmctl kernel build --which {label}`, then retry",
            mvm_build::kernel_fetch::cached_kernel_path(&cache, &arch, label).display()
        ),
    }
}

/// How a library embedder supplies a start.
///
/// It never builds. The workload kernel comes only from the verified cache,
/// the image is one the caller resolved before the start (resolution is
/// asynchronous, the start is not), and volumes are leased from the local
/// catalog. A spec carrying CLI-grammar volume strings is refused: there is no
/// parser for them on this side, and dropping them would boot a machine
/// without mounts its spec asked for.
pub struct EmbedderStartHost {
    image: Option<BootImage>,
    profile: crate::volume::AdmittedProfile,
    secrets: Option<Arc<SecretService>>,
    backend: Option<AnyBackend>,
}

impl EmbedderStartHost {
    /// A host for a machine running under `profile`, booting `image` if its
    /// spec names one.
    pub fn new(image: Option<BootImage>, profile: &str) -> Self {
        Self {
            image,
            profile: crate::volume::AdmittedProfile::from_profile_name(profile),
            secrets: None,
            backend: None,
        }
    }

    /// Start on `backend` when the machine's hypervisor is the one it runs,
    /// so a caller holding a backend sees the machines started through this
    /// host.
    #[must_use]
    pub fn with_backend(mut self, backend: &AnyBackend) -> Self {
        self.backend = Some(backend.handle());
        self
    }

    /// Validate the machine's secret references against `service` rather
    /// than the host's own.
    #[must_use]
    pub fn with_secret_service(mut self, service: Arc<SecretService>) -> Self {
        self.secrets = Some(service);
        self
    }
}

impl StartHost for EmbedderStartHost {
    fn workload_kernel(&self, backend: &str) -> Result<Option<String>> {
        cached_workload_kernel(backend)
    }

    fn resolve_image(&self, reference: &str) -> Result<BootImage> {
        match &self.image {
            Some(image) if image.label == reference => Ok(image.clone()),
            _ => bail!("the image {reference:?} was not resolved before the start"),
        }
    }

    fn secret_service(&self) -> Result<Arc<SecretService>> {
        match &self.secrets {
            Some(service) => Ok(Arc::clone(service)),
            None => Ok(Arc::new(
                SecretService::local().context("opening the local secret service")?,
            )),
        }
    }

    fn backend(&self, hypervisor: &str) -> AnyBackend {
        match &self.backend {
            Some(backend) if backend.name() == hypervisor => backend.handle(),
            _ => AnyBackend::from_hypervisor(hypervisor),
        }
    }

    fn prepare_volumes(&self, name: &str, volume_specs: &[String]) -> Result<LaunchPreparation> {
        if !volume_specs.is_empty() {
            bail!(
                "machine {name:?} declares CLI-grammar volume strings, which a library start \
                 cannot parse; attach managed volumes instead"
            );
        }
        use crate::volume::VolumeService as _;
        let request = crate::volume::LaunchLeaseRequest::builder(name)?
            .profile(self.profile)
            .unlock(crate::volume::UnlockPolicy::JustInTime)
            .build();
        crate::volume::LocalVolumeService::new()
            .acquire_launch_lease(&request)
            .with_context(|| format!("volume leases for {name:?}"))
    }
}

/// Resolve the OCI image or rootfs `reference` to a bootable rootfs for the
/// machine `name`, recording the digest of the bytes that will boot.
pub async fn resolve_boot_image(reference: &str, name: &str) -> Result<BootImage> {
    let source: mvm_core::rootfs_source::RootfsSource = reference
        .parse()
        .map_err(|e| anyhow::anyhow!("image {reference:?}: {e}"))?;
    let rootfs = crate::local::resolve_local_rootfs(&source, name)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let digest = mvm_core::crypto::image_verify::sha256_file_cached(&rootfs)
        .with_context(|| format!("hashing rootfs at {}", rootfs.display()))?;
    Ok(BootImage {
        label: reference.to_string(),
        rootfs,
        digest: format!("sha256:{digest}"),
    })
}

/// Stamp `spec` as started from the artifact with `resolved_digest`, now.
pub fn record_machine_started(spec: &mut mp::MachineSpec, resolved_digest: String) {
    spec.resolved_digest = Some(resolved_digest);
    spec.last_started_at = Some(mvm_core::time::utc_now());
}

fn persistent_workload_dir(spec: &mp::MachineSpec) -> Option<PathBuf> {
    spec.workload_dir.as_deref().map(PathBuf::from).or_else(|| {
        let manifest = spec.manifest.as_deref()?;
        crate::instruction_trust::gate::local_workload_dir(None, Some(manifest)).or_else(|| {
            let path = std::path::Path::new(manifest);
            (path.extension() == Some(std::ffi::OsStr::new("toml"))).then(|| {
                path.parent()
                    .map_or_else(|| PathBuf::from("."), PathBuf::from)
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn spec(name: &str) -> mp::MachineSpec {
        mp::MachineSpec {
            schema_version: mp::MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: None,
            manifest: None,
            deployment: None,
            resolved_digest: None,
            runtime_pack: false,
            registry_pack_image: None,
            tools: Default::default(),
            net: false,
            allow_host: Vec::new(),
            peer: Vec::new(),
            routes: Vec::new(),
            ai: None,
            ports: Vec::new(),
            cpus: 1,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            agent_verb: Vec::new(),
            caller_commitment: None,
            workload_dir: None,
            created_at: None,
            last_started_at: None,
            health_check: None,
            grants: None,
            gpu: false,
            gpu_device: None,
        }
    }

    #[test]
    fn a_persistent_pack_pin_requires_a_manifest_source() {
        let mut machine = spec("pack-image");
        machine.registry_pack_image = Some(
            mvm_core::registry_pack::PackPin::new(
                "runtime/python@1.1.0".parse().expect("reference"),
                mvm_core::packs::Sha256Hex::from_bytes(b"signed manifest"),
            )
            .expect("pin"),
        );
        assert!(validate_registry_pack_source(&machine).is_err());
        machine.manifest = Some("built-slot".to_string());
        validate_registry_pack_source(&machine).expect("pack with manifest source");
        machine.image = Some("alpine:3.20".to_string());
        assert!(validate_registry_pack_source(&machine).is_err());
    }

    #[test]
    fn a_persisted_route_is_reapplied_to_the_start_policy() {
        use mvm_contract::policy::routes::{EgressRoute, EndpointRule, RouteOutcome};

        let mut machine = spec("routed");
        machine.allow_host = vec!["api.github.com:443".into()];
        machine.routes = vec![EgressRoute {
            id: "github".into(),
            host: "api.github.com".into(),
            port: 443,
            rules: vec![EndpointRule {
                id: None,
                method: Some("GET".into()),
                path: "/repos/**".into(),
                outcome: RouteOutcome::Allow,
            }],
            otherwise: RouteOutcome::Deny,
            intercept: true,
        }];

        let policy = persisted_network_policy(&machine).expect("network policy");
        assert_eq!(policy.routes(), machine.routes);
    }

    /// A host that answers image resolution from a fixed record and refuses
    /// everything else, so a test sees exactly which of its methods ran.
    struct ImageOnlyHost {
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl StartHost for ImageOnlyHost {
        fn workload_kernel(&self, _: &str) -> Result<Option<String>> {
            bail!("not asked for a kernel")
        }

        fn resolve_image(&self, reference: &str) -> Result<BootImage> {
            self.asked.borrow_mut().push(reference.to_string());
            Ok(BootImage {
                label: format!("label:{reference}"),
                rootfs: PathBuf::from("/cache/rootfs.ext4"),
                digest: "sha256:abc".to_string(),
            })
        }

        fn prepare_volumes(&self, _: &str, _: &[String]) -> Result<LaunchPreparation> {
            bail!("not asked for volumes")
        }
    }

    fn image_host() -> ImageOnlyHost {
        ImageOnlyHost {
            asked: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// An image-backed spec boots what the host resolved for its reference,
    /// and the host is asked for that reference and nothing else.
    #[test]
    fn an_image_spec_boots_what_the_host_resolved() {
        let mut env = TestEnv::new();
        env.remove("MVM_DIRECT_BOOT");
        let host = image_host();
        let mut machine = spec("web");
        machine.image = Some("alpine:3.20".to_string());

        let boot = resolve_boot_source(&machine, &host).unwrap();
        assert_eq!(host.asked.borrow().as_slice(), ["alpine:3.20"]);
        assert_eq!(boot.label, "label:alpine:3.20");
        assert_eq!(boot.rootfs, PathBuf::from("/cache/rootfs.ext4"));
        assert_eq!(boot.digest, "sha256:abc");
        assert_eq!(boot.kernel, None, "the host's kernel is used");
    }

    #[test]
    fn persistent_workload_dir_prefers_the_persisted_source_dir() {
        let mut machine = spec("web");
        machine.workload_dir = Some("/persisted/project".to_string());
        machine.manifest = Some("/other/mvm.toml".to_string());
        assert_eq!(
            persistent_workload_dir(&machine),
            Some(PathBuf::from("/persisted/project"))
        );
    }

    #[test]
    fn persistent_workload_dir_falls_back_to_a_local_manifest_path() {
        let mut machine = spec("web");
        machine.manifest = Some("/workspace/project/mvm.toml".to_string());
        assert_eq!(
            persistent_workload_dir(&machine),
            Some(PathBuf::from("/workspace/project"))
        );
    }

    #[test]
    fn a_spec_with_nothing_to_boot_is_refused() {
        let mut env = TestEnv::new();
        env.remove("MVM_DIRECT_BOOT");
        let host = image_host();
        let err = resolve_boot_source(&spec("empty"), &host)
            .err()
            .expect("nothing bootable");
        assert!(
            err.to_string()
                .contains("neither deployment, image, nor manifest"),
            "{err:#}"
        );
        assert!(host.asked.borrow().is_empty());
    }

    /// A deployment is resolved and verified here, not by the host, and a
    /// directory that does not exist fails the start.
    #[test]
    fn a_missing_deployment_is_refused_before_the_host_is_asked() {
        let mut env = TestEnv::new();
        env.remove("MVM_DIRECT_BOOT");
        let host = image_host();
        let mut machine = spec("deployed");
        machine.deployment = Some("/definitely/not/a/deployment".to_string());
        machine.image = Some("alpine:3.20".to_string());

        assert!(resolve_boot_source(&machine, &host).is_err());
        assert!(
            host.asked.borrow().is_empty(),
            "the deployment wins over the image"
        );
    }

    /// The direct-boot test path supplies its own kernel and rootfs, and
    /// refuses to run half-configured.
    #[test]
    fn direct_boot_takes_kernel_and_rootfs_from_the_environment() {
        let mut env = TestEnv::new();
        env.set("MVM_DIRECT_BOOT", "1");
        env.remove("MVM_KERNEL_PATH");
        let host = image_host();
        assert!(resolve_boot_source(&spec("direct"), &host).is_err());

        env.set("MVM_KERNEL_PATH", "/k/vmlinux");
        env.set("MVM_ROOTFS_PATH", "/r/rootfs.ext4");
        let boot = resolve_boot_source(&spec("direct"), &host).unwrap();
        assert_eq!(boot.kernel.as_deref(), Some("/k/vmlinux"));
        assert_eq!(boot.rootfs, PathBuf::from("/r/rootfs.ext4"));
        assert!(host.asked.borrow().is_empty());
    }

    /// The embedder host only boots the image it was handed, and only for
    /// the reference it was handed it for.
    #[test]
    fn the_embedder_host_boots_only_the_image_it_was_given() {
        let image = BootImage {
            label: "alpine:3.20".to_string(),
            rootfs: PathBuf::from("/cache/rootfs.ext4"),
            digest: "sha256:abc".to_string(),
        };
        let host = EmbedderStartHost::new(Some(image.clone()), "standard");
        assert_eq!(host.resolve_image("alpine:3.20").unwrap(), image);
        assert!(host.resolve_image("alpine:3.19").is_err());
        assert!(
            EmbedderStartHost::new(None, "standard")
                .resolve_image("alpine:3.20")
                .is_err()
        );
    }

    /// A spec with CLI-grammar volume strings is refused rather than started
    /// without the mounts it asked for.
    #[test]
    fn the_embedder_host_refuses_cli_grammar_volumes() {
        let host = EmbedderStartHost::new(None, "standard");
        let err = host
            .prepare_volumes("web", &["/host:/guest".to_string()])
            .expect_err("refused");
        assert!(
            err.to_string().contains("CLI-grammar volume strings"),
            "{err:#}"
        );
    }

    /// Register a writable attachment of an unlocked managed block volume
    /// for `owner`, under the default library profile.
    fn register_writable_managed_volume(home: &crate::volume::test_support::TestVolumeHome) {
        use crate::volume::VolumeService as _;
        home.create_block("state", 16);
        let volumes = crate::volume::LocalVolumeService::new();
        volumes.unlock_volume("state").expect("unlock");
        let request = crate::volume::AttachmentRequest::builder("web", "state")
            .and_then(|b| {
                b.guest_path("/data/state")
                    .access(crate::volume::AccessMode::ReadWrite)
                    .profile(crate::volume::AdmittedProfile::from_profile_name(
                        "standard",
                    ))
                    .build()
            })
            .expect("standard registers a writable managed volume");
        volumes.prepare_attachment(&request).expect("attach");
    }

    /// An embedder starting a machine under the default `standard` profile
    /// gets its writable managed volume, as `dev` and `permissive` do: the
    /// guest writes into the volume's own disk image.
    #[test]
    fn the_embedder_host_leases_a_writable_managed_volume_under_standard() {
        let home = crate::volume::test_support::TestVolumeHome::new();
        register_writable_managed_volume(&home);
        for profile in ["standard", "dev", "permissive"] {
            let prepared = EmbedderStartHost::new(None, profile)
                .prepare_volumes("web", &[])
                .unwrap_or_else(|e| panic!("{profile}: {e:#}"));
            assert_eq!(prepared.volumes.len(), 1, "{profile}");
            assert_eq!(prepared.volumes[0].guest, "/data/state");
            assert!(!prepared.volumes[0].read_only, "{profile}");
            // Dropped uncommitted, so the next profile can take the lease.
        }
    }

    /// `restrictive` grants no writable disk image, and a profile name that
    /// is not a preset grants nothing; both refuse the writable volume.
    #[test]
    fn the_embedder_host_refuses_a_writable_managed_volume_under_restrictive() {
        let home = crate::volume::test_support::TestVolumeHome::new();
        register_writable_managed_volume(&home);
        for (profile, named) in [
            ("restrictive", "profile \"restrictive\""),
            ("prod", "no recognised profile"),
        ] {
            let message = format!(
                "{:#}",
                EmbedderStartHost::new(None, profile)
                    .prepare_volumes("web", &[])
                    .expect_err("no writable volume without the grant")
            );
            assert!(message.contains("does not permit writable"), "{message}");
            assert!(message.contains(named), "{message}");
        }
    }

    /// With nothing in the kernel cache the embedder refuses and says how to
    /// fill it, rather than building one.
    #[test]
    fn the_embedder_host_does_not_build_a_missing_kernel() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let err = EmbedderStartHost::new(None, "standard")
            .workload_kernel("firecracker")
            .expect_err("no cached kernel");
        let message = err.to_string();
        assert!(message.contains("does not build one"), "{message}");
        assert!(
            message.contains("mvmctl kernel build --which workload"),
            "{message}"
        );
    }

    #[test]
    fn recording_a_start_stamps_the_digest_and_time() {
        let mut machine = spec("web");
        record_machine_started(&mut machine, "sha256:def".to_string());
        assert_eq!(machine.resolved_digest.as_deref(), Some("sha256:def"));
        assert!(machine.last_started_at.is_some());
    }

    /// An explicit `--hypervisor <x>` (anything but the `firecracker`
    /// auto-detect sentinel) is returned verbatim — so a Linux/KVM host can
    /// select `libkrun` (or any other backend) without env.
    #[test]
    fn explicit_hypervisor_is_returned_verbatim() {
        assert_eq!(resolve_effective_hypervisor("libkrun"), "libkrun");
        assert_eq!(resolve_effective_hypervisor("hvf"), "hvf");
        assert_eq!(resolve_effective_hypervisor("qemu"), "qemu");
    }

    /// `MVM_HYPERVISOR` overrides auto-detect (and `MVM_BACKEND` is the
    /// back-compat alias); an explicit flag still wins over both. Process-isolated
    /// under nextest; restored here so a threaded runner doesn't leak it.
    #[test]
    fn env_overrides_auto_detect_with_alias() {
        let mut env = TestEnv::new();
        env.remove("MVM_BACKEND");
        env.set("MVM_HYPERVISOR", "libkrun");
        assert_eq!(resolve_effective_hypervisor("firecracker"), "libkrun");
        // An explicit flag wins over the env override.
        assert_eq!(resolve_effective_hypervisor("qemu"), "qemu");
        // The older alias is still honored.
        env.remove("MVM_HYPERVISOR");
        env.set("MVM_BACKEND", "hvf");
        assert_eq!(resolve_effective_hypervisor("firecracker"), "hvf");
    }

    /// On the macOS-26 Apple Silicon tier the auto-detect default is the
    /// HVF VMM (`hvf`). Host-conditioned: the assertion only fires on a host
    /// that actually reports the tier.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_26_default_is_hvf() {
        if !mvm_core::platform::current().is_hvf_default_tier() {
            return; // Not on the macOS-26 tier (e.g. macOS 13-25 CI runner).
        }
        let mut env = TestEnv::new();
        env.remove("MVM_HYPERVISOR");
        env.remove("MVM_BACKEND");
        assert_eq!(resolve_effective_hypervisor("firecracker"), "hvf");
    }
}
