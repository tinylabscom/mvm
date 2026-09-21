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

use anyhow::{Context, Result, bail};
use mvm_runtime::machine::persist as mp;

use super::persistent::{PersistentImageStartParams, start_persistent_oci_machine};
use crate::volume::LaunchPreparation;

/// What the process starting a machine supplies that differs between the CLI
/// and a library embedder.
pub trait StartHost {
    /// The workload kernel to boot.
    fn workload_kernel(&self) -> Result<String>;

    /// The bootable rootfs for the OCI image `reference`, pulling and
    /// materializing it if it is not cached.
    fn resolve_image(&self, reference: &str) -> Result<BootImage>;

    /// `name`'s volumes, from the spec's volume declarations, merged with the
    /// machine's registered volumes and leased for this launch.
    fn prepare_volumes(&self, name: &str, volume_specs: &[String]) -> Result<LaunchPreparation>;
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
    mvm_runtime::backend::AnyBackend::require_hypervisor_selectable(params.hypervisor)?;
    // A granted allow-list is what the gate enforces; the legacy
    // `net`/`allow_host` fields decide the policy only for a spec that granted
    // no egress. Deriving it from the same spec the plan is admitted under is
    // what keeps the enforced policy and the signed one from diverging.
    let network_policy = crate::admission::run_grants::enforced_network_policy(
        spec.grants.as_ref().and_then(|g| g.egress.as_ref()),
        spec.net,
        None,
        &spec.allow_host,
    )?
    .with_ai(spec.ai.clone());
    let (memory_mib, mem_initial_mib) =
        mp::validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let boot = resolve_boot_source(spec, host)?;
    let kernel_path = match boot.kernel {
        Some(kernel) => kernel,
        None => host.workload_kernel()?,
    };
    let prepared_volumes = host
        .prepare_volumes(&spec.name, &spec.volumes)
        .context("resolving registered local volumes before admission")?;
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
        has_ad_hoc_argv: params.has_ad_hoc_argv,
        grants: spec.grants.clone(),
    })?;
    Ok(MachineStart {
        resolved_digest: boot.digest,
        admitted,
    })
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
}

impl EmbedderStartHost {
    /// A host for a machine running under `profile`, booting `image` if its
    /// spec names one.
    pub fn new(image: Option<BootImage>, profile: &str) -> Self {
        Self {
            image,
            profile: crate::volume::AdmittedProfile::from_profile_name(profile),
        }
    }
}

impl StartHost for EmbedderStartHost {
    fn workload_kernel(&self) -> Result<String> {
        let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let arch = mvm_core::arch::GuestArch::host().to_string();
        let (resolution, label) =
            mvm_build::kernel_fetch::resolve_workload_kernel(&cache, &arch, false);
        match resolution {
            mvm_build::kernel_fetch::KernelResolution::Cached(verified) => {
                Ok(verified.path().display().to_string())
            }
            _ => bail!(
                "starting a machine needs a verified workload kernel at {}, and this process \
                 does not build one — create it once with `mvmctl kernel build --which \
                 {label}`, then retry",
                mvm_build::kernel_fetch::cached_kernel_path(&cache, &arch, label).display()
            ),
        }
    }

    fn resolve_image(&self, reference: &str) -> Result<BootImage> {
        match &self.image {
            Some(image) if image.label == reference => Ok(image.clone()),
            _ => bail!("the image {reference:?} was not resolved before the start"),
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
            net: false,
            allow_host: Vec::new(),
            peer: Vec::new(),
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
            created_at: None,
            last_started_at: None,
            health_check: None,
            grants: None,
        }
    }

    /// A host that answers image resolution from a fixed record and refuses
    /// everything else, so a test sees exactly which of its methods ran.
    struct ImageOnlyHost {
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl StartHost for ImageOnlyHost {
        fn workload_kernel(&self) -> Result<String> {
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

    /// With nothing in the kernel cache the embedder refuses and says how to
    /// fill it, rather than building one.
    #[test]
    fn the_embedder_host_does_not_build_a_missing_kernel() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let err = EmbedderStartHost::new(None, "standard")
            .workload_kernel()
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
