//! Construction of a persistent machine spec from CLI and manifest inputs.

use super::*;

#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct MachinePackBaseArgs {
    /// Local signed image-set manifest for a development composition.
    #[arg(id = "pack_base_manifest", long = "pack-base-manifest", value_name = "PATH", requires_all = ["pack", "pack_base_kernel", "pack_base_tar"], hide = true)]
    pub manifest: Option<PathBuf>,
    /// Kernel named by the local image-set manifest.
    #[arg(id = "pack_base_kernel", long = "pack-base-kernel", value_name = "PATH", requires_all = ["pack", "pack_base_manifest", "pack_base_tar"], hide = true)]
    pub kernel: Option<PathBuf>,
    /// Composition tar named by the local image-set manifest.
    #[arg(id = "pack_base_tar", long = "pack-base-tar", value_name = "PATH", requires_all = ["pack", "pack_base_manifest", "pack_base_kernel"], hide = true)]
    pub tar: Option<PathBuf>,
    /// PR-only runtime quartet, never a release input.
    #[cfg(feature = "pr-test-guest-runtime")]
    #[arg(id = "pack_pr_test_runtime_dir", long = "pack-pr-test-runtime-dir", value_name = "PATH", requires_all = ["pack_base_manifest", "pack_pr_test_pull_request"], hide = true)]
    pub pr_runtime_dir: Option<PathBuf>,
    /// Pull request whose workflow signed the test runtime.
    #[cfg(feature = "pr-test-guest-runtime")]
    #[arg(id = "pack_pr_test_pull_request", long = "pack-pr-test-pull-request", value_name = "NUMBER", requires_all = ["pack_base_manifest", "pack_pr_test_runtime_dir"], hide = true)]
    pub pr_pull_request: Option<u64>,
}

impl MachinePackBaseArgs {
    pub(super) fn selected(&self) -> Result<Option<mvm_client::machine_spec::LocalPackBaseSource>> {
        use mvm_client::machine_spec::{LocalPackBaseSource, LocalPackPrRuntime};

        #[cfg(feature = "pr-test-guest-runtime")]
        let pr_runtime = match (&self.pr_runtime_dir, self.pr_pull_request) {
            (Some(directory), Some(pull_request)) => Some(LocalPackPrRuntime {
                directory: directory.clone(),
                pull_request,
            }),
            (None, None) => None,
            _ => anyhow::bail!("PR test runtime requires its directory and pull request"),
        };
        #[cfg(not(feature = "pr-test-guest-runtime"))]
        let pr_runtime: Option<LocalPackPrRuntime> = None;
        match (&self.manifest, &self.kernel, &self.tar) {
            (Some(manifest), Some(kernel), Some(tar)) => Ok(Some(
                LocalPackBaseSource::from_selected(manifest, kernel, tar, pr_runtime)?,
            )),
            (None, None, None) if pr_runtime.is_none() => Ok(None),
            _ => anyhow::bail!("local pack base requires a manifest, kernel and composition tar"),
        }
    }
}

/// Inputs shared by `machine create` and `machine start --image`.
pub(super) struct MachineSpecInputs<'a> {
    pub name: &'a str,
    pub image: Option<&'a str>,
    pub local_pack: Option<&'a mvm_client::machine_spec::LocalPackSource>,
    pub net: bool,
    pub allow_host: &'a [String],
    pub peer: &'a [String],
    pub routes: &'a [EgressRoute],
    pub gpu: bool,
    pub gpu_device: Option<u32>,
    pub ai: Option<&'a mvm_core::network_policy::AiPolicy>,
    pub cpus: Option<u32>,
    pub cpu_limit: Option<u32>,
    pub timeout: Option<u64>,
    pub grants_file: Option<&'a Path>,
    pub memory: Option<&'a str>,
    pub mem_initial: Option<&'a str>,
    pub profile: Option<RunProfile>,
    pub workflow: Option<&'a ManifestMachineWorkflow>,
    pub volumes: &'a [String],
    pub init: &'a [String],
    pub policy: &'a [String],
    pub project: Option<&'a mvm_client::policy_profiles::ProjectPolicy>,
}

pub(super) fn build_machine_spec(inputs: MachineSpecInputs<'_>) -> Result<MachineSpec> {
    validate_machine_name(inputs.name)?;
    let workflow = inputs.workflow;
    anyhow::ensure!(
        inputs.local_pack.is_none() || (inputs.image.is_none() && workflow.is_none()),
        "local pack cannot be combined with an image or manifest source"
    );
    let image = match (inputs.image, workflow, inputs.local_pack) {
        (Some(image), _, None) => Some(image.to_string()),
        (None, Some(workflow), None) => Some(workflow.image.clone()),
        (None, None, Some(_)) => None,
        (None, None, None) => {
            bail!(
                "machine {} requires --image, --manifest or --pack",
                inputs.name
            )
        }
        _ => bail!("local pack cannot be combined with another machine source"),
    };
    let net = inputs.net || workflow.is_some_and(|workflow| workflow.net);
    let gpu_device = inputs
        .gpu_device
        .or_else(|| workflow.and_then(|workflow| workflow.gpu_device));
    let gpu = inputs.gpu || gpu_device.is_some() || workflow.is_some_and(|workflow| workflow.gpu);
    let cpus = inputs
        .cpus
        .or_else(|| workflow.map(|workflow| workflow.cpus))
        .unwrap_or(2);
    let memory = inputs
        .memory
        .map(String::from)
        .or_else(|| workflow.map(|workflow| workflow.mem.clone()))
        .unwrap_or_else(|| "512M".to_string());
    // The manifest's `[network] allow_hosts` reaches the spec through the
    // policy, the same way it reaches `run` and `machine run`.
    let policy = create_policy::machine_policy(create_policy::MachinePolicyInputs {
        policies: inputs.policy,
        project: inputs.project,
        allow_host: inputs.allow_host,
        net,
        cpu_limit: inputs.cpu_limit,
        timeout: inputs.timeout,
        cpus,
        memory_mib: u64::from(mvm_core::util::parse_human_size(&memory)?),
    })?;
    let allow_host = policy.allow_host;
    let routes = mvm_client::admission::run_routes::resolve_run_routes(&[], inputs.routes)?;
    let allow_host = routes.with_allow_host(&allow_host);
    let ai = inputs
        .ai
        .or(workflow.and_then(|workflow| workflow.ai.as_ref()));
    // Resolving grants also settles the egress policy, so validating it
    // here validates the same policy the machine will actually boot under.
    let config = mvm_core::user_config::load(None);
    let resolved = super::super::shared::resolve_policy_run_grants(
        super::super::shared::GrantInputs {
            cpu_limit_millicores: policy.cpu_limit,
            timeout_secs: policy.timeout,
            allow_host: &allow_host,
            peer: inputs.peer,
            net,
            network_preset: None,
            grants_file: inputs.grants_file,
            manifest: workflow.map(|workflow| &workflow.grants),
            config: &config,
            ai,
        },
        policy.policy.as_ref(),
    )?;
    if cpus == 0 {
        bail!("machine CPUs must be >= 1");
    }
    let mem_initial = inputs
        .mem_initial
        .map(String::from)
        .or_else(|| workflow.and_then(|workflow| workflow.mem_initial.clone()));
    let _ = validate_machine_memory(&memory, mem_initial.as_deref())?;
    let profile = inputs.profile.unwrap_or(RunProfile::Dev);
    anyhow::ensure!(
        inputs.local_pack.is_none() || profile == RunProfile::Dev,
        "local pack machines require the dev profile"
    );
    enforce_volume_profile(profile, inputs.volumes)?;
    let profile_name = run_profile_name(profile).to_string();
    enforce_dev_init_profile(&profile_name, inputs.init)?;
    Ok(MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name: inputs.name.to_string(),
        image,
        manifest: None,
        deployment: None,
        resolved_digest: None,
        runtime_pack: false,
        registry_pack_image: None,
        local_pack: inputs.local_pack.cloned(),
        net,
        allow_host,
        peer: inputs.peer.to_vec(),
        routes: routes.routes,
        ai: ai.cloned(),
        ports: Vec::new(),
        cpus,
        memory,
        mem_initial,
        profile: profile_name,
        volumes: inputs.volumes.to_vec(),
        init: inputs.init.to_vec(),
        agent_verb: Vec::new(),
        caller_commitment: None,
        workload_dir: None,
        created_at: Some(mvm_core::time::utc_now()),
        last_started_at: None,
        health_check: None,
        grants: resolved.plan_grants,
        gpu,
        gpu_device,
    })
}

impl MachineCreateArgs {
    pub(super) fn into_spec(self) -> Result<MachineSpec> {
        self.into_spec_with(crate::commands::vm::prepare_local_pack_data)
    }

    pub(super) fn into_spec_with(
        self,
        prepare: impl FnOnce(
            &Path,
            Option<&mvm_client::machine_spec::LocalPackBaseSource>,
        ) -> Result<PathBuf>,
    ) -> Result<MachineSpec> {
        let name = match self.name {
            Some(name) => {
                validate_machine_name(&name)?;
                name
            }
            None => auto_machine_name(),
        };
        let pack_base = self.pack_base.selected()?;
        anyhow::ensure!(
            self.pack.is_some() || pack_base.is_none(),
            "local base selection requires --pack"
        );
        let manifest_source = if self.pack.is_some() {
            None
        } else {
            match (self.image.is_none(), self.manifest.as_deref()) {
                (_, Some(arg)) => Some(load_machine_manifest_source(Path::new(arg))?),
                (true, None) => Some(load_machine_manifest_source(Path::new(".")).with_context(
                    || "machine create requires --image, --pack or an image-backed mvm.toml in the current directory",
                )?),
                (false, None) => None,
            }
        };
        let local_pack = self
            .pack
            .as_deref()
            .map(|recipe| -> Result<_> {
                let archive = prepare(recipe, pack_base.as_ref())?;
                let sha = mvm_core::packs::Sha256Hex::new(
                    mvm_core::crypto::image_verify::sha256_file(&archive)?,
                )?;
                let mut source =
                    mvm_client::machine_spec::LocalPackSource::from_prepared(recipe, sha)?;
                source.base = pack_base;
                Ok(source)
            })
            .transpose()?;
        let workflow = manifest_source.as_ref().map(|source| &source.workflow);
        let init = workflow
            .map(|workflow| workflow.init.clone())
            .unwrap_or_default();
        let volumes = match manifest_source.as_ref() {
            Some(source) => source
                .workflow
                .volumes
                .iter()
                .map(|spec| absolutize_manifest_volume_spec(spec, &source.base_dir))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };
        build_machine_spec(MachineSpecInputs {
            name: &name,
            image: self.image.as_deref(),
            local_pack: local_pack.as_ref(),
            net: self.net,
            allow_host: &self.allow_host,
            peer: &self.peer,
            routes: manifest_source
                .as_ref()
                .map(|source| source.routes.as_slice())
                .unwrap_or_default(),
            gpu: self.gpu,
            gpu_device: self.gpu_device,
            ai: None,
            cpus: self.cpus,
            cpu_limit: self.cpu_limit,
            timeout: self.timeout,
            grants_file: self.grants_file.as_deref(),
            memory: self.memory.as_deref(),
            mem_initial: self.mem_initial.as_deref(),
            profile: self.profile,
            workflow,
            volumes: &volumes,
            init: &init,
            policy: &self.policy,
            project: manifest_source.as_ref().map(|source| &source.project),
        })
    }
}

pub(super) fn run_profile_name(profile: RunProfile) -> &'static str {
    profile.as_str()
}

fn profile_allows_dev_init(profile: RunProfile) -> bool {
    profile.grants().dev_guest
}

/// A stored spec's unrecognised profile must refuse before guest init.
pub(super) fn enforce_dev_init_profile(profile: &str, init: &[String]) -> Result<()> {
    if init.is_empty() {
        return Ok(());
    }
    let parsed = RunProfile::from_name(profile)
        .ok_or_else(|| anyhow!("machine spec carries an unrecognised profile {profile:?}"))?;
    if !profile_allows_dev_init(parsed) {
        bail!(
            "machine dev.init requires a dev-capable profile; use --profile dev or --profile permissive"
        );
    }
    Ok(())
}
