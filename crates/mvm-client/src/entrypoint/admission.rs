//! The one admission an entrypoint VM boots under, whether it serves one
//! transient call or a warm session.
//!
//! Both used to carry their own copy of this closure, and they had drifted:
//! the session boot resolved no entrypoint, never persisted its plan ahead of
//! the pre-start egress moat, and always took the host's default backend,
//! while the transient boot did all three but let a dev boot carry an
//! agent-verb restriction. The single admission keeps the stricter side of
//! each: the entrypoint is resolved from the image on every boot, the plan is
//! persisted before start on the backends whose egress moat reads it, the
//! backend is the caller's, and a dev boot refuses an agent-verb restriction.

use anyhow::{Context, Result};
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::CallerCommitment;

use super::boot::{AdmitInputs, SessionAuditSubstrate};
use crate::admission::secrets::ResolvedPlanSecrets;
use crate::admission::{
    AdmissionContext, AdmitPlanForBootParams, admit_plan_for_boot,
    attach_guest_boot_config_for_plan, guest_profile_for_boot,
};

/// The tenant every locally admitted entrypoint VM is scoped under.
const LOCAL_TENANT: &str = "local";

/// The policy an entrypoint VM is admitted under. Built once per boot; the
/// facts only the boot can know (rootfs, kernel, name, volumes) arrive at
/// [`EntrypointAdmission::admit`] time.
#[derive(Debug, Clone)]
pub struct EntrypointAdmission {
    backend_name: String,
    cpus: u32,
    mem_mib: u64,
    secrets: ResolvedPlanSecrets,
    agent_verb_override: Vec<String>,
    caller_commitment: Option<CallerCommitment>,
    dev: bool,
    network_policy: NetworkPolicy,
    stream_stdin: bool,
}

/// An admitted entrypoint boot: the context the audit narrative binds to, and
/// what the plan contributes to the VM's start config.
pub struct AdmittedEntrypoint {
    /// The admitted plan and the emitter bound to it.
    pub context: AdmissionContext,
    /// The plan-bearing start-config fields.
    pub substrate: SessionAuditSubstrate,
}

impl EntrypointAdmission {
    /// An admission for a boot on `backend_name`: one vCPU, 256 MiB, no
    /// secrets, the computed agent verbs, production profile, deny-all egress,
    /// and no host→guest stdin stream until told otherwise.
    #[must_use]
    pub fn builder(backend_name: impl Into<String>) -> EntrypointAdmissionBuilder {
        EntrypointAdmissionBuilder(Self {
            backend_name: backend_name.into(),
            cpus: 1,
            mem_mib: 256,
            secrets: ResolvedPlanSecrets::default(),
            agent_verb_override: Vec::new(),
            caller_commitment: None,
            dev: false,
            network_policy: NetworkPolicy::deny_all(),
            stream_stdin: false,
        })
    }

    /// The backend this admission binds the plan to.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    /// The egress policy the plan and the VM's start config carry.
    #[must_use]
    pub fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
    }

    /// Whether the plan will carry the host→guest stdin grant.
    #[must_use]
    pub fn streams_stdin(&self) -> bool {
        self.stream_stdin
    }

    /// The same admission, asking for the stdin grant or not. Separate from the
    /// builder because the caller that knows whether a call streams is the one
    /// that decides how its payload travels, which is after the policy exists.
    #[must_use]
    pub fn with_stream_stdin(mut self, stream_stdin: bool) -> Self {
        self.stream_stdin = stream_stdin;
        self
    }

    /// Admit a boot of what `inputs` describes.
    ///
    /// # Errors
    /// Any admission refusal: an unverifiable image, a replayed nonce, a
    /// stdin grant over a shell-shaped or unresolvable entrypoint, or a plan
    /// that cannot be persisted ahead of the egress moat.
    pub fn admit(&self, inputs: AdmitInputs<'_>) -> Result<AdmittedEntrypoint> {
        let AdmitInputs {
            rootfs,
            kernel,
            vm_name,
            sdk_sidecar: _,
            assets,
            volumes,
        } = inputs;
        let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::default();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            instructions: Default::default(),
            outputs: Vec::new(),
            network_mode: crate::launch::persistent::preflight_network(),
            tenant: LOCAL_TENANT,
            vm_name,
            backend_name: &self.backend_name,
            configured_images_dir: mvm_build::image_source::configured_images_dir().as_deref(),
            rootfs_path: rootfs,
            kernel_path: kernel,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: self.cpus,
            mem_mib: self.mem_mib,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: self.secrets.secret_release,
            secrets: self.secrets.secrets.clone(),
            caller_commitment: self.caller_commitment.clone(),
            ledger: &ledger,
            keys_dir: None,
            audit_dir: None,
            policy_dir: None,
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: mvm_hostd::run::shares_from_vm_volumes(volumes),
            assets: assets.to_vec(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            tools: Default::default(),
            network_policy: self.network_policy.clone(),
            agent_verb_override: self.agent_verb_override.clone(),
            // The entrypoint is driven over agent RPC: no PTY, no ad-hoc argv,
            // so the profile alone decides.
            restrict_agent_verbs: crate::admission::agent_verbs::grant_eligible(
                false, false, self.dev,
            ),
            // Default-deny, and conditional on the caller having asked. A plan
            // carrying this token is one whose workload's stdin can be driven
            // from the host; a plan without it leaves that stdin unreachable
            // from outside the guest no matter what the host-side gate says.
            services: if self.stream_stdin {
                vec![input_grant_service()]
            } else {
                Vec::new()
            },
            // Resolved from the image beside the rootfs rather than assumed,
            // and on every boot rather than only when the grant is asked for,
            // so the path that feeds the refusal is the ordinary path.
            entrypoint: crate::admission::entrypoint_resolve::resolve_for_rootfs(rootfs),
            // An entrypoint boot admits the built workload's own launch and
            // authors no grant of its own.
            grants: None,
            backend_kind: None,
        })?;

        let mut start_config = mvm_core::vm_backend::VmStartConfig::default();
        attach_guest_boot_config_for_plan(
            &mut start_config,
            ctx.admitted.plan(),
            &ctx.host_signer_public_path,
            guest_profile_for_boot(self.dev, rootfs),
        )?;
        if crate::launch::persistent::persists_plan_before_start(&self.backend_name) {
            mvm_hostd::audit::plan_persist::write_plan(vm_name, ctx.admitted.plan())
                .context("persisting admitted plan for the pre-start egress moat")?;
        }
        let plan_json = serde_json::to_string(ctx.admitted.signed())
            .context("serializing admitted plan for the entrypoint VM")?;
        let bundle_json = ctx
            .policy_bundle
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .context("serializing admitted policy bundle for the entrypoint VM")?;
        Ok(AdmittedEntrypoint {
            substrate: SessionAuditSubstrate {
                tenant_id: ctx.admitted.plan().tenant.0.clone(),
                plan_json,
                bundle_json,
                config_files: start_config.config_files,
            },
            context: ctx,
        })
    }
}

/// Builder for [`EntrypointAdmission`].
pub struct EntrypointAdmissionBuilder(EntrypointAdmission);

impl EntrypointAdmissionBuilder {
    /// vCPUs the plan admits.
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.0.cpus = cpus;
        self
    }

    /// Guest memory the plan admits, in MiB.
    #[must_use]
    pub fn mem_mib(mut self, mem_mib: u64) -> Self {
        self.0.mem_mib = mem_mib;
        self
    }

    /// Secret bindings, resolved before anything boots.
    #[must_use]
    pub fn secrets(mut self, secrets: ResolvedPlanSecrets) -> Self {
        self.0.secrets = secrets;
        self
    }

    /// An explicit ProdSafe agent-verb set to mint into the grant instead of
    /// the computed default.
    #[must_use]
    pub fn agent_verb_override(mut self, verbs: Vec<String>) -> Self {
        self.0.agent_verb_override = verbs;
        self
    }

    /// An opaque caller commitment to bind into the plan.
    #[must_use]
    pub fn caller_commitment(mut self, commitment: Option<CallerCommitment>) -> Self {
        self.0.caller_commitment = commitment;
        self
    }

    /// Boot under the dev profile, which admits DevOnly verbs.
    #[must_use]
    pub fn dev(mut self, dev: bool) -> Self {
        self.0.dev = dev;
        self
    }

    /// The egress policy the plan carries.
    #[must_use]
    pub fn network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.0.network_policy = policy;
        self
    }

    /// Ask for the host→guest stdin grant.
    #[must_use]
    pub fn stream_stdin(mut self, stream_stdin: bool) -> Self {
        self.0.stream_stdin = stream_stdin;
        self
    }

    /// The finished admission policy.
    ///
    /// # Errors
    /// A dev boot with an agent-verb restriction: dev boots stay permissive
    /// by contract, so a restriction there would be silently meaningless.
    pub fn build(self) -> Result<EntrypointAdmission> {
        if self.0.dev && !self.0.agent_verb_override.is_empty() {
            anyhow::bail!(
                "an agent-verb restriction is refused on a dev boot; dev boots stay \
                 permissive by contract"
            );
        }
        Ok(self.0)
    }
}

/// The signed-plan token that says this workload's stdin may be driven from
/// the host. One spelling, parsed from the protocol constant, so a typo here
/// could not quietly mint a grant the gate does not recognise.
#[must_use]
pub fn input_grant_service() -> mvm_contract::protocol::broker::ServiceId {
    mvm_contract::protocol::broker::ServiceId::parse(
        mvm_contract::stream::input::INPUT_GRANT_SERVICE,
    )
    .expect("the input-plane grant token is a valid service id")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::builder_vm::GuestSidecar;
    use mvm_core::util::test_env::TestEnv;

    fn inputs<'a>(rootfs: &'a std::path::Path, vm: &'a str) -> AdmitInputs<'a> {
        AdmitInputs {
            rootfs,
            kernel: None,
            vm_name: vm,
            sdk_sidecar: None,
            assets: &[],
            volumes: &[],
        }
    }

    #[test]
    fn a_dev_boot_refuses_an_agent_verb_restriction() {
        let error = EntrypointAdmission::builder("firecracker")
            .dev(true)
            .agent_verb_override(vec!["ping".into()])
            .build()
            .expect_err("dev boots stay permissive");
        assert!(format!("{error:#}").contains("refused on a dev boot"));
    }

    #[test]
    fn the_stdin_grant_can_be_asked_for_after_the_policy_is_built() {
        let admission = EntrypointAdmission::builder("mock")
            .build()
            .expect("a default admission builds");
        assert!(!admission.streams_stdin());
        assert!(admission.with_stream_stdin(true).streams_stdin());
    }

    #[test]
    fn the_input_grant_token_is_the_protocol_constant() {
        assert_eq!(
            input_grant_service().as_str(),
            mvm_contract::stream::input::INPUT_GRANT_SERVICE
        );
    }

    #[test]
    fn admit_entrypoint_boot_admits_sealed_images_even_without_secrets() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        let mut sidecar = GuestSidecar::for_oci_run("audit-probe", true, true);
        sidecar.accessible = false;
        sidecar.sealed = true;
        sidecar.write_to_dir(dir.path()).expect("write sidecar");

        let admitted = EntrypointAdmission::builder("firecracker")
            .agent_verb_override(vec!["run-entrypoint".into(), "ping".into()])
            .build()
            .expect("admission policy")
            .admit(inputs(&rootfs, "invoke-proof-sealed"))
            .expect("sealed entrypoint boot admitted");

        let verbs = admitted
            .context
            .admitted
            .plan()
            .agent_verbs
            .as_ref()
            .expect("sealed entrypoint plan should carry agent verbs");
        assert!(verbs.iter().any(|v| v.as_str() == "run-entrypoint"));
        assert!(verbs.iter().any(|v| v.as_str() == "ping"));
        assert!(
            admitted
                .substrate
                .config_files
                .iter()
                .any(|f| f.name == mvm_hostd::audit::host_keypair::PUBLIC_FILENAME),
            "host signer pubkey must be attached when verb grants are present"
        );
        let policy_file = admitted
            .substrate
            .config_files
            .iter()
            .find(|f| f.name == crate::admission::SECURITY_POLICY_FILENAME)
            .expect("security policy must be attached");
        let policy: mvm_core::security::SecurityPolicy =
            serde_json::from_str(&policy_file.content).expect("parse security policy");
        assert_eq!(policy.profile, mvm_core::security::AgentProfile::SealedProd);
    }

    #[test]
    fn admit_entrypoint_boot_carries_resolved_allow_list_not_deny_all() {
        use mvm_core::network_policy::HostPort;

        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        GuestSidecar::for_oci_run("egress-probe", true, true)
            .write_to_dir(dir.path())
            .expect("write sidecar");

        // A literal-IP allow-list skips DNS resolution in the generated signed
        // policy, so this exercises the real threading without a resolver.
        let admitted = EntrypointAdmission::builder("firecracker")
            .agent_verb_override(vec!["run-entrypoint".into()])
            .network_policy(NetworkPolicy::allow_list(vec![HostPort::new(
                "127.0.0.1",
                443,
            )]))
            .build()
            .expect("admission policy")
            .admit(inputs(&rootfs, "invoke-proof-allow"))
            .expect("entrypoint boot admitted");

        // deny_all resolves to no generated bundle; the allow-list resolves to
        // concrete L4 rules, so the bundle's presence proves the resolved
        // policy survived rather than being hardcoded to deny_all.
        let bundle = admitted
            .context
            .policy_bundle
            .as_ref()
            .expect("allow-list admission must generate a signed egress policy bundle");
        assert!(
            bundle
                .egress
                .allow_list
                .iter()
                .any(|(host, port)| host == "127.0.0.1" && *port == 443)
        );
        assert!(
            bundle
                .network
                .l4
                .iter()
                .any(|r| r.dst_cidr == "127.0.0.1/32" && r.port_lo == 443 && r.port_hi == 443)
        );
    }

    #[test]
    fn a_backend_whose_moat_reads_the_plan_gets_it_persisted_before_start() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        GuestSidecar::for_oci_run("persist-probe", true, true)
            .write_to_dir(dir.path())
            .expect("write sidecar");

        EntrypointAdmission::builder("firecracker")
            .build()
            .expect("admission policy")
            .admit(inputs(&rootfs, "persist-proof-vm"))
            .expect("admitted");
        mvm_hostd::audit::plan_persist::read_plan("persist-proof-vm")
            .expect("the admitted plan is on disk before the backend starts");
    }
}

#[cfg(test)]
mod stdin_grant_tests {
    //! What a streamed-stdin call asks admission for, and what admission does
    //! about it.
    //!
    //! Driven through [`EntrypointAdmission::admit`] rather than the plan
    //! admission directly, because the thing worth proving is the join: the
    //! entrypoint admission resolves what the image runs *from the image*,
    //! and hands that resolution to the gate.

    use super::*;
    use mvm_build::builder_vm::GuestSidecar;
    use mvm_core::util::test_env::TestEnv;

    /// One image on disk: a rootfs stand-in and the sidecar beside it, which
    /// is everything the host can see about a workload before it boots.
    struct Image {
        rootfs: std::path::PathBuf,
        _dir: tempfile::TempDir,
        _env: TestEnv,
        _home: tempfile::TempDir,
    }

    impl Image {
        /// `argv = None` writes a sidecar with no recorded entrypoint.
        fn sealed_running(argv: Option<&[&str]>) -> Self {
            let mut env = TestEnv::new();
            let home = tempfile::tempdir().expect("an isolated MVM_HOME");
            env.isolate_mvm_home(home.path());

            let dir = tempfile::tempdir().expect("an image dir");
            let rootfs = dir.path().join("rootfs.ext4");
            std::fs::write(&rootfs, b"rootfs bytes").expect("write the rootfs stand-in");
            let sidecar = GuestSidecar::for_oci_run("stdin-grant", true, true);
            let sidecar = match argv {
                Some(argv) => {
                    sidecar.with_entrypoint_argv(argv.iter().map(|a| (*a).to_string()).collect())
                }
                None => sidecar,
            };
            sidecar.write_to_dir(dir.path()).expect("write the sidecar");

            Self {
                rootfs,
                _dir: dir,
                _env: env,
                _home: home,
            }
        }

        fn admit(&self, vm: &str, stream_stdin: bool) -> anyhow::Result<AdmittedEntrypoint> {
            EntrypointAdmission::builder("firecracker")
                .stream_stdin(stream_stdin)
                .build()?
                .admit(AdmitInputs {
                    rootfs: &self.rootfs,
                    kernel: None,
                    vm_name: vm,
                    sdk_sidecar: None,
                    assets: &[],
                    volumes: &[],
                })
        }
    }

    #[test]
    fn a_shell_entrypoint_read_off_the_image_is_refused_the_stdin_grant() {
        let image = Image::sealed_running(Some(&["/bin/sh", "-i"]));
        let Err(err) = image.admit("vm-stdin-shell", true) else {
            panic!("a shell entrypoint asking for streamed stdin must be refused");
        };
        let rendered = format!("{err:#}");
        assert!(rendered.contains("shell-shaped"), "{rendered}");
        assert!(rendered.contains("/bin/sh"), "{rendered}");
    }

    #[test]
    fn an_image_that_cannot_say_what_it_runs_is_refused_the_stdin_grant() {
        // Fail closed: an unresolved entrypoint is an unchecked one.
        let image = Image::sealed_running(None);
        let Err(err) = image.admit("vm-stdin-unknown", true) else {
            panic!("an unresolvable entrypoint must not be handed a stdin writer");
        };
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("cannot say what the workload runs"),
            "{rendered}"
        );
    }

    #[test]
    fn a_shell_entrypoint_that_asked_for_nothing_still_boots() {
        let image = Image::sealed_running(Some(&["/bin/sh", "-i"]));
        let admitted = image
            .admit("vm-stdin-none", false)
            .expect("a call that asked for no input grant must not be refused");
        assert!(
            admitted.context.admitted.plan().services.is_empty(),
            "a call that did not ask for streamed stdin must carry no grant"
        );
    }

    #[test]
    fn a_non_shell_entrypoint_that_asked_for_it_carries_the_grant_on_the_signed_plan() {
        let image = Image::sealed_running(Some(&["/usr/bin/worker", "--serve"]));
        let admitted = image
            .admit("vm-stdin-granted", true)
            .expect("a non-shell entrypoint may be granted streamed stdin");
        let services = &admitted.context.admitted.plan().services;
        assert!(
            mvm_contract::stream::input::grants_input_for(services),
            "the admitted plan must carry the input grant: {services:?}"
        );
    }
}
