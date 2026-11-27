//! Cold start: prepare the boot, bind it, boot it and register its host services.

use super::admission::{admitted_ingress, admitted_network_limits};
use super::broker::admitted_broker_bindings;
use super::*;

impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Maps an already-bound configuration into a backend boot. Production
    /// callers must hold the lifecycle lease and pass the verifier's paths.
    #[cfg(test)]
    pub(super) fn boot_bound_workload(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
    ) -> Result<Box<dyn RunningVm>> {
        self.boot_bound_workload_guarded(
            inputs,
            None,
            Vec::new(),
            crate::runtime_evidence::UnsyncedBind::default(),
        )
    }

    pub(super) fn require_caller_registration_shape(&self, config: &VmStartConfig) -> Result<()> {
        if config.caller_registration.is_some() {
            anyhow::ensure!(
                self.driver.kind() == mvm_core::vm_backend::BackendKind::Hvf,
                "caller registration requires a cold HVF workload"
            );
            let plan = config
                .plan_json
                .as_deref()
                .context("caller registration requires a signed plan")?;
            serde_json::from_str::<mvm_core::plan::SignedExecutionPlan>(plan)
                .context("caller registration requires a signed plan")?;
        }
        Ok(())
    }

    /// Prepare the same policy, endpoint and device mapping for both ordinary
    /// boots and the concrete owned cold channel.
    pub(super) fn prepare_workload_boot(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
    ) -> Result<PreparedWorkloadBoot> {
        // A caller times this call from outside and cannot see past it, yet the
        // VMM boot and every post-boot registration happen in here. Off unless
        // a measurement asked for it.
        let mut trace =
            mvm_core::launch_trace::LaunchTraceRecorder::new(self.driver.kind().as_str());

        let state_dir = vm_state_dir(&inputs.config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        crate::base::runtime_meta::record_from_start_config(
            &inputs.config.name,
            StartMode::Detached,
            inputs.config,
        )?;
        let network_limits = admitted_network_limits(inputs.config.plan_json.as_deref())?;
        let ingress = admitted_ingress(inputs.config.plan_json.as_deref())?;
        let reader_plan = inputs
            .config
            .plan_json
            .as_deref()
            .map(mvm_core::plan::plan_from_admitted_json)
            .transpose()
            .context("parse admitted mailbox reader plan")?;
        if let Some(audit) = &inputs.config.audit_context {
            anyhow::ensure!(
                audit.plan() == reader_plan.as_ref(),
                "workload audit context differs from admitted plan"
            );
        }
        if reader_plan.as_ref().is_some_and(|plan| {
            plan.services
                .iter()
                .any(|service| service.as_str() == "host.actor.v1")
        }) {
            anyhow::ensure!(
                inputs.config.audit_context.is_some(),
                "actor boot requires the exact admitted audit context"
            );
        }
        let actor_bootstrap = reader_plan
            .as_ref()
            .map(mvm_vmm::host::actor_identity::ActorBootMaterial::for_plan)
            .transpose()?
            .flatten();

        // Spawn the per-child substitution endpoint through the shared
        // `ClaimGuards`, so a warm claim stands up the identical guarded endpoint
        // a cold boot does, keyed on this VM's own id. A deny-all, secret-free
        // workload receives no egress channel and therefore needs no process.
        // Advance before the call: an error may conceal a partial helper spawn.
        self.begin_dispatch();
        let guards = ClaimGuards::new(&self.spawner);
        let endpoint = guards.spawn_endpoint(
            &VmId(inputs.config.name.clone()),
            &EndpointSpawnInputs {
                state_dir: &state_dir,
                tenant: inputs.tenant,
                audit: inputs.config.audit_context.as_ref(),
                secrets: inputs.secrets,
                redaction: inputs.redaction,
                network_policy: inputs.network_policy,
                network_limits,
                ingress: &ingress,
                reader_plan: reader_plan.as_ref().filter(|plan| plan.mailbox.is_some()),
                mailbox_conversation: inputs.config.mailbox_conversation.as_ref(),
                actor: actor_bootstrap
                    .as_ref()
                    .map(|material| material.guest_projection()),
                // A cold boot mints this guest's identity and hands it a drive.
                identity: FlowMuxIdentitySource::Mint,
            },
        )?;
        trace.mark("endpoint_spawn");

        let mut boot_cmdline = inputs.cmdline.clone();
        if let Some(token) =
            mvm_vmm::host::egress_bridge::telemetry_cmdline_token(&inputs.config.name)
        {
            append_cmdline_token(&mut boot_cmdline, &token);
        }
        if let Some(problem) = cmdline::cmdline_overflow(&boot_cmdline) {
            anyhow::bail!("refusing to start VM {}: {problem}", inputs.config.name);
        }

        // A GPU launch gets its host endpoint before the spec is assembled:
        // the channel the guest dials must already have a listener, and the
        // socket path the endpoint bound is by construction the one
        // `standing_sockets` resolves for the spec.
        if inputs.config.gpu {
            let gpu_transport = Self::gpu_endpoint_transport(self.driver.kind(), &state_dir);
            mvm_vmm::host::gpu_endpoint_spawn::spawn_gpu_endpoint(
                &inputs.config.name,
                &state_dir,
                gpu_transport,
                inputs.config.gpu_device,
            )
            .context("spawning the GPU endpoint")?;
        }
        let socks = standing_sockets(&state_dir, inputs.config);
        let spec = workload_spec(&WorkloadSpecInputs {
            config: inputs.config,
            identity_drive: endpoint.identity_drive(),
            sockets: socks.with_egress(endpoint.egress_uds()),
            cmdline: boot_cmdline,
            console_log: socks.console_log.clone(),
        });

        trace.mark("spec_assembly");

        Ok(PreparedWorkloadBoot {
            spec,
            socks,
            endpoint,
            actor_bootstrap,
            trace: Some(trace),
        })
    }

    /// Maps an already-bound configuration into a backend boot. Production
    /// callers must hold the lifecycle lease and pass the verifier's paths,
    /// with the bind's writes still to sync: they are made durable beside the
    /// boot, and nothing is activated until they are.
    pub(super) fn boot_bound_workload_guarded(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
        kernel: Option<&crate::kernel_custody::KernelBoundLaunch>,
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        unsynced: crate::runtime_evidence::UnsyncedBind,
    ) -> Result<Box<dyn RunningVm>> {
        anyhow::ensure!(
            (inputs.config.canonical_kernel.is_none()
                && inputs.config.kernel_read_sha256.is_none())
                || kernel.is_some(),
            "canonical kernel launch has no actual final-config custody guard"
        );
        if let Some(kernel) = kernel {
            anyhow::ensure!(
                std::ptr::eq(inputs.config, kernel.config()),
                "launch substituted the final config object"
            );
        }
        let PreparedWorkloadBoot {
            spec,
            socks,
            mut endpoint,
            actor_bootstrap,
            trace,
        } = self.prepare_workload_boot(inputs)?;
        if let Some(material) = actor_bootstrap {
            let bootstrap = self
                .actor_bootstrap
                .lock()
                .expect("actor bootstrap poisoned")
                .take()
                .context("actor controllers require an owned bootstrap consumer")?;
            bootstrap(material).context("prepare original actor holder before native boot")?;
        }
        let mut trace = trace.context("prepared workload launch trace missing")?;
        let state_dir = vm_state_dir(&inputs.config.name);
        // Unconditional and best-effort. The follower can wait for a console
        // file that does not exist yet, so install it alongside VMM boot rather
        // than serializing its process setup after guest readiness.
        let capture = ConsoleCapture {
            vm_name: &inputs.config.name,
            supervisor_owned: supervisor_owns_console(self.driver.kind()),
            console_log: &socks.console_log,
            display_socket: socks.display.as_deref(),
            redaction: inputs.redaction,
            retention: plan_stream_retention(inputs.config.plan_json.as_deref()),
        };
        let beside_boot = durability::wait_for_unactivated_boot(inputs.config, unsynced)?;
        // Fails closed: only a sync that ran to completion replaces it.
        let mut synced = Err(anyhow::anyhow!(
            "the lifecycle lease and runtime generation sync did not run"
        ));
        if let Some(kernel) = kernel {
            kernel.before_boot(&spec)?;
        }
        let streamer = Arc::clone(&self.console_streamer);
        #[cfg(unix)]
        let disks = mvm_vmm::driver::prepared_disks::PreparedWritableDisks::bind_sources(
            &spec,
            writable_images,
        )?;
        let boot = console_boot::boot_while_starting_console(
            || {
                #[cfg(unix)]
                {
                    match kernel {
                        Some(kernel) => kernel.boot_custodied(&self.driver, &spec, disks),
                        None => {
                            disks.validate_spec(&spec)?;
                            self.driver.boot_custodied(
                                &spec,
                                mvm_vmm::driver::prepared_disks::PreparedBootFiles {
                                    kernel: None,
                                    writable: disks,
                                    data: None,
                                },
                            )
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    match kernel {
                        Some(kernel) => kernel.boot(&self.driver, &spec),
                        None => self.driver.boot(&spec),
                    }
                }
            },
            || {
                streamer.start(&capture);
                synced = beside_boot.sync();
            },
            || trace.mark("driver_boot"),
        );
        let vm = match boot {
            Ok(vm) => vm,
            Err(error) => {
                return Err(cold_hvf_channel::retain_boot_error(
                    error,
                    (endpoint, Arc::clone(&self.console_streamer)),
                ));
            }
        };
        let completion = (|| -> Result<()> {
            if let Some(kernel) = kernel {
                kernel.observe_booted(&*vm)?;
            }
            trace.mark("console_stream_start");

            // The guest's first entrypoint call must find its admitted host routes ready.
            // Keep the guard armed until activation succeeds.
            let (mut broker_guard, services) =
                self.register_workload_broker(inputs.config, &socks)?;
            trace.mark("broker_register");

            // Universal initramfs path: the guest PID-1 agent waits for a signed
            // ActivateEnvironment before exposing operational RPCs. Send it now,
            // while the broker registration still has a guard that rolls back
            // on failure. A rootfs boot whose universal initramfs could not be
            // resolved was refused at launch resolution, before the VMM started.
            if crate::microvm::booted_with_universal_initramfs(inputs.config) {
                if self.actor_failed_vm.is_some() {
                    synced.and_then(|()| durability::wait_for_owned_activation(inputs.config))?;
                } else {
                    durability::wait_for_activation(
                        inputs.config,
                        synced,
                        &*vm,
                        &*self.console_streamer,
                    )?;
                }
                trace.mark("admission_durable");
                crate::microvm::activate_workload(&*vm, inputs.config)
                    .context("activate workload after boot")?;
            }
            trace.mark("activate_workload");

            endpoint.defuse();
            broker_guard.defuse();
            trace.degrade_unless("host_services", broker_guard.services_healthy(&services));
            trace.write_to(&state_dir);
            Ok(())
        })();
        if let Err(error) = completion {
            if let Some(slot) = &self.actor_failed_vm {
                endpoint.defuse();
                *slot.lock().expect("original actor VM custody poisoned") = Some(vm);
            }
            return Err(error);
        }
        Ok(vm)
    }

    pub(super) fn register_workload_broker(
        &self,
        config: &VmStartConfig,
        socks: &sockets::StandingSockets,
    ) -> Result<(BrokerGuard, Vec<ServiceId>)> {
        let state_dir = vm_state_dir(&config.name);
        let (services, capability_bindings, epoch) =
            admitted_broker_bindings(config.plan_json.as_deref())?;
        let guard = self.broker.register(&BrokerRegisterRequest {
            vm_name: &config.name,
            state_dir: &state_dir,
            tenant: config.tenant_id.as_deref(),
            broker_listen_socket: socks.broker.as_deref(),
            services: &services,
            capability_bindings: &capability_bindings,
            service_proxies: &config.service_proxies,
            epoch: epoch.as_ref(),
        })?;
        Ok((guard, services))
    }
}
