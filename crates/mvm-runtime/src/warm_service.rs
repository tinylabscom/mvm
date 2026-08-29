//! In-process warm-launch service boundary.
//!
//! The service owns active leases and exposes the same Claim/Release/Prewarm
//! operations that a future resident local transport will carry. Keeping the
//! ownership map here makes lease cleanup independent of the CLI invocation
//! that initiated a claim.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::vm_backend::{
    StandbyClaim, StandbyCompat, VmBackend, WarmArtifactIdentity, WarmClaimRefusal,
    WarmClaimTiming, WarmPrewarmSource, WarmServiceRequest, WarmServiceResponse,
};

use crate::standby_pool::SupervisorStandbyPool;
use crate::vm::lease::{AcquireSpec, ReplenishFn, WarmLease, WarmLeaseOrigin};
use crate::warm_artifact_builder::WarmArtifactWorker;
use crate::warm_artifacts::PrewarmJob;

/// Callback used to replenish a compatibility shape asynchronously or on
/// release. It returns the current published count after the operation.
pub type PrewarmFn = Arc<
    dyn Fn(&StandbyCompat, &WarmPrewarmSource, &WarmArtifactIdentity, u32) -> Result<u32>
        + Send
        + Sync,
>;

/// Resident in-process owner for active warm leases.
pub struct WarmLaunchService {
    leases: Mutex<BTreeMap<String, WarmLease>>,
    prewarm: Option<PrewarmFn>,
    artifact_worker: Option<Arc<WarmArtifactWorker>>,
}

impl WarmLaunchService {
    /// Create a service with no prewarm worker. Claim and release remain usable;
    /// `Prewarm` returns an explicit unavailable error until a worker is wired.
    pub fn new() -> Self {
        Self {
            leases: Mutex::new(BTreeMap::new()),
            prewarm: None,
            artifact_worker: None,
        }
    }

    /// Create a service with the callback that owns artifact/pool preparation.
    pub fn with_prewarm(prewarm: PrewarmFn) -> Self {
        Self {
            leases: Mutex::new(BTreeMap::new()),
            prewarm: Some(prewarm),
            artifact_worker: None,
        }
    }

    /// Create a service whose prewarm requests enqueue durable artifact jobs.
    /// The worker is retained by the service so a resident loop can call
    /// [`Self::process_prewarm_once`] without involving a claim.
    pub fn with_artifact_worker(worker: Arc<WarmArtifactWorker>) -> Self {
        let prewarm = Some(worker.prewarm_callback());
        Self {
            leases: Mutex::new(BTreeMap::new()),
            prewarm,
            artifact_worker: Some(worker),
        }
    }

    /// Handle a claim while retaining the admitted claim payload in the
    /// trusted in-process caller. The serialized request carries only its
    /// identity, mode, and host-path-free compatibility shape.
    pub fn claim(
        &self,
        request: WarmServiceRequest,
        backend: Arc<dyn VmBackend>,
        pool: &SupervisorStandbyPool,
        claim: StandbyClaim,
        replenish: Option<ReplenishFn>,
    ) -> Result<WarmServiceResponse> {
        let WarmServiceRequest::Claim {
            request_id,
            lease_id,
            mode,
            compatibility,
        } = request
        else {
            bail!("warm service claim received a non-claim request")
        };

        if self.has_lease(&lease_id)? {
            bail!("warm lease '{lease_id}' is already active");
        }
        let started = Instant::now();
        let spec = AcquireSpec {
            want: compatibility,
            mode,
            claim,
        };
        match WarmLease::acquire(backend, pool, &spec, replenish) {
            Ok(lease) => {
                let vm_id = lease.id().clone();
                let origin = lease.origin();
                self.insert_lease(lease_id.clone(), lease)?;
                let elapsed = elapsed_us(started);
                let timing = WarmClaimTiming {
                    pool_wait_us: 0,
                    claim_us: elapsed,
                    warm_window_us: elapsed,
                };
                Ok(match origin {
                    WarmLeaseOrigin::WarmClaim => WarmServiceResponse::Claimed {
                        request_id,
                        lease_id,
                        vm_id,
                        timing,
                    },
                    WarmLeaseOrigin::ColdBoot => WarmServiceResponse::ColdBoot {
                        request_id,
                        lease_id,
                        vm_id,
                        timing,
                    },
                })
            }
            Err(error) => match error.downcast::<WarmClaimRefusal>() {
                Ok(refusal) => Ok(WarmServiceResponse::Refused {
                    request_id,
                    refusal,
                    timing: WarmClaimTiming {
                        pool_wait_us: 0,
                        claim_us: elapsed_us(started),
                        warm_window_us: elapsed_us(started),
                    },
                }),
                Err(error) => Err(error).context("warm service claim"),
            },
        }
    }

    /// Release and stop an active lease. Removal from the ownership map occurs
    /// only after the lease has been taken, so a duplicate release cannot stop
    /// a different VM.
    pub fn release(&self, request: WarmServiceRequest) -> Result<WarmServiceResponse> {
        let WarmServiceRequest::Release {
            request_id,
            lease_id,
        } = request
        else {
            bail!("warm service release received a non-release request")
        };
        let mut lease = self
            .leases
            .lock()
            .map_err(|_| anyhow!("warm service lease registry is poisoned"))?
            .remove(&lease_id)
            .with_context(|| format!("unknown warm lease '{lease_id}'"))?;
        if let Err(error) = lease.release() {
            self.insert_lease(lease_id.clone(), lease)
                .context("restore warm lease after release failure")?;
            return Err(error).with_context(|| format!("release warm lease '{lease_id}'"));
        }
        Ok(WarmServiceResponse::Released {
            request_id,
            lease_id,
        })
    }

    /// Submit an asynchronous prewarm request to the configured worker.
    pub fn prewarm(&self, request: WarmServiceRequest) -> Result<WarmServiceResponse> {
        let WarmServiceRequest::Prewarm {
            request_id,
            source,
            artifact,
            compatibility,
            target,
        } = request
        else {
            bail!("warm service prewarm received a non-prewarm request")
        };
        let worker = self
            .prewarm
            .as_ref()
            .context("warm prewarm worker is not configured")?;
        source
            .validate()
            .map_err(|error| anyhow!(error))
            .context("validate warm prewarm source")?;
        let current =
            worker(&compatibility, &source, &artifact, target).context("submit warm prewarm")?;
        Ok(WarmServiceResponse::PrewarmAccepted {
            request_id,
            target,
            current,
        })
    }

    /// Process one queued artifact job on the resident worker. This method is
    /// intentionally separate from [`Self::prewarm`], which only acknowledges
    /// queueing and must remain bounded and non-blocking.
    pub fn process_prewarm_once(&self) -> Result<Option<PrewarmJob>> {
        self.artifact_worker
            .as_ref()
            .context("warm artifact worker is not configured")?
            .process_next()
    }

    /// Number of active leases currently owned by the service.
    pub fn active_leases(&self) -> Result<usize> {
        Ok(self
            .leases
            .lock()
            .map_err(|_| anyhow!("warm service lease registry is poisoned"))?
            .len())
    }

    fn has_lease(&self, lease_id: &str) -> Result<bool> {
        Ok(self
            .leases
            .lock()
            .map_err(|_| anyhow!("warm service lease registry is poisoned"))?
            .contains_key(lease_id))
    }

    fn insert_lease(&self, lease_id: String, lease: WarmLease) -> Result<()> {
        let mut leases = self
            .leases
            .lock()
            .map_err(|_| anyhow!("warm service lease registry is poisoned"))?;
        if leases.insert(lease_id.clone(), lease).is_some() {
            bail!("warm lease '{lease_id}' is already active")
        }
        Ok(())
    }
}

impl Default for WarmLaunchService {
    fn default() -> Self {
        Self::new()
    }
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> WarmArtifactIdentity {
        WarmArtifactIdentity {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "aa".repeat(32),
            kernel_sha256: "bb".repeat(32),
            initramfs_sha256: "cc".repeat(32),
            rootfs_sha256: "dd".repeat(32),
            runtime_overlay_sha256: Some("ee".repeat(32)),
        }
    }

    #[test]
    fn service_starts_with_no_active_leases_or_prewarm_worker() {
        let service = WarmLaunchService::new();
        assert_eq!(service.active_leases().expect("registry is healthy"), 0);
        let request = WarmServiceRequest::Prewarm {
            request_id: "req-1".into(),
            source: WarmPrewarmSource::OciImage {
                reference: "python:3.12".into(),
            },
            artifact: artifact(),
            compatibility: StandbyCompat {
                template_id: None,
                kernel_sha256: "aa".repeat(32),
                vcpus: 2,
                mem_mib: 128,
                image_sha256: None,
                root_strategy: Default::default(),
                vsock_egress: false,
            },
            target: 1,
        };
        let error = service.prewarm(request).expect_err("worker is absent");
        assert!(
            error
                .to_string()
                .contains("prewarm worker is not configured")
        );
    }

    #[test]
    fn service_forwards_the_host_path_free_source_to_the_worker() {
        let service = WarmLaunchService::with_prewarm(Arc::new(|_, source, _, target| {
            assert_eq!(
                source,
                &WarmPrewarmSource::OciImage {
                    reference: "python:3.12".into()
                }
            );
            Ok(target + 1)
        }));
        let response = service
            .prewarm(WarmServiceRequest::Prewarm {
                request_id: "req-2".into(),
                source: WarmPrewarmSource::OciImage {
                    reference: "python:3.12".into(),
                },
                artifact: artifact(),
                compatibility: StandbyCompat {
                    template_id: None,
                    kernel_sha256: "aa".repeat(32),
                    vcpus: 2,
                    mem_mib: 128,
                    image_sha256: Some("bb".repeat(32)),
                    root_strategy: Default::default(),
                    vsock_egress: false,
                },
                target: 1,
            })
            .expect("prewarm source is accepted");
        assert_eq!(
            response,
            WarmServiceResponse::PrewarmAccepted {
                request_id: "req-2".into(),
                target: 1,
                current: 2,
            }
        );
    }

    #[test]
    fn service_queues_artifact_work_and_processes_it_outside_preheat_submission() {
        let root = tempfile::tempdir().expect("artifact root");
        let worker = WarmArtifactWorker::new(
            crate::warm_artifacts::WarmArtifactStore::at(root.path()),
            Arc::new(|_, _| anyhow::bail!("source unavailable")),
            Arc::new(|_, _, _| anyhow::bail!("golden VM unavailable")),
        );
        let service = WarmLaunchService::with_artifact_worker(Arc::new(worker));
        let response = service
            .prewarm(WarmServiceRequest::Prewarm {
                request_id: "req-3".into(),
                source: WarmPrewarmSource::OciImage {
                    reference: "python:3.12".into(),
                },
                artifact: artifact(),
                compatibility: StandbyCompat {
                    template_id: None,
                    kernel_sha256: "aa".repeat(32),
                    vcpus: 2,
                    mem_mib: 128,
                    image_sha256: Some("dd".repeat(32)),
                    root_strategy: Default::default(),
                    vsock_egress: false,
                },
                target: 1,
            })
            .expect("prewarm enqueues quickly");
        assert_eq!(
            response,
            WarmServiceResponse::PrewarmAccepted {
                request_id: "req-3".into(),
                target: 1,
                current: 0,
            }
        );
        let error = service
            .process_prewarm_once()
            .expect_err("worker failure is reported on the worker tick");
        assert!(
            error
                .root_cause()
                .to_string()
                .contains("source unavailable")
        );
    }
}

#[cfg(all(test, feature = "test-support"))]
mod integration_tests {
    use super::*;
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::vm_backend::{StandbyState, VmStartConfig, WarmLaunchMode};
    use std::path::PathBuf;

    fn compatibility() -> StandbyCompat {
        StandbyCompat {
            template_id: None,
            kernel_sha256: "aa".repeat(32),
            vcpus: 2,
            mem_mib: 128,
            image_sha256: None,
            root_strategy: Default::default(),
            vsock_egress: false,
        }
    }

    fn claim() -> StandbyClaim {
        StandbyClaim {
            start_config: Some(VmStartConfig {
                name: "cold-fallback".into(),
                rootfs_path: "/tmp/rootfs.ext4".into(),
                cpus: 2,
                memory_mib: 128,
                ..Default::default()
            }),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: PathBuf::from("/tmp/audit"),
            gateway_audit_socket: PathBuf::from("/tmp/audit.sock"),
            gateway_events_socket: None,
            plan_json: "{}".into(),
            bundle_json: None,
            network_policy: NetworkPolicy::deny_all(),
        }
    }

    #[test]
    fn service_claims_and_releases_the_owned_lease() {
        let pool_root = tempfile::tempdir().expect("pool tempdir");
        let pool = SupervisorStandbyPool::at(pool_root.path());
        let shape = compatibility();
        pool.record(&mvm_core::vm_backend::StandbyHandle {
            id: "standby-1".into(),
            template_id: None,
            control_socket: "/tmp/standby.sock".into(),
            pid: std::process::id(),
            kernel_sha256: shape.kernel_sha256.clone(),
            vcpus: shape.vcpus,
            mem_mib: shape.mem_mib,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: None,
            root_strategy: shape.root_strategy,
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        })
        .expect("record standby");
        let backend: Arc<dyn VmBackend> = Arc::new(crate::MockBackend::new().with_standby());
        let service = WarmLaunchService::new();
        let claim_request = WarmServiceRequest::Claim {
            request_id: "request-1".into(),
            lease_id: "lease-1".into(),
            mode: WarmLaunchMode::Required,
            compatibility: shape,
        };

        let claimed = service
            .claim(claim_request, backend, &pool, claim(), None)
            .expect("claim request succeeds");
        assert!(matches!(claimed, WarmServiceResponse::Claimed { .. }));
        assert_eq!(service.active_leases().expect("registry is healthy"), 1);

        let released = service
            .release(WarmServiceRequest::Release {
                request_id: "request-2".into(),
                lease_id: "lease-1".into(),
            })
            .expect("release request succeeds");
        assert!(matches!(released, WarmServiceResponse::Released { .. }));
        assert_eq!(service.active_leases().expect("registry is healthy"), 0);
    }

    #[test]
    fn service_reports_cold_fallback_and_retains_failed_release() {
        let pool_root = tempfile::tempdir().expect("pool tempdir");
        let pool = SupervisorStandbyPool::at(pool_root.path());
        let backend: Arc<dyn VmBackend> = Arc::new(crate::MockBackend::new().with_failing_stop());
        let service = WarmLaunchService::new();
        let claimed = service
            .claim(
                WarmServiceRequest::Claim {
                    request_id: "request-1".into(),
                    lease_id: "lease-1".into(),
                    mode: WarmLaunchMode::Optional,
                    compatibility: compatibility(),
                },
                backend,
                &pool,
                claim(),
                None,
            )
            .expect("optional claim cold-boots");
        assert!(matches!(claimed, WarmServiceResponse::ColdBoot { .. }));

        let error = service
            .release(WarmServiceRequest::Release {
                request_id: "request-2".into(),
                lease_id: "lease-1".into(),
            })
            .expect_err("failing backend stop is surfaced");
        assert!(error.to_string().contains("release warm lease"));
        assert_eq!(service.active_leases().expect("registry is healthy"), 1);
    }
}
