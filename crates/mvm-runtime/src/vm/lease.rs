//! `WarmLease` — an exclusively-held warm VM.
//!
//! RAII borrow-handle over the supervisor standby pool: [`WarmLease::acquire`]
//! claims a compatible idle standby (or cold-boots on a miss), and
//! [`WarmLease::release`] / `Drop` **stop the VM and replenish a fresh
//! standby** — never returning a mutated, booted VM to the pool. This is the
//! security-correct inverse of the borrow-pool prior art: it avoids cross-run
//! state bleed (claim 1 / one-guest-one-workload) and matches the saved-state
//! reality (a booted VM can only be discarded and re-restored, not "returned").
//!
//! There is no single `Vm` value to `Deref` to — mvm's model is *backend +
//! `VmId` + transport* — so the handle bundles those and exposes `id()` /
//! `transport()`.

use std::sync::Arc;

use crate::standby_pool::SupervisorStandbyPool;
use anyhow::{Context, Result};
use mvm_core::vm_backend::{
    StandbyClaim, StandbyCompat, VmBackend, VmId, WarmClaimRefusal, WarmLaunchMode,
};

use crate::vsock_transport::{self, VsockTransport};

/// What a lease needs to claim (or cold-boot) a warm VM.
pub struct AcquireSpec {
    /// Compat key for the standby match (kernel + fixed resources + image).
    pub want: StandbyCompat,
    /// Whether the caller permits a cold boot when warm capacity is unavailable.
    pub mode: WarmLaunchMode,
    /// The admitted, signed workload to attach. `claim.start_config` doubles
    /// as the cold-boot config used on a pool miss.
    pub claim: StandbyClaim,
}

/// Replenish trigger, injected so `mvm` does not depend upward on the CLI's
/// `pool warm` machinery. Called best-effort after a claimed lease releases, to
/// keep the pool topped up to its target.
pub type ReplenishFn = Arc<dyn Fn() -> Result<()> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleasePolicy {
    /// Cold-boot fallback: stop only (it was never a pooled standby).
    Stop,
    /// Claimed a pooled standby: stop the booted VM and replenish a fresh one.
    StopAndReplenish,
}

/// How a lease obtained its VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmLeaseOrigin {
    /// The VM was claimed from a compatible standby parent.
    WarmClaim,
    /// The VM was started directly because warm capacity was not used.
    ColdBoot,
}

/// An exclusively-held warm VM. Dropping it stops the VM (and replenishes the
/// pool for a claimed lease); use [`WarmLease::release`] to surface errors that
/// `Drop` deliberately swallows.
pub struct WarmLease {
    backend: Arc<dyn VmBackend>,
    id: VmId,
    origin: WarmLeaseOrigin,
    release_policy: ReleasePolicy,
    replenish: Option<ReplenishFn>,
    released: bool,
    replenished: bool,
}

impl WarmLease {
    /// Claim a compatible idle standby, or cold-boot when the mode permits it.
    ///
    /// On a hit: reserve (`mark_claimed`, so a concurrent acquire can't
    /// double-claim) → `claim_standby` → remove the pool entry (its control
    /// socket is one-shot). A failed claim is quarantined. Required warm mode
    /// returns a typed refusal; optional mode may then cold-boot.
    pub fn acquire(
        backend: Arc<dyn VmBackend>,
        pool: &SupervisorStandbyPool,
        spec: &AcquireSpec,
        replenish: Option<ReplenishFn>,
    ) -> Result<Self> {
        if !matches!(spec.mode, WarmLaunchMode::Cold) {
            if !backend.supports_standby_pool() {
                if spec.mode.requires_warm() {
                    return Err(anyhow::Error::new(WarmClaimRefusal::BackendUnsupported {
                        backend: backend.name().to_string(),
                    }));
                }
            } else if let Some(handle) = pool.claim_idle_compatible(&spec.want)? {
                let claimed = backend.claim_standby(&handle, &spec.claim);
                pool.remove(&handle.id)
                    .with_context(|| format!("quarantining claimed standby {}", handle.id))?;
                match claimed {
                    Ok(id) => {
                        return Ok(Self {
                            backend,
                            id,
                            origin: WarmLeaseOrigin::WarmClaim,
                            release_policy: ReleasePolicy::StopAndReplenish,
                            replenish,
                            released: false,
                            replenished: false,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(standby = %handle.id, error = %e, "warm claim failed");
                        if spec.mode.requires_warm() {
                            return Err(anyhow::Error::new(WarmClaimRefusal::ClaimRejected {
                                reason: e.to_string(),
                            }));
                        }
                    }
                }
            } else if spec.mode.requires_warm() {
                return Err(anyhow::Error::new(WarmClaimRefusal::NoCompatibleParent));
            }
        }

        let cfg = spec
            .claim
            .start_config
            .as_ref()
            .context("cold-boot fallback requires AcquireSpec.claim.start_config")?;
        let id = backend.start(cfg).context("cold-boot fallback start")?;
        Ok(Self {
            backend,
            id,
            origin: WarmLeaseOrigin::ColdBoot,
            release_policy: ReleasePolicy::Stop,
            replenish,
            released: false,
            replenished: false,
        })
    }

    /// The booted VM's id.
    pub fn id(&self) -> &VmId {
        &self.id
    }

    /// Whether this lease came from a standby parent or a direct boot.
    pub fn origin(&self) -> WarmLeaseOrigin {
        self.origin
    }

    /// A vsock transport to the leased VM.
    pub fn transport(&self) -> Result<Box<dyn VsockTransport>> {
        vsock_transport::for_vm(&self.id.0)
    }

    /// Stage files + run a command (or chain) in the leased VM over one stream.
    pub fn exec(&self) -> super::exec_builder::ExecBuilder<'_> {
        super::exec_builder::ExecBuilder::new(self)
    }

    /// Stop the VM (and replenish for a claimed lease), surfacing errors that
    /// `Drop` would swallow.
    pub fn release(&mut self) -> Result<()> {
        self.teardown()
    }

    fn teardown(&mut self) -> Result<()> {
        if !self.released {
            self.backend
                .stop(&self.id)
                .with_context(|| format!("stopping warm-leased VM {}", self.id.0))?;
            self.released = true;
        }
        if self.release_policy == ReleasePolicy::StopAndReplenish && !self.replenished {
            if let Some(replenish) = &self.replenish {
                replenish().context("replenishing the standby pool after release")?;
            }
            self.replenished = true;
        }
        Ok(())
    }
}

impl Drop for WarmLease {
    fn drop(&mut self) {
        if self.released
            && (self.release_policy != ReleasePolicy::StopAndReplenish || self.replenished)
        {
            return;
        }
        // Best-effort, non-panicking: a dropped lease must never leave a VM
        // running, but Drop cannot surface errors — use `release()` for that.
        if let Err(e) = self.teardown() {
            tracing::warn!("WarmLease drop teardown failed (use release() to surface): {e}");
        }
    }
}

// Every test below drives `WarmLease` through `MockBackend`, the only
// hermetic `VmBackend` test double available — so the whole module is
// gated behind `test-support` along with the mock it exercises.
#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::MockBackend;
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::vm_backend::{StandbyHandle, StandbyState, VmStartConfig};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn compat() -> StandbyCompat {
        StandbyCompat {
            template_id: None,
            kernel_sha256: "kern-abc".to_string(),
            vcpus: 2,
            mem_mib: 512,
            image_sha256: None,
            root_strategy: Default::default(),
            vsock_egress: false,
        }
    }

    fn handle(id: &str) -> StandbyHandle {
        let c = compat();
        StandbyHandle {
            id: id.to_string(),
            template_id: None,
            control_socket: "/tmp/unused.sock".to_string(),
            pid: 0,
            kernel_sha256: c.kernel_sha256,
            vcpus: c.vcpus,
            mem_mib: c.mem_mib,
            binding_nonce: "nonce".to_string(),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: c.image_sha256,
            root_strategy: c.root_strategy,
            parent_checkpoint: None,
            vsock_egress: c.vsock_egress,
            preloaded_child_vm_name: None,
        }
    }

    fn claim(cold_name: &str) -> StandbyClaim {
        StandbyClaim {
            start_config: Some(VmStartConfig {
                name: cold_name.to_string(),
                rootfs_path: "/tmp/stub.ext4".to_string(),
                cpus: 2,
                memory_mib: 512,
                ..Default::default()
            }),
            rootfs_path: "/tmp/stub.ext4".to_string(),
            tenant_id: "local".to_string(),
            audit_dir: std::path::PathBuf::from("/tmp/audit"),
            gateway_audit_socket: std::path::PathBuf::from("/tmp/gw-audit.sock"),
            gateway_events_socket: None,
            plan_json: "{}".to_string(),
            bundle_json: None,
            network_policy: NetworkPolicy::deny_all(),
        }
    }

    fn flag_replenish() -> (ReplenishFn, Arc<AtomicBool>) {
        let fired = Arc::new(AtomicBool::new(false));
        let f = fired.clone();
        let rf: ReplenishFn = Arc::new(move || {
            f.store(true, Ordering::SeqCst);
            Ok(())
        });
        (rf, fired)
    }

    #[test]
    fn acquire_cold_boots_when_pool_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mock = Arc::new(MockBackend::new()); // no standby support
        let backend: Arc<dyn VmBackend> = mock.clone();
        let (rf, fired) = flag_replenish();
        let spec = AcquireSpec {
            want: compat(),
            mode: WarmLaunchMode::Optional,
            claim: claim("cold-vm"),
        };

        let mut lease = WarmLease::acquire(backend, &pool, &spec, Some(rf)).unwrap();
        assert_eq!(lease.id().0, "cold-vm");
        assert_eq!(mock.count(), 1, "cold boot should start one VM");

        lease.release().unwrap();
        assert_eq!(mock.count(), 0, "release stops the VM");
        assert!(
            !fired.load(Ordering::SeqCst),
            "a cold-boot lease must NOT replenish the pool"
        );
    }

    #[test]
    fn acquire_claims_a_compatible_idle_standby_and_release_replenishes() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("sb-1")).unwrap();
        let mock = Arc::new(MockBackend::new().with_standby());
        let backend: Arc<dyn VmBackend> = mock.clone();
        let (rf, fired) = flag_replenish();
        let spec = AcquireSpec {
            want: compat(),
            mode: WarmLaunchMode::Optional,
            claim: claim("unused-cold"),
        };

        let mut lease = WarmLease::acquire(backend, &pool, &spec, Some(rf)).unwrap();
        assert_eq!(
            lease.id().0,
            "sb-1",
            "claimed the pooled standby, not cold boot"
        );
        assert_eq!(mock.count(), 1);
        assert!(
            pool.list().unwrap().is_empty(),
            "the claimed standby is removed from the pool (one-shot socket)"
        );

        lease.release().unwrap();
        assert_eq!(mock.count(), 0);
        assert!(
            fired.load(Ordering::SeqCst),
            "releasing a claimed lease replenishes the pool"
        );
    }

    #[test]
    fn dropping_a_claimed_lease_stops_and_replenishes() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&handle("sb-2")).unwrap();
        let mock = Arc::new(MockBackend::new().with_standby());
        let backend: Arc<dyn VmBackend> = mock.clone();
        let (rf, fired) = flag_replenish();
        let spec = AcquireSpec {
            want: compat(),
            mode: WarmLaunchMode::Optional,
            claim: claim("unused-cold"),
        };

        {
            let _lease = WarmLease::acquire(backend, &pool, &spec, Some(rf)).unwrap();
            assert_eq!(mock.count(), 1);
        } // drop here

        assert_eq!(mock.count(), 0, "drop stops the leased VM");
        assert!(
            fired.load(Ordering::SeqCst),
            "drop replenishes a claimed lease"
        );
    }

    #[test]
    fn release_surfaces_a_stop_error_that_drop_would_swallow() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let mock = Arc::new(MockBackend::new().with_failing_stop());
        let backend: Arc<dyn VmBackend> = mock.clone();
        let spec = AcquireSpec {
            want: compat(),
            mode: WarmLaunchMode::Optional,
            claim: claim("cold-vm"),
        };

        let mut lease = WarmLease::acquire(backend, &pool, &spec, None).unwrap();
        let err = lease.release().unwrap_err();
        assert!(
            err.to_string().contains("stopping warm-leased VM"),
            "release surfaces the stop failure, got: {err}"
        );
    }

    #[test]
    fn required_mode_refuses_when_backend_has_no_warm_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let backend: Arc<dyn VmBackend> = Arc::new(MockBackend::new());
        let spec = AcquireSpec {
            want: compat(),
            mode: WarmLaunchMode::Required,
            claim: claim("must-not-cold-boot"),
        };

        let err = match WarmLease::acquire(backend, &pool, &spec, None) {
            Ok(_) => panic!("required warm mode must not cold-boot"),
            Err(err) => err,
        };
        assert!(matches!(
            err.downcast_ref::<WarmClaimRefusal>(),
            Some(WarmClaimRefusal::BackendUnsupported { .. })
        ));
    }

    #[test]
    fn required_mode_refuses_pool_exhaustion() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let backend: Arc<dyn VmBackend> = Arc::new(MockBackend::new().with_standby());
        let spec = AcquireSpec {
            want: compat(),
            mode: WarmLaunchMode::Required,
            claim: claim("must-not-cold-boot"),
        };

        let err = match WarmLease::acquire(backend, &pool, &spec, None) {
            Ok(_) => panic!("required warm mode must refuse an empty pool"),
            Err(err) => err,
        };
        assert!(matches!(
            err.downcast_ref::<WarmClaimRefusal>(),
            Some(WarmClaimRefusal::NoCompatibleParent)
        ));
    }
}
