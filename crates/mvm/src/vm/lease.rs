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

use anyhow::{Context, Result};
use mvm_backend::standby_pool::SupervisorStandbyPool;
use mvm_core::vm_backend::{StandbyClaim, StandbyCompat, VmBackend, VmId};

use crate::vsock_transport::{self, VsockTransport};

/// What a lease needs to claim (or cold-boot) a warm VM.
pub struct AcquireSpec {
    /// Compat key for the standby match (kernel + fixed resources + image).
    pub want: StandbyCompat,
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

/// An exclusively-held warm VM. Dropping it stops the VM (and replenishes the
/// pool for a claimed lease); use [`WarmLease::release`] to surface errors that
/// `Drop` deliberately swallows.
pub struct WarmLease {
    backend: Arc<dyn VmBackend>,
    id: VmId,
    release_policy: ReleasePolicy,
    replenish: Option<ReplenishFn>,
    released: bool,
}

impl WarmLease {
    /// Claim a compatible idle standby, or cold-boot on a miss.
    ///
    /// On a hit: reserve (`mark_claimed`, so a concurrent acquire can't
    /// double-claim) → `claim_standby` → remove the pool entry (its control
    /// socket is one-shot). A failed claim falls back to cold boot rather than
    /// proceeding without the workload.
    pub fn acquire(
        backend: Arc<dyn VmBackend>,
        pool: &SupervisorStandbyPool,
        spec: &AcquireSpec,
        replenish: Option<ReplenishFn>,
    ) -> Result<Self> {
        if backend.supports_standby_pool()
            && let Some(handle) = pool.select_idle_compatible(&spec.want)?
        {
            pool.mark_claimed(&handle.id)
                .with_context(|| format!("reserving standby {}", handle.id))?;
            let claimed = backend.claim_standby(&handle, &spec.claim);
            pool.remove(&handle.id)
                .with_context(|| format!("removing claimed standby {}", handle.id))?;
            match claimed {
                Ok(id) => {
                    return Ok(Self {
                        backend,
                        id,
                        release_policy: ReleasePolicy::StopAndReplenish,
                        replenish,
                        released: false,
                    });
                }
                Err(e) => {
                    tracing::warn!("warm claim failed, falling back to cold boot: {e}");
                }
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
            release_policy: ReleasePolicy::Stop,
            replenish,
            released: false,
        })
    }

    /// The booted VM's id.
    pub fn id(&self) -> &VmId {
        &self.id
    }

    /// A vsock transport to the leased VM.
    pub fn transport(&self) -> Result<Box<dyn VsockTransport>> {
        vsock_transport::for_vm(&self.id.0)
    }

    /// Stop the VM (and replenish for a claimed lease), surfacing errors that
    /// `Drop` would swallow.
    pub fn release(mut self) -> Result<()> {
        self.released = true; // claim teardown here so Drop does not repeat it
        self.teardown()
    }

    fn teardown(&self) -> Result<()> {
        self.backend
            .stop(&self.id)
            .with_context(|| format!("stopping warm-leased VM {}", self.id.0))?;
        if self.release_policy == ReleasePolicy::StopAndReplenish
            && let Some(replenish) = &self.replenish
        {
            replenish().context("replenishing the standby pool after release")?;
        }
        Ok(())
    }
}

impl Drop for WarmLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // Best-effort, non-panicking: a dropped lease must never leave a VM
        // running, but Drop cannot surface errors — use `release()` for that.
        if let Err(e) = self.teardown() {
            tracing::warn!("WarmLease drop teardown failed (use release() to surface): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_backend::MockBackend;
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::vm_backend::{StandbyHandle, StandbyState, VmStartConfig};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn compat() -> StandbyCompat {
        StandbyCompat {
            kernel_sha256: "kern-abc".to_string(),
            vcpus: 2,
            mem_mib: 512,
            image_sha256: None,
        }
    }

    fn handle(id: &str) -> StandbyHandle {
        let c = compat();
        StandbyHandle {
            id: id.to_string(),
            control_socket: std::path::PathBuf::from("/tmp/unused.sock"),
            pid: 0,
            kernel_sha256: c.kernel_sha256,
            vcpus: c.vcpus,
            mem_mib: c.mem_mib,
            binding_nonce: "nonce".to_string(),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: c.image_sha256,
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
            claim: claim("cold-vm"),
        };

        let lease = WarmLease::acquire(backend, &pool, &spec, Some(rf)).unwrap();
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
            claim: claim("unused-cold"),
        };

        let lease = WarmLease::acquire(backend, &pool, &spec, Some(rf)).unwrap();
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
            claim: claim("cold-vm"),
        };

        let lease = WarmLease::acquire(backend, &pool, &spec, None).unwrap();
        let err = lease.release().unwrap_err();
        assert!(
            err.to_string().contains("stopping warm-leased VM"),
            "release surfaces the stop failure, got: {err}"
        );
    }
}
