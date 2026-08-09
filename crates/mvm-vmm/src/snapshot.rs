//! The backend-agnostic snapshot seam: how the host talks to a paused VMM,
//! and the vsock-only device-model guard that stands between loading a
//! snapshot and resuming it.
//!
//! Lives here rather than in `mvm-runtime` so concrete backends can implement
//! [`SnapshotIO`] without a back-edge into the orchestration crate. The
//! *store* — the on-disk `~/.mvm/instances/<vm>/snapshot/` layout, the HMAC
//! envelope, and the tenant-key encryption around it — stays in
//! `mvm-runtime`: it is runtime policy, and nothing below this layer needs it.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::crypto::snapshot_hmac::{MEM_FILENAME, VMSTATE_FILENAME};

/// Trait the pause/resume orchestrator uses to talk to Firecracker.
/// Production wires `FirecrackerIO`; tests use `CannedIO` which
/// just writes canned bytes into the snapshot files.
///
/// `load_snapshot` used to load the bytes AND resume vCPUs in one call. It is
/// split into [`load_snapshot_paused`](Self::load_snapshot_paused) and
/// [`resume`](Self::resume) so the device-model guard
/// (`assert_vsock_only_device_model`) can run against the restored VMM's
/// config in the gap between the two — after the snapshot's devices exist to
/// inspect, but before vCPUs execute a single instruction. A restored VMM
/// reconstructs whatever devices the snapshot captured; if that includes a
/// network interface, resuming it would bypass the vsock-only egress
/// boundary. See
/// `mvm-runtime`'s `verify_and_resume_from_dir` for where the
/// three calls are sequenced.
pub trait SnapshotIO {
    /// Quiesce the running VM, write `vmstate.bin` + `mem.bin` into
    /// `dir`, leave the VM in a paused-and-shutdown state.
    fn create_snapshot(&self, dir: &Path) -> Result<()>;

    /// Load the sealed snapshot at `<dir>/{vmstate,mem}.bin` into a
    /// fresh VMM, leaving vCPUs PAUSED. The caller must inspect
    /// [`restored_device_model`](Self::restored_device_model) and run
    /// the device-model guard before calling
    /// [`resume`](Self::resume).
    fn load_snapshot_paused(&self, dir: &Path) -> Result<()>;

    /// Load a forked child's snapshot, leaving vCPUs PAUSED.
    ///
    /// Same contract as
    /// [`load_snapshot_paused`](Self::load_snapshot_paused) — the guard still
    /// has to run before [`resume`](Self::resume) — but the child's device
    /// paths are already bind-mounted into its private mount namespace, so
    /// this variant must not re-create the host vsock socket underneath them.
    fn load_snapshot_for_fork_paused(&self, dir: &Path) -> Result<()>;

    /// How many network interfaces the restored VM's device model carries,
    /// read after load and before resume — the input to
    /// `assert_vsock_only_device_model`.
    ///
    /// A count rather than a parsed model: each backend spells its device
    /// model differently, and the guard only ever asks "how many NICs?".
    /// Keeping the format on the backend side of the seam stops a
    /// hypervisor's wire schema leaking into the shared contract.
    fn restored_network_interface_count(&self) -> Result<usize>;

    /// Resume vCPUs. Only called after the device-model guard passes;
    /// calling this before the guard runs would let a NIC-carrying
    /// restore execute.
    fn resume(&self) -> Result<()>;

    /// Best-effort teardown of a VMM left paused by
    /// [`load_snapshot_paused`](Self::load_snapshot_paused) — used
    /// when the device-model guard refuses the restore, so the
    /// never-resumed VMM does not linger. Errors here are swallowed
    /// by the caller; this exists to clean up, not to report status.
    fn teardown_paused(&self) -> Result<()>;
}

/// Refuse to restore a snapshot whose device model carries a network
/// interface.
///
/// A restored VMM reconstructs whatever devices the snapshot captured. Any
/// network interface would let guest traffic reach a device outside the
/// vsock transport, bypassing the sole auditable egress boundary — so a
/// non-zero count is a hard refusal, not a warning.
///
/// Takes the count rather than a parsed config so the decision stays one
/// function with one implementation, independent of how any given backend
/// spells its device model on the wire. Backends report the count through
/// [`SnapshotIO::restored_network_interface_count`]; the parsing stays with
/// the backend that owns the format.
///
/// Pure: inspects only the passed-in count. No I/O, no VM, no clock.
pub fn assert_vsock_only_device_model(network_interface_count: usize) -> Result<()> {
    anyhow::ensure!(
        network_interface_count == 0,
        "restore refused: the snapshot's device model carries \
         {network_interface_count} network interface(s) — a network interface would \
         bypass the vsock-only egress boundary"
    );
    Ok(())
}

pub fn guarded_load_resume<IO: SnapshotIO + ?Sized>(io: &IO, dir: &Path) -> Result<()> {
    if let Err(e) = io.load_snapshot_paused(dir) {
        // The VMM may be left paused after a failed load; do not let it sit
        // alive with an unaudited device model.
        let _ = io.teardown_paused();
        return Err(e).context(format!("load_snapshot_paused({})", dir.display()));
    }
    guard_and_resume(io)
}

/// Fork variant of [`guarded_load_resume`].
///
/// A forked child's device paths are already bind-mounted into its private
/// mount namespace, so its load must not re-create the host vsock socket the
/// way a plain instance restore does. Only the load differs — the guard and the
/// resume are the same, so a fork cannot reach userspace unchecked or stay
/// paused forever.
pub fn guarded_fork_load_resume<IO: SnapshotIO + ?Sized>(io: &IO, dir: &Path) -> Result<()> {
    if let Err(e) = io.load_snapshot_for_fork_paused(dir) {
        // A failed fork load must not leave a paused child VMM behind.
        let _ = io.teardown_paused();
        return Err(e).context(format!("load_snapshot_for_fork_paused({})", dir.display()));
    }
    guard_and_resume(io)
}

/// Load a fork snapshot, run the no-NIC guard, and leave the VMM paused.
///
/// Pool refill uses this form so process creation and snapshot loading happen
/// before a workload is admitted. The claim later wires its fresh channels and
/// resumes the guarded VMM; no guest code runs before both steps complete.
pub fn guarded_fork_load_paused<IO: SnapshotIO + ?Sized>(io: &IO, dir: &Path) -> Result<()> {
    if let Err(e) = io.load_snapshot_for_fork_paused(dir) {
        let _ = io.teardown_paused();
        return Err(e).context(format!("load_snapshot_for_fork_paused({})", dir.display()));
    }
    if let Err(e) = guard_loaded_device_model(io) {
        let _ = io.teardown_paused();
        return Err(e).context("restore refused by device-model guard");
    }
    Ok(())
}

/// Shared tail: read the restored device model, refuse anything carrying a NIC
/// (tearing down the paused VMM on refusal), and only then resume vCPUs.
///
/// Every load path funnels through here, so adding a new way to load a snapshot
/// cannot silently bypass the guard.
fn guard_and_resume<IO: SnapshotIO + ?Sized>(io: &IO) -> Result<()> {
    guard_loaded_device_model(io)?;
    io.resume().with_context(|| "resume after restore")
}

fn guard_loaded_device_model<IO: SnapshotIO + ?Sized>(io: &IO) -> Result<()> {
    let count = match io
        .restored_network_interface_count()
        .with_context(|| "reading restored device model")
    {
        Ok(n) => n,
        Err(e) => {
            // The paused VMM has an unreadable device model; tear it down
            // before surfacing the error so it never resumes unchecked.
            let _ = io.teardown_paused();
            return Err(e);
        }
    };
    if let Err(e) = assert_vsock_only_device_model(count) {
        let _ = io.teardown_paused();
        return Err(e).context("restore refused by device-model guard");
    }
    Ok(())
}
/// The one `SnapshotIO` double: writes canned bytes, reports a configurable
/// restored NIC count, and records call order. Used by the unit tests below
/// and by integration tests exercising the seal/verify flow without a live
/// Firecracker.
///
/// Defaults to a vsock-only (no-NIC) restore. Call
/// [`with_network_interfaces`](Self::with_network_interfaces) to drive the
/// guard's refusal path, and [`calls`](Self::calls) to assert the
/// load → guard → resume ordering (and that a refusal tears down without
/// ever resuming).
pub struct CannedIO {
    pub vmstate_bytes: Vec<u8>,
    pub mem_bytes: Vec<u8>,
    restored_network_interfaces: usize,
    calls: std::cell::RefCell<Vec<&'static str>>,
}

impl CannedIO {
    /// A no-NIC double over the given snapshot payloads.
    pub fn new(vmstate_bytes: impl Into<Vec<u8>>, mem_bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            vmstate_bytes: vmstate_bytes.into(),
            mem_bytes: mem_bytes.into(),
            restored_network_interfaces: 0,
            calls: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Report `n` network interfaces on restore, so a test can drive the
    /// device-model guard's refusal.
    pub fn with_network_interfaces(mut self, n: usize) -> Self {
        self.restored_network_interfaces = n;
        self
    }

    /// The `SnapshotIO` methods called so far, in order.
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }
}

impl SnapshotIO for CannedIO {
    fn create_snapshot(&self, dir: &Path) -> Result<()> {
        std::fs::write(dir.join(VMSTATE_FILENAME), &self.vmstate_bytes)?;
        std::fs::write(dir.join(MEM_FILENAME), &self.mem_bytes)?;
        Ok(())
    }
    fn load_snapshot_paused(&self, _dir: &Path) -> Result<()> {
        self.calls.borrow_mut().push("load_paused");
        Ok(())
    }
    fn load_snapshot_for_fork_paused(&self, _dir: &Path) -> Result<()> {
        self.calls.borrow_mut().push("load_fork_paused");
        Ok(())
    }
    fn restored_network_interface_count(&self) -> Result<usize> {
        self.calls.borrow_mut().push("restored_device_model");
        Ok(self.restored_network_interfaces)
    }
    fn resume(&self) -> Result<()> {
        self.calls.borrow_mut().push("resume");
        Ok(())
    }
    fn teardown_paused(&self) -> Result<()> {
        self.calls.borrow_mut().push("teardown_paused");
        Ok(())
    }
}
