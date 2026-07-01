# Backend unification on the `VmmDriver` seam — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two parallel, twice-implemented backend hierarchies with one `VmmDriver` mechanics seam consumed by two thin role runners (`WorkloadRunner`, `BuilderRunner`), and route all guest egress through a single host-side vsock bridge — deleting every NIC, gateway, and per-backend egress path.

**Architecture:** Per [ADR-102](../adrs/102-vmm-driver-seam-role-runners.md). A `VmmDriver` high seam (`blocks + vsock + console`, **no NIC**) is implemented once per VMM; the in-house VMM's lower `hv.rs` seam stays inside `InHouseDriver`. Workload backends collapse 5→1 (`WorkloadRunner`, the sole `WorkloadBackend`); builders collapse 3→1 (`BuilderRunner`). One `vsock_egress_bridge` carries claims 10/12/13 for every backend. Migration is witness-gated slice by slice; old and new coexist behind `AnyBackend` until each slice's parity passes.

**Tech Stack:** Rust (workspace, edition 2024 idioms already in tree), `anyhow`, `cargo nextest`, the existing `mvm-core::vm_backend` types (`VmId`, `VmExitStatus`, `VmStatus`, `VmCapabilities`, `SnapshotCapability`).

## Global Constraints

- **Toolchain:** use `~/.cargo/bin/cargo` (rustup), never Homebrew's `cargo`/`rustc`.
- **Gates before any task is "done":** `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace --all-targets -- -D warnings`. All four must pass.
- **No `#[allow(clippy::too_many_arguments)]`** in hand-written code — use a params struct + builder instead.
- **No spec references in code comments** — no `ADR-…`, `Plan …`, `#NN`, `WN.X`, `Sprint …` tokens in `.rs` comments (the `check-no-spec-refs-in-comments` gate fails on them). `claim-10`/`claim 10` style tokens are allowed. Keep the *reasoning* in the comment, drop the citation.
- **No Claude co-author trailer** in any commit message; attribute to the user.
- **Comment style:** terse, WHY-not-WHAT, expert-human voice. No decorative bold, no hedging.
- **Paths via `mvm-core::config`** helpers — never inline `$HOME/.mvm`.
- **`VmmSpec` has no `net` field** — vsock is the only channel off the guest. This is load-bearing, not an oversight.
- **S0 is purely additive** — it creates a new `crates/mvm-backend/src/driver/` module and touches no existing file except `crates/mvm-backend/src/lib.rs` (one `pub mod` line). `mvm-core`'s `VmBackend` is untouched until the deletion slice (S5).

---

## Slice roadmap (ADR-102 §Migration)

This file's detailed tasks implement **S0 only** — the additive, hypervisor-free foundation. Each later slice gets its own plan section appended here as it is scheduled, so each slice stays a self-contained, reviewable, working deliverable.

| Slice | Deliverable | Status |
|---|---|---|
| **S0** | `VmmDriver`/`RunningVm`/`VmmSpec` + `MockDriver`; additive, unit-tested | **this plan** |
| S1 | `InHouseDriver` + `WorkloadRunner` (HVF reference proof); promote `vsock_egress_bridge` | next |
| S2 | `LibkrunDriver` → `WorkloadRunner` | later |
| S3 | `VzDriver` → `WorkloadRunner` | later |
| S4 | `FcDriver`; FC egress nftables→vsock (careful, live-KVM) | later |
| S5 | delete the 5 old workload types + `EgressSubstitutionTransport` | later |
| S6 | `BuilderRunner` + migrate libkrun/vz/qemu builders (in-house builder falls out) | later |
| S7 | builder vsock-egress cutover; delete `BuilderNet` + all NICs | later |

---

## S0 — File structure

- `crates/mvm-backend/src/driver/mod.rs` — module root + re-exports. One responsibility: name the seam's public surface.
- `crates/mvm-backend/src/driver/spec.rs` — `VmmSpec` and its parts (`KernelImage`, `BlockDev`, `VsockPort`, `VsockDirection`, `ConsoleCapture`). Pure data; no behavior beyond small helpers.
- `crates/mvm-backend/src/driver/traits.rs` — `VmmDriver`, `RunningVm`, `DuplexStream`. The seam itself.
- `crates/mvm-backend/src/driver/mock.rs` — `MockDriver`, `MockRunningVm`. Hypervisor-free test double that records the `VmmSpec` and provides a loopback vsock. Test infrastructure (mirrors the existing `mock.rs` precedent — a real module, not `#[cfg(test)]`, so later slices' unit tests can drive it).
- `crates/mvm-backend/src/lib.rs` — add `pub mod driver;`.

---

### Task 1: `VmmSpec` and its parts

**Files:**
- Create: `crates/mvm-backend/src/driver/spec.rs`
- Create: `crates/mvm-backend/src/driver/mod.rs`
- Modify: `crates/mvm-backend/src/lib.rs` (add `pub mod driver;` among the existing `pub mod` declarations)

**Interfaces:**
- Produces: `VmmSpec { name: String, kernel: KernelImage, cmdline: String, vcpus: u32, memory_mib: u32, mem_initial_mib: Option<u32>, blocks: Vec<BlockDev>, vsock: Vec<VsockPort>, console: ConsoleCapture }`; `KernelImage::{Path(PathBuf), Bundled}`; `BlockDev { source: PathBuf, read_only: bool, slot: u8 }` with `fn device_node(&self) -> String`; `VsockDirection::{HostDials, GuestDials}`; `VsockPort { guest_port: u32, host_uds: PathBuf, direction: VsockDirection }`; `ConsoleCapture { log_path: PathBuf }`. All `#[derive(Debug, Clone, PartialEq, Eq)]`.

- [ ] **Step 1: Write the failing test**

Append to `crates/mvm-backend/src/driver/spec.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_dev_device_node_maps_slot_to_letter() {
        let mk = |slot| BlockDev {
            source: "/x".into(),
            read_only: true,
            slot,
        };
        assert_eq!(mk(0).device_node(), "/dev/vda");
        assert_eq!(mk(1).device_node(), "/dev/vdb");
        assert_eq!(mk(25).device_node(), "/dev/vdz");
    }
}
```

- [ ] **Step 2: Write the types + module wiring so it compiles**

Prepend to `crates/mvm-backend/src/driver/spec.rs` (above the test module):

```rust
//! `VmmSpec` — the backend-agnostic physical recipe a `VmmDriver` boots.
//!
//! A guest VM has exactly three host-visible channel kinds: block storage,
//! vsock, and a write-only console. There is deliberately no NIC: a guest's
//! only path off the box is a reserved vsock egress port terminated by the
//! host-side egress bridge. Keeping networking out of the spec is what stops a
//! driver from being able to enforce — or bypass — egress policy.

use std::path::PathBuf;

/// Where a VM's kernel comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelImage {
    /// An explicit kernel file on the host (Firecracker, qemu, the in-house VMM).
    Path(PathBuf),
    /// The backend supplies its own bundled kernel (libkrun's libkrunfw).
    Bundled,
}

/// One virtio-blk device. `slot` fixes the guest device-node ordering so the
/// kernel cmdline (roothash, overlay) can name a stable `/dev/vdX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDev {
    pub source: PathBuf,
    pub read_only: bool,
    pub slot: u8,
}

impl BlockDev {
    /// The guest device node for this slot: 0 -> `/dev/vda`, 1 -> `/dev/vdb`, ...
    /// Panics above slot 25; no workload needs more than 26 disks.
    pub fn device_node(&self) -> String {
        assert!(self.slot <= 25, "block slot {} exceeds /dev/vdz", self.slot);
        let letter = (b'a' + self.slot) as char;
        format!("/dev/vd{letter}")
    }
}

/// Which side opens a vsock connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsockDirection {
    /// The guest listens on `guest_port`; the host dials it (e.g. the agent RPC).
    HostDials,
    /// The host listens on `host_uds`; the guest dials it (e.g. the egress port).
    GuestDials,
}

/// One vsock port mapping between a guest port and a host unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockPort {
    pub guest_port: u32,
    pub host_uds: PathBuf,
    pub direction: VsockDirection,
}

/// Write-only host capture of the guest console. There is no input fd — the
/// host can read the log but never write the guest's console, so a sealed
/// guest stays non-interactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleCapture {
    pub log_path: PathBuf,
}

/// The backend-agnostic physical recipe a [`VmmDriver`](crate::driver::VmmDriver)
/// boots. No NIC: vsock is the only channel off the guest besides storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmSpec {
    pub name: String,
    pub kernel: KernelImage,
    pub cmdline: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    /// Initial host commitment for virtio-balloon elasticity; `None` commits
    /// the full `memory_mib` at boot.
    pub mem_initial_mib: Option<u32>,
    pub blocks: Vec<BlockDev>,
    pub vsock: Vec<VsockPort>,
    pub console: ConsoleCapture,
}
```

Create `crates/mvm-backend/src/driver/mod.rs` — **only the `spec` module for now**; Task 2 adds `traits` and `mock`, so each task compiles on its own:

```rust
//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.

pub mod spec;

pub use spec::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};
```

Add to `crates/mvm-backend/src/lib.rs`, alongside the other `pub mod` declarations:

```rust
pub mod driver;
```

- [ ] **Step 3: Run the test to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-backend driver::spec`
Expected: `block_dev_device_node_maps_slot_to_letter` PASS. The crate compiles — `mod.rs` references only `spec`, which exists.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-backend/src/driver/spec.rs crates/mvm-backend/src/driver/mod.rs crates/mvm-backend/src/lib.rs
git commit -m "feat(driver): VmmSpec — the no-NIC physical recipe for the VmmDriver seam"
```

---

### Task 2: `VmmDriver` / `RunningVm` traits + `MockDriver` boot/exit

**Files:**
- Create: `crates/mvm-backend/src/driver/traits.rs`
- Create: `crates/mvm-backend/src/driver/mock.rs`
- Modify: `crates/mvm-backend/src/driver/mod.rs` (add `traits` + `mock` modules and re-exports)
- Test: in `crates/mvm-backend/src/driver/mock.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `VmmSpec` (Task 1); `mvm_core::vm_backend::{VmId, VmExitStatus, VmStatus, VmCapabilities, SnapshotCapability}`.
- Produces: `trait DuplexStream: Read + Write + Send`; `trait VmmDriver: Send + Sync` with `fn name(&self) -> &str`, `fn is_available(&self) -> Result<bool>`, `fn capabilities(&self) -> VmCapabilities`, `fn snapshot_capability(&self) -> SnapshotCapability`, `fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>>`; `trait RunningVm: Send` with `id`/`wait`/`kill`/`pause`/`resume`/`status`/`vsock_connect`. `MockDriver` with `fn with_exit(VmExitStatus) -> Self`, `fn booted_specs(&self) -> Vec<VmmSpec>`, `fn take_guest_end(&self, &VmId, u32) -> Option<UnixStream>` (the last used in Task 3).

- [ ] **Step 1: Write the failing test**

Put in `crates/mvm-backend/src/driver/mock.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::spec::{ConsoleCapture, KernelImage, VmmSpec};

    fn sample_spec(name: &str) -> VmmSpec {
        VmmSpec {
            name: name.to_string(),
            kernel: KernelImage::Bundled,
            cmdline: String::new(),
            vcpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks: vec![],
            vsock: vec![],
            console: ConsoleCapture { log_path: "/tmp/console.log".into() },
        }
    }

    #[test]
    fn mock_driver_records_booted_spec_and_scripts_exit() {
        let driver = MockDriver::with_exit(VmExitStatus { code: Some(2), success: false });
        let spec = sample_spec("probe");
        let vm = driver.boot(&spec).unwrap();
        assert_eq!(driver.booted_specs(), vec![spec]);
        assert_eq!(vm.wait().unwrap(), VmExitStatus { code: Some(2), success: false });
        assert_eq!(vm.id(), &VmId("probe".into()));
        assert_eq!(driver.name(), "mock");
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `~/.cargo/bin/cargo nextest run -p mvm-backend driver::mock`
Expected: FAIL to compile — `MockDriver`/`VmmDriver` not yet defined.

- [ ] **Step 3: Write the traits**

Replace `crates/mvm-backend/src/driver/traits.rs` with:

```rust
//! The `VmmDriver` seam: pure VMM mechanics, written once per VMM. Role policy
//! (workload admission/egress/audit, builder orchestration) lives in the role
//! runners above this trait, never here. The driver carries no workload
//! permission and never sees an admitted plan — it boots what the spec
//! describes and nothing more.

use anyhow::Result;
use mvm_core::vm_backend::{SnapshotCapability, VmCapabilities, VmExitStatus, VmId, VmStatus};

use crate::driver::spec::VmmSpec;

/// A bidirectional, owned guest channel (a connected vsock stream).
pub trait DuplexStream: std::io::Read + std::io::Write + Send {}
impl<T: std::io::Read + std::io::Write + Send> DuplexStream for T {}

/// VMM mechanics, written once per VMM.
pub trait VmmDriver: Send + Sync {
    /// Stable backend token (`"libkrun"`, `"vz"`, `"firecracker"`, `"in-house"`, `"mock"`).
    fn name(&self) -> &str;
    /// Whether this VMM can run on the current host.
    fn is_available(&self) -> Result<bool>;
    /// Coarse capability flags.
    fn capabilities(&self) -> VmCapabilities;
    /// Honest warm-start tier.
    fn snapshot_capability(&self) -> SnapshotCapability;
    /// Boot the VM described by `spec`, returning a live handle.
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>>;
}

/// A live VM handle. Launch-model-agnostic: an in-process VMM, a subprocess,
/// and an external supervisor all present the same surface.
pub trait RunningVm: Send {
    fn id(&self) -> &VmId;
    /// Block until the VM exits; returns its status.
    fn wait(&self) -> Result<VmExitStatus>;
    /// Force-terminate the VM.
    fn kill(&self) -> Result<()>;
    fn pause(&self) -> Result<()>;
    fn resume(&self) -> Result<()>;
    fn status(&self) -> Result<VmStatus>;
    /// Open a host->guest vsock connection to `guest_port`.
    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>>;
}
```

- [ ] **Step 4: Write `MockDriver` / `MockRunningVm`**

Prepend to `crates/mvm-backend/src/driver/mock.rs` (above the test module):

```rust
//! `MockDriver` — a hypervisor-free `VmmDriver` test double. It records the
//! `VmmSpec` it is handed and returns a `MockRunningVm` with a scripted exit
//! status and an in-process loopback vsock, so the role runners can be unit
//! tested with no real VM. Test infrastructure; never a production backend.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use mvm_core::vm_backend::{SnapshotCapability, VmCapabilities, VmExitStatus, VmId, VmStatus};

use crate::driver::spec::VmmSpec;
use crate::driver::traits::{DuplexStream, RunningVm, VmmDriver};

type GuestEnds = Arc<Mutex<HashMap<(String, u32), UnixStream>>>;

/// Hypervisor-free `VmmDriver` test double.
#[derive(Clone)]
pub struct MockDriver {
    exit: VmExitStatus,
    booted: Arc<Mutex<Vec<VmmSpec>>>,
    guest_ends: GuestEnds,
}

impl Default for MockDriver {
    fn default() -> Self {
        Self::with_exit(VmExitStatus::SUCCESS)
    }
}

impl MockDriver {
    /// A mock whose VMs return `exit` from `wait()`.
    pub fn with_exit(exit: VmExitStatus) -> Self {
        Self {
            exit,
            booted: Arc::new(Mutex::new(Vec::new())),
            guest_ends: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The specs this driver has booted, in order.
    pub fn booted_specs(&self) -> Vec<VmmSpec> {
        self.booted.lock().unwrap().clone()
    }

    /// Take the guest end of the loopback a prior `vsock_connect` opened, to
    /// script the guest side in a test.
    pub fn take_guest_end(&self, vm: &VmId, guest_port: u32) -> Option<UnixStream> {
        self.guest_ends.lock().unwrap().remove(&(vm.0.clone(), guest_port))
    }
}

impl VmmDriver for MockDriver {
    fn name(&self) -> &str {
        "mock"
    }
    fn is_available(&self) -> Result<bool> {
        Ok(true)
    }
    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities { vsock: true, ..Default::default() }
    }
    fn snapshot_capability(&self) -> SnapshotCapability {
        SnapshotCapability::Unsupported
    }
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        self.booted.lock().unwrap().push(spec.clone());
        Ok(Box::new(MockRunningVm {
            id: VmId(spec.name.clone()),
            exit: self.exit,
            guest_ends: Arc::clone(&self.guest_ends),
        }))
    }
}

/// A `MockDriver`'s live VM: a scripted exit + a per-port loopback vsock whose
/// guest end the owning `MockDriver` hands back via `take_guest_end`.
pub struct MockRunningVm {
    id: VmId,
    exit: VmExitStatus,
    guest_ends: GuestEnds,
}

impl RunningVm for MockRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }
    fn wait(&self) -> Result<VmExitStatus> {
        Ok(self.exit)
    }
    fn kill(&self) -> Result<()> {
        Ok(())
    }
    fn pause(&self) -> Result<()> {
        Ok(())
    }
    fn resume(&self) -> Result<()> {
        Ok(())
    }
    fn status(&self) -> Result<VmStatus> {
        Ok(VmStatus::Running)
    }
    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        let (host, guest) = UnixStream::pair().map_err(|e| anyhow!("socketpair: {e}"))?;
        self.guest_ends
            .lock()
            .unwrap()
            .insert((self.id.0.clone(), guest_port), guest);
        Ok(Box::new(host))
    }
}
```

- [ ] **Step 5: Wire `traits` + `mock` into `mod.rs`**

Update `crates/mvm-backend/src/driver/mod.rs` to declare and re-export the two new modules (it currently has only `spec`):

```rust
//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.

pub mod mock;
pub mod spec;
pub mod traits;

pub use mock::{MockDriver, MockRunningVm};
pub use spec::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};
pub use traits::{DuplexStream, RunningVm, VmmDriver};
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-backend driver::`
Expected: both `driver::spec` and `driver::mock::tests::mock_driver_records_booted_spec_and_scripts_exit` PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-backend/src/driver/traits.rs crates/mvm-backend/src/driver/mock.rs crates/mvm-backend/src/driver/mod.rs
git commit -m "feat(driver): VmmDriver/RunningVm seam + hypervisor-free MockDriver"
```

---

### Task 3: `MockRunningVm` loopback vsock

**Files:**
- Modify: `crates/mvm-backend/src/driver/mock.rs` (add a test; the impl from Task 2 already supports it)

**Interfaces:**
- Consumes: `MockDriver::take_guest_end`, `RunningVm::vsock_connect` (Task 2).
- Produces: nothing new — proves the loopback contract later slices' runner tests depend on (host writes a frame, the test reads it as the guest, and vice versa).

- [ ] **Step 1: Write the failing test**

Add inside the existing `#[cfg(test)] mod tests` in `crates/mvm-backend/src/driver/mock.rs`:

```rust
    #[test]
    fn mock_vsock_connect_loops_host_and_guest_both_ways() {
        use std::io::{Read, Write};

        let driver = MockDriver::default();
        let vm = driver.boot(&sample_spec("v")).unwrap();

        let mut host = vm.vsock_connect(5253).unwrap();
        let mut guest = driver
            .take_guest_end(vm.id(), 5253)
            .expect("guest end registered by vsock_connect");

        host.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        guest.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");

        guest.write_all(b"pong").unwrap();
        let mut back = [0u8; 4];
        host.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong");
    }
```

- [ ] **Step 2: Run it to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-backend driver::mock::tests::mock_vsock_connect_loops_host_and_guest_both_ways`
Expected: PASS (the Task 2 impl already wires the loopback; this locks the contract). If it fails to find a guest end, confirm `vsock_connect` inserts under `(self.id.0, guest_port)` and `take_guest_end` removes under `(vm.0, guest_port)`.

- [ ] **Step 3: Run the full workspace gates**

Run each; all must pass:

```bash
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
~/.cargo/bin/cargo nextest run --workspace
~/.cargo/bin/cargo test --workspace --doc
```

Expected: clean. The change is purely additive, so no existing test should move.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-backend/src/driver/mock.rs
git commit -m "test(driver): lock the MockRunningVm loopback vsock contract"
```

---

## S0 self-review

- **Spec coverage (S0 scope only):** `VmmSpec` no-NIC recipe ✓ (Task 1); `VmmDriver`/`RunningVm` seam ✓ (Task 2); `MockDriver` records spec + scripts exit + loopback vsock ✓ (Tasks 2–3). Bridge promotion, the role runners, and any real driver are explicitly out of S0 (S1+).
- **Placeholder scan:** every step carries real code or an exact command — no TBD/TODO. Each task compiles standalone: Task 1's `mod.rs` declares only `spec`; Task 2 extends it with `traits`/`mock` in the same task that creates them.
- **Type consistency:** `VmId(pub String)`, `VmExitStatus { code, success }`, `VmStatus::Running`, `VmCapabilities { vsock, .. }`, `SnapshotCapability::Unsupported` all match `mvm-core/src/protocol/vm_backend.rs`. `MockDriver::take_guest_end(&VmId, u32)` keys match `vsock_connect`'s insert key `(self.id.0, guest_port)`.
- **Additive guarantee:** only `lib.rs` gains one `pub mod driver;` line; no existing module is modified, so no claim witness can move in S0.

---

## S1 — design (InHouseDriver + WorkloadRunner, HVF reference proof)

**Goal:** route the HVF workload path through the new seam — a `WorkloadRunner` (the sole `WorkloadBackend`) holding an `InHouseDriver: VmmDriver` — and prove parity against the current `HvfBackend` on a live boot, without moving any claim witness incorrectly.

**Ground truth from the current code:**
- HVF is an *external-supervisor* launch model: `HvfBackend::start(&VmStartConfig)` builds an `HvfSupervisorConfig` (`crates/mvm-build/src/hvf_supervisor.rs`: `kernel`, `initramfs`, `disk`, `vsock`, `console_log`, `pid_file`, `workload_exit`, `network_policy`, `timeout_secs`, `agent_socket`, `substitution_socket`), spawns the detached `mvm-hvf-supervisor` subprocess with the JSON on stdin, and waits on the PID file. The in-house `vmm::run` loop runs *inside* that subprocess.
- The claim-10 `EgressGate` is built **inside the supervisor** from `cfg.network_policy` (`crates/mvm-vm-host/src/bin/mvm-hvf-supervisor.rs:211`, `EgressGate::from_network_policy`); the run loop's `egress_proxy`/`substitution_bridge` enforce it and relay bound-secret flows to the separate `substitution_socket` endpoint (claims 12/13).
- The bridge modules are consumed cross-crate: `mvm-vm-host` (`egress_server.rs`, `mvm-hvf-supervisor.rs`), `mvm-backend` (`kvm/vm.rs`, `hvf/kernel_boot.rs`), and examples import `mvm_backend::vmm::egress_gate`.

### OPEN DECISION (security-critical) — where does the claim-10 gate run in the unified model?

The seam says the driver is pure mechanics and one host-side `vsock_egress_bridge` carries claims 10/12/13 for every backend. But today the in-house VMM's claim-10 gate runs *inside* the supervisor, fed by `network_policy` in the config. Two coherent resolutions:

- **G1 — gate in a host-side bridge process (ADR-pure, maximal uniformity).** `WorkloadRunner` spawns one `vsock_egress_bridge` process (claim-10 gate + claims-12/13 substitution) with the resolved policy. `VmmSpec` carries a `VsockPort { guest_port: EGRESS_PORT, host_uds: <bridge uds>, GuestDials }`. Every VMM — including the in-house supervisor — becomes policy-free and just relays the guest's `EGRESS_PORT` stream to that UDS (the supervisor already relays to `substitution_socket`, so this is the same move generalized). `HvfSupervisorConfig` loses `network_policy`. End state: one egress codepath, driver truly pure mechanics. Cost: changes the in-house supervisor/run loop (remove the in-process gate, keep only relay) — a real change to the code deliverable-3-style enforcement rides on.
- **G2 — gate stays in-VMM, policy threaded as a non-spec boot param.** Keep the supervisor's in-process gate; `WorkloadRunner` hands the policy to `InHouseDriver::boot` via a parameter *outside* `VmmSpec`. Smaller change, but the driver now receives policy (weakens "pure mechanics") and each VMM keeps its own in-process gate — the per-backend egress divergence the restructure targets is not fully removed.

**DECIDED: G1 (2026-06-30).** The gate moves into a host-side `vsock_egress_bridge` process the `WorkloadRunner` spawns; every VMM (incl. the in-house supervisor) becomes policy-free and relays `EGRESS_PORT` to the bridge UDS.

**Recommendation: G1.** It is the ADR's actual intent ("one host-side bridge for every backend; the driver only wires the wire"), and it is what lets Firecracker (S4) drop nftables onto the *same* bridge rather than a second in-VMM gate. G2 is a shortcut that leaves the divergence in place and would have to be undone at S4 anyway. G1's cost — moving the in-house gate out of the supervisor into a host bridge process — is paid once here and is the reference the other backends copy. This decision is a prerequisite to authoring S1b/S1c tasks; it must be settled before execution.

### Sub-slices (task detail authored per sub-slice at execution, after the G1/G2 call)

- **S1a — promote the bridge (non-live, unit-tested).** Move `vmm/{egress_gate,egress_proxy,substitution_bridge}` into a top-level `mvm_backend::vsock_egress_bridge` module. Keep `pub use` re-exports at the old `vmm::` paths so the cross-crate consumers (`mvm-vm-host`, `kvm/vm.rs`, `hvf/kernel_boot.rs`, examples) stay green — pure move + re-export, zero behavior change. Under G1 this module also gains the standalone bridge-process entry the runner spawns.
- **S1b — `InHouseDriver: VmmDriver` (mostly non-live).** Extract the supervisor-spawn + `HvfSupervisorConfig`-build + PID-wait mechanics from `HvfBackend::start` into `InHouseDriver::boot(&VmmSpec)`; `RunningVm` wraps the supervisor child + `workload_exit` vsock port + PID file. Under G1, `boot` maps `VmmSpec` (no policy) → a policy-free `HvfSupervisorConfig`. Unit-test the `VmmSpec → HvfSupervisorConfig` mapping directly.
- **S1c — `WorkloadRunner` (mostly non-live).** New `WorkloadRunner` holding a `dyn VmmDriver`, the sole `impl WorkloadBackend`. Maps `VmStartConfig → VmmSpec`, admits the plan, spawns the egress bridge + substitution endpoint (G1), emits audit, calls `driver.boot`. `HvfBackend` becomes a thin constructor `WorkloadRunner::new(InHouseDriver::new())`. Unit-test the `VmStartConfig → VmmSpec` mapping and the bridge-spawn wiring against `MockDriver`.
- **S1d — live HVF parity (live, this Mac).** Boot a real workload through `WorkloadRunner<InHouseDriver>` and compare to the old `HvfBackend` path: same exit code, same egress allow/deny verdict via `examples/egress-probe`, same audit-chain entries. Only after parity passes is the old `HvfBackend` internals swap complete.

Firecracker/libkrun/vz are untouched in S1 (still their own `AnyBackend` variants); S1 proves the seam on the cleanest VMM first.

---

### S1a — task detail (bridge promotion; behavior-preserving move + re-export)

**Single refactor task.** Relocate the three bridge modules out of the in-house VMM device model into a top-level, backend-agnostic `vsock_egress_bridge` module, preserving every consumer path via re-exports. No behavior change — the existing bridge tests + a green workspace are the proof (a move-refactor has no new failing test to write first).

**Files:**
- Move (git mv, preserve history): `crates/mvm-backend/src/vmm/egress_gate.rs` → `crates/mvm-backend/src/vsock_egress_bridge/egress_gate.rs`; `…/vmm/egress_proxy.rs` → `…/vsock_egress_bridge/egress_proxy.rs`; `…/vmm/substitution_bridge.rs` → `…/vsock_egress_bridge/substitution_bridge.rs`
- Create: `crates/mvm-backend/src/vsock_egress_bridge/mod.rs`
- Modify: `crates/mvm-backend/src/vmm/mod.rs` (replace the three `mod` decls with re-exports)
- Modify: `crates/mvm-backend/src/lib.rs` (add `pub mod vsock_egress_bridge;`)
- Modify: `xtask/src/check_vsock_only_egress.rs` (add the new dir to `GUARDED_DIRS`)

**Why it's clean:** `egress_proxy` + `substitution_bridge` reference only `super::egress_gate` (all three move together, so `super::` still resolves); the sole other `super::` uses are `use super::*;` inside each file's own `#[cfg(test)] mod tests` (self-referential). Internal consumers reach the modules via `crate::vmm::egress_gate` (in `hvf/kernel_boot.rs`, `kvm/vm.rs`, `vmm/vsock.rs`, `vmm/run.rs`) and `mvm-vm-host` reaches `egress_gate` cross-crate — all preserved by the re-exports below.

- [ ] **Step 1: Create the new module root.** `crates/mvm-backend/src/vsock_egress_bridge/mod.rs`:

```rust
//! The single host-side vsock egress bridge: the one place the claim-10 gate and
//! claims-12/13 substitution are enforced, for every backend. Promoted out of the
//! in-house VMM device model so it is backend-agnostic and one implementation
//! serves all backends.

pub mod egress_gate;
pub(crate) mod egress_proxy;
pub(crate) mod substitution_bridge;
```

- [ ] **Step 2: Move the three files** with `git mv` (keeps blame):

```bash
cd crates/mvm-backend/src
git mv vmm/egress_gate.rs vsock_egress_bridge/egress_gate.rs
git mv vmm/egress_proxy.rs vsock_egress_bridge/egress_proxy.rs
git mv vmm/substitution_bridge.rs vsock_egress_bridge/substitution_bridge.rs
```

- [ ] **Step 3: Replace the module decls in `vmm/mod.rs` with re-exports.** Find the lines `pub mod egress_gate;`, `pub(crate) mod egress_proxy;`, `pub(crate) mod substitution_bridge;` and replace all three with:

```rust
// Promoted to the top-level backend-agnostic bridge module; re-exported at the
// old paths so the in-house run loop and cross-crate consumers keep working.
pub use crate::vsock_egress_bridge::egress_gate;
pub(crate) use crate::vsock_egress_bridge::{egress_proxy, substitution_bridge};
```

- [ ] **Step 4: Register the module.** Add to `crates/mvm-backend/src/lib.rs`, near the other `pub mod` lines:

```rust
pub mod vsock_egress_bridge;
```

- [ ] **Step 5: Extend the NIC-free guard** so it covers the egress code in its new home. In `xtask/src/check_vsock_only_egress.rs`, add the new dir to `GUARDED_DIRS`:

```rust
const GUARDED_DIRS: &[&str] = &[
    "crates/mvm-backend/src/vmm",
    "crates/mvm-backend/src/hvf",
    "crates/mvm-backend/src/vsock_egress_bridge",
];
```

- [ ] **Step 6: Run the full gates** (a move-refactor is proven by the existing suite staying green):

```bash
~/.cargo/bin/cargo fmt --all -- --check
~/.cargo/bin/cargo clippy --workspace --all-targets -- -D warnings
~/.cargo/bin/cargo nextest run -p mvm-backend        # the moved bridge tests + all backend tests
~/.cargo/bin/cargo run -p xtask -- check-vsock-only-egress
```

Expected: clean. The moved modules' tests (`egress_gate`, `egress_proxy`, `substitution_bridge`) run under their new paths; every consumer resolves through the re-exports; the guard now reports the `vsock_egress_bridge` dir as NIC-free.

- [ ] **Step 7: Commit.**

```bash
git add -A
git commit -m "refactor(backend): promote the vsock egress bridge out of the vmm device model"
```
