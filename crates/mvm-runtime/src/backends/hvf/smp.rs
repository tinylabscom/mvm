//! Secondary-vCPU bring-up: the PSCI state machine and the gate a parked CPU
//! waits on.
//!
//! HVF requires a vCPU be created on the thread that runs it, so an SMP machine
//! is one thread per CPU. Every thread but the boot CPU's starts *parked*: the
//! arm64 boot protocol has the kernel bring secondaries up itself, one PSCI
//! `CPU_ON` at a time, each carrying the entry point and per-CPU context that
//! CPU is to start with. A secondary that ran before its `CPU_ON` would execute
//! whatever the boot CPU had left in RAM.
//!
//! Nothing here touches the hypervisor. The gates are the synchronisation and
//! the PSCI decisions, kept separate from `hv_vcpu_*` so both can be tested
//! without a VM — which matters because the failure mode this code prevents is
//! a boot that hangs with no console output, and that is not a thing one
//! debugs from a test.

use std::sync::{Condvar, Mutex};

use crate::vmm::fdt;

/// PSCI return codes, from the Arm Power State Coordination Interface spec.
/// Named rather than inlined because the guest's behaviour differs sharply
/// between them and `-2` at a call site says nothing about which.
pub(crate) mod psci {
    pub(crate) const SUCCESS: u64 = 0;
    pub(crate) const NOT_SUPPORTED: u64 = (-1i64) as u64;
    /// The target CPU is not one this machine has.
    pub(crate) const INVALID_PARAMETERS: u64 = (-2i64) as u64;
    /// The target CPU is already running.
    pub(crate) const ALREADY_ON: u64 = (-4i64) as u64;
    /// `AFFINITY_INFO`: the queried CPU is running.
    pub(crate) const AFFINITY_ON: u64 = 0;
    /// `AFFINITY_INFO`: the queried CPU is stopped.
    pub(crate) const AFFINITY_OFF: u64 = 1;
}

/// The register state one vCPU starts from.
///
/// The primary and a secondary differ only in these values, not in how they are
/// created, so the difference is data rather than a second code path. The
/// primary enters at the kernel's entry point with the DTB in x0, per the arm64
/// boot protocol. A secondary released by PSCI `CPU_ON` enters at the address
/// that call supplied, with its context id in x0 — the kernel puts a per-CPU
/// pointer there and reads it back on the other side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VcpuStart {
    /// MPIDR_EL1 affinity. Must equal the `cpu@<addr>` node's reg in the device
    /// tree, or the CPU cannot be matched to its GIC redistributor frame.
    pub(crate) mpidr: u64,
    /// Where this CPU begins executing.
    pub(crate) entry: u64,
    /// x0 at entry: the DTB address for the primary, the PSCI context id for a
    /// secondary.
    pub(crate) x0: u64,
}

impl VcpuStart {
    /// The boot CPU: entry point from the kernel image, DTB in x0.
    pub(crate) fn primary(entry: u64, dtb_addr: u64) -> Self {
        Self {
            mpidr: fdt::mpidr_for_cpu(0),
            entry,
            x0: dtb_addr,
        }
    }

    /// A secondary released by `CPU_ON(target, entry, context_id)`.
    pub(crate) fn secondary(cpu: u32, entry: u64, context_id: u64) -> Self {
        Self {
            mpidr: fdt::mpidr_for_cpu(cpu),
            entry,
            x0: context_id,
        }
    }
}

/// Why a parked secondary woke up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Release {
    /// A PSCI `CPU_ON` supplied these start values; enter the guest.
    Start(VcpuStart),
    /// The run is ending. Leave without ever entering the guest — this is the
    /// path for a CPU the guest never onlined (a `maxcpus=` cmdline, or a
    /// kernel that simply chose not to).
    Shutdown,
}

/// What one secondary is waiting on.
#[derive(Debug, Default)]
struct GateState {
    /// Set by a `CPU_ON` from another CPU; taken by the parked thread.
    requested: Option<VcpuStart>,
    /// Whether this CPU has been released. Distinct from `requested`, which the
    /// waiting thread consumes: `AFFINITY_INFO` and the `ALREADY_ON` check have
    /// to keep answering after the request is taken.
    on: bool,
    /// The run is ending; wake and leave.
    shutdown: bool,
}

/// One secondary's parking spot.
#[derive(Default)]
struct CpuGate {
    state: Mutex<GateState>,
    wake: Condvar,
}

/// Every secondary's gate, and the PSCI calls answered against them.
///
/// Indexed by CPU number, with index 0 unused — the boot CPU is never parked
/// and is never a `CPU_ON` target. Keeping it in the vector rather than
/// offsetting by one means a CPU number is an index everywhere, which is one
/// fewer place for an off-by-one to put a CPU's start values into its
/// neighbour's gate.
pub(crate) struct SecondaryGates {
    gates: Vec<CpuGate>,
}

impl SecondaryGates {
    /// Gates for a machine of `vcpus` CPUs.
    pub(crate) fn new(vcpus: u32) -> Self {
        Self {
            gates: (0..vcpus.max(1)).map(|_| CpuGate::default()).collect(),
        }
    }

    /// CPUs this machine has.
    pub(crate) fn vcpus(&self) -> u32 {
        u32::try_from(self.gates.len()).unwrap_or(u32::MAX)
    }

    /// Answer a PSCI `CPU_ON(target_mpidr, entry, context_id)`.
    ///
    /// Never reports `SUCCESS` for a CPU no thread is waiting to run. The
    /// kernel's `cpu_up` blocks until the target reaches its release point, so
    /// a success this VMM cannot honour turns "fewer CPUs than asked for" into
    /// "the boot never finishes" — a hang with no console output, which reads
    /// as a VMM fault rather than a topology mismatch.
    pub(crate) fn cpu_on(&self, target_mpidr: u64, entry: u64, context_id: u64) -> u64 {
        let Some(cpu) = self.cpu_index(target_mpidr) else {
            return psci::INVALID_PARAMETERS;
        };
        if cpu == 0 {
            // The boot CPU is running this very call.
            return psci::ALREADY_ON;
        }
        let mut state = self.lock(cpu);
        if state.on {
            return psci::ALREADY_ON;
        }
        state.on = true;
        state.requested = Some(VcpuStart::secondary(cpu, entry, context_id));
        drop(state);
        self.gates[cpu as usize].wake.notify_all();
        psci::SUCCESS
    }

    /// Answer a PSCI `AFFINITY_INFO(target_mpidr, ..)`.
    ///
    /// The kernel polls this after a `CPU_ON`, so the answer has to separate a
    /// CPU that does not exist from one that exists and has not started.
    /// `NOT_SUPPORTED` here would leave it unable to tell a failed bring-up
    /// from an unimplemented call.
    pub(crate) fn affinity_info(&self, target_mpidr: u64) -> u64 {
        let Some(cpu) = self.cpu_index(target_mpidr) else {
            return psci::INVALID_PARAMETERS;
        };
        if cpu == 0 {
            return psci::AFFINITY_ON;
        }
        if self.lock(cpu).on {
            psci::AFFINITY_ON
        } else {
            psci::AFFINITY_OFF
        }
    }

    /// Record that `cpu` is already running, without releasing a gate.
    ///
    /// For a restored machine: that CPU was running when its parent was
    /// captured, so it resumes directly from the saved registers rather than
    /// waiting for a `CPU_ON` the guest has no reason to issue again. The gate
    /// still has to know, or `AFFINITY_INFO` would report a running CPU as off
    /// and a later `CPU_ON` would try to restart it.
    pub(crate) fn mark_on(&self, cpu: u32) {
        if cpu < self.vcpus() {
            self.lock(cpu).on = true;
        }
    }

    /// Park the calling thread until CPU `cpu` is released or the run ends.
    ///
    /// Returns [`Release::Shutdown`] for a CPU the guest never onlined, so
    /// every spawned thread has a way out that does not depend on the guest
    /// having cooperated.
    pub(crate) fn wait_for_release(&self, cpu: u32) -> Release {
        let gate = &self.gates[cpu as usize];
        let mut state = gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(start) = state.requested.take() {
                return Release::Start(start);
            }
            if state.shutdown {
                return Release::Shutdown;
            }
            state = gate
                .wake
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Wake every parked secondary to leave. Idempotent, so the shutdown path
    /// can call it without tracking whether it already has.
    pub(crate) fn shutdown(&self) {
        for gate in &self.gates {
            gate.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown = true;
            gate.wake.notify_all();
        }
    }

    /// The CPU number an MPIDR names, or `None` if this machine has no such
    /// CPU.
    fn cpu_index(&self, target_mpidr: u64) -> Option<u32> {
        (0..self.vcpus()).find(|cpu| fdt::mpidr_for_cpu(*cpu) == target_mpidr)
    }

    fn lock(&self, cpu: u32) -> std::sync::MutexGuard<'_, GateState> {
        self.gates[cpu as usize]
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A `CPU_ON` releases exactly the CPU it named, with the values it carried.
    ///
    /// The entry point and context id are the whole payload of the call: the
    /// kernel reads its per-CPU pointer back out of x0 on the other side, so
    /// delivering another CPU's values — or the DTB address the primary got —
    /// has the secondary dereference the wrong thing as its own state. That
    /// faults inside the guest, with nothing on the host to explain it.
    #[test]
    fn cpu_on_releases_the_named_cpu_with_the_values_it_carried() {
        let gates = Arc::new(SecondaryGates::new(4));
        let waiter = {
            let gates = Arc::clone(&gates);
            std::thread::spawn(move || gates.wait_for_release(2))
        };

        // Issued without waiting for the thread to park. The request is stored
        // in the gate rather than signalled to whoever happens to be waiting,
        // so a `CPU_ON` that lands first is still collected — the race a
        // notify-only gate would lose is exactly the one that hangs a boot.
        assert_eq!(
            gates.cpu_on(2, 0x8100_0000, 0xDEAD_BEEF),
            psci::SUCCESS,
            "cpu 2 exists and is off, so CPU_ON must succeed"
        );

        assert_eq!(
            waiter.join().unwrap(),
            Release::Start(VcpuStart {
                mpidr: 2,
                entry: 0x8100_0000,
                x0: 0xDEAD_BEEF,
            })
        );
    }

    /// A CPU this machine does not have is refused, not silently accepted.
    #[test]
    fn cpu_on_refuses_a_cpu_this_machine_does_not_have() {
        let gates = SecondaryGates::new(2);
        for absent in [2u64, 3, 64] {
            assert_eq!(
                gates.cpu_on(absent, 0x8100_0000, 0),
                psci::INVALID_PARAMETERS,
                "cpu {absent} does not exist on a 2-CPU machine"
            );
            assert_eq!(gates.affinity_info(absent), psci::INVALID_PARAMETERS);
        }
    }

    /// The boot CPU is always on, and turning it on again is `ALREADY_ON`.
    #[test]
    fn the_boot_cpu_reports_on_and_cannot_be_turned_on_again() {
        let gates = SecondaryGates::new(4);
        assert_eq!(gates.affinity_info(0), psci::AFFINITY_ON);
        assert_eq!(gates.cpu_on(0, 0x8100_0000, 0), psci::ALREADY_ON);
    }

    /// A second `CPU_ON` for a CPU already released is `ALREADY_ON`.
    ///
    /// It must not queue a second set of start values: the CPU is running by
    /// then, and re-entering it at a fresh entry point would reset a CPU the
    /// kernel believes it owns.
    #[test]
    fn a_repeated_cpu_on_is_refused_rather_than_restarting_the_cpu() {
        let gates = SecondaryGates::new(2);
        assert_eq!(gates.cpu_on(1, 0x8100_0000, 1), psci::SUCCESS);
        assert_eq!(gates.cpu_on(1, 0x8200_0000, 2), psci::ALREADY_ON);
        assert_eq!(
            gates.wait_for_release(1),
            Release::Start(VcpuStart {
                mpidr: 1,
                entry: 0x8100_0000,
                x0: 1,
            }),
            "the first request stands; the second must not have replaced it"
        );
    }

    /// `AFFINITY_INFO` separates a CPU that is absent from one that is present
    /// and stopped.
    #[test]
    fn affinity_info_separates_an_absent_cpu_from_a_stopped_one() {
        let gates = SecondaryGates::new(4);
        assert_eq!(gates.affinity_info(3), psci::AFFINITY_OFF);
        assert_eq!(gates.affinity_info(4), psci::INVALID_PARAMETERS);
        assert_eq!(gates.cpu_on(3, 0x8100_0000, 0), psci::SUCCESS);
        assert_eq!(
            gates.affinity_info(3),
            psci::AFFINITY_ON,
            "a released CPU reports on even after its request is consumed"
        );
    }

    /// A CPU the guest never onlined still has a way out.
    ///
    /// A `maxcpus=1` cmdline, or a kernel that simply declines to online the
    /// rest, leaves those threads parked forever. Without this the run would
    /// hang at join — the VM's work finished, every workload result in hand,
    /// waiting on a CPU the guest was never going to ask for.
    #[test]
    fn shutdown_releases_a_cpu_the_guest_never_onlined() {
        let gates = Arc::new(SecondaryGates::new(3));
        let waiters: Vec<_> = [1u32, 2]
            .into_iter()
            .map(|cpu| {
                let gates = Arc::clone(&gates);
                std::thread::spawn(move || gates.wait_for_release(cpu))
            })
            .collect();

        gates.shutdown();

        for waiter in waiters {
            assert_eq!(waiter.join().unwrap(), Release::Shutdown);
        }
    }

    /// Shutdown after a release still lets an already-started CPU be woken
    /// again — the second wait returns `Shutdown` rather than blocking.
    #[test]
    fn shutdown_is_idempotent_and_outlives_a_consumed_request() {
        let gates = SecondaryGates::new(2);
        assert_eq!(gates.cpu_on(1, 0x8100_0000, 0), psci::SUCCESS);
        assert!(matches!(gates.wait_for_release(1), Release::Start(_)));
        gates.shutdown();
        gates.shutdown();
        assert_eq!(gates.wait_for_release(1), Release::Shutdown);
    }

    /// A single-CPU machine has gates that answer, rather than a special case.
    ///
    /// `--cpus 1` is by far the common path, and it reaches exactly this code.
    /// Every target above the boot CPU is absent, which is what makes a guest
    /// that probes for secondaries leave them offline and carry on.
    #[test]
    fn a_single_cpu_machine_reports_only_the_boot_cpu() {
        let gates = SecondaryGates::new(1);
        assert_eq!(gates.vcpus(), 1);
        assert_eq!(gates.affinity_info(0), psci::AFFINITY_ON);
        for absent in [1u64, 2, 7] {
            assert_eq!(gates.cpu_on(absent, 0, 0), psci::INVALID_PARAMETERS);
            assert_eq!(gates.affinity_info(absent), psci::INVALID_PARAMETERS);
        }
    }

    /// Every CPU's start state agrees with the device tree node built for it.
    ///
    /// These are two halves of one fact. If they drift, the CPU cannot be
    /// matched to its GIC redistributor frame and IRQ init faults before any
    /// console output.
    #[test]
    fn each_vcpu_start_agrees_with_its_device_tree_node() {
        assert_eq!(VcpuStart::primary(0, 0).mpidr, fdt::mpidr_for_cpu(0));
        for cpu in 1..8u32 {
            assert_eq!(
                VcpuStart::secondary(cpu, 0x8100_0000, 0).mpidr,
                fdt::mpidr_for_cpu(cpu),
                "cpu {cpu}: start affinity must match its device tree node"
            );
        }
    }

    /// The primary carries the DTB in x0; a secondary carries its context id.
    #[test]
    fn the_primary_carries_the_dtb_and_a_secondary_its_context_id() {
        let primary = VcpuStart::primary(0x8008_0000, 0x9FE0_0000);
        assert_eq!(primary.entry, 0x8008_0000);
        assert_eq!(
            primary.x0, 0x9FE0_0000,
            "arm64 boot protocol puts the DTB address in x0"
        );

        let secondary = VcpuStart::secondary(1, 0x8100_0000, 0xFEED_FACE);
        assert_eq!(secondary.entry, 0x8100_0000);
        assert_eq!(
            secondary.x0, 0xFEED_FACE,
            "PSCI supplies the context id, not the DTB"
        );
    }

    /// Concurrent `CPU_ON`s for different CPUs each release their own.
    ///
    /// Linux brings secondaries up one at a time, but nothing in PSCI requires
    /// it, and a gate that serialised them through shared state would be a
    /// latent hang the moment a guest did otherwise.
    #[test]
    fn concurrent_cpu_ons_release_each_cpu_independently() {
        let gates = Arc::new(SecondaryGates::new(5));
        let waiters: Vec<_> = (1..5u32)
            .map(|cpu| {
                let gates = Arc::clone(&gates);
                std::thread::spawn(move || (cpu, gates.wait_for_release(cpu)))
            })
            .collect();

        let callers: Vec<_> = (1..5u32)
            .map(|cpu| {
                let gates = Arc::clone(&gates);
                std::thread::spawn(move || {
                    gates.cpu_on(u64::from(cpu), 0x8100_0000 + u64::from(cpu), u64::from(cpu))
                })
            })
            .collect();

        for caller in callers {
            assert_eq!(caller.join().unwrap(), psci::SUCCESS);
        }
        for waiter in waiters {
            let (cpu, release) = waiter.join().unwrap();
            assert_eq!(
                release,
                Release::Start(VcpuStart {
                    mpidr: u64::from(cpu),
                    entry: 0x8100_0000 + u64::from(cpu),
                    x0: u64::from(cpu),
                }),
                "cpu {cpu} must receive its own start values, not another's"
            );
        }
    }
}
