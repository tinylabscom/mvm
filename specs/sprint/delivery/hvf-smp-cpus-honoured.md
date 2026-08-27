# `--cpus N` gives the guest N vCPUs on HVF

`mvmctl machine run --cpus 4` exited 0 and handed back one CPU (#2888). The
default is 2, so this was not a flag nobody used — every HVF guest on this
backend was running on one CPU while its admitted plan said two.

Four things had to line up, and the count had to reach all of them from one
place or they would disagree. The device tree was already done (`build_dtb`
takes `vcpus`, one `cpu@N` node each, redistributor region sized for the set).
What landed here is the rest.

**The count reaches the process that creates vCPUs.** `HvfSupervisorConfig`
gained `vcpus`, populated from `spec.vcpus`. `effective_vcpus` is the single
function the device tree and the vCPU bring-up both read, so the tree cannot
describe a CPU no thread backs — that mismatch does not degrade to a smaller
machine, it hangs the boot with an empty console. Nothing is clamped beyond
"zero means one": the host's real ceiling is whatever `hv_vcpu_create` grants,
and a count it refuses fails the boot rather than quietly shrinking the machine.

**PSCI `CPU_ON` and `AFFINITY_INFO` are answered against gates that exist.**
`backends/hvf/smp.rs` holds the state machine and the parking spot, and touches
no hypervisor call — so the behaviour that would otherwise only be observable as
a hung boot is unit-testable. `CPU_ON` never reports SUCCESS for a CPU no thread
is waiting to run, because the kernel's `cpu_up` blocks on the target reaching
its release point.

**One thread per vCPU, because HVF binds a vCPU to its creating thread.**
Secondaries are created up front and report success before the guest starts: the
tree already describes them, so a vCPU the host refuses has to fail the boot
*here*, while a failure is still a failed boot. Each then parks until its
`CPU_ON`, and a CPU the guest never onlines (a `maxcpus=` cmdline) leaves through
the same gate rather than being joined forever.

**One device bus.** `run_on_bus` reaches devices through a `DeviceBus`, and every
vCPU of a machine shares one `SharedBus` — a single lock over all devices, taken
per access and never held across the pause or throttle holds. A single-CPU run
takes the same path and pays an uncontended lock per MMIO exit, which is nothing
next to the exit; the alternative was a second copy of the loop for the common
case, which is the kind that rots. KVM still enters through `SoleBus` and is
unchanged.

## Two things the hardware taught us

`hv_gic_get_redistributor_base` **must be called after MPIDR_EL1 is set** — it
returns `HV_BAD_ARGUMENT` otherwise, which is what the first working build did
for four minutes of confusion. That is also the useful fact: HVF places a vCPU's
redistributor frame by its *affinity*, not by creation order, so an early
experiment serialising `hv_vcpu_create` into CPU order was solving a problem that
does not exist and was removed. Each secondary now sets its own MPIDR at creation
and the frame is checked against the address the device tree published. A
mismatch is `RedistributorMismatch { cpu, expected, actual }` rather than a guest
that faults in IRQ init before the console exists.

## Snapshot, restore and the CPU quota

These were all single-vCPU shaped and are the machinery warm-fork depends on, so
"SMP works but forking a 2-CPU machine does not" would have been a worse trade
than no SMP at all.

A snapshot frame now carries one fixed-width record per CPU in CPU order; the
count is the section length over the record length, so no separate field can
disagree with the payload, and a partial or empty section is refused rather than
silently dropping a CPU. Capture is cooperative because it has to be — HVF only
lets a vCPU's registers be read from its own thread, so the boot CPU cannot
reach into a secondary. Each secondary publishes its registers while parked and
the boot CPU assembles, only once every CPU has parked: capturing while one is
still in the guest would write a frame whose RAM and whose registers describe
different instants. Restore is the mirror — the boot CPU parses and resumes
itself, each secondary applies its own state and enters the guest directly
rather than waiting for a `CPU_ON` the guest has no reason to issue again. A
frame whose CPU count does not match the machine is refused.

The quota bounds the *machine*, so `VcpuQuota` takes every vCPU's handle and a
`SummedClock` over every vCPU thread's Mach CPU time. A controller reading one
thread of a four-CPU guest sees a quarter of what it is consuming and never
throttles — the workload runs at four times its granted share while the audit
record says it stayed inside it. The hold flag is created before the vCPU threads
and handed to the controller, because every vCPU has to be able to read it from
the moment it exists. `VcpuQuota` also grew a `Drop`: a boot that failed between
starting the controller and reading it back used to leak the controller thread.

ADR-001's claim-18 prose and CLAUDE.md were updated to say "summed across every
vCPU thread" rather than "the vCPU thread's".

## Confirmed live, on a real guest

`--cpus 2` → `2/2` and `--cpus 4` → `4/4`, reading `nproc` and
`grep -c ^processor /proc/cpuinfo` and comparing the whole line. Both are
asserted because both were wrong together: they agreed at 1 before, so a fix
that moved only one would be reading something other than the machine.
`--cpus 1` → `1/1`, unchanged. `machine create --cpus 2` + `start` + `exec`
reports 2.

`--memory` was never verified on this path either, and could not be checked at
512M — that is also the built-in default, so a guest ignoring the flag reports
the expected number. At `--memory 1024M` the guest sees over 800 MiB.

Checkpointing a live 2-vCPU guest produces a frame whose vCPU section is 768
bytes: two 384-byte records, remainder zero.

## Not verified live, and why

The **HVF restore** half is covered by unit tests and by the CPU-count refusal,
but was not driven end-to-end on this host. `machine fork` and `machine restore`
are Firecracker-shaped verbs — `restore` refuses an HVF checkpoint with "does not
carry a Firecracker machine state" — and the HVF frame is consumed by the
warm-claim path instead. That path would not populate a standby here: every
`MVM_RESIDENCY=warm` launch reported `launch_mode=cold` with `claim_ms=0.0`, and
`MVM_HVF_WARM_REQUIRE_CLAIM=1` reported no compatible parent. The pool is filled
by `warm_to_target` in the CLI, above the supervisor, and it already carries
`vcpus` in its spec — so this is host-side policy rather than anything the VMM
decides. Worth someone getting a standby to spawn and confirming a multi-vCPU
claim before this is relied on for warm-fork.

Witnesses: `the_booted_tree_describes_exactly_the_cpus_the_vmm_creates`,
`psci_answers_for_exactly_the_cpus_the_tree_describes`,
`a_requested_cpu_count_is_honoured_rather_than_reduced`,
`cpu_on_releases_the_named_cpu_with_the_values_it_carried`,
`cpu_on_refuses_a_cpu_this_machine_does_not_have`,
`a_repeated_cpu_on_is_refused_rather_than_restarting_the_cpu`,
`shutdown_releases_a_cpu_the_guest_never_onlined`,
`concurrent_cpu_ons_release_each_cpu_independently`,
`every_vcpu_survives_the_frame_in_cpu_order`,
`a_partial_vcpu_record_is_refused_rather_than_truncated`,
`a_summed_clock_charges_every_vcpu_of_the_machine`, and the two launch-suite
scenarios "--cpus is honoured on a real boot" and "--memory is honoured on a
real boot" (`MIN_SCENARIOS` raised to 16).
