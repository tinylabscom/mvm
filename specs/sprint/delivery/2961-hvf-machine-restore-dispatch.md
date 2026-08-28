# 2961 — route the machine fork verbs at the backend that captured the checkpoint

`mvmctl machine fork`, `restore`, and `warm-restore` all called
`fork_vm_full_arm_fc` directly, so an HVF checkpoint entered the Firecracker
arm no matter which VMM produced it. The HVF arm existed, was correct, and was
unreachable from any verb a user types. The `vm checkpoint fork` surface next
door already dispatched on the recorded machine-state blob; the `machine` verbs
now call the same dispatcher.

The two guards that made the old path unsatisfiable are gone with it. The
Firecracker arm refuses a live parent because a restored child inherits the
parent's TAP name and MAC out of the snapshot, and `machine fork` refuses a
stopped one — so an HVF user could satisfy neither. `ForkParentLiveness` makes
that a per-backend decision instead of a constant: `MustBeStopped` is the
builder default and every existing caller keeps it, and HVF passes
`MayBeRunning` because an HVF guest has no NIC at all and cannot collide on an
address it does not have.

## The restore had never resumed a second CPU

Capture was proven before this; restore had only unit coverage, which is the
half that cannot fail quietly. A frame carries the boot CPU and each secondary,
but Hypervisor.framework will only accept a vCPU's registers from the thread
that created it, and those threads do not exist when the frame is parsed. The
bring-up now runs against two barriers: the primary restores the process-global
GIC and its own state, releases the start gate so every secondary installs its
CPU-local state on its own thread, collects one report per secondary, and only
then releases the run gate. A secondary that cannot restore reports the failure
instead of entering the guest, and the machine stops rather than running a CPU
short of the tree the guest believes it has.

Restoring a CPU also turned out to need more than the fifteen registers the
frame carried: the SIMD/FP file, `FPCR`/`FPSR`, the pointer-authentication
keys, `SP_EL0`, `TPIDR*`, `CPACR_EL1`, and the GIC CPU-interface registers, plus
the opaque GIC distributor and redistributor blob as its own section. A resumed
kernel uses all of them. `hv_vcpu_set_simd_fp_reg` takes its 128-bit vector by
value, which stable Rust cannot express, so a four-instruction leaf shim loads
`q0` and tail-calls the framework entry point.

## A resumed child is no longer asked to rename itself

Wiring the fork to the HVF arm exposed the next failure immediately: every fork
died with `sethostname(...) failed: Operation not permitted`. A guest takes its
hostname from `mvm.hostname=` on the kernel cmdline, applied by PID 1 before it
drops to the unprivileged agent identity. A restore skips that boot entirely, so
the only path that can set a hostname never runs, and the agent that survives
into the child holds neither `CAP_SYS_ADMIN` nor any way to regain it.

There is no unprivileged way to rename a resumed guest, and adding a privileged
helper to buy a cosmetic name is the wrong trade. Both restore paths now build
their signal with `VsockPostRestoreSignal::for_resumed_child`, which carries no
hostname — matching what the Firecracker fork path already did. The child keeps
the parent's name; its identity is its own admitted plan, nonce, and verb grant,
none of which the guest chooses. The warm-claim path in `VmmDriver` had the same
unsatisfiable request and is fixed with it, where it had been latent only
because the warm pool never populated.

## What was verified live

macOS 26.5.2 on Apple Silicon, against a real 2-vCPU HVF guest, with the shipped
code and no diagnostic patches:

- A live 2-vCPU parent forks and the child comes up. The child's console log
  carries no kernel boot output where the parent's carries the full log, so the
  child resumed the captured memory rather than cold-booting.
- The child's effective supervisor config records `vcpus: 2` with both
  `restore_ram` and `restore_frame` set.
- A counter-stamped probe running inside the parent is itself restored and keeps
  running in the child. Capturing the child's live RAM afterwards shows 102
  samples past the fork point, every well-formed one reporting `nproc=2`,
  `grep -c ^processor /proc/cpuinfo` of 2, and `online=0-1`, with no RCU stall or
  lockup warning on the child console.

The probe is read out of the child's own guest RAM because a forked child gets a
workload-tier verb grant that excludes `exec` — correctly, so the CPU count had
to come from the guest rather than from a shell the guest is not allowed to run.

## Not covered

The warm pool still does not populate, so a warm *claim* of a multi-vCPU parent
is unexercised; `machine fork` reaches the same restore code and is what proved
it. The parent is briefly unreachable while it is paused for capture and
recovers on its own. `nextest` carries one pre-existing failure unrelated to this
branch — `dev_vm_connects_via_libkrun_per_port_socket` asserts no socket-path
shortening and so fails under macOS's long default `TMPDIR`, passing under
`TMPDIR=/tmp`; this branch does not touch `crates/mvm-vmm/src/host/`.

CI cannot check any of the live work: the microVM and macOS lanes skip on pull
requests.
