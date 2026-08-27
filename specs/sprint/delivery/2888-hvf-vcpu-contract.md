# HVF refuses unsupported multi-vCPU launches

Issue #2888 showed that a workload could request multiple vCPUs from the HVF
backend, receive a successful launch, and still observe only one processor in
the guest. The resource count reached `VmmSpec`, but the backend is single-vCPU
by construction: its supervisor, FDT, PSCI handling, snapshots, and run loop do
not implement SMP.

The HVF driver now validates the requested count before writing supervisor
state or spawning a process. Exactly one vCPU remains supported. Zero or more
than one returns a clear error that names both the backend limit and the
requested count. Other backends keep their existing multi-vCPU behavior.

The README's backend-neutral examples now request one vCPU and state the HVF
limit explicitly. This removes the false promise while leaving room for a
future complete SMP implementation that includes secondary-vCPU lifecycle,
PSCI `CPU_ON`, FDT CPU nodes, GIC redistributors, snapshot state, and quota
accounting together.

Validation:

- a focused HVF driver regression proves a two-vCPU spec is refused with the
  exact diagnostic;
- the complete `mvm-backends` test suite;
- workspace check and Clippy gates before submission;
- the required PR and merge-group checks remain the merge gate.
