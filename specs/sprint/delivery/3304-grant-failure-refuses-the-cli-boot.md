# A grant that fails to apply refuses the CLI boot (#3304)

The persistent-machine start path (`start_persistent_oci_machine`, which is
what `mvmctl machine start` boots through) applied a VM's grants after the
backend start and treated a failure as a read-back problem: it logged a warning,
substituted `EnforcedGrants::all_declared()`, recorded that per VM, and signed
it into `plan.grants_enforced`. The VM kept running. The admitted-start tail in
`mvm-hostd` has always done the opposite for the same failure — stop the VM,
record `plan.failed` at the `grants` stage, return the error.

`Declared` is a legitimate answer from a backend that applied the grants on a
host with no mechanism for a dimension. It is not a legitimate answer for "the
backend errored", and on the chain the two were indistinguishable.

## What changed

- `mvm_hostd::plan_admission::apply_admitted_grants_or_undo_launch` is the one
  place that applies an admitted plan's grants to a just-started VM and undoes
  the launch on failure. `start_admitted` and the CLI path both call it, so the
  posture cannot diverge again.
- `mvm_client::start_prepared` returns a `StartedVm` carrying the backend object
  that performed the start. The grants are applied to that object. The old
  `enforced_grants_after_start` rebuilt a backend from the hypervisor name — a
  different instance from the one that started the VM, and for a backend that
  keeps per-run state in memory (the wasm backend does) one with nothing to
  read back.
- `report_enforced_grants` now returns `Result` and the start path propagates
  it. Volume leases are committed only after the grants apply, so a refused
  boot releases them.
- The mock backend gained `with_failing_apply_grants()`; its default answer is
  unchanged (`all_declared`, as a host with no mechanism reports).

## Witnesses

- `a_grant_that_fails_to_apply_refuses_the_cli_boot` (mvm-client,
  `test-support`): the CLI reporter against a mock whose `apply_grants` errors.
  The VM is stopped, the chain carries `plan.failed` naming `grants`, and there
  is no `plan.grants_enforced` entry and no per-VM tier. Fails on the previous
  code, which wrote the entry.
- `a_host_without_a_mechanism_boots_and_records_declared` (mvm-client,
  `test-support`): the other side of the line. A successful `Declared` answer
  keeps the VM running and is recorded.
- `a_grant_that_cannot_be_applied_undoes_the_launch` (mvm-hostd): the same
  refusal through `admit_and_start`, which had no test for this arm.

Both refusal witnesses are cited under claim 18 in ADR-001 and
`model/claims.toml`. The `dormant-controls.toml` entry that pinned
`enforced_grants_after_start` as live now pins the shared helper.

## Not done here

The CLI start path still differs from `start_admitted` in the host-budget
charge and the other post-start steps; collapsing the two stacks is #3303.
