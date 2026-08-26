# The block-volume scenarios failed instead of skipping, and ran nowhere

Backing: shipped-source
Validation: cargo nextest run -p mvm-conformance --lib

Two scenarios in `s26_volumes/volume_lifecycle.feature` — a writable volume
persisting bytes across restart, and a read-only attachment refusing a guest
write — begin with `Given a cached live workload kernel`. That step read
`MVM_BDD_WORKLOAD_KERNEL` with `.expect(...)`.

The variable is named in no Justfile recipe, no CI lane and no document. Its
only occurrences in the entire tree were the three lines of the step that read
it. So on a host with `/dev/kvm` the scenarios did not skip — they *failed*,
with `MVM_BDD_WORKLOAD_KERNEL must name the live workload kernel`, and on a host
without one they never ran at all.

They have therefore never passed anywhere.

## Two things wrong, not one

**A missing fixture failed rather than skipped.** The harness already models
this: `RuntimeCaps` + `ScenarioGate` turn an absent capability into a clean skip
that lands in the run's skip tally. A bare `.expect` in a step bypasses that and
reports a missing operator input as a red test — indistinguishable, in a log,
from a broken volume path. This is the same defect the `@bundle` fixture had,
in the opposite direction: that one skipped silently and hid a real gap, this
one failed loudly and invented one.

**The fixture had no default.** The step copies the kernel to
`<isolated home>/cache/builder-vm/<arch>/kernels/workload/vmlinux` — the exact
path `mvmctl` writes it to under the real home. So the file it demands an
operator name by hand is, on any host that has built one, already sitting at a
known location. `workload_kernel_path` now prefers `MVM_BDD_WORKLOAD_KERNEL` and
falls back to the host's builder-VM cache. That default is what makes the lane
runnable rather than merely honest.

## The gate correctly objected

`check-test-home-isolation` flagged the `default_mvm_cache_dir` call: reading
the shared cache from a test is how an isolated run gets a real artifact copied
in behind its back and passes for the wrong reason.

Here the seed *is* the intent, and it cannot mask an absence assertion — these
scenarios assert about volume bytes and write refusal, never about whether a
kernel is cached. Declared in `SEED_SITES` with that reasoning rather than
worked around.

## Evidence

`workload_kernel_scenario_skips_without_a_kernel` asserts both directions:
skipped without a kernel, run with one. 73 conformance lib tests pass; all 61
`xtask` gates green.

Adding the capability field made the compiler reject five `RuntimeCaps`
literals in the existing tests — the exhaustive-init check doing exactly its
job, and the reason this file lists the field on every one rather than
defaulting it.
