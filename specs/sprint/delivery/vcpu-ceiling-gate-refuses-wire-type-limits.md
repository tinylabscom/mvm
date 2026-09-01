# A gate for the vCPU ceiling, because the mistake was made twice

Firecracker and libkrun each declared `max_vcpus: Some(u32::from(u8::MAX))`,
independently, for the same reason: the vCPU count is a byte on the wire, so
255 is the largest value the call can carry. True of both, and the limit of
neither — `/machine-config` refuses anything above 32, and libkrun's
`krun_set_vm_config` accepts all 255 and then aborts inside `krun_start_enter`
at 65. The clamp above the backends faithfully granted a count that would not
boot, so `--cpus 9999` failed on both while succeeding on HVF, whose ceiling is
asked of the host. Both were fixed under #3051 and #3065.

Two independent authors reaching the same wrong conclusion is the argument for
a gate rather than a third careful review. Nothing stopped a fourth backend
from declaring the same thing tomorrow, and the failure is invisible until
someone boots a guest with an absurd `--cpus` on that specific backend — which
is how both of these survived: the number was wrong the whole time, and the
tests that existed asserted it.

`xtask check-vcpu-ceilings` refuses a `max_vcpus` declaration derived from an
integer type's `MAX`. It is registered in `check-all`, which `ci.yml` runs on
every PR.

## What it does and does not say

The rule is narrow on purpose. *How* a backend obtains a real ceiling is its
own business: a measured constant (`Some(MAX_VCPUS)`) and a host query
(`hvf_max_vcpus()`) are both fine and the gate prefers neither. What it refuses
is the one derivation that cannot be right, because the width of a field says
nothing about what the VMM behind it accepts.

It matches any width and both signednesses rather than `u8::MAX` alone: the
reasoning that produced the bug — "the field is N bits wide, so its ceiling is
what N bits hold" — is not specific to a byte, and a backend whose count
travels as a `u16` would repeat it verbatim.

Test code is scanned too, since a declaration in a fixture binds as much as one
in a driver — but note what that does *not* buy. `mvm-client`'s clamp test read
`assert_eq!(..., Some(u32::from(u8::MAX)))`, pinning the defect as the
contract, and this gate walks straight past it: that is an `assert_eq!`
argument, not a `max_vcpus` declaration. Reaching it would mean flagging a
wire-type `MAX` anywhere near vCPU text, which immediately hits honest uses —
the libkrun driver's
`u8::try_from(spec.vcpus.clamp(1, MAX_VCPUS)).unwrap_or(u8::MAX)` is an
infallible-conversion fallback on an already-clamped value, on a line that says
`vcpus`. A gate that cried wolf there would be switched off. So the rule stays
narrow, and the wrong assertion stays CI's job — which is how that one was
actually caught: it went red the moment the ceiling was corrected.

Comments and strings are blanked first through the shared
`xtask::rust_source` scanner rather than a second copy of that handling — the
gate's own explanation says `u8::MAX` several times, and a scanner that read
comments as code would fail the gate on its own prose.

A declaration floor (`MINIMUM_DECLARATIONS`) is the other half: a gate that
passes because every ceiling has been deleted has stopped noticing that
ceilings used to be declared. Same failure `check-backend-resource-controls`
guards with its matrix floor.

## Witness

Both halves were checked by hand against the real code rather than inferred:
reintroducing the declaration defect in `fc.rs` fails the gate, and
reintroducing the assertion defect in `mvm-client` does *not* — which is the
boundary described above, confirmed rather than assumed.

The gate's unit tests cover the spellings it must catch (`Some(u8::MAX)`,
`Some(u32::from(u8::MAX))`, `Some(u16::MAX)`, `Some(std::u8::MAX)`), the ones
it must not (`Some(MAX_VCPUS)`, a host query, a bare literal, `None`), the
near-misses that would make it noisy (`MAX_VCPUS` and `FALLBACK_u8::MAX` end in
`MAX` but name no primitive), and that it passes on the tree that ships it.

Checked against the real thing rather than only its fixtures: reintroducing the
original defect in `fc.rs` fails the gate with the file, the line, the spelling,
and what to do instead —

```
crates/mvm-backends/src/driver/fc.rs:666: `max_vcpus` is derived from `u8::MAX`
— that is the width of the wire field, not a count the VMM boots. Declare what
the backend will actually start (a measured constant, or a value queried from
the host/library) so the clamp above the backends grants a request that runs.
```

## What it does not cover

qemu declares no ceiling at all, so this gate has nothing to check there and
the reporting clamp stays silent on that backend. Measured while writing this:
QEMU reports its own limit (`Invalid SMP CPUs 256. The max CPUs supported by
machine 'pc-i440fx-noble-v2' is 255`), and 255 is exactly what the qemu driver
already clamps to — so x86_64 is correct today by coincidence rather than by
derivation. The number is machine-type and version dependent, so a constant
would be wrong and a probe means spawning QEMU from `capabilities()`. Left
alone: qemu is a dev/test backend that carries no workload, is never
auto-selected, and does not fail — the residue is a missing warning, not a
broken launch.
