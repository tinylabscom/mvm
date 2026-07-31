# Verification

Which axis of the normative acceptance gate discharges which class of claim.
`AGENTS.md` and the conformance model are the source of truth; this file maps
rules onto the commands that enforce them and records the planted defects that
prove each gate can fail.

## The rules

| Rule | What it says | Enforced by |
| --- | --- | --- |
| R1 | The model is the single source. Every claim lives in `model/*.toml`, and `CONFORMANCE.md` is generated from it. | `cargo run -p xtask -- check-conformance` |
| R2 | Levels are load-bearing. A claim is `some-true`, `build`, or `open`, and the two registers are never blurred. | `cargo run -p xtask -- check-honesty` |
| R3 | A capability begins as a register row, then a scenario, then a witness. | `cargo test -p mvm-conformance --test meta` |
| R4 | Nothing is deferred. No deferral marker, no stub, no capability behind a flag that turns it off. | `cargo run -p xtask -- check-deferrals` |

## Falsifiability

A gate nobody has seen fail is indistinguishable from a gate that cannot. Each
row below records a defect that was planted to prove the gate fires.

| Gate | Planted defect | Reported |
| --- | --- | --- |
| `check-conformance` (R1) | Edit `CONFORMANCE.md` so it disagrees with `model/claims.toml` | yes |
| `check-honesty` (R2) | Add "MVM-SEC-07 proves cargo deps are audited" to `README.md` | yes |
| `meta` (R3) | Register `MVM-SEC-99` with no scenario, or remove a scenario's ID tag | yes |
| `check-deferrals` (R4) | Add `// TODO example` to a production source file outside an exemption | yes |
| `check-abi-layout` | Add a `#[repr(C)]` struct with no `size_of`/`align_of` assertion | yes |
| `check-abi-layout` | Mention `size_of::<T>()` in a comment instead of asserting it | yes |
| `check-claim-catalog` | Name a witness in the ADR-001 ledger that `model/claims.toml` does not list | yes |
| `check-workflow-paths` | Point a fuzz step's `working-directory` at `crates/mvm-oci` (the pre-consolidation path that made the fuzz lane dead for ten nightlies) | yes |
| `check-mvm-host-binaries-sync` | Drop `--bin mvm-builderd` from the builder-VM cross-compile step, reproducing the "path does not exist" image-build failure | yes |

The `meta` gate also catches the reverse direction: a scenario tagged with an
unregistered ID, or a scenario whose level tag disagrees with the register.

The layout contracts `check-abi-layout` requires were each planted against
too, since the gate only proves an assertion is present and the assertion is
what has to discriminate. A same-type field reorder is the case of interest:
it changes no types, so nothing but an offset assertion sees it.

| Contract | Planted defect | Reported |
| --- | --- | --- |
| `hv_vcpu_exit_exception_t` | Swap the `syndrome` and `virtual_address` `u64` fields | yes |
| `SockaddrVm` | Revert to the pre-6.0 `svm_zero: [u8; 4]` shape | yes |
| `DmTargetSpec` | Swap the `sector_start` and `length` `u64` fields | yes |

### Does device-mapper layout drift fail open?

Asked because `DmIoctl`/`DmTargetSpec` build the dm-verity table, and a
drift that produced a *working but unverified* device would make
MVM-SEC-03 silently void rather than loudly broken.

Measured directly against the kernel on Linux 6.8 rather than inferred:
a `dm_target_spec` was submitted to `DM_TABLE_LOAD` with `target_type`
displaced by 4 and by 8 bytes, the displacement a same-size field
reorder upstream of it would cause.

| Layout | `DM_TABLE_LOAD` |
| --- | --- |
| Correct | succeeds; device resumes with a live table |
| `target_type` shifted +4 | `EINVAL` |
| `target_type` shifted +8 | `EINVAL` |

**Fail-closed.** The kernel resolves the target by name string before any
target-specific parsing, so a displaced field yields a name that matches
no registered target and the load is rejected. The mechanism is
target-agnostic, so this holds for `verity` as it does for the `linear`
target used in the probe.

The layout contracts are therefore drift insurance that turns a confusing
runtime `EINVAL` into a build error — worth having, but MVM-SEC-03 was
not at risk. One residual case is not covered: a displacement that
happened to land a *different valid* target name at the kernel's read
offset would resolve. Nothing in the current struct makes that reachable,
and the offset contracts now prevent the displacement outright.

## What this suite does not establish

Anything about a dependency. A library imported here is gated in its own
repository; restating its guarantees would give a claim two sources, which is
what R1 forbids. What may be claimed here is what is built here.
