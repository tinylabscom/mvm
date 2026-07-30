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

## What this suite does not establish

Anything about a dependency. A library imported here is gated in its own
repository; restating its guarantees would give a claim two sources, which is
what R1 forbids. What may be claimed here is what is built here.
