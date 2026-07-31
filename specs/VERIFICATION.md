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
| `check-claim-witness-freshness` | Change `security.yml`'s cron to hourly so its real last-run age exceeds the allowance; reported `security.yml last ran 14h ago (schedule allows 3h)` naming all 8 claims it backs | yes |
| `cargo-fuzz crates still compile` | None planted — run against main it independently rediscovered both real defects (`fuzz_authed_path` E0308, `fuzz_build_image` unclosed delimiter) that the nightly took eleven days to surface | yes |

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

### CI-lane witnesses

Three claims are witnessed only by a CI lane — a symbol grep, a fuzz run,
a dependency audit. Mutation testing cannot reach them: there is no Rust
function body whose mutation exercises a workflow job. They were planted
against by hand instead.

| Claim | Witness | Planted defect | Fired |
| --- | --- | --- | --- |
| MVM-SEC-05 | `ci:fuzz` | Unchecked `s[..8]` slice behind a `deserialize_with` on `GuestRequest::FsRead::path` | yes — libFuzzer `deadly signal` inside a 90s budget |
| MVM-SEC-07 | `ci:cargo-deny` | Remove `MIT` from `deny.toml`'s licence allow-list | yes — `rejected: license is not explicitly allowed` |
| MVM-SEC-04 | `ci:prod-agent-runentry-contract` | Ungate `do_exec_streaming` so it compiles into a production build | no — see below |

**MVM-SEC-05.** The lane could not have fired at all until its
`working-directory` values were corrected — they pointed at crates the
consolidation renamed, so it died on a missing directory rather than on
anything it was meant to detect. With the paths fixed, a planted parser
panic is found inside the per-run budget. The seed corpus is what makes that fast — the
fuzzer starts from valid `GuestRequest` JSON rather than random bytes.

**MVM-SEC-07.** Removing an allowed licence is a deterministic stand-in
for a dependency arriving with a disallowed one; it exercises the same
rejection path without depending on a particular crate's licensing. Note
the lane also fired on a *real* defect during this work — duplicate
`curve25519-dalek` — which is stronger evidence than any plant.

**MVM-SEC-04 — the plant did not fire, and that is the correct
behaviour.** Ungating `do_exec_streaming` leaves it with no caller in a
production build, so it is dead-code-eliminated and no symbol appears.
The check measures *reachability*, not source presence. An unreachable
function is not a leak, so this is the property worth having; a faithful
plant needs a production-reachable call site.

What makes this witness trustworthy is not a hand-planted defect at all:
`scripts/check-prod-agent-no-exec.sh` carries **its own positive
control** — it builds a second time with `interactive` enabled and fails
if `do_exec` is *not* detectable there. That proves the detector works,
so the absence assertion cannot rot into a no-op against a renamed
symbol. It also carries a canary (`handle_run_entrypoint` must be
present) so a stripped symbol table cannot make the absence check
vacuously true. Both pass today.

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
