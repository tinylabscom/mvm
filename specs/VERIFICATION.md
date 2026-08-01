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
| `included_top_level_is_a_superset_of_the_nix_filter_allowlist` | Remove `"nix"` from `INCLUDED_TOP_LEVEL` while `workspace-filter.nix` still admits it, so a `nix/` change would go unhashed and boot a stale image | yes |
| `excluded_basenames_are_a_subset_of_the_nix_workspace_filter` | Add `"crates"` to `EXCLUDED_BASENAMES`, pruning a tree the nix filter keeps | yes |

The two build-fingerprint rows are a matched pair, and their bindings point in
opposite directions because the nix filter admits by top-level entry and prunes
by basename. Both were planted separately; each fired only its own gate.

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

### Mutation-tested witnesses: what the first full run found

`check-mutation-witnesses --run` breaks each claim-surface file on purpose
and asks whether any witness notices. Its nightly lane ran
`continue-on-error` until a baseline covered the whole surface. Producing
that baseline is recorded here, because most of what it found was not
surviving mutants.

The whole surface now measures — **1221 mutants** — which it had never
done before, and **the lane is armed**: `continue-on-error` is gone, so a
witness that stops detecting its own property fails the nightly.

Every survivor is either closed by a test or carried in
`xtask/mutation-witness-baseline.json` with the mechanism that makes it
uncatchable here. Ninety-one entries, and none of them says "not yet
triaged": the generator that wrote them leaves anything without a stated
mechanism *out*, so an untriaged survivor fails the gate rather than being
suppressed by omission. Each entry comes from the newest **completed** run
of that file — completion checked on `end_time`, because cargo-mutants
writes `outcomes.json` incrementally and a run 39 of 50 through reports
`missed: 0` and looks clean.

| Mechanism | Entries |
| --- | --- |
| libkrun VM lifecycle over a live supervisor process | 31 |
| Firecracker snapshot driver I/O + vsock readiness probes | 17 |
| witnessed only by a nix-gated integration test the lane does not run | 12 |
| not compiled by the lane's feature set (`pure-mkfs`) | 11 |
| OCI registry / blob-cache I/O | 6 |
| equivalent: the field's value equals the derived `Default` | 5 |
| needs a live VM state dir plus a controlled pid | 3 |
| singletons (binary entrypoint, fail-closed constant, two provable equivalences, two untestable inputs) | 6 |

These are **accepted rather than scoped out** on purpose. Scoping would
stop the lane measuring those files at all; accepting keeps the ratchet
live, so a *new* hole in any of them still fails the nightly. Scoping is
reserved for the case where the non-claim noise would drown the ledger —
164 and 78 entries would, 40 and 14 do not. The residual coverage debt is
tracked in #2033.

**Four of eight packages could not be measured at all.** The lane runs
`cargo mutants -p <package> --file <path>` in a fresh copy of the tree, so
a package whose own suite does not pass *on its own* never reaches a
mutant. Three packages were in that state, each green under `--workspace`
and red alone:

| Package | Why the package-scoped suite failed | Surface files |
| --- | --- | --- |
| `mvm-sdk` | uses `mvm-core`'s `TestEnv` without enabling `test-support`; the feature arrived only through workspace-wide feature unification, so the crate's tests did not compile | 1 |
| `mvm-cli` | 42 tests drive the `mvmctl` binary, which belongs to the root package — `CARGO_BIN_EXE_mvmctl` is only set for tests in the package declaring the bin | 4 |
| `mvm-runtime` | a test spawned the real `mvm-substitution-endpoint`, an `mvm-hostd` binary; it passed only when another package's build had populated the shared `target/` | 3 |

Eight of the twenty-six surface files — claims 1, 3, 10, 11, 14 and 15 —
were therefore unmeasured while the lane reported no new misses.

**And two of them read as clean.** A file whose baseline never runs
reports `total_mutants: 0, missed: 0, caught: 0`, which is what a
fully-covered file reports. `ensure_mutants_actually_ran` was written for
exactly this, but it enumerated the one baseline verdict it had seen —
`Failure` — and `crates/mvm-build/src/app_deps_gate.rs` came back
`Timeout`. cargo-mutants found 33 mutants there and tested none of them.

The check now requires the baseline verdict to *be* `Success` rather than
to not be one of a known list, and requires `total_mutants` to be nonzero.
A verdict this code has never seen is not evidence that anything ran.

| Guard | Planted defect | Reported |
| --- | --- | --- |
| `ensure_mutants_actually_ran` | `outcomes.json` with a `Baseline`/`Timeout` verdict and zero counts (verbatim from the observed run) | yes |
| `ensure_mutants_actually_ran` | a baseline verdict string the code has never seen | yes |
| `ensure_mutants_actually_ran` | a passing baseline with `total_mutants: 0` | yes |

**A witness can also resolve to a file that is not its subject.** The
surface maps each `fn:` witness to its declaring file, assuming the file
is the enforcement code the witness guards. That holds for a cohesive
module and fails for a large multi-purpose binary.
`crates/mvm-build/src/bin/mvm-host-vm-init.rs` is 4476 lines and sits on
claim 2's surface only because the witness test
`virtiofs_mount_flags_keep_workspace_read_only` is declared in it. That
witness guards one function, which is fully caught; the file's other 164
surviving mutants are vsock framing, nix-store seeding and ext4 probing,
none of which claim 2 asserts.

Narrowing a claim's surface is a weakening move that reads as routine in
a diff, so `SurfaceScope` makes it expensive rather than convenient: a
scope cannot be produced by resolution, only added by hand to the
committed baseline; `why` and `excluded_tracked_by` are both mandatory
and enforced exactly as an accepted miss's reason is; and a re-pin carries
scopes forward so maintenance cannot silently widen one back out. The 164
excluded mutants are filed as #2006 with the measurement attached.

**Most surviving mutants were real holes.** Each of the tests below was
verified by planting its mutant by hand and confirming the new test fails,
then reverting. Two categories of genuine non-hole turned up, both
recorded as accepted misses naming their mechanism rather than asserted to
be equivalent: a read-buffer size (`64 * 1024` versus `64 + 1024`, same
digest either way) and the feature-gated mutants above.

| Claim | File | Survivors | Sharpest one |
| --- | --- | --- | --- |
| 10 | `policy/network_policy.rs` | 4 | `is_banned_ssh_port` pinned to `false` — the crate asserted only the negative direction, so disarming the SSH ban failed nothing |
| 12 | `protocol/broker.rs` | 4 | `Display` blanked and `as_str` pinned to a constant on identifiers that are rendered into audit entries |
| 13 | `protocol/vm_backend.rs` | 6 | `LayerCoverage::is_microvm` with `&&` weakened to `||` — fail-open, since it gates the Tier 3 shared-kernel banner |
| 9 | `plan/bundle.rs` | 5 | four `e.kind() == NotFound` guards pinned to `true`, merging "absent" with "unreadable" in resolve, remove and list |
| 12 | `broker/registry.rs` | 1 | `Registry::is_empty` pinned to `true`, read by the broker's startup readiness gate |

The four `network_policy` entries had been sitting in `accepted_misses`
recorded as untriaged. They were holes, so they are closed rather than
explained.

**A mutant in code the run does not compile cannot be killed by
anything.** cargo-mutants generates mutants by parsing source, and `syn`
does not evaluate `cfg`. A function behind a feature the mutation build
does not enable is therefore mutated, never compiled, and reported as a
survivor — indistinguishable from a real hole, and unkillable by any test.

Measured on `overlay_mode_of`, which copies a staged file's permission
bits into the runtime overlay and lives behind the non-default
`pure-mkfs`:

| Build | `& 0o7777` → `| 0o7777` |
| --- | --- |
| default features — what the lane runs | survives, against 720 passing tests |
| `--features pure-mkfs` | caught |

The mutant is not cosmetic: it makes every file in the overlay
world-writable and setuid. The test that catches it exists and passes;
the lane simply does not build the code. Until the run compiles the
features its surface needs, these are recorded as accepted misses naming
that mechanism, which is falsifiable — enable the feature and they become
catchable.

**One measurement was of the wrong thing.** `mvm-build`'s baseline timed
out because `runtime_overlay_build.rs` shells out to a real `nix build`.
The lane does not install `nix`, so those tests skip there — the timeout
was an artifact of the host used to produce the baseline. The baseline is
therefore produced with `nix` off `PATH`, matching the lane. The
consequence is recorded rather than hidden: on the lane, no nix-gated
integration test participates, so a mutant only those tests would catch
survives.

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
