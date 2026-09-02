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
| `check-build-egress-callers` | Add a `NetworkPolicy::trusted_build_egress()` call to `workload_runner/runner.rs` — the shape of a future workload path reaching the unrestricted-egress constructor and turning off claim 10's default-deny | yes — named the file and line, refused |
| `check-build-egress-callers` (vacuity) | Point the gate at a tree with no allow-listed call site, i.e. the state it would reach if the constructor were renamed and the gate silently stopped checking anything | yes — refused rather than passing empty |
| `check-verified-kernel-reads` | Add a boot path that takes `cached_kernel_path` and accepts it on `is_file()` — the shape of the Firecracker arm and the kernel-less-image fallback that both booted an unverified kernel | yes — named the file and line, refused |
| `check-verified-kernel-reads` (vacuity) | Point the gate at a tree where no file pairs the location helper with `resolve_kernel`, i.e. the state it would reach if either were renamed | yes — refused rather than passing empty |
| `check-conformance` (R1) | Edit `CONFORMANCE.md` so it disagrees with `model/claims.toml` | yes |
| `check-honesty` (R2) | Add "MVM-SEC-07 proves cargo deps are audited" to `README.md` | yes |
| `meta` (R3) | Register `MVM-SEC-99` with no scenario, or remove a scenario's ID tag | yes |
| `check-deferrals` (R4) | Add `// TODO example` to a production source file outside an exemption | yes |
| `check-abi-layout` | Add a `#[repr(C)]` struct with no `size_of`/`align_of` assertion | yes |
| `check-abi-layout` | Mention `size_of::<T>()` in a comment instead of asserting it | yes |
| `check-claim-catalog` | Name a witness in the ADR-001 ledger that `model/claims.toml` does not list | yes |
| `check-workflow-paths` | Point a fuzz step's `working-directory` at `crates/mvm-oci` (the pre-consolidation path that made the fuzz lane dead for ten nightlies) | yes |
| `check-mvm-host-binaries-sync` | Drop `--bin mvm-builderd` from the builder-VM cross-compile step, reproducing the "path does not exist" image-build failure | yes |
| `check-mutation-witnesses` (shard matrix) | Remove the `mvm-cli` shard from `security.yml`'s mutation matrix, so that package would never be mutated while every shard stayed green | yes — `package mvm-cli is on the mutation surface but has no shard` |
| `check-claim-witness-freshness` | Change `security.yml`'s cron to hourly so its real last scheduled run exceeds the allowance, or feed the classifier a completed `cancelled` run; reports the stale or unhealthy scheduled evidence and names every claim it backs | yes |
| `a_modified_kernel_is_rejected_and_both_files_evicted` etc. | Make `verify_cached_kernel` return the path unchecked, i.e. restore the path-trust `resolve_kernel` shipped with — a cached kernel served because the file exists | yes — 3 of the read-path tests fired |
| `resolve_cached_when_present_and_pinned` | The pre-existing version of this test staged a kernel with **no** pin and asserted a cache hit, encoding "existence is evidence". It had to be rewritten for the new contract, which is the clearest single sign of what changed | n/a — the old test was the defect |
| `no_std_verifier_accepts_the_same_corpus_the_host_verifier_does` | Drop `skip_serializing_if = "Option::is_none"` from the `no_std` mirror's `bundle_id`, so it reconstructs different signed bytes than the host emitted. The two implementations now disagree about the wire form of an *absent* field | yes — `SignatureInvalid { line: 0 }` over the shared corpus |
| `frozen_chain_matches_what_the_signer_produces_and_the_host_verifier_accepts` | Change what the host signer emits without regenerating the corpus, i.e. the case where every chain already written becomes unverifiable | yes — committed corpus no longer matches the signer |
| `ProtocolDigest` compile-fail doctest | Add `impl From<ProtocolDigest> for StorageAddress`, giving σ and κ the bridge the doctest asserts cannot exist. The first version of this test was **vacuous** — it used a bare `let kappa: StorageAddress = sigma;`, which never compiles whatever impls exist, so it passed with the bridge present; rewritten to `sigma.into()`, which compiles exactly when a bridge exists | yes — doctest FAILED once the bridge existed |
| `a_non_collision_resistant_digest_cannot_become_an_address` | Feed MD5 (32 hex), CRC32C (8), CRC64 (16) and a right-width non-hex string to both σ and κ constructors | yes — each refused |
| `ir_hash_vectors_are_frozen` | Hash the canonical form with a trailing newline appended, so every address moves consistently. All four existing `ir::hash` tests still passed — stable-for-identical, key-order-independent, different-values-differ, 64-hex — because each is relational and none pins a value | yes — `ir_hash/empty-object: address moved` |
| `base_plan_address_is_frozen` / `stored_plan_id_is_excluded_from_its_own_address` | Change `compute_plan_id` to strip a field name that does not exist, so the stored `plan_id` is folded into its own digest and the address stops being a content-address | yes — `plan_id/differing-stored-id-addresses-the-same: address moved` |
| `check-claim-catalog` (witness kinds) | Delete `ci:seccomp-functional` from **both** `model/claims.toml` and the ADR-001 ledger row for claim 1 — the way a witness would actually be retired. Before this gate the run reported `clean (16 claims, 48 witnesses verified)`: claim 1 had silently lost its only CI evidence with a green board | yes — `claim MVM-SEC-01: declares witness kind \`ci\` but has no \`ci:\` witness` |
| `check-claim-catalog` (witness kinds, converse) | Add a `ci:` witness to `MVM-SEC-08`, which declares `fn` only, leaving the new evidence unpinned and droppable again unnoticed | yes — `has a \`ci:\` witness that \`witness_kinds\` does not declare` |
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

Two claims are witnessed in part by a CI lane — a runtime boundary test, a fuzz run,
a dependency audit. Mutation testing cannot reach them: there is no Rust
function body whose mutation exercises a workflow job. They were planted
against by hand instead.

| Claim | Witness | Planted defect | Fired |
| --- | --- | --- | --- |
| MVM-SEC-05 | `ci:fuzz` | Unchecked `s[..8]` slice behind a `deserialize_with` on `GuestRequest::FsRead::path` | yes — libFuzzer `deadly signal` inside a 90s budget |
| MVM-SEC-07 | `ci:cargo-deny` | Remove `MIT` from `deny.toml`'s licence allow-list | yes — `rejected: license is not explicitly allowed` |
| MVM-SEC-04 | `ci:guest-agent-runtime-boundary` | Remove the runtime profile or grant check before dispatching a DevOnly request | yes — the grant and handler conformance tests fail |

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

**MVM-SEC-04 — the runtime boundary is the witness.** The universal agent
contains the DevOnly handlers in every build, but a production-safe run still
cannot reach them: request classification, the runtime profile, and the
launch-provisioned signed grant must all authorize the call. The unit suite
enumerates the DevOnly request set, and the CI lane runs those tests against
the same artifact shape used by both tiers.

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

The lane is **sharded per package**, because it has to be: the whole
surface takes ~6.9 hours end to end and a GitHub-hosted job is killed at
six. One job could not reliably finish, so it would go red nightly for a
reason unrelated to any claim and be ignored — the same failure this lane
exists to prevent, arrived at from the other side. That makes the matrix a
second place the surface is written down, so `check-mutation-witnesses`
pins it against the baseline on every PR; the row above records the
planted defect.

Per package was not enough for long. On 2026-08-15 the `mvm-hostd` shard
died on the platform cap having reached six of its ten files in 3h17m, and
because the cap kills the runner rather than the job, the only trace was
`The runner has received a shutdown signal` — naming no package, no file
and no claim. A package may therefore be split further, spelled
`mvm-hostd/1of2` in the matrix and passed through the same `--package`
flag. Files are ordered by path and then packed onto the emptiest shard
heaviest-first, so membership is a property of the committed surface
rather than of resolution order. The gate
checks the split is total: a missing index, a repeated one, disagreeing
totals, or a bare entry alongside sharded ones all fail, because each
leaves files nothing mutates while every remaining shard stays green.

The job also carries `timeout-minutes: 330`, under the cap, so a shard
that outgrows its budget is stopped as this job rather than as the runner,
and uploads its partial cargo-mutants output either way.

**A shard stopped that way does not report as failed.** Actions gives a
job killed by `timeout-minutes` the conclusion `cancelled`, not
`timed_out`, so `security-lane-watch.yml` counts `cancelled` as failing and
skips only when the run as a whole was cancelled. Before it did, a shard
that never finished contributed no failing job — and on a night where it
was the only casualty, the empty failing set read as green and closed the
tracking issue.

**File count is not cost, and adding shards did not make it one.** The
two-shard split measured the gap on 2026-08-16: `1of2` finished five files
in 100 minutes while `2of2` drew `plan_admission` (93 mutants),
`supervisor/audit_file` (107) and `supervisor/network/stages` (108), spent
its full 330 and never reached its fifth file. The response was to cut
`mvm-hostd` four ways, on the correct diagnosis but the wrong remedy: a
cost-blind split of an unequal surface stays unequal at any width. It
recurred on 2026-08-21, when `2of4` and `4of4` were both killed at 330
minutes — round-robin had put the four most expensive files in the tree on
those two shards — while `3of4` finished its three cheapest in 24.

Assignment is therefore by cost, not by stride: shards are packed
longest-first, heaviest file onto the lightest shard. Cost is stood in for
by source size, which needs nothing recorded or maintained beside the
surface and tracks mutant count closely enough to pack with. Replaying the
2026-08-21 per-file measurements through it splits that same surface
188/189/191/193 minutes where round-robin gave 90/323/24/324 — 1.01x the
ideal even split against 1.70x. `xtask`'s
`cost_packing_balances_a_surface_that_round_robin_left_lopsided` pins the
ratio against those measurements, and fails on the old assignment.

`mvm-hostd` is cut six ways on top of that, putting the worst shard at
~181 measured minutes, 55% of the budget. The headroom is deliberate: two
of the per-file costs behind it are lower bounds, taken from shards killed
part-way through a file.

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
