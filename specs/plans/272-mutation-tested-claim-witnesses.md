# Plan 272: Mutation-tested claim witnesses

**Status:** WS-1 (gate + surface pin) shipped. WS-2 (full-surface baseline)
unblocked — #1958 isolated the `--run` lane's state roots in the workflow;
the baseline itself is pending a nightly run. WS-3 (the four claims this gate cannot reach) folded in from
plan 274, whose WS3/WS4 are struck in favour of this plan.
**Owner:** mvm core.
**Depends on:** the claims ledger in `specs/adrs/001-microvm-security-posture.md`
(`<!-- claims-catalog:begin -->`) and `xtask check-claim-catalog`.

## Goal

`check-claim-catalog` proves a named witness *exists*. Nothing proves the
witness *bites*. A test can name the right symbol, exercise the happy path,
and pass forever while the property it supposedly ratifies is broken — the
claim stays green because the assertion never had the power to fail.

This plan closes that gap with mutation testing scoped to the claim surface:
deliberately break the enforcement code, then check that a claim witness
notices. A surviving mutant is a claim whose witness cannot detect its own
property being violated.

The scope is derived from the ledger, not hand-listed. Each `fn:` witness
resolves to the file that declares it; the union of those files is the
mutation surface. This repo keeps `#[cfg(test)] mod tests` in the same file
as the implementation, so resolving a witness lands on the enforcement code
it guards — no second list to drift out of sync with the ledger.

## Why not just run cargo-mutants over the workspace

Cost. A full-workspace run rebuilds and re-tests once per mutant across a
~4,350-test suite; there are thousands of mutants. Scoping to the claim
surface keeps the run affordable enough to be a real recurring gate instead
of an aspiration, and it targets the code where a vacuous test is most
expensive — the fifteen security claims.

## Design

Three modes, one gate:

| Invocation | Cost | Lane |
| --- | --- | --- |
| `check-mutation-witnesses` | milliseconds | every PR |
| `check-mutation-witnesses --run` | hours | nightly |
| `check-mutation-witnesses --write-baseline` | hours | manual, by a maintainer |

The cheap default mode is the part that runs on a PR. It resolves the
surface from the ledger and compares it against the surface committed in
`xtask/mutation-witness-baseline.json`. That makes two failure modes
reviewable in a diff:

- A claim's witnesses stop resolving to any mutable file — the claim has
  dropped out of mutation coverage entirely.
- The surface changed — a witness moved, was renamed, or a claim's anchor
  shifted to a different file. The diff shows exactly which claim moved.

Without the committed surface, a claim could silently leave the expensive
lane's scope and the nightly run would keep reporting success over a smaller
and smaller surface. Pinning it is what stops "the gate is green" from
drifting away from "the gate covers the claims".

`--run` additionally shells out to cargo-mutants once per surface file,
scoped with `-p <owning crate> --file <path>`, and ratchets the observed
missed mutants against `accepted_misses` in the baseline:

- A missed mutant not in the baseline fails the gate. That is a new hole.
- A baseline entry that is now caught is reported, not failed, with a note
  to shrink the baseline. Ratchet down, never silently up.

Mutant identity is `file` + description with `line:col` stripped
(`replace == with != in resolve_network_policy`), so unrelated edits above a
mutant in the same file do not invalidate the baseline. Two mutants that
differ only in position collapse to one identity; that is deliberate — it
keeps the baseline stable and a genuinely new hole still shows up as a new
description.

### What a "miss" means here

Each invocation is scoped `-p <owning crate> --file <path>`, so the tests
that get a chance to catch a mutant are the owning crate's own. A surviving
mutant therefore means *the crate that owns the invariant does not test it* —
not that nothing in the workspace would notice. A cross-crate test may well
catch it.

That is a deliberate trade. Running the full workspace suite per mutant is
roughly an order of magnitude more expensive and would put the lane out of
reach; and the narrower question is the more useful one, because a claim
whose enforcement is only ever exercised from another crate is fragile by
construction. The claim-10 anchor is a live example: `is_deny_all`'s only
assertion lives in a different crate, and it survives both constant
replacements here.

The cost of the trade is that a "miss" is not automatically a hole, so a
baseline entry must say which it is. That is why `reason` is mandatory and
why the gate fails on an empty one.

## Deliberate non-goals

- **Not PR-blocking on mutation results.** Hours-long lanes do not belong on
  a PR. The PR-visible half is the surface pin; the mutation result is
  nightly. This is stated rather than implied because a gate whose expensive
  half never runs on a PR is exactly the failure mode this plan exists to
  catch elsewhere — see the honesty note below.
- **Not a coverage percentage.** A mutation *score* invites tuning the
  threshold. The ratchet asks a sharper question: is there a new hole?

## Honesty note

The nightly lane lives in `security.yml`, which runs on release tags and a
nightly cron and is therefore invisible on a PR. That is a pre-existing
property of that workflow, not something this plan fixes, and it is the
reason the surface pin is a separate cheap mode wired into the PR lint lane.
The claim this gate supports is "a new hole in a claim witness is detected
within a day", not "within a PR".

## Workstreams

### WS-1 — gate + surface pin (PR-visible)

- [x] Extract the ledger parser out of `check_claim_catalog` into
      `xtask/src/claims_ledger.rs` so both gates read one parser.
- [x] `xtask/src/check_mutation_witnesses.rs`: resolve `fn:` witnesses to
      declaring files, derive the owning crate, pin the surface.
- [x] Report and pin the claims that reach *no* mutable file, so "the
      mutation lane is green" cannot quietly mean "over 22 of 26 files
      and 12 of 16 claims". Claims 4, 5 and 7 are witnessed only by CI
      lanes (a symbol grep and a fuzz job have no function to mutate);
      claim 16's three witnesses all live in
      `crates/mvm-hostd/tests/egress_secret_leak_gate.rs`, and
      cargo-mutants does not mutate test targets.
- [x] `mutants.out/` in `.gitignore` — the gate always redirects
      cargo-mutants to a temp dir, but a hand-run would otherwise leave a
      report tree in the working copy. No `mutants.toml`: the gate passes
      `-p`, `--file`, `--test-tool` and `--timeout` explicitly, so a
      config file would carry nothing.
- [x] Wire `check-mutation-witnesses` into `xtask/src/main.rs` and the
      `Justfile` (`mutation-surface`, `mutation-witnesses`,
      `mutation-repin`).
- [x] Unit tests: surface resolution, owning-crate derivation, mutant
      identity normalization, ratchet verdicts.
- [x] Add the gate to the PR lint lane in `ci.yml`.

### WS-2 — full-surface baseline (nightly)

- [x] Nightly `mutation-witnesses` job in `security.yml`, marked
      `continue-on-error` until the baseline covers the whole surface.
- [x] Seed `accepted_misses` from a real run of the claim-10 anchor
      (`crates/mvm-protocol/src/policy/network_policy.rs`): 52 mutants,
      35 caught, 12 unviable, 1 timeout, **4 missed**.
- [x] Confine `--run` to a throwaway `HOME` + `MVM_HOME` (#1958, closing
      \#1946). A mutant is the enforcement code with a check removed, so
      running the suite against one can mint a signer key at whatever path
      the mutated logic picks and leave audit state behind. The nightly job
      now exports both roots to a runner temp dir, carrying
      `CARGO_HOME`/`RUSTUP_HOME` across so an hours-long run does not
      re-download the registry and toolchain.
      **Residual:** the isolation is in the workflow step, so it does not
      reach `just mutation-witnesses` — the local recipe #1946 called the
      sharper of the two, since a developer's real `~/.mvm` is not a
      discarded VM. Moving it into the gate itself, where cargo-mutants is
      spawned, would cover both entry points from one place.
- [ ] Populate `accepted_misses` for the remaining 25 surface files from
      the first full nightly runs, then drop `continue-on-error` so a new
      hole fails the lane. **Triage rule:** a **real hole** gets the test
      that catches it; an **equivalent mutant** gets an `accepted_misses`
      entry with a stated reason. `check_accepted_reasons` already refuses
      an unexplained entry, so the reason is enforced, not encouraged.
- [ ] Triage the four seeded misses. What the first run already shows:
  - [ ] `is_banned_ssh_port -> false` survives. Only the negative
        direction is asserted inside mvm-protocol, so pinning the
        predicate to false goes unnoticed while flipping its `==` is
        caught. The SSH ban has real callers in mvm-core and mvm-cli;
        the owning crate should assert port 22 *is* banned.
  - [ ] `NetworkPreset::is_deny_all` survives being replaced by **both**
        `true` and `false`. It has no production caller anywhere in the
        tree — its only use is an assertion in mvm-core's
        `security_profile` tests. Either it is load-bearing and wants a
        caller, or it is dead code wearing a claim-shaped name.
  - [ ] `NetworkPolicy::trusted_build_egress -> Default::default()`
        survives. The mutant substitutes the deny-all default, so it
        makes the policy *stricter*: a functional coverage gap, not a
        security hole. Worth recording as exactly that.

### WS-3 — the witnesses this gate cannot reach (folded in from plan 274)

Plan 274's WS3 covered the same ground and is struck in favour of this
section; 274 keeps only WS1 (ABI layout contracts) and WS2 (the nextest
profile), both shipped. The merge is not tidiness: 274 hand-copied the
list of unreachable claims into prose and recorded **three**, while this
gate *derives* the list from the ledger and reports **four**. Keeping the
follow-up next to the code that computes it is what stops the two from
drifting again.

`check-mutation-witnesses` reports four claims reaching no mutable file,
for two different reasons — and the reason decides the treatment:

| Claim | Why unreachable | How to falsify it |
| --- | --- | --- |
| 4 (no `do_exec` in prod) | no `fn:` witness — a symbol grep | build the agent *with* `interactive`, confirm the job fails |
| 5 (fuzz targets) | no `fn:` witness — a fuzz lane | break the `GuestRequest` framing, confirm a short local run finds it |
| 7 (dependency audit) | no `fn:` witness — a `cargo deny` job | add a crate with a disallowed licence, confirm `cargo deny` fails |
| 16 (egress substitution) | **has** `fn:` witnesses, but all three live in `crates/mvm-hostd/tests/`, which cargo-mutants does not mutate | plant a defect in the *enforcement* code and confirm the integration test fires |

Claim 16 is the one 274 missed, and it is not a CI-lane falsification at
all — its witnesses are real Rust functions that mutation testing skips
only because they sit in a test target. It needs the hand planted-defect
treatment that 274's WS3 originally described for everything.

- [ ] Falsify claims 4, 5 and 7 against their CI lanes. Each needs a
      pushed branch to observe, since the lane is the thing under test.
      Record wall-clock-to-detect for claim 5: a lane that needs hours to
      find a planted defect is weaker evidence than one that finds it in
      seconds.
- [ ] Falsify claim 16 by planting a defect in the egress-substitution
      enforcement path and confirming
      `crates/mvm-hostd/tests/egress_secret_leak_gate.rs` goes red.
- [ ] Record all four in `specs/VERIFICATION.md` §"Falsifiability". A
      *did not fire* is a finding, not a failed task.

### WS-4 — deferred follow-ups

- [ ] Consolidate the seven private `walk()` helpers duplicated across
      `xtask/src/check_*.rs` into one shared xtask util. This plan adds no
      new copy — `check_mutation_witnesses` reuses the ledger module's
      walker — but the existing duplication remains.
- [ ] Consider a `mutate:` witness kind in the ledger for claims whose
      enforcement lives in a different file from their anchor test, so the
      surface can name enforcement code directly instead of inferring it.
- [ ] `substitute` resolves to four files (an overloaded name across the
      agent, keyholder, and supervisor network stages). All four land in the
      surface today. A more specific witness token would narrow it.
- [ ] Three cargo-fuzz harnesses exist and no workflow runs them:
      `fuzz_builder_request` and `fuzz_entrypoint_event` (mvm-agentd) and
      `fuzz_snapshot_frame` (mvm-core). Left out of the lane restoration
      deliberately — it had run nothing for ten nightlies, so adding
      never-executed targets to the change that revives it would make a
      first-run failure indistinguishable from the restoration being wrong.
      Add them once the lane is observed green.
- [ ] `check-duplicate-majors` is wired into `ci.yml`'s Lint job but not
      `ci-full.yml`'s, against the standing rule that a gate lives in both
      lists. It happens to be the gate that would have caught the dalek
      duplication early.
- [x] `ci:NAME` witnesses resolved by literal string match anywhere in
      `.github/workflows/*`. Closed in #1980: a token now resolves to a real
      job key or a parenthesised step token, so a deleted job no longer keeps
      a green witness.
- [x] A claim's CI lane can stop backing it two ways — going red, and
      ceasing to run. #1970 (`Security lane watch`) reports the first, but
      triggers on `workflow_run: completed`, so it is structurally blind to
      the second: Security ran nightly to 2026-06-16 and not again until
      2026-07-21, and nothing could have said so.
      `check-claim-witness-freshness` covers absence on its own schedule.
- [ ] The freshness gate reasons only about crons that fire at least daily;
      a lane moved to a weekly schedule silently drops out of its scope
      (reported as a note, not a failure). Deriving a weekly interval needs
      calendar arithmetic the gate deliberately does not attempt yet.
