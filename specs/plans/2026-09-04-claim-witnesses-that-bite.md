# Claim witnesses that bite

Backing: shipped-source
Validation: check-mutation-witnesses

**Issues:** [#3148](https://github.com/tinylabscom/mvm/issues/3148),
[#3149](https://github.com/tinylabscom/mvm/issues/3149)

## Outcome

`security.yml`'s three red mutation shards go green on their own merits: every
surviving mutant is either killed by a witness verified against the reported
mutation, or recorded as equivalent with a proof. Nothing is re-pinned away.

## Why the lane went red

Claims 19 and 20 landed in #3133 and #3162. Adding a claim adds its witnesses'
files to the mutation surface, and the surface pin is the cheap check that runs
on a PR — so both PRs correctly re-pinned it. What neither could do is record
the *misses*, because that needs the six-hour run the nightly owns. The next
nightly therefore met four new surface files with no accepted-miss entries and
failed, which is the ratchet working as designed and reporting a real gap.

`check-claim-witness-freshness` (#3149) is downstream of that: it reports that
claims 1, 3, 4, 5, 6, 7, 10, 11 and 15 have a green ledger entry and a red
witness lane. It is a symptom, and it clears when #3148 does.

## The three shards

### mvm-cli — a dead shard, not a witness gap

The shard did not report survivors. It died:

    Error: reading .../crates_mvm-cli_src_commands_tests.rs/mutants.out/outcomes.json
    Caused by: No such file or directory (os error 2)

`crates/mvm-cli/src/commands/tests.rs` is 165 KB behind `#![cfg(test)]`.
cargo-mutants does not mutate test code, so it generated no mutants and wrote
no outcomes file at all — and the gate died reading that path, taking the whole
package's run with it. The four files in the same shard that *did* have mutants
reported nothing, and the error named a temp-directory path that reads as a
missing file rather than as a run that never started.

The file is on the surface because resolution maps a `fn:` witness to the file
declaring it, assuming that file is the enforcement code the witness guards.
That assumption is stated in the module docs and holds because this repo keeps
`#[cfg(test)] mod tests` inline. It does not hold when the tests are a separate
module file: `commands/mod.rs` declares `mod tests;`, so claim 19's
`test_audit_asset_id_parses` resolved onto the tests themselves.

Resolution now recognises the inner attribute and keeps such a file off the
surface, the same way it already keeps `crates/*/tests/` off it. Claim 19 keeps
its coverage — it still resolves to four other files — so the surface loses one
entry and no claim loses a witness. The uncovered-claim reason is reworded to
cover both shapes of test-only code.

### mvm-cli — eight survivors in the claim-20 verifier

`bump_verify_outcome`'s six match arms could each be deleted, and its
`outcome != "network"` guard inverted, without a witness noticing. These are
not cosmetic: the counters are the alerting channel mvmd's reconciliation loop
watches for attack-shaped spikes, and the guard is what decides that a
security-relevant rejection reaches the forensics log while an operational
download failure does not. A deleted arm does not fail verification; it makes a
rejection stop being visible.

`fetch_expected_hashes`'s digest predicate could have its `&&` relaxed to `||`.
That map is the pin every downloaded artifact is then held to, so the
disjunction admits a 64-character run of anything, and any length of hex, as a
pinned SHA-256.

Four tests close all eight, each verified by applying the reported mutation and
confirming the failure.

### mvm-contract — twenty survivors in `plan/types.rs`

Seven are closed by `specs/plans/2026-09-04-evidence-that-earns-trust.md`'s work
(the ingress cap boundary, the `as_str` wire spellings, `is_default`).

Twelve are closed here: the hex decoder's ASCII bases, `Nonce::as_hex` as a view
rather than a constant, `StreamRetention::persists`, `Variant::is_prod`, and the
five `PlanSeccompTier` spellings. Each is a handful of lines with no branching
worth the name, which is why none was covered — they read as too obvious to
test. Each is consumed by something that decides policy, and each was
replaceable by a constant, or the wrong constant, unnoticed.

One is equivalent and is recorded as an accepted miss with its proof: replacing
`|` with `^` in `CallerCommitment::from_hex`. `caller_commitment_nibble` returns
0..=15, so `high << 4` occupies bits 4-7 and `low` occupies bits 0-3; the bit
sets are disjoint, which makes the two operators the same function over every
input the expression can receive. Checked exhaustively over all 256 nibble
pairs, and the full 1007-test suite passes with the mutation applied.

## Delivery checklist

- [x] Keep `#![cfg(test)]` module files off the mutation surface, so a witness
      resolving into test code cannot kill a shard.
- [x] Re-pin the surface for that resolution change alone, and confirm no claim
      lost coverage.
- [x] Close the eight claim-20 survivors in `artifact_verify.rs`.
- [x] Close the twelve killable survivors in `plan/types.rs`.
- [x] Record the one equivalent mutant with a proof rather than a re-pin.
- [x] Verify every new witness by applying the reported mutation and confirming
      it fails.
- [x] Close the survivors the dead shard was hiding. Stopping the crash let the
      mvm-cli shard reach `commands/vm/up/admission.rs`, which sorts after
      `commands/tests.rs` and had never run; the mvm-contract shard surfaced
      `NetworkPolicy::admits_outbound`, added by #3170 after the run this plan
      was written from. Six more mutants, all killed, all verified by applying
      the mutation.
- [ ] Confirm on the first uninterrupted nightly that all three shards are green.
- [ ] Close #3148 and #3149 through their linkage.

## What was deliberately not done

`--write-baseline --run` would have made the lane green in one command by
re-recording every survivor as accepted. That converts a real gap into a green
light, and it is what the ledger exists to prevent. The surface pin was re-taken
exactly once, for a resolution change whose diff is one file.

The mvm-hostd shard's four survivors were closed separately in #3170 and are
already on `main`.
