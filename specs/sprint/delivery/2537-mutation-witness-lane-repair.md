# 2537 — Mutation-witness lane repair

## What was red

Five shards of the nightly `Security` workflow's `Claim witnesses —
mutation-tested` lane failed on `bdff1866`: `mvm-cli`, `mvm-core`, `mvm-vmm`,
`mvm-hostd`, `mvm-contract`. Nothing about the lane's tooling was broken. Every
failure was the ratchet doing its job — seven mutants of claim-enforcement code
that no witness detected, none of them in
`xtask/mutation-witness-baseline.json`.

They fall into two groups.

## Group 1 — four real holes, now closed by tests

| file | mutant | claim |
| --- | --- | --- |
| `crates/mvm-contract/src/substitution.rs` | `PlaceholderMap::is_empty -> true` / `-> false` | 13 |
| `crates/mvm-cli/src/commands/shared/resolve.rs` | `delete !` in `resolve_manifest_arg` | 10 |
| `crates/mvm-hostd/src/plan_admission.rs` | `delete field plan_id` from `DecisionScenario` and from `AttestationBinding` in `launch_decision_record` | 1, 8, 18 |

`PlaceholderMap::is_empty` could be pinned to either constant unnoticed:
nothing asserted the map's own answer to "did this session mint anything"
before an insert or after one. That one landed separately in #2532 while this
was in flight, so it is not in this change; it is listed because it is one of
the seven the lane reported.

`launch_decision_record` names the plan it launched twice — once in the
scenario it describes, once in the attestation it binds to. Either could be
deleted and the record still emitted, leaving an audit entry that says a
workload was launched but not which signed plan authorized it. The scenario's
`plan_id` is inside the record's content address, so the deletion also
re-addressed the decision. Nothing read either field back.

`resolve_manifest_arg` is the more interesting one. The ratchet keys on the
mutant's description, so `delete ! in resolve_manifest_arg` covered two sites,
and they were not the same kind of problem:

- `if !module_path.is_file()` — reachable. Inverting it refuses every wasm
  manifest as a module that "does not exist". But the check is a verbatim
  duplicate of `Manifest::validate`, which runs the same `path.is_file()` on
  the same already-resolved path a few lines earlier.
- `if !module_path.is_absolute()` — unreachable. `Manifest::read_file` resolves
  a relative `wasm` against the manifest's own directory before returning, and
  the path handed to it is canonicalized, so what arrives is always absolute.
  With the `!` deleted the branch runs, `base.join(absolute)` returns the
  absolute path unchanged, and the function returns the same value.

Both are deleted rather than witnessed. Baselining was not an option for
either: the two share one identity, so a waiver for the dead branch would have
suppressed the live one with it. What they encoded is asserted directly instead
— a wasm manifest resolves to its module by absolute path whether the manifest
names it relatively or absolutely, and a manifest naming an absent module is
refused.

## Group 2 — three provably equivalent mutants, baselined

`replace X::builder -> XBuilder with Default::default()` on `SynthesisInput`,
`SubstitutionSpawnParams` and `AdmitAndStartParams`. In all three,
`builder()` is a one-line alias for `XBuilder::new()` and the file's
`impl Default for XBuilder` returns `Self::new()` — `Default::default()`
evaluates the identical expression. No test can distinguish them.

This class will recur: the builder pattern is the house rule for structs with
several optional fields, `clippy::new_without_default` requires the `Default`
impl that makes the mutant viable, and every new builder on a claim-surface
file arrives with one. Each is one baseline line with the equivalence written
out; if a fourth appears, that is what to add.

## What is not proven

The `mvm-hostd` shard was killed by a runner shutdown after 3h22m, having
mutated 6 of its 10 surface files. The three new misses above are from the
files it reached. The four it never reached — `supervisor/dns_audit.rs`,
`supervisor/network/stages.rs`, `supervisor/network_endpoint.rs`,
`supervisor/network_endpoint_proxy.rs` (claims 10, 13, 17, 13) — carry no
evidence either way, from that run or from this change. A local sweep of them
was started and abandoned: `network/stages.rs` alone generates 152 mutants, and
at the rate a laptop retires them the four files are a multi-hour run. What it
did cover — 18 of `stages.rs`'s 152 — came back with nothing missed, which is
weak evidence and is offered as nothing more. The next nightly is what measures
them, and it may find more.

The `mvm-cli` shard also reported eleven baseline entries in `pull_core.rs` and
`resolve.rs` as now caught. Dropping stale entries tightens the ratchet, but
`pull_core.rs` needs its own half-hour run to confirm, so they are left in
place rather than dropped on one observation.

## Overlap with #2532

\#2532 landed first, mid-flight, and reached the same conclusion that one of
the two wasm branches is dead — but removed the other one, and said in its own
body that the surviving `is_absolute` mutant stands and the lane is still red.
That is correct: the branch it kept is the dead one.

This change rebases onto it rather than around it. Its `is_empty` test stands
and the duplicate written here was dropped; its `resolve.rs` test stands, with
its doc comment corrected, because the mutation it claimed to witness is one no
test can catch. What remains is the deletion of the dead branch, the coverage
the deletion needs, and the other four crates.
