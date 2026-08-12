# Bound a warm-claimed child by the host ceiling

Plan 308, Task 23 — the last open admission gap in `Preview` claim 18.

A warm-claimed child was bounded by its parent for egress (an absent parent
grant projects to deny-all) but not for CPU. The standby parent deliberately
carries no grant — one parent serves every later claim, so sealing a
provisioning workload's grant onto it would bind unrelated claims to a
stranger's number — which left `claim_standby`'s parent-subset comparison with
nothing to bind against, and the child booted with whatever share its plan
asked for.

**What now bounds it.** `ensure_child_grants_within_host_ceiling`
(`crates/mvm-runtime/src/workload_runner/claim.rs`), called from
`claim_standby` immediately after the parent-subset comparison, against
`MvmConfig::grant_ceiling()` read from host config. That is deliberately the
weakest of the options considered: a host-wide maximum every cold boot on this
host already clears, not a pool-specific grant. It is strictly stronger than
the unbounded claim it replaces and no stronger than that, and both the code
comment and ADR-001's limit 4 say so.

**Checked after pool matching, not folded into the compatibility key.** Keying
on a grant value would fragment one pool into a pool per distinct share and
cost the warm hit rate the pool exists for. The price is that a claim can match
a parent and then be refused, so the refusal names both the ceiling and the
request and reads as a bound rather than a bug.

**The spawn half.** Investigated rather than assumed:

- Firecracker saved-state fork — already spawn-bounded; it routes through the
  same `restore_fork` launch line a `vm_full` fork does, carrying the plan's
  CPU grant.
- Firecracker preloaded-child resume — not reachable. The child's process was
  spawned before the claim arrived; there is no spawn left to wrap.
- HVF resident handoff — not reachable. No process is spawned at all: the
  parent's own supervisor is resumed by `SIGUSR2`, and that process was born
  grant-less as shared pool capacity, so binding it would bind the pool rather
  than the claim.

`bind_cpu_grant` wraps a `Command` and this tree has no post-spawn cgroup
attach, so the two unreachable paths stay declared. ADR-001's limit 4 states
this, and also corrects a stale sentence that said a *forked* child was not
re-bound — it has been since the restore re-arm landed.

**Witnesses** (`crates/mvm-runtime/src/workload_runner/runner.rs`):
`a_claimed_child_over_the_host_ceiling_is_refused` (proven red with the check
removed), `a_claimed_child_within_the_ceiling_is_admitted`,
`the_refusal_names_the_ceiling_and_the_request`, and
`pool_matching_is_unchanged_by_the_bound`, whose exhaustive `StandbyCompat`
destructure fails to compile the day a grant dimension joins the key.
Registered on `MVM-SEC-18` in `model/claims.toml` and in ADR-001's row 18.
