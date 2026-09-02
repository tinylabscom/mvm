# A forked child gets its parent's secret bindings

Backing: shipped-source
Validation: Option A is complete. Focused CLI, admission, tenant-isolation,
attenuation, and audit tests pass; `cargo test --workspace`, workspace
all-target clippy, and `just check-gated` are green.

## Status

**COMPLETE, OPTION A.**

Two designs are recorded here. **Option A (explicit at fork) is the recommended
build.** Option B (inherited from the checkpoint) is the more ergonomic design
and is deliberately deferred — it is recorded so the decision is legible, not
because it is queued.

W0 and Option A are implemented. Option B remains deliberately deferred.

## The gap

`admit_forked_child` (`crates/mvm-cli/src/commands/vm/checkpoint/fork_vm_full.rs:327`)
mints a fresh plan for a vm_full fork child. Selective inheritance from the
parent is already the established shape there:

| field | inherited from parent | how |
| --- | --- | --- |
| `grants` | yes | `p.parent_meta.grants.clone()` |
| `agent_verb_override` | yes | `parent_agent_verb_override(...)` |
| `network_mode` | yes | `super::parent_network_mode(...)` |
| `network_policy` | no — hardcoded `deny_all()` | deliberate |
| `secrets` | **no — hardcoded `Vec::new()`** | not deliberate |
| `services` | **no — hardcoded `Vec::new()`** | not deliberate |

The child therefore boots with an empty `SubstitutionRegistry`. Every
placeholder the parent's workload minted before capture is dead in the child:
`SubstitutionRegistry::resolve` returns `None` and the endpoint refuses, which
is the behaviour `placeholder_from_another_session_does_not_resolve`
(`crates/mvm-hostd/src/keyholder/substitution.rs:449`) already pins for the
cross-session case.

That is fail-closed and therefore not a security bug. It is a **capability
bug**: a forked child cannot reach any authenticated upstream its parent could,
so the fork-per-run pattern is unavailable to most real workloads. Warm-claim
fork is becoming the primary launch path (#2336, the blocker previously
believed to be BUG-2, closed 2026-08-14 — see #2343 for the corrected
diagnosis), so this moves from latent to load-bearing.

### The part that is worth fixing today, under either option

The current failure is **silent**. Forking a parent that held secrets yields a
child that cannot reach anything, with no diagnostic — it presents as a network
fault, not a missing capability. That is a bad failure mode independent of
which design wins, and fixing it needs no schema change:

- [x] W0 — when a fork drops a non-empty parent secret set, warn with the
      dropped names. Source of truth is the parent's **persisted plan**
      (`plan_persist::read_plan(parent_meta.vm_name).secrets`), which
      `bind_checkpoint_forked` already reads — so W0 needs no schema change and
      does not depend on Option B's `CheckpointMeta` field.

W0 is worth landing on its own, before either option below is chosen.

W0 began as a warning. Option A makes the drop actionable: a fork now refuses
to omit a parent binding unless the caller explicitly supplies
`--allow-secret-drop`. This keeps the secure default while preserving an
auditable escape hatch for intentional attenuation.

A caveat the diagnostic cannot avoid: an unreadable parent plan yields an empty
set, so silence means "unknown", not "the parent held none". A fork of a parent
whose plan file is gone warns about nothing.

## Why not simply copy the parent's plan

Recorded because it is the first thing anyone proposes. It is wrong for the
reason the existing comment in `admit_forked_child` gives:

> The child's plan is its own, never the parent's: a distinct nonce, a distinct
> VM name, and `deny_all` networking.

and for the reason recorded against `Preview` claim 18 — a child's kill audited
under its parent's plan identity writes a *wrong* audit entry, which is worse
than a missing one. Plan identity must not be shared. Both options below keep
the child's plan wholly its own.

The enabling observation for both: **a secret binding is not a secret.**
`SecretRef` (`crates/mvm-contract/src/ir/workload.rs`) carries `name`, `mount`,
`auth_type`, `allowed_hosts`, and optional non-secret `sigv4` params. Every
field is a reference and a constraint. The value lives in the secret store and
is resolved by `LocalResolver` inside the per-VM substitution endpoint, which is
the one process holding it in the clear. So bindings can move without any secret
material moving.

## Option A — explicit at fork (recommended)

The requester declares which secrets the child gets, at fork time, the same way
any other VM declares them at admission. `admit_forked_child` stops hardcoding
`Vec::new()` and instead threads a caller-supplied set through the existing
`admit_plan_for_boot` `secrets` parameter, validated against `BindingStore` for
the child's tenant exactly as a normal boot would.

Why this first:

- **No `CheckpointMeta` change**, so no content-address change and no migration
  (see the hazard section below, which Option A does not incur at all).
- **No new inheritance edge** in the claim-12 binding graph. The child's
  capability is visible in the child's own plan; reading that plan is sufficient
  to know what it holds and why.
- **Strictly additive.** It closes the capability gap using machinery that
  already exists and is already tested on the normal boot path.
- The ergonomic cost — re-declaring on each fork — is an *empirical* question.
  Once fork-per-run is real, you will know within days whether it bites.

Work items:

- [x] A1 — plumb a caller-supplied `Vec<SecretBinding>` into
      `AdmitForkedChildParams` and through to `admit_plan_for_boot`.

      Two corrections to this item as first written. The type is
      `mvm_core::plan::SecretBinding` (`{name, source}`), **not** the keyholder's
      `SecretRef`: the plan-level binding carries a name and a source reference,
      and the destination binding (`auth_type` + `allowed_hosts`) is resolved by
      name against the tenant's `BindingStore` at the substitution endpoint. A
      declared name the operator has not bound therefore grants nothing, which is
      the property that makes declaring safe.

      And the stated test — "resolves a freshly minted placeholder against the
      declared host set" — needs a booted VM with a live endpoint, which is not a
      unit test. A1's test is scoped to admission: the declared set lands in the
      child's signed plan, and an empty set yields none. Placeholder resolution
      and host-set refusal are already covered at the endpoint by
      `substitutes_real_credential_for_a_bound_destination` and
      `unbound_destination_is_refused_without_decrypting`.
- [x] A2 — `--secret VAR` / `--secret VAR=ADDRESS` on `vm checkpoint fork`,
      repeatable. Wired to **both** fork arms: vm_full always admits a plan, and
      fs_quick admits one under `--boot`, so the flag means the same thing
      whichever class the parent is. Without `--boot` an fs_quick fork carries
      no plan at all and the help text says so.

      `fork()` moved to a params struct (`ForkCmdParams`) — it was already at
      seven positional arguments. `revert` reuses `fork()` verbatim as its
      anti-bypass guarantee and declares nothing, preserving its behaviour.

      **Fixed a defect in A1 as committed:** `admit_forked_child` set `secrets`
      while leaving `secret_release` at `SecretReleasePolicy::default()`, which
      is `None` — "no secrets may be released". A child would have carried
      bindings nothing could release. Both fork arms now derive it from the set
      via the existing `secret_release_for_bindings` (empty → `None`, non-empty
      → `PlanBound`) rather than defaulting.
- [x] A3 — cross-tenant declaration refused at admission (this falls out of
      `BindingStore` tenant scoping; assert it rather than assume it).
- [x] A4 — `checkpoint.forked` records the child's binding names + hosts, never
      values. Mirror the assertion shape of
      `stream_audit_entries_carry_the_binding_and_no_payload_bytes`.
- [x] A5 — HVF arm wired (`fork_vm_full_arm_hvf`); FC arm wired behind its
      existing `fc_vm_full_fork_experimental_enabled` gate, which stays.
- [x] A6 — refuse a fork that drops parent bindings the caller did not
      re-declare, now that re-declaring is possible. This is W0's refusal arm,
      deferred to here because it is incoherent before A1.

## Option B — inherited from the checkpoint (deferred)

Record the admitted binding set on `CheckpointMeta` beside `grants`, and re-bind
it onto the child by **intersection** with the operator binding currently in
`BindingStore`, so a checkpoint can never pin a capability wider than what is
presently granted. Cross-tenant refs dropped. Nothing minted — the child's
registry mints its own placeholders, so
`placeholder_from_another_session_does_not_resolve` stays green unchanged.

Why it is deferred rather than built:

Its entire value over Option A is ergonomic — you do not re-declare. It buys
that with an **implicit capability flow**: reading the child's plan no longer
tells you why it holds what it holds. You must walk the lineage and reconstruct
an intersection against mutable operator state to answer "why can this VM reach
that host?". For a codebase whose posture is that capability is explicit,
signed, and legible at the point of admission, silent inheritance is the wrong
default to adopt before the friction it removes has actually been felt.

If re-declaration turns out to be painful in practice, this is the design to
build, and
the intersection rule is the load-bearing part of it — never a union, never the
recorded set alone.

### Digest migration, if Option B is ever built

`compute_meta_digest` (`crates/mvm-core/src/checkpoint.rs:281`) feeds a fixed
field list into `CheckpointDigestInput`, and `verify_lineage` recomputes and
compares against what is stored on disk. A new field naively added to that input
changes the digest of **every checkpoint already on disk**, which surfaces as
`meta_digest drift` — i.e. as *tampered* — for records nobody touched.

This is already solved once, one field above where the new one would go:

```rust
/// Skipped when absent so a record that seals no grant hashes exactly as it
/// did before the field existed. […] The check is meant to be believed, so
/// it must not cry tamper over a field nobody touched.
#[serde(skip_serializing_if = "Option::is_none")]
grants: &'a Option<mvm_contract::grants::Grants>,
```

So the requirement is not novel risk, it is a documented pattern to follow:
`#[serde(skip_serializing_if = "Vec::is_empty")]` on the **digest input** field,
not merely on the `CheckpointMeta` field, so an empty set serializes to nothing
and pre-existing records hash byte-identically. Getting this wrong is loud and
immediate rather than subtle, but it would brick lineage verification for every
existing checkpoint, so it belongs in the first commit with a test that seals a
pre-field record and asserts its digest is unchanged.

## What neither option buys

- No tag-based binding groups — "attach a credential to a label and every VM
  wearing it gets it." That is a larger design needing an operator-facing
  surface, and it is not this.
- No revocation propagation to *running* children. Narrowing a binding affects
  the next fork, not a child already booted. Killing a live capability is the
  endpoint's job and is unchanged.
- A time-travel revert still declares no bindings and therefore fails closed
  for a secret-bearing parent. The explicit `machine restore` surface accepts
  declarations and intentional attenuation.
- An unbooted `FsQuick` child has no admitted plan, so `--secret` is rejected
  unless `--boot` is also present. A booted child uses the same policy as the
  vm_full path.

## Claims impact

No numbered claim changes under either option. Claim 13 (no raw secret over the
broker channel) is untouched — no value crosses any new boundary, and the
endpoint remains the only process holding cleartext. Claim 12's binding-gated
dispatch gains no new admission under Option A, and under Option B gains only a
strictly attenuating edge, so no admission previously refused becomes admitted.

`Preview` claim 18's limit — "a restored or warm-claimed child is
admission-bounded without its host-side CPU control **or its wall-clock timer**
being re-armed" — is **unaffected and still open**. Neither option re-arms
anything. A change touching fork admission is exactly the kind of work that gets
misread as having closed it; it does not.
