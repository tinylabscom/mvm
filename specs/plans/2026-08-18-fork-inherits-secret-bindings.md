# A forked child inherits its parent's secret bindings, re-bound to its own identity

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

## Status

**READY FOR IMPLEMENTATION.** No code has been written. The mechanism this
extends (`grants` on `CheckpointMeta`) is shipped and is the template.

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
bug**: the fork-per-run pattern — warm a parent to steady state, fork a child
per unit of work — cannot be used for any workload that talks to an
authenticated upstream, which is most of them. The warm-start work makes fork
the primary launch path, so this stops being a corner case.

## Why the obvious fix is wrong

"Copy the parent's plan onto the child" is wrong for the reason the existing
comment in `admit_forked_child` gives:

> The child's plan is its own, never the parent's: a distinct nonce, a distinct
> VM name, and `deny_all` networking.

and for the reason recorded against `Preview` claim 18 — a child's kill audited
under its parent's plan identity writes a *wrong* audit entry, which is worse
than a missing one. Plan identity must not be shared.

The insight that makes this tractable: **a secret binding is not a secret, and
it is not a plan.** `SecretRef` (`crates/mvm-contract/src/ir/workload.rs`)
carries `name`, `mount`, `auth_type`, `allowed_hosts`, and optional non-secret
`sigv4` params. Every field is a *reference and a constraint*. The value lives
in the secret store and is resolved by `LocalResolver` inside the per-VM
substitution endpoint, which is the one process holding it in the clear. So a
binding can be inherited by value without any secret material moving, exactly
as `grants` is today.

## Design

### 1. Record the bindings on the checkpoint

Add to `CheckpointMeta` (`crates/mvm-core/src/checkpoint.rs:221`), adjacent to
`grants` and sharing its doc rationale verbatim:

```rust
/// The secret bindings the captured VM was admitted under. Load-bearing for
/// the same reason as `grants`: the digest covers this field, the signed
/// chain covers the digest, so a record edited to widen `allowed_hosts` or
/// name a secret the parent never held stops verifying before it can
/// justify a wider child.
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub secrets: Vec<SecretRef>,
```

`#[serde(default)]` per the repo's no-schema-bump rule. Critically, the field
must be folded into `meta_digest` in the same commit — a field outside the
content-address is an unauthenticated field, and this one grants capability.

`services` gets the same treatment; the claim-12 binding-gated dispatch is the
same shape of constraint and has the same problem.

### 2. Re-bind, don't copy, at admission

`admit_forked_child` stops passing `secrets: Vec::new()` and instead passes the
parent's recorded set through an **attenuating** re-bind:

```rust
secrets: rebind_for_child(&p.parent_meta.secrets, &child_tenant),
```

`rebind_for_child` lives in `crates/mvm-hostd/src/keyholder/binding.rs` beside
`BindingStore`, and enforces three rules:

1. **Tenant-scoped.** A `SecretRef` whose `name` does not resolve in the child's
   tenant via `BindingStore::get(child_tenant, name)` is dropped, not carried.
   A fork across a tenant boundary must not smuggle a binding.
2. **Attenuation only.** The child's `allowed_hosts` is the *intersection* of
   the parent's recorded set and the operator binding currently in
   `BindingStore`. If the operator narrowed or revoked a binding after the
   parent was captured, the child gets the narrowed set — a checkpoint cannot
   pin a stale-wide capability. Never a union; never the recorded set alone.
3. **Nothing minted.** `rebind_for_child` returns `SecretRef`s only. The child's
   `SubstitutionRegistry` mints its own placeholders at its own boot, so a
   placeholder token from the parent's session still does not resolve in the
   child. That test stays green unchanged, and it should — the guest re-reads
   its placeholders from the environment the endpoint hands it.

The child plan is still wholly its own: distinct nonce, distinct VM name,
distinct plan_id, `deny_all` network policy. Only the binding *constraints*
carry.

### 3. Audit the inheritance

`bind_checkpoint_forked` (`crates/mvm-hostd/src/audit/bind.rs`) gains the
inherited binding set — names and `allowed_hosts` only, never values — in the
`checkpoint.forked` entry, so the chain records what capability the child was
granted and on whose authority. An inheritance that could not be audited
refuses the fork, matching the `.context("refusing an unaudited fork")` policy
already on that path.

### 4. Where it does not apply

- **`bind_checkpoint_restored` / time-travel restore.** Out of scope. A restore
  re-admits under a fresh plan for a user-driven reason; inheritance there is a
  separate decision and this plan does not make it.
- **Firecracker.** `fork_vm_full_arm_fc` is behind
  `fc_vm_full_fork_experimental_enabled`. Wire it, but the gate stays.
- **`FsQuick` checkpoints.** No live guest state, so no live placeholder set to
  keep meaningful. Record the field; do not consume it.

## What this does *not* buy

Deliberately out of scope, and worth stating so the plan is not read as more
than it is:

- No tag-based binding groups. Inheritance here is parent→child down a
  lineage, not "attach a credential to a label and every VM wearing it gets it."
  That is a separate, larger design and it needs an operator-facing surface.
- No revocation propagation to *running* children. Narrowing a binding affects
  the next fork, not a child already booted. Killing a live capability is the
  endpoint's job and is unchanged.

## Work items

- [ ] W1 — `CheckpointMeta.secrets` + `.services`, folded into `meta_digest`.
      Test: a record with a hand-edited `allowed_hosts` fails `verify_lineage`.
- [ ] W2 — `rebind_for_child` in `keyholder/binding.rs`. Tests: cross-tenant
      binding dropped; post-capture narrowing wins over the recorded set;
      revoked binding yields no ref; intersection is never a union.
- [ ] W3 — capture path records the admitted `secrets`/`services` onto the meta.
- [ ] W4 — `admit_forked_child` consumes W2. Test: a child booted from a parent
      with a bound secret resolves a *freshly minted* placeholder against the
      inherited host set, and a host outside the intersection is refused.
- [ ] W5 — `checkpoint.forked` carries the inherited binding names + hosts;
      chain verifies; no value bytes present. Mirror the assertion shape of
      `stream_audit_entries_carry_the_binding_and_no_payload_bytes`.
- [ ] W6 — HVF arm wired (`fork_vm_full_arm_hvf`); FC arm wired behind its
      existing experimental gate.
- [ ] W7 — ADR-023 §egress-substitution gains a "fork lineage" subsection;
      `specs/REFACTOR-STATUS.md` + `specs/SPRINT.md` updated in the same change.

## Claims impact

No numbered claim changes. Claim 13 (no raw secret over the broker channel) is
untouched — no value crosses any new boundary, and the endpoint remains the only
process holding cleartext. Claim 12's binding-gated dispatch gains an
inheritance edge that is strictly attenuating, so no admission that was
previously refused becomes admitted. `Preview` claim 18's "a restored or warm-
claimed child is admission-bounded without its host-side CPU control or its
wall-clock timer being re-armed" limit is **unaffected and still open** — this
plan does not re-arm anything, and must not be read as closing it.
