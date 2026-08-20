# 2698 — forked children are admitted with no secret bindings

Issue: #2698. Plan: `specs/plans/2026-08-18-fork-inherits-secret-bindings.md`.
PR: #2696.

## Delivered

**W0 — the drop is loud.** A vm_full fork mints a fresh plan for its child with
`secrets: Vec::new()`, so every binding the parent held is dropped and the child
cannot reach any authenticated upstream the parent could. That was silent, and
presented as an upstream that stopped answering rather than as a capability the
child never received.

- `parent_secret_names(parent_checkpoint, store) -> Vec<String>` in
  `crates/mvm-cli/src/commands/vm/checkpoint.rs`. Reads the parent's persisted
  plan (`plan_persist::read_plan(parent_meta.vm_name).secrets`) — the same
  source `bind_checkpoint_forked` already uses — so no schema change was needed.
  Shape matches the three sibling helpers `parent_agent_verb_override`,
  `parent_network_mode` and `parent_plan_resources`.
- `warn_dropped_parent_secrets` emits the diagnostic. Wired into both admit
  sites: `checkpoint.rs` (`--boot` arm) and
  `checkpoint/fork_vm_full.rs::admit_forked_child`.

Names only. `SecretBinding` carries a name and a source reference and never a
value; the diagnostic echoes only the name, asserted by a dedicated test.

## Tests

Three, in `crates/mvm-cli/src/commands/vm/checkpoint.rs`:

- `parent_secret_names_lists_the_parent_bindings_by_name`
- `parent_secret_names_echoes_no_source_addresses`
- `parent_secret_names_is_empty_when_the_parent_plan_is_unreadable`

Mutation-checked: forcing the helper to return `Vec::new()` turns the two
positive tests red. Without that check they could have passed vacuously, since
the helper returns an empty vec on every error path.

## Scope deliberately not taken

**W0 warns; it does not refuse.** The plan originally specified "refuse under
`--prod`". There is no `--prod` on this path — a fork is always prod-profile —
so the refusal had no flag to gate on, and an unconditional refusal would turn
every existing fork of a secret-holding parent from degraded-but-working into a
hard failure. Moved to plan item A6, where it becomes coherent once the child's
bindings can be declared.

**Known limit:** an unreadable parent plan yields an empty set, so silence means
"unknown", not "the parent held none". A fork of a parent whose plan file is
gone warns about nothing. Recorded in the helper's doc comment and in the plan.

## A1 — the child's bindings are declared

`AdmitForkedChildParams` gains `declared_secrets: &[SecretBinding]`, threaded
through both arm param structs and every call site; `admit_forked_child` passes
it where it hardcoded `Vec::new()`. Outer callers pass `&[]` until a CLI surface
exists, so behaviour is unchanged.

`fork_vm_full_arm` moved from six positional arguments to its existing
`ForkVmFullArmParams` struct rather than growing a seventh — matching its
`fork_fs_quick_arm` sibling and staying clear of the banned
`too_many_arguments` allow.

Two corrections to A1 as the plan first wrote it. The type is
`mvm_core::plan::SecretBinding` (`{name, source}`), not the keyholder's
`SecretRef`; the destination binding is resolved by name against the tenant's
`BindingStore` at the endpoint, which is what makes declaring safe — a name the
operator has not bound grants nothing. And the stated test needed a booted VM,
so A1's tests are scoped to admission; placeholder resolution and host-set
refusal are already covered at the endpoint.

Tests: `a_declared_binding_lands_in_the_forked_childs_plan` and
`a_fork_declaring_nothing_admits_a_child_with_no_bindings`. Mutation-checked by
restoring the pre-A1 `Vec::new()`: the first goes red, the second stays green
(the mutant satisfies it), which is the expected split.

**Learned while building the fixture:** `admit_plan_for_boot` re-hashes the
rootfs blob and verifies it against `precomputed_image_sha256` rather than
trusting the recorded value, so a fork test needs a real blob on disk whose
digest matches the checkpoint record. A `meta.json` edited to claim a different
sha cannot redirect what gets admitted.

## A2 — the CLI surface

`--secret VAR` / `--secret VAR=ADDRESS` on `vm checkpoint fork`, repeatable.
`parse_declared_secrets` refuses an empty half on either side; nothing contacts
the keystore at parse time, because a binding is a reference and an unbound name
simply fails to resolve later rather than granting anything.

Wired to both fork arms. vm_full always admits a plan; fs_quick admits one only
under `--boot`, and the help text states that asymmetry rather than leaving the
flag silently inert for half its inputs. `revert`, which reuses `fork()`
verbatim as its anti-bypass guarantee, declares nothing.

`fork()` moved to `ForkCmdParams` — already at seven positional arguments, so an
eighth would have tripped the banned `too_many_arguments`.

**Fixed a defect in A1 as committed:** `secret_release` was left at
`SecretReleasePolicy::default()` = `None`, "no secrets may be released", while
`secrets` was populated. A child would have carried a binding list nothing could
release. Both arms now derive the policy from the set via the existing
`secret_release_for_bindings` helper.

Tests: `bare_secret_name_binds_var_and_address_alike`,
`var_equals_address_separates_the_two`, `an_empty_half_is_refused`,
`declaring_nothing_parses_to_nothing`,
`declared_bindings_make_the_release_policy_plan_bound`. Mutation-checked by
disabling the refusal: `an_empty_half_is_refused` goes red and the other four
stay green, since they do not exercise that path.

**A mutation check that nearly passed for the wrong reason:** the first run
filtered on `secret`, which does not match three of the five test names, so the
test that should have caught the disabled refusal never ran and the mutant
looked clean. Re-run with explicit filters. A filtered mutation check proves
nothing unless the filter is confirmed to include the test that must fail.

## A3–A6 — tenant validation, audit, entry points, and attenuation

Every declared keystore address is resolved against the child's tenant-scoped
`FileBindingStore` before cloning or booting. An unbound or cross-tenant address
therefore refuses admission. External providers retain their existing runtime
resolution contract and do not acquire local binding metadata by accident.

`checkpoint.forked` now records a JSON list containing each local binding's
guest name and allowed hosts. The event never records source addresses,
providers, or values. The audit API uses a named parameter struct rather than
growing another positional argument list.

The declaration surface is wired through both HVF and Firecracker vm_full
arms, with the existing experimental Firecracker gate unchanged, and through
the booted fs_quick path. `machine fork`, `machine restore`, and
`machine warm-restore` expose the same repeatable `--secret` and explicit
`--allow-secret-drop` flags as `vm checkpoint fork`.

A fork refuses any parent guest binding name that the caller did not re-declare
unless `--allow-secret-drop` is present. The explicit-drop warning contains
names only. An unbooted fs_quick fork rejects `--secret` because it has no child
plan; revert declares nothing and consequently fails closed for secret-bearing
parents rather than bypassing the attenuation check.

Added coverage includes:

- `secret_attenuation_requires_explicit_drop_permission`
- `dropped_parent_secrets_excludes_explicit_redeclarations`
- `fork_secret_audit_resolves_only_child_tenant_metadata`
- hostd bind/emitter assertions for names and allowed hosts with no source or
  secret value
- CLI help assertions for the three machine entry points

Focused tests, workspace tests, isolated doctests, workspace all-target clippy,
and the Linux/BDD gated compile are green. No booted VM was required: admission
composition is tested here, while live placeholder resolution and host refusal
remain covered by the substitution endpoint's own tests.

Option B (inherit from the checkpoint) remains designed and deliberately
deferred.

`Preview` claim 18's unre-armed wall-clock/CPU limit is untouched and still
open.
