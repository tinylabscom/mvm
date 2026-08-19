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

## Not delivered

Options A (declare bindings at fork, A1–A6) and B (inherit from the checkpoint)
are designed and unimplemented. `Preview` claim 18's unre-armed wall-clock/CPU
limit is untouched and still open.
