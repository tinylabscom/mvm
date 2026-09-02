# The 0700 posture on `~/.mvm` is now enforced by code that runs

`mvm_core::config::ensure_home_dir` and `ensure_cache_dir` were `pub`,
correct, and called by nothing. The claimed posture — `~/.mvm` and every child
at mode 0700 — was established by no code path at all; it held only when a
directory happened to be made by something that chmodded, and silently did not
hold otherwise. A doc comment in the cleanup planner even described the repair
as something "whichever command next calls `ensure_home_dir()`" performed. No
command called it.

This surfaced as a red nightly lane — `data dir mode: MISSING (expected 0700,
got 0755 at /home/runner/.mvm)` — where the proximate cause was the e2e harness
creating the home bare. That part was fixed separately. The reason a 0755 home
then *survived an entire suite run*, through many `mvmctl` invocations writing
into it, is what this change addresses.

## Why not a startup call

The obvious wiring — call it once when the CLI starts — was rejected for two
reasons. It puts a write side effect on read-only commands, so `mvmctl --help`
would create `~/.mvm` and hermetic tests that assert no writes would start
writing. And more importantly it fixes the wrong thing: `create_dir_all` makes
each *missing ancestor* at the process umask, so a directory created later in
the same run still arrives with loose parents. The root is not the only
component, and a startup pass cannot reach the ones that do not exist yet.

## What landed

**One helper at the creation seam.** `config::create_private_dir` creates the
path and locks every component from the mvm home down to the leaf, repairing
components that already exist. Any writer therefore repairs a home that arrived
loose — from a bare `mkdir`, an unpacked archive, an older build — on the first
command that touches state, which is the property the startup pass was wanted
for, without the startup pass.

The target itself is locked wherever it lives; only the *ancestor walk* is
confined to the home, because above the home the path stops being ours and
chmodding `/tmp` or `$HOME` en route would be a side effect on someone else's
property.

**A duplicate implementation folded in.** `mvm-client`'s volume module had its
own `ensure_private_dir` chmodding only the leaf — the same ancestor bug, in a
second copy. It now delegates.

**Six hand-rolled sites converted**: the host signing key directory, the audit
chain directory (two constructors), the decision store, the receipt store, the
per-VM state directory, the witness directory, and the two managed-volume
roots. Each was `create_dir_all` followed by a `set_permissions(0o700)` on the
leaf alone — which reads at a glance as though the mode had been handled.

Two of them were worse than that. `AuditEmitter::with_dir` tightened the
directory only `if !audit_dir.exists()`, so a chain directory that arrived
loose was left exactly as found — the one case where the mode mattered.

**A gate so it stays fixed.** `xtask check-private-mvm-dirs` refuses
`create_dir_all` in the modules owning the secret-bearing roots. It found four
sites I had missed, including both volume roots.

## Deliberately scoped

The gate watches `crates/mvm-hostd/src/audit` and `crates/mvm-client/src/volume`,
not the workspace. There are ~1000 `create_dir_all` calls in this tree and the
overwhelming majority are honest — temp dirs, unpacked guest rootfs trees,
caller-named `--out` targets, build scratch. A rule that flagged those would be
switched off within a week, which is the failure mode `check-vcpu-ceilings`
documents at length.

So this does **not** cover a deep path created elsewhere under an
already-0700 root. That is cosmetic rather than a leak — traversal needs execute
permission on every ancestor and the root denies it — but it is a real gap
against the letter of the claim, and it is not closed here.

`emitter/atomic_write.rs` is allowlisted: it creates the parent of a file it is
about to rename into place, is called with paths both inside and outside the
home (an operator's export target among them), and the audit roots it touches
are already created privately by the emitter before any write reaches it.

## Tests

- `create_private_dir_locks_every_component_including_a_pre_existing_loose_root`
  — starts from exactly the CI runner's state (an existing 0755 home) and
  asserts root, intermediate and leaf all end 0700. **Verified by mutation**:
  reverting the helper to a leaf-only chmod fails it.
- `create_private_dir_locks_a_target_outside_the_home_but_not_its_parents` —
  both halves of the boundary rule.
- `check-private-mvm-dirs` carries `passes_on_this_workspace` plus a check that
  a comment naming the banned call does not trip the gate on its own docs.

A first cut skipped the mode entirely for paths outside the home, on the
reasoning that they were caller-owned. Two existing mode assertions in
`mvm-hostd` caught it immediately — a keys directory relocated by a test seam
is still a keys directory. The rule above is the corrected one.

## Validation

68 gates clean · `cargo nextest run --workspace` 12982 passed · doctests clean ·
`clippy --all-targets -D warnings` clean · `fmt --all --check` clean ·
`check-gated` clean with `RUSTFLAGS=-D warnings`.
