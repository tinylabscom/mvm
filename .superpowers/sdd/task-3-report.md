# Task 3 Report: Wire --agent-verb + computed default into mvmctl up synthesis

## Status: DONE

## Commit hash: d58a4dc7

## Grounding result (Step 1)

`security_profile` exists only as a field on `up::Args` (line 956); it is never read or consumed in any code path — no resolved `AgentProfile`/`AdmissionProfile` exists. `admit_plan_for_boot` takes `AdmitPlanForBootParams`, not `up::Args` directly. The `--security-profile` flag is on the retired `vm up` command, not the live `machine run` path.

**Signal used:** `is_sealed_prod = profile != "dev"` — derived from `PersistentImageStartParams.profile: &'a str` inside `start_persistent_oci_machine`. The `profile` field carries the image/template profile string ("dev" / "worker" / "minimal" / etc.), which is the natural sealed-prod discriminant for the persistent machine path. For all other call sites (transient exec, invoke, checkpoint, untrusted-transient), `is_sealed_prod: true` is hardcoded (they always run production workloads).

## Architecture: what was added

Because `admit_plan_for_boot` does not have direct access to `up::Args`, the computation is threaded via two new fields on `AdmitPlanForBootParams`:

- `agent_verb_override: Vec<String>` — raw CLI `--agent-verb` values
- `is_sealed_prod: bool` — caller-derived sealed-prod flag

The `SynthesisInput.agent_verbs` is set at line ~462 (inside `admit_plan_for_boot`) as:
```rust
agent_verbs: super::agent_verbs::parse_agent_verb_override(&p.agent_verb_override)?
    .or_else(|| {
        super::agent_verbs::default_agent_verbs(p.is_sealed_prod, !p.shares.is_empty())
    }),
```

`PersistentImageStartParams` gained `agent_verb: Vec<String>` (threaded from the `machine/mod.rs` call site as `vec![]` — no CLI flag wired on `machine run` yet, `up::Args.agent_verb` is the legacy `vm up` struct).

## Files modified

- `crates/mvm-cli/src/commands/vm/up.rs` — `--agent-verb` on `up::Args`, new fields on `AdmitPlanForBootParams` and `PersistentImageStartParams`, `SynthesisInput.agent_verbs` wired at synthesis, test added, all test call sites updated with `agent_verb_override: vec![], is_sealed_prod: true`
- `crates/mvm-cli/src/commands/vm/agent_verbs.rs` — removed `#[allow(dead_code)]` from both functions, removed unused `names()` test helper and its allow
- `crates/mvm-cli/src/commands/vm/checkpoint.rs` — two `AdmitPlanForBootParams` call sites updated
- `crates/mvm-cli/src/commands/vm/exec.rs` — one call site updated
- `crates/mvm-cli/src/commands/vm/invoke.rs` — one call site updated
- `crates/mvm-cli/src/commands/machine/mod.rs` — `PersistentImageStartParams` call site updated with `agent_verb: vec![]`
- `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md` — Plan 217 completion noted

## Test output

```
~/.cargo/bin/cargo nextest run -p mvm-cli up_populates_agent_verbs agent_verbs
6 tests run: 6 passed, 1196 skipped
  PASS mvm-cli commands::vm::agent_verbs::tests::dev_gets_no_restriction
  PASS mvm-cli commands::vm::agent_verbs::tests::default_never_contains_a_devonly_verb
  PASS mvm-cli commands::vm::agent_verbs::tests::prod_without_shares_drops_volume_verbs_keeps_lifecycle_and_entrypoint
  PASS mvm-cli commands::vm::agent_verbs::tests::override_parses_valid_and_rejects_unknown_and_empty
  PASS mvm-cli commands::vm::up::admit_plan_tests::up_populates_agent_verbs_default_and_override
  PASS mvm-cli commands::vm::agent_verbs::tests::prod_with_shares_includes_mount
```

## Build/check/lint output

```
cargo check --workspace --all-targets     → clean (no errors)
cargo build -p mvm-cli (MVM_SKIP_EMBED_BINARIES=1) → Finished in 27.79s
cargo fmt --all -- --check               → clean
cargo clippy -p mvm-cli --all-targets -- -D warnings → clean (no warnings)
```

Pre-existing failures: `artifact_model_cli` / `artifact_extract_cli` integration tests fail because `target/debug/mvmctl` isn't built in this worktree — confirmed pre-existing before any changes.

---

## Fix pass: move --agent-verb to machine run + persist in spec

### Commit hash: 9b32b573

### What changed

**`MachineRunArgs` flag added** (`crates/mvm-cli/src/commands/machine/mod.rs`):
```rust
#[arg(long = "agent-verb", value_name = "VERB")]
pub agent_verb: Vec<String>,
```

**`MachineSpec` field added** (additive, `#[serde(default, skip_serializing_if = "Vec::is_empty")]`):
```rust
agent_verb: Vec<String>,
```
Old specs without this field deserialize cleanly (empty vec).

**Persist/thread path (mirrors `profile`)**:
- `machine_run_spec()` → `spec.agent_verb = args.agent_verb.clone()`
- `start_machine()` → `PersistentImageStartParams { agent_verb: spec.agent_verb.clone(), ... }` (replaces the `vec![]` hardcode at what was line 1768)
- `machine_config_matches()` + `machine_config_diff()` updated to include `agent_verb` so a verb-list change triggers the recreate notice

**`up::Args.agent_verb` removed** — the dead field (Clap flag on the retired `vm up` struct that was never reachable from `machine run`).

**New test** `agent_verb_flag_persisted_in_spec_and_survives_roundtrip`:
- Parses `--agent-verb run-entrypoint --agent-verb resolve-secret`
- Asserts the spec captures both verbs
- Round-trips through save/load and asserts the loaded spec matches
- Writes a legacy spec JSON without the field and asserts it deserializes as empty

### Test output

```
cargo nextest run -p mvm-cli agent_verb
7 tests run: 7 passed, 1196 skipped
  PASS mvm-cli commands::vm::agent_verbs::tests::prod_with_shares_includes_mount
  PASS mvm-cli commands::vm::agent_verbs::tests::dev_gets_no_restriction
  PASS mvm-cli commands::vm::up::admit_plan_tests::up_populates_agent_verbs_default_and_override
  PASS mvm-cli commands::vm::agent_verbs::tests::default_never_contains_a_devonly_verb
  PASS mvm-cli commands::vm::agent_verbs::tests::override_parses_valid_and_rejects_unknown_and_empty
  PASS mvm-cli commands::vm::agent_verbs::tests::prod_without_shares_drops_volume_verbs_keeps_lifecycle_and_entrypoint
  PASS mvm-cli commands::machine::tests::agent_verb_flag_persisted_in_spec_and_survives_roundtrip

machine suite: 107 tests run: 107 passed
```

### Build/check/lint

```
cargo check --workspace --all-targets  → clean
cargo fmt --all -- --check             → clean
cargo clippy -p mvm-cli --all-targets -- -D warnings → clean
```

### STATUS: DONE

---

## Final-review fix pass

### Fix 1 — Thread `--agent-verb` through the transient path

**Decision: threaded (not rejected).** The flag now works on transient runs.

**Call sites changed:**

- `crates/mvm-cli/src/commands/vm/exec.rs` — added `agent_verb: Vec<String>` field to `RunArgs` (internal, `#[arg(skip)]`); added `let admit_agent_verb = args.agent_verb.clone();` capture before the `move` closure; replaced the hardcoded `agent_verb_override: vec![]` at line ~364 with `agent_verb_override: admit_agent_verb.clone()`.
- `crates/mvm-cli/src/commands/machine/mod.rs` — `into_run_args()` now copies `agent_verb: self.agent_verb` (was omitted entirely).
- `crates/mvm-cli/src/commands/vm/run_plan.rs` — `base_run_args()` test helper gained `agent_verb: Vec::new()` to keep struct exhaustiveness.
- `exec.rs` test helper `run_args()` — gained `agent_verb: Vec::new()`.

### Fix 2 — Doc corrections

- `specs/plans/217-agent-verbs-population.md`: Goal/Architecture rewritten to state this POPULATES the field as a prerequisite; enforcement only activates once the grant-delivery path (PR #1385) also lands. Architecture paragraph updated to name the real CLI surface (`MachineRunArgs`, `machine run`, both paths). Task 3 section replaced with as-implemented description; note added that the original plan's `up::Args` target was the retired `vm up` struct.
- `specs/SPRINT.md` Task 3 bullet: corrected `up::Args` reference to `MachineRunArgs`; added prerequisite-only note.
- `specs/REFACTOR-STATUS.md` first entry: corrected `up::Args` reference to `MachineRunArgs`; added prerequisite-only note.

### New tests

- `commands::machine::tests::agent_verb_forwarded_to_run_args_on_transient_path` — asserts `into_run_args()` copies `["run-entrypoint", "ping"]` from `MachineRunArgs.agent_verb` to `RunArgs.agent_verb`.
- `commands::machine::tests::agent_verb_empty_on_transient_path_when_not_specified` — asserts the field is empty when the flag is absent.

### Test + check + clippy output

```
cargo nextest run -p mvm-cli agent_verbs machine into_run_args
115 tests run: 115 passed, 1090 skipped
  PASS mvm-cli commands::machine::tests::agent_verb_forwarded_to_run_args_on_transient_path
  PASS mvm-cli commands::machine::tests::agent_verb_empty_on_transient_path_when_not_specified
  (+ all prior agent_verb and machine tests)

cargo check --workspace --all-targets     → clean
cargo fmt --all -- --check               → clean
cargo clippy -p mvm-cli --all-targets -- -D warnings → clean
```
