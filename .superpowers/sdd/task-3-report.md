# Task 3 Report: Reconcile remaining verb-grant admit sites + honest doc-comment

## Status: DONE

## Commit hash: d70a000c

## Step 1: Site Classification

| Line (original) | Context | Category | Action |
|---|---|---|---|
| 658 | `untrusted_transient_admit_in()` — MCP code-runner / shared untrusted transient path. Doc says "Shared by `mvmctl run` and the MCP code-runner"; always runs arbitrary user code. No pty signal, but unconditionally ad-hoc. | **(b) real ad-hoc run** | Set `false` |
| 1698 | `fn no_supervisor_short_circuits_to_none` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 1734 | `fn admits_real_rootfs_and_returns_plan_id` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 1791 | `fn admission_plan_carries_ssh_agent_auth_policy` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 1885 | `fn admission_failure_when_rootfs_missing` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 1928 | `fn two_admissions_in_same_run_produce_distinct_plan_ids` (first call) — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 1955 | `fn two_admissions_in_same_run_produce_distinct_plan_ids` (second call) — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 2024 | `fn admission_emits_policy_resolved_for_default_local_default_refs` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 2076 | `fn admission_weaves_allow_list_into_signed_generated_policy_bundle` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |
| 2135 | `fn admission_weaves_unrestricted_policy_into_signed_generated_policy_bundle` — inside `#[cfg(test)] mod admit_plan_tests` | **(a) test fixture** | Leave unchanged |

**Summary:** 1 real production site fixed (line 658 → `false`); 9 test-fixture sites left unchanged.

## Step 2: Changes Applied

### Doc-comment on `AdmitPlanForBootParams.is_sealed_prod` (line ~155)

Replaced stale description with the honest doc-comment from the brief:

```rust
    /// True iff this run should receive an attenuated agent-verb grant —
    /// i.e. a baked-entrypoint run on a non-dev profile (see grant_eligible).
    /// Interactive / ad-hoc / dev runs are false: they issue DevOnly verbs a
    /// ProdSafe grant would refuse. (Field name kept for now; semantics are
    /// "restrict agent verbs", not literally "sealed prod".)
    pub is_sealed_prod: bool,
```

### `untrusted_transient_admit_in` (line 661 post-edit)

```rust
            // Untrusted transient runs are always ad-hoc (arbitrary user code);
            // they must not receive an attenuated verb grant.
            is_sealed_prod: false,
```

## Step 3: Persistent path verified

`grep -n "is_sealed_prod" up.rs` confirms line 1178 still reads:

```rust
        is_sealed_prod: profile != "dev",
```

No persistent-admit test helper exists in the file; verified by inspection.

## Step 4: Gate output

| Gate | Result |
|---|---|
| `cargo check --workspace --all-targets` | PASS (0 errors) |
| `cargo nextest run -p mvm-cli` | 1199/1200 PASS; 1 SIGTERM (`pick_console_transport_does_not_route_workload_to_dev_socket` — pre-existing timeout, present on prior commit `f5df25d0`) |
| `cargo fmt --all -- --check` | PASS (no drift) |
| `cargo clippy -p mvm-cli --all-targets -- -D warnings` | PASS (0 warnings) |
| Targeted admission + grant tests (22 tests) | 22/22 PASS |

The timed-out console test is pre-existing and unrelated to this task.

## Commit

`d70a000c` — fix(cli): reconcile remaining verb-grant admit sites to run-mode gating

## Final-review fix pass

### Tree-wide site table (post-rename: `restrict_agent_verbs`)

| File:line (pre-rename) | Category | New value |
|---|---|---|
| `up.rs:160` (struct field) | Rename + doc update | `restrict_agent_verbs: bool` |
| `up.rs:470` (usage in `admit_plan_for_boot`) | Rename | `p.restrict_agent_verbs` |
| `up.rs:661` (untrusted transient — already false) | Rename | `restrict_agent_verbs: false` |
| `up.rs:1178` (persistent OCI machine) | **Critical fix** | `grant_eligible(false, has_ad_hoc_argv, profile == "dev")` |
| `up.rs:1701,1737,1794,1888,1931,1958,2027,2079,2138` (`#[cfg(test)]`) | Rename only (test fixtures) | `restrict_agent_verbs: true` |
| `exec.rs:368` (transient run — already `grant_eligible(...)`) | Rename | `restrict_agent_verbs: grant_eligible(...)` |
| `invoke.rs:183` (session admit) | **Critical fix** | `restrict_agent_verbs: !call.keep_alive_dev` |
| `checkpoint.rs:893` (fork child) | **Important fix** | `restrict_agent_verbs: false` (fail-open; no parent run mode available) |
| `checkpoint.rs:1041` (restore child) | **Important fix** | `restrict_agent_verbs: false` (fail-open; no source run mode available) |
| `agent_verbs.rs:19` (fn param) | Rename | `restrict_agent_verbs: bool` param |

### Persistent `has_ad_hoc_argv` threading

- Added `has_ad_hoc_argv: bool` field to `PersistentImageStartParams` with doc-comment.
- Added `has_ad_hoc_argv: bool` field (as `#[arg(skip)]`) to `MachineStartArgs`.
- `run_persistent()` passes `has_ad_hoc_argv: !args.argv.is_empty()` when constructing `MachineStartArgs`.
- `start_machine()` passes `has_ad_hoc_argv: args.has_ad_hoc_argv` into `PersistentImageStartParams`.
- `start_persistent_oci_machine()` uses `grant_eligible(false, has_ad_hoc_argv, profile == "dev")`.
- New test `persistent_with_trailing_argv_is_not_eligible` in `agent_verbs.rs` asserts `!grant_eligible(false, true, false)`.

### Invoke fix

`restrict_agent_verbs: !call.keep_alive_dev` — plain entrypoint invoke (no `--keep-alive-dev`) stays `true` (attenuated grant OK); `--keep-alive-dev` drops to `false` so subsequent `session exec`/`run-code` DevOnly verbs are not refused.

### Checkpoint fixes

Both fork (`checkpoint.rs:893`) and restore (`checkpoint.rs:1041`) sites set `restrict_agent_verbs: false` with comments explaining fail-open policy (parent run mode is not tracked; per-fork grant reconciliation is a follow-up).

### Rename scope

- `AdmitPlanForBootParams.is_sealed_prod` → `restrict_agent_verbs` (field + doc-comment)
- `default_agent_verbs(is_sealed_prod: bool, ...)` → `default_agent_verbs(restrict_agent_verbs: bool, ...)`
- All construction sites: `is_sealed_prod: <value>` → `restrict_agent_verbs: <value>`
- Compiler caught all missed sites; no `is_sealed_prod` remains in `crates/mvm-cli/src/` after the fix.

### Post-fix grep confirmation

`grep -rn "restrict_agent_verbs" crates/mvm-cli/src/` returns only:
- struct field definition + doc update
- function param rename in `agent_verbs.rs`
- usage sites: `false` (untrusted transient, checkpoint fork, checkpoint restore); `grant_eligible(...)` (exec transient, persistent OCI); `!call.keep_alive_dev` (invoke); `true` (test fixtures only)

No real site hardcodes `true` for a path that can issue DevOnly verbs.

### Gate output

| Gate | Result |
|---|---|
| `cargo check --workspace --all-targets` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy -p mvm-cli --all-targets -- -D warnings` | PASS |
| `cargo nextest run -p mvm-cli` (targeted: 19 grant/verb tests) | 19/19 PASS |
| Full `cargo nextest run -p mvm-cli` | 1182/1201 PASS; 1 FAIL pre-existing (`each_embedded_binary_starts_with_elf_magic` — stub build with MVM_SKIP_EMBED_BINARIES=1); 1 SLOW/SIGTERM pre-existing (console transport timeout) |

### Commit hash

(pending — see below)
