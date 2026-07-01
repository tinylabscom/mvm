# Agent-Verbs Population Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `ExecutionPlan.agent_verbs` at synthesis with a computed-minimal set for sealed-prod workloads (overridable by CLI), so the plan-bound verb enforcement stops being dormant.

**Architecture:** Purely synthesis-side. A canonical ProdSafe verb list lives in `mvm-guest`; a pure `default_agent_verbs(is_sealed_prod, has_shares)` computes the minimal set (all ProdSafe minus the volume verbs when the workload declares no shares; `None` for dev = class-gate-only); `mvmctl up` computes `override ?? default` and passes it into the existing `SynthesisInput.agent_verbs` field. No guest/enforcement change — the guest already intersects the set subtractively.

**Tech Stack:** Rust, `clap` (CLI), `serde`. Tests via `cargo nextest`.

## Global Constraints

- **STACKS ON #1380 (Plan 215 core).** This plan REQUIRES `mvm_core::plan::VerbId` and the `ExecutionPlan.agent_verbs: Option<Vec<VerbId>>` field + `SynthesisInput.agent_verbs: Option<Vec<VerbId>>` — all added by #1380, which is NOT yet on `main` at authoring time. **Do not start until #1380 has merged to `main`**, then branch this off fresh `main`. If `grep -c agent_verbs crates/mvm-core/src/plan/execution_plan.rs` returns 0, #1380 has not landed — stop.
- **Strictly subtractive is already enforced.** The guest intersects `agent_verbs` with the class/profile gate (`enforce_verb_grant` after `allowed_in`). This plan only *supplies* the set; it never needs to touch enforcement. A CLI override can therefore never grant more than the profile allows.
- **Reuse first.** The CLI flag mirrors `--network-allow` (`crates/mvm-cli/src/commands/vm/up.rs:947`). The ProdSafe list is the single source of truth in `mvm-guest`; do not hardcode a second copy anywhere.
- **Conservative default is deliberate.** All host-lifecycle/status ProdSafe verbs stay in the default unconditionally (pause/resume/snapshot/pooling are host-initiated and must never break); the ONLY attenuation is dropping `mount-volume`/`unmount-volume` when the plan has no `shares`.
- **Dev is unaffected.** Non-sealed-prod → `agent_verbs = None` (class-gate-only), byte-identical to today.
- **No spec/PR/ADR/task citations in code comments** (CI lint `check-no-spec-refs-in-comments` fails on `Task N`/`Plan N`/`ADR-`/`#NNN`). Reasoning stays in this doc.
- **Merge-order note:** keep the `up.rs` and `synthesize_plan` edits additive to minimize conflict with in-flight `ExecutionPlan`-field PRs (#1359/#1360/#1361). This plan does not touch `execution_plan.rs` at all.
- **Docs upkeep on completion:** tick Plan 217 in `specs/REFACTOR-STATUS.md` + reflect in `specs/SPRINT.md` in the same change.

---

### Task 1: Canonical ProdSafe verb list in mvm-guest

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs` (add `prod_safe_verb_names` near `kind_name`/`class`, around `:555`–`:844`; add a guard test in the existing `#[cfg(test)]` block near the classification tests at `:5578`/`:5915`)

**Interfaces:**
- Produces: `pub fn prod_safe_verb_names() -> &'static [&'static str]` — the `kind_name()` kebab strings of every `GuestRequest` variant that classifies `RequestClass::ProdSafe`.

- [ ] **Step 1: Read the existing enumeration.** Read `kind_name_covers_every_variant` (`vsock.rs:5915`) and the classification test at `:5578` to see how the test suite constructs one of every `GuestRequest` variant and reads `.class()` / `.kind_name()`. You will reuse that exact enumeration in the guard test below — do not invent a new one.

- [ ] **Step 2: Write the failing guard test**

```rust
// crates/mvm-guest/src/vsock.rs  (in the #[cfg(test)] mod, beside the classification tests)
#[test]
fn prod_safe_verb_names_matches_classification() {
    // Reuse the same every-variant enumeration the classification test uses
    // (see kind_name_covers_every_variant): for each constructed variant,
    // its kind_name() is in prod_safe_verb_names() IFF class() == ProdSafe.
    let listed: std::collections::BTreeSet<&str> =
        prod_safe_verb_names().iter().copied().collect();
    for req in every_guest_request_variant() {          // <- the existing helper the classification test uses
        let name = req.kind_name();
        let is_prod = matches!(req.class(), RequestClass::ProdSafe);
        assert_eq!(
            listed.contains(name), is_prod,
            "{name}: listed={} but class ProdSafe={}", listed.contains(name), is_prod
        );
    }
    // No duplicates, all non-empty.
    assert_eq!(listed.len(), prod_safe_verb_names().len(), "duplicate in prod_safe_verb_names");
    assert!(prod_safe_verb_names().iter().all(|n| !n.is_empty()));
}
```

> If the existing test constructs variants inline rather than via a shared `every_guest_request_variant()` helper, factor that construction into such a helper (or copy the same list of constructed variants) so both tests share one enumeration. Name it to match what's already there if a helper exists.

- [ ] **Step 3: Run test to verify it fails**

Run: `~/.cargo/bin/cargo nextest run -p mvm-guest prod_safe_verb_names`
Expected: FAIL — `prod_safe_verb_names` undefined.

- [ ] **Step 4: Implement**

```rust
// crates/mvm-guest/src/vsock.rs (near kind_name / class)
/// The kebab `kind_name()`s of every ProdSafe control verb — the candidate
/// members of an `agent_verbs` grant. Single source of truth; the
/// classification guard test keeps it in lockstep with `class()`.
pub fn prod_safe_verb_names() -> &'static [&'static str] {
    &[
        "protocol-hello", "ping", "readiness-status",
        "worker-status", "sleep-prep", "wake",
        "integration-status", "checkpoint-integrations", "probe-status",
        "primed-status", "post-restore", "entrypoint-status",
        "run-entrypoint", "mount-volume", "unmount-volume", "update-idle-timeout",
    ]
}
```

> This list must EXACTLY equal the set the guard test derives from `class()`. If the test fails because a verb is missing/extra/misspelled, fix THIS list (it is the source of truth being validated), not the test. Confirm each string against `kind_name()` (`:555`).

- [ ] **Step 5: Run test to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-guest prod_safe_verb_names`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-guest/src/vsock.rs
git commit -m "feat(guest): canonical prod_safe_verb_names list guarded against class()"
```

---

### Task 2: `default_agent_verbs` + CLI verb parsing/validation in mvm-cli

**Files:**
- Create: `crates/mvm-cli/src/commands/vm/agent_verbs.rs` (+ `mod agent_verbs;` in the parent `mod.rs`)
- Test: inline `#[cfg(test)]` in that file

**Interfaces:**
- Consumes: `mvm_core::plan::VerbId`, `mvm_guest::vsock::prod_safe_verb_names` (Task 1).
- Produces:
  - `pub fn default_agent_verbs(is_sealed_prod: bool, has_shares: bool) -> Option<Vec<VerbId>>`
  - `pub fn parse_agent_verb_override(raw: &[String]) -> Result<Option<Vec<VerbId>>>` — validates each against `prod_safe_verb_names()`; returns `Ok(None)` for an empty slice; `Err` (listing valid verbs) for any unknown/non-ProdSafe/malformed value.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/mvm-cli/src/commands/vm/agent_verbs.rs  (bottom)
#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &Option<Vec<VerbId>>) -> Vec<String> {
        v.as_ref().map(|s| s.iter().map(|x| x.as_str().to_string()).collect()).unwrap_or_default()
    }

    #[test]
    fn dev_gets_no_restriction() {
        assert_eq!(default_agent_verbs(false, false), None);
        assert_eq!(default_agent_verbs(false, true), None);
    }

    #[test]
    fn prod_without_shares_drops_volume_verbs_keeps_lifecycle_and_entrypoint() {
        let set = default_agent_verbs(true, false).unwrap();
        let s: Vec<&str> = set.iter().map(|v| v.as_str()).collect();
        assert!(s.contains(&"run-entrypoint"));
        assert!(s.contains(&"readiness-status"));
        assert!(s.contains(&"wake"));            // host-lifecycle stays
        assert!(!s.contains(&"mount-volume"));   // attenuated: no shares
        assert!(!s.contains(&"unmount-volume"));
    }

    #[test]
    fn prod_with_shares_includes_mount() {
        let set = default_agent_verbs(true, true).unwrap();
        assert!(set.iter().any(|v| v.as_str() == "mount-volume"));
    }

    #[test]
    fn default_never_contains_a_devonly_verb() {
        // "exec"/"fs-read"/"proc-start" are DevOnly kind_names — none may appear.
        let set = default_agent_verbs(true, true).unwrap();
        for banned in ["exec", "fs-read", "proc-start", "console-open"] {
            assert!(!set.iter().any(|v| v.as_str() == banned), "{banned} leaked into default");
        }
    }

    #[test]
    fn override_parses_valid_and_rejects_unknown_and_empty() {
        assert_eq!(parse_agent_verb_override(&[]).unwrap(), None);
        let ok = parse_agent_verb_override(&["run-entrypoint".into(), "ping".into()]).unwrap().unwrap();
        assert_eq!(ok.iter().map(|v| v.as_str()).collect::<Vec<_>>(), ["run-entrypoint", "ping"]);
        assert!(parse_agent_verb_override(&["exec".into()]).is_err());        // DevOnly rejected
        assert!(parse_agent_verb_override(&["not-a-verb".into()]).is_err());  // unknown rejected
        assert!(parse_agent_verb_override(&["BAD".into()]).is_err());         // not kebab
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `~/.cargo/bin/cargo nextest run -p mvm-cli agent_verbs`
Expected: FAIL — module/functions absent.

- [ ] **Step 3: Implement**

```rust
// crates/mvm-cli/src/commands/vm/agent_verbs.rs  (top)
use anyhow::{Context, Result, bail};
use mvm_core::plan::VerbId;
use mvm_guest::vsock::prod_safe_verb_names;

/// Compute the default agent-verb set for a workload.
/// - Non-sealed-prod (dev) → `None` (class-gate-only; unchanged behavior).
/// - Sealed-prod → all ProdSafe verbs, minus the volume verbs when the
///   workload declares no shares (the only safe per-workload attenuation;
///   host-lifecycle verbs stay so pause/resume/snapshot/pooling never break).
pub fn default_agent_verbs(is_sealed_prod: bool, has_shares: bool) -> Option<Vec<VerbId>> {
    if !is_sealed_prod {
        return None;
    }
    let set = prod_safe_verb_names()
        .iter()
        .filter(|n| has_shares || (**n != "mount-volume" && **n != "unmount-volume"))
        .map(|n| VerbId::new(n).expect("prod_safe_verb_names entries are valid kebab verbs"))
        .collect();
    Some(set)
}

/// Validate CLI `--agent-verb` values into an override set. Empty ⇒ `None`
/// (use the computed default). Any value that is not a known ProdSafe verb
/// (unknown, DevOnly, or malformed) is a hard error.
pub fn parse_agent_verb_override(raw: &[String]) -> Result<Option<Vec<VerbId>>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let allowed: std::collections::BTreeSet<&str> = prod_safe_verb_names().iter().copied().collect();
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let v = VerbId::new(r).with_context(|| format!("invalid --agent-verb '{r}'"))?;
        if !allowed.contains(v.as_str()) {
            bail!(
                "unknown or non-production --agent-verb '{r}'; valid verbs: {}",
                prod_safe_verb_names().join(", ")
            );
        }
        out.push(v);
    }
    Ok(Some(out))
}
```

Add `mod agent_verbs;` (and `pub use` if the parent module re-exports siblings) to `crates/mvm-cli/src/commands/vm/mod.rs`.

- [ ] **Step 4: Run to verify it passes**

Run: `~/.cargo/bin/cargo nextest run -p mvm-cli agent_verbs`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/agent_verbs.rs crates/mvm-cli/src/commands/vm/mod.rs
git commit -m "feat(cli): default_agent_verbs + --agent-verb override parsing"
```

---

### Task 3: Wire the flag + default into `mvmctl up` synthesis

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up.rs` — add the `--agent-verb` arg to the `Args` struct (near `network_allow` at `:947`); at the `SynthesisInput { … }` construction (`:430`), set `agent_verbs = parse_agent_verb_override(&args.agent_verb)? .or_else(|| default_agent_verbs(is_sealed_prod, !shares.is_empty()))`.
- Test: extend the existing `up.rs` synthesis tests (the ones building `SynthesisInput` at `:2150`/`:2252`/…), or add a focused test.

**Interfaces:**
- Consumes: `default_agent_verbs`, `parse_agent_verb_override` (Task 2); the existing `SynthesisInput.agent_verbs` field (from #1380).
- Produces: a populated `ExecutionPlan.agent_verbs` for `mvmctl up`.

- [ ] **Step 1: Ground the sealed-prod signal.** Grep how `up.rs` resolves prod vs dev today: `grep -n "security_profile\|AgentProfile\|SealedProd\|is_prod\|dev_mode" crates/mvm-cli/src/commands/vm/up.rs`. If there is an already-resolved `AgentProfile`/`AdmissionProfile`, derive `is_sealed_prod` from it (`== AgentProfile::SealedProd`). Otherwise use `args.security_profile.as_deref() != Some("dev")` (production is the default per `--security-profile` at `:954`). Record which you used.

- [ ] **Step 2: Write the failing test**

```rust
// crates/mvm-cli/src/commands/vm/up.rs  (in the #[cfg(test)] mod, mirroring the existing SynthesisInput synthesis tests)
#[test]
fn up_populates_agent_verbs_default_and_override() {
    use crate::commands::vm::agent_verbs::{default_agent_verbs, parse_agent_verb_override};
    // Default path: sealed-prod, no shares → mount-volume attenuated, run-entrypoint present.
    let d = parse_agent_verb_override(&[]).unwrap()
        .or_else(|| default_agent_verbs(true, false)).unwrap();
    assert!(d.iter().any(|v| v.as_str() == "run-entrypoint"));
    assert!(!d.iter().any(|v| v.as_str() == "mount-volume"));
    // Override path: explicit set replaces the default.
    let o = parse_agent_verb_override(&["run-entrypoint".into()]).unwrap()
        .or_else(|| default_agent_verbs(true, false)).unwrap();
    assert_eq!(o.iter().map(|v| v.as_str()).collect::<Vec<_>>(), ["run-entrypoint"]);
    // Dev path: None (class-gate only).
    assert!(parse_agent_verb_override(&[]).unwrap().or_else(|| default_agent_verbs(false, false)).is_none());
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `~/.cargo/bin/cargo nextest run -p mvm-cli up_populates_agent_verbs`
Expected: FAIL (until the `use` path + wiring compile).

- [ ] **Step 4: Implement the Arg + wiring**

Add to the `Args` struct near `network_allow` (`up.rs:947`):

```rust
    /// Restrict the guest agent to these control verbs (repeatable). Overrides
    /// the computed sealed-prod default. Values must be production-safe verbs.
    #[arg(long = "agent-verb", value_name = "VERB")]
    pub agent_verb: Vec<String>,
```

At the `SynthesisInput { … }` construction (`:430`), compute and set the field (replace the current `agent_verbs: None` if #1380 left it `None` there):

```rust
        agent_verbs: crate::commands::vm::agent_verbs::parse_agent_verb_override(&args.agent_verb)?
            .or_else(|| crate::commands::vm::agent_verbs::default_agent_verbs(
                is_sealed_prod,           // resolved in Step 1
                !shares.is_empty(),       // the shares vec already built above
            )),
```

Leave the test-only `SynthesisInput` constructions (`:2150` etc.) at `agent_verbs: None` unless a test specifically exercises population.

- [ ] **Step 5: Run + build**

Run: `~/.cargo/bin/cargo nextest run -p mvm-cli up_populates_agent_verbs agent_verbs && ~/.cargo/bin/cargo build -p mvm-cli`
Expected: PASS + builds.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/up.rs
git commit -m "feat(cli): populate ExecutionPlan.agent_verbs from --agent-verb or computed default"
```

---

## Full-suite gate (after the last task)

- [ ] `~/.cargo/bin/cargo fmt --all -- --check`
- [ ] `~/.cargo/bin/cargo check --workspace --all-targets` (catches any `SynthesisInput` site left unset)
- [ ] `~/.cargo/bin/cargo nextest run -p mvm-guest -p mvm-cli`
- [ ] `~/.cargo/bin/cargo clippy -p mvm-guest -p mvm-cli --all-targets -- -D warnings`
- [ ] If any host↔guest wire type changed (it should NOT here — this is synthesis-side): `cargo run -p xtask -- check-stubs`. Not expected to drift.
- [ ] Update `specs/REFACTOR-STATUS.md` + `specs/SPRINT.md`.

## Self-Review

- **Spec coverage:** C-refined design = Task 1 (source-of-truth list) + Task 2 (computed default `None`-for-dev / minimal-for-prod, + CLI validation) + Task 3 (override ?? default wired into synthesis). Conservative default (lifecycle always in, only mount-volume gated on shares) = Task 2 `default_agent_verbs`. Override mirrors `--network-allow` = Task 3. Dev unaffected = `default_agent_verbs(false, _) == None`, tested. Subtractive enforcement unchanged = not touched (correct — it's already in the guest).
- **Placeholders:** the Step-1 grounding notes ("grep how up.rs resolves prod/dev", "reuse the every-variant enumeration") are explicit read-first instructions, not hand-waving; all new code is fully specified.
- **Type consistency:** `default_agent_verbs(bool, bool) -> Option<Vec<VerbId>>`, `parse_agent_verb_override(&[String]) -> Result<Option<Vec<VerbId>>>`, `prod_safe_verb_names() -> &'static [&'static str]`, `VerbId::{new,as_str}` — used identically across tasks.
- **Dependency:** every task assumes #1380's `VerbId` + `agent_verbs` field exist; the Global Constraints gate stops the implementer if they don't.
