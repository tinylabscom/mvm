# Plan 205 — Builder residency Step 1 (policy-driven routing + observability) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make `MVM_RESIDENCY` reach the builder VM end-to-end for the warm/cold axis: `cold` opts builds out of the persistent builder (ephemeral, torn down after the build), `warm`/`parked` keep using it (today's default), and the builder's residency is observable in `mvmctl doctor`. This is the clean, no-live-VM half; the live-coupled mechanism (auto-start, idle keeper, snapshot-park) is Step 2 (a separate tracked plan).

**Architecture:** `mvm-core::residency::ResidencyPolicy` gains a typed `kind` (`Warm|Parked|Cold`) and `allows_persistent_builder()` (false only for `Cold`). The builder routing chokepoint in `dev_build.rs` already chooses persistent-vs-ephemeral; it gains one guard so `Cold` skips the persistent path (= the existing `--no-persistent-builder` behavior, which boots a single-shot builder and tears it down). `mvmctl doctor` gains a `builder residency` line reporting the policy's builder effect and whether a persistent session is live.

**Tech Stack:** Rust (`mvm-core` policy + `mvm-build` routing + `mvm-cli` doctor), unit tests only — no live VM.

## Global Constraints

- No placeholders. No spec/PR/ADR citations in code comments (`xtask check-no-spec-refs-in-comments`).
- `mvm-core` stays runtime-free (`xtask check-core-runtime-free`); only `std`.
- `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo nextest run -p <crate>`.
- `#[allow(clippy::too_many_arguments)]` banned.
- **Additive only:** `ResidencyPolicy`'s existing accessors (`warm_target`/`idle_timeout`/`label`) and the WS-B consumers (`effective_warm_pool_size`, the `residency` doctor line) must not change behavior. Adding the `kind` field + accessor is additive.
- **Default behavior preserved:** only `MVM_RESIDENCY=cold` may change builder routing. `warm` and `parked` (the auto-detect defaults) must route exactly as today.

## Out of scope / deferred (Step 2 — separate plan)

- Builder VM **snapshot-park** (vz saved-state into the builder boot path) — `parked` degrades to "use persistent" (same as warm) until this lands.
- Builder **idle-timeout keeper** (cross-process demotion daemon).
- `dev up` **auto-start** of a persistent builder when `warm` and none is active.
- Actively **tearing down a running** persistent builder when the policy flips to `cold` mid-session (Step 1 only changes routing for new builds; it does not kill a running session).

## File Structure

- Modify `crates/mvm-core/src/residency.rs` — `ResidencyKind` + `kind`/`allows_persistent_builder` (Task 1).
- Modify `crates/mvm-build/src/pipeline/dev_build.rs` — the routing guard + a testable helper (Task 2).
- Modify `crates/mvm-cli/src/doctor.rs` — `builder_residency_check()` (Task 3).

---

### Task 1: `ResidencyKind` + `allows_persistent_builder`

**Files:**
- Modify: `crates/mvm-core/src/residency.rs` (struct at line 14, constructors at 22/30/38, accessors after `label` at ~52)

**Interfaces:**
- Produces: `pub enum ResidencyKind { Warm, Parked, Cold }`; `ResidencyPolicy::kind(&self) -> ResidencyKind`; `ResidencyPolicy::allows_persistent_builder(&self) -> bool`. Tasks 2–3 consume them.

- [ ] **Step 1: Write the failing tests** (in the `#[cfg(test)] mod tests` of `residency.rs`)

```rust
    #[test]
    fn kind_matches_constructor() {
        assert_eq!(ResidencyPolicy::always_warm().kind(), ResidencyKind::Warm);
        assert_eq!(ResidencyPolicy::parked().kind(), ResidencyKind::Parked);
        assert_eq!(ResidencyPolicy::cold().kind(), ResidencyKind::Cold);
    }

    #[test]
    fn only_cold_disallows_the_persistent_builder() {
        assert!(ResidencyPolicy::always_warm().allows_persistent_builder());
        assert!(ResidencyPolicy::parked().allows_persistent_builder());
        assert!(!ResidencyPolicy::cold().allows_persistent_builder());
    }
```

Run: `cargo test -p mvm-core residency::tests::kind_matches_constructor`
Expected: FAIL — `ResidencyKind` / `kind` / `allows_persistent_builder` undefined.

- [ ] **Step 2: Implement**

Add the enum near `ResidencySource`:

```rust
/// Which residency a policy expresses — the typed discriminant behind the three
/// constructors, so callers branch on intent rather than the display label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencyKind {
    Warm,
    Parked,
    Cold,
}
```

Add a `kind: ResidencyKind` field to `ResidencyPolicy` (after `label`), set it in each constructor (`always_warm` → `Warm`, `parked` → `Parked`, `cold` → `Cold`), and add the accessors in the `impl ResidencyPolicy` block:

```rust
    pub fn kind(&self) -> ResidencyKind {
        self.kind
    }

    /// Whether builds may use (and keep) the persistent builder VM under this
    /// policy. Only `Cold` opts out — it routes builds through the single-shot
    /// builder that boots and tears down per build.
    pub fn allows_persistent_builder(&self) -> bool {
        !matches!(self.kind, ResidencyKind::Cold)
    }
```

Run: `cargo test -p mvm-core residency`
Expected: PASS (all residency tests, old + 2 new).

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-core --all-targets -- -D warnings
cargo run -p xtask -- check-core-runtime-free
git add crates/mvm-core/src/residency.rs
git commit -m "feat(plan-205): ResidencyKind + allows_persistent_builder (builder residency step 1)"
```

---

### Task 2: route `cold` to the ephemeral builder

The chokepoint (`dev_build.rs` ~line 595) routes to the persistent builder when `!persistent_dispatch_disabled() && read_active_session().is_some()`. Add a residency guard so `Cold` skips it.

**Files:**
- Modify: `crates/mvm-build/src/pipeline/dev_build.rs` (the `dev_build` routing block ~585–620; add the helper + its test near `persistent_dispatch_disabled` ~630)

**Interfaces:**
- Consumes: `mvm_core::residency::{resolve_residency, ResidencyPolicy}` (Task 1's `allows_persistent_builder`).
- Produces: `fn persistent_routing_allowed(policy: &ResidencyPolicy, dispatch_disabled: bool) -> bool`.

- [ ] **Step 1: Write the failing test** (in `dev_build.rs`'s `#[cfg(test)]` module; if none under the `builder-vm` feature, add one gated the same way `persistent_dispatch_disabled` is)

```rust
    #[test]
    fn persistent_routing_blocked_by_cold_or_opt_out() {
        use mvm_core::residency::ResidencyPolicy;
        // warm/parked + not opted out → allowed
        assert!(persistent_routing_allowed(&ResidencyPolicy::always_warm(), false));
        assert!(persistent_routing_allowed(&ResidencyPolicy::parked(), false));
        // cold → blocked even when not opted out
        assert!(!persistent_routing_allowed(&ResidencyPolicy::cold(), false));
        // explicit opt-out always blocks
        assert!(!persistent_routing_allowed(&ResidencyPolicy::always_warm(), true));
    }
```

Run: `cargo test -p mvm-build persistent_routing_blocked_by_cold_or_opt_out`
Expected: FAIL — `persistent_routing_allowed` undefined.

- [ ] **Step 2: Implement the helper + wire the predicate**

Add beside `persistent_dispatch_disabled` (same `#[cfg(feature = "builder-vm")]` gate):

```rust
/// Whether a build may route to the persistent builder: the user has not opted
/// out (`MVM_NO_PERSISTENT_BUILDER`) and the residency policy is not `cold`
/// (cold builds boot a single-shot builder that tears down per build).
#[cfg(feature = "builder-vm")]
fn persistent_routing_allowed(policy: &mvm_core::residency::ResidencyPolicy, dispatch_disabled: bool) -> bool {
    !dispatch_disabled && policy.allows_persistent_builder()
}
```

Change the routing block (the `if !persistent_dispatch_disabled() && let Some(record) = read_active_session()`) to resolve the policy and call the helper:

```rust
    let residency = mvm_core::residency::resolve_residency().0;
    if persistent_routing_allowed(&residency, persistent_dispatch_disabled())
        && let Some(record) = crate::persistent_builder::read_active_session()
    {
        tracing::info!(
            session_id = %record.session_id,
            socket = %record.dispatch_socket_path.display(),
            "routing build through persistent supervisor"
        );
        let persistent = crate::persistent_builder::PersistentBuilderVm::new(record.clone());
        match dev_build_with_builder_vm(env, flake_ref, profile, mode, &persistent) {
            Ok(result) => return Ok(result),
            Err(e) => {
                tracing::warn!(error = %e, "persistent dispatch failed; falling back to single-shot builder VM");
            }
        }
    } else if !residency.allows_persistent_builder()
        && crate::persistent_builder::read_active_session().is_some()
    {
        tracing::info!("MVM_RESIDENCY=cold: skipping the active persistent builder; booting a single-shot builder");
    }
```

(Keep the existing single-shot fall-through below unchanged. The `else if` branch is only an observability log when cold bypasses a live session; if it complicates the borrow of `residency`, drop it and keep just the guarded `if` — the behavior is what matters, the log is a nicety.)

Run: `cargo test -p mvm-build persistent_routing_blocked_by_cold_or_opt_out`
Expected: PASS. Then `cargo nextest run -p mvm-build -E 'test(persistent) or test(dev_build) or test(routing)'` to confirm no regression.

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-build --all-targets -- -D warnings
git add crates/mvm-build/src/pipeline/dev_build.rs
git commit -m "feat(plan-205): MVM_RESIDENCY=cold routes builds to the ephemeral builder (step 1)"
```

---

### Task 3: `mvmctl doctor` builder-residency line

Report the residency policy's builder effect and whether a persistent builder session is live. Mirror `builder_backend_check` (`doctor.rs` — feature-gated `#[cfg(feature = "builder-vm")]`) and `residency_check` (the WS-B workload line). This is a SEPARATE line from the WS-B `residency` line.

**Files:**
- Modify: `crates/mvm-cli/src/doctor.rs` (add `builder_residency_check()`; push it next to `builder_backend_check`)

**Interfaces:**
- Consumes: `mvm_core::residency::resolve_residency`, `mvm_build::persistent_builder::read_active_session`, the `Check` struct.

- [ ] **Step 1: Write the failing test** (in `doctor.rs`'s `#[cfg(test)]` module)

```rust
    #[test]
    fn builder_residency_check_reports_policy_and_session_state() {
        let c = builder_residency_check();
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        assert!(c.info.contains("persistent builder"), "info was {:?}", c.info);
        // names the builder routing effect
        assert!(
            c.info.contains("uses persistent") || c.info.contains("ephemeral"),
            "info was {:?}", c.info
        );
    }
```

Run: `cargo test -p mvm-cli builder_residency_check_reports_policy_and_session_state`
Expected: FAIL — `builder_residency_check` undefined.

- [ ] **Step 2: Implement** (gate `#[cfg(feature = "builder-vm")]` to match `builder_backend_check`; verify the test compiles under the test feature set — if the doctor tests don't build with `builder-vm`, gate the test the same way)

```rust
#[cfg(feature = "builder-vm")]
fn builder_residency_check() -> Check {
    let (policy, _source) = mvm_core::residency::resolve_residency();
    let routing = if policy.allows_persistent_builder() {
        "uses persistent when active"
    } else {
        "ephemeral per build (cold)"
    };
    let session = if mvm_build::persistent_builder::read_active_session().is_some() {
        "persistent builder active"
    } else {
        "no persistent builder"
    };
    Check {
        name: "builder residency",
        category: "platform",
        ok: true,
        info: format!("{} — builds {} — {}", policy.label(), routing, session),
    }
}
```

Push it next to `builder_backend_check` (same `#[cfg(feature = "builder-vm")]` region):

```rust
    checks.push(builder_residency_check());
```

Run: `cargo test -p mvm-cli builder_residency_check_reports_policy_and_session_state`
Expected: PASS. (The doctor reads no live VM — `read_active_session` returns `None` in a clean test env.)

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-cli --all-targets -- -D warnings
cargo nextest run -p mvm-cli -E 'test(builder_residency) or test(residency_check)'
git add crates/mvm-cli/src/doctor.rs
git commit -m "feat(plan-205): doctor reports builder residency (policy + persistent session) (step 1)"
```

---

## Step 2 (deferred — separate tracked plan)

Builder VM snapshot-park (vz saved-state into the builder boot path), the idle-timeout keeper daemon, `dev up` auto-start of a warm persistent builder, and active teardown of a running session when the policy is cold. All live-coupled; validated on a macOS-26 box, gated like the Plan 118/159 live lanes.

## Self-Review

- **Coverage:** `cold` opts out of the persistent builder (Task 2, guarded by Task 1's `allows_persistent_builder`); `warm`/`parked` unchanged; the builder residency is observable (Task 3). The live mechanism is explicitly Step 2.
- **Default preserved:** only `Cold` flips routing; `Warm`/`Parked` (the auto-detect defaults) keep `persistent_routing_allowed == true`, so behavior is unchanged unless a user sets `MVM_RESIDENCY=cold`.
- **Placeholders:** none — real Rust + commands; the `else if` log is marked optional.
- **Type consistency:** `ResidencyKind`, `kind()`, `allows_persistent_builder()`, `persistent_routing_allowed`, `builder_residency_check` used identically across tasks.
