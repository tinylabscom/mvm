# Plan 205 Workstream B — Residency policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ADR-090's residency slider a real, resolvable, observable policy — one knob (`warm_min` + `idle_timeout`) resolved from an env override or a per-host default — and feed it into the existing warm-pool size and `mvmctl doctor`. The *mechanism* that demotes idle warm standbys to parked snapshots is WS-D; WS-B is the policy and its observability.

**Architecture:** A pure `ResidencyPolicy` value type in `mvm-core` with a `resolve()` that reads `MVM_RESIDENCY` then falls back to a per-host default (macOS-26 Apple Silicon → always-warm; everything else, incl. CI/Linux → parked), reporting which source won. The existing `VmStartConfig.warm_pool_size` default is sourced from the policy's `warm_target()`, so `min ≥ 1` actually keeps the pool warm. `mvmctl doctor` gains a `residency` line mirroring the `builder backend` line, so the resolved policy and its source are observable.

**Tech Stack:** Rust (`mvm-core` value type + `mvm-cli` doctor), unit tests only — no live VM.

## Global Constraints

- No placeholders. No spec/PR/ADR citations in code comments (a CI lint gate forbids them; `xtask check-no-spec-refs-in-comments`).
- `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo nextest run -p <crate>` green.
- `#[allow(clippy::too_many_arguments)]` is banned in hand-written code.
- `mvm-core` default build must stay runtime-free (no `tokio`); this work adds none (`xtask check-core-runtime-free` gate). Use `std::time::Duration` only.
- All env-overridable settings follow the `mvm_core::config` pattern: read the `MVM_*` var, trim, empty → fall through; unrecognised value → log a warning and fall through to auto-detect (mirror `MVM_BUILDER_BACKEND`).
- Per-host detection reuses `mvm_core::platform::Platform` — do NOT hand-roll OS sniffing.

## Out of scope / deferred (tracked, not built here)

- **Idle→parked demotion mechanism** (reaper marks an idle warm standby parked + snapshots it): WS-D, because it needs the vz/FC snapshot park/resume primitives. WS-B carries the `idle_timeout` *value* and reports it; nothing demotes on it yet.
- **Snapshot park/resume wiring** (`vz::snapshot_save`/`snapshot_restore`): WS-D.
- Per-tenant residency overrides: not needed for the single-user local case; revisit if the fleet needs it.

## File Structure

- Create `crates/mvm-core/src/residency.rs` — the `ResidencyPolicy` value type + `resolve()` (Task 1).
- Modify `crates/mvm-core/src/lib.rs` — `pub mod residency;` (Task 1).
- Modify the site that defaults `VmStartConfig.warm_pool_size` — source it from the policy (Task 2; implementer locates via grep).
- Modify `crates/mvm-cli/src/doctor.rs` — add `residency_check()` and push it (Task 3).

---

### Task 1: `ResidencyPolicy` value type + resolution

**Files:**
- Create: `crates/mvm-core/src/residency.rs`
- Modify: `crates/mvm-core/src/lib.rs` (add `pub mod residency;` next to the other `pub mod` lines)

**Interfaces:**
- Consumes: `mvm_core::platform::Platform` — specifically `Platform::current().is_vz_default_tier()` (true on macOS 26+ Apple Silicon), per `crates/mvm-core/src/platform/platform.rs:85`.
- Produces: `ResidencyPolicy`, `ResidencySource`, `pub fn resolve_residency() -> (ResidencyPolicy, ResidencySource)`, and `ResidencyPolicy::{warm_target, idle_timeout, label}`. Task 2 consumes `warm_target()`; Task 3 consumes all of it.

- [ ] **Step 1: Write the failing tests**

Create `crates/mvm-core/src/residency.rs` with the test module first:

```rust
//! Residency policy: how warm the standby pool is kept. One knob — a warm
//! target plus an idle timeout — resolved from `MVM_RESIDENCY` or a per-host
//! default. The demotion-on-idle mechanism lives elsewhere; this module only
//! resolves and describes the policy.

use std::time::Duration;

pub const MVM_RESIDENCY_ENV: &str = "MVM_RESIDENCY";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_warm_keeps_one_warm_with_idle_timeout() {
        let p = ResidencyPolicy::always_warm();
        assert_eq!(p.warm_target(), 1);
        assert_eq!(p.idle_timeout(), Some(Duration::from_secs(20 * 60)));
        assert_eq!(p.label(), "always-warm");
    }

    #[test]
    fn parked_holds_no_warm_and_no_idle_timer() {
        let p = ResidencyPolicy::parked();
        assert_eq!(p.warm_target(), 0);
        assert_eq!(p.idle_timeout(), None);
        assert_eq!(p.label(), "parked");
    }

    #[test]
    fn cold_holds_no_warm() {
        assert_eq!(ResidencyPolicy::cold().warm_target(), 0);
        assert_eq!(ResidencyPolicy::cold().label(), "cold");
    }

    #[test]
    fn env_override_wins_case_insensitive() {
        assert_eq!(parse_env_residency("warm"), Some(ResidencyPolicy::always_warm()));
        assert_eq!(parse_env_residency("  PARKED "), Some(ResidencyPolicy::parked()));
        assert_eq!(parse_env_residency("Cold"), Some(ResidencyPolicy::cold()));
    }

    #[test]
    fn unrecognised_or_empty_env_is_none() {
        assert_eq!(parse_env_residency(""), None);
        assert_eq!(parse_env_residency("hot"), None);
    }

    #[test]
    fn host_default_is_warm_on_vz_tier_parked_otherwise() {
        assert_eq!(host_default_for(true), ResidencyPolicy::always_warm());
        assert_eq!(host_default_for(false), ResidencyPolicy::parked());
    }
}
```

Run: `cargo test -p mvm-core residency 2>&1 | head`
Expected: FAIL to compile — `ResidencyPolicy`, `parse_env_residency`, `host_default_for` undefined.

- [ ] **Step 2: Implement to green**

Add above the test module:

```rust
/// How warm the standby pool is kept. `warm_target` standbys are held live;
/// `idle_timeout`, when set, is how long a warm standby may sit idle before it
/// is eligible for demotion to a parked snapshot (demotion handled elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidencyPolicy {
    warm_target: u32,
    idle_timeout: Option<Duration>,
    label: &'static str,
}

impl ResidencyPolicy {
    /// Keep one standby warm; demote to parked after 20 minutes idle.
    pub fn always_warm() -> Self {
        Self { warm_target: 1, idle_timeout: Some(Duration::from_secs(20 * 60)), label: "always-warm" }
    }
    /// Hold nothing warm; resume from a parked snapshot on demand.
    pub fn parked() -> Self {
        Self { warm_target: 0, idle_timeout: None, label: "parked" }
    }
    /// Hold nothing warm and keep no snapshot; cold-boot on demand.
    pub fn cold() -> Self {
        Self { warm_target: 0, idle_timeout: None, label: "cold" }
    }

    pub fn warm_target(&self) -> u32 {
        self.warm_target
    }
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }
    pub fn label(&self) -> &'static str {
        self.label
    }
}

/// Where a resolved policy came from — for observability in `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencySource {
    EnvOverride,
    AutoDetect,
}

fn parse_env_residency(raw: &str) -> Option<ResidencyPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "warm" | "always-warm" => Some(ResidencyPolicy::always_warm()),
        "parked" => Some(ResidencyPolicy::parked()),
        "cold" => Some(ResidencyPolicy::cold()),
        _ => None,
    }
}

fn host_default_for(is_vz_default_tier: bool) -> ResidencyPolicy {
    if is_vz_default_tier {
        ResidencyPolicy::always_warm()
    } else {
        ResidencyPolicy::parked()
    }
}

/// Resolve the active policy: `MVM_RESIDENCY` if set to a known value, else the
/// per-host default. Returns the policy and which source decided it.
pub fn resolve_residency() -> (ResidencyPolicy, ResidencySource) {
    if let Ok(raw) = std::env::var(MVM_RESIDENCY_ENV)
        && !raw.trim().is_empty()
    {
        if let Some(p) = parse_env_residency(&raw) {
            return (p, ResidencySource::EnvOverride);
        }
        eprintln!(
            "[mvm] warning: unrecognised {MVM_RESIDENCY_ENV}={raw:?} (expected warm|parked|cold); using auto-detect"
        );
    }
    let is_tier = crate::platform::Platform::current().is_vz_default_tier();
    (host_default_for(is_tier), ResidencySource::AutoDetect)
}
```

Add `pub mod residency;` to `crates/mvm-core/src/lib.rs` beside the other `pub mod` declarations.

Run: `cargo test -p mvm-core residency`
Expected: PASS (6 tests).

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-core --all-targets -- -D warnings
cargo run -p xtask -- check-core-runtime-free
git add crates/mvm-core/src/residency.rs crates/mvm-core/src/lib.rs
git commit -m "feat(plan-205): ResidencyPolicy value type + per-host resolution (WS-B)"
```

---

### Task 2: Source the warm-pool default from the residency policy

Today `VmStartConfig.warm_pool_size` defaults to `0` (`crates/mvm-core/src/protocol/vm_backend.rs:120`). WS-B makes an *unset* warm-pool size fall back to the resolved policy's `warm_target()`, so `MVM_RESIDENCY=warm` actually keeps a standby warm.

**Files:**
- Modify: `crates/mvm-core/src/residency.rs` (add the resolver helper + test)
- Modify: the single site that decides the effective `warm_pool_size` when none is explicitly requested — locate it with `rg 'warm_pool_size' crates/` and read the call sites; the default/CLI path that sets it from `0` is the one to adopt the helper (do NOT change the `VmStartConfig` field default itself — keep `0` as "unset" sentinel).

**Interfaces:**
- Consumes: `ResidencyPolicy::warm_target` (Task 1).
- Produces: `pub fn effective_warm_pool_size(explicit: Option<u32>) -> u32`.

- [ ] **Step 1: Write the failing test** (in `residency.rs` test module)

```rust
    #[test]
    fn explicit_warm_pool_size_overrides_policy() {
        assert_eq!(effective_warm_pool_size(Some(3)), 3);
        assert_eq!(effective_warm_pool_size(Some(0)), 0);
    }
```

Run: `cargo test -p mvm-core residency::tests::explicit_warm_pool_size_overrides_policy`
Expected: FAIL — `effective_warm_pool_size` undefined.

- [ ] **Step 2: Implement**

In `residency.rs`:

```rust
/// The warm-pool size to use: an explicit request wins; otherwise the resolved
/// residency policy's warm target.
pub fn effective_warm_pool_size(explicit: Option<u32>) -> u32 {
    match explicit {
        Some(n) => n,
        None => resolve_residency().0.warm_target(),
    }
}
```

Run: `cargo test -p mvm-core residency::tests::explicit_warm_pool_size_overrides_policy`
Expected: PASS.

- [ ] **Step 3: Adopt at the call site**

`rg 'warm_pool_size' crates/ -l` to find where the CLI/up path sets `VmStartConfig.warm_pool_size`. At the site where it is currently set from an explicit flag-or-zero, route it through `mvm_core::residency::effective_warm_pool_size(explicit_flag)`. If the flag is absent, pass `None`. Read the surrounding code first; if the only consumer is a test/bench harness with a hard-coded size, adopt it only where a *user* path defaults the size (do not change bench fixtures). If no user-facing default site exists yet, record that in the report as DONE_WITH_CONCERNS and leave the helper ready for the consumer — do not invent a call site.

- [ ] **Step 4: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-core -p mvm-cli --all-targets -- -D warnings
cargo nextest run -p mvm-core
git add -A
git commit -m "feat(plan-205): default warm-pool size from residency policy (WS-B)"
```

---

### Task 3: `mvmctl doctor` residency line

Mirror `builder_backend_check` (`crates/mvm-cli/src/doctor.rs:1552`). Report the resolved policy, its source, the warm target, and the idle timeout.

**Files:**
- Modify: `crates/mvm-cli/src/doctor.rs` (add `residency_check()`; push it near `checks.push(builder_backend_check(plat));` ~line 534)

**Interfaces:**
- Consumes: `mvm_core::residency::{resolve_residency, ResidencySource}`, and the existing `Check` struct (`doctor.rs:86`).

- [ ] **Step 1: Write the failing test**

In `doctor.rs`'s `#[cfg(test)]` module, add:

```rust
    #[test]
    fn residency_check_reports_policy_and_source() {
        let c = residency_check();
        assert_eq!(c.category, "platform");
        assert!(c.ok);
        // label — source — warm_target=N
        assert!(c.info.contains("warm_target="), "info was {:?}", c.info);
        assert!(
            c.info.contains("auto-detected") || c.info.contains("override"),
            "info was {:?}", c.info
        );
    }
```

Run: `cargo test -p mvm-cli residency_check_reports_policy_and_source`
Expected: FAIL — `residency_check` undefined.

- [ ] **Step 2: Implement**

```rust
fn residency_check() -> Check {
    use mvm_core::residency::{ResidencySource, resolve_residency, MVM_RESIDENCY_ENV};
    let (policy, source) = resolve_residency();
    let source_str = match source {
        ResidencySource::EnvOverride => format!("override via ${MVM_RESIDENCY_ENV}"),
        ResidencySource::AutoDetect => "auto-detected".to_string(),
    };
    let idle = match policy.idle_timeout() {
        Some(d) => format!(", idle={}m", d.as_secs() / 60),
        None => String::new(),
    };
    Check {
        name: "residency",
        category: "platform",
        ok: true,
        info: format!("{} — {} — warm_target={}{}", policy.label(), source_str, policy.warm_target(), idle),
    }
}
```

Push it beside the builder-backend check (`doctor.rs` ~line 534):

```rust
    checks.push(residency_check());
```

(If `builder_backend_check` is behind `#[cfg(feature = "builder-vm")]`, do NOT gate `residency_check` the same way — residency is platform-wide; push it unconditionally next to the other always-on platform checks.)

Run: `cargo test -p mvm-cli residency_check_reports_policy_and_source`
Expected: PASS.

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-cli --all-targets -- -D warnings
cargo nextest run -p mvm-cli
git add crates/mvm-cli/src/doctor.rs
git commit -m "feat(plan-205): doctor reports resolved residency policy (WS-B)"
```

---

## Deferred follow-ups (track in this plan, not built here)

- [ ] WS-D: reaper demotes a warm standby to a parked snapshot after `idle_timeout`, using `vz::snapshot_save`/`snapshot_restore`; parked→warm promotion on claim; the `StandbyHandle` gains an `idle_since` timestamp.
- [ ] Live: prove `MVM_RESIDENCY=warm` holds a standby and a second `up` claims it without a boot (needs the live pool — gated like the Plan 118 live lanes).

## Self-Review

- **Spec coverage (Plan 205 WS-B bullets):** "residency policy (`min` warm + idle) over the pool" → Task 1 (`ResidencyPolicy` carries `warm_target` + `idle_timeout`); "per-host default (AS dev = warm, CI = parked) + override" → Task 1 `resolve_residency` (env override → `host_default_for`); "`mvmctl doctor` reports live residency state + default source" → Task 3. "warm→parked demotion / parked→warm promotion" → explicitly deferred to WS-D (needs the snapshot mechanism), with the `idle_timeout` value and reporting landed here.
- **Placeholder scan:** none — every step is real Rust/commands; Task 2 step 3 is a precise locate-and-adopt instruction with an honest DONE_WITH_CONCERNS escape if no user default site exists.
- **Type consistency:** `ResidencyPolicy::{warm_target,idle_timeout,label}`, `resolve_residency`, `ResidencySource`, `effective_warm_pool_size`, `MVM_RESIDENCY_ENV` are used identically across Tasks 1–3.
