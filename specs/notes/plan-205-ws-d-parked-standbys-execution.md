# Plan 205 Workstream D — Parked standbys (snapshot park/resume, logic slice) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ADR-090's residency demotion real for snapshot-style standbys: an idle, saved-state standby that ages past the warm TTL is **demoted to `Parked`** (kept on disk, still claimable) instead of being reaped — and a parked standby is resumed on claim via the existing path. This lights up WS-B's `idle_timeout` for the vz backend. Live end-to-end resume validation is gated to a macOS-26 box; this slice is the pure pool state-machine, unit-tested.

**Architecture:** A vz standby is already saved-state on disk from spawn (`pid=0`); a libkrun standby is a live process (`pid≠0`). The pool's `is_saved_state()` (`pid==0`) check therefore already discriminates "can be parked" (vz) from "reap to cold" (libkrun) — no new capability gate is needed. WS-D adds a `StandbyState::Parked` variant, teaches `reap_stale` to **demote idle saved-state standbys to `Parked`** at the warm TTL (and only remove them at a longer parked TTL), and lets `select_idle_compatible` claim a parked standby. Resume on claim is the existing saved-state claim path. Workload-standby freshness stays the existing `StandbyCompat` (`kernel_sha256` + `image_sha256`) match — **not** the builder fingerprint (Plan 195's `builder_vm_source_fingerprint` is for the builder VM, a different concern).

**Tech Stack:** Rust (`mvm-core` enum + `mvm-backend` pool logic), unit tests only — no live VM.

## Global Constraints

- No placeholders. No spec/PR/ADR citations in code comments (`xtask check-no-spec-refs-in-comments`).
- `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo nextest run -p <crate>` green.
- `#[allow(clippy::too_many_arguments)]` banned. `mvm-core` stays runtime-free.
- Schema additivity: the new `StandbyState::Parked` variant must serialize as `"parked"` (the enum is `#[serde(rename_all = "snake_case")]`); adding a variant is backward-compatible (old writers never emit it; new readers handle it). Do not change `reap_stale`'s public signature (keep `(ttl, now)`) — derive the parked TTL internally so the 3 call sites (two tests + `mvmctl cache prune`) need no change.

## Out of scope / deferred (tracked, not built here)

- **Live end-to-end resume proof** (a parked vz standby is claimed and resumes correctly on a macOS-26 box): gated, like the Plan 118/159 live lanes.
- **libkrun parking:** libkrun standbys are live processes on a snapshot-incapable (DiskOnly) backend; they keep today's reap-to-cold behavior. No parked state for libkrun.
- **Replenish counting:** `idle_count_compatible` (replenish-to-target) keeps counting only warm (`Idle`) standbys; a parked standby is claimable but not "warm", so it does not suppress re-warming. Intentional.

## File Structure

- Modify `crates/mvm-core/src/protocol/vm_backend.rs` — add `StandbyState::Parked` + a claimability helper (Task 1).
- Modify `crates/mvm-backend/src/standby_pool.rs` — demotion in `reap_stale`; claim a parked standby in `select_idle_compatible` (Tasks 2–3).

---

### Task 1: `StandbyState::Parked` variant + claimability helper

**Files:**
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (enum at line 654; `StandbyHandle` impl at line 630)

**Interfaces:**
- Produces: `StandbyState::Parked`; `StandbyState::is_claimable(&self) -> bool` (true for `Idle` and `Parked`). Tasks 2–3 consume both.

- [ ] **Step 1: Write the failing tests**

In the `#[cfg(test)]` module of `vm_backend.rs` (find it with `rg '#\[cfg\(test\)\]' crates/mvm-core/src/protocol/vm_backend.rs`), add:

```rust
    #[test]
    fn standby_state_parked_serde_roundtrips_snake_case() {
        let j = serde_json::to_string(&StandbyState::Parked).unwrap();
        assert_eq!(j, "\"parked\"");
        let back: StandbyState = serde_json::from_str("\"parked\"").unwrap();
        assert_eq!(back, StandbyState::Parked);
    }

    #[test]
    fn idle_and_parked_are_claimable_claimed_is_not() {
        assert!(StandbyState::Idle.is_claimable());
        assert!(StandbyState::Parked.is_claimable());
        assert!(!StandbyState::Claimed.is_claimable());
    }
```

Run: `cargo test -p mvm-core standby_state_parked_serde_roundtrips_snake_case`
Expected: FAIL — no `Parked` variant / no `is_claimable`.

- [ ] **Step 2: Implement**

Add the variant to the enum (line 657–662):

```rust
pub enum StandbyState {
    /// Spawned, blocked on its control UDS, not yet claimed.
    Idle,
    /// An attach was sent; the standby is booting or has booted.
    Claimed,
    /// Aged out of the warm set but kept as a claimable saved-state snapshot.
    Parked,
}
```

Add the helper (an `impl StandbyState` block near the enum):

```rust
impl StandbyState {
    /// A launch may claim a standby that is warm (`Idle`) or parked.
    pub fn is_claimable(&self) -> bool {
        matches!(self, StandbyState::Idle | StandbyState::Parked)
    }
}
```

Run: `cargo test -p mvm-core 'standby_state' && cargo test -p mvm-core idle_and_parked_are_claimable`
Expected: PASS.

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-core --all-targets -- -D warnings
cargo run -p xtask -- check-core-runtime-free
git add crates/mvm-core/src/protocol/vm_backend.rs
git commit -m "feat(plan-205): StandbyState::Parked variant + is_claimable (WS-D)"
```

---

### Task 2: `reap_stale` demotes idle saved-state standbys to `Parked`

Today `reap_stale` removes an expired saved-state standby. WS-D demotes an expired **idle** saved-state standby to `Parked` (kept, claimable) and only removes a parked one once it ages past a longer parked TTL. Live-pid (libkrun) standbys keep today's reap-to-cold.

**Files:**
- Modify: `crates/mvm-backend/src/standby_pool.rs` (`reap_stale`, line 122)

**Interfaces:**
- Consumes: `StandbyState::Parked` (Task 1), `StandbyHandle::is_saved_state()`.
- Produces: behavior — `reaped` excludes demoted standbys; a const `PARKED_TTL_MULTIPLIER`.

- [ ] **Step 1: Write the failing tests**

In the `#[cfg(test)]` module of `standby_pool.rs` (the existing reaper tests are around line 258–390 — reuse the `handle(...)` / `saved_handle(...)` helpers already there; read them first), add:

```rust
    #[test]
    fn reap_demotes_idle_saved_state_expired_to_parked_not_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        // Idle saved-state (pid=0), expired by the warm ttl.
        let mut h = saved_handle("vz1", "aa", "img", StandbyState::Idle);
        h.spawned_unix_secs = now - 7_200; // 2h old
        pool.record(&h).unwrap();

        let reaped = pool.reap_stale(std::time::Duration::from_secs(3_600), now).unwrap();

        assert!(!reaped.contains(&"vz1".to_string()), "demoted, not reaped");
        assert_eq!(pool.load("vz1").unwrap().state, StandbyState::Parked);
    }

    #[test]
    fn reap_keeps_parked_under_parked_ttl_and_removes_over_it() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        let ttl = std::time::Duration::from_secs(3_600);

        let mut young = saved_handle("p_young", "aa", "img", StandbyState::Parked);
        young.spawned_unix_secs = now - 4 * 3_600; // older than warm ttl, under parked ttl
        pool.record(&young).unwrap();

        let mut old = saved_handle("p_old", "aa", "img", StandbyState::Parked);
        old.spawned_unix_secs = now - 100 * 3_600; // well past parked ttl
        pool.record(&old).unwrap();

        let reaped = pool.reap_stale(ttl, now).unwrap();

        assert!(!reaped.contains(&"p_young".to_string()), "young parked kept");
        assert!(reaped.contains(&"p_old".to_string()), "old parked removed");
        assert_eq!(pool.load("p_young").unwrap().state, StandbyState::Parked);
    }

    #[test]
    fn reap_still_removes_live_pid_expired_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let now = 1_000_000u64;
        // Live-pid standby (pid!=0, dead pid) expired — libkrun stays reap-to-cold.
        let mut h = handle("lk1", "aa", StandbyState::Idle);
        h.pid = 999_999; // not alive
        h.spawned_unix_secs = now - 7_200;
        pool.record(&h).unwrap();

        let reaped = pool.reap_stale(std::time::Duration::from_secs(3_600), now).unwrap();
        assert!(reaped.contains(&"lk1".to_string()));
        assert!(pool.load("lk1").is_err(), "removed");
    }
```

(If the existing helpers are named differently — e.g. `saved_handle` takes other args — read the existing reaper tests at lines ~258–390 and adapt the helper calls verbatim to what's there; keep the assertions.)

Run: `cargo test -p mvm-backend reap_demotes_idle_saved_state_expired_to_parked_not_removed`
Expected: FAIL (demotes nothing yet — the standby is removed).

- [ ] **Step 2: Implement the demotion**

Add the const above `impl SupervisorStandbyPool` (or near the top of the file):

```rust
/// A parked standby is a low-cost saved-state snapshot; it may outlive the warm
/// TTL by this factor before the reaper finally removes it.
const PARKED_TTL_MULTIPLIER: u64 = 6;
```

Replace the `is_saved_state()` arm of `reap_stale` (lines 127–132) with the demote-then-reap logic; leave the live-pid arm unchanged:

```rust
        for h in self.list()? {
            let age = now.saturating_sub(h.spawned_unix_secs);
            let expired = age > ttl_secs;
            if h.is_saved_state() {
                match h.state {
                    // Already parked: keep until it ages past the longer parked TTL.
                    StandbyState::Parked => {
                        if age > ttl_secs.saturating_mul(PARKED_TTL_MULTIPLIER) {
                            self.remove(&h.id)?;
                            reaped.push(h.id);
                        }
                    }
                    // Idle saved-state that aged out: demote to parked, keep it claimable.
                    StandbyState::Idle if expired => {
                        let mut parked = h.clone();
                        parked.state = StandbyState::Parked;
                        self.record(&parked)?;
                    }
                    // Claimed-but-expired (stuck) or not-yet-expired idle: remove only if expired.
                    _ if expired => {
                        self.remove(&h.id)?;
                        reaped.push(h.id);
                    }
                    _ => {}
                }
            } else {
                let alive = pid_alive(h.pid);
                if !alive || expired {
                    if alive {
                        // SAFETY: SIGTERM to a pid this host spawned; a stale pid is a no-op.
                        unsafe { libc::kill(h.pid as libc::pid_t, libc::SIGTERM) };
                    }
                    self.remove(&h.id)?;
                    reaped.push(h.id);
                }
            }
        }
```

Update the `reap_stale` doc comment to describe the demotion (no spec citations). Confirm `StandbyHandle` derives `Clone` (it does — used elsewhere); if not, the implementer adapts by re-loading + mutating instead of `clone()`.

Run: `cargo test -p mvm-backend 'reap_'`
Expected: PASS (the new three + the pre-existing reaper tests stay green — verify the existing ones still pass, since demotion changes the saved-state path).

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-backend --all-targets -- -D warnings
cargo nextest run -p mvm-backend -E 'test(reap)'
git add crates/mvm-backend/src/standby_pool.rs
git commit -m "feat(plan-205): reap_stale demotes idle saved-state standbys to Parked (WS-D)"
```

---

### Task 3: claim a parked standby

`select_idle_compatible` gates on `state == Idle`; a parked standby must also be claimable (resume on claim uses the existing saved-state path).

**Files:**
- Modify: `crates/mvm-backend/src/standby_pool.rs` (`select_idle_compatible`, line 79)

**Interfaces:**
- Consumes: `StandbyState::is_claimable()` (Task 1).

- [ ] **Step 1: Write the failing test**

In the `standby_pool.rs` test module, add:

```rust
    #[test]
    fn select_claims_compatible_parked_saved_state_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let want = compat("aa"); // same helper the other select tests use
        let parked = saved_handle("vzp", "aa", "img", StandbyState::Parked);
        pool.record(&parked).unwrap();

        let got = pool.select_idle_compatible(&want).unwrap();
        assert_eq!(got.map(|h| h.id), Some("vzp".to_string()));
    }
```

(Match `compat(...)` / `saved_handle(...)` to the real helpers in the existing select tests around lines 210–346; the image must match what `compat` expects — read those tests and mirror exactly.)

Run: `cargo test -p mvm-backend select_claims_compatible_parked_saved_state_standby`
Expected: FAIL — `select_idle_compatible` skips non-`Idle`.

- [ ] **Step 2: Implement**

Change the predicate in `select_idle_compatible` (line 80–84) from `h.state == StandbyState::Idle` to `h.state.is_claimable()`:

```rust
    pub fn select_idle_compatible(&self, want: &StandbyCompat) -> Result<Option<StandbyHandle>> {
        Ok(self.list()?.into_iter().find(|h| {
            h.state.is_claimable()
                && h.is_compatible(want)
                && (h.is_saved_state() || pid_alive(h.pid))
        }))
    }
```

Then verify nothing downstream re-rejects a parked claim: `rg 'StandbyState::Idle' crates/` and read each hit. The claim flow (e.g. `vz_claim_standby` in `crates/mvm-backend/src/vz.rs`, and the `up` claim path) must not gate on `state == Idle` after selection; if any does, switch it to `is_claimable()` and note it in the report. Do NOT change `idle_count_compatible` (replenish counts warm only — intentional, per the plan's Out-of-scope).

Run: `cargo test -p mvm-backend select_claims_compatible_parked_saved_state_standby && cargo test -p mvm-backend select`
Expected: PASS (the new test + the pre-existing select tests stay green).

- [ ] **Step 3: Gate + commit**

```bash
cargo fmt --all
cargo clippy -p mvm-backend --all-targets -- -D warnings
cargo nextest run -p mvm-backend -E 'test(select) or test(reap) or test(standby)'
git add -A
git commit -m "feat(plan-205): select_idle_compatible claims parked standbys (WS-D)"
```

---

## Deferred follow-ups (tracked, not built here)

- [ ] Live macOS-26 proof: a vz standby demoted to `Parked` is claimed by a second `up` and resumes from its saved state (no fresh boot), gated like the Plan 118/159 live lanes.
- [ ] If `vz_claim_standby` needs a resume-path tweak for parked (vs idle saved-state) claims beyond the selection change, spin it out once the live proof exists.

## Self-Review

- **Spec coverage (Plan 205 WS-D bullets, corrected):** "wire snapshot into the parked state / resume <1s" → vz standbys are already saved-state, so demotion (Task 2) + claim (Task 3) reuse the existing capture/restore; live timing proof is deferred. "FC leg via Plan 175" → libkrun/FC stay reap-to-cold (Out-of-scope, correct — they're snapshot-incapable here). "freshness keyed to builder fingerprint (Plan 195)" → **corrected**: freshness is the existing `StandbyCompat` match; the builder fingerprint is a different concern (noted in Architecture).
- **Placeholder scan:** none — real Rust + commands; the helper-name adaptation notes are precise locate-and-mirror instructions against cited line ranges.
- **Type consistency:** `StandbyState::Parked`, `is_claimable()`, `PARKED_TTL_MULTIPLIER`, `is_saved_state()` used identically across tasks.
