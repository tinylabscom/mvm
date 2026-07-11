# Instant-First-Use Benchmark Harness (SP4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A reproducible benchmark of the two first-use latencies the "instant first-use" work targets — (1) `mvmctl dev up` wall-clock (cold vs warm) and (2) the in-guest Nix build cost of a common builder-VM build — so SP3 (seeding a Nix closure into the builder pack) becomes a data-driven decision instead of a guess.

**Architecture:** SP4 of Plan 213. Mirror the existing `mvmctl ops bench` shape: the pure measurement/aggregation/reporting substrate is always-compiled and unit-tested (PR-safe, no VM); the live probes that boot real VMs sit behind a feature gate (`bench-first-use`) and fail honestly when it's off — exactly like the existing `libkrun-live` gate. The in-guest build cost is read from the builder VM's already-emitted `boot-timings.json` (`job_end_ms - job_start_ms`). Design: `specs/notes/instant-first-use-pack-design.md` (SP4).

**Tech Stack:** Rust (edition 2024), `mvm-cli` (`commands/ops/bench.rs`); POSIX `sh` (capture script).

## Global Constraints

- Edition 2024; no `#[allow(clippy::too_many_arguments)]` (use a params struct); no spec/plan/PR/ADR refs in code comments; no `Co-Authored-By` trailer.
- **Live VM work must NOT run in normal CI.** The dev-up and in-guest-build probes go behind a new `bench-first-use` cargo feature (or reuse `libkrun-live`); without it the subcommand compiles but the live path returns an honest "not built with live benching" error — never a fake number. The pure stats/parse/report code is always compiled + unit-tested.
- **No fake numbers.** A missing `boot-timings.json` / failed boot is an error, not a zero.
- Reuse the existing `bench.rs` machinery (`PhaseStats`, `summarize`, `percentile`, the JSON `write_report_with_latest`, `--baseline`/`--max-regression-pct` compare) rather than reinventing.
- Verification gate: `cargo fmt --all -- --check`, `cargo clippy -p mvm-cli --all-targets -- -D warnings`, `cargo nextest run -p mvm-cli -E 'test(bench)'`, `sh -n scripts/plan-213-sp4-baseline.sh`.
- Work in worktree `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-sp4-benchmark` (branch `feat/plan-213-sp4-benchmark`, off main which has SP1).

## Scope

IN: an `mvmctl ops bench first-use` subcommand — pure aggregation/report (Task 1) + the two live probes gated behind `bench-first-use` (Task 2) — and a contributor capture script (Task 3). OUT: producing the actual numbers (needs a clean quiet-box live run — a manual follow-up, per the plan's own measurement-gate note), and any SP3 closure-content decision.

## File Structure

- `crates/mvm-cli/src/commands/ops/bench.rs` — **modify**: add the `FirstUse` subcommand variant + `FirstUseArgs`, the pure `FirstUseReport`/aggregation, and the live-probe entrypoints (feature-gated).
- `crates/mvm-cli/src/commands/ops/bench_first_use.rs` — **new** (child module of `bench`): the pure aggregation + `boot-timings.json` parsing (`build_ms` extraction), plus the feature-gated live probes.
- `crates/mvm-cli/Cargo.toml` — **modify**: add the `bench-first-use = []` feature.
- `scripts/plan-213-sp4-baseline.sh` — **new**: contributor-invoked capture that shells out to the subcommand and writes a dated markdown verdict.

---

## Task 1: Pure first-use measurement substrate (parse + aggregate + report)

**Files:**
- Create: `crates/mvm-cli/src/commands/ops/bench_first_use.rs`
- Modify: `crates/mvm-cli/src/commands/ops/bench.rs` (`mod bench_first_use; use ...;` + the `FirstUse` subcommand variant + dispatch)
- Test: inline `#[cfg(test)]` in `bench_first_use.rs`

**Interfaces:**
- Produces:
  ```rust
  /// One "run this common flake build in the builder VM" sample: the in-guest
  /// build wall-clock, read from the builder VM's boot-timings.json.
  pub struct BuildSample { pub build_ms: u64 }
  /// Parse `build_ms = job_end_ms - job_start_ms` from a builder-VM job dir's
  /// boot-timings.json. Err if the file/fields are missing (never 0-on-missing).
  pub fn build_ms_from_boot_timings(boot_timings_json: &str) -> anyhow::Result<u64>;
  /// Aggregate N samples into the existing PhaseStats shape (reuse bench.rs's
  /// `summarize`/`percentile`).
  pub fn summarize_build_samples(samples: &[BuildSample]) -> super::bench::PhaseStats;
  ```
  (Confirm the real `PhaseStats`/`summarize`/`percentile` names + visibility in `bench.rs` first; make them `pub(super)` if needed.)

- [ ] **Step 1: Write the failing tests** — in `bench_first_use.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ms_reads_job_delta() {
        let json = r#"{"job_start_ms": 1000, "job_end_ms": 4200, "other": 1}"#;
        assert_eq!(build_ms_from_boot_timings(json).unwrap(), 3200);
    }

    #[test]
    fn build_ms_errors_on_missing_fields() {
        assert!(build_ms_from_boot_timings(r#"{"job_start_ms": 1000}"#).is_err());
        assert!(build_ms_from_boot_timings("not json").is_err());
    }

    #[test]
    fn build_ms_errors_when_end_before_start() {
        // A clock/measurement anomaly must fail, not underflow to a bogus value.
        assert!(build_ms_from_boot_timings(r#"{"job_start_ms": 5000, "job_end_ms": 1000}"#).is_err());
    }

    #[test]
    fn summarize_reports_p50_over_samples() {
        let s = summarize_build_samples(&[
            BuildSample { build_ms: 100 }, BuildSample { build_ms: 200 }, BuildSample { build_ms: 300 },
        ]);
        assert_eq!(s.p50, 200); // adapt to PhaseStats's real field name/type
    }
}
```

- [ ] **Step 2: Run to verify they fail** — `cargo test -p mvm-cli --lib bench_first_use 2>&1 | tail -8` → undefined.

- [ ] **Step 3: Implement** the pure functions. `build_ms_from_boot_timings` parses the two `u64` fields (via `serde_json::Value` or a typed struct), errors on missing / `end < start`. `summarize_build_samples` maps to the real `PhaseStats` by reusing `bench.rs`'s `summarize`/`percentile`. Add `FirstUse(FirstUseArgs)` to the bench subcommand enum with a minimal `FirstUseArgs { #[arg(long, default_value_t = 5)] runs: u32, #[arg(long)] flake: Option<PathBuf>, #[arg(long)] json: bool, #[arg(long)] out: Option<PathBuf> }` and a `run()` that, for now, calls the live entrypoint (Task 2) — in this task, stub the live call to return the honest "not built with `bench-first-use`" error under `#[cfg(not(feature = "bench-first-use"))]` so the command exists and the pure code is exercised by tests.

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-cli --lib bench_first_use` PASS; `cargo build -p mvm-cli` clean; `cargo run -- ops bench first-use --help` shows the subcommand.

- [ ] **Step 5: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-sp4-benchmark
git add crates/mvm-cli/src/commands/ops/bench_first_use.rs crates/mvm-cli/src/commands/ops/bench.rs
git commit -m "feat(bench): first-use bench substrate — parse in-guest build_ms, aggregate"
```

---

## Task 2: Live probes (dev-up cold/warm + in-guest build), feature-gated

**Files:**
- Modify: `crates/mvm-cli/Cargo.toml` (add `bench-first-use = []`)
- Modify: `crates/mvm-cli/src/commands/ops/bench_first_use.rs` (the `#[cfg(feature = "bench-first-use")]` live probes)

**Interfaces:**
- Consumes: Task 1's `BuildSample`/`build_ms_from_boot_timings`/`summarize_build_samples`; the existing report writer `bench::write_report_with_latest`.

- [ ] **Step 1: Add the feature** in `crates/mvm-cli/Cargo.toml` next to `libkrun-live`: `bench-first-use = []`. Note in a comment that it boots real VMs and is not for default/CI builds.

- [ ] **Step 2: Implement the live probes** under `#[cfg(feature = "bench-first-use")]`:
  - **dev-up probe:** for each of `runs`, spawn `mvmctl dev up --json` (via `std::process::Command`, `current_exe()` as the mvmctl path — mirror how bench_probe resolves the binary/plan), timing spawn→exit wall-clock. Do a **cold** sample first (the caller is responsible for a fresh cache; the probe just records that the run resolved the download/build path) then a **warm** sample (repeat; the `ensure_dev_image` cache-hit path). Record both series into `PhaseStats` (cold vs warm), and `mvmctl dev down` between iterations so each is a real start. On non-zero exit, error.
  - **in-guest build probe:** for each of `runs`, snapshot the builder-VM job dir (`mvm_core::config::mvm_cache_dir()/builder-vm/jobs/`), run `mvmctl machine build --flake <FirstUseArgs.flake or the default fixture>`, diff the job dir to find the new job, read its `boot-timings.json`, and `build_ms_from_boot_timings` → `BuildSample`. Aggregate via `summarize_build_samples`.
  - Assemble a `FirstUseReport { dev_up_cold, dev_up_warm, in_guest_build }` (each a `PhaseStats`) and write it with the existing `write_report_with_latest` + optional `--json`. Support `--baseline`/regression compare only if it's a clean reuse; otherwise leave it out of this cut.
  - The default fixture: use an existing real flake (e.g. `examples/python/hello-app-with-deps/`) so `build_ms` reflects genuine nixpkgs eval+build — confirm it builds via `machine build --flake`; if it needs args SP4 can't supply cleanly, add a minimal `tests/fixtures/sp4-common-build/flake.nix` instead and document why.
- Under `#[cfg(not(feature = "bench-first-use"))]`, the `run()` live path returns `anyhow::bail!("first-use benching needs a build with --features bench-first-use (it boots real VMs; not for CI)")`.

- [ ] **Step 3: Verify (compile both ways; no live run in CI)** — `cargo build -p mvm-cli` (feature off: the honest-error path compiles) AND `cargo build -p mvm-cli --features bench-first-use` (the live path compiles). `cargo clippy -p mvm-cli --all-targets --features bench-first-use -- -D warnings` clean. Do NOT run the live probe here — that's a manual quiet-box step; note it in the report.

- [ ] **Step 4: Commit**

```bash
git add crates/mvm-cli/Cargo.toml crates/mvm-cli/src/commands/ops/bench_first_use.rs
git commit -m "feat(bench): live first-use probes (dev-up cold/warm + in-guest build), feature-gated"
```

---

## Task 3: Capture script for the clean quiet-box run

**Files:**
- Create: `scripts/plan-213-sp4-baseline.sh`

- [ ] **Step 1: Write the script** modeled on `scripts/plan-89-baseline.sh` (read it first): env-gated opt-in (`MVM_SP4_LIVE=1` required, else print usage + exit), builds `mvmctl` with `--features bench-first-use`, runs `mvmctl ops bench first-use --runs <N> --json`, writes the JSON evidence + a dated markdown summary under `specs/notes/` (NOT committed evidence — the script writes to a `--out` dir), and prints the two headline numbers (warm-vs-cold `dev up`, in-guest `build_ms` p50/p95). Use the CURRENT build verb (`mvmctl machine build`, not the stale `mvmctl build`). No latency threshold verdict yet (the "instant bar" is TBD until the first real run) — just report the numbers clearly, with a one-line note that these feed the SP3 closure-content/size decision.

- [ ] **Step 2: Verify** — `sh -n scripts/plan-213-sp4-baseline.sh` parses; running it without `MVM_SP4_LIVE=1` prints usage and exits non-fatally.

- [ ] **Step 3: Commit**

```bash
git add scripts/plan-213-sp4-baseline.sh
git commit -m "chore(bench): plan-213 sp4 clean-box capture script for first-use numbers"
```

---

## Self-Review

- **Spec coverage:** dev-up cold/warm measurement → Task 2; in-guest build cost via `boot-timings.json` → Tasks 1+2; reuse existing bench machinery → Tasks 1/2; live work feature-gated + honest-error → Task 2 (both `#[cfg]` arms); no fake numbers → Task 1 (errors on missing/anomalous); PR-safe pure code unit-tested → Task 1; clean-box capture → Task 3; the actual NUMBERS explicitly out of scope (manual quiet-box run) → Scope + Task 2 Step 3 note.
- **Type consistency:** `BuildSample`/`build_ms_from_boot_timings`/`summarize_build_samples`/`FirstUseArgs`/`FirstUseReport` used consistently; `PhaseStats` field names confirmed against `bench.rs` before use.
- **No placeholders:** the feature-off path is a real honest error, not a stub returning success.
