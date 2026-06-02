# Plan 120 — Core demo (Phase 1): the `dev → compile → up → vsock` spine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the #1 deliverable end-to-end on macOS (libkrun): `mvmctl dev up` boots the persistent builder VM → `mvmctl compile examples/python/hello-app/app.py` lowers the decorator app to a flake → `mvmctl up --flake <dir>` builds it **inside** the builder VM and boots the microVM → the guest agent answers `Ping` over vsock. Lock that spine behind a CI-gated E2E test so the rest of the rewrite has a regression guard, land the `ArtifactSidecar` → `ArtifactManifest` rename along the way, and ship the one-call live-exec ergonomic on the existing `Sandbox` (`Sandbox.create(image).exec(...)`, dev-tier) as the DX headline (Task 5; full surface in 125).

**Architecture:** The whole spine already exists and is verified present — only the regression guard and one rename are missing. The verbs are real: `Dev` (`commands/env/dev.rs`), `Compile` (`commands/build/compile.rs`, "Compile Workload IR into build artifacts"), `Up` (`commands/vm/up.rs`, "Build and run a VM"). The decorator `.py` path is wired (`compile.rs:181` matches `parse_python(&bytes, &path)` — its module docstring claiming "Phase 4 not landed" is stale). `up` already calls `wait_for_guest_agent(&vm, 30)` (`up.rs:1366`, which pings the agent over vsock) and prints `Waiting for guest agent...` → `Guest agent not reachable.` on failure (`up.rs:1364`,`:1385`), so **`up` exiting 0 without that failure line IS the boot→ping proof** — no new status verb needed. A *fresh* dev build already emits `overlay_aware: true` (`crates/mvm-base/src/runtime_meta.rs:303`), so `admit_overlay_aware` (`crates/mvm-build/src/builder_vm.rs:800`) **admits** it — the documented `default-microvm` admit blocker is the *downloaded, manifest-less* default image (blocks the bench baseline), **not** this fresh-build path.

**Tech Stack:** Rust (`mvm-cli`, `mvm-build`, `mvm-base`, `mvm-security`, `mvm`, `mvm-guest`), the `mvm-sdk` compile path (`parse_python` → `Workload` → `compile`), libkrun (macOS), vsock (`GUEST_CID=3`, `GuestRequest::Ping`). Gated E2E via `MVM_E2E_SMOKE=1` (the existing convention from `crates/mvm-cli/tests/dev_up_smoke.rs`).

**Out of scope / deferred follow-ups** (tracked in `### deferred follow-ups`): the slim `mkfs.ext4 -d` build off the `microvm.nix` substrate (build-layer work, **plan 131**); Linux/Firecracker parity (own plan, `/dev/kvm` test backend); encryption-at-rest + Noise vsock (plan 122); the downloaded-`default-microvm` admit blocker (separate — it blocks bench, not this demo).

---

## File structure

- **Rename `ArtifactSidecar` → `ArtifactManifest`** (type only; the `mvm-meta.json` filename + `SIDECAR_FILENAME` const stay) across the 6 files that reference it:
  - `crates/mvm-build/src/builder_vm.rs` (definition + impl + tests; 14 refs)
  - `crates/mvm-build/src/pipeline/dev_build.rs` (4 refs)
  - `crates/mvm-base/src/runtime_meta.rs` (3 refs, incl. the `overlay_aware: true` emit at :303)
  - `crates/mvm-base/src/snapshot_integrity.rs`
  - `crates/mvm-security/src/snapshot_hmac.rs`
  - `crates/mvm/src/vm/instance_snapshot.rs`
- **Modify** `crates/mvm-cli/src/commands/build/compile.rs:1–26` — correct the stale v1 docstring (the `.py`/`.ts` decorator entry is handled, not rejected).
- **Create** `crates/mvm-cli/tests/compile_hello_app.rs` — CLI test locking `mvmctl compile <app.py>` decorator lowering.
- **Create** `crates/mvm-cli/tests/core_demo_e2e.rs` — the boot→ping E2E (gated on `MVM_E2E_SMOKE=1`).
- **Use** `examples/python/hello-app/app.py` (the decorator-form hello-world; exists).
- **Touch only if Task 4 surfaces it** — the macOS workload-backend selection in `commands/vm/up.rs` (the `--backend` default is `firecracker`, `up.rs:705`).

---

## Task 1: Rename `ArtifactSidecar` → `ArtifactManifest`

> **✅ LANDED 2026-05-31** (out-of-band, owner request). Renamed the *type* in the 3 code files that use it — `runtime_meta.rs`, `builder_vm.rs`, `dev_build.rs` — plus the two docs that name it; build + `admit_overlay_aware`/round-trip tests + clippy green; `SIDECAR_FILENAME` + `mvm-meta.json` unchanged. The earlier "6 files" count conflated the type with the `SIDECAR_FILENAME` *constant* (which stays in 3 other files). The steps below are the historical recipe.

Mechanical type rename; the existing round-trip + admit tests in `builder_vm.rs` are the guard (they must stay green). The on-disk filename (`mvm-meta.json`) and the `SIDECAR_FILENAME` constant are **unchanged** (renaming the file would be a real migration; out of scope).

**Files:** the 6 listed above. **Test:** the existing `crates/mvm-build/src/builder_vm.rs` `mod tests` (`admit_overlay_aware_*`, sidecar round-trip).

- [ ] **Step 1: Confirm the guard tests pass before touching anything.**

  Run: `cargo test -p mvm-build builder_vm`
  Expected: PASS (the admit + round-trip cases referencing `overlay_aware`).

- [ ] **Step 2: Rename the type definition + impl in `crates/mvm-build/src/builder_vm.rs`.**

  Change `pub struct ArtifactSidecar {` → `pub struct ArtifactManifest {` and `impl ArtifactSidecar {` → `impl ArtifactManifest {` (around lines 200 / 238). Update the doc comment's "sidecar" → "manifest" where it names the *type* (the `mvm-meta.json` *file* may still be called the metadata file). Keep `SIDECAR_FILENAME`, `path_in`, `write_to_dir`, `read_from_dir`, `is_overlay_aware`.

- [ ] **Step 3: Update the remaining references with a workspace-wide type-name replace.**

  Verify the count first, then apply (macOS `sed -i ''`; on Linux drop the `''`):
  ```bash
  git grep -c '\bArtifactSidecar\b' -- crates/
  git grep -l '\bArtifactSidecar\b' -- crates/ | xargs sed -i '' 's/\bArtifactSidecar\b/ArtifactManifest/g'
  ```
  `SIDECAR_FILENAME` and `mvm-meta.json` are not matched (no word-boundary hit).

- [ ] **Step 4: Build + test + lint.**

  Run: `cargo test -p mvm-build -p mvm-base -p mvm-security -p mvm builder_vm runtime_meta snapshot`
  Then: `cargo clippy --workspace -- -D warnings`
  Expected: PASS, zero warnings. The admit/round-trip tests now exercise `ArtifactManifest` with identical behavior.

- [ ] **Step 5: Commit.**

  ```bash
  git -C /Users/auser/work/tinylabs/mvmco/mvm add -A
  git -C /Users/auser/work/tinylabs/mvmco/mvm commit -m "refactor(mvm-build): rename ArtifactSidecar -> ArtifactManifest (kill the sidecar overload)"
  ```

## Task 2: Lock `mvmctl compile <app.py>` (decorator lowering) + fix its stale docstring

The decorator `.py` path **is wired** — `crates/mvm-cli/src/commands/build/compile.rs:181` matches `parse_python(&bytes, &path)` (symbols imported at `compile.rs:36–37`), and `--out <dir>` is a real flag (`compile.rs:68`). But the module docstring (`compile.rs:8–18`) still says "Decorator-script entry … lands with Phase 4 … `.py` … rejected with a `not-yet-implemented` pointer" and "v1 only handles the IR-JSON path." That is stale (Phase 4 landed). Lock the real behavior with a CLI test, then correct the docstring.

**Files:** Create `crates/mvm-cli/tests/compile_hello_app.rs` (CLI integration tests live in `crates/mvm-cli/tests/` per CLAUDE.md). Modify `crates/mvm-cli/src/commands/build/compile.rs:1–26`.

- [ ] **Step 1: Write the failing CLI test.**

  ```rust
  // Plan 120 Task 2: the decorator `.py` path lowers statically (no host exec).
  use assert_cmd::cargo::CommandCargoExt;
  use std::process::Command;

  #[test]
  fn compile_hello_app_lowers_decorator_to_flake() {
      let out = tempfile::tempdir().expect("tmp out");
      let app = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/python/hello-app/app.py");
      #[allow(deprecated)]
      let st = Command::cargo_bin("mvmctl").expect("locate mvmctl")
          .args(["compile", app, "--out", out.path().to_str().unwrap()])
          .status().expect("spawn mvmctl compile");
      assert!(st.success(), "mvmctl compile <app.py> failed");
      assert!(out.path().join("flake.nix").exists(), "flake.nix emitted");
      assert!(out.path().join("launch.json").exists(), "launch.json emitted");
  }
  ```

- [ ] **Step 2: Run it.** `cargo test -p mvm-cli --test compile_hello_app -- --nocapture`
  Expected: PASS — `compile.rs:181` already lowers `app.py` via `parse_python`. **If** it instead bails `not-yet-implemented`, that is the gap to close: in `compile.rs::run` wire the `.py` arm to `parse_python(&bytes, &path)? -> App -> Workload -> compile(&workload, out, manifest_dir)` using the symbols already imported at `compile.rs:36`. Re-run to green.

- [ ] **Step 3: Correct the stale docstring** at `crates/mvm-cli/src/commands/build/compile.rs:8–18` — state that the `.py`/`.ts` decorator entry is parsed statically (via `parse_python`/`parse_typescript`) into the Workload IR and lowered; drop the "lands with Phase 4 / v1 only handles the IR-JSON path / rejected with a `not-yet-implemented` pointer" sentences. Keep the `--from-ir`, `--from-recording`, `--out`, `--mode`, `--dev`/`--prod` flag descriptions.

- [ ] **Step 4: Run the test again** (`cargo test -p mvm-cli --test compile_hello_app`) → PASS, then `cargo fmt --all -- --check`.

- [ ] **Step 5: Commit.**
  ```bash
  git -C /Users/auser/work/tinylabs/mvmco/mvm add -A
  git -C /Users/auser/work/tinylabs/mvmco/mvm commit -m "test(mvm-cli): lock mvmctl compile <app.py> decorator lowering; fix stale v1 docstring"
  ```

## Task 3: The boot→ping E2E (`core_demo_e2e.rs`) — the regression guard

One gated test driving the whole spine with the **verified** verbs: `mvmctl dev up` (builder), `mvmctl compile <app.py> --out <dir>` (lower), `mvmctl up --flake <dir>` (build + boot + wait-for-agent), then teardown. `up` calls `wait_for_guest_agent(&vm, 30)` (`crates/mvm-cli/src/commands/shared/vsock.rs:19`, invoked at `up.rs:1366`) and prints `Waiting for guest agent...` (`up.rs:1364`) → `Guest agent not reachable.` (`up.rs:1385`) only on failure; so **`up` exiting 0 without that line is the boot→ping proof.** Modeled on `crates/mvm-cli/tests/dev_up_smoke.rs`.

**Files:** Create `crates/mvm-cli/tests/core_demo_e2e.rs`.

- [ ] **Step 1: Write the failing E2E (gated; default-skips).**

  ```rust
  // Plan 120 core-demo E2E: dev up -> compile the hello-app -> up (build+boot) ->
  // guest agent answers Ping over vsock -> teardown. Gated on MVM_E2E_SMOKE=1
  // (needs libkrun + the builder VM; runs for minutes). The spine's regression guard.
  use assert_cmd::cargo::CommandCargoExt;
  use std::process::Command;

  fn mvmctl(args: &[&str]) -> std::process::Output {
      #[allow(deprecated)]
      Command::cargo_bin("mvmctl").expect("locate mvmctl").args(args).output().expect("spawn mvmctl")
  }

  #[test]
  fn core_demo_dev_compile_up_ping() {
      if std::env::var("MVM_E2E_SMOKE").ok().as_deref() != Some("1") {
          eprintln!("skipping core-demo E2E; set MVM_E2E_SMOKE=1 to run");
          return;
      }
      let out = tempfile::tempdir().expect("tmp out");
      let app = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/python/hello-app/app.py");

      // 1) builder VM up (idempotent).
      assert!(mvmctl(&["dev", "up"]).status.success(), "dev up failed");

      // 2) lower the decorator app to flake.nix + launch.json.
      let c = mvmctl(&["compile", app, "--out", out.path().to_str().unwrap()]);
      assert!(c.status.success(), "compile failed: {}", String::from_utf8_lossy(&c.stderr));

      // 3) build + boot the workload microVM; `up` waits for the guest agent
      //    (wait_for_guest_agent -> vsock Ping). Exit 0 + no "not reachable" == agent answered.
      let up = mvmctl(&["up", "--flake", out.path().to_str().unwrap()]);
      let log = String::from_utf8_lossy(&up.stderr);
      assert!(up.status.success(), "up failed: {log}");
      assert!(!log.contains("Guest agent not reachable"), "agent never answered: {log}");

      // 4) teardown the builder (best-effort).
      let _ = mvmctl(&["dev", "down"]);
  }
  ```
  *(On macOS the workload backend must be libkrun, not the `--backend` firecracker default — Task 4 wires that selection. The assertion contract is fixed: `up` boots and the agent answers.)*

- [ ] **Step 2: Run it gated** on a libkrun host: `MVM_E2E_SMOKE=1 cargo test -p mvm-cli --test core_demo_e2e -- --nocapture`. First run surfaces the real gaps (Task 4). The default (ungated) run skips and passes — confirm with `cargo test -p mvm-cli --test core_demo_e2e` (prints the skip line, exits 0).

- [ ] **Step 3: Add the lane to CI** as a manual/opt-in job (not every PR — it needs a libkrun runner), mirroring how `dev_up_smoke` is gated. Document it in `public/src/content/docs/contributing/development.md`.

- [ ] **Step 4: Commit.**
  ```bash
  git -C /Users/auser/work/tinylabs/mvmco/mvm add -A
  git -C /Users/auser/work/tinylabs/mvmco/mvm commit -m "test(mvm-cli): core-demo boot->ping E2E (MVM_E2E_SMOKE-gated)"
  ```

## Task 4: Close whatever the E2E surfaces, until it is green

The spine is *believed* complete (fresh build → `overlay_aware: true` → admits; `up` pings the agent). Task 4 is the iterate-to-green loop: run the gated E2E, read `<vm_state_dir>/console.log` **first** on any boot failure (per the project's debugging convention), fix the one gap, re-run. **No speculative fixes** — only what the E2E proves broken. The likely gaps, in order:

- [ ] **Step 1: macOS workload backend.** `up`'s `--backend` defaults to `firecracker` (`up.rs:705`), which needs Linux KVM. On macOS the workload microVM must run via libkrun. Confirm `up` selects libkrun on macOS (per-OS default) or thread the backend through the E2E. This is the most likely first failure.
- [ ] **Step 2: `compile → up` handoff.** Confirm `up --flake <compiled-dir>` consumes `compile`'s rendered `flake.nix`. If `up` expects a flake *reference* rather than a directory of rendered artifacts, wire the handoff (point `up` at the rendered dir, or have the E2E pass it as a path-flake `--flake path:<dir>`).
- [ ] **Step 3: teardown.** Confirm `dev down` stops the builder; if `up` leaves a workload VM running, stop it (the `mvmctl` stop/kill verb) in the test's teardown so repeated runs stay idempotent.
- [ ] **Step 4: Repeat** until `MVM_E2E_SMOKE=1 cargo test -p mvm-cli --test core_demo_e2e` is green on a macOS/libkrun host. Each fix is its own red→green→commit cycle.
- [ ] **Step 5: Tick the §4 acceptance boxes** in `specs/plans/117-cleanup-and-rearchitecture-brief.md` for the criteria this proves (`dev up` persistent builder; hello-app compiles + builds in-VM; `up` boots + agent answers vsock; the loop driven by `mvmctl dev`/`compile`/`up`). Leave the cross-platform + encrypted-at-rest + Noise boxes for their plans.

## Task 5: the one-call live-exec ergonomic — `Sandbox` (the DX headline)

The gap analysis (`specs/research/embeddable-sandbox-sdk-dx-gap-analysis.md`) put the parity gap in one place: the imperative "boot a sandbox, exec against it" experience. mvm **already has the class** — `sdks/python/mvm/_sandbox.py` (`Sandbox.create(...)`, `sb.commands.start(...)`) with two modes (record → prod plan, live → dev) and the dev-tier guard `SandboxDevOnly` already in place. This task adds the dead-simple one-shot ergonomic on top and makes it the demo headline. **Extend `Sandbox`; do not add a new class** (and never name it `Box` — that's a competitor's term). Typed helpers / async / Node are plan 125.

**Files:** `sdks/python/mvm/_sandbox.py` (add the one-shot `exec`); test `sdks/python/tests/test_sandbox_exec.py` (gated — it boots a real VM).

- [ ] **Step 1: Write the failing test.**
  ```python
  # Live-mode Sandbox is dev-tier (SandboxDevOnly guards prod). exec() is a
  # one-shot convenience over commands.start: run argv, collect stdout + exit.
  from mvm import Sandbox

  def test_sandbox_exec_returns_stdout():
      sb = Sandbox.create(image="python:slim")     # boots a dev-tier microVM
      try:
          r = sb.exec("python", "-c", "print(2+2)")
          assert r.exit_code == 0
          assert r.stdout.strip() == "4"
      finally:
          sb.shutdown()
  ```
- [ ] **Step 2: Add `Sandbox.exec(*argv, timeout=None, cwd=None, env=None) -> ExecResult`** as a one-shot over the existing `commands.start` (start → wait → collect stdout/stderr/exit). Keep the existing `SandboxDevOnly` refusal for prod-tier — no silent fallback (ADR-053). Reuse the `_live_sandbox` one-process invariant already in `_sandbox.py`.
- [ ] **Step 3: Run gated** (`MVM_E2E_SMOKE=1`) on a libkrun host → PASS; ungated → skip. Commit.
- [ ] **Step 4: Lead the quickstart with it** — README / `mvmctl` quickstart shows the five-line `Sandbox` example, not the build/derive path.

## Acceptance (this plan is done when)

- [x] `ArtifactSidecar` → `ArtifactManifest` rename landed (2026-05-31, 3 code files); build + affected tests (`mvm-build`/`mvm-base`) + clippy green.
- [ ] `crates/mvm-cli/tests/compile_hello_app.rs` passes (decorator `app.py` lowers to `flake.nix` + `launch.json`); the stale `compile.rs` docstring is corrected.
- [ ] `crates/mvm-cli/tests/core_demo_e2e.rs` exists, is `MVM_E2E_SMOKE`-gated, and is **green on a macOS/libkrun host** end-to-end (`dev up` → `compile` → `up` with the agent reachable).
- [ ] The one-shot `Sandbox.exec(...)` returns stdout on a dev-tier sandbox and raises `SandboxDevOnly` in prod; the quickstart leads with it.
- [ ] The proven §4 acceptance boxes are ticked in the brief.

### deferred follow-ups

- [ ] Slim `mkGuest` build via `mkfs.ext4 -d` populate-at-format, off the heavy `microvm.nix` substrate (build-layer work — **plan 131**).
- [ ] Linux / Firecracker parity for this same E2E (own plan; `/dev/kvm` test backend).
- [ ] Encrypt build artifacts at rest + upgrade vsock frames to Noise (plan 122) — completes §4's *full* acceptance.
- [ ] The downloaded `default-microvm` admit blocker (manifest-less image) — separate from this fresh-build path; blocks the bench baseline.
- [ ] Builder/dev-VM agent ping (proves the guest agent is *universal* across VM types — ADR-066 §6 invariant) — depends on **plan 124** making `mvm-host-vm-init` fork `mvm-guest-agent`; this plan's E2E only pings the *workload* microVM's agent.

## Self-review

- **Spec coverage** (brief §4 acceptance): `dev up` persistent builder (Task 3 §1 / Task 4 §1); hello-app compiles via the SDK decorator path (Task 2) + builds in-VM (Task 3 §3 `up`); `up` boots + agent answers vsock (Task 3 assertion on `wait_for_guest_agent`); driven by `mvmctl dev`/`compile`/`up` (Tasks 2–4). Cross-platform / encrypted-at-rest / Noise are explicitly deferred to their plans.
- **No placeholders / real symbols:** every referenced symbol is verified — `parse_python` (`compile.rs:181`), `--out` (`compile.rs:68`), `--flake` (`up.rs:681`), `wait_for_guest_agent` (`shared/vsock.rs:19`, called `up.rs:1366`), the `Guest agent not reachable.` marker (`up.rs:1385`), `overlay_aware: true` (`runtime_meta.rs:303`), the 6 rename sites. Task 2 §2 handles the one residual unknown (does `app.py` lower today or bail?) as an honest TDD red step with the real wire-code, not a guess.
- **Type consistency:** `ArtifactManifest` used consistently; `mvm-meta.json` filename + `SIDECAR_FILENAME` deliberately unchanged.
