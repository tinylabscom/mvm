# Vz workload liveness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unblock live Vz validation by hardening the sealed-workload `/init` stdin against Vz's input-less console (one line) and adding a long-lived sealed-workload example to validate against.

**Architecture:** A one-line change in `nix/lib/mk-guest.nix` redirects the sourced workload's stdin to `/dev/null` (claim-15-preserving); a regression test asserts the redirect can't silently disappear; a new `examples/sleeper/` flake mirrors `examples/exit_code/` with a long-lived command. The live Vz bringup is a documented, non-gating follow-on.

**Tech Stack:** Nix (`mkGuest` / `writeScript`), a Rust regression test, a flake fixture.

**Design doc:** `specs/notes/vz-workload-liveness-design.md`
**Worktree:** `../mvm-vz-liveness` (branch `feat/vz-workload-liveness`).

**Standing rules:** NO plan/PR/ADR/sprint refs in code comments (the `check-no-spec-refs-in-comments` lint gate, Plan 180, is live on main — it WILL fail the merge otherwise); no `Co-Authored-By`; `cargo fmt --all`; clippy `-D warnings`.

**Ground-truth pins:**
- `nix/lib/mk-guest.nix` line **624**: `    . "$MVM_BOOT"` (sealed-workload arm, after the dev-idle `if`-block, before `MVM_CODE=$?` at 625). `/init` is rendered via `initScript = pkgs.writeScript "mvm-init" ''...''` at line 255.
- claim-15 lane `prod-agent-no-console` (`scripts/check-prod-agent-no-console.sh` / `.github/workflows/security.yml`) greps the **agent binary** for `mvm_guest.*console.*(open_session|run_console_relay|resize_active_session)` — it does NOT inspect `/init`, so this nix-only change is invisible to it.
- `examples/exit_code/flake.nix` is the shape to mirror: `inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix"`, `inputs.nixpkgs.follows = "mvm/nixpkgs"`, `outputs` with an `eachSystem` over `["x86_64-linux" "aarch64-linux"]`, `packages.default = mvm.lib.${system}.mkGuest { ... entrypoint.command = [...]; hypervisor = "libkrun"; vcpus = 1; memory_mib = 256; }`. **`examples/exit_code/` has NO committed `flake.lock`.**
- Example flakes are discovered + checked by the `flake-locks-clean` lane (`.github/workflows/security.yml`); `nix-flake-check` (`ci-full.yml`) only covers `nix/`.

---

## File Structure

| File | Change |
|------|--------|
| `nix/lib/mk-guest.nix` | line 624: `. "$MVM_BOOT"` → `. "$MVM_BOOT" </dev/null` (+ a no-spec-ref comment) |
| `crates/xtask/...` (a test module) | regression test: `mk-guest.nix` workload arm carries the `</dev/null` redirect |
| `examples/sleeper/flake.nix` *(create)* | long-lived sealed-workload fixture |
| `examples/sleeper/flake.lock` *(maybe)* | only if the `flake-locks-clean` lane requires it (mirror exit_code) |
| `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md` | record the fix + live-validation status |

---

## Task 1: `/init` workload stdin hardening + regression test

**Files:**
- Modify: `nix/lib/mk-guest.nix` (line 624)
- Modify/Create: a Rust test in `crates/xtask` asserting the redirect

- [ ] **Step 1: Write the failing regression test.** Add a `#[test]` that reads `nix/lib/mk-guest.nix` at runtime (via `CARGO_MANIFEST_DIR`, which is robust to where you place the test) and asserts the sealed-workload arm detaches stdin. Place it in a `#[cfg(test)] mod tests` in an `xtask` source file (e.g. `crates/xtask/src/main.rs` or the nearest existing module). `CARGO_MANIFEST_DIR` for `xtask` is `<repo>/crates/xtask`, so the file is at `../../nix/lib/mk-guest.nix` from there:

```rust
#[test]
fn guest_init_detaches_workload_stdin_from_console() {
    // The sealed-workload arm must source the boot command with stdin
    // redirected away from the input-less Vz console; otherwise a workload
    // that reads stdin EOF-crashes ~5s after boot on Vz.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../nix/lib/mk-guest.nix");
    let init = std::fs::read_to_string(path).expect("read mk-guest.nix");
    // The redirect substring is literally: . "$MVM_BOOT" </dev/null
    assert!(
        init.contains(". \"$MVM_BOOT\" </dev/null"),
        "mk-guest.nix workload arm must redirect the workload's stdin to /dev/null"
    );
}
```
Run it; it FAILS (the source currently has `. "$MVM_BOOT"` without the redirect):
```bash
cargo test -p xtask guest_init_detaches_workload_stdin 2>&1 | tail -10
```
Expected: FAIL (assertion: redirect absent). If the path doesn't resolve, confirm `CARGO_MANIFEST_DIR` → `crates/xtask` and that `../../nix/lib/mk-guest.nix` reaches repo root (xtask → crates → root → nix).

- [ ] **Step 2: Make the edit.** In `nix/lib/mk-guest.nix`, change line 624 from:
```
    . "$MVM_BOOT"
```
to:
```
    # Detach the workload's stdin from the input-less serial console: a
    # write-only console hands the guest an immediate EOF, which crashes a
    # workload that reads stdin shortly after boot. /dev/null is the correct
    # stdin for a non-interactive sealed workload; stdout/stderr stay on the
    # console for capture, and the exit-code capture below is unaffected.
    . "$MVM_BOOT" </dev/null
```
The comment must NOT cite any plan/PR/ADR/sprint number (the lint gate will fail the merge). Describe the WHY in plain terms only.

- [ ] **Step 3: Run the test → passes.**
```bash
cargo test -p xtask guest_init_detaches_workload_stdin 2>&1 | tail -8
```
Expected: PASS.

- [ ] **Step 4: Confirm nothing else broke + the spec-ref lint is happy.**
```bash
cargo fmt --all
cargo clippy -p xtask -- -D warnings 2>&1 | tail -5
# the spec-ref lint (Plan 180) — confirm the new comment doesn't trip it:
cargo run -p xtask -- check-no-spec-refs 2>&1 | tail -5 || cargo xtask check-no-spec-refs 2>&1 | tail -5
```
(The exact `xtask` subcommand name for the spec-ref lint may differ — find it: `cargo run -p xtask -- --help 2>&1 | grep -iE "spec|comment|ref"`. Run it and confirm zero new violations from the added comment.)

- [ ] **Step 5: Commit.**
```bash
git add nix/lib/mk-guest.nix crates/xtask
git commit -m "fix(guest-init): detach sealed-workload stdin from the input-less Vz console"
```

---

## Task 2: `examples/sleeper/` long-lived sealed-workload fixture

**Files:**
- Create: `examples/sleeper/flake.nix`
- Maybe create: `examples/sleeper/flake.lock`

- [ ] **Step 1: Create `examples/sleeper/flake.nix`** mirroring `examples/exit_code/flake.nix`'s exact structure, with a long-lived command and NO plan/PR refs in comments:
```nix
{
  description = "sleeper — long-lived sealed workload fixture for live Vz validation.";

  # A minimal sealed (prod) workload whose PID-1 command never exits, so the
  # VM stays resident long enough to checkpoint / fork / pause / resume and be
  # probed over the guest-agent vsock. The `command` form makes mkGuest infer
  # the sealed/prod image (agent built without the dev-shell console). The
  # `github:tinylabscom/mvm` pin is load-bearing: a source-checkout `mvmctl up`
  # rewrites it to the in-repo flake, so this builds without a release round-trip.

  inputs.mvm.url = "github:tinylabscom/mvm/main?dir=nix";
  inputs.nixpkgs.follows = "mvm/nixpkgs";

  outputs =
    { self, mvm, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: builtins.listToAttrs
        (map (s: { name = s; value = f s; }) systems);
    in
    {
      packages = eachSystem (system:
        {
          default = mvm.lib.${system}.mkGuest {
            name = "sleeper";

            # Never returns: PID-1's workload idles with a portable max-int sleep
            # loop (busybox is already in the rootfs as /bin/busybox), so the VM
            # stays up for live validation.
            entrypoint.command = [
              "/bin/busybox" "sh" "-c"
              "while :; do /bin/busybox sleep 2147483647; done"
            ];

            hypervisor = "libkrun";
            vcpus = 1;
            memory_mib = 256;
          };
        });
    };
}
```

- [ ] **Step 2: Match `exit_code`'s lock handling for the CI `flake-locks-clean` lane.** First check how `exit_code` is treated (it has NO committed lock yet passes CI):
```bash
ls -la examples/exit_code/                       # confirms: no flake.lock
rg -n "exit_code|plan-89-baseline|template_scaffold|EXCLUDE|exclude" .github/workflows/security.yml | head
sed -n '541,594p' .github/workflows/security.yml  # read the flake-locks-clean lane
```
Determine the lane's rule: does it (a) skip flakes with no lock, (b) require a lock for any flake with inputs, or (c) carry an explicit exclude list? Then make `sleeper` match `exit_code`:
  - If `exit_code` passes with no lock (lane skips lockless flakes or excludes the examples) → ship `sleeper` with **no** `flake.lock`, mirroring `exit_code`.
  - If the lane requires a lock for input-bearing flakes → generate one and commit it: `nix flake lock examples/sleeper` (or add `sleeper` to the same exclude list `exit_code` uses, matching the established pattern).
Report which rule applied and what you did. Do NOT diverge from how `exit_code` is handled.

- [ ] **Step 3: Eval-check the new flake.** The `flake-locks-clean` lane discovers it; also eval it directly if nix is available:
```bash
nix flake check --no-build ./examples/sleeper 2>&1 | tail -10 || echo "(nix unavailable locally — CI's flake-locks-clean lane will gate it)"
```
If nix is unavailable in this environment, confirm the flake is syntactically valid by structural comparison to `exit_code/flake.nix` (same shape, only `name`/`description`/`entrypoint.command` differ) and rely on the CI lane. Report which.

- [ ] **Step 4: Commit.**
```bash
git add examples/sleeper
git commit -m "test(examples): sleeper — long-lived sealed workload for live Vz validation"
```

---

## Task 3: Gates + rollup (REFACTOR-STATUS + SPRINT) + PR

- [ ] **Step 1: Workspace gates** (the change is nix + a new example + one xtask test — the Rust suite should be untouched):
```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings 2>&1 | tail -15
cargo test -p xtask 2>&1 | tail -8                       # incl. the new regression test
cargo nextest run --workspace -E 'not package(mvm-backend)' 2>&1 | tail -15
cargo test -p mvm-backend checkpoint:: 2>&1 | tail -4     # plain cargo test (nextest SIGKILLs mvm-backend here)
```
Known `HOME_TEST_LOCK`/fs2-flock + degraded-builder-store flakes pass single-threaded / are pre-existing — confirm, don't chase. Fix any REAL failure in the changed files.

- [ ] **Step 2: Update `specs/REFACTOR-STATUS.md`.** Under PLAN 159 (the vz-DX umbrella) — or as a short standalone note near the WS-2 entry — record the liveness unblock, e.g.:
```
  [x] Vz workload liveness: /init detaches sealed-workload stdin from the
      input-less console + examples/sleeper long-lived fixture (unblocks live
      Vz validation of WS-2 + the fork semantic-A spike)
```
Bump `**Last updated:**` to 2026-06-11. Keep the file's `[x]`/`[~]`/`[ ]` style; don't touch other plans' lines.

- [ ] **Step 3: Update `specs/SPRINT.md`.** This is the Vz backend area — add a concise note under **Sprint 55** (`Virtualization.framework` backend) or the nearest Vz section recording: the sealed-workload-on-Vz init-EOF foot-gun is closed (stdin → /dev/null) and `examples/sleeper` is the long-lived live-validation fixture; the live Vz round-trip bringup + fork semantic-A spike are the tracked next step (best-effort, host-flakiness-gated). Match the file's existing bullet/heading style; keep it short; don't restructure other sprints.

- [ ] **Step 4: Commit + push + open PR** (controller runs the final review + finishing-a-development-branch).
```bash
git add specs/REFACTOR-STATUS.md specs/SPRINT.md
git commit -m "docs: record Vz workload liveness unblock (rollup + sprint)"
```

---

## Live bringup (bonus — NOT a plan task; documented in the design)

After this PR lands, on the Vz Mac: build `examples/sleeper`, `mvmctl up --flake examples/sleeper --hypervisor vz`, confirm it survives past ~5s (agent vsock ping / console.log), then run the WS-2 round-trips (`checkpoint create --class fs-quick`/`fork`, `--class vm-full`/`restore`, `pause`/`resume`) and — if cross-identity restore works — the fork semantic-A spike. This is best-effort and gated on host Vz flakiness (codesign, vsock-proxy hang #673); it does not gate the PR. Captured in `specs/notes/vz-workload-liveness-design.md`.

---

## Notes for the implementer
- The `/init` change is ONE line + a plain-language comment (no spec refs — the lint gate is live). Don't touch the dev arm, the console attachment, or the exit-capture.
- The regression test is a source-level `include_str!` grep — intentionally nix-free so it runs in the normal suite and can't silently regress.
- Mirror `examples/exit_code` exactly for the flake + its lock handling; do not invent a different shape.
