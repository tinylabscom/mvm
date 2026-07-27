# Lightweight microVM guest — WS-1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drop the glibc closure from the mkGuest workload rootfs by building `setpriv` static-musl, and lock the win with an eval-level regression gate plus a measured rootfs budget.

**Architecture:** `nix/lib/mk-guest.nix` currently references the glibc `pkgs.util-linux` `setpriv` at four privilege-drop sites — the sole glibc anchor in the busybox-PID-1 rootfs. Swap those to `pkgs.pkgsStatic.util-linux` (static-musl, closure = the binary itself), surface the chosen `setpriv` path in `passthru`, and assert its provenance in the existing pure-Nix eval test. Then measure the closure delta and set the rootfs budget from the number.

**Tech Stack:** Nix (nixpkgs `pkgsStatic`), the `nix/tests/mk-guest-eval.nix` pure-eval harness (shelled out by root `tests/nix_flake_structure.rs` when `nix` is on PATH), Rust `xtask perf` budget.

## Global Constraints

- Work in the existing worktree `feat/lightweight-microvm-guest` (`../.worktrees/mvm-light-guest`); git via `git -C <wt-abs>`; edit with worktree absolute paths.
- The `setpriv` flag surface is preserved **exactly** — `--reuid --regid --clear-groups --no-new-privs` at all sites, plus `--inh-caps=+net_bind_service --ambient-caps=+net_bind_service` at the addon-DNS and egress-client sites. Static-musl util-linux ships the same full `setpriv`; only the link mode changes.
- Security witnesses stay green: setpriv uid / no-new-privs drops (host-fs confinement, no uid-0 elevation), dm-verity roothash seal, prod agent with no `do_exec`/console. A lightness change that flips a claim is a regression.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs`); reword to the concept. Spec docs may reference them; code may not.
- DRY: one `let`-bound `setpriv` path, not four inline store-path expressions.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push (CI Lint uses nightly rustfmt); run `cargo nextest run --workspace` before push (filtered runs miss shape/count tests).
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- **Environment note:** Task 1's `nix eval` and Task 2's `nix build` require `nix` on PATH. Where the executing host has no `nix`, apply the edits, run the Rust pin test, and defer the nix eval/build verification to CI — state that explicitly rather than claiming a green you did not observe.

---

### Task 1: Swap `setpriv` to static-musl util-linux + eval regression gate

**Files:**
- Modify: `nix/lib/mk-guest.nix` — add the `setpriv` binding near `busybox` (~line 43); replace the four `${pkgs.util-linux}/bin/setpriv` references (lines ~294, ~693, ~757, ~817); reword the justification comments (~274–296, ~813–816); expose `setpriv` in `passthru` (~line 1385, beside `inherit rootfsTree;`).
- Test: `nix/tests/mk-guest-eval.nix` — add one boolean check to the returned attrset.

**Interfaces:**
- Produces: `passthru.setpriv` on every mkGuest derivation — a string, the absolute store path `"${pkgs.pkgsStatic.util-linux}/bin/setpriv"`. Task 2 and the eval test read it.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing eval check**

In `nix/tests/mk-guest-eval.nix`, add to the returned attrset (sibling to `agent_binary_is_real`):

```nix
  # ── Privilege-drop binary provenance ─────────────────────────
  #
  # setpriv must be the static-musl util-linux build, not the glibc one.
  # busybox's stripped setpriv lacks --reuid/--regid/--clear-groups, so we
  # need the full binary — but the *static* build keeps glibc out of the
  # rootfs closure. A revert to the dynamic util-linux flips this and fails
  # before the closure regrows.
  setpriv_is_static_musl =
    shellGuest.setpriv == "${pkgs.pkgsStatic.util-linux}/bin/setpriv"
    && commandGuest.setpriv == "${pkgs.pkgsStatic.util-linux}/bin/setpriv";
```

- [ ] **Step 2: Run the eval test to verify it fails**

```bash
cd nix && nix --extra-experimental-features 'nix-command flakes' \
  eval --file tests/mk-guest-eval.nix --json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print("setpriv_is_static_musl", d["setpriv_is_static_musl"])'
```

Expected: FAIL — `error: attribute 'setpriv' missing` (the derivation has no `passthru.setpriv` yet).

- [ ] **Step 3: Implement the swap**

In `nix/lib/mk-guest.nix`, beside `busybox = pkgs.pkgsStatic.busybox;` (~line 43):

```nix
  # Static-musl util-linux setpriv. busybox's stripped setpriv applet lacks
  # --reuid/--regid/--clear-groups, so /init needs the full util-linux binary
  # to drop privilege before exec. The *static* build's runtime closure is the
  # binary itself — no glibc — so it does not drag glibc into the rootfs.
  setpriv = "${pkgs.pkgsStatic.util-linux}/bin/setpriv";
```

Replace the `setprivWrap` body reference (~line 294):

```nix
      "${setpriv} "
      + "--reuid=${toString uid} --regid=${toString uid} "
      + "--clear-groups --no-new-privs -- ${cmd}";
```

Replace each of the three `/init` fork sites (~lines 693, 757, 817), leaving every flag untouched — only the path token changes:

```nix
      /bin/busybox setsid ${setpriv} \
```

Reword the two justification comment blocks (~274–296 and ~813–816) so they describe the static build (busybox-lacks-the-flags reasoning stays; drop any wording that implies the glibc/dynamic build is required — it is not). Keep them free of spec-ref tokens.

Add to the `passthru` attrset (~line 1385, beside `inherit rootfsTree;`):

```nix
    inherit setpriv;
```

- [ ] **Step 4: Run the eval test to verify it passes**

```bash
cd nix && nix --extra-experimental-features 'nix-command flakes' \
  eval --file tests/mk-guest-eval.nix --json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["setpriv_is_static_musl"] is True, d["setpriv_is_static_musl"]; print("PASS")'
```

Expected: PASS. Confirm no other check regressed by scanning the JSON for any `false` value.

- [ ] **Step 5: Run the Rust seam + formatting**

```bash
# Root integration test that shells out to the eval file (skips if nix absent).
cargo nextest run --test nix_flake_structure
rustup run nightly cargo fmt --all -- --check
```

Expected: the `nix_flake_structure` test passes (or reports skipped without nix); fmt clean.

- [ ] **Step 6: Commit**

```bash
WT=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-light-guest
git -C "$WT" add nix/lib/mk-guest.nix nix/tests/mk-guest-eval.nix
git -C "$WT" commit -m "feat(light-guest): build guest setpriv static-musl, dropping glibc from the rootfs"
```

---

### Task 2: Measure the glibc drop and set the rootfs budget

**Files:**
- Modify: `xtask/src/perf.rs` — `ROOTFS_MAX_BYTES` (~line 57) and its pin test (~line 410).

**Interfaces:**
- Consumes: `passthru.setpriv` and `passthru.rootfsTree` from Task 1.
- Produces: an updated, measured rootfs budget pinned by test.

- [ ] **Step 1: Prove glibc is gone from the rootfs closure**

Build the mkGuest rootfs tree for a minimal sealed workload and inspect its closure:

```bash
cd nix
TREE=$(nix --extra-experimental-features 'nix-command flakes' build --impure --no-link --print-out-paths \
  --expr 'let f = builtins.getFlake (toString ./.); g = f.lib.x86_64-linux.mkGuest { name = "measure"; entrypoint.command = ["/bin/true"]; }; in g.passthru.rootfsTree')
echo "rootfsTree: $TREE"
nix --extra-experimental-features 'nix-command flakes' path-info -rsSh "$TREE" | sort -k2 -h | tail -20
nix --extra-experimental-features 'nix-command flakes' path-info -r "$TREE" | grep -i glibc && echo "GLIBC STILL PRESENT — investigate" || echo "no glibc in rootfs closure"
```

Expected: `no glibc in rootfs closure`. If glibc persists, another store path anchors it — record the offending path; it becomes a WS-5 (rootfs closure minimization) item, and this task stops here with that finding.

- [ ] **Step 2: Measure the ext4 byte delta**

Build the packed rootfs image (the derivation itself, not the tree) on this branch and on `main`, and record both sizes:

```bash
cd nix
build_ext4() {
  nix --extra-experimental-features 'nix-command flakes' build --impure --no-link --print-out-paths \
    --expr 'let f = builtins.getFlake (toString ./.); in f.lib.x86_64-linux.mkGuest { name = "measure"; entrypoint.command = ["/bin/true"]; }'
}
AFTER=$(build_ext4); echo "after (static setpriv): $(stat -c%s "$AFTER"/*.ext4 2>/dev/null || stat -f%z "$AFTER"/*.ext4) bytes"
# Repeat from a clean `main` checkout for the baseline; record both numbers in the commit body.
```

Record the before/after rootfs bytes and the closure-size delta in the Task 2 commit message — these seed the campaign scoreboard.

- [ ] **Step 3: Set the budget from the measurement**

`ROOTFS_MAX_BYTES` gates the packed release/pack rootfs (`release.yml`, `security.yml`, `pack-signing-smoke.yml` invoke `xtask perf rootfs-size --rootfs …`). Decide from Step 2:

- If the measured `after` rootfs is comfortably below the current 20 MiB, tighten `ROOTFS_MAX_BYTES` (`xtask/src/perf.rs:57`) to `after` rounded up with ~15% headroom, and update the pin test (`xtask/src/perf.rs:410`):

```rust
pub const ROOTFS_MAX_BYTES: u64 = <measured_after_plus_headroom>; // set from Step 2
```
```rust
assert_eq!(ROOTFS_MAX_BYTES, <measured_after_plus_headroom>);
```

- If the packed rootfs the gate measures does not reflect the mkGuest closure (a different artifact), leave `ROOTFS_MAX_BYTES` unchanged, and add a one-line note in the plan's deferred section that a mkGuest-rootfs size gate belongs to WS-6 (unified footprint ledger). Do not tighten a budget against the wrong artifact.

- [ ] **Step 4: Run the pin test**

```bash
cargo nextest run -p xtask perf
```

Expected: PASS (the `ROOTFS_MAX_BYTES` pin test agrees with the constant).

- [ ] **Step 5: Commit**

```bash
WT=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-light-guest
git -C "$WT" add xtask/src/perf.rs
git -C "$WT" commit -m "perf(light-guest): record glibc-drop rootfs measurement and set the budget"
```

---

## Deferred follow-ups (campaign roadmap — not built in this plan)

Tracked here per the deferred-work convention; each is its own future plan.

- **WS-2 (lever E):** custom `mvm-setpriv` static-musl helper in `mvm-agentd`, built through `crates/mvm-build/src/guest_agent_build.rs` beside `seccomp-apply`/`netinit`/`verity-init`; decided on WS-1's measured numbers (build only if the ~1 MiB + reduced attack surface justifies owning a privilege primitive).
- **WS-3 (lever B):** unify the runtime-overlay binaries on static-musl and drop the glibc loader/`libc.so.6`/`libgcc_s.so.1` bundle from `nix/images/runtime-overlay/flake.nix`; needs a mini-design for moving `libmvm_host_services.so` (the FFI cdylib SDKs dlopen) to an SDK-workload sidecar. Tighten the 32 MiB overlay cap after.
- **WS-4 (lever D):** add a measured guest-agent RSS gate (≤ ~8 MB); the tokio-free agent already lands most of it.
- **WS-5 (lever A/E):** rootfs closure minimization — CA-bundle trim, kernel-module audit, rootfs package-count budget; absorbs any residual glibc anchor found in Task 2 Step 1.
- **WS-6:** fold rootfs/overlay/closure/kernel/RSS budgets into one `xtask perf footprint` ledger; add the mkGuest-rootfs size gate if Task 2 Step 3 deferred it.

## Self-review

- **Spec coverage:** WS-1's two deliverables (the swap + eval gate; the measurement + budget) map to Task 1 and Task 2. Guardrails are Global Constraints. WS-2..6 are the roadmap, explicitly out of this plan.
- **Placeholder scan:** the only value left to the executor is `ROOTFS_MAX_BYTES`, which is derived from a Step-2 measurement, not a guess — the edit locations and the derivation rule are exact.
- **Type consistency:** `passthru.setpriv` is produced in Task 1 and consumed by name in the eval test and Task 2; the string value `"${pkgs.pkgsStatic.util-linux}/bin/setpriv"` is identical at both the guest and the test (same nixpkgs input + system).
