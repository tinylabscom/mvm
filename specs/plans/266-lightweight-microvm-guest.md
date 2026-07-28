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

- [x] **Step 1: Write the failing eval check**

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

- [x] **Step 2: Run the eval test to verify it fails**

```bash
cd nix && nix --extra-experimental-features 'nix-command flakes' \
  eval --file tests/mk-guest-eval.nix --json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print("setpriv_is_static_musl", d["setpriv_is_static_musl"])'
```

Expected: FAIL — `error: attribute 'setpriv' missing` (the derivation has no `passthru.setpriv` yet).

- [x] **Step 3: Implement the swap**

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

- [x] **Step 4: Run the eval test to verify it passes**

```bash
cd nix && nix --extra-experimental-features 'nix-command flakes' \
  eval --file tests/mk-guest-eval.nix --json | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["setpriv_is_static_musl"] is True, d["setpriv_is_static_musl"]; print("PASS")'
```

Expected: PASS. Confirm no other check regressed by scanning the JSON for any `false` value.

- [x] **Step 5: Run the Rust seam + formatting**

```bash
# Root integration test that shells out to the eval file (skips if nix absent).
cargo nextest run --test nix_flake_structure
rustup run nightly cargo fmt --all -- --check
```

Expected: the `nix_flake_structure` test passes (or reports skipped without nix); fmt clean.

- [x] **Step 6: Commit**

```bash
WT=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-light-guest
git -C "$WT" add nix/lib/mk-guest.nix nix/tests/mk-guest-eval.nix
git -C "$WT" commit -m "feat(light-guest): build guest setpriv static-musl, dropping glibc from the rootfs"
```

---

### Task 2: CI-provable no-glibc closure gate

**Files:**
- Modify: `nix/flake.nix` — add a `checks.<system>.guest-rootfs-no-glibc` derivation.
- Modify: `.github/workflows/ci.yml` — build that check in the existing `nix-flake-check` job.
- Modify: `specs/plans/266-lightweight-microvm-guest.md` — add the deferred WS-6 note (budget left as-is).

**Interfaces:**
- Consumes: `libFor` (already in the flake's `let`) and `passthru.rootfsTree` (already exposed; Task 1 added `setpriv`).
- Produces: a build-backed flake check that fails if any `glibc` store path is in the mkGuest rootfs closure — provable on every PR.

**Why a build-backed check, not a byte measurement.** Task 1's eval gate proves `setpriv` *references* the static build. This task proves the *actual closure* carries no glibc — the stronger, end-to-end property — and enforces it in CI. A pure `nix eval` cannot see a derivation's runtime closure, so the check must realize the closure; the `ubuntu-latest` Nix runner builds it natively (no sudo, no darwin linux-builder). The exact rootfs byte budget is deferred to WS-6 — `ROOTFS_MAX_BYTES` gates a packed *release* rootfs, not this `lib` output, so it must not be tightened here.

- [x] **Step 1: Add the check derivation to `nix/flake.nix`**

Add a `checks` output beside the `packages` output (systems come from the existing `systems` list):

```nix
      checks = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          guest = (libFor { inherit system; }).mkGuest {
            name = "no-glibc-check";
            entrypoint.command = [ "/bin/true" ];
          };
        in
        {
          # The mkGuest rootfs is static-musl only. If any glibc store path
          # enters its closure, this build fails — the guest privilege-drop
          # setpriv and every other rootfs binary must stay static.
          guest-rootfs-no-glibc =
            pkgs.runCommand "guest-rootfs-no-glibc"
              { closure = pkgs.closureInfo { rootPaths = [ guest.passthru.rootfsTree ]; }; }
              ''
                if grep -Eq -- '-glibc(-|$)' "$closure/store-paths"; then
                  echo "glibc present in guest rootfs closure:" >&2
                  grep -- '-glibc' "$closure/store-paths" >&2
                  exit 1
                fi
                echo ok > "$out"
              '';
        });
```

- [x] **Step 2: Verify the check evaluates (local, no build, no sudo)**

```bash
cd nix
nix --extra-experimental-features 'nix-command flakes' eval \
  .#checks.x86_64-linux.guest-rootfs-no-glibc.drvPath
```

Expected: prints a `/nix/store/…-guest-rootfs-no-glibc.drv` path. Cross-system eval works on macOS; this confirms the derivation and its `closureInfo` input are well-formed. Do NOT `nix build` it here — realizing an `x86_64-linux`/`aarch64-linux` closure on this macOS host needs the sudo-gated linux-builder, which is out of bounds. The build-proof runs in CI (Step 3). Also run the existing loop to confirm no eval regression: `nix flake check --no-build ./` from `nix/`.

- [x] **Step 3: Build the check in CI**

In `.github/workflows/ci.yml`, in the `nix-flake-check` job, add a step after "Eval-check every flake":

```yaml
      - name: Guest rootfs carries no glibc
        run: |
          set -euo pipefail
          nix build --print-build-logs \
            ./nix#checks.x86_64-linux.guest-rootfs-no-glibc
```

The runner is `ubuntu-latest` (x86_64-linux); this realizes the rootfs closure (substituted from cache) and fails the job if glibc appears — the per-PR proof.

- [x] **Step 4: Leave the size budget; record the deferred gate**

Do NOT change `xtask/src/perf.rs` `ROOTFS_MAX_BYTES` — it gates a packed release rootfs, a different artifact. Add one line under "## Deferred follow-ups" for WS-6: a mkGuest-rootfs *size* (bytes) budget belongs with the unified footprint ledger; this task lands the *no-glibc* gate, not a byte budget.

- [x] **Step 5: Commit**

```bash
WT=/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-light-guest
git -C "$WT" add nix/flake.nix .github/workflows/ci.yml specs/plans/266-lightweight-microvm-guest.md
git -C "$WT" commit -m "test(light-guest): CI gate asserting the guest rootfs closure carries no glibc"
```

**Notes.** Cap-parity needs no separate runtime witness: util-linux `setpriv`
links libcap-ng unconditionally (no compile-time guard), so a static build
either honors the `--inh-caps`/`--ambient-caps` flags the DNS/egress forks
use or fails to build outright — and the no-glibc check already builds that
binary as part of the rootfs closure.

---

## Deferred follow-ups (campaign roadmap — not built in this plan)

Tracked here per the deferred-work convention; each is its own future plan.

- **WS-2 (lever E):** custom `mvm-setpriv` static-musl helper in `mvm-agentd`, built through `crates/mvm-build/src/guest_agent_build.rs` beside `seccomp-apply`/`netinit`/`verity-init`; decided on WS-1's measured numbers (build only if the ~1 MiB + reduced attack surface justifies owning a privilege primitive).
- **WS-3 (lever B):** the static-musl runtime-overlay cut and separate SDK sidecar
  packaging are complete; automatic runtime attachment for workloads using the
  SDK host-service verbs remains. Tighten the 32 MiB overlay cap after measuring
  the new image.
- **WS-4 (lever D):** add a measured guest-agent RSS gate (≤ ~8 MB); the tokio-free agent already lands most of it.
- **WS-5 (lever A/E):** rootfs closure minimization — CA-bundle trim, kernel-module audit, rootfs package-count budget; absorbs any residual glibc anchor found in Task 2 Step 1.
- **WS-6:** fold rootfs/overlay/closure/kernel/RSS budgets into one `xtask perf footprint` ledger; Task 2 landed the no-glibc closure gate only (`checks.<system>.guest-rootfs-no-glibc`) — the mkGuest-rootfs size (bytes) budget stays deferred here, per `xtask/src/perf.rs`'s `ROOTFS_MAX_BYTES` being left untouched.

## Self-review

- **Spec coverage:** WS-1's two deliverables (the swap + eval gate; the measurement + budget) map to Task 1 and Task 2. Guardrails are Global Constraints. WS-2..6 are the roadmap, explicitly out of this plan.
- **Placeholder scan:** the only value left to the executor is `ROOTFS_MAX_BYTES`, which is derived from a Step-2 measurement, not a guess — the edit locations and the derivation rule are exact.
- **Type consistency:** `passthru.setpriv` is produced in Task 1 and consumed by name in the eval test and Task 2; the string value `"${pkgs.pkgsStatic.util-linux}/bin/setpriv"` is identical at both the guest and the test (same nixpkgs input + system).

## WS-3 handoff

The static runtime-overlay cut is implemented in the follow-up worktree:

- [x] Instantiate all overlay guest executables through `pkgs.pkgsStatic`.
- [x] Remove the loader, `libc.so.6`, `libgcc_s.so.1`, and `patchelf` from the
  runtime overlay staging step.
- [x] Publish the glibc `libmvm_host_services.so` artifact separately as
  `packages.<system>.sdk-sidecar` (including its matching loader, libc, and
  libgcc); both language SDKs default to `/mvm/sdk/lib`.
- [ ] Wire runtime attachment so a workload that uses host-service verbs is
  automatically opted into the SDK sidecar. The default static overlay
  intentionally does not carry the SDK FFI or its glibc closure.
