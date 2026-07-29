# Lightweight microVM guest — WS-1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drop the glibc closure from the mkGuest workload rootfs by building `setpriv` static-musl, and lock the win with an eval-level regression gate plus a measured rootfs budget.

**Architecture:** WS-1 replaced the glibc `pkgs.util-linux` `setpriv` at the four privilege-drop sites with the static-musl build. WS-2 now replaces that baseline with the smaller `mvm-agentd` `mvm-setpriv` binary, built by a dedicated static-musl Nix package; the eval metadata, structural Nix test, and Linux execution tests lock its identity and security behavior. The remaining closure and byte measurements continue through the footprint ledger.

**Tech Stack:** Nix (nixpkgs `pkgsStatic`), the `nix/tests/mk-guest-eval.nix` pure-eval harness (shelled out by root `tests/nix_flake_structure.rs` when `nix` is on PATH), Rust `xtask perf` budget.

## Global Constraints

- Work in the existing worktree `feat/lightweight-microvm-guest` (`../.worktrees/mvm-light-guest`); git via `git -C <wt-abs>`; edit with worktree absolute paths.
- The generated privilege-drop flag surface is preserved **exactly** — `--reuid --regid --clear-groups --no-new-privs` at all sites, plus `--inh-caps=+net_bind_service --ambient-caps=+net_bind_service` at the addon-DNS and egress-client sites. The custom helper implements only that required surface.
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

**Notes.** The custom helper makes capability handling explicit: it keeps only
`CAP_NET_BIND_SERVICE` in the effective, permitted, and inheritable sets when
requested, raises that capability ambiently, and otherwise clears all capability
sets. Linux execution tests cover both branches; the builder-backed Nix build
still proves the guest binary is statically linked for the target.

---

## Deferred follow-ups (campaign roadmap — not built in this plan)

Tracked here per the deferred-work convention; each is its own future plan.

- **WS-2 (lever E):** the custom static-musl `mvm-setpriv` helper is complete as a
  dedicated `mvm-agentd` binary and Nix package; the generated `mkGuest` init now
  uses it instead of util-linux.
- **WS-3 (lever B):** the static-musl runtime-overlay cut and separate SDK sidecar
  packaging are complete; automatic runtime attachment for workloads using the
  SDK host-service verbs remains. The overlay allocation is now capped at 16 MiB,
  with a build-backed footprint gate covering the Nix-built rootfs, overlay,
  verity sidecars, and workload kernel.
- **WS-4 (lever D):** complete. The capability-negotiated `ResourceUsage`
  control request reports the agent's own current RSS through the existing
  `/proc` sampler. A fresh static-musl Dev-profile overlay measured a
  conservative observed peak of 1,372,160 bytes (steady idle: 1,359,872 bytes),
  and `xtask perf footprint --guest-rss-bytes` enforces the 8 MiB ceiling.
- **WS-5 (lever A/E):** the kernel-module metadata audit is complete and the rootfs
  now copies only `modules.dep`. The default tenant also drops its redundant
  dynamic busybox closure. The Mozilla CA bundle is copied into `/etc` without
  retaining its source store path, and a build-backed gate caps the lean registered
  runtime closure at static BusyBox plus `mvm-setpriv`. Because the rootfs is
  immutable, `mkGuest` also removes the generic 16 MiB ext4 growth reserve after
  the nixpkgs image builder runs.
- **WS-6:** complete. `xtask perf footprint` measures the Nix-built rootfs,
  runtime overlay, dm-verity sidecars, and kernel against the literal 50 MB
  complete-artifact contract; validates the exact hash-anchored rootfs closure,
  capped at two store paths; and validates/reports measured guest-agent RSS in
  the same JSON/human ledger. The build-backed ledger measures 33,917,960 bytes
  of storage with 16,082,040 bytes of headroom.

## Self-review

- **Spec coverage:** WS-1's two deliverables (the static baseline + eval gate; the measurement + budget) map to Task 1 and Task 2. WS-2 and the later footprint slices are tracked in the handoff sections below.
- **Placeholder scan:** the only value left to the executor is `ROOTFS_MAX_BYTES`, which is derived from a Step-2 measurement, not a guess — the edit locations and the derivation rule are exact.
- **Type consistency:** `passthru.mvm.setprivHelperName` records the generated init's helper identity without forcing the target derivation during pure eval; the structural test checks the actual `/bin/mvm-setpriv` path wiring.

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

## WS-2 handoff

- [x] Add the narrow `mvm-setpriv` parser and exec binary to `mvm-agentd`.
- [x] Implement numeric uid/gid replacement, supplementary-group clearing,
  no-new-privileges, full capability dropping, and the optional
  `CAP_NET_BIND_SERVICE` inheritable/ambient path.
- [x] Build the helper through a dedicated static-musl Nix package and use it
  from every generated `mkGuest` privilege-drop site.
- [x] Add parser tests and a structural Nix test proving the util-linux path is
  no longer part of `mkGuest`.

## WS-5/WS-6 handoff

- [x] Copy only `modules.dep` from the kernel module metadata; retain the
  module files and dependency closures required by VSOCK and virtio-fs.
- [x] Cap the static runtime overlay allocation at 16 MiB after confirming
  the source-built overlay is approximately 5.3 MiB.
- [x] Add `xtask perf footprint` with JSON and human-readable output for the
  rootfs, overlay, optional dm-verity sidecars, and optional kernel.
- [x] Add a CI build-backed gate that runs the ledger against the Nix-built
  default-tenant image, runtime overlay, verity sidecars, and kernel with a
  50 MB limit.
- [x] Remove the default tenant's redundant dynamic busybox input. The measured
  Nix-built rootfs is 27,330,560 bytes; rootfs + overlay + both verity sidecars
  total 36,771,840 bytes and pass the 50 MB ledger gate.
- [x] Copy the Mozilla CA bundle into `/etc` without retaining the `cacert` source
  store path, and build-gate the lean registered runtime closure at two paths.
  The measured Nix-built rootfs is 26,718,208 bytes; rootfs + overlay + both
  verity sidecars total 36,139,008 bytes (34.46 MiB), leaving 13,860,992 bytes
  below the 50 MB limit.
- [x] Count the 14,460,936-byte workload kernel in the same ledger and CI gate.
  The first all-in measurement was 50,599,944 bytes (48.26 MiB), exposing that
  the artifact was 599,944 bytes over the original literal 50 MB target.
- [x] Export the exact rootfs closure inventory from the default-tenant image and
  validate it in the unified ledger. The build-backed measurement contains two
  hash-anchored paths: static BusyBox and static `mvm-setpriv`.
- [x] Add a capability-negotiated guest-agent RSS query, measure the rebuilt
  static agent in a live guest, and enforce the 8 MiB limit in the unified
  ledger. The Dev-profile peak was 1,372,160 bytes.
- [x] Re-minimize the immutable Nix-built ext4 rootfs after nixpkgs adds its
  generic 16 MiB growth reserve, verify it with `e2fsck`, and tighten the
  complete-artifact gate from 50 MiB to exactly 50,000,000 bytes. The rootfs
  falls from 26,718,208 to 10,499,072 bytes; its verity sidecar falls from
  851,968 to 339,968 bytes. Rootfs + overlay + both verity sidecars +
  14,460,936-byte kernel total 33,917,960 bytes (32.35 MiB), leaving
  16,082,040 bytes below the literal 50 MB target.
