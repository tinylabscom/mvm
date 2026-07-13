# Plan 249 — Headless builder substrate, store robustness, air-gapped import

**Created:** 2026-07-12
**Related:** Plan 246 (dev removal), Plan 247/248 (macOS-26 `run_in_vm` fallout).
This plan covers the **larger** deferred items those left open.
**Status:** draft (design + sequencing; not yet executed)

The small followups (stale `dev up` code-comments; the stale-doc `mvmctl build --flake`
→ `mvmctl build image --flake` fix) are handled separately. This plan is the three
substantial pieces.

---

## WS-A — Headless builder typed-exec substrate (unblocks `build validate` + `--update-hash` on macOS 26+)

**Problem.** On macOS 26+ these genuine guest ops (`nix flake check`, the `--update-hash`
TOFU `nix build`) have no way to reach a Linux builder: the typed `mvm-builderd` daemon
only runs in the **persistent** boot mode (opt-in, hidden `persistent-builder` verb), the
single-shot builder VM that `build image` uses never spawns it, the persistent path is
**libkrun-only** (Vz was the second backend, now deleted — the socket-discovery still
carries dead Vz-shape code), and HVF (the macOS-26 default) was never wired into it. They
are gated with a clear error today (Plan 248 T4).

**Design.**
1. **On-demand typed-exec wrapper.** A `boot builder → submit one typed op → collect result → teardown` path, reusing the existing `BuilderVm::run_build` boot/teardown machinery but submitting a typed request instead of a `BuilderJob`. This is the missing primitive — `build image` already boots-runs-one-job-teardowns; generalize that to typed ops.
2. **New/confirmed typed ops** in `builder_protocol.rs` (`HostVmRequest`): `FlakeCheck` already exists (used by the opt-in `MVM_BUILDERD_TYPED` path) — route `validate` through the on-demand wrapper by default. Add a `ComputeFodHash { flake_ref, attr }` op for `--update-hash` (blanks `outputHash`, runs `nix build`, scrapes `got: sha256-…`). Do NOT add a generic `Exec { script }` — keep it job/op-shaped.
3. **HVF into the typed path.** Give the HVF builder a persistent/dispatch-marker boot mode + an HVF control-socket-discovery shape (replacing the dead Vz-shape candidate in `resolve_running_builder_socket`). For the on-demand wrapper this can be simpler than full persistent mode — a single typed op over the same transport the single-shot boot already establishes.
4. **Flip the gate → the substrate.** Once (1)–(3) land, `validate`/`--update-hash` call the on-demand typed path instead of returning the Plan 248 T4 error; keep the error only as the `--no-default-features`/unavailable fallback.

**Tasks (sketch):** typed op + protocol; on-demand wrapper (boot→op→teardown); route `validate` through it; `ComputeFodHash` op + route `--update-hash`; HVF socket-discovery shape; remove the T4 gate for these two; live-proof on macOS-26. **Effort: large.** `validate` (FlakeCheck exists) is the near half; `--update-hash` + HVF discovery are the far half.

## WS-B — Builder-store robustness (the corruption/space failure we hit)

**Problem.** `machine run --flake` / `machine build` fail hard with a cryptic "guest did
not write result" from **two independent builder-VM faults**, observed live on macOS-26:
- **(i) Store corruption.** A corrupted persistent nix-store (`EXT4-fs error … Directory
  block failed checksum` → mounts read-only) fails every build. Recovery today is a manual
  `rm -rf ~/.cache/mvm/builder-vm` + full rebuild. The store also grows unbounded (seen at
  111 GB), and a crashed build leaves its multi-GB `input.img` transient behind (the reaper
  only runs on `cache prune` / next launch).
- **(ii) virtiofs share failure → disk-transport no-space.** Even with a **fresh** store,
  the libkrun builder's virtiofs shares don't attach (`virtio-fs: tag <work>/<out>/<job>/
  <mvm-bins> not found` → EINVAL), forcing the disk-transport fallback (`tar x /dev/vdc`),
  which then fails `No space left on device` staging the closure → read-only → no result.
  This is a transport-attach + input-disk-sizing bug, distinct from (i), and blocks
  `--flake` builds on this host regardless of store health. Root-cause the virtiofs
  tag-not-found on the libkrun builder (supervisor share config vs. libkrun version), and
  size the disk-transport input/store for real closures.

**Design.**
1. **Detect + auto-recover a bad store.** When the builder guest reports a read-only /
   checksum-failed store (surface the marker from `mvm-host-vm-init` in the console), the
   host recognizes it and either `e2fsck -fy` the store image or rebuilds it from Stage 0,
   with a clear one-line message — instead of the opaque "guest did not write result".
2. **Eager transient reaping.** Reap a crashed build's transient VM dir (its `input.img`)
   on the next launch even without an explicit `cache prune` (the Stage-0 reaper is
   prefix-agnostic — extend it to the job-transient dirs).
3. **Bound the persistent store.** A size ceiling + GC (`nix-collect-garbage` inside the
   builder, or a store-size check that triggers a prune) so it can't grow to 100 GB+.
4. **`mvmctl doctor` surfaces store health** (size, last-known-good, corruption flag) and
   `mvmctl cache repair` gains a builder-store path.

**Tasks (sketch):** console marker for read-only/corrupt store; host detect + `e2fsck`/rebuild recovery; eager transient reap; store size cap + GC; doctor/cache-repair surface; **root-cause the libkrun virtiofs tag-not-found and size the disk-transport input/store (fault ii)**. **Effort: medium.**

## WS-C — Air-gapped builder-image import (successor to the removed `mvmctl dev import-image`)

**Problem.** `mvmctl dev import-image` let air-gapped operators install a builder VM image
from a local file (no network). It was deleted with `mvmctl dev`; no successor exists
(`BuilderVmBootstrapArgs` is an empty struct), so `mvmctl bootstrap`'s air-gapped hint was
dropped (Plan 248 T4) and the docs carry a `:::caution`.

**Design.** Resurrect the import logic (from the deleted `cmd_dev_import_image` in git
history) as a headless verb — the cleanest shape is a flag on the existing bootstrap verb:
`mvmctl bootstrap --from-image <path>` (installs a local builder image into
`~/.cache/mvm/builder-vm/<arch>/` with hash-verification, no network), plus the matching
`mvmctl builder-vm-bootstrap` internal path. Decide vs. a standalone `mvmctl builder
import <path>` verb. Then restore the air-gapped hint + drop the docs caution.

**Tasks (sketch):** recover import + verify logic; pick the verb shape; wire it; restore the hint/docs. **Effort: small–medium.** Gate on whether air-gapped operators are a supported audience — if not, formally record the capability as dropped instead.

---

## Sequencing
WS-B (robustness) is the highest-value-per-effort — it turns a hard, cryptic, all-builds
failure into a self-healing one, and it's what bit the live check. WS-A (substrate) is the
largest and unblocks two commands; do it once WS-B makes the builder reliable to iterate
on. WS-C is small and independent. Each is its own PR.


---

## Discovered during WS-B PR-1 validation (2026-07-12) — a 3rd, separate `--flake` blocker

Live-testing PR-1 (fault ii fixed: input no longer overflows, the real nix build now runs)
uncovered a **third** independent bug that still blocks `machine run --flake` for SDK flakes,
in the nix image build — NOT builder-store robustness, NOT PR-1 (which touches no `nix/`):

    mvm-rootfs-tree-exit-code> cp: cannot create regular file
      '…/mvm-rootfs-tree-…/usr/local/bin/mvm-addon-dns': No such file or directory

The `mkGuest` rootfs-tree derivation `cp`s guest binaries into `usr/local/bin/` without the
parent dir existing. `nix/lib/mk-guest.nix` was last changed by #1658 (Plan 213 SP3, seeded
closure) and #1613 (runtime overlay) — the regression is in one of those. Likely a one-line
`mkdir -p $out/usr/local/bin` in the rootfs-tree buildCommand, but it needs its own
investigation (the overlay reworked rootfs assembly). **Own fix — file separately.** Until it
lands, `machine run --flake` stays blocked here even with PR-1 + a clean store.
