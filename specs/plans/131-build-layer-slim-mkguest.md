# Plan 131 — Build layer: slim `mkGuest`, off `microvm.nix`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the image build off the heavy `microvm.nix` substrate (full NixOS, systemd PID-1, large closure) onto a slim `mkGuest` — a minimal non-NixOS rootfs assembled with `mkfs.ext4 -d` (populate-at-format), busybox PID-1, a tiny kernel — so the boot budget (§7, sub-150 ms) is reachable, while the four authoring surfaces still lower to one IR → one build and the agent rides the verity overlay (ADR-051), image-source-agnostic.

**Architecture:** ADR-066 "Patterns" (the build-layer note) is explicit: v2's build is layered on `microvm.nix` (ADR-013), which produces *full NixOS* microVMs — too heavy for the slim base the boot budget demands. The rewrite replaces it with slim `mkGuest`. **Keep** from `microvm.nix`'s design (it's a good design for what it does): the per-hypervisor **runner** abstraction (validates `VmBackend` — "add a backend = add a runner"), the hypervisor restriction matrix (e.g. Firecracker: no 9p/virtiofs shares), **erofs** as a read-only-root option to measure against squashfs, and the read-only-root + writable-overlay model (validates ADR-051). The existing `nix/lib/mk-guest.nix` already carries the overlay-aware `/init` + the agent-resolution ladder; this plan slims the *base* it assembles.

**Tech Stack:** Nix (`nix/lib/mk-guest.nix`, `nix/images/*`), `mkfs.ext4 -d` (e2fsprogs, populate-at-format — ADR-065), busybox, the custom tiny kernel (`nix/images/builder-vm/kernel`, `CONFIG_MODULES=n`), erofs-utils + squashfs-tools (measured), the verity initramfs (ADR-051). No new Rust deps.

**Prereqs:** 121 (the `mvm-build` home + the host-bin moves). **Enables 127** (the boot number — the slim build is what makes sub-150 ms measurable) and feeds 124 (the overlay carries the lean agent onto the slim base). 120's deferred slim-`mkGuest` follow-up lands here.

**Why a dedicated plan:** the build-layer move is a substantial, self-contained pipeline rewrite (image assembly, PID-1, kernel, read-only-root strategy). It is not structural consolidation (121), dep reduction (126), or storage (123) — it fell out of the Stage-C set; this is its home.

---

## Phase A — slim rootfs assembly

### Task A1: `mkfs.ext4 -d` populate-at-format (no loopback)

ADR-065 — assemble the rootfs from a staged directory directly at format time, no loopback mount, no root.

**Files:** `nix/lib/mk-guest.nix` (the rootfs derivation); the staged-tree builder.

- [ ] **Step 1:** Failing test (`nix flake check` on a slim image) — `mkGuest` produces a `rootfs.ext4` from a staged dir via `mkfs.ext4 -d <staged>`, with no `microvm.nix` import in the derivation's closure (`nix path-info -r` has no `microvm` / `nixos` system closure).
- [ ] **Step 2:** Stage the tree (busybox + the workload entrypoint + `/etc/{passwd,group,nsswitch}` read-only + the mount points incl. `/mvm/runtime`) and `mkfs.ext4 -d` it. Keep the existing `passthru.mvm.{accessible,sealed,overlayAware}` so the manifest emit (plan 120) still works. Commit.

### Task A2: busybox PID-1 (no systemd)

- [ ] **Step 1:** Failing test — the slim image boots to the agent with busybox `/init` (the existing `mk-guest.nix` `/init` script), no systemd in the closure; a minimal PID-1 init-detection ladder (the survey's note) handles the cases.
- [ ] **Step 2:** Wire the busybox init; the `/init` forks the agent at stage 2.5 as today (the agent path is unchanged — plan 124). Commit.

### Task A3: the tiny kernel

- [ ] **Step 1:** The custom kernel (`CONFIG_MODULES=n`, everything in-tree `=y`) ships no `/lib/modules` tree (ADR via plan 92's minimal-kernel work). Confirm the slim rootfs needs none. Failing test: the image boots on the kernel with no module-load attempts. Commit.

## Phase B — read-only-root + writable-overlay (ADR-051)

### Task B1: read-only base + the verity runtime overlay

The slim base is read-only; the agent (+ netinit/seccomp-apply) ride the verity-sealed `/mvm/runtime` overlay (ADR-051 / plan 124). This is the "every image-source gets the agent without baking it in" property.

- [ ] **Step 1:** Failing test — a slim image with the overlay attached runs the agent from `/mvm/runtime/agent` (not a baked copy); the base rootfs is mounted `ro`; writes go to the writable upper (123 snapshot-upper) / tmpfs. A tampered overlay fails the dm-verity roothash (claim 3).
- [ ] **Step 2:** Wire the read-only-root + writable-overlay + `mvm-verity-init` bind-mount (composes with plan 124 C1). Commit.

## Phase C — read-only-root format: erofs vs squashfs

### Task C1: measure smaller-vs-faster

The survey flagged erofs (smaller) vs squashfs (faster) for the read-only root. Measure, don't guess.

- [ ] **Step 1:** Build the slim base both ways; record image size + the read-only-root contribution to the `spawn`/`kernel` boot phases (plan 127's harness). Write the numbers to `docs/investigations/`.
- [ ] **Step 2:** Pick the default from the data (note the tradeoff); keep the other behind a flag. Commit.

## Phase D — keep the runner abstraction + restriction matrix

### Task D1: per-hypervisor runner (validates `VmBackend`)

`microvm.nix`'s runner-per-hypervisor maps onto `VmBackend` ("add a backend = add a runner"). Preserve it: the slim image declares its hypervisor constraints (the restriction matrix — e.g. Firecracker: no 9p/virtiofs) so `VmBackend` selection respects them.

- [ ] **Step 1:** Failing test — the image's `passthru` carries the hypervisor restriction matrix; a backend that violates a constraint (asks Firecracker for virtiofs) is refused with a typed error (ADR-053), not a silent failure.
- [ ] **Step 2:** Encode the matrix in `mk-guest.nix` `passthru`; `mvm-backend` selection reads it. Commit.

## Phase E — boot-budget validation

### Task E1: the slim build hits the budget

- [ ] **Step 1:** Run plan 127's per-phase boot harness on the slim image vs the old `microvm.nix` image (where still buildable); record cold + warm per backend. The slim image should move the `kernel`+`init` phases materially toward the sub-150 ms target.
- [ ] **Step 2:** Add the slim-image boot numbers to `docs/budgets.json` (127's dashboard). If the budget isn't met, the harness flags it (warning, not a gate — §7). Commit.

## Acceptance

- [ ] `mkGuest` produces a slim rootfs via `mkfs.ext4 -d` with **no `microvm.nix`/NixOS system closure**; busybox PID-1; the tiny kernel; `nix flake check` green.
- [ ] Read-only base + the verity runtime overlay (ADR-051) carries the agent; a tampered overlay fails the roothash; writes go to the upper.
- [ ] erofs-vs-squashfs measured, a default chosen from data, numbers in `docs/investigations/`.
- [ ] The per-hypervisor restriction matrix rides `passthru`; a violating backend is refused with a typed error.
- [ ] The slim image's boot phases are measured (127) and recorded in `docs/budgets.json`; the four authoring surfaces still lower to this one build.
- [ ] `cargo test --workspace` + the affected `nix flake check`s green; no new Rust dep.

### deferred follow-ups

- [ ] Drop the `microvm.nix` dependency from `flake.nix` entirely once the slim path is the only one (a CHANGELOG + ADR-013 supersession note).
- [ ] Per-workload base-image caching (the COW shared-base from 123 B3) over the slim base.

## Self-review

- **Spec coverage (ADR-066 build-layer note):** slim `mkGuest` + `mkfs.ext4 -d` (Phase A), read-only-root + overlay (B), erofs/squashfs measurement (C), the runner abstraction + restriction matrix (D), boot-budget validation (E). All the "keep from microvm.nix" items are preserved.
- **Grounding:** extends the real `nix/lib/mk-guest.nix` (the overlay-aware `/init` exists); ties to ADR-065 (`mkfs.ext4 -d`), ADR-051 (overlay), plan 92 (tiny kernel), plan 124 (agent on overlay), plan 127 (boot numbers).
- **Honesty:** erofs-vs-squashfs is measured not asserted; the boot-budget check flags, doesn't fail (§7); the `microvm.nix` drop is staged (Phase A removes the system closure; the deferred follow-up removes the flake input once the slim path is sole).
- **Voice:** comments/notes mark the non-obvious (why populate-at-format avoids loopback/root, why the agent rides the overlay not the base, why the restriction matrix must refuse not degrade), not the mechanics.
