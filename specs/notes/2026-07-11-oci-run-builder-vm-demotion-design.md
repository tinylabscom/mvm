# Design — Kernel-cheap `machine run --image`; demote the builder VM to a headless nix build engine

**Date:** 2026-07-11
**Owner:** Ari
**Status:** design — approved direction, pending spec review
**Related:** Plan 236 (host-authority runtime roadmap), Plan 242 (overlay-required
runtime rollout — the guest-binary overlay this design depends on, complete on
`feat/overlay-required-plan`/#1613), Plan 239 (kernel-config subtraction),
Plan 221 (in-process rootfs materialize), Plan 213 (attested builder packs),
ADR-046 (two artifact layers / source-checkout hermeticity),
`fix/stage0-homeless-shelter-purity`, `#1640` (fetch pinned workload kernels on
installed builds).

## Problem

`mvmctl machine run --image alpine -it -- /bin/sh` in a source checkout spends
~2 min on an opaque "Builder VM image build", streams raw cargo/nix compile
output over a spinner, and then dies on:

    error: home directory "/homeless-shelter" exists; please remove it to
    assure purity of builds without sandboxing

Running a runtime OCI image should be near-instant and must not build the Nix
builder VM.

### Root cause

Booting a microVM needs three things: (1) an OCI rootfs, (2) the mvm guest
binaries inside it, (3) a Linux kernel. On `main`, (1) and (2) are already
in-process / pure-Rust for an `--image` run — `oci_runtime_inject::inject_mvm_runtime`
overlays init/agent/netd/egress onto the unpacked tree and `materialize_ext4_pure`
writes the ext4. **No nix, no builder VM.** The runtime overlay the user asked
for already exists.

The *only* thing that pulls in the builder VM is **the kernel**:

1. `--image` resolves its kernel via `ensure_workload_kernel()`
   (`crates/mvm-cli/src/commands/env/dev_vz/default_microvm.rs:19`).
2. Source checkouts may **not** download mvm-published artifacts (ADR-046
   hermeticity invariant), so on a cold cache the kernel must be **built
   locally** (`3135b0cca`, #1588).
3. A local kernel build is a Stage 0 nix build that first bootstraps the **whole
   builder VM image** (`bootstrap_builder_vm_image_via_root_dir_stage0`) — the
   "Builder VM image build" spinner and the leaking compile stream.
4. That nix build then fails on the `/homeless-shelter` purity bug (already
   fixed on `fix/stage0-homeless-shelter-purity`).

So the builder VM is today the *vehicle for producing the kernel, and only the
kernel*. The fix is to make the kernel a cheap cached artifact and to demote the
builder VM from an interactive dev environment to a headless build engine.

## Goals

1. `machine run --image` never does more than **acquire a cached-or-one-time
   kernel**; it never redundantly rebuilds the full builder image.
2. Two audiences, two paths:
   - **Installed end-user:** download + verify + cache a prebuilt workload
     kernel (seconds; no builder VM, ever).
   - **Source-checkout contributor:** build the kernel **once**, cache it
     forever; every later run is instant.
3. The **builder VM becomes a headless, single-purpose nix build engine**: it
   builds images (the kernel and user `--flake` images) and nothing else. No
   interactive shell.
4. Builder-VM networking for nix substituters rides **audited host-brokered
   egress** (guest → vsock → host proxy → `cache.nixos.org`), giving
   auditability / attestation / traceability by construction. No raw guest NIC.
5. **`mvmctl dev` interactive subcommands are removed** (`up/down/shell/status`);
   first-class build **logs** replace the "shell in to debug a build" use case.
6. Cold builds are honest: one clear labeled line, logged to a file, `-v`
   streams, failures print the tail + log path.

## Non-goals

- No `mvmctl builder` subcommand tree (YAGNI — auto-build-once needs none; add a
  thin pre-warm verb later only if CI wants it).
- No third-party build caches (Cachix/attic stay off the table — hermeticity).
- No raw guest NIC for the builder VM.
- Not redesigning attestation or the egress data plane — reuse Plan 213 packs
  and the existing host-brokered egress path.
- Not relaxing the ADR-046 source-checkout hermeticity rule for the kernel:
  contributors still build locally; only *installed* builds download.

## Design

### 1. Kernel as a cached artifact (the core)

`ensure_workload_kernel` resolution order, unchanged in spirit, hardened in
practice:

1. **Cached** — `find_cached_workload_kernel` hit → use it (no build, no
   network). Cache key includes the arch + kernel-config fingerprint (already
   in place, #1477) so a config edit invalidates correctly and nothing else
   does.
2. **ReusableBuilder** — non-prod run + an existing builder kernel present →
   reuse it (no build). A contributor who has ever built anything already has a
   kernel here, so the common "cold OCI run" costs **zero** extra build.
3. **Acquire**:
   - Installed build → **download** `vmlinux-<arch>-workload` + checksums,
     hash-verify, cache. Fixes the current 404 by having the release actually
     publish the asset (align with #1640).
   - Source checkout → **one-time local build**, cached forever.

The source-checkout local build must **not** drag in a full builder-VM image
rebuild when a reusable kernel exists, and when it genuinely must build, it is
labeled as a *kernel* build, not a mysterious "Builder VM image build". Land the
`fix/stage0-homeless-shelter-purity` fix so the one-time build succeeds.

### 2. Builder VM = headless nix build engine

- Keep the launch→build→teardown→prune lifecycle (the Stage 0 reaper already
  prunes prefix-agnostically). Remove only the interactive layer.
- **Networking:** no raw NIC. nix substituter fetches go over the audited
  host-brokered egress path (vsock → host proxy → upstream). The host is the
  chokepoint that records provenance — this is *how* goal 4's
  attestation/traceability is satisfied, not a bolt-on.
- **Attestation/traceability:** reuse Plan 213 attested builder packs + the
  chain-signed audit log; every brokered substituter fetch is host-logged.

### 3. Logging: inspect / log / fix (replaces the dev shell)

Every builder/nix build emits:
- one labeled line up front — e.g. `Building workload kernel (one-time, ~2 min)…`
  or `Building image <name>…`;
- full output streamed to a **log file** at a stable path echoed to the user;
- live stream when `-v`/`--verbose` is passed;
- on failure: the last ~30 lines **plus** the log path, not the raw
  cargo-over-spinner soup.

This is the entire justification for removing `mvmctl dev`: if you can read,
tail, and diagnose a build from its log, you never need a shell inside the
builder.

### 4. Remove `mvmctl dev`

- Delete `dev up/down/shell/status` and the interactive builder-shell paths
  (PTY/console-over-vsock *into the builder*; the workload console path is
  untouched — claim 15).
- Keep the builder VM launch/build/teardown internals the build path calls.
- **Descope consequence:** in-flight interactive-dev work
  (`feat/plan-222-phase4-devbackend-hvf` — HVF dev VM + `/work` virtiofs shell,
  and siblings) is abandoned by this decision. Flag before landing.

## Sequencing (multi-workstream)

- **WS1 — Unblock.** Land `fix/stage0-homeless-shelter-purity`. Small.
- **WS2 — Kernel-cheap run.** Reuse-or-build-once-and-cache; guarantee a reusable
  kernel short-circuits; ensure `--image` never bootstraps the full builder
  image when a kernel is obtainable. Integration test: cold OCI run performs no
  full-builder-image build; second run is instant.
- **WS3 — Logging overhaul.** Log-to-file + `-v` stream + tail-on-failure. This
  gates WS6.
- **WS4 — End-user download.** Release publishes `vmlinux-<arch>-workload` +
  checksums; wire/verify the download path for installed builds (with #1640).
- **WS5 — Builder audited egress.** nix substituters over host-brokered egress;
  attestation/audit witnesses. Reuse existing egress + Plan 213.
- **WS6 — Remove `mvmctl dev`.** Delete interactive subcommands + tests + docs
  once WS3 lands.

WS1→WS3 fix the reported bug and the DX. WS4→WS6 complete the vision.

## Testing

- Cold-cache `machine run --image` integration test: asserts no
  `bootstrap_builder_vm_image` invocation, kernel materialized + cached, and a
  second run resolves `Cached` with no build.
- `/homeless-shelter` purity regression (from the fix branch).
- Logging: build routed to a file; failure surfaces tail + path; `-v` streams.
- `dev` removal: `tests/cli.rs` help/arg-parse updated; no `dev` subcommand.
- Builder egress: substituter fetch is brokered + audited (witness).

## Reconciliation with in-flight work

- **Reuse:** `fix/stage0-homeless-shelter-purity` (WS1), #1640 kernel-pin-fetch
  (WS4), Plan 242 overlay (already provides the guest-binary overlay), Plan 213
  attested packs + existing host-brokered egress (WS5).
- **Supersede / descope:** `mvmctl dev` interactive work incl.
  `feat/plan-222-phase4-devbackend-hvf`.
- This design is a DX-focused consolidation over a heavily-worked area; it does
  not compete with Plan 236 — it delivers Plan 236's "cleaner runtime UX than
  the field" line for the OCI-run path.

## Open risks

- **Reusable-vs-fresh kernel correctness.** Reusing the builder kernel as the
  workload kernel is only safe where configs match; the fingerprint key must
  gate this or a slim workload kernel diverges from a fat builder kernel
  (interacts with Plan 239).
- **Removing `dev` mid-flight.** Several worktrees actively build dev-mode HVF;
  coordinate the descope so we don't strand merged pieces.
- **Release asset availability.** The end-user download path is only as good as
  the release job actually publishing the kernel asset per arch.

## Phasing (agreed 2026-07-11) — 2 phases, 3 PRs

- **PR 1 — the plan.** The implementation plan doc; no code.
- **PR 2 — Phase 1: kernel-cheap `machine run --image`.** WS1 (land
  `fix/stage0-homeless-shelter-purity`) + WS2 (reuse-or-build-once-and-cache
  kernel; `--image` never triggers a redundant full builder-image build) + **WS3
  (build logging/inspection — first-class, not polish)**. Confirm working
  end-to-end before Phase 2.
- **PR 3 — Phase 2: remove `mvmctl dev`.** WS6. **Hard gate:** ships only once
  Phase 1's logging/inspection is *proven* able to diagnose a builder-VM build
  failure from its logs — that inspection capability is the reason `dev` can go.

### Deferred follow-ups (outside the 3-PR scope)

- **WS4 — end-user prebuilt-kernel download / release asset.** Contributor path
  (build-once) is what Phase 1 fixes; the installed-user download is separate.
- **WS5 — builder audited-egress cutover.** Hand off to Plan 236's existing
  builder no-guest-NIC / host-brokered-egress work; do not duplicate it here.
