# Plan 161 — OCI-unpacker TOCTTOU fix + ADR-002 positioning note (Plan 143 R2 + R3)

> Number 161 is free against `origin/main` + the working tree. Reconcile against
> open PRs before merge — `xtask check-spec-numbers` hard-fails on a duplicate
> prefix.
>
> **Relationship to Plan 143:** this is the *execution* breakdown of Plan 143's
> two **unblocked** tasks — R2 (OCI unpacker) and R3 (ADR note). It deliberately
> **excludes R1** (the ioctl seccomp denylist), which Plan 143 gates behind Plan
> 120 `core_demo_e2e` going green. Pulling R2/R3 into their own plan lets them
> land now without waiting on the gate. Plan 143 stays the parent / source of
> truth; this doc adds the fine-grained red→green steps it only sketched.

## Context

The OCI layer unpacker is the one place mvm parses genuinely attacker-controlled
input (image tar layers). Its path-escape defense currently ends in a
**check-then-use**: it walks parent components with `symlink_metadata` (check)
and a later call writes (use); `O_NOFOLLOW` only guards the *leaf* open, not the
intermediate dirs the kernel traverses. That is a TOCTTOU window — a parent
component swapped to a symlink between the walk and the write escapes the root.
The kernel-native fix (`openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`)
closes the window atomically and deletes the bespoke walk. R3 records *why* mvm
takes this in-guest hardening at all given the hardware boundary, pre-empting the
recurring "why not seccomp/Landlock in a namespace?" review question.

Neither task is gated; both are off the flake spine (different crate / doc).

## Non-goals

- R1 (ioctl TIOCSTI/TIOCLINUX denylist) — gated on Plan 120; stays in Plan 143.
- New dependencies. Use `openat2` via an existing workspace crate if one is
  already present (e.g. `rustix`), otherwise the raw `libc::syscall(SYS_openat2…)`
  path — `libc` is already a dep. Do **not** add a crate for this (see the
  limit-dependencies discipline).
- Re-homing the unpacker off-host — it already runs only in the Linux builder VM
  (ADR-050), which is exactly why `openat2` (Linux ≥ 5.6) is available.

## Task R2 — close the OCI-unpacker TOCTTOU with `openat2`

**Where:** `crates/mvm-oci/src/unpack.rs`. The current 5-layer defense is
documented at `:85-114`; the relevant sites are `unpack_layer:470`,
`starts_with(output_root):562`, `parent_chain_has_symlink:904`, the leaf
`O_NOFOLLOW:104`, and the write/dir/symlink helpers at `:1128/:1179/:1287/:1325`.
Refusals already flow through `RefusalReason::SymlinkInParent` / `JoinedPathEscape`.

- [ ] **Step 1 (red):** add a regression test that swaps a parent component to a
      symlink *mid-unpack* (after the prefix exists, before the leaf write) and
      asserts the entry is refused — mapped to the existing `RefusalReason`, not a
      bare error. Add a small escape corpus (`..`, absolute, separator-quirk,
      symlinked-parent) as table-driven cases. The symlink-swap case must fail
      against the current check-then-use code, proving the gap is real.
- [ ] **Step 2 (green):** under `cfg(target_os = "linux")`, resolve each entry's
      **parent directory** relative to an `output_root` dirfd via `openat2` with
      `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, then create the leaf with `*at`
      calls (`openat`/`mkdirat`/`symlinkat`/`linkat`) against that returned dirfd —
      never against a re-derived host path. Keep the cheap string checks
      (`..`/absolute) as fail-fast, but make `openat2` the **authority**: an
      `EXDEV`/`ELOOP`/`EXDEV`-class refusal from the kernel maps to
      `RefusalReason::SymlinkInParent` (symlink/`RESOLVE_NO_SYMLINKS`) or
      `JoinedPathEscape` (`RESOLVE_IN_ROOT` boundary). Delete
      `parent_chain_has_symlink` once `openat2` subsumes it. Non-Linux retains the
      current logic behind `cfg` (it's a test-only build target).
- [ ] **Step 3 (preserve invariants):** confirm the existing handling is intact —
      whiteout markers, hardlink-target-missing refusal, device-node allowlist,
      setid/xattr policy, and timestamp-zeroing reproducibility. The change is a
      swap of the *resolution mechanism*, not the policy. Re-run the
      reproducible-unpack byte-identity assertion.
- [ ] **Step 4 (fuzz):** extend `crates/mvm-oci/fuzz/fuzz_targets/unpack_layer.rs`
      with the escape corpus (coordinate the gate wiring with Plan 128's fuzz
      re-homing — this plan adds the corpus + behavior; Plan 128 owns the CI lane,
      do not duplicate a gate here).

**R2 acceptance:**
- [ ] The symlink-swap regression + escape corpus pass; the symlink-swap test
      demonstrably failed before Step 2 and passes after.
- [ ] `parent_chain_has_symlink` is gone (or reduced to the fail-fast string
      check); `openat2` is the resolution authority on Linux.
- [ ] Whiteout / hardlink / device-node / setid handling and reproducible-unpack
      byte-identity unchanged.

## Task R3 — ADR-002 positioning note

**Where:** `specs/adrs/002-microvm-security-posture.md`, the Threat-model /
out-of-scope discussion (prose, **not** the numbered claim table).

- [ ] **Step 1:** add one paragraph stating *why* mvm chose a hardware boundary
      (KVM/VMM) over a userspace application-kernel sandbox — stronger isolation,
      no syscall-compat surface, no in-process TOCTTOU class — and citing that
      class of sandbox as the reference for the in-guest hardening layer (R2 here,
      R1 in Plan 143). Keep it **name-clean**: oblique "userspace application-kernel
      sandbox" phrasing only, matching the scrubbed Plan 143 — no product name.
- [ ] **Step 2:** keep it out of the numbered claim table. This is adjacent-threat
      *positioning*, so it belongs in §Threat model, not §Out of scope and not as
      a new claim (the out-of-scope list only carries items in the same threat
      model as a claim). Do not add a `specs/claims/` witness — there's no new
      claim. `xtask check-spec-numbers` + ADR lint must pass.

**R3 acceptance:**
- [ ] ADR-002 records the hardware-boundary-vs-application-kernel rationale; no new
      numbered claim; `specs/claims/catalog.md` untouched.

## Verification (whole plan)

- [ ] `rustup run nightly cargo fmt --all -- --check` (CI Lint uses nightly
      rustfmt; stable under-formats).
- [ ] `cargo test --workspace` green, including the new R2 tests.
- [ ] `cargo clippy --workspace -- -D warnings` clean.
- [ ] `crates/mvm-oci/fuzz` builds with the extended corpus (`cargo +nightly
      fuzz build unpack_layer`); a short local run finds no immediate escape.
- [ ] `just lint` green.

## Sequencing / ownership

- R2 and R3 are independent of each other and of Plan 120 — land in any order.
- CI-gate wiring (the unpack fuzz lane, the ADR/CLAUDE.md security-section
  reconcile) routes through **Plan 128**, Stage D — same as Plan 143. This plan
  delivers behavior + corpus; Plan 128 owns the gate. Don't add a parallel gate.
- On completion, tick R2/R3 in Plan 143's Task 2 / Task 3 checklists so the parent
  stays accurate; R1 remains open and gated there.
