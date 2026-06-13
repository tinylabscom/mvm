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

- [x] **Step 1 (red):** added `concurrent_symlink_swap_in_parent_never_escapes_root`
      (`cfg(target_os = "linux")`): a swapper thread flips a parent component
      between a real dir and an out-of-root symlink while the unpacker writes
      `p/q/secret`; the test asserts nothing ever lands at the out-of-root escape
      target. A deterministic single-process witness of the exact check→write
      window is not constructible — zero tar-stream reads sit between
      `parent_chain_has_symlink` and the leaf open, so single-threaded the existing
      string+walk checks are sound; the residual gap is a concurrent parent swap.
      The witness therefore is the concurrency test, and it inspects only the
      escape target so the racing swapper can never make it flaky post-fix.
      Box-verified: it **fails** against the pre-openat2 check-then-use write
      (escape occurs) and **passes** with the fix. Plus deterministic
      `escape_corpus_entries_are_refused_and_write_nothing` (absolute / `..` /
      separator-quirk, table-driven) + `escape_corpus_symlinked_parent_is_refused`.
- [x] **Step 2 (green):** added `Rooted`, created once per `unpack_layer`. On
      `cfg(target_os = "linux")` it opens `output_root` once and resolves each
      entry's parent through `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS)`
      (creating intermediates with `mkdirat` as it descends), then creates the leaf
      with `*at` calls (`openat2`/`mkdirat`/`symlinkat`/`linkat`/`mknodat`) against
      the returned dir handle — never a re-derived host path. The cheap
      `..`/absolute string checks stay as fail-fast; `openat2` is the authority.
      `ELOOP` → `SymlinkInParent`, `EXDEV` → `JoinedPathEscape`. Non-Linux retains
      the path-based writers behind `cfg` (test/dev build target only).
- [x] **Step 3 (preserve invariants):** whiteout markers, hardlink-target-missing
      refusal, device-node allowlist, setid/xattr policy, and timestamp-zeroing
      reproducibility all unchanged — the full pre-existing suite passes on macOS
      (fallback path, 84 tests) and on the Linux box (openat2 path, 73 unit + 15
      integration). The change swaps the resolution mechanism, not the policy.
- [x] **Step 4 (fuzz):** extended `crates/mvm-oci/fuzz/fuzz_targets/unpack_layer.rs`
      with a structured, dependency-free arm (hand-rolled USTAR — keeps the frozen
      fuzz lockfile untouched) that derives attacker-shaped paths from the fuzz
      input and drives the absolute / traversal / symlinked-parent branches plus
      the openat2 resolution path. CI lane stays Plan 128's; no gate added here.

**R2 acceptance:**
- [x] The symlink-swap regression + escape corpus pass; the symlink-swap test
      demonstrably failed before Step 2 (box-verified escape) and passes after.
- [x] `parent_chain_has_symlink` is **reduced to a cross-platform fail-fast
      pre-filter**; on Linux the `openat2` handle is the load-bearing resolution
      authority for writes. Full deletion awaits the whiteout-removal openat2
      conversion (see deferred follow-ups).
- [x] Whiteout / hardlink / device-node / setid handling and reproducible-unpack
      byte-identity unchanged (full suite green on both platforms).

### Deferred follow-ups

- [ ] Convert the whiteout-**removal** walk (`apply_regular_whiteout` /
      `apply_opaque_whiteout` / `remove_*_except_current_layer`) and the non-Linux
      hardlink path to openat2/`*at` so `parent_chain_has_symlink` can be deleted
      outright. This PR scopes openat2 to the **write/creation** path (where
      attacker bytes land); the removal path keeps the `symlink_metadata` +
      `starts_with` guard plus the fail-fast scan, which is unchanged from before.

## Task R3 — ADR-002 positioning note

**Where:** `specs/adrs/002-microvm-security-posture.md`, the Threat-model /
out-of-scope discussion (prose, **not** the numbered claim table).

- [x] **Step 1:** added the "Why a hardware boundary, not a userspace
      application-kernel sandbox" paragraph to ADR-002 §Threat model — stronger
      hardware-enforced isolation, no syscall-compat surface, an escape is a
      hardware-assisted VM escape rather than an in-process logic bug — and cites
      that sandbox class as the reference for the in-guest hardening layer (the
      openat2-confined unpacker here; the ioctl seccomp denylist tracked elsewhere).
      Name-clean: oblique "userspace application-kernel sandbox" phrasing only.
- [x] **Step 2:** kept in §Threat model, not §Out of scope, not the numbered claim
      table; no `specs/claims/` witness added. `catalog.md` untouched.

**R3 acceptance:**
- [x] ADR-002 records the hardware-boundary-vs-application-kernel rationale; no new
      numbered claim; `specs/claims/catalog.md` untouched.

## Verification (whole plan)

- [x] `rustup run nightly cargo fmt --all -- --check` clean.
- [x] `cargo test -p mvm-oci` green on macOS (fallback path, 84 tests) and on a
      real Linux host (openat2 path, 73 unit + 15 integration). Full-workspace
      `cargo test` is left to CI — `mvm-backend`'s test binary `SIGKILL`s under
      macOS codesign locally (environmental, pre-existing).
- [x] `cargo clippy -p mvm-oci --all-targets -- -D warnings` clean on Linux
      (openat2 path) and macOS (fallback). Workspace clippy → CI.
- [x] `crates/mvm-oci/fuzz` type-checks with the extended corpus (`cargo check`
      on the Linux host; `cargo fuzz`/nightly not installed on the box, so the
      libFuzzer run + Plan 128 CI lane stays the gate).
- [x] `check-no-spec-refs-in-comments` clean.

## Sequencing / ownership

- R2 and R3 are independent of each other and of Plan 120 — land in any order.
- CI-gate wiring (the unpack fuzz lane, the ADR/CLAUDE.md security-section
  reconcile) routes through **Plan 128**, Stage D — same as Plan 143. This plan
  delivers behavior + corpus; Plan 128 owns the gate. Don't add a parallel gate.
- On completion, tick R2/R3 in Plan 143's Task 2 / Task 3 checklists so the parent
  stays accurate; R1 remains open and gated there.
