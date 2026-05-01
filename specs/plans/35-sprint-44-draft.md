# Sprint 44 — Verified-boot polish + cross-backend parity (DRAFT)

> Status: planning — proposed structure for the next sprint after
> sprint 42 (microVM hardening) and sprint 43 (MCP/agent adoption)
> close. Master plan: [`plans/35-post-w3-cleanup.md`](35-post-w3-cleanup.md).
>
> This file is a draft. When sprint 42's `SPRINT.md` is archived to
> `specs/backlog/42-microvm-hardening.md` and sprint 43's PRs are
> merged, copy this file to `specs/SPRINT.md` and rename it to
> "Sprint 44".

## Goal

Close the long tail from sprint 42's W3 (verified boot): two
init-script defects the live boot exposed, an unverified
snapshot/restore round-trip, an unverified Apple Container live
path, and the runbook → CI promotion. No new hardening claims;
this sprint upholds existing ones with fewer asterisks.

**Branch**: TBD (per-PR feature branches; merge target: `main`).

## Why this sprint, why now

Sprint 42 closed with all 7 ADR-002 success-criteria claims
backed by code, but the `specs/runbooks/w3-verified-boot.md` live
test exposed two init-script defects (broken bind-mount of
`/etc/nsswitch.conf`; setpriv flag conflict) plus three open
"untested-but-wired" surfaces (snapshot/restore with verity,
Apple Container live boot, automated regression). Each is a small
correctness gap that the W3 sprint deliberately scoped out — but
leaving them open turns claim #2 ("no guest binary can elevate to
uid 0") and claim #3 ("a tampered rootfs ext4 fails to boot")
into "true at moment of merge, untested continuously."

The whole sprint is ~1 week of work and 4 small PRs.

## Current Status (sprint open)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 8 + root facade + xtask  |
| Total tests      | 1 121 (sprint 42 close)  |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
| MSRV             | 1.85                     |
| Binary           | `mvmctl`                 |

## In-flight workstreams

### C0 — Carryover housekeeping  🟡

Plan: [`plans/35-post-w3-cleanup.md`](plans/35-post-w3-cleanup.md) §C0.
½ hour, smallest PR; lands in front of everything else.

- [ ] **C0.1** `git rm -r nix/images/examples/{paperclip,openclaw}/`
      (W7.1 sandbox-blocked deletion from sprint 42's plan 31).
- [ ] **C0.2** Audit `nix/images/examples/flake.nix` (or per-
      example flake aggregator) for dangling references to the
      deleted directories; remove or update so `nix flake check`
      stays green.

**Done when**: `git ls-files nix/images/examples/ | grep -E
'(paperclip|openclaw)'` returns nothing and `nix flake check`
on the remaining examples passes.

### C1 — Init-script defects exposed by W3 live boot  🟡

Plan: [`plans/35-post-w3-cleanup.md`](plans/35-post-w3-cleanup.md) §C1.
Single PR, two one-line fixes.

- [ ] **C1.1** `/etc/nsswitch.conf` bind-mount source-deletion
      bug. `04-etc-and-users.sh.in` symlink dance leaves the
      staging file in inconsistent state for one of the three
      promoted bind-mounts. Fix: drop intermediate symlinks,
      write content directly to `/run/mvm-etc/*`, bind on top
      of empty `/etc/*` targets.
- [ ] **C1.2** `setpriv` `--clear-groups --groups=…` mutually
      exclusive flag conflict in `mkServiceBlock` non-explicit
      branch and `guestAgentBlock`. Fix: drop `--clear-groups`
      (`--groups=` already replaces the supplementary group
      set; the combination was redundant + ambiguous to
      util-linux's setpriv).

**Done when**: a fresh Lima boot of a verity-enabled template
shows no `mount: failed` or `setpriv: mutually exclusive` lines
on the console.

### C2 — Verity snapshot/restore parity  🟡

Plan: [`plans/35-post-w3-cleanup.md`](plans/35-post-w3-cleanup.md) §C2.
1-2 days, 1 PR. May grow to 3 days if dm-state isn't preserved
across Firecracker snapshot.

- [ ] **C2.1** Investigate: snapshot a verity-enabled VM, restore
      it, inspect `mount` output and `/sys/block/dm-0`. Determine
      whether Firecracker's snapshot serializes the in-kernel
      dm-verity device-mapper state.
- [ ] **C2.2** If dm-state IS preserved: ship a regression test
      and runbook §6 documenting the round-trip. If NOT: extend
      the `PostRestore` vsock RPC handler to re-apply the verity
      target on signal.
- [ ] **C2.3** `crates/mvm-runtime/tests/verity_snapshot_restore.rs`
      integration test, gated on Linux/KVM availability.

**Done when**: snapshotting a verity template and restoring it
produces a guest with `/dev/dm-0` still mounted as root, plus
the test exercising the round-trip.

### C3 — Apple Container live-boot smoke  🟡

Plan: [`plans/35-post-w3-cleanup.md`](plans/35-post-w3-cleanup.md) §C3.
½ day, ½ PR (could fold into C2's PR if both are small).

- [ ] **C3.1** Build a verity template on Lima, copy artifacts
      to macOS host's `~/.mvm/templates/<id>/revisions/<rev>/`,
      boot via `mvmctl up --hypervisor apple-container`. Surface
      and fix any wiring gaps (e.g. prebuilt-image copy missing
      `rootfs.initrd`).
- [ ] **C3.2** Runbook §3.5 captures the boot log + tamper test.

**Done when**: the runbook has a §3.5 with "Apple Container
live boot ✅" and the captured log shows
`mvm-verity-init: switching to /init`.

### C4 — Live-KVM regression automation  🟡

Plan: [`plans/35-post-w3-cleanup.md`](plans/35-post-w3-cleanup.md) §C4.
1-2 days, 1 PR.

- [ ] **C4.1** `scripts/w3-live-test.sh` wraps the runbook into
      a single command. Runs every step, asserts on log
      contents, exits non-zero on failure.
- [ ] **C4.2** `just w3-live-test` recipe; `just w3-live-test
      --tamper` for the tamper-only sub-step.
- [ ] **C4.3** Soft-gated `live-verity-boot` lane in
      `.github/workflows/security.yml`. Conditional on
      `[ -e /dev/kvm ]` — skipped on standard GitHub runners,
      enforced where KVM is available.
- [ ] **C4.4** Fold sprint 43's deferred A.2 v2 cold-vs-warm
      latency test into the same script (`just
      mcp-warm-vm-latency`). Reuses the KVM detection.

**Done when**: `just w3-live-test` exits 0 on Lima; CI lane
skips cleanly on public runners.

### C5 — L7 egress feature-gate (PR #23 follow-up)  🟡

Plan: [`plans/35-post-w3-cleanup.md`](plans/35-post-w3-cleanup.md) §C5.
½ day, 1 PR.

- [ ] **C5.1** Add `l7-egress` Cargo feature to
      `crates/mvm-core/Cargo.toml` (default off).
- [ ] **C5.2** Gate `EgressMode::L3PlusL7` + `EgressProxy`
      trait export + `StubEgressProxy` instance behind
      `#[cfg(feature = "l7-egress")]`.
- [ ] **C5.3** CLI parser in `crates/mvm-cli/src/commands/vm/up.rs`
      rejects `--egress-mode l3-plus-l7` with a clear error
      pointing at plan 34 when feature off.

**Done when**: default `cargo build` doesn't expose
`l3-plus-l7` in `mvmctl up --help`; `--features l7-egress`
build does; default-build CLI rejection error contains
"plan 34". Removes the user-visible footgun PR #23 left
behind without blocking on plan 34's runtime backing.

## Success criteria

By sprint close:

1. ✅ Sprint 42's W7.1 paperclip/openclaw deletion closed (C0).
2. ✅ Verity-enabled template boots cleanly with no init-script
   warnings on console (C1).
3. ✅ Snapshot/restore round-trip works for verity VMs (C2).
4. ✅ Apple Container live boot of a verity template succeeds
   on macOS (C3).
5. ✅ `just w3-live-test` exits 0 in Lima end-to-end (C4).
6. ✅ L7 egress variant feature-gated; user can't silently pick
   the no-op stub (C5).
7. ✅ Sprint 42 archived to `specs/backlog/42-microvm-hardening.md`.

## Phasing

PRs are independently mergeable. Suggested order:

1. **PR-A**: C0 (housekeeping deletion). Tiny PR, lands first.
2. **PR-B**: C1 (init-script defects). Single PR, both fixes.
3. **PR-C**: C2 (snapshot/restore parity). Investigation may
   extend; ship the test + runbook entry, defer the
   `PostRestore` recovery handler if needed.
4. **PR-D**: C3 (Apple Container smoke). Foldable into PR-C.
5. **PR-E**: C4 (live-KVM regression automation).
   Self-contained.
6. **PR-F**: C5 (L7 egress feature-gate). Self-contained.

## Carryover from earlier sprints

Items deferred at sprint 42/43 close that do NOT fit this sprint
but still need a home:

| Item | Source | Where it goes |
|---|---|---|
| L7 egress runtime backing (mitmdump + CA + DNS pinning) | Sprint 43, [`plans/34-egress-l7-proxy.md`](plans/34-egress-l7-proxy.md) | Own sprint (already sized) |
| Hosted MCP transport (HTTP/SSE) | Sprint 43, [`plans/33-hosted-mcp-transport.md`](plans/33-hosted-mcp-transport.md) | Cross-repo (mvmd) |
| `mkNodeService` → `pkgs.buildNpmPackage` swap | Sprint 42 W7.4 deferred | Own follow-up; needs hello-node validation |

## Non-goals (named explicitly)

- Hosted CI infrastructure (self-hosted KVM runners, GitHub
  paid-tier nested-virt). C4 ships the script + soft-gated
  lane; runner capacity is separate operator work.
- New ADR-002 claims or W-workstreams. Sprint 42 closed plan
  25; this sprint upholds it.
- Touching the Firecracker snapshot wire format. If C2's
  investigation shows dm-state isn't preserved, the fix is in
  guest-side recovery code (the `PostRestore` handler), not
  in Firecracker.

## Completed Sprints

(Carryover from sprint 42's SPRINT.md when archived. Sprint 42
+ 43 should be added to this list when their final PRs merge.)
