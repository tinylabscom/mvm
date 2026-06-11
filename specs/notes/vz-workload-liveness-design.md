# Vz workload liveness — design

**Date:** 2026-06-11
**Status:** design approved; ready for implementation-plan authoring
**Goal:** Unblock live Vz validation of the merged WS-2 checkpoint/fork/pause-resume
work by (1) hardening the sealed-workload `/init` stdin against Vz's input-less
console and (2) adding a long-lived sealed-workload example to validate against.

## Context

On Vz, the serial console is **write-only** — `vz_objc.rs` attaches it with
`fileHandleForReading: None` (claim-15 sealed-console parity: no host input fd).
The guest `/init` workload arm runs `. "$MVM_BOOT"` with PID-1's kernel-provided
fds intact, so the workload's **stdin is `/dev/console`** (input-less). A workload
that reads stdin hits EOF and can crash ~5s after boot — the long-standing reason
every live Vz validation has been deferred. The **dev** VM arm was already fixed
(it idles PID-1 and serves the shell over vsock); only the **sealed-workload** arm
remains exposed, and there is **no long-lived sealed-workload example** in the repo
to even test with (`examples/exit_code` is a one-shot `exit 7`).

## Decision (from the brainstorm)

Deliverable **A**: ship two CI-testable, mergeable artifacts (the `/init` stdin
hardening + a long-lived example) as a normal PR, and treat the live Vz bringup as
a separate, best-effort follow-on pass that does not gate the PR.

## Part 1 — `/init` workload stdin hardening

**File:** `nix/lib/mk-guest.nix` (the sealed-workload arm, the `. "$MVM_BOOT"` line).

**Change:** `. "$MVM_BOOT"` → `. "$MVM_BOOT" </dev/null`.

This points the sourced workload's stdin at `/dev/null` (a clean, well-defined
EOF — the correct stdin contract for a non-interactive daemon) instead of the
input-less Vz console. stdout/stderr stay on `/dev/console` (console.log capture
unchanged); the exit-code capture (`MVM_CODE=$?`) is unaffected.

- **Claim-15 preserved (arguably strengthened):** no host input fd is added; the
  console stays write-only; the guest workload can no longer read the console at
  all. The `prod-agent-no-console` security lane is unaffected.
- **All-backends-correct:** sealed workloads are non-interactive by contract, so
  `/dev/null` stdin is correct on Firecracker/libkrun too. Well-behaved workloads
  (which do not read stdin) see no behavior change.
- **Defensive framing (YAGNI honesty):** the Part 2 example does NOT read stdin,
  so it would not trigger the crash on its own. This change removes the documented
  foot-gun for the *general* case (a sealed workload that reads stdin) on the
  fragile Vz console path, and makes the daemon stdin contract correct.

The new comment on this line must NOT cite plan/PR/ADR numbers (the `Plan 180`
`check-no-spec-refs-in-comments` lint gate is now live on main).

## Part 2 — long-lived sealed-workload example

**Dir:** `examples/sleeper/` — `flake.nix` (+ any `flake.lock` the build needs).

Mirror `examples/exit_code/flake.nix`'s exact shape (GitHub-pinned `inputs.mvm`
following `mvm/nixpkgs`, image built via `mvm.lib.<system>.mkGuest`, sealed
`entrypoint.command` form so mkGuest infers prod / no dev-shell), but with a
**long-lived** command instead of `exit 7`:

```
entrypoint.command = [ "/bin/busybox" "sh" "-c" "while :; do /bin/busybox sleep 2147483647; done" ];
```

PID-1's workload stays resident; the guest agent (forked in `/init` independently
of the workload) stays reachable over vsock. This is the missing fixture every
WS-2 live validation needed: a VM that stays up long enough to `checkpoint
create`/`fork`, `pause`/`resume`, and be probed via the agent.

The flake's doc comments describe what it is (a long-lived liveness fixture) and
the entrypoint shape — without plan/PR refs.

## Testing

**CI-testable (the mergeable PR gates):**
- `nix flake check` / eval of `examples/sleeper` (it parses + the `mkGuest` call
  resolves, the same gate the other example flakes pass).
- A structural assertion that the rendered `/init` carries the `</dev/null`
  redirect on the sealed-workload arm. If an existing test renders/inspects the
  mkGuest `/init` script, extend it; otherwise add a focused check (e.g. an
  `xtask`/test grep over the generated init, or a nix-eval assertion) so the
  hardening can't silently regress.
- The claim-15 `prod-agent-no-console` security lane stays green (the change
  doesn't touch the console attachment or the agent console symbol).
- `cargo fmt --all --check`, `cargo clippy --workspace -D warnings`, the workspace
  test suite — confirm nothing else regressed (the change is nix-only + a new
  example dir, so the Rust suite should be untouched).

**Not host-CI-testable (the live bonus, below):** runtime EOF-survival and the
WS-2 round-trips require a real Vz boot.

## Live bringup (bonus — separate, best-effort; does NOT gate the PR)

After the PR's artifacts land, on this Vz Mac:
1. Build the `sleeper` image (source-checkout build via the in-repo flakes) and
   `mvmctl up --flake examples/sleeper --hypervisor vz`.
2. Confirm it survives past ~5s (agent vsock ping / `console.log` shows no
   init-EOF poweroff).
3. Run the real WS-2 round-trips against it: `checkpoint create --class fs-quick`
   then `checkpoint fork`; `checkpoint create --class vm-full` then `checkpoint
   restore`; `pause` then `resume`. Capture outcomes + `console.log`.
4. If the VM stays live and a cross-identity restore works, run the deferred
   **fork semantic-A spike** (restore a saved memory state under a fresh
   machine-id + new MAC; check guest networking) — success flips the two consts
   (`FORK_FRESH_MACHINE_ID`, `FORK_ALLOW_PARENT_RUNNING`) to enable the live
   two-copy fork.

If the other documented Vz flakes (supervisor codesign, the vsock-proxy hang
tracked as #673) block the bringup, the PR still stands on its own and the blocker
is reported concretely as the next target.

## Scope guard (YAGNI)

In scope: the one-line `/init` stdin hardening + the `sleeper` example + their CI
gates. Out of scope: any other `/init` change; rewriting the Vz console
attachment; the live bringup as a *gated* deliverable; the fork A-upgrade itself
(only attempted opportunistically in the bonus pass).

## Crate / file placement

- `/init` stdin redirect → `nix/lib/mk-guest.nix` (sealed-workload arm).
- example → `examples/sleeper/flake.nix` (+ lock as needed).
- `/init` structural test → extend the existing mkGuest init test if present, else
  a new focused check under `xtask` or the nearest test harness.
