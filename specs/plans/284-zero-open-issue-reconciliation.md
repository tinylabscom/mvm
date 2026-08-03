# Zero-open-issue reconciliation

Issues: #1819, #1821, #1822, #1823, #1825, #1826, #1849, #1851, #1937,
#1972, #1973, #1977, #1983, #2006, #2007, #2021, #2028, #2029, #2033,
#2035, #2036, #2039, #2040, #2042, #2048, #2052, #2054, plus #2060 and
#2067 filed during execution

Status: COMPLETE (2026-08-02)

## Goal

Reconcile every open GitHub issue against the current architecture and code,
close completed, superseded, or unplanned work with an explicit reason, and
deliver every remaining relevant fix. Completion means the repository has no
open GitHub issues.

## Reconciliation checklist

- [x] Close roadmap proposals superseded by repository plans or rejected by
      accepted architecture: #1819, #1821, #1822, #1823, #1825, #1826, #1849,
      and #1851.
- [x] Close #1973 as completed by the merged seed-caller isolation gate.
- [x] Close #1977 as completed by the merged observable-condition and hang-guard
      fix for `worker_pool_warm`.
- [x] Close unbounded mutation-coverage proposals #2006, #2021, and #2033 after
      confirming the security witnesses are caught and the exact-identity
      baseline ratchets against new misses.
- [x] Land the queued fixes for #2007, #2028, and #2029.
- [x] Transfer #2036 to `tinylabscom/mvmd#196`, whose fleet-orchestrator
      ownership covers the epic's production object-store, encryption,
      reconciliation, quota, RBAC, and durability acceptance gates.
- [x] Repair #2039 by replacing the PID-1 `SIGCHLD` handler race with one
      ownership-aware child waiter and proving reaper-first exit-status
      delivery; merged in #2041.
- [x] Execute the refiled cross-repository volume epic #2040 through its
      dedicated production-object-store plan.
- [x] Repair #2042 so per-VM helper processes exit with their owning run and
      stale helpers remain discoverable across worktree boundaries.
- [x] Repair #2048 by negative-caching confirmed missing default-origin
      initramfs release artifacts without caching transient failures or
      suppressing configured mirrors.
- [x] Close #2052 after #2050 moved mediated-tool setup into the shared guest
      bootstrap and replaced BusyBox applet symlinks before bind mounting, with
      regression coverage proving `/bin/busybox` remains untouched.
- [x] Close #2054 after the exact sealed Apple-container E2E passed on current
      main, covering guest-agent readiness, status, inventory, logs, stop, and
      stopped status.
- [x] Repair #1983 by updating the vulnerable Wasmtime 46.0.1 lock to 46.0.2
      and confirming the queued mutation-baseline fix clears the other failing
      security job.
- [x] Repair #1937 by synchronizing both Linux pins on 6.12.100 and its verified
      upstream tarball hash, including the compatibility adjustment required
      by the libkrunfw datagram patch set.
- [x] Repair #1972 by making the installer fixture read a complete, bounded
      HTTP header instead of treating one socket read as one request.
- [x] Repair #2035 by injecting the cold-cache resolution failure into the
      non-fatal attachment test so Linux never performs a real initramfs build.
- [x] Keep plan-mode integration coverage hermetic when the worktree exports
      `MVM_HOME`, so it cannot consume mutable signing keys from another test.
- [x] Run focused tests, workspace tests, workspace check, Linux all-targets
      clippy, Nix evaluation/build checks, and `cargo audit`.
- [x] Publish the implementation, enter the merge queue, and verify that all
      closing pull requests merge.
- [x] Confirm the GitHub open-issue count is zero.
- [x] Repair #2067 after the scheduled security workflow reported two real CI
      wiring defects: audit the protected-credential-path test as deny-only in
      the no-SSH scanner, install the pinned embedded-host Zig toolchain only in
      the `mvm-cli` mutation shard, and add PR-time regression coverage for that
      toolchain dependency.
- [x] Repair the additional `mvm-agentd` mutation-witness gap exposed by the
      exact security rerun: cover every `DropReport` state, prove recording
      calls cannot disappear, and run the real Linux privilege drop in an
      isolated root child that checks
      `/proc/thread-self/status` for `NoNewPrivs=1` and zero capability sets.
- [x] Classify the rerun's `mvm-runtime` survivor as equivalent: deleting
      libkrun's explicit `l3_vsock: false` falls back to the same derived
      `VmCapabilities` default. Pin the declared L3 refusal in the capability
      tests and the exact equivalent mutation in the ratchet.
- [x] Close the final post-merge `mvm-agentd` witness gap: classify bounding-set
      syscall results through a pure fail-closed helper, cover success, stale
      errno, unsupported-capability, and permission-denied cases, and confirm
      the exact Linux mutation shard catches every relevant privilege-drop
      mutant.

Closeout evidence (2026-08-02): the production-volume implementation merged
across mvm PRs #2044 and #2064 and mvmd PRs #198 through #202. The independent
HVF entropy issue #2060 merged through mvm PR #2065 after appearing during the
reconciliation. Issue #2040 was closed with an explicit shipped-versus-rejected
scope ledger, #2060 closed from its merge, and `gh issue list --state open`
returned an empty JSON array. A later scheduled-run alert opened #2067 from an
older main commit; its two reproducible workflow failures are repaired by the
follow-up above. Its exact branch rerun additionally exposed the L3
privilege-drop mutation gap and the equivalent libkrun capability deletion,
which the same closing PR repairs and classifies before restoring the zero-issue
state. The corrected-head security run then found one additional comparison
mutation in bounding-set result handling; the follow-up truth-table witness
kills it, and the exact Linux shard is clean at 27 files across 8 packages with
83 accepted misses.

## Verified upstream inputs

- Linux 6.12.100 is the latest upstream 6.12 point release on 2026-08-01.
- `nix store prefetch-file` returned
  `sha256-Z/lzUzQGSS6Gd0usvO+uUNUNXDTL9wPEfsUmpe/c7pA=` for the official
  `linux-6.12.100.tar.xz` archive.
- RustSec advisories RUSTSEC-2026-0222 and RUSTSEC-2026-0223 require Wasmtime
  46.0.2 or later within the 46.x release line.
