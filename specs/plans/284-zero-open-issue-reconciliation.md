# Zero-open-issue reconciliation

Issues: #1819, #1821, #1822, #1823, #1825, #1826, #1849, #1851, #1937,
#1972, #1973, #1977, #1983, #2006, #2007, #2021, #2028, #2029, #2033,
#2035, #2036, #2039, #2040, #2042, #2048

Status: IN PROGRESS

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
- [ ] Execute the refiled cross-repository volume epic #2040 through its
      dedicated production-object-store plan.
- [x] Repair #2042 so per-VM helper processes exit with their owning run and
      stale helpers remain discoverable across worktree boundaries.
- [ ] Repair #2048 by negative-caching confirmed missing default-origin
      initramfs release artifacts without caching transient failures or
      suppressing configured mirrors.
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
- [ ] Publish the implementation, enter the merge queue, and verify that all
      closing pull requests merge.
- [ ] Confirm the GitHub open-issue count is zero.

## Verified upstream inputs

- Linux 6.12.100 is the latest upstream 6.12 point release on 2026-08-01.
- `nix store prefetch-file` returned
  `sha256-Z/lzUzQGSS6Gd0usvO+uUNUNXDTL9wPEfsUmpe/c7pA=` for the official
  `linux-6.12.100.tar.xz` archive.
- RustSec advisories RUSTSEC-2026-0222 and RUSTSEC-2026-0223 require Wasmtime
  46.0.2 or later within the 46.x release line.
