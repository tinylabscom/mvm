---
title: "Warm-claim latency: where the time goes on Firecracker and HVF, and the sealed-digest fix"
author: Ari
date: 2026-10-30
branch: main
cost: { minutes: 830, tokens: 6325608 }
touches:
  - ".github/workflows/bench-hvf-m1.yml"
---

## Decided
- Firecracker warm claim was 80 ms p50; 46 ms of it was `verify_restored_layout` re-hashing kernel, initramfs and read-only drives in every fresh `mvmctl` process. Fixed by taking those digests from the sealed sidecar (`sha256_file_verified` falls back to `sha256_file_cached`), sealing only files that have settled (250 ms, signed arithmetic, `read_started` captured before the identity stat), and sealing at refill only a digest equal to the one verification accepted. Claim p50 is now about 32 ms (box with rotational disks, shared runner: a before/after, not evidence for the 30/50 ms gate).
- HVF claim is about 145 ms; 104 ms is forking the child at claim. HVF has no preloaded child; Firecracker already has one (`preload_standby_child` at refill, `resume_preloaded_child` at claim), so the proposed ready-child pool only applies to HVF.
- Per-phase claim markers (`claim_phase!`, plus `mvm_vmm::agent_debug::phase`) written to the `MVM_HVF_AGENT_DEBUG` trace file are how every number above was measured; a branch-only push-triggered workflow on the self-hosted macOS runner can reproduce the HVF ones.

## Tried and ruled out
- Process-local digest registry (#4697) alone: useless for claims, because each claim is a fresh process. Do not retry it for claim-path savings.
- Claiming a "move the fork to refill" fix for Firecracker: it is already done there; the 51 ms step was the layout verification inside the resume, not the fork.
- Sealing a digest immediately after copying a private file: unsound on coarse timestamps (same-tick rewrite keeps identity); the settle window is required.

## Watch out
- Other sessions push to the same PR branch under the same GitHub account: fetch and rebase before pushing, never `--force-with-lease` over a moved remote.
- The pre-commit hook runs stable workspace clippy and can fail on an unrelated lint (tracked in #4828); apply the fix unstaged, commit only your files, then revert it.
- HVF standby sockets overflowed the macOS 104-char socket path under a deep runner `MVM_HOME` (fixed in #4774); long homes break the macOS runner in surprising ways.
- Hetzner box measurements: the box is rotational and shared with a CI runner; always clean up `MVM_HOME`-tagged firecracker processes and the working dir after a run.
