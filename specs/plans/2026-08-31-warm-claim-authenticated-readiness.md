# Warm claim authenticated readiness

Backing: shipped-source
Validation: check-sprint-append

Issue: #3039

## Problem

A restored standby child was considered ready as soon as the VMM accepted a
connection to its guest-agent port. The transport exists before the guest agent
is serving, so the following authenticated `PostRestore` RPC could race the
guest and fail. Optional warm launches then discarded the dead standby and
cold-booted, hiding the failed claim behind a warning.

## Contract

- [x] Settle post-restore readiness on the guest-agent wire with the existing
      authenticated Ping exchange, not a successful socket connection.
- [x] Bound each probe's reads and writes so an accepted but unserved transport
      cannot consume the complete restore deadline.
- [x] Keep auto-detected warm residency best-effort, but treat an operator's
      explicit `MVM_RESIDENCY` request as requiring a successful warm claim.
- [x] Cover both a connected silent peer and a serving authenticated guest.
- [x] Cover required versus optional warm-launch policy without process-global
      environment mutation.
- [x] Pass workspace tests, workspace Clippy, gated Linux/BDD compilation, and
      repository policy checks.
- [ ] Merge through the queue and let the merged PR close #3039.

## Security

Readiness uses the same authenticated session handshake as the operational RPC.
A socket owner that cannot prove the pinned host/guest session and answer a
framed Ping is never allowed to advance the restore state machine.
