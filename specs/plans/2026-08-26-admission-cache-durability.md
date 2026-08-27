# Admission cache durability boundary

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS**

Issue #2900 measured admission spending nearly all of its time in stable-storage
barriers. The chain-signed audit log is the authorization record and must remain
durable before boot. Receipt files, decision files, and the per-machine
`plan.json` are derived lifecycle views that can be reconstructed from that
chain; they must publish atomically for readers, but they must not each add an
independent pre-boot durability wait.

## Delivery

- [x] Add a regression proving receipt and decision caches contribute no paths
      to the admission audit batch's stable-storage barrier.
- [x] Keep the chain-signed audit event authoritative and preserve its existing
      fail-closed durability barrier.
- [x] Publish receipt, decision, and lifecycle-plan caches atomically without
      independent `fsync` waits.
- [x] Prove receipt recovery, decision rebuild, plan roundtrip and permissions,
      the admission-barrier regression, formatting, and package Clippy are
      green.
- [ ] Merge the repair through the merge queue and confirm issue #2900 closes
      from the merged PR.
