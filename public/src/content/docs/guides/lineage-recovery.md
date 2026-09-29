---
title: Rewind and replay a sandbox
description: Navigate signed checkpoint and image history, then restore a prior state into a newly admitted microVM.
---

Use lineage recovery when an agent needs to inspect an earlier sandbox state or
branch from it. This is **not an undo of external effects**: a restore cannot
retract an API call, message, package publication, or other action that already
left the guest. Decide separately whether those effects need compensation.

## Inspect before restoring

```sh
mvmctl machine timeline <checkpoint-id>
# An image node uses its sha256:<hex> digest instead.
mvmctl machine timeline <image-digest> --kind image --json
```

`timeline` shows ancestors and immediate children. It is read-only: it does
not boot or change a VM. Each hop is checked against the signed audit chain
and marked if its evidence is missing or damaged. The command still renders
a damaged timeline for investigation; its display is **not** permission to
restore an unverified node. Use
`mvmctl machine checkpoint verify <checkpoint-id>` for a fail-closed
checkpoint verification result.

## Choose a state

```sh
# Restore exactly the selected checkpoint into a new VM identity.
mvmctl machine revert <checkpoint-id> --new-id recovered-agent

# Restore its parent, one step back.
mvmctl machine rewind <checkpoint-id> --new-id earlier-agent

# Restore a child, one step forward. Select one explicitly if it forked.
mvmctl machine advance <checkpoint-id> --to <child-digest> --new-id later-agent
```

`revert`, `rewind`, and `advance` do not mutate the current machine. They
verify the selected record and its ancestry, then launch a **new VM identity**
under a freshly signed `ExecutionPlan` and current admission policy. A
missing, tampered, or un-audited lineage record is refused. `rewind` cannot
move before a genesis node; `advance` needs `--to` if there is more than one
child. A digest that exists in both stores needs `--kind checkpoint` or
`--kind image` to avoid ambiguity.

For an image node, pass its digest in place of the checkpoint ID. The restore
re-runs the recorded digest-pinned image reference through the normal admitted
run path and chooses a VM name automatically; `--new-id` applies only to
checkpoint restores. For a checkpoint, `--hypervisor` selects the restore
backend (default `firecracker`), and the backend must support that checkpoint
class. Check `mvmctl doctor` and [snapshot support](/working/snapshots/) before
relying on a recovery path.

## Preserve the evidence boundary

A successful checkpoint restore records `checkpoint.restored`; an image
restore records `image.reverted`. Both events include which of the three
restore verbs initiated it. Inspect the [audit chain and run
receipts](/guides/audit-and-receipts/) to correlate the new run with the
original. Checkpoints can hold memory and derived credentials, so restrict
access and retention. The guest still has no network device; any network
access is decided by the host endpoint under the new signed plan, not by
authority inherited from the older sandbox.

For every flag and the lower-level checkpoint commands, see the
[CLI reference](/reference/cli-commands/#lineage--time-travel/).
