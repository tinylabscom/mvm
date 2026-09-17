# Extended CI warm-claim repair

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#3330](https://github.com/tinylabscom/mvm/issues/3330)

## Outcome

Restore the scheduled Firecracker warm-claim witness without weakening or
skipping it. The hosted runner provides KVM, but the witness must also enter a
private mount namespace to bind-remap the absolute device paths retained by a
Firecracker snapshot.

## Checklist

- [x] Reproduce the scheduled failure on the pull-request head.
- [x] Preserve warm-pool spawn, audit, and preload error chains at the CLI
      boundary so a failed live witness names its actual cause.
- [x] Prove the failure occurs during fork preload because the hosted runner
      user lacks the mount-namespace privilege required by the remap path.
- [x] Add a workflow regression requiring the guarded warm-claim recipe to run
      through the hosted runner's passwordless-sudo boundary with a narrow
      preserved environment.
- [x] Keep `/dev/kvm` absence fail-closed; do not turn a missing live witness
      into a green skip.
- [x] Pass the complete pull-request validation matrix and a manually
      dispatched Extended CI warm-claim job on the exact head.
- [x] Prepare the issue-linked pull request for merge and automatic closure of
      #3330.
