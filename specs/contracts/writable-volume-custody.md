# Writable-volume writer custody

## Protocol

A persistent writable volume has two cooperating-writer locks: its backing inode
and the stable `<image>.lock` sidecar. Materialization takes the sidecar before
inspecting or changing image bytes. Boot preparation opens the final physical
backing and sidecar without following a final symlink, takes both locks, and
binds them to the exact final disk slot and object identity. Hardlink aliases
therefore contend even when they use different sidecar paths. Read-only and
ephemeral disks do not acquire these resources.

Materialization transfers the original locked backing and sidecar through launch
preparation; the runtime never reacquires against its own guard. HVF inherits
both into its supervisor. The supervisor adopts them through the same complete
startup-descriptor preflight as the verified kernel, consumes the backing as the
virtio disk, and retains the sidecar until after the disk's final flush and
destruction. Firecracker inherits the original descriptions through its bounded
sudo launch and opens them through `/proc/self/fd`. Strict per-launch source
metadata restores original paths in snapshots and observations; replacement
writers prepare new locks only after the old writer's confirmed stop. QEMU and
libkrun inherit the original backing and sidecar and open the backing through
`/dev/fd`.
In every case the actual writer retains the original lock descriptions through
early-error recovery and uncertain stop; a caller dropping its duplicate is not
a release event. Direct path-based user-writable boots are refused rather than
silently bypassing custody. Trusted-builder protocols and read-only behavior are
unchanged.

These are advisory locks among cooperating MVM writers, not mandatory access
control against another user or an arbitrary process. Path existence, PID
absence, descriptor duplication, or successful lock acquisition is not terminal
writer proof.

## Rollout and activation

Old and new writers must not run concurrently in the protected domain. An
upgrade has no mixed-version online rollout: before activating the first writer
that uses this protocol, the operator must stop every older MVM writer of the
same backing through its authenticated owner and confirm quiescence using the
existing stop/finalization evidence. A missing PID file, removed state
directory, or newly acquired lock does not establish that condition. Any
uncertain stop remains unresolved and blocks activation through the existing
recovery path; this protocol invents no denial-clearing or recovery authority.

After the protected domain is wholly on this protocol, new-writer exclusion is
enforced by the backing and sidecar locks. A legacy path-based activation
attempt is refused. A pre-upgrade writer that was never confirmed quiescent
must not be declared absent merely because a new writer can start.
