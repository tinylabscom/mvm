# Writable-volume writer custody

## Protocol

A persistent writable volume has two cooperating-writer locks: its backing inode
and the stable `<image>.lock` sidecar. Materialization takes the sidecar before
creation/admission, then locks the original backing before inspecting, resizing,
formatting or validating its bytes; all mutation uses that held object. Boot
preparation opens the final physical
backing and sidecar without following a final symlink, takes both locks, and
binds them to the exact final disk slot and object identity. Hardlink aliases
therefore contend even when they use different sidecar paths. Read-only and
ephemeral disks do not acquire these resources.

Materialization transfers the original locked backing and sidecar through launch
preparation; the runtime never reacquires against its own guard. HVF inherits
both into its supervisor. The supervisor adopts them through the same complete
startup-descriptor preflight as the verified kernel, consumes the backing as the
virtio disk, and retains the sidecar until after the disk's final flush and
destruction. Firecracker inherits compact duplicates of the original backing
and sidecar through its bounded sudo launch while its drive recipe and snapshots
keep the original paths. After drive configuration, launch refuses unless the
live `/vm/config` matches that recipe and the actual writer's `/proc/<pid>/fd`
objects include every original locked backing and sidecar. Restore reads drive
roles from the old VMM's live `/vm/config`, positively stops that writer, and
only then prepares replacement locks. A fresh or blank-outgoing restore may use
an unresumed paused VMM to capture the restored recipe, but writable roles then
require another verified stop, lock acquisition and paused reload before resume.
Missing or mismatched writer identity after capture blocks replacement and
cleanup. Restore never parses snapshot bitcode or rewrites snapshot source
metadata. QEMU and libkrun inherit the original backing
and sidecar and open the backing through `/dev/fd`.
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
