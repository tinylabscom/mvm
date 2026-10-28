---
title: Persistent workspaces
description: Use encrypted volumes, copy workflows, snapshots, and cleanup policies for stateful sandboxes.
---

:::note[Hidden verbs]
`machine volume`, `machine cp` and `machine fs` are all marked hidden in the
CLI: they work, but they do not appear in `mvmctl machine --help`.

Guest mount paths must be under `/data` or `/work` — those are the only two
allow-roots. `/cache`, `/workspace` and anything under `/mnt` are refused.
:::

Guest mount destinations must be real directories: symlinks are refused in
every destination component, including inside an earlier mounted volume.
The guest pins destination directories with file descriptors and attaches
mounts without resolving the destination pathname again. These checks apply
to cold boot, warm-restore volume attachment, and live volume operations.
They constrain the destination, not whether the source is an ad-hoc local
directory, an explicit disk image, or a registered volume.

Volume attachment requires Linux 5.2 or newer with the new mount APIs and
support for the selected filesystem. Missing support fails the operation;
there is no path-based fallback. Live unmount also requires the guest's
trusted procfs at `/proc`.

Persistent state is useful for agents, browser sessions, caches, databases, and
long-running services. It is also where sensitive data accumulates. Choose the
smallest state mechanism that fits the workflow, and make the retention policy
explicit before the sandbox starts.

## Pick a state mechanism

| Need | Use | Security posture |
| --- | --- | --- |
| One input file or result file | `mvmctl machine cp` or `mvmctl machine fs` | Narrowest boundary; preferred for generated-code tasks. |
| Read-only fixtures | `mvmctl run --mount ...:ro` | Host data is exposed but not writable by the guest. |
| Local dev edits | `mvmctl machine cp` or managed volume | Explicit copy or encrypted persistent state; no writable transient host share. |
| Stateful app data | managed encrypted volume | Encrypted at rest when locked; plaintext exists while unlocked. |
| Fast retry or recovery | snapshot or cold mode | Can contain memory, files, processes, prompts, and credentials. |

Do not use a snapshot when a narrow output file is enough. Do not use a writable
host share when a managed volume is enough.

## Managed encrypted volume

Create a managed local volume:

```sh
mvmctl machine volume create agent-cache
```

Managed volumes are locked by default. Unlock before mounting:

```sh
mvmctl machine volume unlock agent-cache
```

Mount the unlocked volume into a running sandbox:

```sh
mvmctl machine volume mount agent-sandbox \
  --volume agent-cache \
  --guest /data/cache \
  --rw
```

List mounts:

```sh
mvmctl machine volume ls agent-sandbox
```

Unmount and lock when the workflow is done:

```sh
mvmctl machine volume unmount agent-sandbox /data/cache
mvmctl machine volume lock agent-cache
```

### Lifetimes: unlock, attach, release, relock

A managed volume is plaintext on the host only between an unlock and the lock
that follows it. Which lock that is depends on who unlocked it:

- **Explicit unlock** (`mvmctl machine volume unlock`) persists. The volume
  stays unlocked across any number of machine starts and stops until you run
  `mvmctl machine volume lock`; stopping a machine does not re-seal it.
- **Just-in-time unlock** happens when a library or SDK start (`LocalBackend`,
  the host library) finds a registered volume locked. The start unlocks it,
  holds the attachment lease for the life of the machine, and re-seals it when
  that lease is released at stop. It re-seals only what it unlocked itself.
- **A refused or failed start** re-seals every volume it unlocked just in time
  before it returns, including the ones unlocked before the refusal, and
  releases its leases. A volume you unlocked explicitly is left unlocked.
- **Attachment** (`volume mount`) only registers the volume for a machine; it
  needs the volume already unlocked and never unlocks it.
- **Locking** writes only ciphertext. It streams the plaintext into a private
  staging directory beside the archive and renames the result into place, so
  no plaintext copy is ever made next to the ciphertext. An interrupted lock
  recovers to the unlocked image with its writes intact.

### Where unlocked plaintext may live

Unlocked plaintext is written under the volume root's `unlocked/` directory —
`~/.mvm/volumes/mvm-managed/unlocked` by default, or `<root>/unlocked` for a
volume created with `--root`. That directory and the volume root are created
owner-only (`0700`), and the image is `0600`. The directory must also be on
storage that is **verified encrypted**:

- **macOS**: the APFS volume holding it reports `FileVault: Yes` (or
  `Encrypted: Yes`) in `diskutil info`. A volume that is only hardware
  "encrypted at rest" with FileVault off does not count — its key is not bound
  to your login, so the data is readable by anyone who can boot or attach the
  disk.
- **Linux**: it is on an ext2/ext3/ext4 filesystem with no external journal,
  and every block device beneath it is a dm-crypt/LUKS mapping. Proving the
  journal is internal runs `tune2fs -l` on the device, which needs read access
  to it (root, or the `disk` group on most distributions). Other filesystems
  and layouts are reported as unverified rather than guessed at.

The check runs before anything is written, at every point plaintext could
appear or be used: `volume create` (before a key is minted), `volume unlock`
and just-in-time unlock (before decrypting), `volume mount`, and every start
that leases the volume — an explicitly unlocked volume is re-checked at each
start, so moving its root to other storage later is caught. A refusal leaves
locked ciphertext untouched and never deletes an unlocked image, so writable
data is never lost to a refusal; `volume lock` needs no check and always works.

When the check fails, the command refuses and says why:

```text
refusing to place managed volume plaintext at …/unlocked: the storage is not
verified encrypted. Enable FileVault (macOS) or put the location on a
dm-crypt/LUKS ext4 filesystem (Linux), or choose a location that is. For local
development only, set MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE=1 to proceed anyway;
each use is audited and --prod refuses it
```

`mvmctl doctor` reports the same verdict for the default location on its
`volume storage (encrypted backing)` line.

**Development override.** On a laptop or CI host without FileVault or LUKS, set
`MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE=1` to accept unverified storage. It is
never on by default and only the value `1` turns it on. Each use writes a
`volume_storage_override` entry (purpose, path, and the reason the check
failed) to the local audit log at `~/.mvm/state/log/audit.jsonl`; if that entry
cannot be written the operation is refused. `--prod` refuses a run that carries
the variable at all.

Security rules:

- `volume mount` refuses a managed volume while it is locked;
- `volume unlock` creates plaintext state that must be treated as sensitive;
- `volume lock` reseals the volume and removes plaintext after use;
- keep volume names scoped to the workflow or project;
- do not mount the same writable volume into unrelated sandboxes unless sharing
  state is the intent;
- a managed volume is an ext4 image the guest writes into, never a live host
  directory, so `--rw` follows the same profile grant as a
  `HOST.img:/GUEST:SIZE:rw` disk image: every start (`mvmctl machine start`,
  `LocalBackend`, or the language SDKs through their host library) admits it
  when the machine's profile is `standard` (the default), `dev`, or
  `permissive`, and refuses it under `restrictive`. `volume mount --rw` against
  an existing `restrictive` machine is refused at registration.

## Explicit disk images

`--mount HOST.img:/GUEST:SIZE[:rw]` on `mvmctl run`, `mvmctl machine run`, or a
persistent machine names an image file directly instead of a managed volume. It
is not registered in the volume catalog, has no lock or unlock, and is never
encrypted by mvm: whatever the guest writes sits in that file as plaintext. So
a **writable** (`:rw`) image follows the same rules as unlocked managed-volume
plaintext, checked before anything is created:

- the filesystem it will live on must be verified encrypted, with the same
  development override and the same `--prod` refusal;
- a missing image is created `0600`, and any missing directory above it `0700`;
- an existing image is used only if it is a regular file no other user can
  read or write (fix with `chmod 600 <image>`); mvm never changes the mode of a
  file or directory you already own;
- an image in a directory other users can write to (`/tmp`, a `0777` share) is
  refused, since they could replace it.

A read-only image is only read by the guest, so none of these apply to it.

## Durable tenant volumes through mvmd

:::caution[Daemon API compatibility]
The remote client uses `/api/v1/tenants/{tenant_id}/volumes`. The current
`mvmd` V1 API uses `/v1` routes and does not implement volume or bucket
endpoints. The examples below require a daemon implementing the tenant-volume
API; they do not establish support in V1. Local registered and ad-hoc volumes
do not depend on this remote API.

`MVM_TENANT_ID` selects a request namespace; it does not authorize access.
The daemon must bind volume creation, registration, and attachment to the
authenticated principal, and verify ownership of both the volume and target
instance before attaching.
:::

Use remote mode when mvmd owns the tenant, storage provider, encryption keys,
quota, and attachment policy. Configure the authenticated client without
putting the bearer token on the command line:

```sh
export MVM_GATEWAY_URL=https://mvmd.example.com
export MVM_TENANT_ID=tenant-acme
read -rsp "mvmd bearer token: " MVM_GATEWAY_TOKEN
export MVM_GATEWAY_TOKEN
```

The client refuses cleartext HTTP except for a loopback sidecar. Provider
credentials never enter `mvmctl`; mvmd resolves them from the registered
`StorageBucket`.

Create and list durable volumes:

```sh
mvmctl machine volume create database --size 20G --remote --bucket bucket-primary
mvmctl machine volume catalog --remote --json
```

The API allocates whole GiB, so smaller human-readable sizes round up to one
GiB. Use the returned volume ID for attachment and checkpoint operations:

```sh
mvmctl machine volume mount worker-1 --volume vol-123 --guest /data --rw --remote
mvmctl machine volume checkpoint vol-123 before-upgrade --remote
mvmctl machine volume restore vol-123 snap-456 --target database-recovered --remote
mvmctl machine volume unmount worker-1 /data --remote
mvmctl machine volume delete vol-123 --remote
```

Remote restore always creates a new volume from a pinned, ready checkpoint; it
does not overwrite the source volume. Delete is refused while a volume remains
attached or retains checkpoints. Attachment conflicts, quota failures,
authorization failures, provider outages, and integrity refusals are returned
as errors rather than falling back to the local registry.

## Host-backed mounts

Ad-hoc host-backed mounts seed a machine from an existing encrypted host
directory. The directory is **snapshotted into a content-addressed ext4 image**
and attached as a block device; it is not a live view. `machine start` hashes
the source tree and refreshes the registered snapshot when its contents or
guest-visible metadata changed. Host edits made while the machine is running
therefore become visible after the next stop/start. If the source directory is
missing at start, the launch refuses instead of silently using stale bytes.

This is the same treatment `mvmctl machine run --mount HOST:/GUEST` gives a
transient run. Both paths share the same verified mount-image cache, and for
the same reason: no workload backend has a virtio-fs device, so a live
host-directory share cannot be expressed at all.

```sh
mvmctl machine volume mount agent-sandbox \
  --volume project-data \
  --host /absolute/path/to/data \
  --guest /data
```

With `--rw` the machine gets a private copy of the snapshot image. The guest
writes into that copy and never into the source directory, and a source
directory whose contents change replaces the copy — discarding the guest's
writes — at the next start. The copy holds the same tree as the snapshot plus
4 GiB of free space and 65,536 free inodes for the guest to grow into. The
image file is sparse, so the free space takes no host disk until the guest
writes it. Use `--rw` only for trusted workflows:

```sh
mvmctl machine volume mount agent-sandbox \
  --volume project-data \
  --host /absolute/path/to/data \
  --guest /data \
  --rw
```

The host directory must live on verified encrypted backing storage, judged by
the same check as unlocked managed volumes (see
[Where unlocked plaintext may live](#where-unlocked-plaintext-may-live)), with
the same development override. If encryption cannot be verified and the
override is not set, the command fails closed — the check runs against the source
directory and independently against the private mount-image cache before any
snapshot bytes are written. Files are streamed into the cache rather than held
as a whole tree in memory, and a file that changes while its snapshot is being
built refuses the launch instead of publishing mismatched bytes.

## Copy instead of mount

For model-generated code, third-party scripts, and code interpreter workloads,
prefer copy-in/copy-out:

```sh
mvmctl machine cp ./input.json agent-sandbox:/work/input.json
mvmctl machine exec agent-sandbox -- python /work/task.py
mvmctl machine cp --max-bytes 16777216 agent-sandbox:/work/output.json ./output.json
```

Copy workflows reduce host exposure. Treat copied guest output as untrusted
input when it returns to the host.

## Snapshots versus volumes

Volumes preserve selected filesystem state. Snapshots preserve machine state.

| Capability | Volume | Snapshot or cold state |
| --- | --- | --- |
| Files only | Yes | Yes |
| Process memory | No | Yes |
| Running process state | No | Backend-specific |
| Easier to inspect | Yes | No |
| Smaller retention surface | Usually | Usually not |
| Can contain secrets | Yes | Yes |

Use a volume when you need durable files. Use cold mode or snapshots when you
need to resume a whole machine state.

## Agent workspace pattern

For a coding agent:

1. Create a named sandbox with a short TTL.
2. Copy the task input into `/work`.
3. Mount a managed volume at `/data/workspace` only if the agent needs durable state.
4. Keep network closed until the task has an approved egress need.
5. Copy out bounded results.
6. Stop, cold-pause, or destroy based on the retention decision.
7. Lock volumes and record receipt/audit identifiers.

Example:

```sh
mvmctl machine volume create coding-agent-work
mvmctl machine volume unlock coding-agent-work
mvmctl machine run --flake ./agent-image --name coding-agent -d
mvmctl machine volume mount coding-agent --volume coding-agent-work --guest /data/workspace --rw
mvmctl machine cp ./task.json coding-agent:/work/task.json
mvmctl machine exec coding-agent -- python /work/run_task.py
mvmctl machine cp --max-bytes 16777216 coding-agent:/work/result.json ./result.json
mvmctl machine volume unmount coding-agent /data/workspace
mvmctl machine stop coding-agent
mvmctl machine volume lock coding-agent-work
```

## Cleanup checklist

Before marking a stateful sandbox done:

- stop compute with `mvmctl machine stop` when it no longer needs to run;
- lock every managed volume;
- remove mounts that are no longer needed;
- delete snapshots that no longer have a recovery purpose;
- rotate credentials if generated code had access to them;
- store receipt/audit identifiers with the job record;
- review logs before attaching them to tickets, traces, or model context.

Stopping compute is not the same as erasing state. Volumes, logs, receipts,
snapshots, caches, copied files, and generated artifacts may remain.

## Related pages

- [Persistence, pause & resume](/working/persistence/)
- [Filesystem operations](/working/filesystem/)
- [Lifecycle states](/working/lifecycle-states/)
- [Cold mode](/working/cold-mode/)
- [Snapshots](/working/snapshots/)
- [Secrets and credentials](/guides/secrets-and-credentials/)
