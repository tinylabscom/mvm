---
title: Snapshots and cold mode
description: Pause a microVM into sealed state, create checkpoints, and restore later with explicit integrity checks.
---

Cold mode means a workload is not currently consuming a running guest, but it has recoverable state. In `mvm`, that state is represented by backend-specific snapshot and checkpoint artifacts.

The `machine` verbs on this page (`pause`, `resume`, `snapshot`, `checkpoint`) are
hidden advanced operations: they work, but they do not appear in
`mvmctl machine --help`.

## Recovery paths and current status

| Path | Meaning | Current status |
| --- | --- | --- |
| Live-memory snapshot/restore | Restore guest RAM plus VMM state. | Not advertised by the selectable workload runners. `resume --warm` refuses with a typed error when the selected backend cannot honor it. |
| Save/restore machine state | Restore serialized VMM state without claiming live-memory fidelity. | Advertised by `hvf` and `apple-container`. `firecracker`, `libkrun`, `qemu`, and `wasm` all report `unsupported`. |
| Disk-only CoW warm start | Reboot from a copy-on-write disk/overlay artifact without restoring RAM. | The raw libkrun substrate has this primitive, but no selectable workload runner advertises it yet. |
| Prelaunched supervisor standby | Pre-pay supervisor/setup latency before attaching a workload. | Separate from snapshots; advertised by `firecracker` and `hvf`, and by no other selectable runner. |
| Cold boot | Boot immutable artifacts from scratch. | Supported baseline recovery path. |

Other backends may support stop/start without machine-state recovery. Do not
assume a recovery tier unless the active backend reports it in
`mvmctl doctor`.

## Sealed instance snapshots

The `pause`/plain `resume` commands use the sealed instance-snapshot envelope.
They do not imply that the backend supports live-memory warm start. Both verbs
default to `--hypervisor firecracker` and drive the snapshot through
Firecracker's control socket, so this lifecycle is a Firecracker path in
practice.

Pause a running VM:

```sh
mvmctl machine pause agent-sandbox
```

`mvmctl machine pause` asks the backend snapshot transport to write `vmstate.bin` and
`mem.bin` into a private staging directory beside the VM's instance snapshot
directory, encrypts both, seals the sidecar with an epoch-bound HMAC envelope
over the ciphertext, publishes the result as the instance snapshot, and marks
the VM as paused in the local registry.

The published snapshot is replaced only once its replacement is complete. A
pause that fails, or is killed, before that point leaves the previous
snapshot and its epoch as they were, so the machine can still be resumed from
it; the failed attempt's staging is removed with it, or reclaimed later as
described under [Plaintext staging](#plaintext-staging).

### Snapshot encryption is required

A sealed instance snapshot holds the guest's memory, so it is always encrypted
(AES-256-GCM) under a 32-byte snapshot key. There is no setting that writes an
unencrypted snapshot. `mvmctl` reads the key from the first of these that holds
one:

- `MVM_TENANT_KEY_LOCAL`, set to 64 hex characters. Setting it is an explicit
  choice: it is then the only source `mvmctl` reads, which suits development,
  CI, and recovering a snapshot whose key you hold elsewhere.
- The OS keystore entry `mvm/local`.
- `/var/lib/mvm/keys/local.key`, holding the 32 raw bytes, mode `0600` or
  `0400`, readable by the user that runs `mvmctl`.
- `~/.mvm/keys/local.key` (under `MVM_HOME` when that is set), the same format.

A host with none of them gets one: `mvmctl bootstrap`, the first
`mvmctl pool warm`, and a `mvmctl machine prompt` that captures a step
checkpoint write 32 random bytes to `~/.mvm/keys/local.key` at mode
`0600` and record the creation in the local audit log. They never replace a
file that is already there, and a key file another user could read is refused
rather than rewritten. `mvmctl doctor` reports which source the key came from
on its `snapshot encryption key` line.

Keep a copy of the key. A snapshot encrypted under it cannot be resumed
without it, and nothing else holds it.

`pause` resolves and checks the key before it asks the VMM to capture
anything, and the key it checked is the one that encrypts the capture. It
refuses, with nothing written and the VM left running, when:

- **no key is configured** in any of them (a pause does not create one);
- **the key source cannot be read**, for example the key file exists but this
  user may not open it;
- **the key is malformed**: not 64 hex characters, not 32 bytes, or a key file
  whose mode is anything but `0600` or `0400`.

A source that cannot be read or holds a malformed key stops the search; the
other source is not tried in its place, so a snapshot is never encrypted
under a key you did not choose. Refusals name the source and what to fix, and
never quote key material.

Resume reads the key from the same sources:

| Snapshot on disk                    | No key configured                  | Key configured                                                    |
| ----------------------------------- | ---------------------------------- | ----------------------------------------------------------------- |
| Encrypted                           | Refused; configure the key it used | Decrypted and resumed; a different key fails authentication       |
| Unencrypted, from an older `mvmctl` | Resumed as before                  | Refused unless `MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1` for that resume |

A key source that cannot be read, or holds a malformed key, refuses the
resume as it refuses a pause. Pausing the VM again replaces an older
unencrypted snapshot with an encrypted one.

Resume it:

```sh
mvmctl machine resume agent-sandbox
```

`mvmctl machine resume` verifies the sealed envelope before loading the state and
clearing the paused flag. Replay of older sealed snapshots is refused by the
epoch binding. `mvmctl machine resume --warm` is a distinct live-memory request and
fails closed when the selected backend cannot honor that tier.

Once the guest is running again, `resume` hands it a fresh generation token and
the guest reseeds its kernel random generator from it. The resume line reports
the result (`VMGenID rotated`), and the same result goes into the resume's
`workload_wake` entry in the local audit log. The same sealed snapshot can be
resumed more than once, so a guest that did not reseed would reuse random state
(nonces and keys included) that it had already used. **A resume whose guest does
not confirm a reseed is refused**, whether the guest reported that it could not
reseed or its agent did not answer, failed, did not acknowledge, or took longer
than the admission deadline. Its VMM is stopped, the machine stays paused, the
refusal is recorded as a `resume_refused` entry in the local audit log, and the
sealed snapshot is kept, so the resume can be retried. The machine is marked
resumed only after the guest confirms the reseed. The error says what to do: a
guest whose image has no reseed helper needs its image rebuilt, and a guest whose
helper failed can retry the resume. Only one resume of a machine runs at a time;
a second waits for the first to finish.

The same holds when the resume itself is cut short. If `mvmctl` receives Ctrl-C
(SIGINT), SIGTERM, or SIGHUP (its terminal closed) while it waits for the guest,
it stops the restored VMM and records the refusal before it exits. An admitted
guest is recorded as admitted next to its VMM's pid before the machine is
marked resumed. A SIGKILL or an out-of-memory kill cannot be caught: the guest
then keeps running until the next state-touching `mvmctl` command, whose
reconcile pass on entry finds a paused machine whose Firecracker is running with
neither a pause nor an admission record, stops it, and records the refusal. That
pass re-checks under the machine's resume lock, so it never stops a resume that
another `mvmctl` process is still admitting, or one that has since admitted its
guest.

What a refusal does and does not undo:

- **A refused guest has run.** Its vCPUs are resumed before it is asked to
  reseed, so it runs until it answers or the fifteen-second admission deadline
  passes (five seconds for its agent to come up, ten for the exchange), and then
  for as long as stopping its VMM takes. Each retry of a refused resume runs the
  same state for that window again.
- **Its egress path is up during that window.** The per-VM network endpoint
  stays running, so traffic the network policy admits can leave the VM before a
  refusal, carrying values derived from the reused random state.
- **An admitted guest also runs briefly on the old state**, between its vCPUs
  resuming and the reseed taking effect.
- **The reseed covers the kernel's generator only.** User-space generators that
  were seeded before the snapshot (a library's own pool, a key a process already
  derived) are not re-keyed by it; a workload that must not repeat such values
  has to reseed them itself after a restore.
- **The record is not tamper-evident.** `resume_refused` and `workload_wake` go
  to the local audit log, which is unsigned and written best-effort; neither
  goes to the chain-signed per-tenant log.

`resume --warm` would refuse on the same grounds and stop the VM the same way,
but no backend completes a live-memory warm start today, so that path is not
reachable yet.

When the snapshot is encrypted, a resume decrypts it into a
private directory beside the sealed snapshot (mode 0700, files 0600) and loads
from there. The sealed files are never modified, so a refused resume can be
retried. The decrypted copies are removed when the load returns, whether it
succeeded or failed, and by the interrupt handling above. If `mvmctl` is killed
outright or aborts mid-load, they stay on disk until the next resume of that
machine or the next state-touching command's reconcile pass removes them.

This affects images built before the reseed helper existed: they cannot be
resumed from a sealed snapshot until they are rebuilt. A snapshot taken from
such an image keeps the old guest runtime and can never reseed, so after you rebuild,
boot the machine fresh before you pause it again.

List and remove local sealed snapshots:

```sh
mvmctl machine snapshot ls
mvmctl machine snapshot rm agent-sandbox
```

## Full-VM memory checkpoints

Full-VM memory checkpoints capture full guest state. They require a backend whose snapshot tier is `save-restore` or better — today `hvf` and `apple-container`; `firecracker`, `libkrun`, and `qemu` refuse with an explicit tier error. Check `mvmctl doctor` for the authoritative capability on this host:

```sh
mvmctl machine checkpoint create agent-sandbox --class vm-full
mvmctl machine checkpoint restore <checkpoint-id>
```

`checkpoint create` pauses the VM, saves machine state and memory to the checkpoint directory, and records the content hash in the audit chain. `checkpoint restore` re-hashes the checkpoint content and checks the record against the signed audit chain before restoring.

### Checkpoints are encrypted at rest

A checkpoint holds the guest's disk and, for `vm_full`, its memory, so every
checkpoint `mvmctl` captures is encrypted. There is no setting that captures an
unencrypted one. Each content blob — rootfs, memory, the backend's machine
state, the launch config, the machine id, sidecars, workspace volumes — is cut
into 1 MiB chunks, and each chunk and each blob's chunk index is sealed in an
authenticated envelope (AES-256-GCM under a per-object data key, wrapped under
the key domain's wrapping key, with the object's kind, key domain, keyed
reference and length bound in). The checkpoint record states that its content
is protected, and that statement is part of the record's digest, which the
signed audit chain covers.

Keys come from the same places as the snapshot key, per key domain:

- **Host domain** — checkpoints of a VM admitted under no tenant, warm-pool
  parents and other host artifacts — uses the host snapshot key
  (`MVM_TENANT_KEY_LOCAL`, the keystore entry `mvm/local`,
  `/var/lib/mvm/keys/local.key`, or `~/.mvm/keys/local.key`).
- **Tenant domain** `tenant:<name>` uses that tenant's own key
  (`MVM_TENANT_KEY_<NAME>`, the keystore entry `mvm/<name>`, or
  `/var/lib/mvm/keys/<name>.key`). The host key is never used in its place.

Each domain's wrapping and reference keys are derived from its root under
labels that include the domain's name, so two domains never share a key.

`checkpoint create` admits the key, and checks that the store's staging area
is a private directory, before it pauses the VM or writes anything. A missing,
unreadable or malformed key refuses the capture with the VM untouched. The
capture's plaintext exists only in that private staging area; it is sealed and
removed before the checkpoint is published, and a capture that fails part way
publishes nothing and leaves any earlier checkpoint under the same name as it
was.

Chunks are deduplicated only inside one key domain: a chunk's reference is an
HMAC under the domain's own key, each domain has its own object directory, and
an object already stored under a reference is reused only after it opens under
that domain's keys as the same chunk. Zero chunks occupy no object storage.
Snapshot mirrors of a checkpoint — the warm-pool snapshot store and a trusted
snapshot backend — receive the sealed objects only; a claim from a mirror opens
each blob from the checkpoint store, which authenticates every byte it
releases.

A warm-pool child is opened from its parent when the pool is refilled, not
when it is claimed. The claim still refuses a parent whose sealed objects
changed since: it checks every object where it lies by unwrapping its data
key under the domain's wrapping key, which binds the object's header and a
hash of its encrypted payload. That catches a changed, missing, swapped or
foreign object without decrypting any of them, so a claim produces no
plaintext and costs a hash of the parent's sealed bytes rather than a
decryption.

Restore and fork verify the record against the signed chain, then open each
blob into a private file beside its destination, renamed into place only once
every chunk has authenticated; on any failure — wrong key, another domain's
key, a tampered, missing, replayed or swapped object or index — nothing is
released and the partial file is removed. The opened files live where the VM
that uses them lives: a fork's in the child's state directory, a restore's in
a private directory under the checkpoint store that is removed when the
restore returns. Protected content never enters the shared restore cache.

Checkpoints captured before encryption carry no protection marker and are read
as the unencrypted checkpoints they are, through the older verified path; a
record cannot be relabelled either way without failing its digest. A store
opened without key custody — only possible through the library, with an
explicit root — captures unencrypted checkpoints and refuses to open an
encrypted one.

Unencrypted checkpoints are stored the same way, as authenticated 1 MiB
chunks, without the envelope. For those, restore keeps a verified, read-only
contiguous materialization for each chunk index. A later restore clones the
closest cached index and rewrites only changed chunks, then verifies every
chunk in the private result before handing it to the backend. The shared cache
is never the file a VM loads, so changing a cache entry after restore cannot
change a running guest's private image.

Restore fails closed. A checkpoint whose content has drifted, whose record disagrees with the signed chain, or that carries no signed creation entry is refused rather than restored. `checkpoint restore` and a `vm_full` fork also refuse a checkpoint for any tenant other than the one whose signed chain recorded its creation, because its saved memory is that tenant's data. The recorded tenant comes from the signed entry. The tenant it is compared with is the one the caller runs as (`MVM_TENANT` or the configured tenant), which the caller chooses. So this check stops a checkpoint from being restored into another tenant by mistake; it is not an authenticated boundary. Warm-pool claims are exempt: a pool parent is a boot that never ran a workload and carries no plan, tenant, secrets or volumes, so its memory holds no tenant's data.

On `hvf`, guest memory is not copied back into the restored VM. The RAM image is cloned into a private file in the VM's state directory, which must be on a local filesystem. The clone is opened read-only and its name removed, then it is hashed against the recorded digest, and the supervisor maps that same descriptor copy-on-write. The image is read once, to hash it. A page enters the restored VM's memory only when the guest touches it, and a page becomes private to that VM only when the guest writes it. Editing or replacing the checkpoint after verification does not reach the restored guest, because the guest maps the clone, not the checkpoint. Other users cannot write the clone either. This does not protect against a process running as your own user: in the moment between creating the clone and removing its name, such a process can open it for writing. That is outside the current threat model, because the VM supervisor already runs as your user, unsandboxed, and can read the host signing key. Each restore gets its own clone, so restored VMs share no memory pages with each other, even within one tenant. One limit: memory a restored VM frees is not handed back to the host while it runs. Free page reporting returns freed memory only for anonymous RAM, and a restored VM's RAM is a mapping of its clone, so pages it wrote stay charged to it until it stops. The restorer only ever maps plaintext: an encrypted checkpoint is opened into private staging first, as described above, and a RAM image still in ciphertext is refused, because mapping it would boot noise. On a filesystem that cannot clone files, the image is copied byte for byte on every restore, which costs a full write of the guest's memory. Checkpoints taken before this layout (with guest RAM inside the frame file) are refused with a message asking you to capture them again.

### HVF runtime identity evidence

The HVF supervisor answers a local runtime-artifact query only while every vCPU
is parked. The observation records the initramfs bytes supplied to the loader,
the final kernel command line, and SHA-256 hashes of the read-only disk files
actually opened for that boot. Disk hashes are captured once from held file
handles, not by reopening their paths on every query. Writable disks are not
included. Editing `supervisor.json` cannot alter this observation.

The query uses an owner-only Unix socket in the supervisor state directory.
The client checks the kernel-reported peer user and process identity and a fresh
query challenge. Request and response sizes and elapsed I/O time are bounded.
Evidence is serialized while the primary vCPU is stopped and the secondary
vCPUs are held; the hold is released before transmitting the response. A response
is an observation at that boundary, not a lease that prevents a later resume.

New HVF snapshots also retain this evidence inside the authenticated frame.
On restore, the supervisor consumes the verified, descriptor-owned frame rather
than mutable metadata. It checks the inherited initramfs identity against the
selected runtime, retains the inherited command line, and measures the newly
opened read-only disks. Recapture preserves that lineage. The wire response and
retained frame distinguish a loaded boot from inherited snapshot evidence.
An older frame without this evidence can still be loaded by the low-level
restore path, but its runtime-artifact query reports unsupported; it cannot
supply evidence for a checkpoint admission that requires it.

This proves **boot-input identity or authenticated boot lineage**, not the
contents of current guest RAM. It does not detect a guest modifying its runtime
in memory, host writes to a backing file after its boot-time measurement, or a
hostile process running as the supervisor's own user. Release-generation and
checkpoint-content verification remain separate required checks.

List and remove checkpoints:

```sh
mvmctl machine checkpoint ls
mvmctl machine checkpoint rm <checkpoint-id>
```

`rm` refuses a checkpoint that a live or parked agent session resumes from, or that another stored checkpoint was forked from — restoring that descendant walks its parent chain and would fail once the parent is gone. Remove descendants first. `mvmctl cache prune` follows the same rule: it keeps every ancestor of a checkpoint it keeps.

Checkpoints that capture the same machine share their unchanged 1 MiB chunks, so removing one checkpoint frees only the chunks no other checkpoint uses. `mvmctl cache prune` reclaims those after its checkpoint sweep, in the same run, together with the cached restore images of removed checkpoints and anything a crashed capture left behind. A chunk another checkpoint still uses is never removed.

Fork a checkpoint to a new identity (new VM name, same state):

```sh
mvmctl machine checkpoint fork <checkpoint-id> --new-id new-sandbox
```

## Plaintext staging

Some operations have to hold guest memory or disk on the host in the clear for
a moment. Each does it in a staging directory created mode `0700` before the
first byte is written, whatever the umask, and named after the process that
owns it:

| Staging                                   | Holds                                    | Lifetime                                                                            |
| ----------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------- |
| `instances/<vm>/.capture-<pid>-*`         | A pause's capture, until it is encrypted | Becomes the published snapshot, or is removed when the pause fails                  |
| `instances/<vm>/.snapshot.previous`       | The snapshot a pause is replacing        | Only between the two renames that publish its replacement; removed right after      |
| `instances/<vm>/.restore-<pid>-*`         | A resume's decrypted snapshot            | Removed when the load returns                                                       |
| `checkpoints/.staging/<pid>-*`            | A checkpoint capture                     | Sealed and published, or removed when the capture fails                             |
| `checkpoints/.restore-<pid>-*`            | A `vm_full` restore's opened blobs       | Removed when the restore returns                                                    |
| A fork's or restored VM's state directory | The blobs that VM runs from              | Removed with the VM                                                                 |

Every one is also removed on Ctrl-C, SIGTERM or SIGHUP. A process that is
killed outright or aborts cannot remove its own, so the next operation reclaims
it:

- The next pause or resume of that machine, and the reconcile pass every
  state-touching command runs on entry, remove `.capture-*` and `.restore-*`
  staging whose owning process is gone, and finish a publication a pause was
  interrupted in: `.snapshot.previous` with no published snapshot is published
  again, and one left beside a published snapshot is removed. Reconcile covers
  every directory under `instances/`, registered machine or not, and records
  each change as a `registry_reconcile` entry in the local audit log
  (`snapshot_staging_reclaimed`, `snapshot_previous_restored`,
  `snapshot_replaced_removed`).
- The next checkpoint capture removes abandoned capture staging, the next
  restore abandoned restore staging, and `mvmctl cache prune` both.

Staging whose owner is still alive is never touched, and neither is a machine
whose pause or resume holds its lifecycle lock. Nothing outside these names is
treated as staging, so writable data in an instance directory is never
removed by reclamation.

## Security implications

- Snapshot files contain guest memory and runtime state. Treat them as sensitive.
- Restore integrity is backend-specific: Firecracker uses the sealed instance envelope; checkpoints use the audit-chain record digest plus their authenticated object envelopes.
- An encrypted checkpoint is decrypted to disk while a VM restored from it runs, in that VM's own private state directory, and removed with it.
- Deleting a snapshot, a checkpoint or reclaimed staging is logical deletion: it unlinks the files. It does not overwrite them, and it does not reach copies outside `mvmctl`'s directories — filesystem snapshots, backups, SSD blocks not yet reused, or guest memory the host swapped out. Encrypting at rest is what limits what those copies expose; staging is plaintext for as long as it exists. Keeping `~/.mvm` on an encrypted volume, and its backups encrypted, is the operator's part.
- Changing a snapshot or checkpoint key does not re-encrypt what is stored: snapshots and checkpoints sealed under the old key keep needing it and are refused without it. Keep the old key until they are re-captured or removed.
- Snapshots can preserve credentials or derived tokens that existed inside the guest at snapshot time.

## Docs rule

When writing examples, name the backend. "Snapshot restore" is not a universal property of every `mvm` backend, and cold-mode behavior should not be used as a latency claim unless the benchmark states the backend, artifact, and readiness boundary.
