# A workload needs a way to hand results back

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS — `--output` collection, signed grant, and `plan.outputs` landed; hardlink identity and restored-run coverage remain.**

## The gap, measured

A transient workload cannot write anything a host or a later microVM can read.
Not "writes are snapshotted" — nothing is writable at all:

    mvmctl machine run --image alpine --mount /tmp/x:/data:rw    -- …
    → --mount requests rw, but a transient run attaches every directory read-only

    mvmctl machine run --image alpine --mount /tmp/x:/data:2G:rw -- …
    → …attaches every disk read-only

Both shapes refused. So a fleet workload that computes something has no
supported way to return it on the `machine run` path. The persistent path
(`machine start` + a registered volume) can, but that is a different lifecycle:
a named machine you start and stop, not a job you run.

## Why the obvious fix is the wrong one

Making a share writable puts a guest-driven FUSE parser back on the host — the
thing `2026-08-31-remove-virtio-fs` removed, and the reason
claim 1 can now rest on the guest having *no* channel to host filesystem
structure rather than on virtio-fs behaving. The vsock-only data plane is also
what makes claims 10 and 13 and the audit chain enforceable. A writable host
directory would quietly cost all of that.

## The mechanism already exists

The builder does exactly this today, and both builders were migrated onto it
this cycle: **a raw tar written straight onto a block device**, no filesystem
on the transport disk. The guest packs its artifacts; the host `tar x`es them.
Both sides only ever run `tar`, which is why it works on a macOS host that can
neither format nor mount an ext4 (`mvm_build::builder_disk_transport`).

The guest half is already general: `mvm-host-vm-init` collects `/out` onto the
output disk. The host half is `read_output_disk`.

**Correction to an earlier claim in the virtio-fs plan** (and to something I
repeated): "needs a host-side ext4 *reader*, which `mvm-fs` does not have" is
false as a general statement. `ext4-view` is a workspace dependency used by
`mvm-fs`, `mvm-client`, `mvm-runtime` and `mvm-cli` — `mvm-client`'s volume
service and lifecycle both read ext4 images on the host with it. Raw tar
remains the simpler transport, but "the host cannot read an ext4 image" is not
the reason to prefer it.

## Measured: the mechanism already works, and one missing flush makes it unsafe

Before designing anything new, the existing `--mount HOST:/GUEST:SIZE` path was
tried with the `rw` refusal lifted. **It works end to end.** On macOS 26:

    machine run --mount /tmp/wb/data.img:/data:64M:rw \
        -- sh -c "echo x > /data/proof.txt; sync"
    machine run --mount /tmp/wb/data.img:/data:64M -- cat /data/proof.txt
    → x

The guest mounts it genuinely read-write (`/dev/vde on /data type ext4
(rw,relatime)`), `materialize_disk_volume` creates the image at the caller's own
path, and the bytes survive into a *different* VM. No new affordance is needed
for the round trip itself.

**Without the explicit `sync`, the write is silently lost.** The identical run
minus `sync` produced no file on re-attach. `mk-guest.nix` runs
`/bin/busybox sync` before `poweroff -f`, so a mkGuest guest is safe — but an
**OCI guest (`--image …`) does not take that path**, and nothing flushes it. The
common case is the unsafe one.

So the blocker on `rw` is not policy, and not the lock. It is that a workload's
writes are not durable unless it happens to sync, and losing data quietly is
worse than refusing to write.

- [x] **Flush the OCI guest before teardown.** That is the whole prerequisite
      for making `HOST:/GUEST:SIZE:rw` safe, and it makes this plan's remaining
      scope much smaller: with a durable writable disk, a workload hands results
      back through an ordinary ext4 image the host reads with `ext4-view`, and
      the tar-on-a-disk design below is largely unnecessary.

      `mvm-exit-report` gained a `sync(2)` in this change, which covers the
      **detached** path (its reaper is the only caller) and is correct there.
      The non-detached OCI run does not go through it — that is the gap.

      The foreground path now reuses the authenticated `SleepPrep` request
      before stopping a transient VM whenever it carries a writable disk. The
      guest handler calls `sync(2)` directly, so an arbitrary OCI image does
      not need to contain a `sync` executable; the detached exit reporter uses
      the same helper. A failed request makes an otherwise successful run fail
      rather than silently claiming durability. This adds no verb, transport,
      grant, or guest-to-host data path.

      Live macOS HVF evidence used two fresh Alpine OCI VMs and one caller-owned
      64 MiB image. The first wrote `mvm-oci-flush-survived-20260903` without an
      explicit `sync`; the second mounted the image read-only and returned the
      exact marker. `check-gated`, the full workspace nextest suite, workspace doc
      tests, all-targets zero-warning Clippy, `check-all`, and BDD are green.

**Lock groundwork had already landed** so the flag was one flush away rather
than a rewrite: `materialize_disk_volume` returns the `VolumeImageLock` instead
of discarding it. The foreground call site was still acquiring that guard in
request construction and dropping it before boot; this work moves acquisition
into the run lifecycle and holds the guard through the flush and teardown.

## Shape to build

- [x] **Decide the surface.** `--output HOST_DIR:/GUEST[:SIZE[:MAX_ENTRIES]]`
      on `run` and foreground `machine run`, carried on the existing
      disk-image path rather than on a tar written by the guest.

      The choice was between an output affordance that needs a guest-side pack
      step and the durable writable disk the flush above made safe. The disk
      wins on every constraint that is not negotiable:

      - **No guest protocol.** The guest writes files into an ordinary ext4
        mount. The host reads the image after the VM is gone. There is no
        request to send, no verb to add, and no step that has to run between
        workload exit and teardown — the flush is the existing `SleepPrep`.
        The tar design needed exactly such a step in `mvm-guest-agent`, which
        is the part this plan had flagged as the real work.
      - **No host parser the tree did not already trust with guest bytes.**
        `ext4-view` is already how `mvm-client`'s volume service and the
        overlay/sidecar validators read guest-influenced images on the host;
        it is memory-safe, `no_std`, and designed not to panic or loop on
        invalid input. A guest-written tar would have been a second codec fed
        by the guest.
      - **No new network path and no writable share.** The output disk is a
        fresh sparse image in a private scratch directory under
        `~/.mvm/state/outputs/`; nothing on the host is visible to the guest.
      - **In the signed plan.** `ExecutionPlan.outputs` carries each grant —
        guest path, resolved host destination, byte bound, entry bound — and
        synthesis refuses a grant whose guest path is not backed by a writable
        disk the same plan admits in `shares`.

      Still deliberately not a `--mount` mode: the direction is the point, and
      the user never names, owns, or reuses the image.

- [x] **Reuse, do not fork.** `builder_disk_transport` grew nothing — the tar
      codec is not on this path at all. The OCI unpacker's absolute-path and
      `..` refusals were lifted into one shared `escaping_path_refusal`, which
      the unpacker and the output rules both call; the output rules add the
      stricter shape an output path needs (no empty or `.` component, no NUL,
      UTF-8, depth and length bounds). The disk itself goes through
      `materialize_disk_volume`, `VolumeImageLock`, and the writable-disk flush
      unchanged.

- [x] **What writes it in a workload guest.** Nothing new: the workload
      writes files into a mounted directory, and the flush that already runs
      before teardown makes them durable.

- [x] **Bound it, refusing rather than truncating.**
      `mvm_fs::output::collect_from_ext4` walks the whole image first and
      touches nothing on the host until the tree has passed every rule and
      both bounds; only then does it extract, through directory handles opened
      `O_NOFOLLOW`, creating every file `O_EXCL`. Any refusal — including one
      mid-extraction — removes what the collection created. The disk is sized
      past the byte bound so the bound, which names itself in the refusal, is
      what fires, not a full disk.

- [x] **Say what it is in the audit record.** After collection a
      chain-signed `plan.outputs` entry records `outcome=collected` with the
      canonical manifest digest (domain-tagged, length-prefixed, sorted by
      path), entry count, byte total, and the tree digest `--asset` would
      compute for the destination — so a later run that consumes these files
      as an asset names them by the same identity — or `outcome=refused` with
      only the rule's tag. No guest-chosen path reaches the chain; the full
      manifest is written beside the outputs as `HOST_DIR.manifest.json`.

      Live on macOS 26 HVF with fresh Alpine OCI VMs and an isolated
      `MVM_HOME`: a workload running as its unprivileged service user wrote
      `status.txt` and `logs/run.txt`; the host collected three entries
      (10 bytes), wrote the manifest beside them, and the chain recorded
      `plan.outputs outcome=collected`, whose `tree_sha256` equals
      `mvmctl trust audit asset id` on the collected directory. A second run
      that planted `ln -s /etc/passwd` refused with `reason=symlink`, and a
      third that wrote 2 MiB under a `1M` bound refused naming the
      1048576-byte bound (`reason=byte_bound`); neither left a destination,
      and `trust audit verify` stayed clean.

- [ ] **Refuse a hard link instead of copying it twice.** `ext4-view` exposes
      no inode number or link count, so a file linked under two names inside
      the image is indistinguishable from two files with equal bytes. Today it
      is collected as two independent host files, each charged against the
      byte bound — no alias reaches the host, but the rule "hardlinks are
      refused" does not hold. Closing it needs inode identity from the reader
      (an upstream accessor, or a reader that exposes it); reimplementing an
      inode-table walk beside `ext4-view` would be the second parser this plan
      exists to avoid.

- [ ] **Outputs on restored and warm-claimed runs.** A run with any disk
      volume is not warm-claim eligible and boots cold, so `--output` cannot be
      silently dropped by a claim today. If disk volumes ever become
      claimable, output disks need to travel with the claim or keep refusing.

## What this does not need

A writable directory share, a second network path, or any change to the
vsock-only funnel. The output disk is an opaque byte array: the guest writes
bytes, the host decides what they mean, and there is no protocol for a guest to
drive.

## Adjacent, already recorded

`2026-09-02-retire-dirshare` covers the read direction and the
`DirShare` grant record. Its open question — a registered volume that the
transient path silently ignores — is now a warning rather than silence, but the
underlying asymmetry (registrations apply to `machine start` only) is the same
lifecycle split this plan runs into.
