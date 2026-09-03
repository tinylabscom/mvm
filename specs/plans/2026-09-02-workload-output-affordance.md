# A workload needs a way to hand results back

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS — OCI teardown flush complete; surface design remains.**

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
thing `specs/plans/2026-08-31-remove-virtio-fs.md` removed, and the reason
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

- [ ] **Decide the surface.** An explicit output affordance on the transient
      path, e.g. `--output <guest-dir>:<host-dir>`, materialized as an output
      disk the guest writes and the host extracts after exit. Deliberately not
      a mode of `--mount`: the direction is the whole point, and overloading
      `--mount` is what made its two shapes confusing enough to need the
      message fix that preceded this plan.
- [ ] **Reuse `builder_disk_transport`, do not fork it.** `create_output_disk`
      and `read_output_disk` are the host half. If they need widening beyond
      `mvm-build`, widen them — a second raw-tar codec would drift from the
      first.
- [ ] **Decide what writes the tar in a workload guest.** The builder's guest
      init does it today. A workload guest runs `mvm-guest-agent`, not
      `mvm-host-vm-init`, so this is the real work: the agent needs an
      equivalent collect-and-pack step, and it needs to run after the workload
      exits but before teardown.
- [ ] **Bound it.** The output disk is fixed-size at boot; decide the failure
      mode when a workload produces more than fits. The builder's
      `repack_input_disk_in_place` refuses rather than truncating, on the
      grounds that refusing is the only way the failure is visible. Same
      reasoning applies.
- [ ] **Say what it is in the audit record.** A workload that can emit bytes to
      the host is a grant. It should appear in the signed plan the way a
      directory grant does, not arrive as an unrecorded side channel.

## What this does not need

A writable directory share, a second network path, or any change to the
vsock-only funnel. The output disk is an opaque byte array: the guest writes
bytes, the host decides what they mean, and there is no protocol for a guest to
drive.

## Adjacent, already recorded

`specs/plans/2026-09-02-retire-dirshare.md` covers the read direction and the
`DirShare` grant record. Its open question — a registered volume that the
transient path silently ignores — is now a warning rather than silence, but the
underlying asymmetry (registrations apply to `machine start` only) is the same
lifecycle split this plan runs into.
