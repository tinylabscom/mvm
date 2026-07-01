# Remote / object-store `DiskImage` backing (future direction)

Status: idea / future-ADR seed. Not scheduled.

## Why it fits

The in-house VMM's virtio-blk device depends only on a narrow backing surface
— `read_at(off, buf)`, `write_at(off, buf)`, `len`, `read_only`. `DiskImage`
today has two variants (`Mem`, `File`); the device never looks past that seam.
A remote backing (object store, HTTP range server, NBD) is a new variant behind
the same surface, so the device itself does not change.

## The two things that make it real work

1. **Async completion.** Today `read_at`/`write_at` run synchronously inside the
   guest's `QueueNotify` MMIO exit (on the vCPU thread). A `File` pread is
   microseconds, so blocking there is fine; an object GET is tens–hundreds of ms
   and would freeze the vCPU on every miss. A remote backing must move virtio-blk
   from "service synchronously in the exit" to "queue the request, fetch on a
   background thread, complete the used ring + raise the IRQ later." The run
   loop already has that machinery: the `poll()` → used-ring → `set_irq` path
   that delivers vsock host→guest work on the timer tick. Reuse it.

2. **Chunked range-fetch + local cache.** Block I/O is 512 B–128 KB; objects are
   whole blobs. A remote backing is a demand-paged block device: `Range:`
   fetches, a local sparse-file cache tier, readahead. Known pattern — NBD,
   `vhost-user-blk`, Nydus / stargz lazy-pull image formats, lazy-load-from-
   snapshot EBS.

## Two use cases, split cleanly

- **Read-only immutable base — easy, high value.** Golden rootfs / OCI-derived
  image / builder nix-store base, lazily range-fetched + locally cached, never
  mutated. This is *fast cold start*: page the image in on demand instead of
  downloading it whole. Lands on the "fast/lightweight builder, OCI image"
  theme and on cloud-readiness.
- **Read-write persistent — hard, don't do directly.** Object stores replace
  whole objects (no random-access partial writes). Do it as a **local COW
  overlay over a read-only remote base**: reads fall through to the remote base,
  writes land in a local writable file (the file-backed RW path we already
  have), overlay syncs up on flush. Base stays immutable + remote; only the
  delta is local.

## Architecture

Keep the enum while there are two backings (YAGNI). When the third (remote)
backing lands, promote `DiskImage` to a `BlockBacking` trait —
`MemBacking` / `FileBacking` / `CachedObjectBacking` / `OverlayBacking`. The
device is already trait-ready; only the enum→trait swap is needed.

## Security

A remote backing is a new host↔network channel for a VM's disk, so it composes
with — does not replace — integrity. Fetch untrusted bytes from anywhere;
dm-verity's roothash (claim 3) rejects tampering regardless of transport. Trust
is anchored in the roothash, not the transport. The trusted builder tier is the
natural first adopter (no untrusted workload, egress already allowed), and it is
where lazy image pull pays off most.
